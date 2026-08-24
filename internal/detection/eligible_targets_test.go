package detection_test

import (
	"context"
	"testing"

	"sakanner/internal/detection"
	"sakanner/internal/detection/detectiontest"
)

// Phase 3.11.2: RunSummary.EligibleTargets counts every (detector,
// target) pair that passed eligibility, computed in the same
// sequential selection loop that decides whether to schedule work --
// distinct from DetectorRuns (how many actually completed), so a
// caller can tell "nothing was eligible" (EligibleTargets == 0) apart
// from other zero-DetectorRuns causes.

func TestEngine_EligibleTargets_ZeroWhenNoDetectorIsEligible(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http"})

	reg := detection.NewRegistry()
	m := &detectiontest.Mock{Behavior: detectiontest.Finding, EligibleFunc: func(detection.Target) bool { return false }}
	if err := reg.Register(m); err != nil {
		t.Fatalf("Register: %v", err)
	}

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Logger: discardLogger()}
	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.EligibleTargets != 0 {
		t.Errorf("EligibleTargets = %d, want 0 (the only registered detector is never eligible)", summary.EligibleTargets)
	}
	if summary.DetectorRuns != 0 {
		t.Errorf("DetectorRuns = %d, want 0", summary.DetectorRuns)
	}
	if m.Calls() != 0 {
		t.Errorf("Detect was called %d times, want 0 -- an ineligible target must never reach Detect", m.Calls())
	}
}

func TestEngine_EligibleTargets_MatchesDetectorRunsWhenUncancelled(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http"})

	reg := detection.NewRegistry()
	m := &detectiontest.Mock{Behavior: detectiontest.NoFinding}
	if err := reg.Register(m); err != nil {
		t.Fatalf("Register: %v", err)
	}

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Logger: discardLogger()}
	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.EligibleTargets == 0 {
		t.Fatal("EligibleTargets = 0, want at least 1 (the mock detector is eligible for the http_service target)")
	}
	if summary.EligibleTargets != summary.DetectorRuns {
		t.Errorf("EligibleTargets = %d, DetectorRuns = %d, want them equal under normal (uncancelled) operation", summary.EligibleTargets, summary.DetectorRuns)
	}
}

func TestEngine_EligibleTargets_CountsEveryEligibleDetectorTargetPair(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http"})

	reg := detection.NewRegistry()
	m1 := &detectiontest.Mock{IDValue: "mock-1", Behavior: detectiontest.NoFinding}
	m2 := &detectiontest.Mock{IDValue: "mock-2", Behavior: detectiontest.NoFinding}
	if err := reg.Register(m1); err != nil {
		t.Fatalf("Register m1: %v", err)
	}
	if err := reg.Register(m2); err != nil {
		t.Fatalf("Register m2: %v", err)
	}

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Logger: discardLogger()}
	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// One http_service target, both detectors eligible for it -> 2
	// eligible (detector, target) pairs.
	if summary.EligibleTargets != 2 {
		t.Errorf("EligibleTargets = %d, want 2 (2 detectors x 1 eligible target)", summary.EligibleTargets)
	}
	if summary.DetectorRuns != 2 {
		t.Errorf("DetectorRuns = %d, want 2", summary.DetectorRuns)
	}
}

func TestEngine_EligibleTargets_PartialEligibility(t *testing.T) {
	store := newTestStore(t)
	seedRecon(t, store, reconFixture{
		scanJobID: "job1", hostID: "h1", serviceID: "s1", ip: "127.0.0.1", port: 80, url: "http://h/", scheme: "http",
	})

	reg := detection.NewRegistry()
	// Eligible only for TargetKindEndpoint -- the fixture above has no
	// endpoints (no crawl), only the one TargetKindHTTPService target,
	// so this detector should never be eligible for anything.
	endpointOnly := &detectiontest.Mock{
		IDValue:     "endpoint-only",
		TargetKinds: []detection.TargetKind{detection.TargetKindEndpoint},
		Behavior:    detectiontest.NoFinding,
	}
	// Eligible for the http_service target (default TargetKinds cover
	// both kinds).
	httpServiceEligible := &detectiontest.Mock{
		IDValue:  "http-service-eligible",
		Behavior: detectiontest.NoFinding,
	}
	if err := reg.Register(endpointOnly); err != nil {
		t.Fatalf("Register endpointOnly: %v", err)
	}
	if err := reg.Register(httpServiceEligible); err != nil {
		t.Fatalf("Register httpServiceEligible: %v", err)
	}

	e := &detection.Engine{Registry: reg, Store: store, Executor: newExecutor(true), Logger: discardLogger()}
	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: "job1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if summary.EligibleTargets != 1 {
		t.Errorf("EligibleTargets = %d, want 1 (only httpServiceEligible x the 1 http_service target)", summary.EligibleTargets)
	}
	if endpointOnly.Calls() != 0 {
		t.Error("the endpoint-only detector was called despite there being no endpoint targets")
	}
	if httpServiceEligible.Calls() != 1 {
		t.Errorf("httpServiceEligible.Calls() = %d, want 1", httpServiceEligible.Calls())
	}
}
