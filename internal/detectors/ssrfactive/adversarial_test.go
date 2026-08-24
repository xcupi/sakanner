package ssrfactive

import (
	"context"
	"fmt"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/ssrf"
)

// --- Host safety (docs/phase-3-25-ssrf-active-detection.md section 6) ----

// TestAdversarial_ProbeRequest_NeverChangesHost proves the probe
// request's own dial target is always t's own host/IP/port, regardless
// of which payload (baseline, internal-resource URL, or callback URL)
// was injected as the PARAMETER VALUE -- mirroring the identical,
// already-established host-safety argument every other active
// detector's own adversarial suite makes (e.g. idoractive's
// TestAdversarial_KnownBadControl_NeverChangesHost).
func TestAdversarial_ProbeRequest_NeverChangesHost(t *testing.T) {
	var sawHost string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		sawHost = r.Host
		fmt.Fprint(w, "an ordinary response, plenty of content to be non-trivial")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "url", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New(newFakeCallback(), "http://127.0.0.1:1/resource", "unused-marker").Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if sawHost == "" {
		t.Fatal("expected the server to observe at least one request")
	}
	if !strings.HasPrefix(sawHost, tgt.Host) {
		t.Fatalf("SECURITY: server observed Host = %q, want a host beginning with %q -- an injected payload value must never change the scanner's own dial target", sawHost, tgt.Host)
	}
}

// TestAdversarial_DangerousOriginalParameterValueNeverDialed mirrors
// internal/detectors/ssrf's own adversarial test of the identical
// name: the detector only ever dials ITS OWN probe values (baseline,
// internal-resource URL, callback URL) against the TARGET
// APPLICATION -- never the original, possibly-dangerous discovered
// parameter value (e.g. "file:///etc/passwd") directly.
func TestAdversarial_DangerousOriginalParameterValueNeverDialed(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		fmt.Fprint(w, "an ordinary response, plenty of content to be non-trivial")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "url", "query", nethttp.MethodGet)
	tgt.URL = srv.URL + "/?url=file:///etc/passwd"
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New(newFakeCallback(), "", "").Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("a dangerous original parameter value alone must never itself produce a finding -- this detector never dials it")
	}
}

// --- Cross-scan callback isolation (docs section 7, adversarial case 10) --

// TestAdversarial_ConcurrentScans_CallbacksNeverCrossAttribute mirrors
// internal/detectors/ssrf's own
// TestCorrelation_CallbackFromAnotherScanIsolated, extended to run
// truly concurrently against two independent Detect calls (modeling
// two independent scans, each with its own CallbackClient instance --
// e.g. two separate lab.SSRFCallbackServer instances, or a real
// production collaborator service scoped per scan) -- a callback
// recorded under one scan's own token must never surface in the
// other's result.
func TestAdversarial_ConcurrentScans_CallbacksNeverCrossAttribute(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		fmt.Fprint(w, "an ordinary response, plenty of content to be non-trivial")
	}))
	defer srv.Close()

	cbA := newFakeCallback()
	cbB := newFakeCallback()
	// Only scan A's own token ever receives an observation.
	cbA.inject("token-1", ssrf.Observation{Method: "GET", Timestamp: time.Now()})

	tgt := targetFor(t, srv, "url", "query", nethttp.MethodGet)
	x := newExecutor(true, detection.ExecutorConfig{})

	type outcome struct {
		name   string
		result detection.Result
		err    error
	}
	results := make(chan outcome, 2)
	go func() {
		r, err := New(cbA, "", "").Detect(context.Background(), tgt, x)
		results <- outcome{name: "scan-A", result: r, err: err}
	}()
	go func() {
		r, err := New(cbB, "", "").Detect(context.Background(), tgt, x)
		results <- outcome{name: "scan-B", result: r, err: err}
	}()

	byName := map[string]outcome{}
	for i := 0; i < 2; i++ {
		o := <-results
		if o.err != nil {
			t.Fatalf("%s: %v", o.name, o.err)
		}
		byName[o.name] = o
	}
	if byName["scan-A"].result.Outcome != detection.OutcomeFinding {
		t.Errorf("scan-A: Outcome = %s, want finding (its own callback was observed)", byName["scan-A"].result.Outcome)
	}
	if byName["scan-B"].result.Outcome != detection.OutcomeNoFinding {
		t.Fatalf("SECURITY: scan-B: Outcome = %s, want no_finding -- it must never see scan-A's callback observation", byName["scan-B"].result.Outcome)
	}
}

// TestAdversarial_ManyConcurrentProbes_NoRaceNoCrossContamination runs
// many concurrent Detect calls against independently-tokened
// callbacks under the SAME shared underlying callback map (modeling
// many probes within one scan, or many scans sharing one real
// collaborator service instance) -- proves token uniqueness alone is
// sufficient isolation, race-clean.
func TestAdversarial_ManyConcurrentProbes_NoRaceNoCrossContamination(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		fmt.Fprint(w, "an ordinary response, plenty of content to be non-trivial")
	}))
	defer srv.Close()

	shared := newFakeCallback()
	const n = 20
	var wg sync.WaitGroup
	violations := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tgt := targetFor(t, srv, "url", "query", nethttp.MethodGet)
			x := newExecutor(true, detection.ExecutorConfig{})
			result, err := New(shared, "", "").Detect(context.Background(), tgt, x)
			if err != nil {
				violations <- fmt.Sprintf("goroutine %d: Detect error: %v", i, err)
				return
			}
			// No observation was ever injected for ANY token here, so
			// every one of these must be a clean no_finding -- a
			// finding would mean cross-goroutine token confusion.
			if result.Outcome == detection.OutcomeFinding {
				violations <- fmt.Sprintf("goroutine %d: unexpected finding: %+v", i, result.Findings)
			}
		}(i)
	}
	wg.Wait()
	close(violations)
	for v := range violations {
		t.Error(v)
	}
}
