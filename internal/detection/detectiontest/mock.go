// Package detectiontest provides Mock, a configurable Detector
// implementation that exists ONLY to exercise internal/detection's
// framework lifecycle (registration, selection, execution, evidence,
// normalization, deduplication, persistence, scope enforcement,
// cancellation, error isolation, concurrency) in tests.
//
// Mock never claims to detect a real vulnerability -- every finding it
// can be configured to emit is clearly labeled as a test fixture in its
// Title and Description, and it is never registered in any production
// Registry (see cmd/scanner, which registers zero detectors). Treat
// this package the same way internal/testutil is already treated in
// this codebase: test-support code, imported only from _test.go files
// and test packages, never from production wiring.
package detectiontest

import (
	"context"
	"fmt"
	nethttp "net/http"
	"sync/atomic"
	"time"

	"sakanner/internal/detection"
	"sakanner/pkg/models"
)

// Behavior selects what Mock.Detect does once any configured request/
// delay has completed.
type Behavior int

const (
	NoFinding Behavior = iota // Detect returns OutcomeNoFinding, nil -- the "checked, not vulnerable" case
	Finding                   // Detect returns one clearly-labeled test-fixture Finding
	Skipped                   // Detect returns OutcomeSkipped, nil
	Error                     // Detect returns a non-nil error
	Panic                     // Detect panics -- for proving the engine isolates it
)

// Mock is a Detector test fixture. The zero value is a no-op detector
// (ID "mock-detector", eligible for every target, never finds anything)
// -- set fields to exercise other lifecycle paths.
type Mock struct {
	// IDValue overrides the default "mock-detector" ID -- set a distinct
	// value per instance when a test registers more than one Mock, since
	// Registry.Register rejects duplicate IDs.
	IDValue string

	// TargetKinds overrides the default (both TargetKindHTTPService and
	// TargetKindEndpoint) supported-kinds declaration.
	TargetKinds []detection.TargetKind
	// Methods restricts eligibility to endpoint targets with one of
	// these HTTP methods, mirroring detection.Metadata.SupportedMethods.
	Methods []string
	// Prerequisites is carried straight into Metadata().Prerequisites,
	// for tests asserting the registry/CLI surfaces it.
	Prerequisites []string

	// EligibleFunc, if set, overrides the default Eligible behavior
	// (accept every target of a supported kind/method).
	EligibleFunc func(detection.Target) bool

	Behavior   Behavior
	Severity   models.Severity // defaults to models.SeverityInfo if empty
	Confidence float64         // defaults to 1.0 if zero and Behavior == Finding

	// RequestPath, if non-empty, makes Detect issue one GET request via
	// the Executor to t.URL+RequestPath before deciding its outcome --
	// so a test can exercise scope enforcement, timeouts, and the
	// request budget through the real Executor instead of faking them.
	RequestPath string
	// DetectDelay, if non-zero, makes Detect wait (ctx-aware) before
	// doing anything else -- for exercising cancellation mid-detection.
	DetectDelay time.Duration

	calls atomic.Int64
}

// Metadata implements detection.Detector.
func (m *Mock) Metadata() detection.Metadata {
	id := m.IDValue
	if id == "" {
		id = "mock-detector"
	}
	kinds := m.TargetKinds
	if len(kinds) == 0 {
		kinds = []detection.TargetKind{detection.TargetKindHTTPService, detection.TargetKindEndpoint}
	}
	severity := m.Severity
	if severity == "" {
		severity = models.SeverityInfo
	}
	return detection.Metadata{
		ID:                   id,
		Name:                 "Mock Detector (test fixture -- not a real vulnerability detector)",
		Category:             "test-fixture",
		SupportedTargetTypes: kinds,
		SupportedMethods:     m.Methods,
		Prerequisites:        m.Prerequisites,
		DefaultSeverity:      severity,
	}
}

// Eligible implements detection.Detector.
func (m *Mock) Eligible(t detection.Target) bool {
	if m.EligibleFunc != nil {
		return m.EligibleFunc(t)
	}
	return true
}

// Detect implements detection.Detector.
func (m *Mock) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	m.calls.Add(1)

	if m.DetectDelay > 0 {
		timer := time.NewTimer(m.DetectDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return detection.Result{}, ctx.Err()
		}
	}

	if m.RequestPath != "" {
		req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, t.URL+m.RequestPath, nil)
		if err != nil {
			return detection.Result{}, fmt.Errorf("detectiontest: build request: %w", err)
		}
		resp, err := x.Do(ctx, t, req)
		if err != nil {
			return detection.Result{}, err
		}
		resp.Body.Close()
	}

	switch m.Behavior {
	case Error:
		return detection.Result{}, fmt.Errorf("detectiontest: simulated detector error")
	case Panic:
		panic("detectiontest: simulated detector panic")
	case Skipped:
		return detection.Result{Outcome: detection.OutcomeSkipped}, nil
	case Finding:
		return detection.Result{Outcome: detection.OutcomeFinding, Findings: []models.Finding{m.finding()}}, nil
	default:
		return detection.Result{Outcome: detection.OutcomeNoFinding}, nil
	}
}

func (m *Mock) finding() models.Finding {
	severity := m.Severity
	if severity == "" {
		severity = models.SeverityInfo
	}
	confidence := m.Confidence
	if confidence == 0 {
		confidence = 1.0
	}
	return models.Finding{
		VulnerabilityType: "mock-test-fixture",
		Title:             "[TEST FIXTURE] mock finding -- not a real vulnerability",
		Description:       "Produced by internal/detection/detectiontest.Mock, a framework test fixture. This does not indicate a real vulnerability was found on any target.",
		Severity:          severity,
		Confidence:        confidence,
		Evidence: []models.Evidence{
			detection.NewRequestResponseEvidence("", "", detection.RequestResponseEvidence{
				Observation: "mock detector fixture -- no real probe logic",
				Reason:      "detectiontest.Mock exists only to exercise the detection framework's lifecycle",
			}),
		},
	}
}

// Calls returns how many times Detect has been invoked, safe for
// concurrent use -- for tests asserting concurrent/total execution
// counts.
func (m *Mock) Calls() int64 {
	return m.calls.Load()
}
