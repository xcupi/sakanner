package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"sakanner/internal/correlation"
	"sakanner/internal/evidence"
	"sakanner/internal/risk"
	"sakanner/pkg/models"
)

// --- Backpressure (task section 33) ------------------------------------

func TestBackpressure_AcquireScanSlot_BlocksWhenFull(t *testing.T) {
	o := &Orchestrator{Limits: Limits{MaxConcurrentScans: 1}}
	o.init()

	if err := o.acquireScanSlot(context.Background()); err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// A second acquire must block (the queue is bounded, task section
	// 33: "do not create unlimited goroutines") until the first slot is
	// released -- verified via a short timeout race rather than
	// unbounded blocking in the test itself.
	acquired := make(chan error, 1)
	go func() {
		acquired <- o.acquireScanSlot(context.Background())
	}()

	select {
	case <-acquired:
		t.Fatal("second acquireScanSlot returned immediately, want it to block while the slot is held")
	case <-time.After(50 * time.Millisecond):
	}

	o.releaseScanSlot()
	select {
	case err := <-acquired:
		if err != nil {
			t.Errorf("second acquire after release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second acquireScanSlot never unblocked after release")
	}
}

func TestBackpressure_AcquireScanSlot_RespectsContextCancellation(t *testing.T) {
	o := &Orchestrator{Limits: Limits{MaxConcurrentScans: 1}}
	o.init()
	_ = o.acquireScanSlot(context.Background()) // fill the only slot

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- o.acquireScanSlot(ctx) }()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("acquireScanSlot error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("acquireScanSlot did not return after context cancellation")
	}
}

// --- Stage timeout (task section 14) ------------------------------------

func TestWithStageTimeout_NoBoundWhenUnconfigured(t *testing.T) {
	o := &Orchestrator{}
	o.init()
	ctx, cancel := o.withStageTimeout(context.Background())
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Error("context has a deadline despite no StageTimeout configured")
	}
}

func TestWithStageTimeout_AppliesConfiguredBound(t *testing.T) {
	o := &Orchestrator{Limits: Limits{StageTimeout: 10 * time.Millisecond}}
	o.init()
	ctx, cancel := o.withStageTimeout(context.Background())
	defer cancel()
	if _, ok := ctx.Deadline(); !ok {
		t.Error("context has no deadline despite StageTimeout configured")
	}
	<-ctx.Done()
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Errorf("ctx.Err() = %v, want DeadlineExceeded", ctx.Err())
	}
}

// --- isCancellation / terminalStatus -------------------------------------

func TestIsCancellation_WrappedContextCanceled(t *testing.T) {
	wrapped := errors.New("wrapped: " + context.Canceled.Error())
	if isCancellation(false, wrapped) {
		t.Error("a plain error string containing the words must NOT satisfy errors.Is -- only a real wrapped error should")
	}
	real := errWrap(context.Canceled)
	if !isCancellation(false, real) {
		t.Error("a genuinely wrapped context.Canceled must be recognized")
	}
}

func TestIsCancellation_DeadlineExceeded(t *testing.T) {
	if !isCancellation(false, context.DeadlineExceeded) {
		t.Error("context.DeadlineExceeded must be recognized as a cancellation")
	}
}

func TestIsCancellation_CtxDoneRegardlessOfErrorShape(t *testing.T) {
	if !isCancellation(true, errors.New("some unrelated error")) {
		t.Error("an already-Done ctx must count as a cancellation regardless of the error's own shape")
	}
}

func TestIsCancellation_OrdinaryErrorWithLiveContext(t *testing.T) {
	if isCancellation(false, errors.New("boom")) {
		t.Error("an ordinary error with a live context must not be classified as a cancellation")
	}
}

func errWrap(err error) error {
	return &wrappedErr{err}
}

type wrappedErr struct{ err error }

func (w *wrappedErr) Error() string { return "wrapped: " + w.err.Error() }
func (w *wrappedErr) Unwrap() error { return w.err }

func TestTerminalStatus_CancellationTakesPriorityOverWarnings(t *testing.T) {
	o := &Orchestrator{}
	s := NewScanState("s", "t")
	s.AddError(ScanError{Category: ErrorCategoryWarning, Message: "x"})
	got := o.terminalStatus(context.Canceled, true, s)
	if got != StatusCancelled {
		t.Errorf("terminalStatus = %q, want CANCELLED", got)
	}
}

func TestTerminalStatus_FailedForOrdinaryError(t *testing.T) {
	o := &Orchestrator{}
	s := NewScanState("s", "t")
	got := o.terminalStatus(errors.New("boom"), false, s)
	if got != StatusFailed {
		t.Errorf("terminalStatus = %q, want FAILED", got)
	}
}

func TestTerminalStatus_CompletedWithWarningsWhenDetectorErrorsRecorded(t *testing.T) {
	o := &Orchestrator{}
	s := NewScanState("s", "t")
	s.AddError(ScanError{Category: ErrorCategoryDetector, Message: "one detector failed"})
	got := o.terminalStatus(nil, false, s)
	if got != StatusCompletedWithWarnings {
		t.Errorf("terminalStatus = %q, want COMPLETED_WITH_WARNINGS", got)
	}
}

func TestTerminalStatus_PlainCompletedWhenClean(t *testing.T) {
	o := &Orchestrator{}
	s := NewScanState("s", "t")
	got := o.terminalStatus(nil, false, s)
	if got != StatusCompleted {
		t.Errorf("terminalStatus = %q, want COMPLETED", got)
	}
}

func TestTerminalStatus_CancelledWhenCtxDoneEvenWithNilError(t *testing.T) {
	o := &Orchestrator{}
	s := NewScanState("s", "t")
	got := o.terminalStatus(nil, true, s)
	if got != StatusCancelled {
		t.Errorf("terminalStatus = %q, want CANCELLED (task section 13: never COMPLETED when ctx is done)", got)
	}
}

// --- summarize ------------------------------------------------------------

func TestSummarize_CountsBySeverity(t *testing.T) {
	packages := []evidence.FindingPackage{
		{Finding: correlation.CanonicalFinding{Severity: models.SeverityCritical}},
		{Finding: correlation.CanonicalFinding{Severity: models.SeverityCritical}},
		{Finding: correlation.CanonicalFinding{Severity: models.SeverityHigh}},
		{Finding: correlation.CanonicalFinding{Severity: models.SeverityMedium}},
		{Finding: correlation.CanonicalFinding{Severity: models.SeverityLow}},
		{Finding: correlation.CanonicalFinding{Severity: models.SeverityInfo}},
	}
	s := summarize(packages)
	if s.Total != 6 || s.Critical != 2 || s.High != 1 || s.Medium != 1 || s.Low != 1 || s.Info != 1 {
		t.Errorf("summarize() = %+v", s)
	}
}

func TestSummarize_EmptyIsValid(t *testing.T) {
	s := summarize(nil)
	if s.Total != 0 {
		t.Errorf("Total = %d, want 0 for an empty finding set (task section 35: valid, not an error)", s.Total)
	}
}

// --- safeBuildPackage error isolation (task section 11 applied to EVIDENCE)

func TestSafeBuildPackage_NormalFindingProducesNoError(t *testing.T) {
	o := &Orchestrator{EvidenceLimits: evidence.DefaultLimits()}
	cf := correlation.CanonicalFinding{FindingID: "f1", VulnerabilityType: "reflected_xss", Status: correlation.StatusNew}
	a := risk.Assessment{FindingID: "f1"}
	pkg, err := o.safeBuildPackage(cf, a)
	if err != nil {
		t.Fatalf("safeBuildPackage: %v", err)
	}
	if pkg.Finding.FindingID != "f1" {
		t.Errorf("pkg.Finding.FindingID = %q, want f1", pkg.Finding.FindingID)
	}
}
