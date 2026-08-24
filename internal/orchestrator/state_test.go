package orchestrator

import (
	"testing"
)

// --- Scan state model (task section 3) -------------------------------

func TestNewScanState_InitializesEveryStagePending(t *testing.T) {
	s := NewScanState("scan-1", "example.test")
	snap := s.Snapshot()

	if snap.ScanID != "scan-1" || snap.Target != "example.test" {
		t.Errorf("got ScanID=%q Target=%q", snap.ScanID, snap.Target)
	}
	if snap.Status != StatusQueued {
		t.Errorf("Status = %q, want QUEUED", snap.Status)
	}
	if len(snap.Stages) != len(stageOrder) {
		t.Fatalf("len(Stages) = %d, want %d", len(snap.Stages), len(stageOrder))
	}
	for _, sp := range snap.Stages {
		if sp.Status != StageStatusPending {
			t.Errorf("stage %s status = %q, want PENDING", sp.Stage, sp.Status)
		}
	}
}

func TestScanState_StartTransitionsToRunning(t *testing.T) {
	s := NewScanState("scan-1", "t")
	s.Start()
	snap := s.Snapshot()
	if snap.Status != StatusRunning {
		t.Errorf("Status = %q, want RUNNING", snap.Status)
	}
	if snap.StartedAt.IsZero() {
		t.Error("StartedAt is zero after Start()")
	}
}

func TestScanState_StageLifecycle_StartRunningCompleted(t *testing.T) {
	s := NewScanState("scan-1", "t")
	s.StartStage(StageScope)

	snap := s.Snapshot()
	if snap.CurrentStage != StageScope {
		t.Errorf("CurrentStage = %q, want SCOPE", snap.CurrentStage)
	}
	sp := stageByName(snap, StageScope)
	if sp.Status != StageStatusRunning || sp.StartedAt == nil {
		t.Errorf("SCOPE stage = %+v, want RUNNING with StartedAt set", sp)
	}

	s.CompleteStage(StageScope)
	snap = s.Snapshot()
	sp = stageByName(snap, StageScope)
	if sp.Status != StageStatusCompleted || sp.EndedAt == nil {
		t.Errorf("SCOPE stage = %+v, want COMPLETED with EndedAt set", sp)
	}
}

func TestScanState_StageLifecycle_Failed(t *testing.T) {
	s := NewScanState("scan-1", "t")
	s.StartStage(StageRecon)
	s.FailStage(StageRecon)
	sp := stageByName(s.Snapshot(), StageRecon)
	if sp.Status != StageStatusFailed {
		t.Errorf("status = %q, want FAILED", sp.Status)
	}
}

func TestScanState_StageLifecycle_Cancelled(t *testing.T) {
	s := NewScanState("scan-1", "t")
	s.StartStage(StageDetection)
	s.CancelStage(StageDetection)
	sp := stageByName(s.Snapshot(), StageDetection)
	if sp.Status != StageStatusCancelled {
		t.Errorf("status = %q, want CANCELLED", sp.Status)
	}
}

func TestScanState_SkipRemainingStages_OnlyAffectsPending(t *testing.T) {
	s := NewScanState("scan-1", "t")
	s.StartStage(StageScope)
	s.CompleteStage(StageScope)
	s.StartStage(StageRecon)
	s.FailStage(StageRecon)
	s.SkipRemainingStages()

	snap := s.Snapshot()
	if stageByName(snap, StageScope).Status != StageStatusCompleted {
		t.Error("COMPLETED stage must not be overwritten by SkipRemainingStages")
	}
	if stageByName(snap, StageRecon).Status != StageStatusFailed {
		t.Error("FAILED stage must not be overwritten by SkipRemainingStages")
	}
	for _, st := range stageOrder[2:] {
		if stageByName(snap, st).Status != StageStatusSkipped {
			t.Errorf("stage %s = %q, want SKIPPED", st, stageByName(snap, st).Status)
		}
	}
}

func TestScanState_Finish_SetsCompletedAtAndStatus(t *testing.T) {
	s := NewScanState("scan-1", "t")
	s.Start()
	s.Finish(StatusCompleted)
	snap := s.Snapshot()
	if snap.Status != StatusCompleted {
		t.Errorf("Status = %q, want COMPLETED", snap.Status)
	}
	if snap.CompletedAt == nil {
		t.Fatal("CompletedAt is nil after Finish()")
	}
	if snap.Duration < 0 {
		t.Errorf("Duration = %v, want >= 0", snap.Duration)
	}
}

func TestScanState_AddError_StampsOccurredAtIfUnset(t *testing.T) {
	s := NewScanState("scan-1", "t")
	s.AddError(ScanError{Category: ErrorCategoryDetector, Message: "boom"})
	snap := s.Snapshot()
	if len(snap.Errors) != 1 {
		t.Fatalf("len(Errors) = %d, want 1", len(snap.Errors))
	}
	if snap.Errors[0].OccurredAt.IsZero() {
		t.Error("OccurredAt was not stamped")
	}
}

func TestScanState_HasWarningOrDetectorError(t *testing.T) {
	cases := []struct {
		name string
		cat  ErrorCategory
		want bool
	}{
		{"detector", ErrorCategoryDetector, true},
		{"request", ErrorCategoryRequest, true},
		{"warning", ErrorCategoryWarning, true},
		{"fatal", ErrorCategoryFatal, false},
		{"stage", ErrorCategoryStage, false},
	}
	for _, c := range cases {
		s := NewScanState("scan-1", "t")
		s.AddError(ScanError{Category: c.cat, Message: "x"})
		if got := s.HasWarningOrDetectorError(); got != c.want {
			t.Errorf("%s: HasWarningOrDetectorError() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestScanState_SetFindingsCount(t *testing.T) {
	s := NewScanState("scan-1", "t")
	s.SetFindingsCount(7)
	if got := s.Snapshot().FindingsCount; got != 7 {
		t.Errorf("FindingsCount = %d, want 7", got)
	}
}

func TestScanState_MergeCounters_Accumulates(t *testing.T) {
	s := NewScanState("scan-1", "t")
	s.MergeCounters(Counters{HostsDiscovered: 2, RequestsIssued: 10})
	s.MergeCounters(Counters{HostsDiscovered: 3, RequestsIssued: 5})
	snap := s.Snapshot()
	if snap.Counters.HostsDiscovered != 5 {
		t.Errorf("HostsDiscovered = %d, want 5", snap.Counters.HostsDiscovered)
	}
	if snap.Counters.RequestsIssued != 15 {
		t.Errorf("RequestsIssued = %d, want 15", snap.Counters.RequestsIssued)
	}
}

func TestScanState_SetCounters_ReplacesWholesale(t *testing.T) {
	s := NewScanState("scan-1", "t")
	s.MergeCounters(Counters{HostsDiscovered: 99})
	s.SetCounters(Counters{HostsDiscovered: 1})
	if got := s.Snapshot().Counters.HostsDiscovered; got != 1 {
		t.Errorf("HostsDiscovered = %d, want 1 (SetCounters must replace, not merge)", got)
	}
}

// --- Progress (task sections 15-16) -----------------------------------

func TestProgress_ZeroBeforeAnyStageCompletes(t *testing.T) {
	s := NewScanState("scan-1", "t")
	if got := s.ProgressPercent(); got != 0 {
		t.Errorf("ProgressPercent() = %d, want 0", got)
	}
}

func TestProgress_MonotonicallyIncreasesAsStagesComplete(t *testing.T) {
	s := NewScanState("scan-1", "t")
	last := 0
	for _, st := range stageOrder {
		s.StartStage(st)
		s.CompleteStage(st)
		got := s.ProgressPercent()
		if got < last {
			t.Errorf("stage %s: progress went backwards: %d -> %d", st, last, got)
		}
		last = got
	}
	if last != 100 {
		t.Errorf("final progress = %d, want 100 after FINALIZATION completes", last)
	}
}

func TestProgress_Never100BeforeFinalizationCompletes(t *testing.T) {
	s := NewScanState("scan-1", "t")
	for _, st := range stageOrder {
		if st == StageFinalization {
			break
		}
		s.StartStage(st)
		s.CompleteStage(st)
	}
	if got := s.ProgressPercent(); got >= 100 {
		t.Errorf("ProgressPercent() = %d, want < 100 before FINALIZATION completes", got)
	}
}

func TestProgress_RunningStageDoesNotCountAsComplete(t *testing.T) {
	s := NewScanState("scan-1", "t")
	s.StartStage(StageScope)
	s.CompleteStage(StageScope)
	before := s.ProgressPercent()
	s.StartStage(StageRecon) // RUNNING, not yet COMPLETED
	after := s.ProgressPercent()
	if after != before {
		t.Errorf("progress changed from starting a stage (not completing it): %d -> %d", before, after)
	}
}

func TestProgress_EveryDocumentedCheckpointIsInRange(t *testing.T) {
	for st, pct := range stageProgressPercent {
		if pct < 0 || pct > 100 {
			t.Errorf("stage %s: checkpoint %d out of [0,100]", st, pct)
		}
	}
}

func TestProgress_EveryStageHasACheckpoint(t *testing.T) {
	for _, st := range stageOrder {
		if _, ok := stageProgressPercent[st]; !ok {
			t.Errorf("stage %s has no documented progress checkpoint", st)
		}
	}
}

// --- helpers ------------------------------------------------------------

func stageByName(snap StateSnapshot, stage Stage) StageProgress {
	for _, sp := range snap.Stages {
		if sp.Stage == stage {
			return sp
		}
	}
	return StageProgress{}
}
