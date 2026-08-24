package orchestrator

import (
	"sync"
	"time"
)

// stageProgressPercent is task section 15's progress table -- the
// cumulative percent-complete once the named stage COMPLETES. VERIFICATION
// is deliberately given the SAME checkpoint as DETECTION: every real
// detector today performs its own verification internally, as part of
// one Detect() call (see docs/phase-3-11-scan-orchestrator.md "Why
// VERIFICATION has no separate checkpoint"), so there is no distinct
// unit of work between them to assign a different percentage to.
// RECON and DISCOVERY are likewise both driven by ONE atomic
// internal/orchestration.Pipeline.Run call (task section 7's "do not
// duplicate recon functionality" -- Phase 1's pipeline has no
// intra-run stage hooks to attach finer-grained progress to), so
// DISCOVERY's checkpoint is only reached the instant RECON's is.
//
// These are documented, deliberately chosen numbers (task section 15
// permits any distribution); they are never derived from timing.
var stageProgressPercent = map[Stage]int{
	StageScope:        5,
	StageRecon:        45, // Pipeline.Run performs RECON+DISCOVERY atomically
	StageDiscovery:    45,
	StageDetection:    80, // Engine.Run performs DETECTION+VERIFICATION atomically
	StageVerification: 80,
	StageCorrelation:  88,
	StageRisk:         92,
	StageEvidence:     97,
	StageFinalization: 100,
}

// ScanState is one scan's thread-safe, live progress/status record --
// task section 3. Every mutating method acquires its own lock and
// returns quickly; callers observing a scan in progress (a concurrent
// CLI status poll, a test asserting mid-scan state) must go through
// Snapshot(), never read fields directly.
type ScanState struct {
	mu sync.Mutex

	scanID string
	target string
	status Status

	currentStage Stage
	stages       map[Stage]*StageProgress

	startedAt   time.Time
	completedAt *time.Time

	counters      Counters
	errors        []ScanError
	findingsCount int
}

// NewScanState creates a ScanState for scanID/target with every stage
// initialized to StageStatusPending and overall Status QUEUED.
func NewScanState(scanID, target string) *ScanState {
	s := &ScanState{
		scanID: scanID,
		target: target,
		status: StatusQueued,
		stages: make(map[Stage]*StageProgress, len(stageOrder)),
	}
	for _, st := range stageOrder {
		s.stages[st] = &StageProgress{Stage: st, Status: StageStatusPending}
	}
	return s
}

// Start transitions the scan to RUNNING and records its start time.
// Idempotent-safe to call once at the top of Orchestrator.Run.
func (s *ScanState) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = StatusRunning
	s.startedAt = time.Now().UTC()
}

// StartStage marks stage RUNNING and sets it as the current stage.
func (s *ScanState) StartStage(stage Stage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.currentStage = stage
	sp := s.stages[stage]
	sp.Status = StageStatusRunning
	sp.StartedAt = &now
}

// CompleteStage marks stage COMPLETED.
func (s *ScanState) CompleteStage(stage Stage) {
	s.setStageTerminal(stage, StageStatusCompleted)
}

// FailStage marks stage FAILED.
func (s *ScanState) FailStage(stage Stage) {
	s.setStageTerminal(stage, StageStatusFailed)
}

// CancelStage marks stage CANCELLED.
func (s *ScanState) CancelStage(stage Stage) {
	s.setStageTerminal(stage, StageStatusCancelled)
}

// SkipRemainingStages marks every stage still PENDING (i.e. never
// started) as SKIPPED -- called once when a hard failure or
// cancellation ends the scan before every stage ran, so a finished
// scan's stage list never leaves a later stage merely "PENDING" (task
// section 2's implicit "every stage reaches SOME terminal-shaped state
// once the scan itself is done").
func (s *ScanState) SkipRemainingStages() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range stageOrder {
		if s.stages[st].Status == StageStatusPending {
			s.stages[st].Status = StageStatusSkipped
		}
	}
}

func (s *ScanState) setStageTerminal(stage Stage, status StageStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	sp := s.stages[stage]
	sp.Status = status
	sp.EndedAt = &now
}

// Finish transitions the scan to a terminal Status and records its
// completion time. Called exactly once, from a defer in
// Orchestrator.Run, so it always runs regardless of which stage
// returned early or why (task section 14's "no timeout should bypass
// cleanup," applied to state bookkeeping).
func (s *ScanState) Finish(status Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	s.status = status
	s.completedAt = &now
}

// AddError appends err, stamping OccurredAt if unset.
func (s *ScanState) AddError(e ScanError) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	s.errors = append(s.errors, e)
}

// HasWarningOrDetectorError reports whether any recorded error is a
// non-fatal, non-stage category -- used to decide
// StatusCompletedWithWarnings vs plain StatusCompleted.
func (s *ScanState) HasWarningOrDetectorError() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.errors {
		switch e.Category {
		case ErrorCategoryDetector, ErrorCategoryRequest, ErrorCategoryWarning:
			return true
		}
	}
	return false
}

// SetCounters replaces the current Counters wholesale -- callers pass a
// fully-computed Counters value after each stage rather than
// incrementing individual fields, since each stage's own subsystem
// (Pipeline, detection.Engine, correlation.Engine) already returns its
// own authoritative totals.
func (s *ScanState) SetCounters(c Counters) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counters = c
}

// MergeCounters adds delta's non-zero fields into the current Counters
// -- used where a value accumulates across stages (e.g. RequestsIssued
// from both recon and detection) rather than being replaced.
func (s *ScanState) MergeCounters(delta Counters) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counters.HostsDiscovered += delta.HostsDiscovered
	s.counters.ServicesFound += delta.ServicesFound
	s.counters.HTTPServicesFound += delta.HTTPServicesFound
	s.counters.TechnologiesFound += delta.TechnologiesFound
	s.counters.EndpointsFound += delta.EndpointsFound
	s.counters.TargetsConsidered += delta.TargetsConsidered
	s.counters.DetectorRuns += delta.DetectorRuns
	s.counters.RequestsIssued += delta.RequestsIssued
	s.counters.RawFindings += delta.RawFindings
	s.counters.Duplicates += delta.Duplicates
	s.counters.CanonicalFindings += delta.CanonicalFindings
	s.counters.EvidenceItems += delta.EvidenceItems
}

// SetFindingsCount records the final findings count -- task section 3.
func (s *ScanState) SetFindingsCount(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findingsCount = n
}

// ProgressPercent returns the current deterministic progress
// percentage: the HIGHEST stageProgressPercent checkpoint among every
// stage currently COMPLETED, or 0 if none has completed yet. Never
// derived from elapsed time (task section 16) and never 100 before
// FINALIZATION itself completes (stageProgressPercent[StageFinalization]
// is the only 100 in the table, and it's only reachable by that stage
// itself completing).
func (s *ScanState) ProgressPercent() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.progressPercentLocked()
}

func (s *ScanState) progressPercentLocked() int {
	max := 0
	for _, st := range stageOrder {
		if s.stages[st].Status == StageStatusCompleted {
			if pct := stageProgressPercent[st]; pct > max {
				max = pct
			}
		}
	}
	return max
}

// Snapshot returns an immutable, deep copy of the current state --
// the only safe way to read a ScanState from outside its own goroutine.
func (s *ScanState) Snapshot() StateSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	stages := make([]StageProgress, len(stageOrder))
	for i, st := range stageOrder {
		sp := *s.stages[st] // copy
		stages[i] = sp
	}

	errs := make([]ScanError, len(s.errors))
	copy(errs, s.errors)

	var duration time.Duration
	if !s.startedAt.IsZero() {
		end := time.Now().UTC()
		if s.completedAt != nil {
			end = *s.completedAt
		}
		duration = end.Sub(s.startedAt)
	}

	return StateSnapshot{
		ScanID:          s.scanID,
		Target:          s.target,
		Status:          s.status,
		CurrentStage:    s.currentStage,
		Stages:          stages,
		StartedAt:       s.startedAt,
		CompletedAt:     s.completedAt,
		Duration:        duration,
		ProgressPercent: s.progressPercentLocked(),
		Counters:        s.counters,
		Errors:          errs,
		FindingsCount:   s.findingsCount,
	}
}
