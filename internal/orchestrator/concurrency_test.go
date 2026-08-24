package orchestrator

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Concurrency tests (task section 31) -- run under `go test -race`.
// ScanState is the one piece of live, mutable state a scan touches
// from multiple goroutines (stage-completion callbacks can race with a
// concurrent CLI status poll reading Snapshot()); every method takes
// its own lock, verified here directly.

func TestConcurrency_ConcurrentStageTransitionsAndSnapshots(t *testing.T) {
	s := NewScanState("scan-1", "t")
	s.Start()

	var wg sync.WaitGroup
	for _, st := range stageOrder {
		st := st
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.StartStage(st)
			s.MergeCounters(Counters{RequestsIssued: 1})
			s.AddError(ScanError{Category: ErrorCategoryWarning, Stage: st, Message: "x"})
			s.CompleteStage(st)
		}()
	}

	// Concurrent readers, racing with the writers above. Bounded by
	// iteration count (never an unbounded tight loop): under -race, an
	// unthrottled infinite loop racing a slice-growing writer can
	// balloon memory into the gigabytes within seconds purely from
	// shadow-memory/allocation overhead, which is a test-harness defect,
	// not a real property being verified.
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for i := 0; i < 2000; i++ {
			_ = s.Snapshot()
			_ = s.ProgressPercent()
		}
	}()

	wg.Wait()
	readerWG.Wait()

	snap := s.Snapshot()
	if snap.Counters.RequestsIssued != int64(len(stageOrder)) {
		t.Errorf("RequestsIssued = %d, want %d", snap.Counters.RequestsIssued, len(stageOrder))
	}
	if len(snap.Errors) != len(stageOrder) {
		t.Errorf("len(Errors) = %d, want %d", len(snap.Errors), len(stageOrder))
	}
	for _, sp := range snap.Stages {
		if sp.Status != StageStatusCompleted {
			t.Errorf("stage %s = %q, want COMPLETED", sp.Stage, sp.Status)
		}
	}
}

func TestConcurrency_SnapshotNeverObservesPartialMutation(t *testing.T) {
	s := NewScanState("scan-1", "t")
	const writes = 2000
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < writes; i++ {
			s.AddError(ScanError{Category: ErrorCategoryWarning, Message: "x"})
		}
	}()

	for i := 0; i < 500; i++ {
		snap := s.Snapshot()
		// Every element of the returned Errors slice must itself be a
		// fully-formed, non-corrupted ScanError -- a torn read would
		// surface as an empty Category or a zero OccurredAt on an
		// element that's actually present.
		for _, e := range snap.Errors {
			if e.OccurredAt.IsZero() {
				t.Errorf("observed a torn ScanError: %+v", e)
			}
		}
	}
	wg.Wait()
}

func TestConcurrency_AcquireReleaseScanSlot_BoundsConcurrency(t *testing.T) {
	o := &Orchestrator{Limits: Limits{MaxConcurrentScans: 2}}
	o.init()

	var (
		mu      sync.Mutex
		current int
		maxSeen int
	)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := o.acquireScanSlot(context.Background()); err != nil {
				t.Errorf("acquireScanSlot: %v", err)
				return
			}
			defer o.releaseScanSlot()

			mu.Lock()
			current++
			if current > maxSeen {
				maxSeen = current
			}
			mu.Unlock()

			// Yield briefly so overlapping goroutines have a chance to
			// actually overlap (and thus a chance to violate the bound,
			// if it weren't enforced).
			time.Sleep(2 * time.Millisecond)

			mu.Lock()
			current--
			mu.Unlock()
		}()
	}
	wg.Wait()

	if maxSeen > 2 {
		t.Errorf("observed %d concurrently-held scan slots, want <= 2 (Limits.MaxConcurrentScans)", maxSeen)
	}
}
