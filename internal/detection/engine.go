package detection

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"sakanner/internal/storage"
	"sakanner/pkg/models"
)

// Engine runs a Registry's enabled detectors against a scan job's Phase
// 2 recon output, normalizes and deduplicates whatever findings result,
// and persists them -- the "Detector Selection -> Detector Execution ->
// Evidence Collection -> Finding Normalization -> Finding
// Deduplication -> Finding Storage" portion of the pipeline described
// in docs/phase-3-1-detection-engine.md.
type Engine struct {
	Registry *Registry
	Store    storage.Store
	Executor *Executor
	Logger   *slog.Logger
	// Concurrency bounds how many (detector, target) pairs run at once.
	// Executor.cfg.Concurrency separately bounds in-flight HTTP requests
	// -- the two are deliberately independent, since a detector may do
	// non-network work (e.g. inspecting already-fetched Technologies)
	// between requests.
	Concurrency int
}

// RunOptions configures one Engine.Run call.
type RunOptions struct {
	ScanJobID string
}

// DetectorError records one detector's failure against one target,
// kept distinct from both a Finding and a clean no-finding Result -- see
// Detector's doc comment for why a detector error must never abort the
// rest of the scan.
type DetectorError struct {
	DetectorID string
	TargetURL  string
	Err        error
}

func (e DetectorError) Error() string {
	return fmt.Sprintf("detector %s against %s: %v", e.DetectorID, e.TargetURL, e.Err)
}

// RunSummary reports what one Engine.Run call did.
type RunSummary struct {
	TargetsConsidered int
	// EligibleTargets counts every (detector, target) pair that passed
	// both supportsTarget and the detector's own Eligible check -- i.e.
	// every pair Run WOULD attempt, computed in the same sequential
	// selection loop that decides whether to schedule work at all, so
	// it costs nothing beyond what Run already does. Under normal
	// (non-cancelled) operation this equals DetectorRuns, since every
	// eligible pair that gets scheduled goes on to actually run; the
	// two are tracked separately because they answer different
	// questions -- "how much work exists to do" (EligibleTargets) vs
	// "how much of it actually completed" (DetectorRuns) -- which
	// diverge under cancellation, and matter independently to a caller
	// trying to distinguish "nothing was eligible" from "something was
	// eligible but didn't finish."
	EligibleTargets int
	DetectorRuns    int
	FindingsCreated int
	Duplicates      int
	Errors          []DetectorError
	RequestsIssued  int64
	Cancelled       bool
}

// Run loads targets for opts.ScanJobID (via BuildTargets), runs every
// enabled, eligible detector against every target it applies to, and
// persists the resulting, deduplicated findings. It always returns a
// RunSummary describing what happened so far, even when ctx is
// cancelled partway through or an individual detector call panics or
// errors -- only a failure to load targets or to persist a finding
// (storage itself is unavailable) is returned as a non-nil error.
func (e *Engine) Run(ctx context.Context, opts RunOptions) (RunSummary, error) {
	var summary RunSummary

	targets, err := BuildTargets(ctx, e.Store, opts.ScanJobID)
	if err != nil {
		return summary, fmt.Errorf("detection: building targets: %w", err)
	}
	summary.TargetsConsidered = len(targets)

	existing, err := e.Store.Findings().ListByScanJob(ctx, opts.ScanJobID)
	if err != nil {
		return summary, fmt.Errorf("detection: loading existing findings: %w", err)
	}

	detectors := e.Registry.enabledDetectors()
	if len(detectors) == 0 || len(targets) == 0 {
		if ctx.Err() != nil {
			summary.Cancelled = true
		}
		return summary, nil
	}

	concurrency := e.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	logger := e.Logger
	if logger == nil {
		logger = slog.Default()
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)

	var (
		mu              sync.Mutex
		found           []models.Finding
		errs            []DetectorError
		runCount        int
		eligibleTargets int
	)

	for _, d := range detectors {
		d := d
		meta := d.Metadata()
		for _, t := range targets {
			t := t
			if !supportsTarget(meta, t) || !d.Eligible(t) {
				continue
			}
			eligibleTargets++

			g.Go(func() (err error) {
				// A single detector's Detect implementation panicking
				// (a bug in a future detector) must not take down the
				// whole engine run -- recovered here and recorded as a
				// DetectorError, exactly like any other detector
				// failure, per the "error isolation" requirement.
				defer func() {
					if r := recover(); r != nil {
						mu.Lock()
						errs = append(errs, DetectorError{DetectorID: meta.ID, TargetURL: t.URL, Err: fmt.Errorf("panic: %v", r)})
						mu.Unlock()
					}
				}()

				if gctx.Err() != nil {
					return nil
				}

				result, detErr := d.Detect(gctx, t, e.Executor)

				mu.Lock()
				runCount++
				mu.Unlock()

				if detErr != nil {
					logger.Warn("detector error", slog.String("detector_id", meta.ID), slog.String("target", t.URL), slog.String("error", detErr.Error()))
					mu.Lock()
					errs = append(errs, DetectorError{DetectorID: meta.ID, TargetURL: t.URL, Err: detErr})
					mu.Unlock()
					return nil // a detector error is isolated, not propagated to the errgroup (which would cancel every other in-flight detector)
				}

				if result.Outcome == OutcomeFinding && len(result.Findings) > 0 {
					now := time.Now().UTC()
					mu.Lock()
					for _, f := range result.Findings {
						found = append(found, normalizeFinding(f, d, t, now))
					}
					mu.Unlock()
				}
				return nil
			})
		}
	}

	// g.Wait's error is always nil here: every g.Go func above returns
	// nil unconditionally, so errors never propagate through the
	// errgroup itself (which would also cancel gctx and, via it, every
	// other in-flight detector call -- exactly the opposite of "a
	// detector failure must not crash the entire scan"). Detector
	// errors are collected in errs instead, entirely outside the
	// errgroup's own error path.
	_ = g.Wait()

	summary.EligibleTargets = eligibleTargets
	summary.DetectorRuns = runCount
	summary.Errors = errs
	if e.Executor != nil {
		summary.RequestsIssued = e.Executor.RequestCount()
	}
	if ctx.Err() != nil {
		summary.Cancelled = true
	}

	kept, duplicates := Deduplicate(existing, found)
	summary.Duplicates = duplicates

	// Persistence uses ctx, matching every other stage's convention
	// (orchestration.Pipeline's own per-item persistence calls do the
	// same) -- a cancelled scan simply stops persisting new findings at
	// the point of cancellation rather than losing already-committed
	// ones, and whatever was found before cancellation is not silently
	// discarded.
	for _, f := range kept {
		if err := e.Store.Findings().Create(ctx, f); err != nil {
			return summary, fmt.Errorf("detection: persisting finding %s: %w", f.ID, err)
		}
		summary.FindingsCreated++
	}

	return summary, nil
}

// supportsTarget applies a detector's declarative Metadata (SupportedTargetTypes/SupportedMethods)
// as the engine's first, cheap filter, before ever calling the
// detector's own Eligible -- "the core engine must NOT blindly run
// every detector against every asset."
func supportsTarget(meta Metadata, t Target) bool {
	kindOK := false
	for _, k := range meta.SupportedTargetTypes {
		if k == t.Kind {
			kindOK = true
			break
		}
	}
	if !kindOK {
		return false
	}
	if len(meta.SupportedMethods) == 0 || t.Kind != TargetKindEndpoint {
		return true
	}
	for _, m := range meta.SupportedMethods {
		if m == t.Method {
			return true
		}
	}
	return false
}
