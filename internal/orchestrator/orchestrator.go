package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"sakanner/internal/auth"
	"sakanner/internal/chains"
	"sakanner/internal/correlation"
	"sakanner/internal/detection"
	"sakanner/internal/evidence"
	"sakanner/internal/logging"
	"sakanner/internal/mutation"
	"sakanner/internal/orchestration"
	"sakanner/internal/parameters"
	"sakanner/internal/reporting"
	"sakanner/internal/risk"
	"sakanner/internal/scope"
	"sakanner/internal/storage"
	"sakanner/pkg/models"
)

// Options configures one Orchestrator.Run call -- task section 5's
// "user-provided target."
type Options struct {
	// Target is the raw operator-supplied target string -- any format
	// internal/target.Parse already accepts (domain, hostname, IPv4,
	// IPv6, CIDR, or a URL to extract a host from). Never expanded
	// beyond what Phase 1/2 already support (task section 5).
	Target string
	// Ports overrides the Pipeline's own configured default ports for
	// this scan, if non-empty.
	Ports []int

	// ProfileLabel is stamped into Result.Profile verbatim -- this
	// package never inspects or branches on its value (see model.go's
	// package doc: internal/orchestrator contains no profile-name
	// conditionals). The caller (cmd/scanner, via internal/policy)
	// decides what it means; empty preserves every pre-Phase-3.12
	// caller's output unchanged.
	ProfileLabel string

	// DetectionDisabled, when true, skips the DETECTION+VERIFICATION
	// stage entirely -- Run never constructs a detection.Executor or
	// invokes detection.Engine.Run at all, and DetectorSummary.State is
	// set to DetectionStateDisabledByProfile. This is the mechanism
	// behind Phase 3.12's "recon" profile: "detection disabled" is
	// represented as a deliberate, structural per-scan choice, not
	// achieved by leaving the detector registry empty (which would be
	// reported as DetectionStateNotRun -- a different, less accurate
	// claim; see model.go's DetectionState doc comment).
	//
	// The zero value (false) is this field's ENTIRE backward-compatible
	// contract: every Options{} literal written before Phase 3.12
	// (which never mentions this field) continues to run detection
	// exactly as before.
	DetectionDisabled bool

	// CrawlOverride, if non-nil, replaces the Orchestrator's own
	// Pipeline.CrawlEnabled/CrawlMaxDepth/CrawlMaxPages for THIS scan
	// only -- Run makes a shallow copy of *o.Pipeline with these 3
	// fields substituted rather than mutating the shared Pipeline, so
	// concurrent Run calls against one Orchestrator instance may safely
	// use different crawl settings at once (task's "concurrent scans
	// using different profiles" requirement) without racing on shared
	// state. Every other Pipeline field (Store, Resolver, rate
	// limiters, concurrency, AllowReservedRanges, tool backends, ...)
	// is intentionally left shared across concurrent scans -- those are
	// operator/deployment-level resources, not per-scan policy choices.
	//
	// nil (the default) preserves every pre-Phase-3.12 caller's
	// behavior unchanged: Run uses o.Pipeline's own configured crawl
	// settings directly.
	CrawlOverride *CrawlSettings

	// AuthSession is an already-authenticated Phase 3.14 session --
	// resolved and authenticated by the CALLER (e.g. cmd/scanner, via
	// internal/auth) strictly BEFORE Run is ever invoked, exactly
	// mirroring how ProfileLabel/CrawlOverride are pre-resolved policy
	// choices threaded through as inert configuration rather than
	// computed inside this package. This package performs NO
	// authentication of its own -- see model.go's package doc
	// ("this package owns SEQUENCING ONLY") and
	// docs/phase-3-14-authentication.md "Where authentication happens"
	// for why: keeping login entirely outside Run is what makes "an
	// invalid/failed authentication attempt creates no scan job"
	// (task section 12) automatic, with no special-casing inside this
	// package's own stage sequence. nil (the default, and every
	// pre-Phase-3.14 caller) means the scan proceeds unauthenticated --
	// Result.AuthState reports auth.StateUnauthenticated in that case.
	AuthSession *auth.Session
}

// CrawlSettings is the per-scan crawler policy Options.CrawlOverride
// carries -- see its doc comment. ParameterLimits travels alongside
// Enabled/MaxDepth/MaxPages (Phase 3.13) rather than as a separate
// Options field: input discovery is gated by, and lives entirely
// inside, the same crawl step these settings already control (see
// orchestration.Pipeline.ParameterLimits' own doc comment).
type CrawlSettings struct {
	Enabled         bool
	MaxDepth        int
	MaxPages        int
	ParameterLimits parameters.Limits
	// StartPath is the path crawling begins from instead of the
	// target's own root "/" -- see orchestration.Pipeline.CrawlStartPath's
	// own doc comment. Empty means "/", unchanged from every prior
	// phase's behavior. The caller (cmd/scanner) is responsible for
	// resolving the final effective value (CLI flag, else config
	// default, else empty) before constructing this struct, mirroring
	// how Enabled/MaxDepth/MaxPages above are already fully resolved
	// by the caller rather than merged here.
	StartPath string
}

// Orchestrator sequences the full pipeline (task section 1) from a
// single Options.Target to a Result. Every dependency is a fully
// caller-constructed instance of an EXISTING package's own type --
// this struct wires them together and owns no detection, recon, or
// scoring logic of its own. Safe for concurrent use: Run may be called
// concurrently (bounded by Limits.MaxConcurrentScans, task section 31),
// each call gets its own scan ID and its own ScanState.
type Orchestrator struct {
	Store storage.Store

	// Pipeline runs SCOPE+RECON+DISCOVERY (task sections 7-8) --
	// caller-constructed and fully configured (Store/Resolver/
	// Fingerprinter/backends/concurrency/rate limits/AllowReservedRanges
	// all already set, exactly as cmd/scanner/scan.go already builds one
	// today). The orchestrator calls Pipeline.Run once per scan with a
	// propagated ScanJobID (see internal/orchestration.RunOptions) and
	// never modifies Pipeline's own fields.
	Pipeline *orchestration.Pipeline

	// DetectionRegistry is the detector registry (task section 9) --
	// e.g. cmd/scanner's own productionRegistry(). The orchestrator
	// never registers or constructs detectors itself.
	DetectionRegistry *detection.Registry
	// DetectionExecutorConfig configures the per-scan detection.Executor
	// this orchestrator builds fresh for each Run call (task section
	// 10) -- a fresh Executor per scan because it must be built against
	// THIS scan's own scope.Validator snapshot (see
	// resolveAndRegisterTarget's doc comment), never a shared, possibly
	// scope-stale instance.
	DetectionExecutorConfig detection.ExecutorConfig
	// DetectionConcurrency bounds concurrent (detector, target) pairs --
	// task section 10's "max concurrent detectors."
	DetectionConcurrency int

	// EvidenceLimits configures Phase 3.10's evidence bounds (response
	// truncation, max evidence items/finding, etc.) -- task section 32's
	// "maximum evidence," already implemented by internal/evidence and
	// simply wired through here.
	EvidenceLimits evidence.Limits

	Logger *slog.Logger
	Limits Limits

	initOnce  sync.Once
	limits    Limits
	scanSlots chan struct{}
}

func (o *Orchestrator) init() {
	o.initOnce.Do(func() {
		o.limits = o.Limits.normalized()
		o.scanSlots = make(chan struct{}, o.limits.MaxConcurrentScans)
	})
}

func (o *Orchestrator) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.Default()
}

// acquireScanSlot blocks until a concurrent-scan slot is free or ctx is
// done -- task section 31's concurrency bound and task section 33's
// backpressure requirement ("do not create unlimited goroutines; use
// bounded queues"): the channel IS the bounded queue, and a caller
// waiting on it blocks rather than spawning unbounded work.
func (o *Orchestrator) acquireScanSlot(ctx context.Context) error {
	select {
	case o.scanSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (o *Orchestrator) releaseScanSlot() {
	<-o.scanSlots
}

// withStageTimeout returns a derived context bounded by
// o.limits.StageTimeout (task section 14's "stage timeout"), or ctx
// unchanged (with a no-op cancel) if no stage timeout is configured.
func (o *Orchestrator) withStageTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if o.limits.StageTimeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, o.limits.StageTimeout)
}

// Run executes the full pipeline for opts.Target -- task section 1.
// It always returns a Result (even on failure/cancellation, mirroring
// orchestration.Pipeline.Run's and detection.Engine.Run's own
// established "always return what happened so far" contract) alongside
// any terminal error.
func (o *Orchestrator) Run(ctx context.Context, opts Options) (result Result, err error) {
	o.init()

	// scanID/state/logger are constructed BEFORE acquireScanSlot (even
	// though a scan that never gets a slot never truly starts running)
	// so that EVERY exit path -- including "blocked waiting for a slot
	// and the caller's context was cancelled first" -- goes through the
	// same single finalization defer below and returns a properly
	// populated, correctly-statused Result, never a bare zero-value
	// Result{} with an empty Status (a real bug caught by
	// TestPhase3_11_Orchestrator_CancelBeforeStart: an earlier version
	// returned Result{} directly from the acquire-failure path, which
	// has Status == "" instead of CANCELLED).
	scanID := uuid.NewString()
	state := NewScanState(scanID, opts.Target)
	logger := logging.WithScanJob(o.logger(), scanID)

	var (
		runErr                error
		recon                 ReconSummary
		input                 InputSummary
		crawlSum              CrawlSummary
		authenticatedRequests int
		sessionExpired        bool
		detSum                DetectorSummary
		packages              []evidence.FindingPackage
		// ctxDone captures whether ctx was observably Done at the
		// natural end of this scan's own work -- see the two defers
		// registered together below (right where ScanTimeout's
		// context.WithTimeout is set up) for why this must be a
		// CAPTURED snapshot rather than something the finalize closure
		// reads by calling ctx.Err() directly. A context's own cancel
		// func, once called, permanently marks that context Done --
		// indistinguishable by itself from a genuine caller-side
		// cancellation. When Limits.ScanTimeout is positive, this
		// package must release that context's timer before Run returns
		// (routine cleanup), but doing so via a bare `defer cancel()`
		// registered at the WithTimeout call site would, per Go's LIFO
		// defer order, run BEFORE the finalize closure below (which is
		// registered earlier in source order, so runs LAST) -- making
		// EVERY scan using a positive ScanTimeout look cancelled by the
		// time terminalStatus ran, even one that completed cleanly with
		// time to spare. This was a latent bug in this package since
		// Phase 3.11: invisible while every caller left ScanTimeout at
		// 0 (this whole mechanism dormant), and only surfaced once
		// Phase 3.12 profile resolution started giving the CLI a real,
		// positive ScanTimeout by default. ctxDone is snapshotted BEFORE
		// cleanup fires (see below), so the finalize closure sees the
		// true pre-cleanup state regardless.
		ctxDone bool
	)

	// This is the ONLY place result/err (the named returns) are ever
	// set. Every early exit below sets runErr and does a naked return;
	// the defer -- which always runs AFTER the function body's own
	// return statement has been evaluated, but BEFORE control actually
	// reaches the caller -- is what finalizes state (state.Finish, so
	// its Snapshot reflects the TERMINAL status) and only THEN builds
	// the Result from that now-final snapshot. Building the Result at
	// each individual return site (an earlier draft's approach) reads a
	// snapshot that still says RUNNING, since state.Finish() hadn't
	// been called yet at that point -- exactly the bug this structure
	// avoids.
	defer func() {
		status := o.terminalStatus(runErr, ctxDone, state)
		state.SkipRemainingStages()
		state.Finish(status)
		event := "scan_completed"
		switch status {
		case StatusFailed:
			event = "scan_failed"
		case StatusCancelled:
			event = "scan_cancelled"
		}
		logger.Info(event, slog.String("status", string(status)), slog.Int("findings_count", len(packages)))
		result = o.buildResult(scanID, opts.Target, opts.ProfileLabel, opts.AuthSession, state, recon, input, crawlSum, authenticatedRequests, sessionExpired, detSum, packages)
		err = runErr
	}()

	if slotErr := o.acquireScanSlot(ctx); slotErr != nil {
		runErr = fmt.Errorf("orchestrator: waiting for a free concurrent-scan slot: %w", slotErr)
		return
	}
	defer o.releaseScanSlot()

	if o.limits.ScanTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.limits.ScanTimeout)
		defer cancel()
	}
	// Registered AFTER (so it runs BEFORE, per LIFO) the ScanTimeout
	// cancel above when one was registered, and unconditionally
	// otherwise -- either way this captures ctx.Err() at the true end
	// of this scan's work, before this package's own cleanup can touch
	// it, while still catching a genuine caller-side cancellation of
	// the ORIGINAL, un-wrapped ctx exactly as before.
	defer func() { ctxDone = ctx.Err() != nil }()

	state.Start()
	logger.Info("scan_started", slog.String("target", opts.Target))

	// ---------------------------------------------------------------
	// SCOPE (task section 6)
	// ---------------------------------------------------------------
	state.StartStage(StageScope)
	logger.Info("stage_started", slog.String("stage", string(StageScope)))
	scopeCtx, cancelScope := o.withStageTimeout(ctx)
	target, targetErr := o.resolveAndRegisterTarget(scopeCtx, opts.Target)
	cancelScope()
	if targetErr != nil {
		runErr = targetErr
		state.AddError(ScanError{Category: ErrorCategoryFatal, Stage: StageScope, Message: targetErr.Error()})
		state.FailStage(StageScope)
		return
	}
	state.CompleteStage(StageScope)
	logger.Info("stage_completed", slog.String("stage", string(StageScope)))
	if ctx.Err() != nil {
		runErr = ctx.Err()
		return
	}

	// ---------------------------------------------------------------
	// RECON + DISCOVERY (task sections 7-8) -- bundled: Pipeline.Run
	// performs both atomically in one call; see stageProgressPercent's
	// doc comment for why these two stages share one checkpoint.
	// ---------------------------------------------------------------
	state.StartStage(StageRecon)
	state.StartStage(StageDiscovery)
	logger.Info("stage_started", slog.String("stage", string(StageRecon)))
	reconCtx, cancelRecon := o.withStageTimeout(ctx)
	pipeline := o.scanPipeline(opts.CrawlOverride, opts.AuthSession)
	job, pipelineErr := pipeline.Run(reconCtx, orchestration.RunOptions{TargetIDs: []string{target.ID}, Ports: opts.Ports, ScanJobID: scanID})
	// Captured BEFORE cancelRecon() below, for the same reason Run's
	// own ctxDone is captured before its cleanup: cancelRecon (when
	// StageTimeout > 0) permanently marks reconCtx Done the instant
	// it's called, so checking reconCtx.Err() AFTER calling it would
	// misclassify every ordinary RECON failure as a cancellation, not
	// only a genuine one.
	reconCtxDone := reconCtx.Err() != nil
	cancelRecon()
	if pipelineErr != nil {
		runErr = pipelineErr
		if isCancellation(reconCtxDone, pipelineErr) {
			state.CancelStage(StageRecon)
			state.CancelStage(StageDiscovery)
		} else {
			state.AddError(ScanError{Category: ErrorCategoryStage, Stage: StageRecon, Message: pipelineErr.Error()})
			state.FailStage(StageRecon)
			state.FailStage(StageDiscovery)
		}
		return
	}
	state.CompleteStage(StageRecon)
	state.CompleteStage(StageDiscovery)
	logger.Info("stage_completed", slog.String("stage", string(StageRecon)))

	recon = o.buildReconSummary(ctx, job.ID)
	input = o.buildInputSummary(ctx, job.ID, job.Warnings)
	crawlSum = CrawlSummary{
		PublicURLs:             job.AuthCrawlStats.PublicPages,
		AuthenticatedURLs:      job.AuthCrawlStats.AuthenticatedPages,
		AuthenticatedEndpoints: job.AuthCrawlStats.AuthenticatedEndpoints,
	}
	authenticatedRequests = job.AuthCrawlStats.AuthenticatedRequests
	sessionExpired = job.AuthCrawlStats.SessionExpired
	state.MergeCounters(Counters{
		HostsDiscovered: recon.HostCount, ServicesFound: recon.ServiceCount,
		HTTPServicesFound: recon.HTTPServiceCount, TechnologiesFound: recon.TechnologyCount,
		EndpointsFound: recon.EndpointCount,
	})
	if ctx.Err() != nil {
		runErr = ctx.Err()
		return
	}

	// ---------------------------------------------------------------
	// DETECTION + VERIFICATION (task sections 9-12) -- bundled: every
	// real detector performs its own verification internally, inside
	// one Detect() call (see docs/phase-3-11-scan-orchestrator.md "Why
	// VERIFICATION has no separate checkpoint").
	// ---------------------------------------------------------------
	state.StartStage(StageDetection)
	state.StartStage(StageVerification)

	// Phase 3.12: a resolved scan policy may exclude vulnerability
	// detection entirely (e.g. the "recon" profile). This is checked
	// BEFORE building an Executor or touching the detection engine at
	// all -- the strongest available guarantee that "detection
	// disabled" really means zero detector-related requests, not merely
	// zero detectors happening to be eligible. See DetectionState's doc
	// comment for why this is deliberately NOT the same reported state
	// as "ran, found nothing eligible," and why no warning is recorded:
	// this is expected, policy-driven behavior, not an anomaly.
	if opts.DetectionDisabled {
		detSum.State = DetectionStateDisabledByProfile
		state.CompleteStage(StageDetection)
		state.CompleteStage(StageVerification)
		logger.Info("detection_disabled_by_profile", slog.String("scan_job_id", scanID))
	} else {
		logger.Info("detector_started", slog.String("stage", string(StageDetection)))
		detCtx, cancelDet := o.withStageTimeout(ctx)
		executor, execErr := o.buildDetectionExecutor(detCtx, opts.AuthSession)
		if execErr != nil {
			cancelDet()
			runErr = execErr
			detSum.State = DetectionStateFailed
			state.AddError(ScanError{Category: ErrorCategoryStage, Stage: StageDetection, Message: execErr.Error()})
			state.FailStage(StageDetection)
			state.FailStage(StageVerification)
			return
		}
		engine := &detection.Engine{Registry: o.DetectionRegistry, Store: o.Store, Executor: executor, Logger: logger, Concurrency: o.DetectionConcurrency}
		summary, detEngineErr := engine.Run(detCtx, detection.RunOptions{ScanJobID: scanID})
		cancelDet()

		detSum = DetectorSummary{
			TargetsConsidered:  summary.TargetsConsidered,
			EligibleTargets:    summary.EligibleTargets,
			DetectorRuns:       summary.DetectorRuns,
			RawFindingsCreated: summary.FindingsCreated,
			Duplicates:         summary.Duplicates,
			RequestsIssued:     summary.RequestsIssued,
			ErrorCount:         len(summary.Errors),
		}
		state.MergeCounters(Counters{
			TargetsConsidered: summary.TargetsConsidered, DetectorRuns: summary.DetectorRuns,
			RequestsIssued: summary.RequestsIssued, RawFindings: summary.FindingsCreated, Duplicates: summary.Duplicates,
		})
		for _, de := range summary.Errors {
			// Detector failure isolation (task section 11): recorded, never
			// fatal -- the scan continues past this point regardless.
			state.AddError(ScanError{Category: ErrorCategoryDetector, Stage: StageDetection, DetectorID: de.DetectorID, Message: de.Error()})
			logger.Warn("detector_error", slog.String("detector_id", de.DetectorID), slog.String("target", de.TargetURL), slog.String("error", de.Err.Error()))
		}
		logger.Info("detector_completed", slog.String("stage", string(StageDetection)), slog.Int("detector_runs", summary.DetectorRuns), slog.Int("errors", len(summary.Errors)))

		if detEngineErr != nil {
			runErr = detEngineErr
			detSum.State = DetectionStateFailed
			state.AddError(ScanError{Category: ErrorCategoryStage, Stage: StageDetection, Message: detEngineErr.Error()})
			state.FailStage(StageDetection)
			state.FailStage(StageVerification)
			return
		}
		if summary.Cancelled || ctx.Err() != nil {
			runErr = ctx.Err()
			if runErr == nil {
				runErr = context.Canceled
			}
			// State C (task section 5): eligible targets may well have
			// existed, but the stage itself did not run to completion --
			// distinct from state B, where the stage completes cleanly and
			// simply had nothing eligible to do.
			detSum.State = DetectionStateFailed
			state.CancelStage(StageDetection)
			state.CancelStage(StageVerification)
			return
		}
		state.CompleteStage(StageDetection)
		state.CompleteStage(StageVerification)

		// Phase 3.11.2: classify state A vs state B now that the stage has
		// completed cleanly, and -- for state B specifically -- surface WHY
		// no detection happened, since "detector_runs == 0" alone reads
		// exactly like "checked, found nothing" unless something says
		// otherwise (task section 4: never let an operator conflate the
		// two). This is a warning, not a failure: the scan itself succeeded
		// at everything it was configured to do.
		if summary.DetectorRuns > 0 {
			detSum.State = DetectionStateExecuted
		} else {
			detSum.State = DetectionStateNotRun
			_, enabledCount := registeredAndEnabledCounts(o.DetectionRegistry)
			reason := "no eligible detection targets were discovered"
			message := fmt.Sprintf("No vulnerability detectors were executed because %s.", reason)
			if !pipeline.CrawlEnabled {
				reason = "crawling is disabled and no eligible parameterized endpoints were discovered"
				message = "Vulnerability detection did not run because crawling is disabled and no eligible parameterized endpoints were discovered. Recon completed successfully."
			}
			state.AddError(ScanError{Category: ErrorCategoryWarning, Stage: StageDetection, Message: "DETECTION_NOT_RUN: " + message})
			logger.Warn("detection_not_run",
				slog.String("scan_job_id", scanID),
				slog.String("reason", reason),
				slog.Bool("crawler_enabled", pipeline.CrawlEnabled),
				slog.Int("eligible_targets", summary.EligibleTargets),
				slog.Int("detectors_enabled", enabledCount),
			)
		}
	}

	// ---------------------------------------------------------------
	// CORRELATION (task section 21) -- Phase 3.8, unmodified.
	// ---------------------------------------------------------------
	state.StartStage(StageCorrelation)
	logger.Info("stage_started", slog.String("stage", string(StageCorrelation)))
	rawFindings, listErr := o.Store.Findings().ListByScanJob(ctx, scanID)
	if listErr != nil {
		runErr = listErr
		state.AddError(ScanError{Category: ErrorCategoryStage, Stage: StageCorrelation, Message: listErr.Error()})
		state.FailStage(StageCorrelation)
		return
	}
	ce := correlation.NewEngine()
	for i, res := range ce.Ingest(rawFindings...) {
		event := "finding_created"
		if res.Status == correlation.StatusDuplicate {
			event = "finding_deduplicated"
		}
		logger.Info(event, slog.String("finding_id", res.FindingID), slog.Int("index", i))
	}
	canonical := ce.Findings()
	detSum.CanonicalFindings = len(canonical)
	state.MergeCounters(Counters{CanonicalFindings: len(canonical)})

	// Phase 3.31: chain correlation, additive to Phase 3.8's own
	// dedup pass above -- runs against the SAME rawFindings already
	// fetched for correlation, never internal/correlation's own
	// CanonicalFinding output (which does not preserve
	// IdentityContext -- see docs/phase-3-31-chain-integration.md
	// section on why chains.Correlate consumes raw findings
	// directly). A chain-persistence failure is isolated exactly like
	// the Evidence stage's own per-item error isolation below: it
	// never fails the whole scan or blocks any later stage, since a
	// vulnerability finding must remain independently visible/usable
	// even if its own chain data could not be saved.
	chainResult := chains.Correlate(rawFindings, chains.DefaultLimits())
	if err := o.Store.Chains().SaveResult(ctx, scanID, chainResult); err != nil {
		state.AddError(ScanError{Category: ErrorCategoryWarning, Stage: StageCorrelation, Message: fmt.Sprintf("chain persistence: %v", err)})
		logger.Warn("chain_persistence_failed", slog.String("stage", string(StageCorrelation)), slog.String("error", err.Error()))
	} else {
		logger.Info("chains_persisted", slog.String("stage", string(StageCorrelation)),
			slog.Int("relations", len(chainResult.Relations)), slog.Int("candidates", len(chainResult.Candidates)))
	}

	state.CompleteStage(StageCorrelation)
	logger.Info("stage_completed", slog.String("stage", string(StageCorrelation)), slog.Int("canonical_findings", len(canonical)))
	if ctx.Err() != nil {
		runErr = ctx.Err()
		return
	}

	// ---------------------------------------------------------------
	// RISK (task section 22) -- Phase 3.9, unmodified.
	// ---------------------------------------------------------------
	state.StartStage(StageRisk)
	logger.Info("stage_started", slog.String("stage", string(StageRisk)))
	ranked := risk.Rank(risk.AssessAll(canonical, nil))
	for _, a := range ranked {
		logger.Info("risk_calculated", slog.String("finding_id", a.FindingID), slog.Int("risk_score", a.RiskScore), slog.String("priority", string(a.Priority)))
	}
	state.CompleteStage(StageRisk)
	logger.Info("stage_completed", slog.String("stage", string(StageRisk)))
	if ctx.Err() != nil {
		runErr = ctx.Err()
		return
	}

	// task section 32's "maximum findings": applied AFTER deterministic
	// ranking (task section 25: never reorder), so what survives is
	// always the highest-priority prefix, never an arbitrary one.
	truncatedFindings := false
	if len(ranked) > o.limits.MaxFindings {
		ranked = ranked[:o.limits.MaxFindings]
		truncatedFindings = true
	}

	byFindingID := make(map[string]correlation.CanonicalFinding, len(canonical))
	for _, cf := range canonical {
		byFindingID[cf.FindingID] = cf
	}

	// ---------------------------------------------------------------
	// EVIDENCE (task section 23) -- Phase 3.10, unmodified.
	// ---------------------------------------------------------------
	state.StartStage(StageEvidence)
	logger.Info("stage_started", slog.String("stage", string(StageEvidence)))
	for _, a := range ranked {
		if ctx.Err() != nil {
			runErr = ctx.Err()
			state.CancelStage(StageEvidence)
			return
		}
		cf, ok := byFindingID[a.FindingID]
		if !ok {
			continue // defensive: risk.Rank never invents FindingIDs, unreachable in practice
		}
		pkg, buildErr := o.safeBuildPackage(cf, a)
		if buildErr != nil {
			// Error isolation extended to this stage (task section 11's
			// principle applied consistently): one finding's evidence
			// build failing must not lose every other finding's result.
			state.AddError(ScanError{Category: ErrorCategoryWarning, Stage: StageEvidence, Message: fmt.Sprintf("finding %s: %v", a.FindingID, buildErr)})
			continue
		}
		packages = append(packages, pkg)
		logger.Info("evidence_created", slog.String("finding_id", a.FindingID), slog.Int("evidence_items", len(pkg.Evidence)))
	}
	evidenceItems := 0
	for _, pkg := range packages {
		evidenceItems += len(pkg.Evidence)
	}
	state.MergeCounters(Counters{EvidenceItems: evidenceItems})
	state.CompleteStage(StageEvidence)
	logger.Info("stage_completed", slog.String("stage", string(StageEvidence)))
	if ctx.Err() != nil {
		runErr = ctx.Err()
		return
	}

	// ---------------------------------------------------------------
	// FINALIZATION (task section 24)
	// ---------------------------------------------------------------
	state.StartStage(StageFinalization)
	if truncatedFindings {
		state.AddError(ScanError{Category: ErrorCategoryWarning, Stage: StageFinalization, Message: fmt.Sprintf("findings truncated to the configured limit (%d); lower-priority findings were dropped after risk ranking", o.limits.MaxFindings)})
	}
	state.SetFindingsCount(len(packages))
	state.CompleteStage(StageFinalization)

	return
}

// scanPipeline returns the *orchestration.Pipeline this scan should run
// against: o.Pipeline unchanged when override and session are both nil
// (every pre-Phase-3.12 caller's exact behavior), or a shallow copy
// with CrawlEnabled/CrawlMaxDepth/CrawlMaxPages/AuthSession substituted
// otherwise -- see Options.CrawlOverride's and Options.AuthSession's
// doc comments for why a copy, not a mutation of the shared o.Pipeline,
// is required for concurrent-scan safety (task section 5's "concurrent
// authenticated scans are isolated": two Run calls with different
// AuthSession values never share or race on one Pipeline's own field).
// A shallow copy is sufficient and correct here: every other field is
// either an immutable value or a pointer/interface meant to be SHARED
// across concurrent scans (Store, Resolver, rate limiters), and
// copying the struct does not clone what those point to.
func (o *Orchestrator) scanPipeline(override *CrawlSettings, session *auth.Session) *orchestration.Pipeline {
	if override == nil && session == nil {
		return o.Pipeline
	}
	p := *o.Pipeline
	if override != nil {
		p.CrawlEnabled = override.Enabled
		p.CrawlMaxDepth = override.MaxDepth
		p.CrawlMaxPages = override.MaxPages
		p.ParameterLimits = override.ParameterLimits
		p.CrawlStartPath = override.StartPath
	}
	p.AuthSession = session
	return &p
}

// buildDetectionExecutor builds a FRESH detection.Executor for this
// scan, against the CURRENT scope-rule snapshot -- never a shared,
// possibly-stale instance. See target.go's resolveAndRegisterTarget
// doc comment for why a fresh validator per scan is required, not
// optional.
//
// Phase 3.19: session, if non-nil (opts.AuthSession, the scan's own
// already-authenticated Phase 3.14 session), is converted into a
// mutation.SessionContext the exact same way
// internal/orchestration.Pipeline already does for crawling
// (session.JarFor(session.Host)/HeadersFor(session.Host), both
// host-pinned to session.Host, matching CookiesFor/HeadersFor's own
// established host-check contract) and threaded into
// detection.NewExecutorWithSession -- this is what closes the gap
// documented in docs/phase-3-19-active-detection.md section 1 finding
// 4: before this phase, detection-stage requests were unconditionally
// unauthenticated regardless of whether the scan itself authenticated.
func (o *Orchestrator) buildDetectionExecutor(ctx context.Context, session *auth.Session) (*detection.Executor, error) {
	rules, err := o.Store.ScopeRules().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: loading scope rules for detection: %w", err)
	}
	validator := scope.NewValidator(rules, o.allowReservedRanges())
	if session == nil {
		return detection.NewExecutor(validator, o.Pipeline.Resolver, o.DetectionExecutorConfig), nil
	}
	sessCtx := mutation.SessionContext{
		Jar: session.JarFor(session.Host), Headers: session.HeadersFor(session.Host),
		PinnedHost: session.Host, IdentityContext: session.IdentityName,
	}
	return detection.NewExecutorWithSession(validator, o.Pipeline.Resolver, o.DetectionExecutorConfig, sessCtx), nil
}

// registeredAndEnabledCounts reads task section 2's two static
// registry facts -- Registry.List() introspects the registry's own
// in-memory map, no scan state or network involved (task section 16:
// "must not perform expensive additional network operations. Use
// existing scan state."). Safe to call with a nil registry (never
// expected in a properly-constructed Orchestrator, but this is cheap
// enough to guard defensively rather than let a misconfigured
// Orchestrator panic while reporting this specific value).
func registeredAndEnabledCounts(reg *detection.Registry) (registered, enabled int) {
	if reg == nil {
		return 0, 0
	}
	for _, e := range reg.List() {
		registered++
		if e.Enabled {
			enabled++
		}
	}
	return registered, enabled
}

// buildReconSummary reads back RECON+DISCOVERY's persisted results via
// internal/reporting.Build -- task section 7's "integration of existing
// modules," reusing the SAME aggregation Phase 1's own `scanner status`
// command already relies on, rather than re-querying every table here.
func (o *Orchestrator) buildReconSummary(ctx context.Context, scanJobID string) ReconSummary {
	rep, err := reporting.Build(ctx, o.Store, scanJobID)
	if err != nil {
		return ReconSummary{}
	}
	return ReconSummary{
		HostCount:        len(rep.Hosts),
		ServiceCount:     len(rep.Services),
		HTTPServiceCount: len(rep.HTTPServices),
		TechnologyCount:  len(rep.Technologies),
		EndpointCount:    len(rep.Endpoints),
	}
}

// buildInputSummary reads back Phase 3.13's persisted discovery
// results the same way buildReconSummary does -- never re-running
// discovery. warnings is threaded through from the RECON+DISCOVERY
// stage's own models.ScanJob return value (see
// internal/orchestration.Pipeline.Run's own Warnings field doc
// comment) rather than re-derived here.
func (o *Orchestrator) buildInputSummary(ctx context.Context, scanJobID string, warnings []string) InputSummary {
	rep, err := reporting.Build(ctx, o.Store, scanJobID)
	if err != nil {
		return InputSummary{}
	}
	uniqueEndpoints := make(map[string]bool, len(rep.Parameters))
	for _, p := range rep.Parameters {
		uniqueEndpoints[p.EndpointID] = true
	}
	return InputSummary{
		InputCount:                len(rep.Parameters),
		UniqueEndpointsWithInputs: len(uniqueEndpoints),
		Warnings:                  warnings,
	}
}

// safeBuildPackage calls evidence.BuildPackage with panic recovery --
// task section 11's error-isolation principle extended to the EVIDENCE
// stage: a defensive backstop, not evidence that BuildPackage is
// expected to panic (Phase 3.10's own exhaustive adversarial-input
// testing found none), consistent with the same recover() pattern
// detection.Engine.Run already applies around each detector call.
func (o *Orchestrator) safeBuildPackage(cf correlation.CanonicalFinding, a risk.Assessment) (pkg evidence.FindingPackage, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic building evidence: %v", r)
		}
	}()
	pkg = evidence.BuildPackage(cf, a, o.EvidenceLimits)
	return pkg, nil
}

// buildResult assembles the final Result -- task section 24.
func (o *Orchestrator) buildResult(scanID, target, profileLabel string, session *auth.Session, state *ScanState, recon ReconSummary, input InputSummary, crawlSum CrawlSummary, authenticatedRequests int, sessionExpired bool, detSum DetectorSummary, packages []evidence.FindingPackage) Result {
	// DetectorsRegistered/DetectorsEnabled are static registry facts,
	// unconditionally overwritten here regardless of how far the scan
	// got (task section 2: these cost nothing -- Registry.List() reads
	// no scan state -- and stay honestly accurate even when SCOPE/RECON
	// failed before the DETECTION stage was ever reached, in which case
	// detSum's other, scan-derived fields correctly stay zero).
	detSum.DetectorsRegistered, detSum.DetectorsEnabled = registeredAndEnabledCounts(o.DetectionRegistry)

	snap := state.Snapshot()
	var warnings []string
	var errs []ScanError
	for _, e := range snap.Errors {
		if e.Category == ErrorCategoryWarning {
			warnings = append(warnings, e.Message)
		}
		errs = append(errs, e)
	}
	completedAt := time.Now().UTC()
	if snap.CompletedAt != nil {
		completedAt = *snap.CompletedAt
	}
	authState := auth.StateUnauthenticated
	authProfile := ""
	identityName := ""
	if session != nil {
		authState = session.State
		authProfile = session.ProfileName
		identityName = session.IdentityName
	}
	return Result{
		ScanID:                scanID,
		Target:                target,
		Profile:               profileLabel,
		AuthProfile:           authProfile,
		AuthState:             authState,
		Identity:              identityName,
		AuthenticatedRequests: authenticatedRequests,
		SessionExpired:        sessionExpired,
		Status:                snap.Status,
		StartedAt:             snap.StartedAt,
		CompletedAt:           completedAt,
		Duration:              snap.Duration,
		ReconSummary:          recon,
		InputSummary:          input,
		CrawlSummary:          crawlSum,
		DetectorSummary:       detSum,
		Findings:              packages,
		Errors:                errs,
		Warnings:              warnings,
		Summary:               summarize(packages),
	}
}

// summarize computes task section 24's total/critical/high/medium/low
// counts directly from each package's own CanonicalFinding.Severity --
// never re-deriving or second-guessing a severity Phase 3.1-3.9 already
// assigned.
func summarize(packages []evidence.FindingPackage) FindingsSummary {
	var s FindingsSummary
	for _, pkg := range packages {
		s.Total++
		switch pkg.Finding.Severity {
		case models.SeverityCritical:
			s.Critical++
		case models.SeverityHigh:
			s.High++
		case models.SeverityMedium:
			s.Medium++
		case models.SeverityLow:
			s.Low++
		case models.SeverityInfo:
			s.Info++
		}
	}
	return s
}

// terminalStatus decides the scan's final Status -- task section 3,
// with task section 13's "no partial result is incorrectly marked
// COMPLETED" as the overriding priority: cancellation/deadline is
// checked FIRST, before whether every stage otherwise looked clean.
// ctxDone must be a caller-captured snapshot of the relevant context's
// Err() != nil state -- see Run's own ctxDone variable and its doc
// comment for why this must never be a live ctx.Err() call made after
// this package's own internal cleanup (e.g. releasing a ScanTimeout
// context's timer) may have already run.
func (o *Orchestrator) terminalStatus(runErr error, ctxDone bool, state *ScanState) Status {
	if runErr != nil && isCancellation(ctxDone, runErr) {
		return StatusCancelled
	}
	if runErr != nil {
		return StatusFailed
	}
	if ctxDone {
		return StatusCancelled
	}
	if state.HasWarningOrDetectorError() {
		return StatusCompletedWithWarnings
	}
	return StatusCompleted
}

// isCancellation mirrors internal/orchestration.Pipeline's own
// terminalStatusFor: an error is a cancellation if it IS or wraps
// context.Canceled/context.DeadlineExceeded, or if ctxDone (a
// caller-captured snapshot of the relevant context's Done state, NOT a
// live ctx.Err() call -- see terminalStatus's doc comment) says so
// regardless of the error's own shape.
func isCancellation(ctxDone bool, err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctxDone
}
