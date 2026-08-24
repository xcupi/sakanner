// Phase 3.1 detection FRAMEWORK integration tests against the Phase 3
// Security Test Laboratory.
//
// These tests prove the framework (internal/detection) correctly
// consumes real Phase 2 recon output, selects and runs a detector
// against it, collects evidence, normalizes/deduplicates/persists
// findings, keeps scope enforcement active, isolates detector failures,
// and respects cancellation -- all against the real vuln.scanner.test
// lab fixtures. They use ONLY internal/detection/detectiontest.Mock, a
// test-fixture detector that never claims to detect a real
// vulnerability (see that package's doc comment) -- no real SQLi/XSS/
// SSRF/etc. detector exists yet, and these tests do not claim otherwise.
// TestPhase3Lab_ScanAndCompareAgainstGroundTruth (phase3_lab_test.go)
// remains the source of truth for that: zero real findings, because no
// real detector is registered anywhere in this codebase.
package lab

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"sakanner/internal/detection"
	"sakanner/internal/detection/detectiontest"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/logging"
	"sakanner/internal/orchestration"
	"sakanner/internal/scope"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

// runReconAgainstVulnLab runs the real orchestration.Pipeline against
// l's vuln.scanner.test fixtures (crawling enabled, so Endpoint targets
// exist too, not just one HTTPService target), returning the store its
// results were persisted to, the completed ScanJob, and a scope
// Validator built from the exact same ScopeSnapshot the job itself
// recorded -- the same validator internal/detection.Executor must be
// built from, so detection-stage requests are governed by identical
// scope rules to the recon stage that produced their targets.
//
// Callers that also need direct access to l (e.g. to build a Target
// against a DIFFERENT lab host, to prove scope enforcement) must obtain
// their own *Lab via testVulnLab and pass it in -- testVulnLab must only
// be called once per test, since altport.scanner.test binds a fixed
// port (see phase3_lab_test.go's TestPhase3Lab_Determinism for the same
// lesson learned the hard way).
func runReconAgainstVulnLab(t *testing.T, l *Lab) (storage.Store, models.ScanJob, scope.Validator) {
	t.Helper()

	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ctx := context.Background()
	targetID := uuid.NewString()
	if err := store.Targets().Create(ctx, models.Target{ID: targetID, Value: "vuln.scanner.test", Type: models.TargetTypeHost, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := store.ScopeRules().Create(ctx, models.ScopeRule{ID: uuid.NewString(), Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	p := &orchestration.Pipeline{
		Store:               store,
		Resolver:            l.Resolver,
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		DefaultPorts:        []int{mustPort(t, l.VulnAddr)},
		PortDialTimeout:     2 * time.Second,
		HTTPConfig:          httpstage.Config{Timeout: 2 * time.Second, MaxRedirects: 5},
		Concurrency:         orchestration.Concurrency{DNSWorkers: 4, PortWorkers: 4, HTTPWorkers: 4},
		AllowReservedRanges: true,
		MaxCIDRHosts:        256,
		CrawlEnabled:        true,
		CrawlMaxDepth:       2,
		CrawlMaxPages:       30,
		Logger:              logging.New(logging.Options{Level: "error", Format: "text"}),
	}

	job, err := p.Run(ctx, orchestration.RunOptions{TargetIDs: []string{targetID}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed (error: %s)", job.Status, job.Error)
	}

	validator := scope.NewValidator(job.ScopeSnapshot, true) // AllowReservedRanges: the lab is on 127.0.0.0/8, same as the pipeline run above
	return store, job, validator
}

func detectionLogger() *slog.Logger {
	return logging.New(logging.Options{Level: "error", Format: "text"})
}

// TestPhase3_1_EngineConsumesRealReconOutput proves BuildTargets turns a
// real completed scan job's Phase 2 recon (HTTPServices + crawled
// Endpoints) against the vuln lab into a non-trivial target set --
// requirement 1 in the task's "Phase 3 Test Lab Integration" section.
func TestPhase3_1_EngineConsumesRealReconOutput(t *testing.T) {
	l := testVulnLab(t)
	store, job, _ := runReconAgainstVulnLab(t, l)

	targets, err := detection.BuildTargets(context.Background(), store, job.ID)
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	if len(targets) == 0 {
		t.Fatal("BuildTargets returned no targets from a real, completed recon scan of the vuln lab")
	}

	var httpServiceTargets, endpointTargets int
	for _, tgt := range targets {
		switch tgt.Kind {
		case detection.TargetKindHTTPService:
			httpServiceTargets++
			if tgt.IP == nil {
				t.Errorf("http_service target %+v has no resolved IP", tgt)
			}
		case detection.TargetKindEndpoint:
			endpointTargets++
		}
	}
	if httpServiceTargets == 0 {
		t.Error("no http_service-kind targets were built")
	}
	if endpointTargets == 0 {
		t.Error("no endpoint-kind targets were built -- crawling was enabled and should have discovered several endpoints on vuln.scanner.test")
	}
	t.Logf("BuildTargets: %d http_service targets, %d endpoint targets, %d total", httpServiceTargets, endpointTargets, len(targets))
}

// TestPhase3_1_DetectorSelectionByPrerequisites proves the engine only
// runs a detector against targets matching its declared
// SupportedTargetTypes/Eligible -- requirement 2. Two mock detectors are
// registered: one that only declares itself eligible for
// TargetKindHTTPService, one only for TargetKindEndpoint. Each must be
// invoked only against its own kind of real, lab-derived target.
func TestPhase3_1_DetectorSelectionByPrerequisites(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	reg := detection.NewRegistry()
	httpOnly := &detectiontest.Mock{IDValue: "http-service-only", TargetKinds: []detection.TargetKind{detection.TargetKindHTTPService}}
	endpointOnly := &detectiontest.Mock{IDValue: "endpoint-only", TargetKinds: []detection.TargetKind{detection.TargetKindEndpoint}}
	_ = reg.Register(httpOnly)
	_ = reg.Register(endpointOnly)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{})
	e := &detection.Engine{Registry: reg, Store: store, Executor: x, Concurrency: 4, Logger: detectionLogger()}

	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	targets, _ := detection.BuildTargets(context.Background(), store, job.ID)
	var wantHTTPService, wantEndpoint int64
	for _, tgt := range targets {
		if tgt.Kind == detection.TargetKindHTTPService {
			wantHTTPService++
		} else if tgt.Kind == detection.TargetKindEndpoint {
			wantEndpoint++
		}
	}

	if httpOnly.Calls() != wantHTTPService {
		t.Errorf("http-service-only detector ran %d times, want exactly %d (one per real http_service target, never against an endpoint target)", httpOnly.Calls(), wantHTTPService)
	}
	if endpointOnly.Calls() != wantEndpoint {
		t.Errorf("endpoint-only detector ran %d times, want exactly %d (one per real endpoint target, never against the http_service target)", endpointOnly.Calls(), wantEndpoint)
	}
	if summary.DetectorRuns != int(wantHTTPService+wantEndpoint) {
		t.Errorf("DetectorRuns = %d, want %d", summary.DetectorRuns, wantHTTPService+wantEndpoint)
	}
}

// TestPhase3_1_MockDetectorFindingEvidencePersistedAndDeduplicated
// covers requirements 3-7: the mock detector executes against the real
// lab, produces a finding, evidence is attached, the finding is
// persisted, and re-running detection against the same scan job does
// not duplicate it.
func TestPhase3_1_MockDetectorFindingEvidencePersistedAndDeduplicated(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	reg := detection.NewRegistry()
	m := &detectiontest.Mock{
		IDValue:     "mock-against-real-lab",
		TargetKinds: []detection.TargetKind{detection.TargetKindHTTPService},
		Behavior:    detectiontest.Finding,
		RequestPath: "?probe=1", // a real GET through the Executor against vuln.scanner.test's actual index page, before deciding its (fixed) Finding outcome
		Severity:    models.SeverityMedium,
	}
	_ = reg.Register(m)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{})
	e := &detection.Engine{Registry: reg, Store: store, Executor: x, Concurrency: 4, Logger: detectionLogger()}

	first, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID})
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if first.FindingsCreated == 0 {
		t.Fatal("first Run created no findings")
	}
	if len(first.Errors) != 0 {
		t.Errorf("first Run.Errors = %+v, want none", first.Errors)
	}

	persisted, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(persisted) != first.FindingsCreated {
		t.Fatalf("persisted findings = %d, want %d", len(persisted), first.FindingsCreated)
	}
	for _, f := range persisted {
		if f.Host != "vuln.scanner.test" {
			t.Errorf("finding Host = %q, want vuln.scanner.test", f.Host)
		}
		if len(f.Evidence) == 0 {
			t.Errorf("finding %s has no evidence", f.ID)
		}
		if f.ValidationStatus != models.ValidationStatusUnvalidated {
			t.Errorf("finding %s ValidationStatus = %q, want unvalidated", f.ID, f.ValidationStatus)
		}
	}

	second, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID})
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	if second.FindingsCreated != 0 {
		t.Errorf("second Run.FindingsCreated = %d, want 0 (already on record)", second.FindingsCreated)
	}
	if second.Duplicates == 0 {
		t.Error("second Run.Duplicates = 0, want at least 1")
	}

	afterRerun, _ := store.Findings().ListByScanJob(context.Background(), job.ID)
	if len(afterRerun) != len(persisted) {
		t.Errorf("finding count changed across reruns: %d then %d -- deduplication must make this idempotent", len(persisted), len(afterRerun))
	}
}

// TestPhase3_1_ScopeEnforcementStaysActiveDuringDetection is the
// CRITICAL scope-enforcement regression the task explicitly calls out:
// a detector's Executor, built from the exact ScopeRules the real scan
// job recorded (only vuln.scanner.test is in scope), must refuse a
// request aimed at any other host -- including the lab's OTHER hosts
// (e.g. scanner.test, from the Phase 2 lab, reachable on the same
// process but never authorized for this job) -- with zero requests
// reaching that host.
func TestPhase3_1_ScopeEnforcementStaysActiveDuringDetection(t *testing.T) {
	l := testVulnLab(t)
	_, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{})

	// A Target manufactured to point at the Phase 2 lab's scanner.test
	// host (real, running, reachable on this same process) -- but this
	// scan job's ScopeSnapshot only authorizes vuln.scanner.test. Port 80
	// is a placeholder: Executor.Do's scope check runs BEFORE any dial is
	// attempted, so the request never gets far enough to need a real,
	// listening port for this test to be meaningful.
	outOfScopeIPs, err := l.Resolver.LookupHost(context.Background(), "scanner.test")
	if err != nil || len(outOfScopeIPs) == 0 {
		t.Fatalf("resolving scanner.test in the lab's own resolver: %v", err)
	}
	outOfScope := detection.Target{
		ScanJobID: job.ID, Kind: detection.TargetKindHTTPService,
		Host: "scanner.test", IP: outOfScopeIPs[0], Port: 80,
		Scheme: "http", URL: "http://scanner.test/", Path: "/",
	}

	m := &detectiontest.Mock{RequestPath: "probe", Behavior: detectiontest.NoFinding}
	_, detErr := m.Detect(context.Background(), outOfScope, x)
	if detErr == nil {
		t.Fatal("Detect against an out-of-scope target (scanner.test, not in this job's ScopeSnapshot): want error, got nil -- scope enforcement did not stop the request")
	}
	if x.RequestCount() != 0 {
		t.Errorf("Executor.RequestCount() = %d, want 0 -- the out-of-scope request must never actually dial", x.RequestCount())
	}
}

// TestPhase3_1_DetectorErrorAndPanicDoNotStopTheRun covers requirement
// 9: a failing (and separately, a panicking) mock detector running
// alongside a working one against the real lab must not prevent the
// working detector's finding from being produced and persisted.
func TestPhase3_1_DetectorErrorAndPanicDoNotStopTheRun(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	reg := detection.NewRegistry()
	failing := &detectiontest.Mock{IDValue: "failing", TargetKinds: []detection.TargetKind{detection.TargetKindHTTPService}, Behavior: detectiontest.Error}
	panicky := &detectiontest.Mock{IDValue: "panicky", TargetKinds: []detection.TargetKind{detection.TargetKindHTTPService}, Behavior: detectiontest.Panic}
	working := &detectiontest.Mock{IDValue: "working", TargetKinds: []detection.TargetKind{detection.TargetKindHTTPService}, Behavior: detectiontest.Finding}
	_ = reg.Register(failing)
	_ = reg.Register(panicky)
	_ = reg.Register(working)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{})
	e := &detection.Engine{Registry: reg, Store: store, Executor: x, Concurrency: 4, Logger: detectionLogger()}

	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID})
	if err != nil {
		t.Fatalf("Run: %v (a detector error/panic must never surface as Run's own error)", err)
	}
	if summary.FindingsCreated == 0 {
		t.Error("FindingsCreated = 0, want at least 1 from the working detector")
	}
	var sawFailing, sawPanic bool
	for _, de := range summary.Errors {
		if de.DetectorID == "failing" {
			sawFailing = true
		}
		if de.DetectorID == "panicky" {
			sawPanic = true
		}
	}
	if !sawFailing {
		t.Error("no recorded error for the failing detector")
	}
	if !sawPanic {
		t.Error("no recorded error for the panicking detector")
	}
}

// TestPhase3_1_CancellationDuringDetection covers requirement 10:
// cancelling the context mid-run against the real lab must stop the
// engine from starting further detector calls and still return a
// summary rather than hanging.
func TestPhase3_1_CancellationDuringDetection(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	reg := detection.NewRegistry()
	slow := &detectiontest.Mock{DetectDelay: 300 * time.Millisecond}
	_ = reg.Register(slow)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{})
	e := &detection.Engine{Registry: reg, Store: store, Executor: x, Concurrency: 2, Logger: detectionLogger()}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	var summary detection.RunSummary
	var runErr error
	go func() {
		summary, runErr = e.Run(ctx, detection.RunOptions{ScanJobID: job.ID})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of a 50ms context deadline -- cancellation is not being respected")
	}
	if runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}
	if !summary.Cancelled {
		t.Error("summary.Cancelled = false, want true")
	}
}
