// Phase 3.26 Command Injection Active Detection: real orchestrator/
// engine + real lab integration tests, against harness_vuln.go's
// existing /api/ping/* fixtures and harness_cmdinjection_active.go's
// own new Windows-style/form/JSON/path/generic-error additions.
// Mirrors lab/phase3_7_cmdinjection_test.go's own registry/testVulnLab/
// runReconAgainstVulnLab pattern, and
// phase3_19_active_detection_test.go's directly-persisted-parameter
// pattern for the JSON-body case (the crawler cannot yet discover a
// live JSON REQUEST_INPUT parameter -- an honest, pre-existing Phase
// 3.19 limitation, not something this phase regresses or is expected
// to close).
package lab

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"sakanner/internal/auth"
	"sakanner/internal/detection"
	"sakanner/internal/detectors/cmdinjectionactive"
	"sakanner/internal/evidence"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/orchestration"
	"sakanner/internal/orchestrator"
	"sakanner/internal/scope"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

// cmdInjectionActiveRegistry returns a fresh Registry with only
// command-injection-active registered -- isolating these tests from
// every other detector's own findings.
func cmdInjectionActiveRegistry(t *testing.T) *detection.Registry {
	t.Helper()
	r := detection.NewRegistry()
	if err := r.Register(cmdinjectionactive.New()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return r
}

func findCmdInjectionFor(findings []models.Finding, endpoint, parameter string) (models.Finding, bool) {
	for _, f := range findings {
		if f.VulnerabilityType == "command_injection" && f.AffectedEndpoint == endpoint && f.AffectedParameter == parameter {
			return f, true
		}
	}
	return models.Finding{}, false
}

// ---------------------------------------------------------------------
// POSITIVE: query (Unix + Windows), form, path locations (real crawl)
// ---------------------------------------------------------------------

func TestPhase3_26_QueryLocationUnix_Finding(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: cmdInjectionActiveRegistry(t), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	f, found := findCmdInjectionFor(findings, "/api/ping/vulnerable", "host")
	if !found {
		t.Fatalf("expected a command_injection finding for /api/ping/vulnerable's host parameter, got: %+v", findings)
	}
	if f.Confidence != 0.95 {
		t.Errorf("Confidence = %v, want 0.95", f.Confidence)
	}
	if len(f.Evidence) != 2 {
		t.Errorf("expected 2 evidence items (baseline + probe), got %d", len(f.Evidence))
	}
}

func TestPhase3_26_QueryLocationWindows_Finding(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: cmdInjectionActiveRegistry(t), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if _, found := findCmdInjectionFor(findings, "/api/ping/vulnerable-windows", "host"); !found {
		t.Fatalf("expected a command_injection finding for /api/ping/vulnerable-windows's host parameter, got: %+v", findings)
	}
}

func TestPhase3_26_FormLocation_Finding(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLabDeep(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: cmdInjectionActiveRegistry(t), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if _, found := findCmdInjectionFor(findings, "/api/ping/vulnerable-form", "host"); !found {
		t.Fatalf("expected a command_injection finding for /api/ping/vulnerable-form's host parameter, got: %+v", findings)
	}
	params, err := store.Parameters().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob (parameters): %v", err)
	}
	foundFormParam := false
	for _, p := range params {
		if p.Location == "form" && p.Name == "host" {
			foundFormParam = true
		}
	}
	if !foundFormParam {
		t.Fatalf("expected a form-location host Parameter to have been discovered via the real crawl (/forms/index -> /api/ping/vulnerable-form): %+v", params)
	}
}

func TestPhase3_26_PathLocation_Finding(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: cmdInjectionActiveRegistry(t), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	params, err := store.Parameters().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob (parameters): %v", err)
	}
	foundPathParam := false
	for _, p := range params {
		if p.Location == "path" && p.PathSegmentIndex >= 0 {
			// Confirm at least one path parameter round trips to a
			// finding below -- this loop only establishes discovery.
			foundPathParam = true
		}
	}
	if !foundPathParam {
		t.Fatalf("expected at least one path-location parameter to have been discovered via the real crawl (/api/ping/host/<value>, two example links): %+v", params)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob (findings): %v", err)
	}
	found := false
	for _, f := range findings {
		// Path-location findings carry whatever inferred parameter name
		// InferPathInputs assigned -- match by endpoint prefix instead
		// of a fixed parameter name.
		if f.VulnerabilityType == "command_injection" && strings.HasPrefix(f.AffectedEndpoint, "/api/ping/host/") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a command_injection finding for the path-location /api/ping/host/<value> parameter, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------
// POSITIVE: JSON body -- directly-persisted parameter
// ---------------------------------------------------------------------

func TestPhase3_26_JSONLocation_DirectlyPersisted_Finding(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	validator := scope.NewValidator(rules, true)
	ip := dial(t, "vuln.scanner.test", l)

	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	scanJobID := "cmdinjection-json-job"
	if err := store.ScanJobs().Create(context.Background(), models.ScanJob{ID: scanJobID, Status: models.ScanJobStatusRunning, StartedAt: time.Now().UTC(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create scan job: %v", err)
	}
	if err := store.Assets().Create(context.Background(), models.Asset{ID: "a1", ScanJobID: scanJobID, Name: "vuln.scanner.test", Source: "target", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := store.Hosts().Create(context.Background(), models.Host{ID: "h1", ScanJobID: scanJobID, AssetID: "a1", IPAddress: ip.String(), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create host: %v", err)
	}
	if err := store.Services().Create(context.Background(), models.Service{ID: "svc1", ScanJobID: scanJobID, HostID: "h1", Port: mustPort(t, l.VulnAddr), Protocol: "tcp", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create service: %v", err)
	}
	if err := store.HTTPServices().Create(context.Background(), models.HTTPService{
		ID: "http1", ScanJobID: scanJobID, ServiceID: "svc1",
		URL: fmt.Sprintf("http://vuln.scanner.test:%d/", mustPort(t, l.VulnAddr)), Scheme: "http", StatusCode: 200, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create http service: %v", err)
	}
	if err := store.Endpoints().Create(context.Background(), models.Endpoint{
		ID: "ep-cmdi-json", ScanJobID: scanJobID, HTTPServiceID: "http1", Path: "/api/ping/vulnerable-json", Method: "POST", Source: "crawl", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: "p-cmdi-json", ScanJobID: scanJobID, EndpointID: "ep-cmdi-json", Name: "host", Location: "json",
		Method: "POST", Provenance: "REQUEST_INPUT", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})
	e := &detection.Engine{Registry: cmdInjectionActiveRegistry(t), Store: store, Executor: x, Logger: detectionLogger(), Concurrency: 2}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: scanJobID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), scanJobID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if _, found := findCmdInjectionFor(findings, "/api/ping/vulnerable-json", "host"); !found {
		t.Fatalf("expected a command_injection finding from the JSON-body host parameter, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------
// NEGATIVE: safe endpoint, negative controls, generic error
// ---------------------------------------------------------------------

func TestPhase3_26_NegativeControls_NoFinding(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: cmdInjectionActiveRegistry(t), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	for _, path := range []string{
		"/api/ping/safe", "/api/ping/sanitized", "/api/ping/by-id",
		"/api/ping/reflect", "/api/ping/generic", "/api/ping/static-marker",
		"/api/ping/error",
	} {
		for _, f := range findings {
			if f.VulnerabilityType == "command_injection" && f.AffectedEndpoint == path {
				t.Errorf("SECURITY-NEGATIVE: %s was incorrectly flagged: %+v", path, f)
			}
		}
	}
}

// ---------------------------------------------------------------------
// AUTHENTICATED + MULTI-IDENTITY SESSION ISOLATION
// ---------------------------------------------------------------------

// deepAuthCmdInjectionOrchestrator mirrors
// phase3_25_ssrf_active_test.go's own deepAuthSSRFOrchestrator, with
// the registry replaced by ONLY command-injection-active.
func deepAuthCmdInjectionOrchestrator(t *testing.T, l *Lab, rules []models.ScopeRule) (*orchestrator.Orchestrator, storage.Store) {
	t.Helper()
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	for _, r := range rules {
		if err := store.ScopeRules().Create(context.Background(), r); err != nil {
			t.Fatalf("create scope rule %+v: %v", r, err)
		}
	}
	pipeline := &orchestration.Pipeline{
		Store:               store,
		Resolver:            l.Resolver,
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		DefaultPorts:        []int{mustPort(t, l.AuthAddr)},
		PortDialTimeout:     500 * time.Millisecond,
		HTTPConfig:          httpstage.Config{Timeout: 3 * time.Second, MaxRedirects: 5},
		Concurrency:         orchestration.Concurrency{DNSWorkers: 2, PortWorkers: 2, HTTPWorkers: 2},
		AllowReservedRanges: true,
		MaxCIDRHosts:        256,
		CrawlEnabled:        true,
		CrawlMaxDepth:       6,
		CrawlMaxPages:       30,
		Logger:              detectionLogger(),
	}
	registry := detection.NewRegistry()
	if err := registry.Register(cmdinjectionactive.New()); err != nil {
		t.Fatalf("Register(command-injection-active): %v", err)
	}
	orch := &orchestrator.Orchestrator{
		Store:                   store,
		Pipeline:                pipeline,
		DetectionRegistry:       registry,
		DetectionExecutorConfig: detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second},
		DetectionConcurrency:    2,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  detectionLogger(),
		Limits:                  orchestrator.Limits{MaxConcurrentScans: 5, MaxFindings: 1000, StageTimeout: 20 * time.Second},
	}
	return orch, store
}

func TestPhase3_26_AuthenticatedCmdInjection_TwoIdentities_SessionIsolated(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	sessA := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
	sessB := authenticateIdentity(t, l, "account-b", AccountBUsername, AccountBPassword, rules...)

	runFor := func(sess *auth.Session) (models.Finding, bool) {
		orch, store := deepAuthCmdInjectionOrchestrator(t, l, rules)
		result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
		if err != nil {
			t.Fatalf("ListByScanJob: %v", err)
		}
		return findCmdInjectionFor(findings, "/ping-exec", "host")
	}

	fA, foundA := runFor(sessA)
	fB, foundB := runFor(sessB)
	if !foundA || !foundB {
		t.Fatalf("expected both identities to independently produce a command_injection finding for /ping-exec: foundA=%v foundB=%v", foundA, foundB)
	}
	if fA.IdentityContext != "account-a" {
		t.Errorf("account-a finding IdentityContext = %q, want account-a", fA.IdentityContext)
	}
	if fB.IdentityContext != "account-b" {
		t.Errorf("account-b finding IdentityContext = %q, want account-b", fB.IdentityContext)
	}
}

// ---------------------------------------------------------------------
// DETERMINISM
// ---------------------------------------------------------------------

func TestPhase3_26_Determinism_RepeatedScans_SameFindingCount(t *testing.T) {
	l := testVulnLab(t)

	var counts []int
	for i := 0; i < 3; i++ {
		store, job, validator := runReconAgainstVulnLab(t, l)
		x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
		e := &detection.Engine{Registry: cmdInjectionActiveRegistry(t), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
		if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
			t.Fatalf("run %d: engine.Run: %v", i, err)
		}
		findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
		if err != nil {
			t.Fatalf("run %d: ListByScanJob: %v", i, err)
		}
		count := 0
		for _, f := range findings {
			if f.VulnerabilityType == "command_injection" {
				count++
			}
		}
		counts = append(counts, count)
	}
	for i := 1; i < len(counts); i++ {
		if counts[i] != counts[0] {
			t.Errorf("command_injection finding count not deterministic: run 0=%d run %d=%d", counts[0], i, counts[i])
		}
	}
}
