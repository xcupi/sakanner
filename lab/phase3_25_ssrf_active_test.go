// Phase 3.25 SSRF Active Detection Foundation: real orchestrator/
// engine + real lab integration tests, against harness_vuln.go's
// existing /ssrf/* fixtures and harness_ssrf_active.go's own new
// form/JSON/path/blind/redirect additions. Mirrors
// lab/phase3_4_ssrf_test.go's own ssrfRegistry/testVulnLab/
// runReconAgainstVulnLab pattern, and phase3_19_active_detection_test.go's
// directly-persisted-parameter pattern for the JSON-body case (the
// crawler cannot yet discover a live JSON REQUEST_INPUT parameter --
// an honest, pre-existing Phase 3.19 limitation, not something this
// phase regresses or is expected to close).
package lab

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"sakanner/internal/auth"
	"sakanner/internal/detection"
	"sakanner/internal/detectors/ssrf"
	"sakanner/internal/detectors/ssrfactive"
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

// ssrfInternalMarker is the distinctive substring
// ssrfInternalHandler's own existing JSON response already contains
// (harness_vuln.go) -- reused verbatim as ssrfactive's Mode A marker,
// so this phase never needs a new "internal resource" lab server (see
// docs/phase-3-25-ssrf-active-detection.md section 3).
const ssrfInternalMarker = "ssrf-internal-fixture"

// ssrfActiveRegistry returns a fresh Registry with only ssrf-active
// registered, wired to l's real SSRFCallback and SSRFInternalAddr --
// isolating these tests from every other detector's own findings.
func ssrfActiveRegistry(t *testing.T, l *Lab) *detection.Registry {
	t.Helper()
	if l.SSRFCallback == nil {
		t.Fatal("lab has no SSRFCallback -- StartWithVulnerabilities wiring problem")
	}
	r := detection.NewRegistry()
	if err := r.Register(ssrfactive.New(l.SSRFCallback, "http://"+l.SSRFInternalAddr+"/", ssrfInternalMarker)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return r
}

// findSSRFFor locates the ssrf finding for a specific endpoint path +
// parameter name -- NOT parameter name alone, since multiple distinct
// /ssrf/* fixtures share the same "url" parameter name across
// different endpoints (e.g. /ssrf/vulnerable and
// /ssrf/vulnerable-blind), each producing its own, independently-
// confidenced finding.
func findSSRFFor(findings []models.Finding, endpoint, parameter string) (models.Finding, bool) {
	for _, f := range findings {
		if f.VulnerabilityType == "ssrf" && f.AffectedEndpoint == endpoint && f.AffectedParameter == parameter {
			return f, true
		}
	}
	return models.Finding{}, false
}

// ---------------------------------------------------------------------
// POSITIVE: query, form, path locations (real crawl discovery)
// ---------------------------------------------------------------------

func TestPhase3_25_QueryLocation_ResponseBasedAndCallback_Finding(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: ssrfActiveRegistry(t, l), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	f, found := findSSRFFor(findings, "/ssrf/vulnerable", "url")
	if !found {
		t.Fatalf("expected an ssrf finding for the url query parameter, got: %+v", findings)
	}
	// /ssrf/vulnerable genuinely fetches whatever URL it's given and
	// embeds the fetched body -- BOTH modes should confirm here.
	if f.Confidence != 0.95 {
		t.Errorf("Confidence = %v, want 0.95 (both modes confirmed against a genuinely vulnerable, response-embedding endpoint)", f.Confidence)
	}
	if len(f.Evidence) != 3 {
		t.Errorf("expected 3 evidence items (baseline + mode-A + mode-B), got %d", len(f.Evidence))
	}
}

// runReconAgainstVulnLabDeep mirrors phase3_1_detection_test.go's own
// runReconAgainstVulnLab exactly, except with a much higher
// CrawlMaxPages -- the vuln app's root index now links dozens of
// fixtures across every phase, and /forms/index (where this phase's
// own form-location SSRF fixture lives, alongside every other
// vulnerability class's own form example) is one extra hop away,
// competing with all of them for the SAME page budget. Mirrors
// tests/e2e/e2e_active_form_mutation_test.go's own identical "raise
// max_pages" precedent (Phase 3.21) rather than raising the SHARED
// helper's own budget, which other, unrelated tests rely on staying
// as-is.
func runReconAgainstVulnLabDeep(t *testing.T, l *Lab) (storage.Store, models.ScanJob, scope.Validator) {
	t.Helper()

	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	targetID := "target-" + t.Name()
	if err := store.Targets().Create(context.Background(), models.Target{ID: targetID, Value: "vuln.scanner.test", Type: models.TargetTypeHost, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := store.ScopeRules().Create(context.Background(), models.ScopeRule{ID: "rule-" + t.Name(), Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}); err != nil {
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
		CrawlMaxDepth:       3,
		CrawlMaxPages:       150,
		Logger:              detectionLogger(),
	}
	job, err := p.Run(context.Background(), orchestration.RunOptions{TargetIDs: []string{targetID}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed (error: %s)", job.Status, job.Error)
	}
	validator := scope.NewValidator(job.ScopeSnapshot, true)
	return store, job, validator
}

func TestPhase3_25_FormLocation_Finding(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLabDeep(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: ssrfActiveRegistry(t, l), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if _, found := findSSRFFor(findings, "/ssrf/vulnerable-form", "url"); !found {
		t.Fatalf("expected an ssrf finding for /ssrf/vulnerable-form's url parameter, got: %+v", findings)
	}
	params, err := store.Parameters().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob (parameters): %v", err)
	}
	foundFormParam := false
	for _, p := range params {
		if p.Location == "form" && p.Name == "url" {
			foundFormParam = true
		}
	}
	if !foundFormParam {
		t.Fatalf("expected a form-location url Parameter to have been discovered via the real crawl (/forms/index -> /ssrf/vulnerable-form): %+v", params)
	}
}

func TestPhase3_25_PathLocation_Finding(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: ssrfActiveRegistry(t, l), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	params, err := store.Parameters().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob (parameters): %v", err)
	}
	foundPathParam := false
	for _, p := range params {
		if p.Location == "path" {
			foundPathParam = true
			if p.PathSegmentIndex < 0 {
				t.Errorf("PathSegmentIndex = %d, want >= 0 for a persisted path parameter", p.PathSegmentIndex)
			}
		}
	}
	if !foundPathParam {
		t.Fatalf("expected a path-location parameter to have been discovered via the real crawl (/ssrf/fetch/<value>, two example links): %+v", params)
	}
}

// ---------------------------------------------------------------------
// POSITIVE: JSON body -- directly-persisted parameter (see file doc
// comment for why the crawler itself cannot discover this)
// ---------------------------------------------------------------------

func TestPhase3_25_JSONLocation_DirectlyPersisted_Finding(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	validator := scope.NewValidator(rules, true)
	ip := dial(t, "vuln.scanner.test", l)

	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	scanJobID := "ssrf-json-job"
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
		ID: "ep-ssrf-json", ScanJobID: scanJobID, HTTPServiceID: "http1", Path: "/ssrf/vulnerable-json", Method: "POST", Source: "crawl", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: "p-ssrf-json", ScanJobID: scanJobID, EndpointID: "ep-ssrf-json", Name: "url", Location: "json",
		Method: "POST", Provenance: "REQUEST_INPUT", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})
	e := &detection.Engine{Registry: ssrfActiveRegistry(t, l), Store: store, Executor: x, Logger: detectionLogger(), Concurrency: 2}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: scanJobID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), scanJobID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if _, found := findSSRFFor(findings, "/ssrf/vulnerable-json", "url"); !found {
		t.Fatalf("expected an ssrf finding from the JSON-body url parameter, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------
// NEGATIVE: safe endpoint, negative controls, non-object params
// ---------------------------------------------------------------------

func TestPhase3_25_SafeEndpoint_NoFinding(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: ssrfActiveRegistry(t, l), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	for _, f := range findings {
		if f.VulnerabilityType == "ssrf" && f.AffectedEndpoint == "/ssrf/safe" {
			t.Fatalf("SECURITY-NEGATIVE: /ssrf/safe (allowlist-checked, never fetches) was incorrectly flagged: %+v", f)
		}
	}
}

func TestPhase3_25_NegativeControls_NoFinding(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: ssrfActiveRegistry(t, l), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	for _, path := range []string{"/ssrf/reflect-only", "/ssrf/store-only", "/ssrf/client-fetch", "/ssrf/validate-reject"} {
		for _, f := range findings {
			if f.VulnerabilityType == "ssrf" && f.AffectedEndpoint == path {
				t.Errorf("SECURITY-NEGATIVE: %s was incorrectly flagged: %+v", path, f)
			}
		}
	}
}

// ---------------------------------------------------------------------
// BLIND-ONLY and REDIRECT-THROUGH
// ---------------------------------------------------------------------

func TestPhase3_25_BlindOnly_Finding(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: ssrfActiveRegistry(t, l), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
	if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.VulnerabilityType == "ssrf" && f.AffectedEndpoint == "/ssrf/vulnerable-blind" {
			found = true
			if f.Confidence != 0.9 {
				t.Errorf("Confidence = %v, want 0.9 (callback-only -- this endpoint's response can NEVER reveal fetch outcome)", f.Confidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected an ssrf finding for /ssrf/vulnerable-blind (Mode B/callback only), findings: %+v", findings)
	}
}

// TestPhase3_25_RedirectThroughCallback_CallbackRecordsHit is an
// infrastructure-level proof (not through Detect at all): the TARGET
// APPLICATION's own outbound http.Client follows a server-side
// redirect and still reaches the real callback server -- proving
// "callback through redirect" (task section 12) requires zero
// detector-side redirect-specific code, since the whole hop happens
// entirely within the vuln app's own network path, invisible to the
// scanner except via the callback server's own recorded hit.
func TestPhase3_25_RedirectThroughCallback_CallbackRecordsHit(t *testing.T) {
	l := testVulnLab(t)
	if l.SSRFCallback == nil {
		t.Fatal("lab has no SSRFCallback")
	}
	token, callbackURL, err := l.SSRFCallback.NewToken(context.Background())
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	bounceURL := fmt.Sprintf("http://%s/ssrf/redirect-bounce?to=%s", l.VulnAddr, url.QueryEscape(callbackURL))
	vulnerableURL := fmt.Sprintf("http://%s/ssrf/vulnerable?url=%s", l.VulnAddr, url.QueryEscape(bounceURL))

	mustGetBody(t, vulnerableURL)

	deadline := time.Now().Add(2 * time.Second)
	var obs []ssrf.Observation
	for time.Now().Before(deadline) {
		obs, err = l.SSRFCallback.Observations(context.Background(), token)
		if err != nil {
			t.Fatalf("Observations: %v", err)
		}
		if len(obs) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(obs) == 0 {
		t.Fatal("callback was never recorded despite the redirect-through chain")
	}
}

// ---------------------------------------------------------------------
// AUTHENTICATED + MULTI-IDENTITY SESSION ISOLATION
// ---------------------------------------------------------------------

// deepAuthSSRFOrchestrator mirrors phase3_15_authenticated_crawl_test.go's
// own deepAuthOrchestrator, with the registry replaced by ONLY
// ssrf-active (Mode B/callback only -- the auth app has no
// internal-resource-style fixture, and this test cares about
// identity/session isolation, not confidence tier).
func deepAuthSSRFOrchestrator(t *testing.T, l *Lab, rules []models.ScopeRule) (*orchestrator.Orchestrator, storage.Store) {
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
	if err := registry.Register(ssrfactive.New(l.SSRFCallback, "", "")); err != nil {
		t.Fatalf("Register(ssrf-active): %v", err)
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

func TestPhase3_25_AuthenticatedSSRF_TwoIdentities_SessionIsolated(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	sessA := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
	sessB := authenticateIdentity(t, l, "account-b", AccountBUsername, AccountBPassword, rules...)

	runFor := func(sess *auth.Session) (models.Finding, bool) {
		orch, store := deepAuthSSRFOrchestrator(t, l, rules)
		result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
		if err != nil {
			t.Fatalf("ListByScanJob: %v", err)
		}
		return findSSRFFor(findings, "/ssrf-fetch", "url")
	}

	fA, foundA := runFor(sessA)
	fB, foundB := runFor(sessB)
	if !foundA || !foundB {
		t.Fatalf("expected both identities to independently produce an ssrf finding for /ssrf-fetch: foundA=%v foundB=%v", foundA, foundB)
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

func TestPhase3_25_Determinism_RepeatedScans_SameFindingCount(t *testing.T) {
	l := testVulnLab(t)

	var counts []int
	for i := 0; i < 3; i++ {
		store, job, validator := runReconAgainstVulnLab(t, l)
		x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
		e := &detection.Engine{Registry: ssrfActiveRegistry(t, l), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}
		if _, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID}); err != nil {
			t.Fatalf("run %d: engine.Run: %v", i, err)
		}
		findings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
		if err != nil {
			t.Fatalf("run %d: ListByScanJob: %v", i, err)
		}
		ssrfCount := 0
		for _, f := range findings {
			if f.VulnerabilityType == "ssrf" {
				ssrfCount++
			}
		}
		counts = append(counts, ssrfCount)
	}
	for i := 1; i < len(counts); i++ {
		if counts[i] != counts[0] {
			t.Errorf("ssrf finding count not deterministic: run 0=%d run %d=%d", counts[0], i, counts[i])
		}
	}
}
