// Phase 3.22 Active Detection Coverage & Target Routing Completion:
// real orchestrator + real lab integration tests, proving xssactive's
// new form-location coverage end to end, and Phase 3.22's resolution
// of the Phase 3.21 cross-origin-form limitation (both the positive
// case -- a separately in-scope second host -- and the negative
// adversarial cases: same host different port, subdomain confusion).
// Reuses formMutationOrchestrator/sqliActiveOrchestrator/
// findSQLi/findReflectedXSS from the Phase 3.20/3.21/3.19 files in
// this same package.
package lab

import (
	"context"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/sqliactive"
	"sakanner/internal/detectors/xssactive"
	"sakanner/internal/evidence"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/orchestration"
	"sakanner/internal/orchestrator"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

// activeDetectionRegistry registers BOTH active detectors -- Phase
// 3.22's own routing-completion tests care about proving coverage
// across BOTH, not isolating one from the other the way earlier
// per-detector files did.
func activeDetectionRegistry(t *testing.T) *detection.Registry {
	t.Helper()
	r := detection.NewRegistry()
	if err := r.Register(sqliactive.New()); err != nil {
		t.Fatalf("Register sqliactive: %v", err)
	}
	if err := r.Register(xssactive.New()); err != nil {
		t.Fatalf("Register xssactive: %v", err)
	}
	return r
}

// coverageOrchestrator mirrors formMutationOrchestrator (Phase 3.21)
// exactly, swapping in activeDetectionRegistry and accepting an
// explicit rules slice so cross-origin/second-host tests can add more
// than one scope rule.
func coverageOrchestrator(t *testing.T, l *Lab, rules []models.ScopeRule, port int, execCfg detection.ExecutorConfig) (*orchestrator.Orchestrator, storage.Store) {
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
		DefaultPorts:        []int{port},
		PortDialTimeout:     500 * time.Millisecond,
		HTTPConfig:          httpstage.Config{Timeout: 3 * time.Second, MaxRedirects: 5},
		Concurrency:         orchestration.Concurrency{DNSWorkers: 2, PortWorkers: 2, HTTPWorkers: 2},
		AllowReservedRanges: true,
		MaxCIDRHosts:        256,
		CrawlEnabled:        true,
		CrawlMaxDepth:       6,
		CrawlMaxPages:       100,
		Logger:              detectionLogger(),
	}
	orch := &orchestrator.Orchestrator{
		Store:                   store,
		Pipeline:                pipeline,
		DetectionRegistry:       activeDetectionRegistry(t),
		DetectionExecutorConfig: execCfg,
		DetectionConcurrency:    2,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  detectionLogger(),
		Limits:                  orchestrator.Limits{MaxConcurrentScans: 5, MaxFindings: 1000, StageTimeout: 20 * time.Second},
	}
	return orch, store
}

// ---------------------------------------------------------------------
// XSS VIA POST FORM -- FULL CRAWL (task section 3's central requirement)
// ---------------------------------------------------------------------

func TestPhase3_22_FullCrawl_XSSViaPOSTForm_ReachesActiveDetection(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := coverageOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.VulnerabilityType == "reflected_xss" && f.AffectedEndpoint == "/xss/reflected/form-vulnerable" {
			found = true
			if f.AffectedParameter != "q" {
				t.Errorf("AffectedParameter = %q, want q", f.AffectedParameter)
			}
		}
	}
	if !found {
		t.Fatalf("expected a reflected_xss finding for /xss/reflected/form-vulnerable, reached via the real <form method=POST> on /forms/index, got: %+v", findings)
	}
}

// ---------------------------------------------------------------------
// AUTHENTICATED XSS VIA POST FORM / IDENTITY A / IDENTITY B
// ---------------------------------------------------------------------

func TestPhase3_22_AuthenticatedXSSForm_FindingWithIdentityContext(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	sess := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)

	orch, store := coverageOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})
	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	var f models.Finding
	found := false
	for _, cand := range findings {
		if cand.VulnerabilityType == "reflected_xss" && cand.AffectedEndpoint == "/search-form" {
			f, found = cand, true
		}
	}
	if !found {
		t.Fatalf("expected a reflected_xss finding from the authenticated /search-form POST form, got: %+v", findings)
	}
	if f.IdentityContext != "account-a" {
		t.Errorf("Finding.IdentityContext = %q, want account-a", f.IdentityContext)
	}
}

func TestPhase3_22_IdentityAAndB_XSSForm_IndependentFindingsNoContamination(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	sessA := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
	sessB := authenticateIdentity(t, l, "account-b", AccountBUsername, AccountBPassword, rules...)

	execCfg := detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second}
	orchA, storeA := coverageOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), execCfg)
	resultA, err := orchA.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessA})
	if err != nil {
		t.Fatalf("Run account-a: %v", err)
	}
	orchB, storeB := coverageOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), execCfg)
	resultB, err := orchB.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessB})
	if err != nil {
		t.Fatalf("Run account-b: %v", err)
	}

	findingsA, _ := storeA.Findings().ListByScanJob(context.Background(), resultA.ScanID)
	findingsB, _ := storeB.Findings().ListByScanJob(context.Background(), resultB.ScanID)

	hasSearchForm := func(findings []models.Finding, identity string) bool {
		for _, f := range findings {
			if f.VulnerabilityType == "reflected_xss" && f.AffectedEndpoint == "/search-form" && f.IdentityContext == identity {
				return true
			}
		}
		return false
	}
	if !hasSearchForm(findingsA, "account-a") {
		t.Error("expected account-a's scan to produce a /search-form finding tagged account-a")
	}
	if !hasSearchForm(findingsB, "account-b") {
		t.Error("expected account-b's scan to produce a /search-form finding tagged account-b")
	}
	for _, f := range findingsA {
		if f.IdentityContext == "account-b" {
			t.Fatal("SECURITY: account-a's scan job contains an account-b-tagged finding")
		}
	}
	for _, f := range findingsB {
		if f.IdentityContext == "account-a" {
			t.Fatal("SECURITY: account-b's scan job contains an account-a-tagged finding")
		}
	}
}

// ---------------------------------------------------------------------
// CROSS-ORIGIN FORM ACTION -- SEPARATELY IN-SCOPE SECOND HOST
// (Phase 3.22 section 7's positive resolution)
// ---------------------------------------------------------------------

func TestPhase3_22_FullCrawl_SeparatelyInScopeSecondHost_ReachesActiveDetection(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{
		{ID: "rule-vuln", Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow},
		{ID: "rule-second-host", Value: "second-service.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow},
	}
	orch, store := coverageOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.VulnerabilityType == "sql_injection" && f.Host == "second-service.scanner.test" {
			found = true
			if f.AffectedParameter != "id" {
				t.Errorf("AffectedParameter = %q, want id", f.AffectedParameter)
			}
		}
	}
	if !found {
		t.Fatalf("expected a sql_injection finding against second-service.scanner.test (a genuinely separate, separately in-scope host reached via a cross-origin form action), got: %+v", findings)
	}
}

func TestPhase3_22_FullCrawl_SecondHostNotInScope_NoFindingAgainstIt(t *testing.T) {
	// Identical crawl, but WITHOUT second-service.scanner.test in
	// scope -- the cross-origin form's field must never produce a
	// finding against it, proving scope enforcement (not merely
	// Target construction) is what actually gates this.
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := coverageOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	for _, f := range findings {
		if f.Host == "second-service.scanner.test" {
			t.Fatalf("SECURITY: a finding was produced against second-service.scanner.test while it was NOT in scope: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------
// ADVERSARIAL: SAME HOST DIFFERENT PORT / SUBDOMAIN CONFUSION
// (task section 14, at the BuildTargets level -- no live second
// listener is needed to prove the routing decision itself)
// ---------------------------------------------------------------------

func TestPhase3_22_BuildTargets_SameHostDifferentPort_TreatedAsCrossOrigin(t *testing.T) {
	store := newLabTestStoreForTargets(t)
	seedFormEndpoint(t, store, "job-port", "vuln.scanner.test", 80, "/action", "http://vuln.scanner.test:8443")

	targets, err := detection.BuildTargets(context.Background(), store, "job-port")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	var found *detection.Target
	for i, tgt := range targets {
		if tgt.Parameter == "id" {
			found = &targets[i]
		}
	}
	if found == nil {
		t.Fatal("expected a Target for the same-host-different-port form's 'id' field")
	}
	if found.Port != 8443 {
		t.Errorf("Port = %d, want 8443 (the form's OWN action port, not the crawled HTTPService's port 80)", found.Port)
	}
	if found.IP != nil {
		t.Errorf("IP = %v, want nil (a different port is a different origin -- must be resolved and scope-validated fresh)", found.IP)
	}
}

func TestPhase3_22_BuildTargets_SubdomainConfusion_TreatedAsCrossOrigin(t *testing.T) {
	store := newLabTestStoreForTargets(t)
	seedFormEndpoint(t, store, "job-subdomain", "vuln.scanner.test", 80, "/action", "http://evil.vuln.scanner.test:80")

	targets, err := detection.BuildTargets(context.Background(), store, "job-subdomain")
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	var found *detection.Target
	for i, tgt := range targets {
		if tgt.Parameter == "id" {
			found = &targets[i]
		}
	}
	if found == nil {
		t.Fatal("expected a Target for the subdomain-confusion form's 'id' field")
	}
	if found.Host != "evil.vuln.scanner.test" {
		t.Errorf("Host = %q, want evil.vuln.scanner.test (a subdomain is a DIFFERENT host, never silently equated with its parent)", found.Host)
	}
	if found.IP != nil {
		t.Errorf("IP = %v, want nil", found.IP)
	}
}

// ---------------------------------------------------------------------
// DETERMINISM (extended to cover xssactive's new form coverage)
// ---------------------------------------------------------------------

func TestPhase3_22_Determinism_RepeatedCrawls_SameXSSFormFindings(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}

	var counts []int
	for i := 0; i < 3; i++ {
		orch, store := coverageOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})
		result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
		if err != nil {
			t.Fatalf("run %d ListByScanJob: %v", i, err)
		}
		n := 0
		for _, f := range findings {
			if f.VulnerabilityType == "reflected_xss" && f.AffectedEndpoint == "/xss/reflected/form-vulnerable" {
				n++
			}
		}
		counts = append(counts, n)
	}
	for i := 1; i < len(counts); i++ {
		if counts[i] != counts[0] {
			t.Errorf("XSS-via-form finding count not deterministic: run 0=%d run %d=%d", counts[0], i, counts[i])
		}
	}
}

// ---------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------

func newLabTestStoreForTargets(t *testing.T) storage.Store {
	t.Helper()
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// seedFormEndpoint directly persists a minimal recon+form-endpoint+
// parameter chain for a BuildTargets-level adversarial test -- no live
// crawl or listener needed, since these tests only check ROUTING
// decisions (Target.Host/Port/IP), not live execution.
func seedFormEndpoint(t *testing.T, store storage.Store, scanJobID, host string, port int, path, actionOrigin string) {
	t.Helper()
	now := time.Now().UTC()
	ctx := context.Background()
	if err := store.ScanJobs().Create(ctx, models.ScanJob{ID: scanJobID, Status: models.ScanJobStatusRunning, StartedAt: now, CreatedAt: now}); err != nil {
		t.Fatalf("create scan job: %v", err)
	}
	if err := store.Assets().Create(ctx, models.Asset{ID: scanJobID + "-a1", ScanJobID: scanJobID, Name: host, Source: "target", CreatedAt: now}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := store.Hosts().Create(ctx, models.Host{ID: scanJobID + "-h1", ScanJobID: scanJobID, AssetID: scanJobID + "-a1", IPAddress: "127.0.0.21", CreatedAt: now}); err != nil {
		t.Fatalf("create host: %v", err)
	}
	if err := store.Services().Create(ctx, models.Service{ID: scanJobID + "-svc1", ScanJobID: scanJobID, HostID: scanJobID + "-h1", Port: port, Protocol: "tcp", CreatedAt: now}); err != nil {
		t.Fatalf("create service: %v", err)
	}
	if err := store.HTTPServices().Create(ctx, models.HTTPService{
		ID: scanJobID + "-http1", ScanJobID: scanJobID, ServiceID: scanJobID + "-svc1",
		URL: "http://" + host + "/", Scheme: "http", StatusCode: 200, CreatedAt: now,
	}); err != nil {
		t.Fatalf("create http service: %v", err)
	}
	if err := store.Endpoints().Create(ctx, models.Endpoint{
		ID: scanJobID + "-ep1", ScanJobID: scanJobID, HTTPServiceID: scanJobID + "-http1", Path: path, Method: "POST",
		Source: "form", ActionOrigin: actionOrigin, CreatedAt: now,
	}); err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
	if err := store.Parameters().Create(ctx, models.Parameter{
		ID: scanJobID + "-p1", ScanJobID: scanJobID, EndpointID: scanJobID + "-ep1", Name: "id", Location: "form",
		Method: "POST", Provenance: "REQUEST_INPUT", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}
}
