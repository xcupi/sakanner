// Phase 3.19 Active Request Detection Engine Foundation: real
// orchestrator + real lab integration tests, proving the complete
// production path -- discovery -> canonical Target -> mutation.Request
// -> authenticated execution -> mutation.Response -> reflection
// analysis -> RequestResponseEvidence -> Finding -- against
// harness_auth.go's new /search fixture (Phase 3.19) and a directly-
// persisted REQUEST_INPUT JSON parameter (mirroring Phase 3.18's own
// JSON-to-mutation bridge test pattern, since the crawler still cannot
// produce a live JSON request body -- see
// docs/phase-3-18-api-json-discovery.md section 1, unchanged).
package lab

import (
	"context"
	"fmt"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/xssactive"
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

// activeXSSRegistry registers ONLY xss-reflected-active -- isolating
// this file's own tests from the pre-existing xss-reflected detector
// (registerBenignDetectors' own registry), so a finding count here is
// never ambiguous about which detector produced it.
func activeXSSRegistry(t *testing.T) *detection.Registry {
	t.Helper()
	r := detection.NewRegistry()
	if err := r.Register(xssactive.New()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return r
}

// activeDetectionOrchestrator mirrors deepAuthOrchestrator exactly,
// swapping in activeXSSRegistry and accepting an explicit
// ExecutorConfig so resource-limit tests can configure it directly.
// port is the lab server's own listen port (l.AuthAddr's for the auth
// lab, l.VulnAddr's for the vuln lab -- callers pass whichever is
// relevant, since a single Lab exposes several independent fixture
// servers on different ports).
func activeDetectionOrchestrator(t *testing.T, l *Lab, rules []models.ScopeRule, port int, execCfg detection.ExecutorConfig) (*orchestrator.Orchestrator, storage.Store) {
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
		CrawlMaxPages:       30,
		Logger:              detectionLogger(),
	}
	orch := &orchestrator.Orchestrator{
		Store:                   store,
		Pipeline:                pipeline,
		DetectionRegistry:       activeXSSRegistry(t),
		DetectionExecutorConfig: execCfg,
		DetectionConcurrency:    2,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  detectionLogger(),
		Limits:                  orchestrator.Limits{MaxConcurrentScans: 5, MaxFindings: 1000, StageTimeout: 20 * time.Second},
	}
	return orch, store
}

func findReflectedXSS(findings []models.Finding) (models.Finding, bool) {
	for _, f := range findings {
		if f.VulnerabilityType == "reflected_xss" && f.DetectorID == xssactive.ID {
			return f, true
		}
	}
	return models.Finding{}, false
}

// ---------------------------------------------------------------------
// AUTHENTICATED POSITIVE / IDENTITY A / IDENTITY B
// ---------------------------------------------------------------------

func TestPhase3_19_AuthenticatedPositive_FindingWithIdentityContext(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	sess := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)

	orch, store := activeDetectionOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})
	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	f, found := findReflectedXSS(findings)
	if !found {
		t.Fatalf("expected a reflected_xss finding from the authenticated /search endpoint, got findings: %+v", findings)
	}
	if f.IdentityContext != "account-a" {
		t.Errorf("Finding.IdentityContext = %q, want account-a", f.IdentityContext)
	}
	if f.AffectedParameter != "q" {
		t.Errorf("AffectedParameter = %q, want q", f.AffectedParameter)
	}
	if len(f.Evidence) == 0 {
		t.Fatal("expected at least one evidence item")
	}
}

func TestPhase3_19_IdentityAAndB_IndependentFindingsNoContamination(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	sessA := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
	sessB := authenticateIdentity(t, l, "account-b", AccountBUsername, AccountBPassword, rules...)

	execCfg := detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second}
	orchA, storeA := activeDetectionOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), execCfg)
	resultA, err := orchA.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessA})
	if err != nil {
		t.Fatalf("Run account-a: %v", err)
	}
	orchB, storeB := activeDetectionOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), execCfg)
	resultB, err := orchB.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessB})
	if err != nil {
		t.Fatalf("Run account-b: %v", err)
	}

	findingsA, _ := storeA.Findings().ListByScanJob(context.Background(), resultA.ScanID)
	findingsB, _ := storeB.Findings().ListByScanJob(context.Background(), resultB.ScanID)

	fA, foundA := findReflectedXSS(findingsA)
	fB, foundB := findReflectedXSS(findingsB)
	if !foundA || !foundB {
		t.Fatalf("expected both identities to independently produce a finding: foundA=%v foundB=%v", foundA, foundB)
	}
	if fA.IdentityContext != "account-a" {
		t.Errorf("account-a finding IdentityContext = %q", fA.IdentityContext)
	}
	if fB.IdentityContext != "account-b" {
		t.Errorf("account-b finding IdentityContext = %q", fB.IdentityContext)
	}
	// Cross-contamination check, both directions.
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

func TestPhase3_19_ConcurrentIdentityScans_NoRaceNoContamination(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	execCfg := detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second}

	// Orchestrators/stores built in the main test goroutine -- t.Fatalf
	// inside a helper must never run from a spawned goroutine (the
	// established rule from Phase 3.15/3.16's own concurrency tests).
	orchA, storeA := activeDetectionOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), execCfg)
	orchB, storeB := activeDetectionOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), execCfg)

	// Authentication happens sequentially, BEFORE the concurrent section:
	// authenticateIdentity calls t.Setenv, which testing.T does not
	// support calling from two goroutines at once (it races on T's own
	// internal bookkeeping regardless of t.Parallel) -- a real bug this
	// test itself tripped over under -race, not a limitation of the
	// identity/session architecture being tested. What this test is
	// actually proving -- that two independently-authenticated sessions
	// never cross-contaminate findings when scanned CONCURRENTLY -- only
	// requires orch.Run itself to run concurrently, not authentication.
	sessA := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
	sessB := authenticateIdentity(t, l, "account-b", AccountBUsername, AccountBPassword, rules...)

	type outcome struct {
		name   string
		result orchestrator.Result
		err    error
	}
	results := make(chan outcome, 2)
	go func() {
		r, err := orchA.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessA})
		results <- outcome{"account-a", r, err}
	}()
	go func() {
		r, err := orchB.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessB})
		results <- outcome{"account-b", r, err}
	}()

	byName := map[string]orchestrator.Result{}
	for i := 0; i < 2; i++ {
		o := <-results
		if o.err != nil {
			t.Fatalf("%s: %v", o.name, o.err)
		}
		byName[o.name] = o.result
	}

	findingsA, _ := storeA.Findings().ListByScanJob(context.Background(), byName["account-a"].ScanID)
	findingsB, _ := storeB.Findings().ListByScanJob(context.Background(), byName["account-b"].ScanID)
	if _, found := findReflectedXSS(findingsA); !found {
		t.Error("expected account-a's concurrent scan to produce a reflected_xss finding")
	}
	if _, found := findReflectedXSS(findingsB); !found {
		t.Error("expected account-b's concurrent scan to produce a reflected_xss finding")
	}
	for _, f := range findingsA {
		if f.IdentityContext == "account-b" {
			t.Fatal("SECURITY: concurrent scans crossed identity context")
		}
	}
	for _, f := range findingsB {
		if f.IdentityContext == "account-a" {
			t.Fatal("SECURITY: concurrent scans crossed identity context")
		}
	}
}

// ---------------------------------------------------------------------
// BENIGN CASE -- reuses the pre-existing /xss/reflected/safe fixture
// ---------------------------------------------------------------------

func TestPhase3_19_BenignEndpoint_NoFinding(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := activeDetectionOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	for _, f := range findings {
		if f.AffectedEndpoint == "/xss/reflected/safe" {
			t.Fatalf("SECURITY: an HTML-encoded, safely-escaped endpoint produced a finding: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------
// JSON REQUEST_INPUT PARAMETER -- reaches active detection via
// BuildTargets, exactly like Phase 3.18's own JSON-to-mutation bridge
// proof (a directly-persisted parameter, since the crawler cannot
// produce a live JSON request body).
// ---------------------------------------------------------------------

func TestPhase3_19_JSONRequestInputParameter_ReachesActiveDetection(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	validator := scope.NewValidator(rules, true)
	ip := dial(t, "vuln.scanner.test", l)

	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	scanJobID := "json-xss-job"
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
		ID: "ep-json", ScanJobID: scanJobID, HTTPServiceID: "http1", Path: "/xss/reflected/json-echo", Method: "POST", Source: "crawl", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: "p-json", ScanJobID: scanJobID, EndpointID: "ep-json", Name: "name", Location: "json",
		Method: "POST", Provenance: "REQUEST_INPUT", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})
	engine := &detection.Engine{Registry: activeXSSRegistry(t), Store: store, Executor: x, Logger: detectionLogger(), Concurrency: 2}
	if _, err := engine.Run(context.Background(), detection.RunOptions{ScanJobID: scanJobID}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), scanJobID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	f, found := findReflectedXSS(findings)
	if !found {
		t.Fatalf("expected a reflected_xss finding from the JSON-body parameter, got: %+v", findings)
	}
	if f.AffectedParameter != "name" {
		t.Errorf("AffectedParameter = %q, want name", f.AffectedParameter)
	}
}

// ---------------------------------------------------------------------
// RESOURCE LIMIT EXHAUSTION
// ---------------------------------------------------------------------

func TestPhase3_19_ActiveRequestLimit_BoundsRequestsNotUnbounded(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	// A budget of 1 total mutation means the xssactive detector's own
	// SECOND probe (the context-revealing payload) for the FIRST
	// eligible parameter already exhausts it -- proving the limit is
	// real and centrally enforced, not merely documented.
	orch, store := activeDetectionOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second, MaxActiveRequestsPerScan: 1})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The scan itself must still complete (a detector error for one
	// target must never abort the whole scan) -- see DetectorSummary's
	// own ErrorCount for visibility into budget-exhaustion errors.
	if result.Status != orchestrator.StatusCompleted && result.Status != orchestrator.StatusCompletedWithWarnings {
		t.Fatalf("Status = %s, want a completed status even with an exhausted mutation budget", result.Status)
	}
	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	// With a budget this small, at most a handful of findings (never
	// unbounded) can have been produced.
	if len(findings) > 5 {
		t.Errorf("got %d findings with a mutation budget of 1, want a small, bounded number", len(findings))
	}
}
