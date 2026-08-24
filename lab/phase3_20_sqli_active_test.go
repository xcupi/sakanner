// Phase 3.20 SQL Injection Active Detector: real orchestrator + real
// lab integration tests, proving the complete production path against
// the existing /sqli/* fixtures (error-based, boolean-only, generic-
// error negative, dynamic negative -- all reused as-is), the new
// /sqli/form/vulnerable and /sqli/json/vulnerable fixtures, and the
// new authenticated /lookup fixture (harness_auth.go).
package lab

import (
	"context"
	"fmt"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/sqliactive"
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

// sqliActiveRegistry registers ONLY sqli-active -- isolating this
// file's own tests from the pre-existing sqli detector, so a finding
// count here is never ambiguous about which detector produced it.
func sqliActiveRegistry(t *testing.T) *detection.Registry {
	t.Helper()
	r := detection.NewRegistry()
	if err := r.Register(sqliactive.New()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return r
}

// sqliActiveOrchestrator mirrors activeDetectionOrchestrator (Phase
// 3.19) exactly, swapping in sqliActiveRegistry.
func sqliActiveOrchestrator(t *testing.T, l *Lab, rules []models.ScopeRule, port int, execCfg detection.ExecutorConfig) (*orchestrator.Orchestrator, storage.Store) {
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
		DetectionRegistry:       sqliActiveRegistry(t),
		DetectionExecutorConfig: execCfg,
		DetectionConcurrency:    2,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  detectionLogger(),
		Limits:                  orchestrator.Limits{MaxConcurrentScans: 5, MaxFindings: 1000, StageTimeout: 20 * time.Second},
	}
	return orch, store
}

func findSQLi(findings []models.Finding) (models.Finding, bool) {
	for _, f := range findings {
		if f.VulnerabilityType == "sql_injection" && f.DetectorID == sqliactive.ID {
			return f, true
		}
	}
	return models.Finding{}, false
}

// ---------------------------------------------------------------------
// UNAUTHENTICATED POSITIVE (query, via the real vuln lab crawl)
// ---------------------------------------------------------------------

func TestPhase3_20_QueryParameter_FullCrawl_Finding(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := sqliActiveOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	f, found := findSQLi(findings)
	if !found {
		t.Fatalf("expected a sql_injection finding from the real crawl of /sqli/vulnerable, got: %+v", findings)
	}
	if f.AffectedParameter != "id" {
		t.Errorf("AffectedParameter = %q, want id", f.AffectedParameter)
	}
}

func TestPhase3_20_BenignEndpoints_NoFinding(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := sqliActiveOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	for _, f := range findings {
		if f.DetectorID != sqliactive.ID {
			continue
		}
		if f.AffectedEndpoint == "/sqli/safe" || f.AffectedEndpoint == "/sqli/boolean/safe" ||
			f.AffectedEndpoint == "/sqli/generic-error" || f.AffectedEndpoint == "/sqli/dynamic" {
			t.Errorf("SECURITY: a benign/false-positive-trap endpoint produced a finding: %+v", f)
		}
	}
}

func TestPhase3_20_BooleanOnlyEndpoint_Finding(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := sqliActiveOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

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
		if f.DetectorID == sqliactive.ID && f.AffectedEndpoint == "/sqli/boolean/vulnerable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a finding for /sqli/boolean/vulnerable (no error text, boolean-only), got: %+v", findings)
	}
}

// ---------------------------------------------------------------------
// FORM / JSON PARAMETER -- directly-persisted targets (form is not yet
// crawl-submitted; JSON request bodies are not yet crawl-discoverable
// -- both honest, pre-existing architectural facts, unchanged since
// Phase 3.18/3.19).
// ---------------------------------------------------------------------

// TestPhase3_20_FormParameter_ReachesActiveDetection: Phase 3.20 left
// this documented as a limitation (BuildTargets never routed
// Location=="form" parameters into Targets at all) -- Phase 3.21
// closes exactly this gap (see docs/phase-3-21-form-mutation.md). This
// test's own assertion is updated accordingly, mirroring how the
// equivalent JSON test evolved from "no target" (pre-3.19) to "target"
// (3.19 onward) in this same file's history.
func TestPhase3_20_FormParameter_ReachesActiveDetection(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	validator := scope.NewValidator(rules, true)
	ip := dial(t, "vuln.scanner.test", l)

	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	seedSQLiTarget(t, store, "form-job", ip.String(), mustPort(t, l.VulnAddr), "/sqli/form/vulnerable", "POST", "form", "REQUEST_INPUT")

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})
	engine := &detection.Engine{Registry: sqliActiveRegistry(t), Store: store, Executor: x, Logger: detectionLogger(), Concurrency: 2}
	if _, err := engine.Run(context.Background(), detection.RunOptions{ScanJobID: "form-job"}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), "form-job")
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	f, found := findSQLi(findings)
	if !found {
		t.Fatalf("expected a sql_injection finding from the POST-form parameter, got: %+v", findings)
	}
	if f.AffectedParameter != "id" {
		t.Errorf("AffectedParameter = %q, want id", f.AffectedParameter)
	}
}

func TestPhase3_20_JSONRequestInputParameter_ReachesActiveDetection(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	validator := scope.NewValidator(rules, true)
	ip := dial(t, "vuln.scanner.test", l)

	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	seedSQLiTarget(t, store, "json-job", ip.String(), mustPort(t, l.VulnAddr), "/sqli/json/vulnerable", "POST", "json", "REQUEST_INPUT")

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})
	engine := &detection.Engine{Registry: sqliActiveRegistry(t), Store: store, Executor: x, Logger: detectionLogger(), Concurrency: 2}
	if _, err := engine.Run(context.Background(), detection.RunOptions{ScanJobID: "json-job"}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), "json-job")
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	f, found := findSQLi(findings)
	if !found {
		t.Fatalf("expected a sql_injection finding from the JSON-body parameter, got: %+v", findings)
	}
	if f.AffectedParameter != "id" {
		t.Errorf("AffectedParameter = %q, want id", f.AffectedParameter)
	}
}

// ---------------------------------------------------------------------
// AUTHENTICATED POSITIVE / IDENTITY A / IDENTITY B
// ---------------------------------------------------------------------

func TestPhase3_20_AuthenticatedPositive_FindingWithIdentityContext(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	sess := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)

	orch, store := sqliActiveOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})
	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sess})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	f, found := findSQLi(findings)
	if !found {
		t.Fatalf("expected a sql_injection finding from the authenticated /lookup endpoint, got findings: %+v", findings)
	}
	if f.IdentityContext != "account-a" {
		t.Errorf("Finding.IdentityContext = %q, want account-a", f.IdentityContext)
	}
}

func TestPhase3_20_IdentityAAndB_IndependentFindingsNoContamination(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	sessA := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
	sessB := authenticateIdentity(t, l, "account-b", AccountBUsername, AccountBPassword, rules...)

	execCfg := detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second}
	orchA, storeA := sqliActiveOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), execCfg)
	resultA, err := orchA.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessA})
	if err != nil {
		t.Fatalf("Run account-a: %v", err)
	}
	orchB, storeB := sqliActiveOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), execCfg)
	resultB, err := orchB.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessB})
	if err != nil {
		t.Fatalf("Run account-b: %v", err)
	}

	findingsA, _ := storeA.Findings().ListByScanJob(context.Background(), resultA.ScanID)
	findingsB, _ := storeB.Findings().ListByScanJob(context.Background(), resultB.ScanID)

	fA, foundA := findSQLi(findingsA)
	fB, foundB := findSQLi(findingsB)
	if !foundA || !foundB {
		t.Fatalf("expected both identities to independently produce a finding: foundA=%v foundB=%v", foundA, foundB)
	}
	if fA.IdentityContext != "account-a" {
		t.Errorf("account-a finding IdentityContext = %q", fA.IdentityContext)
	}
	if fB.IdentityContext != "account-b" {
		t.Errorf("account-b finding IdentityContext = %q", fB.IdentityContext)
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

func TestPhase3_20_ConcurrentIdentityScans_NoRaceNoContamination(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	execCfg := detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second}

	orchA, storeA := sqliActiveOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), execCfg)
	orchB, storeB := sqliActiveOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), execCfg)

	// Authentication happens sequentially, BEFORE the concurrent section
	// -- authenticateIdentity calls t.Setenv, which testing.T does not
	// support calling from two goroutines at once (races on T's own
	// internal bookkeeping regardless of t.Parallel; see the identical
	// fix applied to TestPhase3_19_ConcurrentIdentityScans_NoRaceNoContamination).
	// What this test actually proves -- that two independently-
	// authenticated sessions never cross-contaminate findings when
	// scanned CONCURRENTLY -- only requires orch.Run itself to run
	// concurrently, not authentication.
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
	if _, found := findSQLi(findingsA); !found {
		t.Error("expected account-a's concurrent scan to produce a sql_injection finding")
	}
	if _, found := findSQLi(findingsB); !found {
		t.Error("expected account-b's concurrent scan to produce a sql_injection finding")
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
// RESOURCE LIMIT EXHAUSTION
// ---------------------------------------------------------------------

func TestPhase3_20_ActiveRequestLimit_BoundsRequestsNotUnbounded(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := sqliActiveOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second, MaxActiveRequestsPerScan: 1})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != orchestrator.StatusCompleted && result.Status != orchestrator.StatusCompletedWithWarnings {
		t.Fatalf("Status = %s, want a completed status even with an exhausted mutation budget", result.Status)
	}
	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(findings) > 5 {
		t.Errorf("got %d findings with a mutation budget of 1, want a small, bounded number", len(findings))
	}
}

// ---------------------------------------------------------------------
// DETERMINISM
// ---------------------------------------------------------------------

func TestPhase3_20_Determinism_RepeatedScans_SameStructuralResult(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}

	var counts []int
	var severities []models.Severity
	for i := 0; i < 3; i++ {
		orch, store := sqliActiveOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})
		result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
		if err != nil {
			t.Fatalf("run %d ListByScanJob: %v", i, err)
		}
		sqliFindings := 0
		var sev models.Severity
		for _, f := range findings {
			if f.DetectorID == sqliactive.ID {
				sqliFindings++
				if f.AffectedEndpoint == "/sqli/vulnerable" {
					sev = f.Severity
				}
			}
		}
		counts = append(counts, sqliFindings)
		severities = append(severities, sev)
	}
	for i := 1; i < len(counts); i++ {
		if counts[i] != counts[0] {
			t.Errorf("finding count not deterministic: run 0=%d run %d=%d", counts[0], i, counts[i])
		}
		if severities[i] != severities[0] {
			t.Errorf("severity not deterministic for /sqli/vulnerable: run 0=%s run %d=%s", severities[0], i, severities[i])
		}
	}
}

// ---------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------

func seedSQLiTarget(t *testing.T, store storage.Store, scanJobID, ip string, port int, path, method, location, provenance string) {
	t.Helper()
	now := time.Now().UTC()
	if err := store.ScanJobs().Create(context.Background(), models.ScanJob{ID: scanJobID, Status: models.ScanJobStatusRunning, StartedAt: now, CreatedAt: now}); err != nil {
		t.Fatalf("create scan job: %v", err)
	}
	if err := store.Assets().Create(context.Background(), models.Asset{ID: scanJobID + "-a1", ScanJobID: scanJobID, Name: "vuln.scanner.test", Source: "target", CreatedAt: now}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if err := store.Hosts().Create(context.Background(), models.Host{ID: scanJobID + "-h1", ScanJobID: scanJobID, AssetID: scanJobID + "-a1", IPAddress: ip, CreatedAt: now}); err != nil {
		t.Fatalf("create host: %v", err)
	}
	if err := store.Services().Create(context.Background(), models.Service{ID: scanJobID + "-svc1", ScanJobID: scanJobID, HostID: scanJobID + "-h1", Port: port, Protocol: "tcp", CreatedAt: now}); err != nil {
		t.Fatalf("create service: %v", err)
	}
	if err := store.HTTPServices().Create(context.Background(), models.HTTPService{
		ID: scanJobID + "-http1", ScanJobID: scanJobID, ServiceID: scanJobID + "-svc1",
		URL: fmt.Sprintf("http://vuln.scanner.test:%d/", port), Scheme: "http", StatusCode: 200, CreatedAt: now,
	}); err != nil {
		t.Fatalf("create http service: %v", err)
	}
	if err := store.Endpoints().Create(context.Background(), models.Endpoint{
		ID: scanJobID + "-ep1", ScanJobID: scanJobID, HTTPServiceID: scanJobID + "-http1", Path: path, Method: method, Source: "crawl", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
	if err := store.Parameters().Create(context.Background(), models.Parameter{
		ID: scanJobID + "-p1", ScanJobID: scanJobID, EndpointID: scanJobID + "-ep1", Name: "id", Location: location,
		Method: method, Provenance: provenance, CreatedAt: now,
	}); err != nil {
		t.Fatalf("create parameter: %v", err)
	}
}
