// Phase 3.21 Form Request Discovery & Active Body Mutation Foundation:
// real orchestrator + real lab integration tests, proving the complete
// production path -- crawl -> form discovery -> canonical Parameter ->
// persisted Parameter -> BuildTargets -> detection target -> mutation
// -> authenticated request execution -> response -> evidence -- via a
// REAL crawl of /forms/index (harness_form_mutation.go) and the
// authenticated /lookup-form fixture (harness_auth.go), reusing
// sqliActiveRegistry/sqliActiveOrchestrator/findSQLi from
// phase3_20_sqli_active_test.go.
package lab

import (
	"context"
	"strconv"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/evidence"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/orchestration"
	"sakanner/internal/orchestrator"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

// formMutationOrchestrator mirrors sqliActiveOrchestrator (Phase 3.20)
// exactly, EXCEPT for a much higher CrawlMaxPages: the vuln lab's own
// index page has grown to 40+ links across every phase's own fixtures,
// and /forms/index (this phase's own link) is appended at the very
// end of that list -- sqliActiveOrchestrator's own CrawlMaxPages: 30
// (correct and sufficient for Phase 3.20's own needs, left unchanged
// so as not to perturb that phase's already-reported results) is not
// enough to guarantee reaching it within one breadth-first crawl. A
// dedicated helper, not a shared one, is the right fix: it affects
// only this file's own tests.
func formMutationOrchestrator(t *testing.T, l *Lab, rules []models.ScopeRule, port int, execCfg detection.ExecutorConfig) (*orchestrator.Orchestrator, storage.Store) {
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
		DetectionRegistry:       sqliActiveRegistry(t),
		DetectionExecutorConfig: execCfg,
		DetectionConcurrency:    2,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  detectionLogger(),
		Limits:                  orchestrator.Limits{MaxConcurrentScans: 5, MaxFindings: 1000, StageTimeout: 20 * time.Second},
	}
	return orch, store
}

// ---------------------------------------------------------------------
// FULL CRAWL -> FORM DISCOVERY -> ACTIVE DETECTION (task section 10's
// central requirement)
// ---------------------------------------------------------------------

func TestPhase3_21_FullCrawl_GETForm_ReachesActiveDetection(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := formMutationOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if _, found := findSQLi(findings); !found {
		t.Fatalf("expected a sql_injection finding reached via the real <form method=GET> on /forms/index, got: %+v", findings)
	}
}

func TestPhase3_21_FullCrawl_POSTForm_ReachesActiveDetection(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := formMutationOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	// This crawl also produces sql_injection findings for
	// /sqli/vulnerable and /sqli/boolean/vulnerable (both real,
	// already-reviewed positives, reachable via their own plain <a
	// href> links) -- findSQLi's own "first match" isn't specific
	// enough here, so this test looks for the ONE finding that can
	// only have come from the real <form method=POST> on /forms/index.
	var f models.Finding
	found := false
	for _, cand := range findings {
		if cand.VulnerabilityType == "sql_injection" && cand.AffectedEndpoint == "/sqli/form/vulnerable" {
			f, found = cand, true
		}
	}
	if !found {
		t.Fatalf("expected a sql_injection finding for /sqli/form/vulnerable, reached via the real <form method=POST> on /forms/index, got: %+v", findings)
	}
	if f.AffectedParameter != "id" {
		t.Errorf("AffectedParameter = %q, want id", f.AffectedParameter)
	}
}

// ---------------------------------------------------------------------
// DISCOVERY FIDELITY: hidden/textarea/select/checkbox/radio/CSRF,
// via a REAL crawl (not a directly-persisted parameter)
// ---------------------------------------------------------------------

func TestPhase3_21_FullCrawl_KitchenSinkForm_FieldsDiscoveredWithCorrectHidden(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := formMutationOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	params, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob parameters: %v", err)
	}

	byName := map[string]models.Parameter{}
	for _, p := range params {
		if p.Location == "form" {
			byName[p.Name] = p
		}
	}
	wantHidden := map[string]bool{
		"csrf_token":   true,
		"display_name": false,
		"bio":          false,
		"theme":        false,
		"newsletter":   false,
		"visibility":   false,
	}
	for name, wantH := range wantHidden {
		p, ok := byName[name]
		if !ok {
			t.Errorf("field %q not discovered via the real crawl (discovered form fields: %v)", name, byName)
			continue
		}
		if p.Hidden != wantH {
			t.Errorf("field %q Hidden = %v, want %v", name, p.Hidden, wantH)
		}
	}
	// The CSRF-shaped field's VALUE must be redacted at discovery time
	// -- Phase 3.15's own, unchanged redaction path (evidence.IsSensitiveFieldName).
	if byName["csrf_token"].Value == "lab-fixed-csrf-token" {
		t.Error("csrf_token's real value was persisted unredacted")
	}
}

func TestPhase3_21_FullCrawl_CSRFField_NeverBecomesItsOwnTarget_ButIsPreservedForSiblings(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := formMutationOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	targets, err := detection.BuildTargets(context.Background(), store, result.ScanID)
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	var displayNameTarget *detection.Target
	for i, tgt := range targets {
		if tgt.Parameter == "csrf_token" {
			t.Fatalf("SECURITY: csrf_token was promoted to its own active-mutation Target: %+v", tgt)
		}
		if tgt.Parameter == "display_name" {
			displayNameTarget = &targets[i]
		}
	}
	if displayNameTarget == nil {
		t.Fatal("expected a Target for the kitchen-sink form's own 'display_name' field")
	}
	if _, ok := displayNameTarget.FormFields["csrf_token"]; !ok {
		t.Error("display_name's Target.FormFields does not carry the sibling csrf_token field at all -- it would be silently dropped from the reconstructed request")
	}
}

// ---------------------------------------------------------------------
// RELATIVE / OUT-OF-SCOPE FORM ACTIONS, via a REAL crawl
// ---------------------------------------------------------------------

func TestPhase3_21_FullCrawl_RelativeFormAction_ResolvedAndTargetable(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := formMutationOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	endpoints, err := store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob endpoints: %v", err)
	}
	found := false
	for _, e := range endpoints {
		if e.Path == "/forms/relative-target" {
			found = true
			if e.ActionOrigin != "" && e.ActionOrigin != "http://vuln.scanner.test:"+portString(t, l) {
				t.Errorf("relative action's ActionOrigin = %q, want empty or the same-origin value", e.ActionOrigin)
			}
		}
	}
	if !found {
		t.Fatal("relative form action (\"relative-target\", on /forms/index) was not resolved to /forms/relative-target")
	}

	targets, err := detection.BuildTargets(context.Background(), store, result.ScanID)
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	for _, tgt := range targets {
		if tgt.Path == "/forms/relative-target" && tgt.Parameter == "q" {
			return // found -- the relative action resolved correctly AND became targetable
		}
	}
	t.Fatal("expected a Target for /forms/relative-target's 'q' field")
}

// TestPhase3_21_FullCrawl_OutOfScopeFormAction_NeverBecomesFinding:
// Phase 3.22 (docs/phase-3-22-active-detection-coverage.md section 7)
// changed WHAT this test asserts -- an out-of-scope form's fields now
// DO become Targets (pointed at their real destination, per Finding
// 3's resolution), but scope enforcement at EXECUTION time
// (mutation.Executor.resolveAndValidate, unchanged) must still refuse
// to ever dial external.scanner.test, so no FINDING can ever result.
// This is the correct, stronger property to test post-3.22: not "was
// a Target ever built" (an implementation detail that legitimately
// changed) but "can an out-of-scope destination ever produce a
// finding" (the actual security invariant, which must hold regardless
// of how Targets are constructed).
func TestPhase3_21_FullCrawl_OutOfScopeFormAction_NeverBecomesFinding(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := formMutationOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The out-of-scope form's own endpoint IS discovered (visibility --
	// task section 1's "preserve the original form action").
	endpoints, err := store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob endpoints: %v", err)
	}
	foundEndpoint := false
	for _, e := range endpoints {
		if e.Source == "form" && e.ActionOrigin == "http://external.scanner.test:80" {
			foundEndpoint = true
		}
	}
	if !foundEndpoint {
		t.Fatal("the out-of-scope form's own ActionOrigin was not recorded at all -- discovery itself regressed")
	}

	// A Target now IS built, targeting external.scanner.test directly
	// (with a nil IP, forcing a fresh resolve+scope-check) -- Phase
	// 3.22's own deliberate change from "excluded outright."
	targets, err := detection.BuildTargets(context.Background(), store, result.ScanID)
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	foundTarget := false
	for _, tgt := range targets {
		if tgt.Parameter == "secret" {
			foundTarget = true
			if tgt.Host != "external.scanner.test" || tgt.IP != nil {
				t.Errorf("Target = {Host:%q IP:%v}, want {external.scanner.test <nil>}", tgt.Host, tgt.IP)
			}
		}
	}
	if !foundTarget {
		t.Fatal("expected a Target for the out-of-scope form's 'secret' field, targeting its real destination")
	}

	// The actual security invariant: regardless of Target construction,
	// scope enforcement at EXECUTION time must still refuse to ever
	// dial external.scanner.test, so no finding can ever result.
	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob findings: %v", err)
	}
	for _, f := range findings {
		if f.AffectedParameter == "secret" {
			t.Fatalf("SECURITY: the out-of-scope form's 'secret' field produced a finding: %+v", f)
		}
	}
}

// ---------------------------------------------------------------------
// AUTHENTICATED POST FORM / IDENTITY A / IDENTITY B
// ---------------------------------------------------------------------

func TestPhase3_21_AuthenticatedPOSTForm_FindingWithIdentityContext(t *testing.T) {
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
	var f models.Finding
	found := false
	for _, cand := range findings {
		if cand.VulnerabilityType == "sql_injection" && cand.AffectedEndpoint == "/lookup-form" {
			f, found = cand, true
		}
	}
	if !found {
		t.Fatalf("expected a sql_injection finding from the authenticated /lookup-form POST form, got: %+v", findings)
	}
	if f.IdentityContext != "account-a" {
		t.Errorf("Finding.IdentityContext = %q, want account-a", f.IdentityContext)
	}
}

func TestPhase3_21_IdentityAAndB_POSTForm_IndependentFindingsNoContamination(t *testing.T) {
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

	hasLookupForm := func(findings []models.Finding, identity string) bool {
		for _, f := range findings {
			if f.VulnerabilityType == "sql_injection" && f.AffectedEndpoint == "/lookup-form" && f.IdentityContext == identity {
				return true
			}
		}
		return false
	}
	if !hasLookupForm(findingsA, "account-a") {
		t.Error("expected account-a's scan to produce a /lookup-form finding tagged account-a")
	}
	if !hasLookupForm(findingsB, "account-b") {
		t.Error("expected account-b's scan to produce a /lookup-form finding tagged account-b")
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
// DETERMINISM
// ---------------------------------------------------------------------

func TestPhase3_21_Determinism_RepeatedCrawls_SameFormDiscoveryAndTargets(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}

	var paramCounts, targetCounts []int
	for i := 0; i < 3; i++ {
		orch, store := formMutationOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})
		result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		params, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
		if err != nil {
			t.Fatalf("run %d ListByScanJob params: %v", i, err)
		}
		formParamCount := 0
		for _, p := range params {
			if p.Location == "form" {
				formParamCount++
			}
		}
		targets, err := detection.BuildTargets(context.Background(), store, result.ScanID)
		if err != nil {
			t.Fatalf("run %d BuildTargets: %v", i, err)
		}
		formTargetCount := 0
		for _, tgt := range targets {
			if tgt.ParameterLocation == "form" {
				formTargetCount++
			}
		}
		paramCounts = append(paramCounts, formParamCount)
		targetCounts = append(targetCounts, formTargetCount)
	}
	for i := 1; i < len(paramCounts); i++ {
		if paramCounts[i] != paramCounts[0] {
			t.Errorf("form parameter count not deterministic: run 0=%d run %d=%d", paramCounts[0], i, paramCounts[i])
		}
		if targetCounts[i] != targetCounts[0] {
			t.Errorf("form target count not deterministic: run 0=%d run %d=%d", targetCounts[0], i, targetCounts[i])
		}
	}
}

// portString returns l's vuln lab port as a string, for building an
// expected same-origin comparison string in
// TestPhase3_21_FullCrawl_RelativeFormAction_ResolvedAndTargetable.
func portString(t *testing.T, l *Lab) string {
	t.Helper()
	return strconv.Itoa(mustPort(t, l.VulnAddr))
}
