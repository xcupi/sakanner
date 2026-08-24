// Phase 3.23 Path Parameter Discovery & Active Detection Foundation:
// real orchestrator + real lab integration tests, proving the complete
// production path -- real crawl -> path discovery ->
// canonical Parameter -> persisted Parameter -> BuildTargets ->
// detection target -> mutation -> authenticated request execution ->
// response -> evidence -- via a REAL crawl of /paths/index
// (harness_path_parameters.go) and the authenticated /orders/{id}
// fixture (harness_auth.go). Reuses activeDetectionRegistry/
// coverageOrchestrator/formMutationOrchestrator from the Phase
// 3.21/3.22 files in this same package.
package lab

import (
	"context"
	"testing"
	"time"

	"sakanner/internal/detection"
	"sakanner/internal/orchestrator"
	"sakanner/pkg/models"
)

// ---------------------------------------------------------------------
// FULL CRAWL -> PATH DISCOVERY -> ACTIVE DETECTION (task section 13's
// central requirement)
// ---------------------------------------------------------------------

func TestPhase3_23_FullCrawl_SQLiViaNumericPathSegment_ReachesActiveDetection(t *testing.T) {
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
	found := false
	for _, f := range findings {
		if f.VulnerabilityType == "sql_injection" && f.DetectorID == "sqli-active" {
			for _, ep := range []string{"/users/1", "/users/2", "/users/3"} {
				if f.AffectedEndpoint == ep {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("expected a sql_injection finding on a real crawl-discovered numeric path segment (/users/N), got: %+v", findings)
	}
}

func TestPhase3_23_FullCrawl_XSSViaNonNumericPathSegment_ReachesActiveDetection(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	// coverageOrchestrator (Phase 3.22) registers BOTH sqli-active and
	// xss-reflected-active -- formMutationOrchestrator (Phase 3.21)
	// registers only sqli-active, which is why this test needs the
	// former specifically.
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
		if f.VulnerabilityType == "reflected_xss" && f.DetectorID == "xss-reflected-active" {
			for _, ep := range []string{"/products/widget-a", "/products/widget-b"} {
				if f.AffectedEndpoint == ep {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("expected a reflected_xss finding on a real crawl-discovered non-numeric path segment (/products/widget-*), got: %+v", findings)
	}
}

// ---------------------------------------------------------------------
// VERSION SEGMENT NEGATIVE, DUPLICATE PATHS -- via a REAL crawl
// ---------------------------------------------------------------------

func TestPhase3_23_FullCrawl_VersionSegment_NeverInferredOrTargeted(t *testing.T) {
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
	for _, p := range params {
		if p.Location == "path" && (p.Value == "v1" || p.Value == "v2") {
			t.Errorf("a version segment was inferred as a path parameter: %+v", p)
		}
	}

	targets, err := detection.BuildTargets(context.Background(), store, result.ScanID)
	if err != nil {
		t.Fatalf("BuildTargets: %v", err)
	}
	for _, tgt := range targets {
		if tgt.Path == "/api/v1/status" || tgt.Path == "/api/v2/status" {
			if tgt.Parameter != "" {
				t.Errorf("a version-segment endpoint unexpectedly produced a parameterized Target: %+v", tgt)
			}
		}
	}
}

func TestPhase3_23_FullCrawl_DuplicatePathValues_RemainDistinguishable(t *testing.T) {
	// Task section 8 (IDOR foundation): /users/1, /users/2, /users/3
	// must remain distinguishable as different concrete Endpoint/
	// Parameter rows sharing the same logical name ("user_id"), not
	// collapsed into one.
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := formMutationOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second})

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	params, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	values := map[string]bool{}
	for _, p := range params {
		if p.Location == "path" && p.Name == "user_id" {
			values[p.Value] = true
		}
	}
	for _, want := range []string{"1", "2", "3"} {
		if !values[want] {
			t.Errorf("expected a distinct user_id path parameter with Value=%q, got values: %v", want, values)
		}
	}
	if len(values) != 3 {
		t.Errorf("got %d distinct user_id values, want exactly 3 (never collapsed): %v", len(values), values)
	}
}

// ---------------------------------------------------------------------
// AUTHENTICATED PATH PARAMETER / IDENTITY A / IDENTITY B
// ---------------------------------------------------------------------

func TestPhase3_23_AuthenticatedPathSegment_FindingWithIdentityContext(t *testing.T) {
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
		if cand.VulnerabilityType == "sql_injection" && (cand.AffectedEndpoint == "/orders/1" || cand.AffectedEndpoint == "/orders/2") {
			f, found = cand, true
		}
	}
	if !found {
		t.Fatalf("expected a sql_injection finding from the authenticated /orders/{id} path segment, got: %+v", findings)
	}
	if f.IdentityContext != "account-a" {
		t.Errorf("Finding.IdentityContext = %q, want account-a", f.IdentityContext)
	}
}

func TestPhase3_23_IdentityAAndB_PathSegment_IndependentFindingsNoContamination(t *testing.T) {
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

	hasOrders := func(findings []models.Finding, identity string) bool {
		for _, f := range findings {
			if f.VulnerabilityType == "sql_injection" && (f.AffectedEndpoint == "/orders/1" || f.AffectedEndpoint == "/orders/2") && f.IdentityContext == identity {
				return true
			}
		}
		return false
	}
	if !hasOrders(findingsA, "account-a") {
		t.Error("expected account-a's scan to produce an /orders/{id} finding tagged account-a")
	}
	if !hasOrders(findingsB, "account-b") {
		t.Error("expected account-b's scan to produce an /orders/{id} finding tagged account-b")
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

func TestPhase3_23_ConcurrentIdentityScans_PathSegment_NoRaceNoContamination(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()
	execCfg := detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second}

	orchA, storeA := sqliActiveOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), execCfg)
	orchB, storeB := sqliActiveOrchestrator(t, l, rules, mustPort(t, l.AuthAddr), execCfg)

	// Authentication happens sequentially, BEFORE the concurrent
	// section -- see the identical fix (and its own explanation) in
	// TestPhase3_19_ConcurrentIdentityScans_NoRaceNoContamination.
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
	hasOrders := func(findings []models.Finding) bool {
		for _, f := range findings {
			if f.VulnerabilityType == "sql_injection" && (f.AffectedEndpoint == "/orders/1" || f.AffectedEndpoint == "/orders/2") {
				return true
			}
		}
		return false
	}
	if !hasOrders(findingsA) {
		t.Error("expected account-a's concurrent scan to produce an /orders/{id} finding")
	}
	if !hasOrders(findingsB) {
		t.Error("expected account-b's concurrent scan to produce an /orders/{id} finding")
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
// RESOURCE LIMITS / DETERMINISM
// ---------------------------------------------------------------------

func TestPhase3_23_ActiveRequestLimit_BoundsPathMutationRequests(t *testing.T) {
	l := testVulnLab(t)
	rules := []models.ScopeRule{{Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow}}
	orch, store := formMutationOrchestrator(t, l, rules, mustPort(t, l.VulnAddr), detection.ExecutorConfig{Concurrency: 2, Timeout: 3 * time.Second, MaxActiveRequestsPerScan: 1})

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
	if len(findings) > 10 {
		t.Errorf("got %d findings with a mutation budget of 1, want a small, bounded number", len(findings))
	}
}

func TestPhase3_23_Determinism_RepeatedCrawls_SamePathDiscoveryAndTargets(t *testing.T) {
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
		pathParamCount := 0
		for _, p := range params {
			if p.Location == "path" {
				pathParamCount++
			}
		}
		targets, err := detection.BuildTargets(context.Background(), store, result.ScanID)
		if err != nil {
			t.Fatalf("run %d BuildTargets: %v", i, err)
		}
		pathTargetCount := 0
		for _, tgt := range targets {
			if tgt.ParameterLocation == "path" {
				pathTargetCount++
			}
		}
		paramCounts = append(paramCounts, pathParamCount)
		targetCounts = append(targetCounts, pathTargetCount)
	}
	for i := 1; i < len(paramCounts); i++ {
		if paramCounts[i] != paramCounts[0] {
			t.Errorf("path parameter count not deterministic: run 0=%d run %d=%d", paramCounts[0], i, paramCounts[i])
		}
		if targetCounts[i] != targetCounts[0] {
			t.Errorf("path target count not deterministic: run 0=%d run %d=%d", targetCounts[0], i, targetCounts[i])
		}
	}
}
