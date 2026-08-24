// Phase 3.24 Authorization & IDOR/BOLA Detection Foundation: real
// orchestrator + real lab integration tests, against
// harness_authorization.go's five fixtures (/notes, /documents,
// /shared, /ping, /archive -- see that file's own doc comment).
// Mirrors phase3_16_multi_identity_test.go's own two-identity
// authentication pattern exactly, extended with a SECOND,
// independently-constructed *detection.Executor for the compare
// identity (mirroring cmd/scanner/scan.go's own buildAuthzExecutor,
// duplicated here since it is unexported from package main). See
// docs/phase-3-24-authorization.md section 17's "no synthetic-only
// proof sufficient" requirement -- the CLI-level proof lives in
// tests/e2e/e2e_authorization_test.go; this file is the lower-level,
// orchestrator-direct proof plus the session-isolation/determinism/
// concurrency scenarios that are cheaper to run without a subprocess
// per iteration.
package lab

import (
	"context"
	"testing"
	"time"

	"sakanner/internal/auth"
	"sakanner/internal/detection"
	"sakanner/internal/detectors/idoractive"
	"sakanner/internal/evidence"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/mutation"
	"sakanner/internal/orchestration"
	"sakanner/internal/orchestrator"
	"sakanner/internal/scope"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

// buildAuthzCompareExecutor mirrors cmd/scanner/scan.go's own
// buildAuthzExecutor exactly (same detection.NewExecutorWithSession
// call, same session.JarFor(session.Host)/HeadersFor(session.Host)
// host-pinning) -- duplicated here since that function is unexported
// from package main, exactly as sqliactive/xssactive's own test files
// duplicate fakeValidator rather than sharing test helpers across
// packages. Uses l.Resolver (the lab's own fake resolver, which knows
// how to resolve auth.scanner.test) in place of production's
// dns.New(cfg.DNS.Timeout).
func buildAuthzCompareExecutor(t *testing.T, l *Lab, rules []models.ScopeRule, sess *auth.Session) *detection.Executor {
	t.Helper()
	validator := scope.NewValidator(rules, true)
	sessCtx := mutation.SessionContext{
		Jar: sess.JarFor(sess.Host), Headers: sess.HeadersFor(sess.Host),
		PinnedHost: sess.Host, IdentityContext: sess.IdentityName,
	}
	return detection.NewExecutorWithSession(validator, l.Resolver, detection.ExecutorConfig{}, sessCtx)
}

// deepAuthzOrchestrator mirrors phase3_15_authenticated_crawl_test.go's
// own deepAuthOrchestrator, with the registry replaced by ONLY
// idor-active (constructed with compareExecutor/compareIdentity) --
// deliberately minimal, mirroring registerBenignDetectors' own
// minimal philosophy, since these tests exist to prove idor-active's
// OWN behavior end to end, not to re-prove every other detector.
func deepAuthzOrchestrator(t *testing.T, l *Lab, rules []models.ScopeRule, compareExecutor *detection.Executor, compareIdentity string) (*orchestrator.Orchestrator, storage.Store) {
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
	if err := registry.Register(idoractive.New(compareExecutor, compareIdentity)); err != nil {
		t.Fatalf("Register(idor-active): %v", err)
	}
	if err := registry.SetEnabled(idoractive.ID, true); err != nil {
		t.Fatalf("SetEnabled(idor-active): %v", err)
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

// runAuthzScan authenticates both identities, builds the compare
// identity's own executor, and runs the baseline identity's scan with
// idor-active enabled against baselineIdentity/compareIdentity's
// credentials -- the one shared setup every test below uses.
func runAuthzScan(t *testing.T, l *Lab, rules []models.ScopeRule, baselineName, baselineUser, baselinePass, compareName, compareUser, comparePass string) (orchestrator.Result, storage.Store) {
	t.Helper()
	baselineSess := authenticateIdentity(t, l, baselineName, baselineUser, baselinePass, rules...)
	compareSess := authenticateIdentity(t, l, compareName, compareUser, comparePass, rules...)
	compareExecutor := buildAuthzCompareExecutor(t, l, rules, compareSess)

	orch, store := deepAuthzOrchestrator(t, l, rules, compareExecutor, compareName)
	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: baselineSess})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return result, store
}

// ---------------------------------------------------------------------
// END-TO-END: vulnerable, safe, and adversarial fixtures
// ---------------------------------------------------------------------

func TestPhase3_24_EndToEnd_HorizontalAuthorizationFailure_RealPipeline(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	result, store := runAuthzScan(t, l, rules, "account-a", AccountAUsername, AccountAPassword, "account-b", AccountBUsername, AccountBPassword)

	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	var found *models.Finding
	for i := range findings {
		if findings[i].VulnerabilityType == "idor" && findings[i].AffectedParameter == "note_id" {
			found = &findings[i]
		}
	}
	if found == nil {
		t.Fatalf("no idor finding for note_id -- findings: %+v", findings)
	}
	if found.IdentityContext != "account-b" {
		t.Errorf("finding IdentityContext = %q, want account-b (the acting identity)", found.IdentityContext)
	}
	if len(found.Evidence) != 3 {
		t.Errorf("expected 3 evidence items, got %d", len(found.Evidence))
	}
}

func TestPhase3_24_SafeOwnershipCheck_NoFinding(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	result, store := runAuthzScan(t, l, rules, "account-a", AccountAUsername, AccountAPassword, "account-b", AccountBUsername, AccountBPassword)

	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	for _, f := range findings {
		if f.VulnerabilityType == "idor" && f.AffectedParameter == "doc_id" {
			t.Fatalf("SECURITY-NEGATIVE: /documents?doc_id= (a genuinely ownership-checked endpoint) was incorrectly flagged: %+v", f)
		}
	}
}

func TestPhase3_24_GenericResponseRegardlessOfValue_NoFinding(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	result, store := runAuthzScan(t, l, rules, "account-a", AccountAUsername, AccountAPassword, "account-b", AccountBUsername, AccountBPassword)

	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	for _, f := range findings {
		if f.VulnerabilityType == "idor" && f.AffectedParameter == "request_id" {
			t.Fatalf("/ping?request_id= (a constant response regardless of value) should never be flagged -- the known-bad-control mechanism must suppress this: %+v", f)
		}
	}
}

func TestPhase3_24_NonObjectParameter_ArchivePage_NeverEligible(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	result, store := runAuthzScan(t, l, rules, "account-a", AccountAUsername, AccountAPassword, "account-b", AccountBUsername, AccountBPassword)

	params, err := store.Parameters().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob (parameters): %v", err)
	}
	foundPage := false
	for _, p := range params {
		if p.Name == "page" {
			foundPage = true
		}
	}
	if !foundPage {
		t.Fatalf("expected /archive?page= to be DISCOVERED (as an input) even though it is never authorization-tested")
	}

	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob (findings): %v", err)
	}
	for _, f := range findings {
		if f.VulnerabilityType == "idor" && f.AffectedParameter == "page" {
			t.Fatalf("a plainly non-object, pagination-shaped parameter was flagged for authorization testing: %+v", f)
		}
	}
}

// TestPhase3_24_SharedObject_DocumentedLimitation demonstrates, on
// purpose, docs/phase-3-24-authorization.md section 15's own honestly
// documented limitation: an object legitimately, intentionally
// accessible to BOTH tested identities cannot be distinguished from a
// genuine authorization failure by response comparison alone. This is
// NOT a bug -- it is why every finding this detector produces is
// evidence for human review, not an infallible verdict. This test
// exists to prove the limitation is real and understood, not to prove
// "correct" behavior in the sense the other tests in this file do.
func TestPhase3_24_SharedObject_DocumentedLimitation(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	result, store := runAuthzScan(t, l, rules, "account-a", AccountAUsername, AccountAPassword, "account-b", AccountBUsername, AccountBPassword)

	findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	found := false
	for _, f := range findings {
		if f.VulnerabilityType == "idor" && f.AffectedParameter == "share_id" {
			found = true
		}
	}
	if !found {
		// Not a failure -- see this test's own doc comment. If this ever
		// starts passing spontaneously (no finding), the detector became
		// MORE conservative, which is still acceptable -- but flag it as
		// a note so a future reader knows this is diverging from the
		// documented, expected (if unfortunate) baseline.
		t.Log("NOTE: /shared?share_id= was NOT flagged -- the detector is behaving more conservatively than docs/phase-3-24-authorization.md section 15 describes; this is not a regression, just worth knowing")
	}
}

// ---------------------------------------------------------------------
// SESSION ISOLATION (docs/phase-3-24-authorization.md section 7)
// ---------------------------------------------------------------------

// TestPhase3_24_SessionIsolation_ReversedDirection_NoCrossContamination
// runs the SAME two accounts in BOTH directions (A baseline / B
// compare, then B baseline / A compare) sequentially, proving neither
// scan's findings, evidence, or credentials leak into the other's --
// task's own "sequential A->B, B->A" requirement.
func TestPhase3_24_SessionIsolation_ReversedDirection_NoCrossContamination(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	resultAB, storeAB := runAuthzScan(t, l, rules, "account-a", AccountAUsername, AccountAPassword, "account-b", AccountBUsername, AccountBPassword)
	resultBA, storeBA := runAuthzScan(t, l, rules, "account-b", AccountBUsername, AccountBPassword, "account-a", AccountAUsername, AccountAPassword)

	findingsAB, err := storeAB.Findings().ListByScanJob(context.Background(), resultAB.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob AB: %v", err)
	}
	findingsBA, err := storeBA.Findings().ListByScanJob(context.Background(), resultBA.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob BA: %v", err)
	}
	for _, f := range findingsAB {
		if f.IdentityContext != "" && f.IdentityContext != "account-b" {
			t.Errorf("A-baseline/B-compare scan produced a finding attributed to %q, want account-b", f.IdentityContext)
		}
	}
	for _, f := range findingsBA {
		if f.IdentityContext != "" && f.IdentityContext != "account-a" {
			t.Errorf("B-baseline/A-compare scan produced a finding attributed to %q, want account-a", f.IdentityContext)
		}
	}
}

// TestPhase3_24_ConcurrentIdentityPairs_NoCrossContamination runs both
// directions truly concurrently -- task's own "concurrent A+B"
// requirement. Every *testing.T-touching call (t.Setenv via
// authenticateIdentity, t.Fatalf via deepAuthzOrchestrator) happens in
// the MAIN goroutine first, exactly mirroring
// phase3_16_multi_identity_test.go's own
// TestPhase3_16_ConcurrentIdentities_AccountAAndB structure -- Go's
// testing package itself forbids t.Setenv from a non-test goroutine
// (detected as a race by `go test -race`, not a real production
// concern), so only the actual orch.Run call -- which never touches t
// -- happens inside the spawned goroutines below.
func TestPhase3_24_ConcurrentIdentityPairs_NoCrossContamination(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	sessA := authenticateIdentity(t, l, "account-a", AccountAUsername, AccountAPassword, rules...)
	sessB := authenticateIdentity(t, l, "account-b", AccountBUsername, AccountBPassword, rules...)
	compareForA := buildAuthzCompareExecutor(t, l, rules, sessB) // used by the A-baseline scan
	compareForB := buildAuthzCompareExecutor(t, l, rules, sessA) // used by the B-baseline scan
	orchAB, storeAB := deepAuthzOrchestrator(t, l, rules, compareForA, "account-b")
	orchBA, storeBA := deepAuthzOrchestrator(t, l, rules, compareForB, "account-a")

	type outcome struct {
		name     string
		findings []models.Finding
		err      error
	}
	results := make(chan outcome, 2)
	go func() {
		result, err := orchAB.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessA})
		if err != nil {
			results <- outcome{name: "A-baseline", err: err}
			return
		}
		findings, err := storeAB.Findings().ListByScanJob(context.Background(), result.ScanID)
		results <- outcome{name: "A-baseline", findings: findings, err: err}
	}()
	go func() {
		result, err := orchBA.Run(context.Background(), orchestrator.Options{Target: "auth.scanner.test", AuthSession: sessB})
		if err != nil {
			results <- outcome{name: "B-baseline", err: err}
			return
		}
		findings, err := storeBA.Findings().ListByScanJob(context.Background(), result.ScanID)
		results <- outcome{name: "B-baseline", findings: findings, err: err}
	}()

	for i := 0; i < 2; i++ {
		o := <-results
		if o.err != nil {
			t.Fatalf("%s: %v", o.name, o.err)
		}
		wantIdentity := "account-b"
		if o.name == "B-baseline" {
			wantIdentity = "account-a"
		}
		for _, f := range o.findings {
			if f.IdentityContext != "" && f.IdentityContext != wantIdentity {
				t.Errorf("SECURITY: %s scan produced a finding attributed to %q, want %q", o.name, f.IdentityContext, wantIdentity)
			}
		}
	}
}

// ---------------------------------------------------------------------
// DETERMINISM
// ---------------------------------------------------------------------

func TestPhase3_24_Determinism_RepeatedScans_SameFindingCount(t *testing.T) {
	l := testAuthLab(t)
	rules := authScopeRules()

	var counts []int
	for i := 0; i < 3; i++ {
		result, store := runAuthzScan(t, l, rules, "account-a", AccountAUsername, AccountAPassword, "account-b", AccountBUsername, AccountBPassword)
		findings, err := store.Findings().ListByScanJob(context.Background(), result.ScanID)
		if err != nil {
			t.Fatalf("run %d: ListByScanJob: %v", i, err)
		}
		idorCount := 0
		for _, f := range findings {
			if f.VulnerabilityType == "idor" {
				idorCount++
			}
		}
		counts = append(counts, idorCount)
	}
	for i := 1; i < len(counts); i++ {
		if counts[i] != counts[0] {
			t.Errorf("idor finding count not deterministic: run 0=%d run %d=%d", counts[0], i, counts[i])
		}
	}
}
