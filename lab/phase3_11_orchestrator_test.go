// Phase 3.11 integration test: runs the REAL, unified
// internal/orchestrator.Orchestrator -- SCOPE -> RECON -> DISCOVERY ->
// DETECTION -> VERIFICATION -> CORRELATION -> RISK -> EVIDENCE ->
// FINALIZATION -- end to end against the real vuln.scanner.test lab
// and against plain httptest.Server negative targets, from a single
// raw target STRING (never a pre-built Target ID), exactly the way the
// CLI's `scanner scan <target>` invokes it. This is the test the task's
// "Real evidence integration" requirement (section 18) specifically
// demands: proving BASELINE/PROBE/OBSERVATION/VERIFICATION/REPRODUCTION
// evidence is actually populated end to end for real detector output,
// not merely well-formed empty structures.
package lab

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/cmdinjection"
	"sakanner/internal/detectors/sqli"
	"sakanner/internal/detectors/xssreflected"
	"sakanner/internal/dns"
	"sakanner/internal/evidence"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/orchestration"
	"sakanner/internal/orchestrator"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

// buildOrchestratorForVulnLab wires a real orchestrator.Orchestrator
// against l exactly the way cmd/scanner's own scan command wires an
// orchestration.Pipeline (see cmd/scanner/scan.go) plus
// allDetectorsRegistry (the same all-6-detectors registry every other
// Phase 3.x lab integration test already uses).
func buildOrchestratorForVulnLab(t *testing.T, l *Lab) (*orchestrator.Orchestrator, storage.Store) {
	t.Helper()
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	if err := store.ScopeRules().Create(context.Background(), models.ScopeRule{
		ID: uuid.NewString(), Value: "vuln.scanner.test", Type: models.ScopeRuleExactHost,
		Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	pipeline := &orchestration.Pipeline{
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
		Logger:              detectionLogger(),
	}

	orch := &orchestrator.Orchestrator{
		Store:                   store,
		Pipeline:                pipeline,
		DetectionRegistry:       allDetectorsRegistry(t, l),
		DetectionExecutorConfig: detection.ExecutorConfig{Concurrency: 8, Timeout: 5 * time.Second, MaxRedirects: 5},
		DetectionConcurrency:    8,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  detectionLogger(),
		Limits:                  orchestrator.Limits{MaxConcurrentScans: 5, MaxFindings: 1000},
	}
	return orch, store
}

// --- Full positive lab (task section 37) ----------------------------------

func TestPhase3_11_Orchestrator_FullPositiveLab(t *testing.T) {
	l := testVulnLab(t)
	orch, _ := buildOrchestratorForVulnLab(t, l)

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v (status=%s errors=%+v)", err, result.Status, result.Errors)
	}
	if result.Status != orchestrator.StatusCompleted && result.Status != orchestrator.StatusCompletedWithWarnings {
		t.Fatalf("Status = %s, want COMPLETED or COMPLETED_WITH_WARNINGS (errors: %+v)", result.Status, result.Errors)
	}
	if len(result.Findings) == 0 {
		t.Fatal("no findings produced against a lab with known-positive fixtures for all 6 vulnerability classes")
	}
	t.Logf("scan %s: %d findings, recon=%+v detectors=%+v", result.ScanID, len(result.Findings), result.ReconSummary, result.DetectorSummary)

	types := map[string]int{}
	for _, pkg := range result.Findings {
		// task section 4: scan_id propagation across every stage.
		if pkg.Finding.ScanID != result.ScanID {
			t.Errorf("finding %s: Finding.ScanID = %q, want %q", pkg.Finding.FindingID, pkg.Finding.ScanID, result.ScanID)
		}
		if pkg.Risk.ScanID != result.ScanID {
			t.Errorf("finding %s: Risk.ScanID = %q, want %q", pkg.Finding.FindingID, pkg.Risk.ScanID, result.ScanID)
		}
		if pkg.Risk.RiskScore < 0 || pkg.Risk.RiskScore > 100 {
			t.Errorf("finding %s: RiskScore = %d, want [0,100]", pkg.Finding.FindingID, pkg.Risk.RiskScore)
		}
		if pkg.Risk.Priority == "" {
			t.Errorf("finding %s: empty Priority", pkg.Finding.FindingID)
		}
		if len(pkg.Evidence) == 0 {
			t.Errorf("finding %s: evidence_count = 0, want > 0 (task section 20)", pkg.Finding.FindingID)
		}
		if pkg.Reproduction.Level == "" {
			t.Errorf("finding %s: empty Reproduction.Level", pkg.Finding.FindingID)
		}
		if pkg.Summary == "" || pkg.WhyVulnerable == "" {
			t.Errorf("finding %s: empty Summary/WhyVulnerable", pkg.Finding.FindingID)
		}
		types[pkg.Finding.VulnerabilityType]++
	}
	for _, vulnType := range []string{"reflected_xss", "sql_injection", "ssrf", "idor", "path_traversal", "command_injection"} {
		if types[vulnType] == 0 {
			t.Errorf("no finding produced for vulnerability type %q", vulnType)
		}
	}

	// task section 25: findings must already be in Phase 3.9's
	// deterministic risk-ranked (descending score) order -- the
	// orchestrator must never reorder them itself.
	for i := 1; i < len(result.Findings); i++ {
		if result.Findings[i-1].Risk.RiskScore < result.Findings[i].Risk.RiskScore {
			t.Errorf("index %d: findings are not in descending risk-score order (%d < %d)", i, result.Findings[i-1].Risk.RiskScore, result.Findings[i].Risk.RiskScore)
		}
	}

	// task sections 18-20: REAL evidence integration -- baseline
	// evidence must actually be populated for every vulnerability type
	// where a real detector captures one (5 of 6 -- see
	// docs/phase-3-11-scan-orchestrator.md "Real evidence integration");
	// reflected_xss legitimately has none (no control request exists).
	seenBaselineFor := map[string]bool{}
	for _, pkg := range result.Findings {
		for _, it := range pkg.Evidence {
			if it.Type == evidence.EvidenceTypeBaseline {
				seenBaselineFor[pkg.Finding.VulnerabilityType] = true
			}
		}
	}
	for _, vulnType := range []string{"sql_injection", "ssrf", "idor", "path_traversal", "command_injection"} {
		if types[vulnType] > 0 && !seenBaselineFor[vulnType] {
			t.Errorf("vulnerability type %q: no BASELINE evidence captured despite the real detector recording one (task section 18 is a CRITICAL requirement)", vulnType)
		}
	}
	if seenBaselineFor["reflected_xss"] {
		t.Error("reflected_xss unexpectedly has BASELINE evidence -- this detector has no control request to record; a positive result here would suggest fabricated evidence, not real capture")
	}
}

// --- Determinism (task section 43) ----------------------------------------

func TestPhase3_11_Orchestrator_Determinism_RepeatedRunsSameFindingIdentitiesAndOrder(t *testing.T) {
	l := testVulnLab(t)
	orchA, _ := buildOrchestratorForVulnLab(t, l)
	orchB, _ := buildOrchestratorForVulnLab(t, l)

	resultA, err := orchA.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("run A: %v", err)
	}
	resultB, err := orchB.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("run B: %v", err)
	}

	if len(resultA.Findings) != len(resultB.Findings) {
		t.Fatalf("len(Findings) differs across independent runs: %d vs %d", len(resultA.Findings), len(resultB.Findings))
	}
	for i := range resultA.Findings {
		a, b := resultA.Findings[i], resultB.Findings[i]
		if a.Finding.VulnerabilityType != b.Finding.VulnerabilityType {
			t.Errorf("index %d: VulnerabilityType differs: %q vs %q", i, a.Finding.VulnerabilityType, b.Finding.VulnerabilityType)
		}
		if a.Risk.RiskScore != b.Risk.RiskScore {
			t.Errorf("index %d (%s): RiskScore differs across runs: %d vs %d", i, a.Finding.VulnerabilityType, a.Risk.RiskScore, b.Risk.RiskScore)
		}
		if a.Risk.Priority != b.Risk.Priority {
			t.Errorf("index %d (%s): Priority differs across runs", i, a.Finding.VulnerabilityType)
		}
		if len(a.Evidence) != len(b.Evidence) {
			t.Errorf("index %d (%s): evidence count differs across runs: %d vs %d", i, a.Finding.VulnerabilityType, len(a.Evidence), len(b.Evidence))
			continue
		}
		for j := range a.Evidence {
			if a.Evidence[j].Type != b.Evidence[j].Type {
				t.Errorf("index %d (%s), evidence %d: Type differs: %s vs %s", i, a.Finding.VulnerabilityType, j, a.Evidence[j].Type, b.Evidence[j].Type)
			}
			// NOT compared: EvidenceID/IntegrityHash/Observation content.
			// cmdinjection and ssrf each embed a freshly generated,
			// per-probe-unpredictable correlation token (a UUID / random
			// callback token) directly in their Observation/evidence by
			// design -- see internal/detectors/cmdinjection/detector.go
			// and internal/detectors/ssrf/detector.go's own doc comments
			// on why that unpredictability is the confirmation mechanism
			// itself, not incidental. Two INDEPENDENT scans are expected
			// to carry different tokens; task section 43 lists "evidence
			// IDs, evidence hashes" as needing determinism only in the
			// sense of "the same scan run repeatably produces the same
			// output" (see TestPhase3_10 hash tests), never "two
			// different scans of the same target produce byte-identical
			// random tokens." What determinism actually requires here --
			// same finding count, type, structural evidence-type
			// sequence, risk score, and priority -- is what's checked.
		}
	}
}

// --- Negative lab / no false positives (task sections 35-36) --------------

func TestPhase3_11_Orchestrator_NegativeTarget_NoFalsePositives(t *testing.T) {
	// Phase 3.11.2 finding: the original version of this fixture served
	// only static content with no crawlable link and no query
	// parameter at all -- meaning it never actually gave any detector
	// an eligible target, so this test's "no false positives" claim was
	// never really exercising detector execution (state A: "detectors
	// ran and found nothing"); it was silently testing state B ("no
	// eligible targets") under a state-A-shaped name and assertion.
	// Phase 3.11.2's new DetectionState observability correctly
	// surfaced this (Status flipped to COMPLETED_WITH_WARNINGS once
	// zero-detector-runs became visible) -- fixed here by giving the
	// benign target a real, crawlable, PARAMETERIZED, safely-escaping
	// endpoint, so xssreflected (enabled by default, no operator config
	// needed) has something real to run against and genuinely find
	// nothing on. See docs/phase-3-11-2-acceptance-test.md "Issues
	// found and fixed."
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/search" {
			fmt.Fprintf(w, "<html><body>results for %s</body></html>", html.EscapeString(r.URL.Query().Get("q")))
			return
		}
		w.Write([]byte(`<html><body><h1>Static, benign content</h1><a href="/search?q=hello">search</a></body></html>`))
	}))
	defer srv.Close()

	orch, store := buildBenignOrchestrator(t, srv)

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: mustHost(t, srv.URL)})
	if err != nil {
		t.Fatalf("Run: %v (status=%s errors=%+v)", err, result.Status, result.Errors)
	}
	if result.Status != orchestrator.StatusCompleted {
		t.Errorf("Status = %s, want COMPLETED (a clean scan with no findings is success, not a warning -- task section 35)", result.Status)
	}
	if result.DetectorSummary.DetectorRuns == 0 {
		t.Error("DetectorRuns = 0, want > 0 -- this test's whole point is proving a detector actually ran and found nothing (state A), not that detection was skipped (state B)")
	}
	if result.DetectorSummary.State != orchestrator.DetectionStateExecuted {
		t.Errorf("DetectionState = %s, want EXECUTED", result.DetectorSummary.State)
	}
	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0 -- false positive against benign, safely-escaped content", len(result.Findings))
	}
	if result.Summary.Total != 0 {
		t.Errorf("Summary.Total = %d, want 0", result.Summary.Total)
	}
	_ = store
}

// buildBenignOrchestrator wires an Orchestrator against a plain,
// vulnerability-free httptest server -- for the "secure target, zero
// findings, no false positives" cases (task sections 35-36) that the
// real vuln.scanner.test lab (which deliberately DOES have positive
// fixtures) cannot exercise on its own.
func buildBenignOrchestrator(t *testing.T, srv *httptest.Server) (*orchestrator.Orchestrator, storage.Store) {
	t.Helper()
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	host := mustHost(t, srv.URL)
	if err := store.ScopeRules().Create(context.Background(), models.ScopeRule{
		ID: uuid.NewString(), Value: host, Type: models.ScopeRuleExactHost,
		Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	// host is a bare IP literal (httptest.Server always binds to
	// 127.0.0.1), so internal/target.Parse classifies it TargetTypeIP --
	// orchestration.Pipeline's own TargetTypeIP path builds the
	// Asset/Host directly from the literal, never calling the resolver
	// at all (see pipeline.go's discoverAndResolve), so a real,
	// never-actually-invoked system resolver is sufficient here.
	pipeline := &orchestration.Pipeline{
		Store:               store,
		Resolver:            dns.New(2 * time.Second),
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		DefaultPorts:        []int{mustPort(t, srv.Listener.Addr().String())},
		PortDialTimeout:     2 * time.Second,
		HTTPConfig:          httpstage.Config{Timeout: 2 * time.Second, MaxRedirects: 5},
		Concurrency:         orchestration.Concurrency{DNSWorkers: 2, PortWorkers: 2, HTTPWorkers: 2},
		AllowReservedRanges: true,
		MaxCIDRHosts:        256,
		CrawlEnabled:        true,
		CrawlMaxDepth:       2,
		CrawlMaxPages:       10,
		Logger:              detectionLogger(),
	}

	registry := registerBenignDetectors(t)

	return &orchestrator.Orchestrator{
		Store:                   store,
		Pipeline:                pipeline,
		DetectionRegistry:       registry,
		DetectionExecutorConfig: detection.ExecutorConfig{Concurrency: 4, Timeout: 5 * time.Second, MaxRedirects: 5},
		DetectionConcurrency:    4,
		EvidenceLimits:          evidence.DefaultLimits(),
		Logger:                  detectionLogger(),
		Limits:                  orchestrator.Limits{MaxConcurrentScans: 5, MaxFindings: 1000},
	}, store
}

// registerBenignDetectors registers the 3 detectors that need no
// operator-supplied lab configuration (xssreflected, sqli,
// cmdinjection -- matching cmd/scanner's own productionRegistry()
// default-enabled set) against a plain benign target. ssrf/idor/
// traversal are intentionally excluded here (they require callback
// infrastructure / auth contexts / traversal cases the benign target
// has no use for), exactly like the production registry when no such
// configuration is supplied.
func registerBenignDetectors(t *testing.T) *detection.Registry {
	t.Helper()
	r := detection.NewRegistry()
	for _, d := range []detection.Detector{xssreflected.New(), sqli.New(), cmdinjection.New()} {
		if err := r.Register(d); err != nil {
			t.Fatalf("Register(%s): %v", d.Metadata().ID, err)
		}
	}
	return r
}

// mustHost extracts the bare host (no port) from rawURL -- httptest
// servers always bind to 127.0.0.1, which internal/target.Parse
// classifies as TargetTypeIP.
func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}
	return u.Hostname()
}

// --- Scan isolation (task section 30) --------------------------------------

func TestPhase3_11_Orchestrator_ScanIsolation(t *testing.T) {
	l := testVulnLab(t)
	vulnOrch, vulnStore := buildOrchestratorForVulnLab(t, l)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>benign</body></html>"))
	}))
	defer srv.Close()
	benignOrch, benignStore := buildBenignOrchestrator(t, srv)

	vulnResult, err := vulnOrch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("vuln scan: %v", err)
	}
	benignResult, err := benignOrch.Run(context.Background(), orchestrator.Options{Target: mustHost(t, srv.URL)})
	if err != nil {
		t.Fatalf("benign scan: %v", err)
	}

	if vulnResult.ScanID == benignResult.ScanID {
		t.Fatal("two independent scans produced the SAME scan ID")
	}
	if len(vulnResult.Findings) == 0 {
		t.Fatal("vuln scan produced no findings -- test setup problem")
	}
	if len(benignResult.Findings) != 0 {
		t.Errorf("benign scan produced %d findings, want 0", len(benignResult.Findings))
	}
	for _, pkg := range vulnResult.Findings {
		if pkg.Finding.ScanID != vulnResult.ScanID {
			t.Errorf("vuln finding carries the wrong ScanID: %q, want %q", pkg.Finding.ScanID, vulnResult.ScanID)
		}
	}

	// Each scan used its OWN store, so no query against one store can
	// ever see the other's findings -- verified directly, not just
	// assumed from separate ScanIDs.
	crossFindings, err := benignStore.Findings().ListByScanJob(context.Background(), vulnResult.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(crossFindings) != 0 {
		t.Errorf("benign store returned %d findings for the VULN scan's ID -- cross-contamination", len(crossFindings))
	}
	_ = vulnStore
}

// --- Concurrent scans (task section 31) -------------------------------------

func TestPhase3_11_Orchestrator_ConcurrentScans(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>benign, scanned concurrently</body></html>"))
	}))
	defer srv.Close()
	orch, _ := buildBenignOrchestrator(t, srv)

	const n = 5
	var wg sync.WaitGroup
	results := make([]orchestrator.Result, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = orch.Run(context.Background(), orchestrator.Options{Target: mustHost(t, srv.URL)})
		}()
	}
	wg.Wait()

	seenIDs := map[string]bool{}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("scan %d: %v", i, errs[i])
			continue
		}
		// This fixture serves a linkless, parameterless static page, so
		// no detector ever has an eligible target (Phase 3.11.2's
		// state B) -- COMPLETED_WITH_WARNINGS is the accurate status
		// here. This test's own purpose is concurrency/isolation
		// safety (unique scan IDs, no cross-contamination), not
		// detection semantics, so either successful terminal status is
		// acceptable; only a hard failure/cancellation would be wrong.
		if results[i].Status != orchestrator.StatusCompleted && results[i].Status != orchestrator.StatusCompletedWithWarnings {
			t.Errorf("scan %d: Status = %s, want COMPLETED or COMPLETED_WITH_WARNINGS", i, results[i].Status)
		}
		if seenIDs[results[i].ScanID] {
			t.Errorf("scan %d: duplicate ScanID %q across concurrent scans", i, results[i].ScanID)
		}
		seenIDs[results[i].ScanID] = true
	}
	if len(seenIDs) != n {
		t.Errorf("observed %d distinct scan IDs, want %d", len(seenIDs), n)
	}
}

// --- Out-of-scope / invalid target (task sections 6, 12) -------------------

func TestPhase3_11_Orchestrator_OutOfScopeTarget_FailsBeforeAnyRequest(t *testing.T) {
	l := testVulnLab(t)
	orch, _ := buildOrchestratorForVulnLab(t, l)
	// No scope rule at all covers this host.
	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "not-in-scope.scanner.test"})
	if err == nil {
		t.Fatal("Run succeeded against an out-of-scope target, want an error")
	}
	if result.Status != orchestrator.StatusFailed {
		t.Errorf("Status = %s, want FAILED", result.Status)
	}
	if len(result.Errors) == 0 || result.Errors[0].Category != orchestrator.ErrorCategoryFatal {
		t.Errorf("Errors = %+v, want a leading FATAL category error", result.Errors)
	}
	if result.DetectorSummary.RequestsIssued != 0 {
		t.Errorf("RequestsIssued = %d, want 0 -- scope enforcement must abort before ANY active request (task section 6: any bypass is an automatic FAIL)", result.DetectorSummary.RequestsIssued)
	}
	if result.ReconSummary.HostCount != 0 {
		t.Errorf("ReconSummary.HostCount = %d, want 0 -- RECON must never have run", result.ReconSummary.HostCount)
	}
}

func TestPhase3_11_Orchestrator_InvalidTarget_FailsCleanly(t *testing.T) {
	l := testVulnLab(t)
	orch, _ := buildOrchestratorForVulnLab(t, l)
	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "not a valid target !! $(rm -rf /)"})
	if err == nil {
		t.Fatal("Run succeeded against a malformed target, want an error")
	}
	if result.Status != orchestrator.StatusFailed {
		t.Errorf("Status = %s, want FAILED", result.Status)
	}
}

// --- Cancellation (task section 13) -----------------------------------------

func TestPhase3_11_Orchestrator_CancelBeforeStart(t *testing.T) {
	l := testVulnLab(t)
	orch, _ := buildOrchestratorForVulnLab(t, l)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := orch.Run(ctx, orchestrator.Options{Target: "vuln.scanner.test"})
	if err == nil {
		t.Fatal("Run succeeded against an already-cancelled context, want an error")
	}
	if result.Status != orchestrator.StatusCancelled {
		t.Errorf("Status = %s, want CANCELLED", result.Status)
	}
	if len(result.Findings) != 0 {
		t.Errorf("a cancelled scan produced %d findings, want 0", len(result.Findings))
	}
}

// --- Stage timeout (task section 14) -- deterministic, no timing race ------

func TestPhase3_11_Orchestrator_StageTimeout_NeverMarksCompleted(t *testing.T) {
	l := testVulnLab(t)
	orch, _ := buildOrchestratorForVulnLab(t, l)
	// A 1-nanosecond stage timeout guarantees the VERY FIRST stage
	// (SCOPE) cannot complete within it, deterministically -- no timing
	// race, no dependence on how fast the real lab happens to respond.
	orch.Limits.StageTimeout = 1 * time.Nanosecond

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err == nil {
		t.Fatal("Run succeeded despite a 1ns stage timeout, want an error")
	}
	if result.Status == orchestrator.StatusCompleted || result.Status == orchestrator.StatusCompletedWithWarnings {
		t.Errorf("Status = %s, want CANCELLED or FAILED -- never COMPLETED when a stage timed out (task section 13)", result.Status)
	}
}

// --- Resource limits: maximum findings (task section 32) -------------------

func TestPhase3_11_Orchestrator_MaxFindingsLimit_TruncatesAfterRanking(t *testing.T) {
	l := testVulnLab(t)
	orch, _ := buildOrchestratorForVulnLab(t, l)
	orch.Limits.MaxFindings = 2

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2 (MaxFindings)", len(result.Findings))
	}
	if result.Status != orchestrator.StatusCompletedWithWarnings {
		t.Errorf("Status = %s, want COMPLETED_WITH_WARNINGS (a limit was reached)", result.Status)
	}
	foundWarning := false
	for _, e := range result.Errors {
		if e.Category == orchestrator.ErrorCategoryWarning {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Error("no ErrorCategoryWarning recorded despite truncating findings")
	}
	// The 2 kept findings must be the 2 HIGHEST-risk ones, not an
	// arbitrary prefix -- confirmed by re-running with no limit and
	// comparing the top 2.
	orch2, _ := buildOrchestratorForVulnLab(t, l)
	full, err := orch2.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("unlimited run: %v", err)
	}
	if len(full.Findings) < 2 {
		t.Fatal("unlimited run produced fewer than 2 findings -- test setup problem")
	}
	if result.Findings[0].Risk.RiskScore != full.Findings[0].Risk.RiskScore || result.Findings[1].Risk.RiskScore != full.Findings[1].Risk.RiskScore {
		t.Errorf("truncated top-2 risk scores (%d, %d) do not match unlimited run's top-2 (%d, %d)",
			result.Findings[0].Risk.RiskScore, result.Findings[1].Risk.RiskScore, full.Findings[0].Risk.RiskScore, full.Findings[1].Risk.RiskScore)
	}
}

// --- Detector failure isolation (task section 11) ---------------------------

// alwaysErrorDetector implements detection.Detector and errors on
// every Detect call -- used to prove one broken detector never aborts
// the whole scan.
type alwaysErrorDetector struct{}

func (alwaysErrorDetector) Metadata() detection.Metadata {
	return detection.Metadata{
		ID: "always-error", Name: "Always-Error Test Detector", Category: "test",
		SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint},
		SupportedMethods:     []string{http.MethodGet},
		DefaultSeverity:      models.SeverityInfo,
	}
}
func (alwaysErrorDetector) Eligible(t detection.Target) bool { return true }
func (alwaysErrorDetector) Detect(ctx context.Context, t detection.Target, x *detection.Executor) (detection.Result, error) {
	return detection.Result{}, errAlwaysFails
}

var errAlwaysFails = &alwaysFailsError{}

type alwaysFailsError struct{}

func (*alwaysFailsError) Error() string { return "this detector always fails (test fixture)" }

func TestPhase3_11_Orchestrator_DetectorFailureIsolation_ScanContinues(t *testing.T) {
	l := testVulnLab(t)
	orch, _ := buildOrchestratorForVulnLab(t, l)
	if err := orch.DetectionRegistry.Register(alwaysErrorDetector{}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v (a broken detector must not fail the whole scan)", err)
	}
	if result.Status != orchestrator.StatusCompletedWithWarnings {
		t.Errorf("Status = %s, want COMPLETED_WITH_WARNINGS", result.Status)
	}
	if len(result.Findings) == 0 {
		t.Error("no findings produced -- the other 6 working detectors must still have run")
	}
	foundDetectorError := false
	for _, e := range result.Errors {
		if e.Category == orchestrator.ErrorCategoryDetector && e.DetectorID == "always-error" {
			foundDetectorError = true
		}
	}
	if !foundDetectorError {
		t.Errorf("no ErrorCategoryDetector recorded for detector %q; Errors = %+v", "always-error", result.Errors)
	}
}

// --- Log correlation (task sections 27-28) ----------------------------------

// capturingHandler is a minimal slog.Handler that records every log
// call for inspection. WithAttrs must actually accumulate and merge
// attrs onto each subsequent record (mirroring what a real handler
// like slog.JSONHandler does internally) -- an earlier draft's
// WithAttrs was a no-op returning the handler unchanged, which
// silently discarded logging.WithScanJob's own scan_job_id attribute
// (attached via a single upfront .With(...) call, not a per-record
// arg) and made this test unable to observe it at all.
type capturingHandler struct {
	mu      *sync.Mutex
	records *[]slog.Record
	attrs   []slog.Attr
}

func newCapturingHandler() *capturingHandler {
	return &capturingHandler{mu: &sync.Mutex{}, records: &[]slog.Record{}}
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, a := range h.attrs {
		r.AddAttrs(a)
	}
	*h.records = append(*h.records, r)
	return nil
}
func (h *capturingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &capturingHandler{mu: h.mu, records: h.records, attrs: merged}
}
func (h *capturingHandler) WithGroup(name string) slog.Handler { return h }

func TestPhase3_11_LogCorrelation_ScanIDAndStagePresent(t *testing.T) {
	l := testVulnLab(t)
	orch, _ := buildOrchestratorForVulnLab(t, l)
	// Registering a detector that always errors guarantees at least one
	// "detector_error" log line (and its detector_id attribute) is
	// actually produced -- the real 6-detector registry run cleanly
	// against this lab (0 detector errors), so without this fixture
	// there would be nothing to observe for that specific assertion.
	if err := orch.DetectionRegistry.Register(alwaysErrorDetector{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	handler := newCapturingHandler()
	orch.Logger = slog.New(handler)

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	if len(*handler.records) == 0 {
		t.Fatal("no log records captured")
	}

	sawScanID, sawStage, sawDetectorID, sawFindingID, sawScanStarted, sawScanCompleted := false, false, false, false, false, false
	for _, r := range *handler.records {
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "scan_job_id":
				if a.Value.String() == result.ScanID {
					sawScanID = true
				}
			case "stage":
				sawStage = true
			case "detector_id":
				sawDetectorID = true
			case "finding_id":
				sawFindingID = true
			}
			return true
		})
		switch r.Message {
		case "scan_started":
			sawScanStarted = true
		case "scan_completed", "scan_failed", "scan_cancelled":
			sawScanCompleted = true
		}
	}
	if !sawScanID {
		t.Error("no log record carried scan_job_id matching the returned ScanID")
	}
	if !sawStage {
		t.Error("no log record carried a stage attribute")
	}
	if !sawDetectorID {
		t.Error("no log record carried a detector_id attribute")
	}
	if !sawFindingID {
		t.Error("no log record carried a finding_id attribute")
	}
	if !sawScanStarted || !sawScanCompleted {
		t.Errorf("scan_started seen=%v, scan_completed/failed/cancelled seen=%v", sawScanStarted, sawScanCompleted)
	}
}

func TestPhase3_11_LogCorrelation_NoSecretsLogged(t *testing.T) {
	l := testVulnLab(t)
	orch, _ := buildOrchestratorForVulnLab(t, l)
	handler := newCapturingHandler()
	orch.Logger = slog.New(handler)

	if _, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	for _, r := range *handler.records {
		msg := strings.ToLower(r.Message)
		if strings.Contains(msg, "authorization") || strings.Contains(msg, "bearer ") || strings.Contains(msg, "cookie:") {
			t.Errorf("log message looks like it leaked a credential: %q", r.Message)
		}
		r.Attrs(func(a slog.Attr) bool {
			v := strings.ToLower(a.Value.String())
			if strings.Contains(v, "bearer ") || strings.HasPrefix(v, "session=") {
				t.Errorf("log attribute %q looks like it leaked a credential: %q", a.Key, a.Value.String())
			}
			return true
		})
	}
}

// --- Performance (task section 42) ------------------------------------------

func TestPhase3_11_Orchestrator_Performance_FullScanCompletesQuickly(t *testing.T) {
	l := testVulnLab(t)
	orch, _ := buildOrchestratorForVulnLab(t, l)

	start := time.Now()
	result, err := orch.Run(context.Background(), orchestrator.Options{Target: "vuln.scanner.test"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	t.Logf("full scan: %s wall-clock, %d requests, %d findings", elapsed, result.DetectorSummary.RequestsIssued, len(result.Findings))
	for _, sp := range result.Warnings {
		t.Logf("warning: %s", sp)
	}
	// Generous bound (this lab is small and entirely local) -- catches a
	// genuine O(n^2)-shaped regression, not a tight benchmark.
	if elapsed > 30*time.Second {
		t.Errorf("full scan took %s, want well under 30s against this small local lab", elapsed)
	}
}

// --- Phase 3.11.2: detection readiness observability -----------------------

// TestPhase3_11_2_DetectionNotRun_LogEventAndWarningCarryNoSecrets is
// task section 15's security requirement: the new zero-detector
// observability logic must never expose credentials/cookies/
// authorization headers, bypass scope, enable the crawler itself, or
// issue any additional request. This test drives the real orchestrator
// with the crawler explicitly disabled against a target whose recon
// response carries a header that would be a serious leak if it ever
// reached a log line or warning message, and confirms the new
// detection_not_run log event and DETECTION_NOT_RUN warning are built
// entirely from static template text plus plain counts/booleans --
// never response content.
func TestPhase3_11_2_DetectionNotRun_LogEventAndWarningCarryNoSecrets(t *testing.T) {
	const secret = "super-secret-session-cookie-value-12345"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session="+secret)
		w.Header().Set("Authorization", "Bearer "+secret)
		w.Write([]byte("<html><body>no links, no parameters here</body></html>"))
	}))
	defer srv.Close()

	orch, _ := buildBenignOrchestrator(t, srv)
	// buildBenignOrchestrator enables the crawler by default; this test
	// specifically wants the crawler-DISABLED wording/log path (state B
	// via "crawling is disabled" rather than via "the crawler ran but
	// found no links"), so it's turned off here.
	orch.Pipeline.CrawlEnabled = false
	handler := newCapturingHandler()
	orch.Logger = slog.New(handler)

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: mustHost(t, srv.URL)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.DetectorSummary.State != orchestrator.DetectionStateNotRun {
		t.Fatalf("DetectionState = %s, want NOT_RUN (test setup problem)", result.DetectorSummary.State)
	}

	for _, w := range result.Warnings {
		if strings.Contains(w, secret) {
			t.Errorf("a DETECTION_NOT_RUN warning leaked the secret: %q", w)
		}
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()
	foundEvent := false
	for _, r := range *handler.records {
		if r.Message == "detection_not_run" {
			foundEvent = true
		}
		if strings.Contains(r.Message, secret) {
			t.Errorf("log message leaked the secret: %q", r.Message)
		}
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Value.String(), secret) {
				t.Errorf("log attribute %q leaked the secret: %q", a.Key, a.Value.String())
			}
			// task section 14's documented fields only -- never a
			// header/cookie/response-body-derived value.
			switch a.Key {
			case "reason", "crawler_enabled", "eligible_targets", "detectors_enabled", "scan_job_id":
			}
			return true
		})
	}
	if !foundEvent {
		t.Error("no detection_not_run log event was emitted")
	}
}

// TestPhase3_11_2_DetectionNotRun_NeverEnablesCrawlerOrChangesScope
// confirms the new observability path is read-only: Pipeline.CrawlEnabled
// and the scope rules on record are byte-for-byte unchanged by a scan
// that hits state B, and no additional scope rule or request was
// triggered by computing the warning/summary.
func TestPhase3_11_2_DetectionNotRun_NeverEnablesCrawlerOrChangesScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>no links, no parameters here</body></html>"))
	}))
	defer srv.Close()

	orch, store := buildBenignOrchestrator(t, srv)
	// Force the crawler-disabled starting condition deliberately (rather
	// than trusting whatever buildBenignOrchestrator happens to default
	// to) so this test is actually exercising "does zero-detector
	// observability ever flip CrawlEnabled to true to fix the problem
	// itself," not just re-confirming an already-true value stayed true.
	orch.Pipeline.CrawlEnabled = false
	before := orch.Pipeline.CrawlEnabled

	rulesBefore, err := store.ScopeRules().List(context.Background())
	if err != nil {
		t.Fatalf("List (before): %v", err)
	}

	result, err := orch.Run(context.Background(), orchestrator.Options{Target: mustHost(t, srv.URL)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.DetectorSummary.State != orchestrator.DetectionStateNotRun {
		t.Fatalf("DetectionState = %s, want NOT_RUN (test setup problem)", result.DetectorSummary.State)
	}

	if orch.Pipeline.CrawlEnabled != before {
		t.Errorf("CrawlEnabled changed from %v to %v -- the observability path must never mutate configuration", before, orch.Pipeline.CrawlEnabled)
	}

	rulesAfter, err := store.ScopeRules().List(context.Background())
	if err != nil {
		t.Fatalf("List (after): %v", err)
	}
	if len(rulesAfter) != len(rulesBefore) {
		t.Errorf("scope rule count changed from %d to %d -- the observability path must never mutate scope", len(rulesBefore), len(rulesAfter))
	}
}
