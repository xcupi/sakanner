// Phase 3.8 integration test: runs the REAL Phase 3.1 detection.Engine,
// with ALL SIX real detectors registered and configured exactly as
// their own phase's lab tests configure them, against the real
// vuln.scanner.test lab -- then feeds every persisted models.Finding
// through the NEW internal/correlation.Engine and verifies it produces
// one canonical finding per distinct vulnerability, with no detector-
// specific logic anywhere in the correlation package itself (see
// docs/phase-3-8-finding-correlation.md "Detector independence").
//
// This is task section 34's "run the actual lab scanners and feed
// their findings through the new correlation engine" requirement,
// verified against real detector output, not synthetic fixtures (see
// internal/correlation/fixtures_test.go for the synthetic-fixture unit
// tests that cover section 23 separately).
package lab

import (
	"context"
	"testing"

	"sakanner/internal/correlation"
	"sakanner/internal/detection"
	"sakanner/internal/detectors/cmdinjection"
	"sakanner/internal/detectors/idor"
	"sakanner/internal/detectors/sqli"
	"sakanner/internal/detectors/ssrf"
	"sakanner/internal/detectors/traversal"
	"sakanner/internal/detectors/xssreflected"
)

// allDetectorsRegistry registers all six real detectors, each
// configured exactly as its own Phase 3.x lab test configures it (the
// same AuthContexts/TraversalCase/CallbackClient every prior phase's
// own integration test already uses) -- so this test observes the
// SAME real detection behavior every earlier acceptance report
// verified, just with all six running together for once.
func allDetectorsRegistry(t *testing.T, l *Lab) *detection.Registry {
	t.Helper()
	r := detection.NewRegistry()
	if l.SSRFCallback == nil {
		t.Fatal("lab has no SSRFCallback -- StartWithVulnerabilities wiring problem")
	}
	detectors := []detection.Detector{
		xssreflected.New(),
		sqli.New(),
		cmdinjection.New(),
		ssrf.New(l.SSRFCallback),
		idor.New(idorAuthContexts()),
		traversal.New(traversalCases()),
	}
	for _, d := range detectors {
		if err := r.Register(d); err != nil {
			t.Fatalf("Register(%s): %v", d.Metadata().ID, err)
		}
	}
	return r
}

func TestPhase3_8_Correlation_RealDetectorOutputProducesCanonicalFindings(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: allDetectorsRegistry(t, l), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}

	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(summary.Errors) != 0 {
		t.Errorf("detector errors during a clean run against the lab: %+v", summary.Errors)
	}
	t.Logf("Engine.Run: %d targets considered, %d detector runs, %d findings created, %d requests issued",
		summary.TargetsConsidered, summary.DetectorRuns, summary.FindingsCreated, summary.RequestsIssued)

	rawFindings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(rawFindings) == 0 {
		t.Fatal("no findings persisted by the real detectors -- test setup problem (expected at least one per detector class)")
	}

	// Feed every real, persisted finding through the NEW correlation
	// engine -- this is the "Detector -> Finding -> Normalizer ->
	// Correlation Engine -> Canonical Finding Set" pipeline (task
	// section 33) exercised end to end against real output.
	ce := correlation.NewEngine()
	ce.Ingest(rawFindings...)
	canonical := ce.Findings()

	t.Logf("Correlation: %d raw findings -> %d canonical findings", len(rawFindings), len(canonical))

	if len(canonical) == 0 {
		t.Fatal("correlation engine produced zero canonical findings from real detector output")
	}
	if len(canonical) > len(rawFindings) {
		t.Errorf("canonical count (%d) exceeds raw count (%d) -- correlation must never CREATE findings", len(canonical), len(rawFindings))
	}

	// Every canonical finding must carry a non-empty FindingID,
	// VulnerabilityType, and Asset.Host -- the minimum shape a real
	// finding must have.
	types := map[string]int{}
	for _, cf := range canonical {
		if cf.FindingID == "" {
			t.Errorf("canonical finding has empty FindingID: %+v", cf)
		}
		if cf.VulnerabilityType == "" {
			t.Errorf("canonical finding has empty VulnerabilityType: %+v", cf)
		}
		if cf.Asset.Host == "" {
			t.Errorf("canonical finding has empty Asset.Host: %+v", cf)
		}
		if cf.ScanID != job.ID {
			t.Errorf("canonical finding ScanID = %q, want %q (scan isolation)", cf.ScanID, job.ID)
		}
		types[cf.VulnerabilityType]++
	}

	// The real lab's ground truth defines exactly how many genuinely
	// distinct, detectable positive fixtures each type has: reflected
	// XSS and SQLi each have TWO (the original text-context/error-based
	// fixture plus Phase 3.2/3.3's own attribute-context/boolean-only
	// addition -- see docs/phase-3-2-*.md and docs/phase-3-3-*.md), SSRF
	// has TWO (the original response-based fixture plus Phase 3.25's own
	// VULN-SSRF-BLIND-001, a genuinely distinct blind/OOB-only positive
	// -- see docs/phase-3-25-ssrf-active-detection.md), command_injection
	// has TWO (the original Unix-style fixture plus Phase 3.26's own
	// VULN-CMDI-API-WINDOWS-001, a genuinely distinct Windows-cmd.exe-
	// style positive -- see docs/phase-3-26-command-injection-active.md),
	// the other two have exactly one apiece (see each Phase 3.x
	// acceptance report's TruePositives=1 result). Correlation must
	// resolve to EXACTLY this many canonical findings per type -- not
	// more (which would mean a false split within one already-distinct
	// fixture) and not fewer (which would mean two genuinely different
	// fixtures were incorrectly merged, or one was lost).
	wantPerType := map[string]int{
		"reflected_xss":     2,
		"sql_injection":     2,
		"ssrf":              2,
		"idor":              1,
		"path_traversal":    1,
		"command_injection": 2,
	}
	for vulnType, want := range wantPerType {
		if types[vulnType] != want {
			t.Errorf("canonical finding count for %q = %d, want exactly %d", vulnType, types[vulnType], want)
		}
	}

	// Deterministic ordering: running Findings() again must reproduce
	// the identical order.
	again := ce.Findings()
	if len(again) != len(canonical) {
		t.Fatal("repeated Findings() call returned a different count")
	}
	for i := range canonical {
		if canonical[i].FindingID != again[i].FindingID {
			t.Errorf("index %d: FindingID differs across repeated Findings() calls", i)
		}
	}

	// Grouping/relationships must run cleanly against real data too.
	groups := correlation.GroupByEndpoint(canonical)
	if len(groups) == 0 {
		t.Error("GroupByEndpoint produced no groups against real canonical findings")
	}
	rels := correlation.Relationships(canonical)
	t.Logf("GroupByEndpoint: %d groups; Relationships: %d pairs", len(groups), len(rels))
}
