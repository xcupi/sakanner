// Phase 3.2 integration tests: sakanner's first real vulnerability
// detector (internal/detectors/xssreflected) run through the real
// Phase 3.1 detection.Engine against the real Phase 3 vuln lab -- not a
// mock, not a synthetic httptest server (see
// internal/detectors/xssreflected/detector_test.go for those unit
// tests). This is the "does it actually find what the lab's own ground
// truth says it should, and stay silent everywhere it shouldn't" check.
package lab

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/xssreflected"
)

// xssRegistry returns a fresh Registry with only xss-reflected
// registered -- isolating this test from any other detector that might
// exist by the time a later phase adds one, so its findings/comparison
// numbers stay specific to reflected XSS.
func xssRegistry(t *testing.T) *detection.Registry {
	t.Helper()
	r := detection.NewRegistry()
	if err := r.Register(xssreflected.New()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return r
}

// reflectedXSSFixtures returns just the reflected_xss-typed entries
// from the Phase 3 ground truth, split into positive/negative -- the
// slice this test's ground-truth comparison is scoped to.
func reflectedXSSFixtures(t *testing.T) (positives, negatives []VulnFinding) {
	t.Helper()
	vulnGT, err := LoadVulnGroundTruth()
	if err != nil {
		t.Fatalf("LoadVulnGroundTruth: %v", err)
	}
	for _, f := range vulnGT.Positives() {
		if f.Type == "reflected_xss" {
			positives = append(positives, f)
		}
	}
	for _, f := range vulnGT.Negatives() {
		if f.Type == "reflected_xss" {
			negatives = append(negatives, f)
		}
	}
	return positives, negatives
}

// TestPhase3_2_ReflectedXSSDetector_MatchesGroundTruth is the
// centerpiece: runs real recon (crawling enabled) against the real
// vuln.scanner.test lab, runs the real xss-reflected detector through
// the real Engine, and compares its persisted findings against every
// reflected_xss ground-truth fixture -- printing the
// Fixture | Expected | Actual | Result table the task asks for, then
// asserting the full TP/FP/FN/Duplicate tally.
func TestPhase3_2_ReflectedXSSDetector_MatchesGroundTruth(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: xssRegistry(t), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}

	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(summary.Errors) != 0 {
		t.Errorf("detector errors during a clean run against the lab: %+v", summary.Errors)
	}
	t.Logf("Engine.Run: %d targets considered, %d detector runs, %d findings created, %d requests issued",
		summary.TargetsConsidered, summary.DetectorRuns, summary.FindingsCreated, summary.RequestsIssued)

	actual, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}

	positives, negatives := reflectedXSSFixtures(t)
	report := CompareFindings(actual, positives, negatives)

	t.Log("Fixture | Expected | Actual | Result")
	t.Log("---|---|---|---")
	for _, r := range report.Results {
		fixtureID, expected := "(unexpected)", "NO FINDING"
		if r.Expected != nil {
			fixtureID = r.Expected.ID
			expected = "FINDING"
		}
		actualStr := "NO FINDING"
		if r.Actual != nil {
			fixtureID = fmt.Sprintf("%s (actual: %s)", fixtureID, r.Actual.AffectedEndpoint)
			actualStr = "FINDING"
		}
		t.Logf("%s | %s | %s | %s", fixtureID, expected, actualStr, r.Status)
	}
	// Every positive fixture not appearing in report.Results as a
	// true_positive or false_negative would be a silent gap -- there
	// isn't one, since CompareFindings emits exactly one Result per
	// expected positive (see lab/comparison.go), but this makes
	// that guarantee explicit for a reader of this test's log output.
	for _, p := range positives {
		found := false
		for _, r := range report.Results {
			if r.Expected != nil && r.Expected.ID == p.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("ground-truth fixture %s produced no comparison result at all -- this must never happen silently", p.ID)
		}
	}

	t.Logf("True Positives:  %d", report.TruePositives)
	t.Logf("False Positives: %d", report.FalsePositives)
	t.Logf("False Negatives: %d", report.FalseNegatives)
	t.Logf("Duplicates:      %d", report.Duplicates)

	if report.TruePositives != len(positives) {
		t.Errorf("TruePositives = %d, want %d -- every reflected-XSS positive fixture must be detected (a missed one is a limitation to document, never a test to weaken)", report.TruePositives, len(positives))
	}
	if report.FalseNegatives != 0 {
		t.Errorf("FalseNegatives = %d, want 0", report.FalseNegatives)
	}
	if report.FalsePositives != 0 {
		t.Errorf("FalsePositives = %d, want 0 -- the detector fired on something not in ground truth as a reflected-XSS positive (check report.Results for which)", report.FalsePositives)
	}
	if report.Duplicates != 0 {
		t.Errorf("Duplicates = %d, want 0 -- the engine's own deduplication (Phase 3.1, reused unchanged) must have already collapsed any redundant detections before persistence", report.Duplicates)
	}

	// Every true positive's severity/endpoint must also match ground
	// truth exactly, not just "a finding of the right type existed
	// somewhere" -- this is the "endpoint attribution" and "severity
	// validation" the Phase 3 lab's integration-test foundation exists
	// to check (see docs/phase-3-test-lab.md).
	for _, r := range report.Results {
		if r.Status != StatusTruePositive {
			continue
		}
		if !r.EndpointMatches {
			t.Errorf("%s: actual finding's AffectedEndpoint (%q) does not match ground truth's endpoint (%q)", r.Expected.ID, r.Actual.AffectedEndpoint, r.Expected.Endpoint)
		}
		if !r.SeverityMatches {
			t.Errorf("%s: actual severity (%q) does not match ground truth's expected severity (%q)", r.Expected.ID, r.Actual.Severity, r.Expected.Severity)
		}
		if !r.EvidenceMatches {
			t.Errorf("%s: true-positive finding carries no evidence", r.Expected.ID)
		}
		if r.Actual.Confidence <= 0 || r.Actual.Confidence > 1 {
			t.Errorf("%s: Confidence = %v, want a value in (0, 1]", r.Expected.ID, r.Actual.Confidence)
		}
	}
}

// TestPhase3_2_ReflectedXSSDetector_NegativeFixturesProduceNoFinding is
// a focused, fixture-by-fixture check on top of the aggregate
// FalsePositives==0 assertion above: run the detector directly (no
// crawl/discovery involved) against each negative fixture's exact
// endpoint+parameter and assert OutcomeNoFinding one at a time, so a
// failure here names the specific fixture rather than requiring a
// reader to cross-reference the table.
func TestPhase3_2_ReflectedXSSDetector_NegativeFixturesProduceNoFinding(t *testing.T) {
	l := testVulnLab(t)
	_, job, validator := runReconAgainstVulnLab(t, l)

	_, negatives := reflectedXSSFixtures(t)
	if len(negatives) == 0 {
		t.Fatal("no reflected_xss negative fixtures found in ground truth -- test setup problem")
	}

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{})
	d := xssreflected.New()

	ips, err := l.Resolver.LookupHost(context.Background(), "vuln.scanner.test")
	if err != nil || len(ips) == 0 {
		t.Fatalf("resolving vuln.scanner.test: %v", err)
	}
	port := mustPort(t, l.VulnAddr)

	for _, neg := range negatives {
		neg := neg
		t.Run(neg.ID, func(t *testing.T) {
			tgt := detection.Target{
				ScanJobID: job.ID, Kind: detection.TargetKindEndpoint,
				Host: "vuln.scanner.test", IP: ips[0], Port: port,
				Scheme: "http", URL: "http://vuln.scanner.test:" + strconv.Itoa(port) + neg.Endpoint + "?" + neg.Parameter + "=placeholder",
				Path: neg.Endpoint, Method: neg.Method, Parameter: neg.Parameter, ParameterLocation: "query",
			}
			result, err := d.Detect(context.Background(), tgt, x)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if result.Outcome == detection.OutcomeFinding {
				t.Errorf("EXPECTED no finding for %s, got one: %+v", neg.ID, result.Findings)
			}
		})
	}
}
