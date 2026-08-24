// Phase 3.5 integration tests: sakanner's fourth real vulnerability
// detector (internal/detectors/idor) run through the real Phase 3.1
// detection.Engine against the real Phase 3 vuln lab, using synthetic
// AuthContext values matching the lab's own idorAPIResources ground
// truth (see harness_vuln.go) -- not a mock target, the real fixture
// (see internal/detectors/idor/detector_test.go for the unit tests
// against synthetic httptest servers). This is the "does it actually
// find what the lab's own ground truth says it should, and stay silent
// everywhere it shouldn't" check, mirroring phase3_2/3_3/3_4's pattern
// exactly.
package lab

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/idor"
)

// idorAuthContexts are the two synthetic authorization contexts this
// test uses -- matching harness_vuln.go's idorAPIResources exactly
// (resource-a owned by user-a, resource-b owned by user-b).
func idorAuthContexts() []idor.AuthContext {
	return []idor.AuthContext{
		{ID: "user-a", Headers: map[string]string{"X-Test-Auth-User": "user-a"}, OwnsResourceIDs: map[string]bool{"resource-a": true}},
		{ID: "user-b", Headers: map[string]string{"X-Test-Auth-User": "user-b"}, OwnsResourceIDs: map[string]bool{"resource-b": true}},
	}
}

// idorRegistry returns a fresh Registry with only idor registered,
// wired to the synthetic lab AuthContexts -- isolating this test from
// any other detector so its findings/comparison numbers stay specific
// to IDOR/BOLA.
func idorRegistry(t *testing.T) *detection.Registry {
	t.Helper()
	r := detection.NewRegistry()
	if err := r.Register(idor.New(idorAuthContexts())); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return r
}

// idorFixtures returns just the idor-typed entries from the Phase 3
// ground truth that are QUERY-PARAMETER based (endpoint doesn't
// contain "{id}", the still-undetectable path-based fixture -- see
// VULN-IDOR-001's requires_capability note), split into
// positive/negative.
func idorFixtures(t *testing.T) (positives, negatives []VulnFinding) {
	t.Helper()
	vulnGT, err := LoadVulnGroundTruth()
	if err != nil {
		t.Fatalf("LoadVulnGroundTruth: %v", err)
	}
	for _, f := range vulnGT.Positives() {
		if f.Type == "idor" && !pathBased(f.Endpoint) {
			positives = append(positives, f)
		}
	}
	for _, f := range vulnGT.Negatives() {
		if f.Type == "idor" && !pathBased(f.Endpoint) {
			negatives = append(negatives, f)
		}
	}
	return positives, negatives
}

func pathBased(endpoint string) bool {
	return strings.Contains(endpoint, "{id}")
}

// TestPhase3_5_IDORDetector_MatchesGroundTruth runs real recon
// (crawling enabled) against the real vuln.scanner.test lab, runs the
// real idor detector (configured with the two synthetic AuthContexts
// above) through the real Engine, and compares its persisted findings
// against every query-parameter-based idor-typed ground-truth fixture.
func TestPhase3_5_IDORDetector_MatchesGroundTruth(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: idorRegistry(t), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}

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

	positives, negatives := idorFixtures(t)
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
		t.Errorf("TruePositives = %d, want %d -- every query-parameter IDOR positive fixture must be detected", report.TruePositives, len(positives))
	}
	if report.FalseNegatives != 0 {
		t.Errorf("FalseNegatives = %d, want 0", report.FalseNegatives)
	}
	if report.FalsePositives != 0 {
		t.Errorf("FalsePositives = %d, want 0 -- the detector fired on something not in ground truth as an IDOR positive (check report.Results for which)", report.FalsePositives)
	}
	if report.Duplicates != 0 {
		t.Errorf("Duplicates = %d, want 0 -- the engine's own deduplication (Phase 3.1, reused unchanged) must have already collapsed any redundant detections before persistence", report.Duplicates)
	}

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

// TestPhase3_5_IDORDetector_NegativeFixturesProduceNoFinding is a
// focused, fixture-by-fixture check on top of the aggregate
// FalsePositives==0 assertion above: run the detector directly against
// each negative fixture's exact endpoint+parameter+id and assert
// OutcomeNoFinding/OutcomeSkipped one at a time.
func TestPhase3_5_IDORDetector_NegativeFixturesProduceNoFinding(t *testing.T) {
	l := testVulnLab(t)
	_, job, validator := runReconAgainstVulnLab(t, l)

	_, negatives := idorFixtures(t)
	if len(negatives) == 0 {
		t.Fatal("no query-parameter idor negative fixtures found in ground truth -- test setup problem")
	}

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{})
	d := idor.New(idorAuthContexts())

	ips, err := l.Resolver.LookupHost(context.Background(), "vuln.scanner.test")
	if err != nil || len(ips) == 0 {
		t.Fatalf("resolving vuln.scanner.test: %v", err)
	}
	port := mustPort(t, l.VulnAddr)

	resourceIDByFixture := map[string]string{
		"VULN-IDOR-API-NEG-001":         "resource-a",
		"VULN-IDOR-API-PUBLIC-NEG-001":  "resource-public",
		"VULN-IDOR-API-INVALID-NEG-001": "does-not-exist",
		"VULN-IDOR-API-GENERIC-NEG-001": "resource-a",
	}

	for _, neg := range negatives {
		neg := neg
		t.Run(neg.ID, func(t *testing.T) {
			id, ok := resourceIDByFixture[neg.ID]
			if !ok {
				t.Fatalf("test setup: no resource id mapped for fixture %s", neg.ID)
			}
			tgt := detection.Target{
				ScanJobID: job.ID, Kind: detection.TargetKindEndpoint,
				Host: "vuln.scanner.test", IP: ips[0], Port: port,
				Scheme: "http", URL: fmt.Sprintf("http://vuln.scanner.test:%d%s?%s=%s", port, neg.Endpoint, neg.Parameter, id),
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

// TestPhase3_5_IDORDetector_ScopeEnforcementStaysActiveDuringDetection
// is the CRITICAL scope-enforcement regression the task explicitly
// calls out: this scan job's ScopeSnapshot only authorizes
// vuln.scanner.test. A Target manufactured to point at the Phase 2
// lab's scanner.test host must be refused by the SCANNER's own
// Executor -- with zero requests reaching that host.
func TestPhase3_5_IDORDetector_ScopeEnforcementStaysActiveDuringDetection(t *testing.T) {
	l := testVulnLab(t)
	_, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{})

	outOfScopeIPs, err := l.Resolver.LookupHost(context.Background(), "scanner.test")
	if err != nil || len(outOfScopeIPs) == 0 {
		t.Fatalf("resolving scanner.test in the lab's own resolver: %v", err)
	}
	outOfScope := detection.Target{
		ScanJobID: job.ID, Kind: detection.TargetKindEndpoint,
		Host: "scanner.test", IP: outOfScopeIPs[0], Port: 80,
		Scheme: "http", URL: "http://scanner.test/?resource_id=resource-a",
		Path: "/", Method: "GET", Parameter: "resource_id", ParameterLocation: "query",
	}

	d := idor.New(idorAuthContexts())
	_, detErr := d.Detect(context.Background(), outOfScope, x)
	if detErr == nil {
		t.Fatal("Detect against an out-of-scope target (scanner.test, not in this job's ScopeSnapshot): want error, got nil -- scope enforcement did not stop the request")
	}
	if x.RequestCount() != 0 {
		t.Errorf("Executor.RequestCount() = %d, want 0 -- the out-of-scope request must never actually dial", x.RequestCount())
	}
}
