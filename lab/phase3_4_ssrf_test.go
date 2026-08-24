// Phase 3.4 integration tests: sakanner's third real vulnerability
// detector (internal/detectors/ssrf) run through the real Phase 3.1
// detection.Engine against the real Phase 3 vuln lab, using the real
// lab.SSRFCallbackServer as its CallbackClient -- not a mock, not
// a fake (see internal/detectors/ssrf/detector_test.go for those unit
// tests). This is the "does it actually find what the lab's own ground
// truth says it should, and stay silent everywhere it shouldn't"
// check, mirroring phase3_2/phase3_3's pattern exactly.
package lab

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/ssrf"
)

// ssrfRegistry returns a fresh Registry with only ssrf registered,
// wired to l's real SSRFCallbackServer -- isolating this test from any
// other detector so its findings/comparison numbers stay specific to
// SSRF.
func ssrfRegistry(t *testing.T, l *Lab) *detection.Registry {
	t.Helper()
	if l.SSRFCallback == nil {
		t.Fatal("lab has no SSRFCallback -- StartWithVulnerabilities wiring problem")
	}
	r := detection.NewRegistry()
	if err := r.Register(ssrf.New(l.SSRFCallback)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return r
}

// ssrfFixtures returns just the ssrf-typed entries from the Phase 3
// ground truth, split into positive/negative.
func ssrfFixtures(t *testing.T) (positives, negatives []VulnFinding) {
	t.Helper()
	vulnGT, err := LoadVulnGroundTruth()
	if err != nil {
		t.Fatalf("LoadVulnGroundTruth: %v", err)
	}
	for _, f := range vulnGT.Positives() {
		if f.Type == "ssrf" {
			positives = append(positives, f)
		}
	}
	for _, f := range vulnGT.Negatives() {
		if f.Type == "ssrf" {
			negatives = append(negatives, f)
		}
	}
	return positives, negatives
}

// TestPhase3_4_SSRFDetector_MatchesGroundTruth runs real recon
// (crawling enabled) against the real vuln.scanner.test lab, runs the
// real ssrf detector (wired to the real, local, non-forwarding
// SSRFCallbackServer) through the real Engine, and compares its
// persisted findings against every ssrf-typed ground-truth fixture.
func TestPhase3_4_SSRFDetector_MatchesGroundTruth(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: ssrfRegistry(t, l), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}

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

	positives, negatives := ssrfFixtures(t)
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
		t.Errorf("TruePositives = %d, want %d -- every SSRF positive fixture must be detected", report.TruePositives, len(positives))
	}
	if report.FalseNegatives != 0 {
		t.Errorf("FalseNegatives = %d, want 0", report.FalseNegatives)
	}
	if report.FalsePositives != 0 {
		t.Errorf("FalsePositives = %d, want 0 -- the detector fired on something not in ground truth as an SSRF positive (check report.Results for which)", report.FalsePositives)
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

// TestPhase3_4_SSRFDetector_NegativeFixturesProduceNoFinding is a
// focused, fixture-by-fixture check on top of the aggregate
// FalsePositives==0 assertion above: run the detector directly against
// each negative fixture's exact endpoint+parameter and assert
// OutcomeNoFinding one at a time.
func TestPhase3_4_SSRFDetector_NegativeFixturesProduceNoFinding(t *testing.T) {
	l := testVulnLab(t)
	_, job, validator := runReconAgainstVulnLab(t, l)

	_, negatives := ssrfFixtures(t)
	if len(negatives) == 0 {
		t.Fatal("no ssrf negative fixtures found in ground truth -- test setup problem")
	}

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{})
	d := ssrf.New(l.SSRFCallback)

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

// TestPhase3_4_SSRFDetector_ScopeEnforcementStaysActiveDuringDetection
// is the CRITICAL scope-enforcement regression the task explicitly
// calls out: this scan job's ScopeSnapshot only authorizes
// vuln.scanner.test. A Target manufactured to point at the Phase 2
// lab's scanner.test host (real, running, reachable on this same
// process, but never authorized for this job) must be refused by the
// SCANNER's own Executor -- with zero requests reaching that host --
// even though the fixture the detector is probing (a hypothetical
// SSRF-vulnerable one) would, if truly vulnerable, be the thing making
// the OUT-of-band request, never the scanner itself. This directly
// distinguishes "the vulnerable application may fetch the controlled
// callback service" (expected, and exactly what VULN-SSRF-001 proves)
// from "the scanner itself must never actively access an out-of-scope
// destination" (this test).
func TestPhase3_4_SSRFDetector_ScopeEnforcementStaysActiveDuringDetection(t *testing.T) {
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
		Scheme: "http", URL: "http://scanner.test/?url=placeholder",
		Path: "/", Method: "GET", Parameter: "url", ParameterLocation: "query",
	}

	d := ssrf.New(l.SSRFCallback)
	_, detErr := d.Detect(context.Background(), outOfScope, x)
	if detErr == nil {
		t.Fatal("Detect against an out-of-scope target (scanner.test, not in this job's ScopeSnapshot): want error, got nil -- scope enforcement did not stop the request")
	}
	if x.RequestCount() != 0 {
		t.Errorf("Executor.RequestCount() = %d, want 0 -- the out-of-scope request must never actually dial", x.RequestCount())
	}
}
