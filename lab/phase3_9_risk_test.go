// Phase 3.9 integration test: runs the REAL Phase 3.1 detection.Engine
// with all six real detectors against the real vuln.scanner.test lab,
// feeds the persisted findings through the REAL Phase 3.8
// correlation.Engine, and then through the NEW Phase 3.9 risk engine --
// verifying every canonical finding, of every vulnerability type this
// project has, receives a risk score, priority, score breakdown, and
// explanation (task section 29).
package lab

import (
	"context"
	"testing"

	"sakanner/internal/correlation"
	"sakanner/internal/detection"
	"sakanner/internal/risk"
)

func TestPhase3_9_Risk_RealCanonicalFindingsProduceAssessments(t *testing.T) {
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

	rawFindings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(rawFindings) == 0 {
		t.Fatal("no findings persisted -- test setup problem")
	}

	ce := correlation.NewEngine()
	ce.Ingest(rawFindings...)
	canonical := ce.Findings()
	t.Logf("Correlation: %d raw findings -> %d canonical findings", len(rawFindings), len(canonical))

	assessments := risk.AssessAll(canonical, nil)
	ranked := risk.Rank(assessments)

	if len(ranked) != len(canonical) {
		t.Fatalf("len(ranked) = %d, want %d (risk scoring must neither create nor drop findings)", len(ranked), len(canonical))
	}

	types := map[string]int{}
	for _, a := range ranked {
		if a.RiskScore < 0 || a.RiskScore > 100 {
			t.Errorf("%s: RiskScore = %d, want in [0, 100]", a.FindingID, a.RiskScore)
		}
		if a.Priority == "" {
			t.Errorf("%s: Priority is empty", a.FindingID)
		}
		if a.Explanation == "" {
			t.Errorf("%s: Explanation is empty", a.FindingID)
		}
		if a.Breakdown.RiskScore != a.RiskScore {
			t.Errorf("%s: Breakdown.RiskScore (%d) != Assessment.RiskScore (%d)", a.FindingID, a.Breakdown.RiskScore, a.RiskScore)
		}
		// Every real finding in this lab has severity=critical or
		// severity=high (see each Phase 3.x detector's confirmed
		// tier) -- never empty, never unrecognized.
		if !a.Breakdown.SeverityRecognized {
			t.Errorf("%s: severity %q was not recognized", a.FindingID, a.Severity)
		}
		types[a.VulnerabilityType]++
	}

	for _, vulnType := range []string{"reflected_xss", "sql_injection", "ssrf", "idor", "path_traversal", "command_injection"} {
		if types[vulnType] == 0 {
			t.Errorf("no assessment produced for vulnerability type %q", vulnType)
		}
	}

	// Deterministic ranking across repeated runs against the SAME
	// canonical set (task section 30).
	rankedAgain := risk.Rank(risk.AssessAll(canonical, nil))
	if len(rankedAgain) != len(ranked) {
		t.Fatal("repeated AssessAll+Rank produced a different length")
	}
	for i := range ranked {
		if ranked[i].FindingID != rankedAgain[i].FindingID {
			t.Errorf("index %d: order differs across repeated runs", i)
		}
		if ranked[i].RiskScore != rankedAgain[i].RiskScore {
			t.Errorf("index %d: RiskScore differs across repeated runs", i)
		}
		if ranked[i].Explanation != rankedAgain[i].Explanation {
			t.Errorf("index %d: Explanation differs across repeated runs", i)
		}
	}

	t.Logf("Top-ranked finding: %s (%s, score=%d, priority=%s)", ranked[0].FindingID, ranked[0].VulnerabilityType, ranked[0].RiskScore, ranked[0].Priority)
}
