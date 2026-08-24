package risk

import (
	"strconv"
	"testing"
	"time"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

func laterTime() time.Time   { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
func earlierTime() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }

// --- Assess / AssessAll ---------------------------------------------------

func TestAssess_PreservesOriginalSeverity(t *testing.T) {
	cf, ctx := fixtureCriticalHighInternetFacing()
	a := Assess(cf, ctx)
	if a.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want critical (must never be altered by risk scoring)", a.Severity)
	}
}

func TestAssess_PopulatesEveryField(t *testing.T) {
	cf, ctx := fixtureHighHighInternetFacing()
	a := Assess(cf, ctx)
	if a.FindingID != cf.FindingID {
		t.Errorf("FindingID = %q, want %q", a.FindingID, cf.FindingID)
	}
	if a.Explanation == "" {
		t.Error("Explanation is empty")
	}
	if a.Priority == "" {
		t.Error("Priority is empty")
	}
	if a.VulnerabilityType != cf.VulnerabilityType {
		t.Errorf("VulnerabilityType = %q, want %q", a.VulnerabilityType, cf.VulnerabilityType)
	}
}

func TestAssessAll_EmptyFindingSet(t *testing.T) {
	got := AssessAll(nil, nil)
	if got == nil {
		t.Error("AssessAll(nil, nil) returned a nil slice, want a non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

func TestAssessAll_SingleFinding(t *testing.T) {
	cf, ctx := fixtureLowLowInternal()
	got := AssessAll([]correlation.CanonicalFinding{cf}, map[string]*AssetContext{cf.FindingID: ctx})
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
}

func TestAssessAll_LargeFindingSet(t *testing.T) {
	var findings []correlation.CanonicalFinding
	for i := 0; i < 500; i++ {
		findings = append(findings, canonicalFinding("scan-1", "f-"+strconv.Itoa(i), "reflected_xss", models.SeverityHigh, 0.9, correlation.StatusNew, "host.test"))
	}
	got := AssessAll(findings, nil)
	if len(got) != 500 {
		t.Fatalf("len = %d, want 500", len(got))
	}
}

// --- Ranking / tie-breaking (task sections 14-16) ---------------------------

func TestRank_SortsByRiskScoreDescending(t *testing.T) {
	low, _ := fixtureLowLowInternal()
	critical, ctx := fixtureCriticalHighInternetFacing()
	assessments := []Assessment{Assess(low, nil), Assess(critical, ctx)}

	ranked := Rank(assessments)
	if ranked[0].FindingID != critical.FindingID {
		t.Errorf("ranked[0] = %s, want the higher-scored finding first", ranked[0].FindingID)
	}
}

func TestRank_DoesNotMutateInput(t *testing.T) {
	low, _ := fixtureLowLowInternal()
	critical, ctx := fixtureCriticalHighInternetFacing()
	original := []Assessment{Assess(low, nil), Assess(critical, ctx)}
	originalCopy := make([]Assessment, len(original))
	copy(originalCopy, original)

	_ = Rank(original)
	for i := range original {
		if original[i].FindingID != originalCopy[i].FindingID {
			t.Error("Rank mutated its input slice's order -- it must return a new slice")
		}
	}
}

func TestRank_TieBreaksBySeverityThenConfidenceThenVerification(t *testing.T) {
	// Two Assessments constructed directly with an EQUAL RiskScore but
	// different Severity, to isolate the tie-break behavior itself
	// rather than relying on the formula to coincidentally produce a
	// tie (task section 16).
	high := Assessment{FindingID: "id-high", RiskScore: 50, Severity: models.SeverityHigh, Factors: RiskFactors{Confidence: ConfidenceHigh, Verification: VerificationVerified}, Asset: AssetSummary{Host: "h.test"}}
	medium := Assessment{FindingID: "id-medium", RiskScore: 50, Severity: models.SeverityMedium, Factors: RiskFactors{Confidence: ConfidenceHigh, Verification: VerificationVerified}, Asset: AssetSummary{Host: "h.test"}}

	ranked := Rank([]Assessment{medium, high})
	if ranked[0].FindingID != "id-high" {
		t.Errorf("ranked[0] = %s, want id-high (higher severity wins the tie)", ranked[0].FindingID)
	}
	// Original severities must remain exactly what was constructed.
	if ranked[0].Severity != models.SeverityHigh || ranked[1].Severity != models.SeverityMedium {
		t.Error("tie-breaking must never alter the original Severity values")
	}
}

func TestRank_TieBreaksDeterministicallyToTheEnd(t *testing.T) {
	// Two Assessments identical in every ranked dimension except
	// FindingID -- must still order deterministically (never randomly).
	a := Assessment{FindingID: "aaa", RiskScore: 50, Severity: models.SeverityHigh, VulnerabilityType: "x", Asset: AssetSummary{Host: "h.test", Path: "/p"}}
	b := Assessment{FindingID: "bbb", RiskScore: 50, Severity: models.SeverityHigh, VulnerabilityType: "x", Asset: AssetSummary{Host: "h.test", Path: "/p"}}

	for i := 0; i < 5; i++ {
		ranked := Rank([]Assessment{b, a})
		if ranked[0].FindingID != "aaa" {
			t.Fatalf("run %d: ranked[0] = %s, want aaa (lexically smaller FindingID wins the final tiebreak)", i, ranked[0].FindingID)
		}
	}
}

func TestRank_NeverUsesRandomOrCreationTimeOrdering(t *testing.T) {
	a := Assessment{FindingID: "aaa", RiskScore: 50, Severity: models.SeverityHigh, AssessedAt: laterTime()}
	b := Assessment{FindingID: "bbb", RiskScore: 50, Severity: models.SeverityHigh, AssessedAt: earlierTime()}
	// b was "assessed" earlier than a, but AssessedAt must never
	// influence ranking -- only the documented 8 keys do.
	ranked := Rank([]Assessment{a, b})
	if ranked[0].FindingID != "aaa" {
		t.Errorf("ranked[0] = %s, want aaa (FindingID tiebreak, ignoring AssessedAt entirely)", ranked[0].FindingID)
	}
}

func TestRank_DeterministicAcrossRepeatedRuns(t *testing.T) {
	cf1, ctx1 := fixtureHighHighInternetFacing()
	cf2, ctx2 := fixtureMediumHighInternal()
	cf3, ctx3 := fixtureCriticalHighInternetFacing()
	findings := []correlation.CanonicalFinding{cf1, cf2, cf3}
	ctxs := map[string]*AssetContext{cf1.FindingID: ctx1, cf2.FindingID: ctx2, cf3.FindingID: ctx3}

	runA := Rank(AssessAll(findings, ctxs))
	runB := Rank(AssessAll(findings, ctxs))
	runC := Rank(AssessAll(findings, ctxs))

	for i := range runA {
		if runA[i].FindingID != runB[i].FindingID || runB[i].FindingID != runC[i].FindingID {
			t.Fatalf("index %d: order differs across runs: %s / %s / %s", i, runA[i].FindingID, runB[i].FindingID, runC[i].FindingID)
		}
		if runA[i].RiskScore != runB[i].RiskScore || runA[i].Explanation != runB[i].Explanation {
			t.Fatalf("index %d: score or explanation differs across runs", i)
		}
	}
}
