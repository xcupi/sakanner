package chains

import (
	"fmt"
	"testing"

	"sakanner/pkg/models"
)

func manyFindingsSameEndpoint(n int) []models.Finding {
	out := make([]models.Finding, n)
	for i := 0; i < n; i++ {
		out[i] = newFinding(fmt.Sprintf("f%03d", i), "scan1", "sqli").
			endpoint("target.test", 80, "/x").build()
	}
	return out
}

func TestLimits_MaxFindings_Bounded(t *testing.T) {
	findings := manyFindingsSameEndpoint(20)
	res := Correlate(findings, Limits{MaxFindings: 5})
	if !res.Truncated {
		t.Error("expected Truncated=true when input exceeds MaxFindings")
	}
	seen := map[string]bool{}
	for _, r := range res.Relations {
		seen[r.FindingAID] = true
		seen[r.FindingBID] = true
	}
	if len(seen) > 5 {
		t.Errorf("relations reference %d distinct findings, want at most 5 (MaxFindings)", len(seen))
	}
}

func TestLimits_MaxFindings_DeterministicSelection(t *testing.T) {
	findings := manyFindingsSameEndpoint(20)
	res1 := Correlate(findings, Limits{MaxFindings: 5})
	res2 := Correlate(findings, Limits{MaxFindings: 5})
	if !relationsEqual(res1.Relations, res2.Relations) {
		t.Error("MaxFindings truncation must select the SAME subset every time, not an arbitrary one")
	}
}

func TestLimits_MaxRelations_Bounded(t *testing.T) {
	// 30 findings all sharing one endpoint -> C(30,2) = 435 SAME_ENDPOINT
	// relations if unbounded.
	findings := manyFindingsSameEndpoint(30)
	res := Correlate(findings, Limits{MaxFindings: 30, MaxRelations: 10})
	if len(res.Relations) > 10 {
		t.Errorf("len(Relations) = %d, want at most 10 (MaxRelations)", len(res.Relations))
	}
	if !res.Truncated {
		t.Error("expected Truncated=true when relations exceed MaxRelations")
	}
}

func TestLimits_MaxChainLength_Bounded(t *testing.T) {
	findings := manyFindingsSameEndpoint(20)
	res := Correlate(findings, Limits{MaxFindings: 20, MaxRelations: 2000, MaxChainLength: 4})
	for _, c := range res.Candidates {
		if len(c.FindingIDs) > 4 {
			t.Errorf("candidate has %d findings, want at most 4 (MaxChainLength): %+v", len(c.FindingIDs), c)
		}
	}
	if !res.Truncated {
		t.Error("expected Truncated=true when a chain exceeds MaxChainLength")
	}
}

func TestLimits_MaxCandidateChains_Bounded(t *testing.T) {
	// Build many DISJOINT pairs (each pair its own candidate) so the
	// candidate count, not chain length, is what's being bounded.
	var findings []models.Finding
	for i := 0; i < 20; i++ {
		host := fmt.Sprintf("host%02d.test", i)
		findings = append(findings,
			newFinding(fmt.Sprintf("a%02d", i), "scan1", "sqli").endpoint(host, 80, "/x").build(),
			newFinding(fmt.Sprintf("b%02d", i), "scan1", "reflected_xss").endpoint(host, 80, "/x").build(),
		)
	}
	res := Correlate(findings, Limits{MaxFindings: 100, MaxRelations: 2000, MaxCandidateChains: 3})
	if len(res.Candidates) > 3 {
		t.Errorf("len(Candidates) = %d, want at most 3 (MaxCandidateChains)", len(res.Candidates))
	}
	if !res.Truncated {
		t.Error("expected Truncated=true when candidates exceed MaxCandidateChains")
	}
}

func TestLimits_DuplicateRelationSuppression(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/x").build()
	b := newFinding("f2", "scan1", "reflected_xss").endpoint("target.test", 80, "/x").build()
	// Submit the same two findings twice.
	res := Correlate([]models.Finding{a, b, a, b}, DefaultLimits())
	seen := map[string]int{}
	for _, r := range res.Relations {
		seen[r.ID]++
	}
	for id, count := range seen {
		if count > 1 {
			t.Errorf("relation %s appeared %d times, want exactly 1 (duplicate suppression)", id, count)
		}
	}
}

func TestLimits_MaxEvidenceItemsPerRelation_Bounded(t *testing.T) {
	// A relation type in this package's default policy never produces
	// more than a handful of evidence items per pair; directly assert
	// the cap is enforced regardless.
	limits := Limits{MaxEvidenceItemsPerRelation: 1}.normalize()
	if limits.MaxEvidenceItemsPerRelation != 1 {
		t.Fatalf("normalize() overrode an explicit positive value: got %d", limits.MaxEvidenceItemsPerRelation)
	}
	a := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/x").build()
	b := newFinding("f2", "scan1", "reflected_xss").endpoint("target.test", 80, "/x").build()
	res := Correlate([]models.Finding{a, b}, limits)
	for _, r := range res.Relations {
		if len(r.Evidence) > 1 {
			t.Errorf("relation %+v has %d evidence items, want at most 1", r, len(r.Evidence))
		}
	}
}

func TestLimits_ZeroValueNormalizesToDefaults(t *testing.T) {
	l := Limits{}.normalize()
	d := DefaultLimits()
	if l != d {
		t.Errorf("Limits{}.normalize() = %+v, want %+v", l, d)
	}
}

func relationsEqual(a, b []FindingRelation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}
