package chains

import (
	"testing"

	"sakanner/pkg/models"
)

func TestCandidate_StructuralOnly_StatusPotential(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/x").build()
	b := newFinding("f2", "scan1", "reflected_xss").endpoint("target.test", 80, "/x").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if len(res.Candidates) != 1 {
		t.Fatalf("expected exactly 1 candidate, got %d: %+v", len(res.Candidates), res.Candidates)
	}
	c := res.Candidates[0]
	if c.Status != ChainPotential {
		t.Errorf("Status = %s, want POTENTIAL (structural-only relation)", c.Status)
	}
	if len(c.MissingEvidence) == 0 {
		t.Error("expected MissingEvidence to explain what would escalate this chain")
	}
}

func TestCandidate_EvidenceBacked_StatusSupported(t *testing.T) {
	expose := newFinding("f1", "scan1", "info_exposure").
		evidence(`leaked_id=OBJ-7788-token`).build()
	authz := newFinding("f2", "scan1", "idor").param("id").
		url("http://target.test/x?id=OBJ-7788-token").build()
	res := Correlate([]models.Finding{expose, authz}, DefaultLimits())
	if len(res.Candidates) != 1 {
		t.Fatalf("expected exactly 1 candidate, got %d: %+v", len(res.Candidates), res.Candidates)
	}
	if res.Candidates[0].Status != ChainSupported {
		t.Errorf("Status = %s, want SUPPORTED (DATA_FLOW evidence present)", res.Candidates[0].Status)
	}
}

func TestCandidate_NeverConfirmedByDefaultPolicy(t *testing.T) {
	// Even the strongest available evidence (multiple corroborating
	// relation types) must never reach CONFIRMED under this phase's
	// own deliberately conservative policy.
	expose := newFinding("f1", "scan1", "info_exposure").identity("account-a").
		endpoint("target.test", 80, "/leak").
		evidence(`leaked_id=OBJ-4455-secret`).build()
	authz := newFinding("f2", "scan1", "idor").identity("account-a").
		endpoint("target.test", 80, "/objects").param("id").
		url("http://target.test/objects?id=OBJ-4455-secret").build()
	res := Correlate([]models.Finding{expose, authz}, DefaultLimits())
	for _, c := range res.Candidates {
		if c.Status == ChainConfirmed {
			t.Errorf("SECURITY: a chain was marked CONFIRMED -- this phase's own policy must never do this: %+v", c)
		}
	}
}

func TestCandidate_Traceability_FindingIDsAndRelationIDsPresent(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/x").build()
	b := newFinding("f2", "scan1", "reflected_xss").endpoint("target.test", 80, "/x").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	c := res.Candidates[0]
	if len(c.FindingIDs) != 2 {
		t.Fatalf("FindingIDs = %v, want 2 entries", c.FindingIDs)
	}
	if len(c.RelationIDs) == 0 {
		t.Fatal("RelationIDs must be populated")
	}
	if c.ScanJobID != "scan1" {
		t.Errorf("ScanJobID = %q, want scan1", c.ScanJobID)
	}
	// Every RelationID must correspond to an actual relation in
	// res.Relations -- a candidate must never reference a relation
	// that doesn't exist in the output.
	relByID := map[string]bool{}
	for _, r := range res.Relations {
		relByID[r.ID] = true
	}
	for _, rid := range c.RelationIDs {
		if !relByID[rid] {
			t.Errorf("candidate references RelationID %q which is not in res.Relations", rid)
		}
	}
}

func TestCandidate_ThreeFindingsChainTogether(t *testing.T) {
	// f1-f2 share an endpoint; f2-f3 share a resource -- f1/f2/f3
	// should end up in ONE connected candidate even though f1 and f3
	// share nothing directly.
	f1 := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/shared").build()
	f2 := newFinding("f2", "scan1", "reflected_xss").endpoint("target.test", 80, "/shared").param("id").
		url("http://target.test/shared?id=OBJ-3311").build()
	f3 := newFinding("f3", "scan1", "idor").endpoint("other.test", 80, "/other").param("id").
		url("http://other.test/other?id=OBJ-3311").build()
	res := Correlate([]models.Finding{f1, f2, f3}, DefaultLimits())
	if len(res.Candidates) != 1 {
		t.Fatalf("expected exactly 1 connected candidate spanning all 3 findings, got %d: %+v", len(res.Candidates), res.Candidates)
	}
	if len(res.Candidates[0].FindingIDs) != 3 {
		t.Errorf("FindingIDs = %v, want all 3 findings in one candidate", res.Candidates[0].FindingIDs)
	}
}

func TestCandidate_DifferentVulnerabilityTypesInOneChain(t *testing.T) {
	f1 := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/x").build()
	f2 := newFinding("f2", "scan1", "reflected_xss").endpoint("target.test", 80, "/x").build()
	res := Correlate([]models.Finding{f1, f2}, DefaultLimits())
	if len(res.Candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(res.Candidates))
	}
	types := map[string]bool{}
	for _, fid := range res.Candidates[0].FindingIDs {
		for _, f := range []models.Finding{f1, f2} {
			if f.ID == fid {
				types[f.VulnerabilityType] = true
			}
		}
	}
	if len(types) != 2 {
		t.Errorf("expected a chain spanning 2 distinct vulnerability types, got: %v", types)
	}
}

func TestCandidate_MultipleFindingsSameVulnerabilityTypeInOneChain(t *testing.T) {
	f1 := newFinding("f1", "scan1", "idor").param("id").url("http://target.test/a?id=OBJ-1122").build()
	f2 := newFinding("f2", "scan1", "idor").param("id").url("http://target.test/b?id=OBJ-1122").build()
	res := Correlate([]models.Finding{f1, f2}, DefaultLimits())
	if len(res.Candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(res.Candidates))
	}
	if len(res.Candidates[0].FindingIDs) != 2 {
		t.Errorf("expected both same-vulnerability-type findings to chain together, got: %v", res.Candidates[0].FindingIDs)
	}
}

func TestCandidate_ExplainsWhy(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/x").build()
	b := newFinding("f2", "scan1", "reflected_xss").endpoint("target.test", 80, "/x").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if res.Candidates[0].Reason == "" {
		t.Error("expected a non-empty Reason explaining why the findings were correlated")
	}
	for _, r := range res.Relations {
		if r.Reason == "" {
			t.Errorf("relation %+v has an empty Reason", r)
		}
		if len(r.Evidence) == 0 {
			t.Errorf("relation %+v has no evidence", r)
		}
	}
}

func TestCandidate_ImpactAndConfidenceSeparateFromFindingSeverity(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/x").severity(models.SeverityLow).build()
	b := newFinding("f2", "scan1", "reflected_xss").endpoint("target.test", 80, "/x").severity(models.SeverityLow).build()
	originalSevA, originalSevB := a.Severity, b.Severity

	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if a.Severity != originalSevA || b.Severity != originalSevB {
		t.Fatal("SECURITY: Correlate must never mutate an input finding's own Severity")
	}
	c := res.Candidates[0]
	if c.ImpactEstimate == "" {
		t.Error("expected a non-empty chain-level ImpactEstimate")
	}
	if c.Confidence <= 0 || c.Confidence > 1 {
		t.Errorf("Confidence = %v, want a value in (0, 1]", c.Confidence)
	}
}
