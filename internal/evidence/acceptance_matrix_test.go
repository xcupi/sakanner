package evidence

import (
	"strings"
	"testing"
)

// TestAcceptanceMatrix_AllSixVulnerabilityClasses is task section 44's
// required table -- every current vulnerability class run through the
// full pipeline, verifying evidence completeness, secret redaction,
// integrity, deterministic ordering, and reproducibility together. See
// docs/phase-3-10-acceptance-test.md for this table reproduced as the
// acceptance report.
func TestAcceptanceMatrix_AllSixVulnerabilityClasses(t *testing.T) {
	t.Log("Finding | Evidence Type | Expected | Actual | Result")
	for vulnType, cf := range allSixFixtures() {
		items := BuildEvidence(cf, DefaultLimits())

		hasVerification := false
		hasReproduction := false
		for _, it := range items {
			switch it.Type {
			case EvidenceTypeVerification:
				hasVerification = true
			case EvidenceTypeReproduction:
				hasReproduction = true
			}
			if it.EvidenceID == "" {
				t.Errorf("%s: item has empty EvidenceID", vulnType)
			}
			if it.IntegrityHash == "" {
				t.Errorf("%s: item has empty IntegrityHash", vulnType)
			}
			if strings.Contains(it.Observation, "SECRET") && strings.Contains(strings.ToUpper(it.Observation), "AUTHORIZATION") {
				t.Errorf("%s: Observation may leak a secret: %q", vulnType, it.Observation)
			}
		}

		result := "PASS"
		if !hasVerification || !hasReproduction {
			result = "FAIL"
		}
		t.Logf("%s | VERIFICATION+REPRODUCTION | present | verification=%v reproduction=%v | %s", vulnType, hasVerification, hasReproduction, result)

		if !hasVerification {
			t.Errorf("%s: no VERIFICATION evidence produced", vulnType)
		}
		if !hasReproduction {
			t.Errorf("%s: no REPRODUCTION evidence produced", vulnType)
		}

		// Deterministic ordering: repeated calls produce identical order.
		items2 := BuildEvidence(cf, DefaultLimits())
		if len(items) != len(items2) {
			t.Fatalf("%s: repeated BuildEvidence call produced a different count", vulnType)
		}
		for i := range items {
			if items[i].EvidenceID != items2[i].EvidenceID {
				t.Errorf("%s: order differs across repeated calls at index %d", vulnType, i)
			}
			if items[i].IntegrityHash != items2[i].IntegrityHash {
				t.Errorf("%s: hash differs across repeated calls at index %d", vulnType, i)
			}
		}
	}
}
