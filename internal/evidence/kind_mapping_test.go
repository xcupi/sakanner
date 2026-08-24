package evidence

import (
	"testing"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

// Phase 3.11's real-evidence-integration tests: 5 of the 6 real
// detectors now record a genuine models.EvidenceKindBaseline (and, for
// idor/traversal, an additional models.EvidenceKindProbe) item
// alongside their existing models.EvidenceKindRequestResponse item --
// see docs/phase-3-11-scan-orchestrator.md "Real evidence integration".
// These tests lock in that BuildEvidence classifies each kind into the
// correct EvidenceType, not just that a real end-to-end run happens to
// produce the right counts (that's covered separately in
// lab/phase3_11_orchestrator_test.go).

func findingWithEvidenceKinds(kinds ...models.EvidenceKind) correlation.CanonicalFinding {
	cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, rawRequestResponseEvidence{})
	cf.Evidence = nil
	for i, k := range kinds {
		raw := rawRequestResponseEvidence{
			Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
			ResponseFragment: "ok", Parameter: "q", Payload: "1",
			Observation: "role=item", Reason: "reason",
		}
		_ = i
		cf.Evidence = append(cf.Evidence, correlation.EvidenceItem{Kind: k, Content: rawJSON(raw)})
	}
	return cf
}

func TestEvidenceType_BaselineKindClassifiesAsBaseline(t *testing.T) {
	cf := findingWithEvidenceKinds(models.EvidenceKindBaseline)
	items := BuildEvidence(cf, DefaultLimits())

	found := false
	for _, it := range items {
		if it.Type == EvidenceTypeBaseline {
			found = true
		}
	}
	if !found {
		t.Errorf("no BASELINE-typed item produced from an EvidenceKindBaseline raw item: %+v", items)
	}
}

func TestEvidenceType_ProbeKindClassifiesAsProbe(t *testing.T) {
	cf := findingWithEvidenceKinds(models.EvidenceKindProbe)
	items := BuildEvidence(cf, DefaultLimits())

	found := false
	for _, it := range items {
		if it.Type == EvidenceTypeProbe {
			found = true
		}
	}
	if !found {
		t.Errorf("no PROBE-typed item produced from an EvidenceKindProbe raw item: %+v", items)
	}
}

func TestEvidenceType_RequestResponseKindStillClassifiesAsVerification(t *testing.T) {
	// The pre-Phase-3.11 default kind (used by xssreflected, and by the
	// "combined" item every other detector still emits alongside its
	// new baseline/probe items) must keep classifying as VERIFICATION --
	// zero regression for every fixture/test written before this phase.
	cf := findingWithEvidenceKinds(models.EvidenceKindRequestResponse)
	items := BuildEvidence(cf, DefaultLimits())

	found := false
	for _, it := range items {
		if it.Type == EvidenceTypeVerification {
			found = true
		}
	}
	if !found {
		t.Errorf("no VERIFICATION-typed item produced from an EvidenceKindRequestResponse raw item: %+v", items)
	}
}

func TestEvidenceType_UnrecognizedKindDefaultsToVerification(t *testing.T) {
	cf := findingWithEvidenceKinds(models.EvidenceKind("something_new_and_unmapped"))
	items := BuildEvidence(cf, DefaultLimits())

	found := false
	for _, it := range items {
		if it.Type == EvidenceTypeVerification {
			found = true
		}
	}
	if !found {
		t.Errorf("an unrecognized EvidenceKind must default to VERIFICATION rather than being dropped or crashing: %+v", items)
	}
}

func TestEvidenceType_MultipleKindsOnOneFindingAllClassifyCorrectly(t *testing.T) {
	cf := findingWithEvidenceKinds(models.EvidenceKindBaseline, models.EvidenceKindProbe, models.EvidenceKindRequestResponse)
	items := BuildEvidence(cf, DefaultLimits())

	var types []EvidenceType
	for _, it := range items {
		types = append(types, it.Type)
	}
	wantOrder := []EvidenceType{EvidenceTypeBaseline, EvidenceTypeProbe, EvidenceTypeVerification, EvidenceTypeReproduction}
	if len(types) != len(wantOrder) {
		t.Fatalf("types = %v, want %v (deterministic BASELINE->PROBE->VERIFICATION->REPRODUCTION order)", types, wantOrder)
	}
	for i, want := range wantOrder {
		if types[i] != want {
			t.Errorf("index %d: type = %s, want %s", i, types[i], want)
		}
	}
}
