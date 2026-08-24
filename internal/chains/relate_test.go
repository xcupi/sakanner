package chains

import (
	"testing"

	"sakanner/pkg/models"
)

func relationOfType(rs []FindingRelation, t RelationType) (FindingRelation, bool) {
	for _, r := range rs {
		if r.Type == t {
			return r, true
		}
	}
	return FindingRelation{}, false
}

func TestSameEndpoint_Recognized(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/search").build()
	b := newFinding("f2", "scan1", "reflected_xss").endpoint("target.test", 80, "/search").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationSameEndpoint); !ok {
		t.Fatalf("expected SAME_ENDPOINT, got: %+v", res.Relations)
	}
}

func TestSameParameter_Recognized(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("a.test", 80, "/a").param("id").build()
	b := newFinding("f2", "scan1", "idor").endpoint("b.test", 80, "/b").param("id").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationSameParameter); !ok {
		t.Fatalf("expected SAME_PARAMETER, got: %+v", res.Relations)
	}
}

func TestSameResource_Recognized(t *testing.T) {
	a := newFinding("f1", "scan1", "idor").endpoint("target.test", 80, "/notes").param("note_id").
		url("http://target.test/notes?note_id=5001").build()
	b := newFinding("f2", "scan1", "info_exposure").endpoint("target.test", 80, "/notes/export").param("note_id").
		url("http://target.test/notes/export?note_id=5001").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	r, ok := relationOfType(res.Relations, RelationSameResource)
	if !ok {
		t.Fatalf("expected SAME_RESOURCE, got: %+v", res.Relations)
	}
	if r.Evidence[0].Detail != "5001" {
		t.Errorf("evidence detail = %q, want 5001", r.Evidence[0].Detail)
	}
}

func TestSameResource_ShortNonIdentifierValue_NotRecognized(t *testing.T) {
	a := newFinding("f1", "scan1", "idor").param("id").url("http://target.test/a?id=1").build()
	b := newFinding("f2", "scan1", "idor").param("id").url("http://target.test/b?id=1").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationSameResource); ok {
		t.Error("a short, non-identifier-shaped value (\"1\") must never be treated as a shared resource identifier")
	}
}

func TestSameIdentity_Recognized(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").identity("account-a").build()
	b := newFinding("f2", "scan1", "idor").identity("account-a").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationSameIdentity); !ok {
		t.Fatalf("expected SAME_IDENTITY, got: %+v", res.Relations)
	}
}

func TestSharedEvidence_Recognized(t *testing.T) {
	a := newFinding("f1", "scan1", "info_exposure").evidence("leaked token: SAKANNER-MARKER-9f31c2").build()
	b := newFinding("f2", "scan1", "ssrf").evidence("callback received token SAKANNER-MARKER-9f31c2 from origin").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	r, ok := relationOfType(res.Relations, RelationSharedEvidence)
	if !ok {
		t.Fatalf("expected SHARED_EVIDENCE, got: %+v", res.Relations)
	}
	if r.Evidence[0].Detail != "SAKANNER-MARKER-9f31c2" {
		t.Errorf("evidence detail = %q, want the shared marker token", r.Evidence[0].Detail)
	}
}

func TestDataFlow_InfoExposureToAuthorization(t *testing.T) {
	// Task's own "information exposure -> object identifier ->
	// authorization finding" scenario.
	expose := newFinding("f1", "scan1", "info_exposure").
		endpoint("target.test", 80, "/api/debug").
		evidence(`{"leaked_internal_object_id":"OBJ-4471-secret"}`).build()
	authz := newFinding("f2", "scan1", "idor").
		endpoint("target.test", 80, "/api/objects").param("object_id").
		url("http://target.test/api/objects?object_id=OBJ-4471-secret").build()
	res := Correlate([]models.Finding{expose, authz}, DefaultLimits())
	r, ok := relationOfType(res.Relations, RelationDataFlow)
	if !ok {
		t.Fatalf("expected DATA_FLOW, got: %+v", res.Relations)
	}
	if r.Evidence[0].Detail != "OBJ-4471-secret" {
		t.Errorf("evidence detail = %q, want the leaked object id", r.Evidence[0].Detail)
	}
}

func TestPotentialPrecondition_RedirectToEndpoint(t *testing.T) {
	// Task's own "redirect behavior -> subsequent security-relevant
	// endpoint relationship" scenario.
	redirect := newFinding("f1", "scan1", "open_redirect").
		endpoint("target.test", 80, "/go").
		evidence("resolved_destination=http://internal-admin.scanner.test/panel").build()
	admin := newFinding("f2", "scan1", "idor").
		endpoint("internal-admin.scanner.test", 80, "/panel").build()
	res := Correlate([]models.Finding{redirect, admin}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationPotentialPrecondition); !ok {
		t.Fatalf("expected POTENTIAL_PRECONDITION, got: %+v", res.Relations)
	}
}

func TestPotentialPrecondition_SSRFToInternalResource(t *testing.T) {
	// Task's own "SSRF finding -> evidence referencing an internal
	// resource" scenario.
	ssrfFinding := newFinding("f1", "scan1", "ssrf").
		endpoint("target.test", 80, "/fetch").
		evidence("callback confirmed: reached internal-metadata.scanner.test successfully").build()
	internal := newFinding("f2", "scan1", "info_exposure").
		endpoint("internal-metadata.scanner.test", 80, "/latest/meta-data").build()
	res := Correlate([]models.Finding{ssrfFinding, internal}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationPotentialPrecondition); !ok {
		t.Fatalf("expected POTENTIAL_PRECONDITION, got: %+v", res.Relations)
	}
}

func TestPotentialPrecondition_SourceReferencingOwnHost_NotRecognized(t *testing.T) {
	// An SSRF finding whose evidence merely mentions its OWN host is
	// not a precondition for anything -- only a DIFFERENT host counts.
	f1 := newFinding("f1", "scan1", "ssrf").endpoint("target.test", 80, "/fetch").
		evidence("fetched from target.test successfully").build()
	f2 := newFinding("f2", "scan1", "info_exposure").endpoint("target.test", 80, "/other").build()
	res := Correlate([]models.Finding{f1, f2}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationPotentialPrecondition); ok {
		t.Error("a source finding referencing its OWN host must never produce POTENTIAL_PRECONDITION")
	}
}

func TestPotentialImpactAmplifier_HighSeveritySameEndpoint(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/x").severity(models.SeverityCritical).build()
	b := newFinding("f2", "scan1", "reflected_xss").endpoint("target.test", 80, "/x").severity(models.SeverityLow).build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationPotentialImpactAmp); !ok {
		t.Fatalf("expected POTENTIAL_IMPACT_AMPLIFIER, got: %+v", res.Relations)
	}
}

func TestNoRelation_CompletelyUnrelatedFindings(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("a.test", 80, "/a").param("q").build()
	b := newFinding("f2", "scan1", "cmdinjection").endpoint("b.test", 443, "/b").param("cmd").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if len(res.Relations) != 0 {
		t.Errorf("expected zero relations between two completely unrelated findings, got: %+v", res.Relations)
	}
	if len(res.Candidates) != 0 {
		t.Errorf("expected zero candidates, got: %+v", res.Candidates)
	}
}
