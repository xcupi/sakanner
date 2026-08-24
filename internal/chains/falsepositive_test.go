// False-positive resistance: the task's own 8 named negative
// scenarios. None of these may ever produce a SUPPORTED or CONFIRMED
// ChainCandidate.
package chains

import (
	"testing"

	"sakanner/pkg/models"
)

func assertNoSupportedOrConfirmedChain(t *testing.T, res Result) {
	t.Helper()
	for _, c := range res.Candidates {
		if c.Status == ChainSupported || c.Status == ChainConfirmed {
			t.Errorf("SECURITY: unexpected %s chain candidate: %+v", c.Status, c)
		}
	}
}

// 1. Two unrelated vulnerabilities on the same endpoint.
func TestFalsePositive_TwoUnrelatedVulnsOnSameEndpoint(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/search").
		evidence("boolean-based difference observed").build()
	b := newFinding("f2", "scan1", "insecure_cookie").endpoint("target.test", 80, "/search").
		evidence("Set-Cookie missing HttpOnly flag").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	// SAME_ENDPOINT is a legitimate, weak structural relation --
	// verify it never escalates past POTENTIAL.
	assertNoSupportedOrConfirmedChain(t, res)
}

// 2. Same parameter name on unrelated endpoints.
func TestFalsePositive_SameParameterNameUnrelatedEndpoints(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/search").param("id").build()
	b := newFinding("f2", "scan1", "cmdinjection").endpoint("target.test", 80, "/export").param("id").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	assertNoSupportedOrConfirmedChain(t, res)
}

// 3. Same object identifier across different identities.
func TestFalsePositive_SameObjectIdentifierDifferentIdentities(t *testing.T) {
	a := newFinding("f1", "scan1", "idor").identity("account-a").param("id").
		url("http://target.test/x?id=OBJ-9001").build()
	b := newFinding("f2", "scan1", "idor").identity("account-b").param("id").
		url("http://target.test/x?id=OBJ-9001").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if len(res.Relations) != 0 {
		t.Fatalf("SECURITY: identity isolation must reject this before any resource match: %+v", res.Relations)
	}
}

// 4. Same vulnerability class on unrelated resources.
func TestFalsePositive_SameVulnClassUnrelatedResources(t *testing.T) {
	a := newFinding("f1", "scan1", "idor").param("id").url("http://target.test/a?id=OBJ-1111").build()
	b := newFinding("f2", "scan1", "idor").param("id").url("http://target.test/b?id=OBJ-2222").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationSameResource); ok {
		t.Error("different resource identifier values must never produce SAME_RESOURCE")
	}
	assertNoSupportedOrConfirmedChain(t, res)
}

// 5. Findings from different ScanJobIDs.
func TestFalsePositive_DifferentScanJobIDs(t *testing.T) {
	a := newFinding("f1", "scan-A", "idor").param("id").url("http://target.test/a?id=OBJ-1111").build()
	b := newFinding("f2", "scan-B", "idor").param("id").url("http://target.test/a?id=OBJ-1111").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if len(res.Relations) != 0 {
		t.Fatalf("SECURITY: different ScanJobIDs must never relate: %+v", res.Relations)
	}
}

// 6. Findings from different hosts.
func TestFalsePositive_DifferentHosts(t *testing.T) {
	a := newFinding("f1", "scan1", "idor").endpoint("host-a.test", 80, "/x").param("id").
		url("http://host-a.test/x?id=OBJ-1111").build()
	b := newFinding("f2", "scan1", "idor").endpoint("host-b.test", 80, "/x").param("id").
		url("http://host-b.test/x?id=OBJ-1111").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationSameEndpoint); ok {
		t.Error("different hosts must never produce SAME_ENDPOINT")
	}
	// SAME_RESOURCE can still legitimately fire (same object id value,
	// same scan, same/no identity) -- that alone must not confirm a
	// chain; different-host correlation stays POTENTIAL at most.
	assertNoSupportedOrConfirmedChain(t, res)
}

// 7. Findings with similar response bodies but unrelated evidence.
func TestFalsePositive_SimilarResponseBodiesUnrelatedEvidence(t *testing.T) {
	a := newFinding("f1", "scan1", "info_exposure").
		evidence("<html><body>Welcome to the site. Please log in.</body></html>").build()
	b := newFinding("f2", "scan1", "misconfiguration").
		evidence("<html><body>Welcome to the site. Contact support.</body></html>").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationSharedEvidence); ok {
		t.Error("generic, non-distinctive shared boilerplate text (\"Welcome to the site\") must never produce SHARED_EVIDENCE")
	}
}

// TestFalsePositive_SharedPortNumber_NeverProducesSharedEvidence
// reproduces a REAL defect discovered during Phase 3.31's own
// integration testing against a real, broad detector scan: every
// finding in one scan against one target shares the SAME port number
// in its own evidence "request" field -- a pure-digit token like
// "40079" satisfying the OLD, looser identifier check, manufacturing
// a SHARED_EVIDENCE relation between literally every pair of findings
// in the scan. Fixed by requiring a SHARED_EVIDENCE token to contain
// BOTH a digit and a non-digit character (looksLikeSharedEvidenceToken).
func TestFalsePositive_SharedPortNumber_NeverProducesSharedEvidence(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").
		evidence(`{"request":"GET http://target.test:40079/sqli?id=1","response":"HTTP 200"}`).build()
	b := newFinding("f2", "scan1", "cmdinjection").
		evidence(`{"request":"GET http://target.test:40079/ping?host=x","response":"HTTP 200"}`).build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationSharedEvidence); ok {
		t.Error("SECURITY: a shared PORT NUMBER (present in every finding's evidence purely because they target the same host) must never produce SHARED_EVIDENCE")
	}
}

// TestFalsePositive_DetectorBoilerplateFieldNames_NeverProducesSharedEvidence
// reproduces the second real defect from the same discovery: generic,
// no-digit evidence-schema vocabulary ("response_fragment",
// detector-internal FIXED marker constants like
// "COMMAND_INJECTION_MARKER") appears identically across MANY
// unrelated findings simply because they share a detector's own
// evidence-formatting convention, not because the findings are
// actually related.
func TestFalsePositive_DetectorBoilerplateFieldNames_NeverProducesSharedEvidence(t *testing.T) {
	a := newFinding("f1", "scan1", "cmdinjection").
		evidence(`{"response_fragment":"ping executed\nCOMMAND_INJECTION_MARKER:token-aaa","observation":"controlled_command_execution_occurred"}`).build()
	b := newFinding("f2", "scan1", "cmdinjection").
		evidence(`{"response_fragment":"ping executed\nCOMMAND_INJECTION_MARKER:token-bbb","observation":"controlled_command_execution_occurred"}`).build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if r, ok := relationOfType(res.Relations, RelationSharedEvidence); ok {
		t.Errorf("SECURITY: two findings sharing only a detector's own fixed schema vocabulary/marker constant (never a genuinely per-finding-unique value) must never produce SHARED_EVIDENCE: %+v", r)
	}
}

// 8. High-severity findings that have no causal relationship.
func TestFalsePositive_HighSeverityNoCausalRelationship(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/a").severity(models.SeverityCritical).build()
	b := newFinding("f2", "scan1", "cmdinjection").endpoint("target.test", 443, "/b").severity(models.SeverityCritical).build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if len(res.Relations) != 0 {
		t.Fatalf("SECURITY: two high-severity findings with no shared endpoint/resource/parameter/evidence must never relate merely because both are severe: %+v", res.Relations)
	}
}
