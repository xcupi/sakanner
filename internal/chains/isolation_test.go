package chains

import (
	"testing"

	"sakanner/pkg/models"
)

// TestIdentityIsolation_TaskWorkedExample is the task's own literal
// example: Account A's IDOR finding on object 1001 must NOT
// automatically become a chain with Account B's XSS finding on the
// same object 1001, merely because the object identifier matches.
func TestIdentityIsolation_TaskWorkedExample(t *testing.T) {
	idor := newFinding("f1", "scan1", "idor").identity("account-a").
		endpoint("target.test", 80, "/objects").param("id").
		url("http://target.test/objects?id=1001").build()
	xss := newFinding("f2", "scan1", "reflected_xss").identity("account-b").
		endpoint("target.test", 80, "/objects").param("id").
		url("http://target.test/objects?id=1001").build()

	res := Correlate([]models.Finding{idor, xss}, DefaultLimits())
	if len(res.Relations) != 0 {
		t.Fatalf("SECURITY: found %d relation(s) between findings from DIFFERENT identities sharing an object identifier -- must be zero: %+v", len(res.Relations), res.Relations)
	}
	if len(res.Candidates) != 0 {
		t.Fatalf("SECURITY: found %d chain candidate(s) spanning different identities: %+v", len(res.Candidates), res.Candidates)
	}
}

func TestIdentityIsolation_UnauthenticatedFindingsCanStillRelate(t *testing.T) {
	// Both "" -- an unauthenticated scan's own findings must still be
	// able to relate to each other; isolation only blocks a
	// NON-EMPTY-vs-different-non-empty (or non-empty-vs-empty)
	// mismatch, never empty-to-empty.
	a := newFinding("f1", "scan1", "sqli").endpoint("target.test", 80, "/x").build()
	b := newFinding("f2", "scan1", "reflected_xss").endpoint("target.test", 80, "/x").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationSameEndpoint); !ok {
		t.Error("two unauthenticated (empty IdentityContext) findings sharing an endpoint must still relate")
	}
}

func TestIdentityIsolation_AuthenticatedVsUnauthenticated_NeverRelate(t *testing.T) {
	auth := newFinding("f1", "scan1", "idor").identity("account-a").endpoint("target.test", 80, "/x").build()
	anon := newFinding("f2", "scan1", "idor").endpoint("target.test", 80, "/x").build() // "" identity
	res := Correlate([]models.Finding{auth, anon}, DefaultLimits())
	if len(res.Relations) != 0 {
		t.Fatalf("SECURITY: an authenticated finding related to an unauthenticated one: %+v", res.Relations)
	}
}

func TestScanIsolation_DifferentScanJobIDs_NeverRelate(t *testing.T) {
	a := newFinding("f1", "scan-A", "sqli").endpoint("target.test", 80, "/x").build()
	b := newFinding("f2", "scan-B", "sqli").endpoint("target.test", 80, "/x").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if len(res.Relations) != 0 {
		t.Fatalf("SECURITY: findings from DIFFERENT ScanJobIDs were related: %+v", res.Relations)
	}
}

func TestScanIsolation_EmptyScanID_NeverRelatesToAnything(t *testing.T) {
	a := newFinding("f1", "", "sqli").endpoint("target.test", 80, "/x").build()
	b := newFinding("f2", "", "sqli").endpoint("target.test", 80, "/x").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if len(res.Relations) != 0 {
		t.Fatalf("SECURITY: findings with an empty ScanID were related to each other: %+v", res.Relations)
	}
}

func TestHostIsolation_DifferentHosts_NeverMerged(t *testing.T) {
	a := newFinding("f1", "scan1", "sqli").endpoint("host-a.test", 80, "/x").param("id").build()
	b := newFinding("f2", "scan1", "sqli").endpoint("host-b.test", 80, "/x").param("id").build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	if _, ok := relationOfType(res.Relations, RelationSameEndpoint); ok {
		t.Error("SECURITY: two different hosts were treated as SAME_ENDPOINT")
	}
	// SAME_PARAMETER is legitimately still recognized (structural,
	// weak) -- this is the "same parameter on unrelated endpoints"
	// false-positive-resistance case, verified NOT to become a chain
	// in falsepositive_test.go.
}
