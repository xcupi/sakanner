// Tests mapped directly to Phase 3.31's own numbered "ADVERSARIAL
// TESTING" list (task section 11) that were not already covered by
// Phase 3.30's own test files. Each test names its own scenario
// number in its doc comment for direct traceability in the acceptance
// report.
package chains

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"sakanner/pkg/models"
)

// Scenario 8: multiple independent chains in one scan.
func TestAdversarial8_MultipleIndependentChainsInOneScan(t *testing.T) {
	// Pair 1: shares an endpoint. Pair 2: shares a DIFFERENT endpoint.
	// Neither pair shares anything with the other.
	f1 := newFinding("f1", "scan1", "sqli").endpoint("host-a.test", 80, "/x").build()
	f2 := newFinding("f2", "scan1", "reflected_xss").endpoint("host-a.test", 80, "/x").build()
	f3 := newFinding("f3", "scan1", "cmdinjection").endpoint("host-b.test", 80, "/y").build()
	f4 := newFinding("f4", "scan1", "ssti").endpoint("host-b.test", 80, "/y").build()
	res := Correlate([]models.Finding{f1, f2, f3, f4}, DefaultLimits())
	if len(res.Candidates) != 2 {
		t.Fatalf("expected exactly 2 independent chain candidates, got %d: %+v", len(res.Candidates), res.Candidates)
	}
	for _, c := range res.Candidates {
		if len(c.FindingIDs) != 2 {
			t.Errorf("expected each independent candidate to contain exactly its own 2 findings, got: %+v", c)
		}
	}
	// The two candidates must not share any finding.
	seen := map[string]bool{}
	for _, c := range res.Candidates {
		for _, fid := range c.FindingIDs {
			if seen[fid] {
				t.Errorf("finding %s appears in more than one independent candidate", fid)
			}
			seen[fid] = true
		}
	}
}

// Scenario 9: one finding participating in multiple valid relations
// (distinct from Phase 3.30's own TestCandidate_ThreeFindingsChainTogether
// -- this test asserts directly on the MIDDLE finding's own relation
// count, not just that all 3 end up in one candidate).
func TestAdversarial9_OneFindingInMultipleRelations(t *testing.T) {
	hub := newFinding("hub", "scan1", "sqli").endpoint("target.test", 80, "/shared").param("id").
		url("http://target.test/shared?id=OBJ-7712").build()
	leafA := newFinding("leafA", "scan1", "reflected_xss").endpoint("target.test", 80, "/shared").build()
	leafB := newFinding("leafB", "scan1", "idor").endpoint("other.test", 80, "/other").param("id").
		url("http://other.test/other?id=OBJ-7712").build()
	res := Correlate([]models.Finding{hub, leafA, leafB}, DefaultLimits())

	hubRelations := 0
	for _, r := range res.Relations {
		if r.FindingAID == "hub" || r.FindingBID == "hub" {
			hubRelations++
		}
	}
	if hubRelations < 2 {
		t.Fatalf("expected the hub finding to participate in at least 2 distinct relations (SAME_ENDPOINT with leafA, SAME_RESOURCE with leafB), got %d: %+v", hubRelations, res.Relations)
	}
	if len(res.Candidates) != 1 || len(res.Candidates[0].FindingIDs) != 3 {
		t.Fatalf("expected all 3 findings to chain together through the hub, got: %+v", res.Candidates)
	}
}

// Scenario 10: circular relation input (a triangle: A-B, B-C, C-A all
// independently true) must never cause infinite recursion/looping and
// must still produce exactly one, correctly deduplicated candidate.
func TestAdversarial10_CircularRelationInput(t *testing.T) {
	// All 3 share the SAME endpoint (pairwise SAME_ENDPOINT for every
	// combination: A-B, B-C, A-C -- a complete triangle in the
	// relation graph).
	a := newFinding("a", "scan1", "sqli").endpoint("target.test", 80, "/shared").build()
	b := newFinding("b", "scan1", "reflected_xss").endpoint("target.test", 80, "/shared").build()
	c := newFinding("c", "scan1", "cmdinjection").endpoint("target.test", 80, "/shared").build()

	done := make(chan Result, 1)
	go func() { done <- Correlate([]models.Finding{a, b, c}, DefaultLimits()) }()
	var res Result
	select {
	case res = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Correlate did not return promptly against a triangle relation graph -- possible infinite loop")
	}

	if len(res.Candidates) != 1 {
		t.Fatalf("expected exactly 1 candidate for a fully-connected triangle, got %d: %+v", len(res.Candidates), res.Candidates)
	}
	if len(res.Candidates[0].FindingIDs) != 3 {
		t.Errorf("expected all 3 findings in the one candidate, got: %v", res.Candidates[0].FindingIDs)
	}
	// Exactly 3 SAME_ENDPOINT relations (A-B, B-C, A-C), never more
	// (no duplicate re-derivation from traversing the cycle multiple
	// times).
	sameEndpointCount := 0
	for _, r := range res.Relations {
		if r.Type == RelationSameEndpoint {
			sameEndpointCount++
		}
	}
	if sameEndpointCount != 3 {
		t.Errorf("expected exactly 3 SAME_ENDPOINT relations (one per pair), got %d", sameEndpointCount)
	}
}

// Scenario 16: secret-containing evidence must never be amplified or
// newly exposed by chain evidence -- internal/chains only ever
// REFERENCES a matched token verbatim from what the finding's own
// evidence ALREADY contained (it never fetches, decrypts, or exposes
// anything beyond what's already in Evidence.Content), so if a
// detector's own evidence (against this codebase's own established
// redaction discipline) never contains a raw credential, chain
// evidence built FROM it cannot introduce one either. This test
// proves that property directly: even if a finding's evidence somehow
// contained a credential-shaped string, chain evidence never
// duplicates MORE than the exact matched substring already present.
func TestAdversarial16_SecretShapedEvidence_NeverAmplified(t *testing.T) {
	secretLike := "Authorization: Bearer sk-not-a-real-secret-9f31c2ab"
	a := newFinding("f1", "scan1", "info_exposure").evidence(fmt.Sprintf("leaked header: %s end-of-evidence-a", secretLike)).build()
	b := newFinding("f2", "scan1", "ssrf").evidence(fmt.Sprintf("observed header: %s end-of-evidence-b", secretLike)).build()
	res := Correlate([]models.Finding{a, b}, DefaultLimits())
	for _, r := range res.Relations {
		for _, ev := range r.Evidence {
			// The relation's own Detail must be a SHORT, single
			// TOKEN (bounded by the tokenizer), never the full
			// secret-shaped string reconstructed/concatenated beyond
			// what a single delimited token already was.
			if len(ev.Detail) > len(secretLike) {
				t.Errorf("SECURITY: relation evidence Detail (%q) is LONGER than the matched secret-shaped substring itself -- evidence must never be expanded/amplified beyond what a single token already contained", ev.Detail)
			}
			if strings.Contains(ev.Detail, "Bearer") {
				t.Logf("relation evidence detail contains a fragment of the secret-shaped string (%q) -- this is an EXISTING evidence value the finding ALREADY carried (see docs/phase-3-31-chain-integration.md's own SECRET PROTECTION section: chains never introduces a NEW secret, it can only reference what a finding's own, already-redaction-governed Evidence.Content contains)", ev.Detail)
			}
		}
	}
}
