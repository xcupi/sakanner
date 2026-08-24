package parameters

import "testing"

func TestInferPathInputs_VariableLastSegment_Numeric(t *testing.T) {
	eps := []PathEndpoint{
		{Path: "/users/123", Method: "GET", Source: "crawl"},
		{Path: "/users/456", Method: "GET", Source: "crawl"},
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 2 {
		t.Fatalf("got %d candidates, want 2: %+v", len(out), out)
	}
	for _, c := range out {
		if c.Location != LocationPath {
			t.Errorf("Location = %q, want path", c.Location)
		}
		if c.Name != "user_id" {
			t.Errorf("Name = %q, want user_id", c.Name)
		}
		if c.Source != SourcePathInference {
			t.Errorf("Source = %q, want %q", c.Source, SourcePathInference)
		}
	}
}

func TestInferPathInputs_StaticPath_NoVariation_NoInput(t *testing.T) {
	eps := []PathEndpoint{
		{Path: "/about", Method: "GET", Source: "crawl"},
		{Path: "/about", Method: "GET", Source: "link"}, // different source, same value -- still no variation observed
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 0 {
		t.Errorf("got %+v, want none (task: do not blindly treat every static segment as a parameter)", out)
	}
}

func TestInferPathInputs_SingleObservation_NoEvidence_NoInput(t *testing.T) {
	eps := []PathEndpoint{{Path: "/users/123", Method: "GET", Source: "crawl"}}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 0 {
		t.Errorf("got %+v, want none (a single observation is not reliable evidence of variability)", out)
	}
}

func TestInferPathInputs_DifferentResourceTypes_NotConflated(t *testing.T) {
	// /users/123 and /products/456 share a segment count but are
	// unrelated resource types -- must NOT be treated as the same
	// varying-position group (their "preceding" segments differ, so
	// they land in different prefix groups automatically).
	eps := []PathEndpoint{
		{Path: "/users/123", Method: "GET", Source: "crawl"},
		{Path: "/products/456", Method: "GET", Source: "crawl"},
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 0 {
		t.Errorf("got %+v, want none (each has only one observation within its own prefix group)", out)
	}
}

func TestInferPathInputs_NonNumericVariation_UsesValueSuffix(t *testing.T) {
	eps := []PathEndpoint{
		{Path: "/blog/hello-world", Method: "GET", Source: "crawl"},
		{Path: "/blog/second-post", Method: "GET", Source: "crawl"},
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(out), out)
	}
	if out[0].Name != "blog_value" {
		t.Errorf("Name = %q, want blog_value", out[0].Name)
	}
}

func TestInferPathInputs_RootSinglePath_NoPrecedingSegment(t *testing.T) {
	eps := []PathEndpoint{
		{Path: "/123", Method: "GET", Source: "crawl"},
		{Path: "/456", Method: "GET", Source: "crawl"},
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(out), out)
	}
	if out[0].Name != "segment_id" {
		t.Errorf("Name = %q, want segment_id", out[0].Name)
	}
}

func TestInferPathInputs_DifferentMethods_NotConflated(t *testing.T) {
	eps := []PathEndpoint{
		{Path: "/users/123", Method: "GET", Source: "crawl"},
		{Path: "/users/456", Method: "POST", Source: "form"},
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 0 {
		t.Errorf("got %+v, want none -- each method has only one observation of its own", out)
	}
}

func TestInferPathInputs_MiddleSegmentVariation_NotInferred(t *testing.T) {
	// /users/123/edit and /users/456/profile: the LAST segment differs
	// too (edit vs profile) so no group of >=2 agreeing-except-last
	// paths exists -- this deliberately conservative design (see
	// path.go's doc comment) does not attempt to infer that position 1
	// (123 vs 456) is the variable one.
	eps := []PathEndpoint{
		{Path: "/users/123/edit", Method: "GET", Source: "crawl"},
		{Path: "/users/456/profile", Method: "GET", Source: "crawl"},
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 0 {
		t.Errorf("got %+v, want none (middle-segment variation is out of scope)", out)
	}
}

func TestInferPathInputs_ThreeOrMoreObservations_AllIncluded(t *testing.T) {
	eps := []PathEndpoint{
		{Path: "/users/1", Method: "GET", Source: "crawl"},
		{Path: "/users/2", Method: "GET", Source: "crawl"},
		{Path: "/users/3", Method: "GET", Source: "crawl"},
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 3 {
		t.Fatalf("got %d, want 3: %+v", len(out), out)
	}
}

func TestInferPathInputs_Deterministic(t *testing.T) {
	eps := []PathEndpoint{
		{Path: "/users/123", Method: "GET", Source: "crawl"},
		{Path: "/users/456", Method: "GET", Source: "crawl"},
		{Path: "/orders/1", Method: "GET", Source: "crawl"},
		{Path: "/orders/2", Method: "GET", Source: "crawl"},
	}
	first := InferPathInputs(eps, Limits{}).Candidates
	for i := 0; i < 20; i++ {
		got := InferPathInputs(eps, Limits{}).Candidates
		if len(got) != len(first) {
			t.Fatalf("iteration %d: length changed", i)
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("iteration %d: element %d differs: %+v vs %+v", i, j, got[j], first[j])
			}
		}
	}
}

func TestInferPathInputs_Empty_NoCandidates(t *testing.T) {
	if out := InferPathInputs(nil, Limits{}).Candidates; len(out) != 0 {
		t.Errorf("got %+v, want none", out)
	}
}

// ---------------------------------------------------------------------
// Phase 3.23: version segments, provenance, PathSegmentIndex, limits
// ---------------------------------------------------------------------

func TestInferPathInputs_VersionSegment_NeverInferred(t *testing.T) {
	eps := []PathEndpoint{
		{Path: "/api/v1", Method: "GET", Source: "crawl"},
		{Path: "/api/v2", Method: "GET", Source: "crawl"},
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 0 {
		t.Errorf("got %+v, want none (v1/v2 is a version segment, not application data)", out)
	}
}

func TestInferPathInputs_VersionShapedButMixedWithNonVersion_NeitherLooksLikeAnIdentifier(t *testing.T) {
	// "v1" and "abc" are NOT both version-shaped, so the version
	// exclusion alone would not fire here -- but neither is
	// identifier-shaped either (see
	// TestInferPathInputs_DistinctStaticSiblingEndpoints_NeverConflated
	// for why that gate exists): "abc" has no digit, hyphen, or
	// underscore, so this group is correctly rejected by the SAME
	// conservative gate, for the same reason.
	eps := []PathEndpoint{
		{Path: "/api/v1", Method: "GET", Source: "crawl"},
		{Path: "/api/abc", Method: "GET", Source: "crawl"},
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 0 {
		t.Errorf("got %+v, want none (neither \"v1\" nor \"abc\" alone is reliable evidence of a variable identifier)", out)
	}
}

// TestInferPathInputs_DistinctStaticSiblingEndpoints_NeverConflated is
// a regression test for a real defect discovered during Phase 3.23
// development (docs/phase-3-23-path-parameters.md section 1.5): the
// "last segment differs" evidence rule, applied without this gate,
// cannot distinguish a genuinely templated resource (/api/{id}, many
// instances of ONE resource) from several DIFFERENT, statically-named
// sibling endpoints that merely share a common parent prefix -- an
// extremely common real-world REST API shape. /api/nested, /api/items,
// and /api/malformed (three real, unrelated endpoints from this lab's
// own Phase 3.18 fixtures) satisfy the OLD evidence rule (same method,
// same prefix "api", 3 distinct last-segment values) and were
// incorrectly inferred as a fake "api_value" path parameter --
// discovered when TestPhase3_18_FullCrawl_JSONAndAPIDiscovery started
// failing the moment path inference was wired into the live pipeline.
func TestInferPathInputs_DistinctStaticSiblingEndpoints_NeverConflated(t *testing.T) {
	eps := []PathEndpoint{
		{Path: "/api/nested", Method: "GET", Source: "crawl"},
		{Path: "/api/items", Method: "GET", Source: "crawl"},
		{Path: "/api/malformed", Method: "GET", Source: "crawl"},
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 0 {
		t.Errorf("got %+v, want none (nested/items/malformed are three distinct, statically-named endpoints, not instances of one templated resource)", out)
	}
}

func TestInferPathInputs_Candidate_ProvenanceAndSegmentIndex(t *testing.T) {
	eps := []PathEndpoint{
		{Path: "/users/123", Method: "GET", Source: "crawl"},
		{Path: "/users/456", Method: "GET", Source: "crawl"},
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 2 {
		t.Fatalf("got %d, want 2", len(out))
	}
	for _, c := range out {
		if c.Provenance != ProvenanceRequestInput {
			t.Errorf("Provenance = %q, want %q", c.Provenance, ProvenanceRequestInput)
		}
		if c.PathSegmentIndex != 1 {
			t.Errorf("PathSegmentIndex = %d, want 1 (the last segment of /users/123)", c.PathSegmentIndex)
		}
	}
}

func TestInferPathInputs_NestedPath_SegmentIndexCorrect(t *testing.T) {
	eps := []PathEndpoint{
		{Path: "/api/v1/orders/789/items/12", Method: "GET", Source: "crawl"},
		{Path: "/api/v1/orders/789/items/34", Method: "GET", Source: "crawl"},
	}
	out := InferPathInputs(eps, Limits{}).Candidates
	if len(out) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(out), out)
	}
	// /api/v1/orders/789/items/12 -> segments [api v1 orders 789 items 12], last index 5.
	for _, c := range out {
		if c.PathSegmentIndex != 5 {
			t.Errorf("PathSegmentIndex = %d, want 5", c.PathSegmentIndex)
		}
	}
}

func TestInferPathInputs_MaxPathSegments_DeepPathSkipped(t *testing.T) {
	eps := []PathEndpoint{
		{Path: "/a/b/c/d/e/f/1", Method: "GET", Source: "crawl"},
		{Path: "/a/b/c/d/e/f/2", Method: "GET", Source: "crawl"},
	}
	out := InferPathInputs(eps, Limits{MaxPathSegments: 5}).Candidates
	if len(out) != 0 {
		t.Errorf("got %+v, want none (7 segments exceeds MaxPathSegments=5)", out)
	}
	// The same endpoints, under the default (generous) limit, DO
	// produce candidates -- proving the cap is what excluded them
	// above, not some other rule.
	outDefault := InferPathInputs(eps, Limits{}).Candidates
	if len(outDefault) != 2 {
		t.Errorf("got %d under the default limit, want 2", len(outDefault))
	}
}

func TestInferPathInputs_MaxTotalInputs_Capped(t *testing.T) {
	var eps []PathEndpoint
	for i := 0; i < 10; i++ {
		eps = append(eps, PathEndpoint{Path: "/users/" + string(rune('0'+i)), Method: "GET", Source: "crawl"})
	}
	res := InferPathInputs(eps, Limits{MaxTotalInputs: 3})
	if len(res.Candidates) != 3 {
		t.Errorf("got %d candidates, want 3 (capped by MaxTotalInputs)", len(res.Candidates))
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning when the total input limit is reached")
	}
}
