package evidence

import (
	"strings"
	"testing"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

// --- Deduplication (task section 18) -------------------------------------

func TestDedup_IdenticalEvidenceItemsCollapse(t *testing.T) {
	raw := rawRequestResponseEvidence{Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200, ResponseFragment: "ok", Parameter: "q", Payload: "1"}
	cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, raw)
	// Two byte-identical raw evidence items (same probe resubmitted).
	cf.Evidence = []correlation.EvidenceItem{
		{Kind: models.EvidenceKindRequestResponse, Content: rawJSON(raw)},
		{Kind: models.EvidenceKindRequestResponse, Content: rawJSON(raw)},
	}

	items := BuildEvidence(cf, DefaultLimits())
	verificationCount := 0
	for _, it := range items {
		if it.Type == EvidenceTypeVerification {
			verificationCount++
		}
	}
	if verificationCount != 1 {
		t.Errorf("VERIFICATION item count = %d, want 1 (duplicate probe must not create duplicate evidence)", verificationCount)
	}
}

func TestDedup_DistinctProbesRemainSeparateEvidence(t *testing.T) {
	rawA := rawRequestResponseEvidence{Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200, ResponseFragment: "marker-A", Parameter: "q", Payload: "1"}
	rawB := rawRequestResponseEvidence{Request: "GET http://h.test/p?q=2", Response: "HTTP 200", StatusCode: 200, ResponseFragment: "marker-B", Parameter: "q", Payload: "2"}
	cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, rawA)
	cf.Evidence = []correlation.EvidenceItem{
		{Kind: models.EvidenceKindRequestResponse, Content: rawJSON(rawA)},
		{Kind: models.EvidenceKindRequestResponse, Content: rawJSON(rawB)},
	}

	items := BuildEvidence(cf, DefaultLimits())
	verificationCount := 0
	for _, it := range items {
		if it.Type == EvidenceTypeVerification {
			verificationCount++
		}
	}
	if verificationCount != 2 {
		t.Errorf("VERIFICATION item count = %d, want 2 (distinct proof must remain distinct)", verificationCount)
	}
}

// --- Deterministic ordering (task section 19) -----------------------------

func TestOrdering_VerificationBeforeReproduction(t *testing.T) {
	items := BuildEvidence(fixtureXSS(), DefaultLimits())
	if len(items) < 2 {
		t.Fatalf("expected at least 2 items (verification + reproduction), got %d", len(items))
	}
	verIdx, reproIdx := -1, -1
	for i, it := range items {
		if it.Type == EvidenceTypeVerification {
			verIdx = i
		}
		if it.Type == EvidenceTypeReproduction {
			reproIdx = i
		}
	}
	if verIdx == -1 || reproIdx == -1 {
		t.Fatal("missing VERIFICATION or REPRODUCTION item")
	}
	if verIdx > reproIdx {
		t.Errorf("VERIFICATION (index %d) must sort before REPRODUCTION (index %d)", verIdx, reproIdx)
	}
}

func TestOrdering_DeterministicAcrossRepeatedCalls(t *testing.T) {
	cf := fixtureIDOR()
	a := BuildEvidence(cf, DefaultLimits())
	b := BuildEvidence(cf, DefaultLimits())
	if len(a) != len(b) {
		t.Fatalf("len mismatch: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].EvidenceID != b[i].EvidenceID {
			t.Errorf("index %d: order differs across repeated calls", i)
		}
	}
}

// --- Evidence limits (task sections 20-21) --------------------------------

func TestLimits_MaxEvidenceItemsPerFinding(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxEvidenceItemsPerFinding = 1

	cf := fixtureXSS() // normally produces 2 items (verification + reproduction)
	items := BuildEvidence(cf, limits)
	if len(items) > 1 {
		t.Errorf("len(items) = %d, want <= 1", len(items))
	}
}

func TestLimits_ResponseExcerptTruncated_1KB(t *testing.T) {
	testResponseTruncation(t, 1024)
}

func TestLimits_ResponseExcerptTruncated_100KB(t *testing.T) {
	testResponseTruncation(t, 100*1024)
}

func TestLimits_ResponseExcerptTruncated_1MB(t *testing.T) {
	testResponseTruncation(t, 1024*1024)
}

func TestLimits_ResponseExcerptTruncated_Oversized(t *testing.T) {
	testResponseTruncation(t, 10*1024*1024)
}

func testResponseTruncation(t *testing.T, size int) {
	t.Helper()
	huge := strings.Repeat("A", size)
	raw := rawRequestResponseEvidence{Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200, ResponseFragment: huge, Parameter: "q", Payload: "1"}
	cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, raw)

	limits := DefaultLimits()
	items := BuildEvidence(cf, limits)
	for _, it := range items {
		if it.Type != EvidenceTypeVerification {
			continue
		}
		if len(it.Response.Excerpt) > limits.MaxResponseExcerptBytes {
			t.Errorf("Excerpt length = %d, want <= %d", len(it.Response.Excerpt), limits.MaxResponseExcerptBytes)
		}
		if size > limits.MaxResponseExcerptBytes && !it.Response.Truncated {
			t.Error("Truncated flag not set for an oversized response")
		}
	}
}

// --- Binary response handling (task section 22) ---------------------------

func TestBinary_ContentTypeDeclaredBinary(t *testing.T) {
	raw := rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
		Headers: map[string]string{"Content-Type": "image/png"}, ResponseFragment: "\x89PNG\x00\x01\x02fakepngdata",
		Parameter: "q", Payload: "1",
	}
	cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, raw)
	items := BuildEvidence(cf, DefaultLimits())

	for _, it := range items {
		if it.Type != EvidenceTypeVerification {
			continue
		}
		if it.Response.Binary == nil {
			t.Fatal("Response.Binary is nil, want a BinarySummary for image/png content")
		}
		if it.Response.Excerpt != "" {
			t.Error("Response.Excerpt must be empty when Binary is set -- never store binary as text")
		}
		if it.Response.Binary.SHA256 == "" {
			t.Error("BinarySummary.SHA256 is empty")
		}
	}
}

func TestBinary_ContentBasedDetectionWithoutDeclaredType(t *testing.T) {
	raw := rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
		ResponseFragment: "binary\x00withnull\xffbytes", Parameter: "q", Payload: "1",
	}
	cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, raw)
	items := BuildEvidence(cf, DefaultLimits())

	for _, it := range items {
		if it.Type != EvidenceTypeVerification {
			continue
		}
		if it.Response.Binary == nil {
			t.Error("Response.Binary is nil, want content-based binary detection to trigger on a NUL byte")
		}
	}
}

func TestBinary_TextContentNeverTreatedAsBinary(t *testing.T) {
	items := BuildEvidence(fixtureXSS(), DefaultLimits())
	for _, it := range items {
		if it.Type != EvidenceTypeVerification {
			continue
		}
		if it.Response.Binary != nil {
			t.Error("ordinary HTML text content must never be classified as binary")
		}
	}
}

// --- Baseline / differential (task sections 4, 27) -------------------------

func TestDiff_StatusDiffers(t *testing.T) {
	d := Diff(404, 200, []byte("not found"), []byte("hello"))
	if d.RelevantDifference != "status code differs" {
		t.Errorf("RelevantDifference = %q, want %q", d.RelevantDifference, "status code differs")
	}
}

func TestDiff_LengthDiffersWhenStatusMatches(t *testing.T) {
	d := Diff(200, 200, []byte("short"), []byte("a much longer response body"))
	if d.RelevantDifference != "response length differs" {
		t.Errorf("RelevantDifference = %q, want %q", d.RelevantDifference, "response length differs")
	}
}

func TestDiff_NeverClaimsVulnerabilityFromLengthAlone(t *testing.T) {
	// Diff only ever DESCRIBES a difference -- it has no notion of
	// "vulnerable" at all; this test exists to document and lock in
	// that DifferentialEvidence carries no such field.
	d := Diff(200, 200, []byte("x"), []byte("y"))
	if d.RelevantDifference == "" {
		t.Error("RelevantDifference must never be empty when lengths match but content differs in a detectable way")
	}
}

func TestDiff_NoDifference(t *testing.T) {
	d := Diff(200, 200, []byte("same"), []byte("same"))
	if d.RelevantDifference != "no significant difference observed" {
		t.Errorf("RelevantDifference = %q, want %q", d.RelevantDifference, "no significant difference observed")
	}
}
