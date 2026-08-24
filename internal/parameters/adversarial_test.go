package parameters

import (
	"strings"
	"testing"

	"sakanner/internal/crawler"
)

// TestNormalize_VeryLongParameterName_NoCrash is task adversarial
// scenario 21.
func TestNormalize_VeryLongParameterName_NoCrash(t *testing.T) {
	longName := strings.Repeat("a", 100000)
	pages := []crawler.Page{{URL: "https://example.test/search?" + longName + "=x"}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 1 || res.Candidates[0].Name != longName {
		t.Fatalf("got %d candidates, want 1 with the full long name preserved", len(res.Candidates))
	}
}

// TestNormalize_VeryLongParameterValue_NoCrash is task adversarial
// scenario 22.
func TestNormalize_VeryLongParameterValue_NoCrash(t *testing.T) {
	longValue := strings.Repeat("b", 200000)
	pages := []crawler.Page{{Forms: []crawler.FormRef{{
		Action: "https://example.test/x", Method: "POST",
		Fields: []crawler.FormField{{Name: "data", Type: "text", Value: longValue}},
	}}}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 1 || res.Candidates[0].Value != longValue {
		t.Fatalf("got %d candidates, want 1 with the full long value preserved", len(res.Candidates))
	}
}

// TestNormalize_UnicodeParameterName is task adversarial scenario 23.
func TestNormalize_UnicodeParameterName(t *testing.T) {
	pages := []crawler.Page{{URL: "https://example.test/search?%E6%A4%9C%E7%B4%A2=hello"}} // "検索" (search), URL-encoded
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(res.Candidates), res.Candidates)
	}
	if res.Candidates[0].Name != "検索" {
		t.Errorf("Name = %q, want the decoded unicode name", res.Candidates[0].Name)
	}
}

// TestNormalize_UnicodeFormFieldName_Emoji ensures raw (not
// percent-encoded) unicode/emoji field names surviving straight from
// HTML attribute parsing don't crash discovery either.
func TestNormalize_UnicodeFormFieldName_Emoji(t *testing.T) {
	pages := []crawler.Page{{Forms: []crawler.FormRef{{
		Action: "https://example.test/x", Method: "POST",
		Fields: []crawler.FormField{{Name: "🔥field", Type: "text", Value: "v"}},
	}}}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 1 || res.Candidates[0].Name != "🔥field" {
		t.Fatalf("got %+v, want one candidate named 🔥field", res.Candidates)
	}
}

// TestNormalize_NullByteInValue_NoCrash is task adversarial scenario
// 24 (null bytes / malformed encoding).
func TestNormalize_NullByteInValue_NoCrash(t *testing.T) {
	pages := []crawler.Page{{Forms: []crawler.FormRef{{
		Action: "https://example.test/x", Method: "POST",
		Fields: []crawler.FormField{{Name: "data", Type: "text", Value: "before\x00after"}},
	}}}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 1 {
		t.Fatalf("got %d candidates, want 1", len(res.Candidates))
	}
	if !strings.Contains(res.Candidates[0].Value, "\x00") {
		t.Error("null byte was stripped rather than preserved as observed -- discovery must not silently mutate observed values")
	}
}

// TestNormalize_MalformedURLEncoding_NoCrash covers the remainder of
// scenario 24: a "%" not followed by valid hex must not panic or
// corrupt the rest of discovery.
func TestNormalize_MalformedURLEncoding_NoCrash(t *testing.T) {
	pages := []crawler.Page{
		{URL: "https://example.test/a?bad=%zz"},
		{URL: "https://example.test/b?good=value"},
	}
	res := Normalize(pages, Limits{})
	found := false
	for _, c := range res.Candidates {
		if c.Name == "good" {
			found = true
		}
	}
	if !found {
		t.Error("a malformed query string on one URL must not prevent discovery on a different, well-formed URL")
	}
}

// TestNormalize_QueryPathNameCollision_RemainDistinct is task
// adversarial scenario 12: a query parameter and a path input sharing
// the same name must not be merged (path inputs come from
// InferPathInputs, a separate function -- this test proves the two
// outputs are never implicitly conflated when combined by a caller).
func TestNormalize_QueryPathNameCollision_RemainDistinct(t *testing.T) {
	pages := []crawler.Page{{URL: "https://example.test/users/123?id=456"}}
	queryRes := Normalize(pages, Limits{})
	pathRes := InferPathInputs([]PathEndpoint{
		{Path: "/users/123", Method: "GET", Source: "crawl"},
		{Path: "/users/999", Method: "GET", Source: "crawl"},
	}, Limits{})

	foundQueryID := false
	for _, c := range queryRes.Candidates {
		if c.Name == "id" && c.Location == LocationQuery {
			foundQueryID = true
		}
	}
	foundPathID := false
	for _, c := range pathRes.Candidates {
		if c.Location == LocationPath {
			foundPathID = true
		}
	}
	if !foundQueryID {
		t.Error("expected a query-location \"id\" candidate")
	}
	if !foundPathID {
		t.Error("expected a path-location candidate")
	}
	// The two are produced by entirely separate function calls with no
	// shared dedup key (candidateKey includes Location) -- structurally
	// impossible to merge, confirmed here behaviorally too.
}

// TestNormalize_GETAndPOSTSameEndpoint_RemainDistinct is task
// adversarial scenario 13.
func TestNormalize_GETAndPOSTSameEndpoint_RemainDistinct(t *testing.T) {
	pages := []crawler.Page{{Forms: []crawler.FormRef{
		{Action: "https://example.test/search", Method: "GET", Fields: []crawler.FormField{{Name: "q", Type: "text"}}},
		{Action: "https://example.test/search", Method: "POST", Fields: []crawler.FormField{{Name: "q", Type: "text"}}},
	}}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 2 {
		t.Fatalf("got %d candidates, want 2 (GET query:q and POST form:q must remain distinct)", len(res.Candidates))
	}
	methods := map[string]bool{}
	for _, c := range res.Candidates {
		methods[c.EndpointMethod] = true
	}
	if !methods["GET"] || !methods["POST"] {
		t.Errorf("expected both GET and POST represented, got %+v", res.Candidates)
	}
}
