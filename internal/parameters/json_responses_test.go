package parameters

import (
	"testing"

	"sakanner/internal/crawler"
	"sakanner/internal/endpoints"
)

func TestNormalizeJSONResponses_TopLevelFields(t *testing.T) {
	pages := []crawler.Page{{
		URL:          "https://example.test/api/data",
		ContentType:  "application/json",
		ResponseBody: []byte(`{"user":"alice","user_id":1001}`),
	}}
	res := NormalizeJSONResponses(pages, Limits{})
	if len(res.Candidates) != 2 {
		t.Fatalf("got %d candidates, want 2: %+v", len(res.Candidates), res.Candidates)
	}
	for _, c := range res.Candidates {
		if c.Provenance != ProvenanceResponseField {
			t.Errorf("Provenance = %q, want %q for a candidate discovered from a response body", c.Provenance, ProvenanceResponseField)
		}
		if c.Source != SourceJSONResponse {
			t.Errorf("Source = %q, want %q", c.Source, SourceJSONResponse)
		}
		if c.EndpointMethod != "GET" || c.EndpointSource != endpoints.SourceCrawl {
			t.Errorf("unexpected endpoint identity: %+v", c)
		}
		if c.EndpointPath != endpoints.PathOf("https://example.test/api/data") {
			t.Errorf("EndpointPath = %q", c.EndpointPath)
		}
	}
}

func TestNormalizeJSONResponses_NonJSONContentType_Ignored(t *testing.T) {
	pages := []crawler.Page{{
		URL:          "https://example.test/page.html",
		ContentType:  "text/html",
		ResponseBody: []byte(`{"a":"b"}`), // even if somehow present, must never be parsed
	}}
	res := NormalizeJSONResponses(pages, Limits{})
	if len(res.Candidates) != 0 {
		t.Errorf("got %d candidates for a non-JSON content type, want 0: %+v", len(res.Candidates), res.Candidates)
	}
}

func TestNormalizeJSONResponses_EmptyBody_Ignored(t *testing.T) {
	pages := []crawler.Page{{
		URL:         "https://example.test/api/empty",
		ContentType: "application/json",
		// ResponseBody intentionally nil -- e.g. a JSON-typed response
		// the crawler never actually captured for some reason.
	}}
	res := NormalizeJSONResponses(pages, Limits{})
	if len(res.Candidates) != 0 || len(res.Warnings) != 0 {
		t.Errorf("got %+v, want an empty result for a page with no captured body", res)
	}
}

func TestNormalizeJSONResponses_MalformedJSON_WarningNoCrash(t *testing.T) {
	pages := []crawler.Page{{
		URL:          "https://example.test/api/broken",
		ContentType:  "application/json",
		ResponseBody: []byte(`{"broken": `),
	}}
	res := NormalizeJSONResponses(pages, Limits{})
	if len(res.Candidates) != 0 {
		t.Errorf("got candidates from malformed JSON, want none: %+v", res.Candidates)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning for malformed JSON")
	}
}

func TestNormalizeJSONResponses_NestedAndArray(t *testing.T) {
	pages := []crawler.Page{{
		URL:          "https://example.test/api/nested",
		ContentType:  "application/json; charset=utf-8",
		ResponseBody: []byte(`{"user":{"id":1,"profile":{"email":"a@b.test"}},"items":[{"id":1},{"id":2}]}`),
	}}
	res := NormalizeJSONResponses(pages, Limits{})
	names := map[string]bool{}
	for _, c := range res.Candidates {
		names[c.Name] = true
	}
	if !names["user.id"] || !names["user.profile.email"] {
		t.Errorf("expected nested dot-path candidates, got %+v", res.Candidates)
	}
	if !names["items"] {
		t.Errorf("expected the array field itself as one candidate, got %+v", res.Candidates)
	}
	if names["items.id"] {
		t.Error("array elements must not be individually discovered")
	}
}

func TestNormalizeJSONResponses_MultiplePages_CorrelateToOwnEndpoint(t *testing.T) {
	pages := []crawler.Page{
		{URL: "https://example.test/api/a", ContentType: "application/json", ResponseBody: []byte(`{"x":1}`)},
		{URL: "https://example.test/api/b", ContentType: "application/json", ResponseBody: []byte(`{"y":2}`)},
	}
	res := NormalizeJSONResponses(pages, Limits{})
	byEndpoint := map[string][]string{}
	for _, c := range res.Candidates {
		byEndpoint[c.EndpointPath] = append(byEndpoint[c.EndpointPath], c.Name)
	}
	if len(byEndpoint["/api/a"]) != 1 || byEndpoint["/api/a"][0] != "x" {
		t.Errorf("/api/a candidates = %v", byEndpoint["/api/a"])
	}
	if len(byEndpoint["/api/b"]) != 1 || byEndpoint["/api/b"][0] != "y" {
		t.Errorf("/api/b candidates = %v", byEndpoint["/api/b"])
	}
}

func TestNormalizeJSONResponses_Deterministic(t *testing.T) {
	pages := []crawler.Page{{
		URL:          "https://example.test/api/data",
		ContentType:  "application/json",
		ResponseBody: []byte(`{"z":1,"a":2,"nested":{"y":1,"b":2}}`),
	}}
	first := NormalizeJSONResponses(pages, Limits{})
	for i := 0; i < 10; i++ {
		got := NormalizeJSONResponses(pages, Limits{})
		if len(got.Candidates) != len(first.Candidates) {
			t.Fatalf("iteration %d: candidate count changed", i)
		}
		for j := range got.Candidates {
			if got.Candidates[j] != first.Candidates[j] {
				t.Fatalf("iteration %d: candidate %d differs: %+v vs %+v", i, j, got.Candidates[j], first.Candidates[j])
			}
		}
	}
}

func TestNormalizeJSONResponses_SensitiveFieldRedacted(t *testing.T) {
	pages := []crawler.Page{{
		URL:          "https://example.test/api/session",
		ContentType:  "application/json",
		ResponseBody: []byte(`{"token":"abc123secretvalue","user":"alice"}`),
	}}
	res := NormalizeJSONResponses(pages, Limits{})
	for _, c := range res.Candidates {
		if c.Name == "token" && c.Value == "abc123secretvalue" {
			t.Fatal("SECURITY: sensitive response field value was not redacted")
		}
	}
}
