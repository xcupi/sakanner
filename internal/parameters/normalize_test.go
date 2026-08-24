package parameters

import (
	"fmt"
	"reflect"
	"testing"

	"sakanner/internal/crawler"
	"sakanner/internal/endpoints"
)

func candidateNames(cs []Candidate) []string {
	var names []string
	for _, c := range cs {
		names = append(names, string(c.Location)+":"+c.Name)
	}
	return names
}

// --- Query discovery -----------------------------------------------------

func TestNormalize_QueryParameters_FromPageURL(t *testing.T) {
	pages := []crawler.Page{{URL: "https://example.test/search?q=test&page=2"}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 2 {
		t.Fatalf("got %d candidates, want 2: %+v", len(res.Candidates), res.Candidates)
	}
	names := candidateNames(res.Candidates)
	want := []string{"query:page", "query:q"} // sorted by name
	if !reflect.DeepEqual(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
	for _, c := range res.Candidates {
		if c.Location != LocationQuery || c.EndpointMethod != "GET" || c.Source != SourceURLQuery {
			t.Errorf("unexpected candidate shape: %+v", c)
		}
	}
}

func TestNormalize_QueryParameters_FromLinks(t *testing.T) {
	pages := []crawler.Page{{
		URL:   "https://example.test/",
		Links: []string{"https://example.test/product?id=42"},
	}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 1 || res.Candidates[0].Name != "id" {
		t.Fatalf("got %+v, want one candidate named id", res.Candidates)
	}
	if res.Candidates[0].EndpointPath != endpoints.PathOf("https://example.test/product?id=42") {
		t.Errorf("EndpointPath = %q, does not match endpoints.PathOf", res.Candidates[0].EndpointPath)
	}
}

func TestNormalize_DuplicateQueryParameter_OnSameURL_OneCandidateFirstValueKept(t *testing.T) {
	// url.ParseQuery collapses repeated ?q=a&q=b into Values{"q": ["a","b"]}
	// -- Normalize must not crash and must keep exactly one candidate,
	// using the first observed value (task's "duplicated parameters").
	pages := []crawler.Page{{URL: "https://example.test/search?q=a&q=b"}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(res.Candidates), res.Candidates)
	}
	if res.Candidates[0].Value != "a" {
		t.Errorf("Value = %q, want %q (first observed)", res.Candidates[0].Value, "a")
	}
}

func TestNormalize_EmptyQueryValue_StillDiscovered(t *testing.T) {
	pages := []crawler.Page{{URL: "https://example.test/search?q="}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 1 || res.Candidates[0].Value != "" {
		t.Fatalf("got %+v, want one candidate with empty value", res.Candidates)
	}
}

func TestNormalize_URLEncodedQueryNameAndValue(t *testing.T) {
	pages := []crawler.Page{{URL: "https://example.test/search?us%65r%20name=hello%20world"}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 1 {
		t.Fatalf("got %d candidates, want 1: %+v", len(res.Candidates), res.Candidates)
	}
	if res.Candidates[0].Name != "user name" || res.Candidates[0].Value != "hello world" {
		t.Errorf("got name=%q value=%q, want decoded \"user name\"/\"hello world\"", res.Candidates[0].Name, res.Candidates[0].Value)
	}
}

func TestNormalize_MalformedQueryString_NoCrash(t *testing.T) {
	pages := []crawler.Page{{URL: "https://example.test/search?%zz=bad"}}
	res := Normalize(pages, Limits{})
	if res.Candidates != nil {
		t.Errorf("malformed query string produced candidates: %+v, want none", res.Candidates)
	}
}

func TestNormalize_NoQueryString_NoCandidates(t *testing.T) {
	pages := []crawler.Page{{URL: "https://example.test/about"}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 0 {
		t.Errorf("got %+v, want none", res.Candidates)
	}
}

// --- Form discovery --------------------------------------------------------

func TestNormalize_GETForm_FieldsUseQueryLocation(t *testing.T) {
	pages := []crawler.Page{{
		Forms: []crawler.FormRef{{
			Action: "https://example.test/search", Method: "GET",
			Fields: []crawler.FormField{{Name: "q", Type: "text"}},
		}},
	}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 1 {
		t.Fatalf("got %+v", res.Candidates)
	}
	c := res.Candidates[0]
	if c.Location != LocationQuery {
		t.Errorf("GET form field Location = %q, want query", c.Location)
	}
	if c.EndpointSource != endpoints.SourceForm {
		t.Errorf("EndpointSource = %q, want %q", c.EndpointSource, endpoints.SourceForm)
	}
	if c.ContentType != "" {
		t.Errorf("GET form field ContentType = %q, want empty", c.ContentType)
	}
}

func TestNormalize_POSTForm_FieldsUseFormLocation(t *testing.T) {
	pages := []crawler.Page{{
		Forms: []crawler.FormRef{{
			Action: "https://example.test/login", Method: "POST",
			Fields: []crawler.FormField{
				{Name: "username", Type: "text", Value: "alice"},
				{Name: "password", Type: "password", Value: "hunter2"},
			},
		}},
	}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 2 {
		t.Fatalf("got %+v", res.Candidates)
	}
	byName := map[string]Candidate{}
	for _, c := range res.Candidates {
		byName[c.Name] = c
	}
	if byName["username"].Location != LocationForm || byName["username"].Value != "alice" {
		t.Errorf("username candidate = %+v", byName["username"])
	}
	if byName["username"].ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("ContentType = %q, want form-urlencoded", byName["username"].ContentType)
	}
	// password is a sensitive field name -- its VALUE must be redacted,
	// never persisted verbatim, even though it's only an
	// already-observed default value.
	if byName["password"].Value == "hunter2" {
		t.Error("password field value was NOT redacted")
	}
}

func TestNormalize_HiddenTextareaSelectFields_AllDiscovered(t *testing.T) {
	pages := []crawler.Page{{
		Forms: []crawler.FormRef{{
			Action: "https://example.test/comment", Method: "POST",
			Fields: []crawler.FormField{
				{Name: "csrf", Type: "hidden", Value: "tok"},
				{Name: "body", Type: "textarea", Value: "hello"},
				{Name: "category", Type: "select", Value: "general"},
			},
		}},
	}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 3 {
		t.Fatalf("got %d candidates, want 3: %+v", len(res.Candidates), res.Candidates)
	}
	// Phase 3.15 regression: "csrf" is a sensitive field name (see
	// internal/evidence's blocklist) -- its observed value must be
	// redacted exactly like "password" already is, never persisted
	// verbatim. This field was present in this test since before Phase
	// 3.15 but its value was never actually checked, so the gap this
	// closes went unnoticed until authenticated-crawling development
	// surfaced it.
	byName := map[string]Candidate{}
	for _, c := range res.Candidates {
		byName[c.Name] = c
	}
	if byName["csrf"].Value == "tok" {
		t.Error("csrf field value was NOT redacted")
	}
	// Phase 3.21: FieldType preserves the raw HTML type attribute so a
	// caller can derive models.Parameter.Hidden without a new Location/
	// Classification value.
	if byName["csrf"].FieldType != "hidden" {
		t.Errorf("csrf FieldType = %q, want hidden", byName["csrf"].FieldType)
	}
	if byName["body"].FieldType != "textarea" {
		t.Errorf("body FieldType = %q, want textarea", byName["body"].FieldType)
	}
	if byName["category"].FieldType != "select" {
		t.Errorf("category FieldType = %q, want select", byName["category"].FieldType)
	}
}

func TestNormalize_QueryCandidate_FieldTypeAlwaysEmpty(t *testing.T) {
	// FieldType is a form-discovery-only concept -- a query candidate
	// (no HTML input behind it at all) must never carry one.
	pages := []crawler.Page{{URL: "https://example.test/search?q=widgets"}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 1 {
		t.Fatalf("got %+v", res.Candidates)
	}
	if res.Candidates[0].FieldType != "" {
		t.Errorf("FieldType = %q, want empty for a query candidate", res.Candidates[0].FieldType)
	}
}

func TestNormalize_DuplicateForm_AcrossTwoPages_Deduplicated(t *testing.T) {
	form := crawler.FormRef{Action: "https://example.test/login", Method: "POST", Fields: []crawler.FormField{{Name: "username", Type: "text"}}}
	pages := []crawler.Page{
		{URL: "https://example.test/", Forms: []crawler.FormRef{form}},
		{URL: "https://example.test/other", Forms: []crawler.FormRef{form}},
	}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 1 {
		t.Fatalf("got %d candidates, want 1 (deduplicated): %+v", len(res.Candidates), res.Candidates)
	}
}

// --- Deduplication across locations/methods/sources ------------------------

func TestNormalize_SameNameDifferentLocation_RemainDistinct(t *testing.T) {
	pages := []crawler.Page{{
		URL: "https://example.test/search?q=fromurl",
		Forms: []crawler.FormRef{{
			Action: "https://example.test/search", Method: "POST",
			Fields: []crawler.FormField{{Name: "q", Type: "text", Value: "fromform"}},
		}},
	}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 2 {
		t.Fatalf("got %d candidates, want 2 (query:q and form:q are distinct): %+v", len(res.Candidates), res.Candidates)
	}
}

func TestNormalize_SamePathDifferentMethod_RemainDistinct(t *testing.T) {
	pages := []crawler.Page{{
		Forms: []crawler.FormRef{
			{Action: "https://example.test/search", Method: "GET", Fields: []crawler.FormField{{Name: "q", Type: "text"}}},
			{Action: "https://example.test/search", Method: "POST", Fields: []crawler.FormField{{Name: "q", Type: "text"}}},
		},
	}}
	res := Normalize(pages, Limits{})
	if len(res.Candidates) != 2 {
		t.Fatalf("got %d candidates, want 2 (GET query:q and POST form:q): %+v", len(res.Candidates), res.Candidates)
	}
}

// --- Resource limits ---------------------------------------------------

func TestNormalize_MaxFormFields_TruncatesAndWarns(t *testing.T) {
	var fields []crawler.FormField
	for i := 0; i < 10; i++ {
		fields = append(fields, crawler.FormField{Name: fmt.Sprintf("f%d", i), Type: "text"})
	}
	pages := []crawler.Page{{Forms: []crawler.FormRef{{Action: "https://example.test/x", Method: "POST", Fields: fields}}}}
	res := Normalize(pages, Limits{MaxFormFields: 3})
	if len(res.Candidates) != 3 {
		t.Fatalf("got %d candidates, want 3 (truncated)", len(res.Candidates))
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning when the form field limit is reached")
	}
}

func TestNormalize_MaxInputsPerEndpoint_TruncatesAndWarns(t *testing.T) {
	pages := []crawler.Page{{URL: "https://example.test/search?a=1&b=2&c=3&d=4&e=5"}}
	res := Normalize(pages, Limits{MaxInputsPerEndpoint: 2})
	if len(res.Candidates) != 2 {
		t.Fatalf("got %d candidates, want 2 (truncated): %+v", len(res.Candidates), res.Candidates)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning when the per-endpoint input limit is reached")
	}
}

func TestNormalize_MaxTotalInputs_TruncatesAcrossEndpointsAndWarns(t *testing.T) {
	pages := []crawler.Page{
		{URL: "https://example.test/a?x=1&y=2"},
		{URL: "https://example.test/b?x=1&y=2"},
	}
	res := Normalize(pages, Limits{MaxTotalInputs: 2})
	if len(res.Candidates) != 2 {
		t.Fatalf("got %d candidates, want 2 (global truncation): %+v", len(res.Candidates), res.Candidates)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning when the total input limit is reached")
	}
}

// --- Determinism -------------------------------------------------------

func TestNormalize_Deterministic(t *testing.T) {
	pages := []crawler.Page{
		{URL: "https://example.test/search?q=x&page=2"},
		{Forms: []crawler.FormRef{{
			Action: "https://example.test/login", Method: "POST",
			Fields: []crawler.FormField{{Name: "b", Type: "text"}, {Name: "a", Type: "text"}},
		}}},
	}
	first := Normalize(pages, Limits{})
	for i := 0; i < 20; i++ {
		got := Normalize(pages, Limits{})
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("Normalize not deterministic at iteration %d:\n%+v\n%+v", i, first, got)
		}
	}
}

func TestNormalize_DuplicateCount_Reported(t *testing.T) {
	form := crawler.FormRef{Action: "https://example.test/login", Method: "POST", Fields: []crawler.FormField{{Name: "username", Type: "text"}}}
	pages := []crawler.Page{
		{URL: "https://example.test/", Forms: []crawler.FormRef{form}},
		{URL: "https://example.test/other", Forms: []crawler.FormRef{form}},
	}
	res := Normalize(pages, Limits{})
	if res.DuplicateCount != 1 {
		t.Errorf("DuplicateCount = %d, want 1", res.DuplicateCount)
	}
}

func TestNormalize_EmptyPages_NoCandidatesNoWarnings(t *testing.T) {
	res := Normalize(nil, Limits{})
	if len(res.Candidates) != 0 || len(res.Warnings) != 0 {
		t.Errorf("got %+v, want empty result", res)
	}
}
