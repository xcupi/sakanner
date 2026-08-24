package endpoints

import (
	"testing"

	"sakanner/internal/crawler"
)

func TestNormalize_ExtractsAllSourceKinds(t *testing.T) {
	pages := []crawler.Page{
		{
			URL:     "http://example.com/",
			Links:   []string{"http://example.com/about"},
			Forms:   []crawler.FormRef{{Action: "http://example.com/login", Method: "POST"}},
			Scripts: []string{"http://example.com/app.js"},
		},
	}

	got := Normalize(pages)

	want := map[string]struct {
		method string
		source string
	}{
		"/":       {"GET", SourceCrawl},
		"/about":  {"GET", SourceLink},
		"/login":  {"POST", SourceForm},
		"/app.js": {"GET", SourceJavaScript},
	}
	if len(got) != len(want) {
		t.Fatalf("Normalize() = %+v, want %d entries", got, len(want))
	}
	for _, e := range got {
		w, ok := want[e.Path]
		if !ok {
			t.Errorf("unexpected endpoint path %q", e.Path)
			continue
		}
		if e.Method != w.method || e.Source != w.source {
			t.Errorf("endpoint %q = {%s %s}, want {%s %s}", e.Path, e.Method, e.Source, w.method, w.source)
		}
	}
}

// ---------------------------------------------------------------------
// Phase 3.21: ActionOrigin
// ---------------------------------------------------------------------

func TestNormalize_FormSameOrigin_ActionOriginMatchesPage(t *testing.T) {
	pages := []crawler.Page{{
		URL:   "http://example.com/account",
		Forms: []crawler.FormRef{{Action: "http://example.com/login", Method: "POST"}},
	}}
	got := Normalize(pages)
	found := false
	for _, e := range got {
		if e.Source == SourceForm {
			found = true
			if e.ActionOrigin != "http://example.com:80" {
				t.Errorf("ActionOrigin = %q, want http://example.com:80", e.ActionOrigin)
			}
		}
	}
	if !found {
		t.Fatal("no SourceForm endpoint produced")
	}
}

func TestNormalize_FormCrossOrigin_ActionOriginReflectsRealDestination(t *testing.T) {
	pages := []crawler.Page{{
		URL:   "http://example.com/account",
		Forms: []crawler.FormRef{{Action: "http://evil.example:8443/collect", Method: "POST"}},
	}}
	got := Normalize(pages)
	for _, e := range got {
		if e.Source == SourceForm {
			if e.ActionOrigin != "http://evil.example:8443" {
				t.Errorf("ActionOrigin = %q, want http://evil.example:8443", e.ActionOrigin)
			}
			return
		}
	}
	t.Fatal("no SourceForm endpoint produced")
}

func TestNormalize_NonFormSources_ActionOriginAlwaysEmpty(t *testing.T) {
	pages := []crawler.Page{{
		URL:     "http://example.com/",
		Links:   []string{"http://example.com/about"},
		Scripts: []string{"http://example.com/app.js"},
	}}
	got := Normalize(pages)
	for _, e := range got {
		if e.ActionOrigin != "" {
			t.Errorf("endpoint %q (source %s) has ActionOrigin = %q, want empty for a non-form source", e.Path, e.Source, e.ActionOrigin)
		}
	}
}

func TestOriginOf(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"http://example.com/login", "http://example.com:80"},
		{"https://example.com/login", "https://example.com:443"},
		{"http://example.com:8080/login", "http://example.com:8080"},
		{"https://example.com:8443/login", "https://example.com:8443"},
		{"http://sub.example.com/login", "http://sub.example.com:80"},
		{"http://good.com@evil.com/login", "http://evil.com:80"}, // userinfo stripped by Hostname()
		{"/relative/path", ""}, // no host at all
		{"not a url at all \x00", ""},
	}
	for _, c := range cases {
		if got := originOf(c.raw); got != c.want {
			t.Errorf("originOf(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestNormalize_DeduplicatesAcrossPages(t *testing.T) {
	pages := []crawler.Page{
		{URL: "http://example.com/page1", Links: []string{"http://example.com/shared"}},
		{URL: "http://example.com/page2", Links: []string{"http://example.com/shared"}},
	}

	got := Normalize(pages)

	count := 0
	for _, e := range got {
		if e.Path == "/shared" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("got %d entries for /shared (found via 2 pages), want exactly 1 (deduplicated)", count)
	}
}

func TestNormalize_QueryStringPreserved(t *testing.T) {
	pages := []crawler.Page{
		{URL: "http://example.com/", Links: []string{"http://example.com/search?q=test"}},
	}
	got := Normalize(pages)

	found := false
	for _, e := range got {
		if e.Path == "/search?q=test" {
			found = true
		}
	}
	if !found {
		t.Errorf("Normalize() = %+v, want an entry with path \"/search?q=test\"", got)
	}
}

func TestNormalize_EmptyInput(t *testing.T) {
	got := Normalize(nil)
	if len(got) != 0 {
		t.Errorf("Normalize(nil) = %+v, want empty", got)
	}
}

func TestNormalize_DeterministicOrder(t *testing.T) {
	pages := []crawler.Page{
		{URL: "http://example.com/", Links: []string{"http://example.com/b", "http://example.com/a"}},
	}
	first := Normalize(pages)
	second := Normalize(pages)
	if len(first) != len(second) {
		t.Fatalf("non-deterministic length: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Path != second[i].Path {
			t.Errorf("non-deterministic order at index %d: %q vs %q", i, first[i].Path, second[i].Path)
		}
	}
}
