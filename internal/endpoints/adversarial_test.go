package endpoints

import (
	"net/url"
	"sync"
	"testing"

	"sakanner/internal/crawler"
)

// Phase 3.18 task section 17's JavaScript/endpoint-discovery-specific
// adversarial suite.

func TestExtractAPIRoutes_MaliciousStringWithQuotesAndBackslashes_NoCrash(t *testing.T) {
	script := []byte(`fetch("/api/a\"; alert(1); //");` + "\n" + `fetch('/api/b\'); DROP TABLE users; --');`)
	base, _ := url.Parse("https://example.test/app.js")
	// Must not panic regardless of how adversarial the embedded string
	// content is -- a pure regex scan over bytes, never evaluated as
	// code.
	_ = ExtractAPIRoutes(script, base, JSLimits{})
}

func TestExtractAPIRoutes_JavaScriptSchemeURL_NotFollowedAsRoute(t *testing.T) {
	script := []byte(`fetch("javascript:alert(document.cookie)");`)
	base, _ := url.Parse("https://example.test/app.js")
	routes := ExtractAPIRoutes(script, base, JSLimits{})
	for _, r := range routes {
		if r == "javascript:alert(document.cookie)" {
			t.Fatal("SECURITY: a javascript: URI must never be extracted as a route candidate")
		}
	}
}

func TestExtractAPIRoutes_DataURI_NotExtracted(t *testing.T) {
	script := []byte(`fetch("data:text/html,<script>alert(1)</script>");`)
	base, _ := url.Parse("https://example.test/app.js")
	routes := ExtractAPIRoutes(script, base, JSLimits{})
	for _, r := range routes {
		if len(r) > 5 && r[:5] == "data:" {
			t.Fatal("a data: URI must never be extracted as a route candidate")
		}
	}
}

func TestExtractAPIRoutes_EncodedHostAttempt_ReturnedVerbatimNotDecoded(t *testing.T) {
	// A route referencing a percent-encoded or userinfo-obfuscated
	// absolute URL is returned exactly as written -- this function
	// performs no scope decision and no decoding of its own; the
	// CALLER's centralized scope check (which DOES correctly resolve
	// hostnames) is what actually decides authorization, not this
	// extraction step. See docs/phase-3-18-api-json-discovery.md
	// section 5 and 8.
	script := []byte(`fetch("https://legit.test@evil.test/api/steal");`)
	base, _ := url.Parse("https://example.test/app.js")
	routes := ExtractAPIRoutes(script, base, JSLimits{})
	if len(routes) != 1 {
		t.Fatalf("got %v, want exactly one extracted (unvalidated) route", routes)
	}
	parsed, err := url.Parse(routes[0])
	if err != nil {
		t.Fatalf("extracted route did not parse as a URL: %v", err)
	}
	if parsed.Hostname() != "evil.test" {
		t.Errorf("Hostname() = %q, want evil.test (the userinfo trick must not fool url.Parse itself)", parsed.Hostname())
	}
}

func TestExtractAPIRoutes_ConcurrentCalls_NoRace(t *testing.T) {
	script := []byte(`fetch("/api/a"); fetch("/api/b"); axios.get("/api/c");`)
	base, _ := url.Parse("https://example.test/app.js")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			routes := ExtractAPIRoutes(script, base, JSLimits{})
			if len(routes) != 3 {
				t.Errorf("concurrent call got %d routes, want 3", len(routes))
			}
		}()
	}
	wg.Wait()
}

func TestNormalize_ClassifyAPI_ConcurrentCalls_NoRace(t *testing.T) {
	pages := []crawler.Page{{URL: "https://example.test/api/data", ContentType: "application/json"}}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := Normalize(pages)
			if len(out) != 1 || !out[0].APICandidate {
				t.Errorf("concurrent Normalize call: unexpected result %+v", out)
			}
		}()
	}
	wg.Wait()
}

func TestNormalize_DuplicateJavaScriptRouteAcrossPages_Deduplicated(t *testing.T) {
	pages := []crawler.Page{
		{URL: "https://example.test/a", Scripts: []string{"https://example.test/app.js"}},
		{URL: "https://example.test/b", Scripts: []string{"https://example.test/app.js"}},
	}
	out := Normalize(pages)
	count := 0
	for _, e := range out {
		if e.Path == "/app.js" && e.Source == SourceJavaScript {
			count++
		}
	}
	if count != 1 {
		t.Errorf("got %d javascript-source endpoint rows for the same script referenced from two pages, want 1 (deduplicated)", count)
	}
}
