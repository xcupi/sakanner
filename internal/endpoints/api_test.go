package endpoints

import (
	"net/url"
	"reflect"
	"testing"

	"sakanner/internal/crawler"
)

func TestClassifyAPI_JSONContentType_Candidate(t *testing.T) {
	page := crawler.Page{URL: "https://example.test/api/data", ContentType: "application/json"}
	candidate, evidence := ClassifyAPI(page)
	if !candidate {
		t.Fatal("expected candidate=true for a JSON content type")
	}
	if len(evidence) == 0 {
		t.Fatal("expected non-empty evidence")
	}
	found := false
	for _, e := range evidence {
		if e == EvidenceResponseContentTypeJSON {
			found = true
		}
	}
	if !found {
		t.Errorf("evidence = %v, want it to contain %q", evidence, EvidenceResponseContentTypeJSON)
	}
}

func TestClassifyAPI_HTMLContentType_NotAPICandidateFromContentTypeAlone(t *testing.T) {
	page := crawler.Page{URL: "https://example.test/about", ContentType: "text/html"}
	candidate, evidence := ClassifyAPI(page)
	if candidate {
		t.Errorf("an ordinary HTML page with a non-API-shaped path must not be classified as an API candidate, got evidence=%v", evidence)
	}
}

func TestClassifyAPI_PathHeuristic_APISegment(t *testing.T) {
	page := crawler.Page{URL: "https://example.test/api/users", ContentType: "text/html"}
	candidate, evidence := ClassifyAPI(page)
	if !candidate {
		t.Fatal("expected candidate=true for a path containing an /api/ segment")
	}
	if len(evidence) != 1 || evidence[0] != EvidencePathHeuristic {
		t.Errorf("evidence = %v, want exactly [%q] (weak signal, not content-type)", evidence, EvidencePathHeuristic)
	}
}

func TestClassifyAPI_PathHeuristic_NumericTrailingSegment(t *testing.T) {
	page := crawler.Page{URL: "https://example.test/users/42", ContentType: "text/html"}
	candidate, evidence := ClassifyAPI(page)
	if !candidate {
		t.Fatal("expected candidate=true for a /users/42-shaped path")
	}
	if len(evidence) != 1 || evidence[0] != EvidencePathHeuristic {
		t.Errorf("evidence = %v", evidence)
	}
}

func TestClassifyAPI_BothSignals_BothReported(t *testing.T) {
	page := crawler.Page{URL: "https://example.test/api/users/42", ContentType: "application/json"}
	candidate, evidence := ClassifyAPI(page)
	if !candidate {
		t.Fatal("expected candidate=true")
	}
	want := []string{EvidenceResponseContentTypeJSON, EvidencePathHeuristic}
	if !reflect.DeepEqual(evidence, want) {
		t.Errorf("evidence = %v, want %v (both signals, content-type first)", evidence, want)
	}
}

func TestClassifyAPI_PlainNumericFirstSegment_NotFlagged(t *testing.T) {
	// A LEADING numeric segment (not following another segment) is
	// NOT the "/resource/id" shape this heuristic targets -- avoids
	// flagging something like "/42" (unusual but not REST-shaped) as
	// confidently as a genuine "/users/42".
	page := crawler.Page{URL: "https://example.test/42", ContentType: "text/html"}
	candidate, _ := ClassifyAPI(page)
	if candidate {
		t.Error("a bare leading numeric segment alone should not trigger the path heuristic")
	}
}

func TestExtractAPIRoutes_FetchCall_AbsoluteAndRelative(t *testing.T) {
	script := []byte(`
		fetch("/api/nested");
		fetch("https://example.test/api/items");
		console.log("just a log message with /api/looking/text but no call shape");
	`)
	base, _ := url.Parse("https://example.test/scripts/app.js")
	routes := ExtractAPIRoutes(script, base, JSLimits{})
	want := []string{"https://example.test/api/items", "https://example.test/api/nested"}
	if !reflect.DeepEqual(routes, want) {
		t.Errorf("routes = %v, want %v", routes, want)
	}
}

func TestExtractAPIRoutes_MultipleCallShapes(t *testing.T) {
	script := []byte(`
		axios.get("/api/a");
		client.post("/api/b");
		client.put("/api/c");
		client.patch("/api/d");
		client.delete("/api/e");
	`)
	base, _ := url.Parse("https://example.test/app.js")
	routes := ExtractAPIRoutes(script, base, JSLimits{})
	if len(routes) != 5 {
		t.Fatalf("got %d routes, want 5: %v", len(routes), routes)
	}
}

func TestExtractAPIRoutes_OrdinaryStringLiteral_Ignored(t *testing.T) {
	script := []byte(`var cssClass = "/some/path/that/is/not/a/call";`)
	base, _ := url.Parse("https://example.test/app.js")
	routes := ExtractAPIRoutes(script, base, JSLimits{})
	if len(routes) != 0 {
		t.Errorf("got %v, want no routes extracted from a bare string literal with no call shape", routes)
	}
}

func TestExtractAPIRoutes_Deduplicated(t *testing.T) {
	script := []byte(`fetch("/api/dup"); fetch("/api/dup"); fetch('/api/dup');`)
	base, _ := url.Parse("https://example.test/app.js")
	routes := ExtractAPIRoutes(script, base, JSLimits{})
	if len(routes) != 1 {
		t.Errorf("got %v, want exactly one deduplicated route", routes)
	}
}

func TestExtractAPIRoutes_Bounded_MaxRoutesPerScript(t *testing.T) {
	script := []byte(`fetch("/api/1"); fetch("/api/2"); fetch("/api/3"); fetch("/api/4"); fetch("/api/5");`)
	base, _ := url.Parse("https://example.test/app.js")
	routes := ExtractAPIRoutes(script, base, JSLimits{MaxRoutesPerScript: 2})
	if len(routes) != 2 {
		t.Fatalf("got %d routes, want exactly 2 (bounded)", len(routes))
	}
}

func TestExtractAPIRoutes_Deterministic(t *testing.T) {
	script := []byte(`fetch("/api/z"); fetch("/api/a"); fetch("/api/m");`)
	base, _ := url.Parse("https://example.test/app.js")
	first := ExtractAPIRoutes(script, base, JSLimits{})
	for i := 0; i < 10; i++ {
		got := ExtractAPIRoutes(script, base, JSLimits{})
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("iteration %d: not deterministic: %v vs %v", i, got, first)
		}
	}
}

func TestExtractAPIRoutes_EmptyScript_NoPanic(t *testing.T) {
	base, _ := url.Parse("https://example.test/app.js")
	routes := ExtractAPIRoutes(nil, base, JSLimits{})
	if len(routes) != 0 {
		t.Errorf("got %v for an empty script", routes)
	}
}
