package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// This file covers CrawlSettings.StartPath (general web application
// start-URL/base-path support): the per-scan override that lets an
// operator point a crawl at a same-origin subpath instead of always
// starting at "/", threaded through scanPipeline into
// orchestration.Pipeline.CrawlStartPath. See lab/start_url_test.go
// for the full-stack (real authenticated session + real lab)
// equivalent of these tests.

// startPathTestServer serves three areas: "/" (links only to
// "/other"), "/other" (a dead end), and "/base/" (a subtree with no
// link into it from "/" at all, whose own index links to
// "/base/child") -- deliberately not DVWA-specific, standing in for
// "any application mounted under a base path."
func startPathTestServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`<html><body><a href="/other">other</a></body></html>`))
	})
	mux.HandleFunc("/other", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>other page, no further links</body></html>`))
	})
	mux.HandleFunc("/base/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/base/" {
			w.Write([]byte(`<html><body><a href="/base/child">child</a></body></html>`))
			return
		}
		w.Write([]byte(`<html><body>base subpage, no further links</body></html>`))
	})
	return httptest.NewServer(mux)
}

// TestOptions_CrawlOverride_StartPath_ChangesCrawlEntryPoint proves
// StartPath actually redirects the crawl's own starting point: a
// crawl overridden to start at /base/ reaches /base/ and /base/child
// (unlinked from "/") but never /other (linked only from "/", which
// StartPath bypasses entirely).
func TestOptions_CrawlOverride_StartPath_ChangesCrawlEntryPoint(t *testing.T) {
	srv := startPathTestServer()
	defer srv.Close()

	orch := buildOrchestratorAgainstRealStore(t, srv, false) // Pipeline-level: crawler OFF; override turns it on
	result, err := orch.Run(context.Background(), Options{
		Target:        "127.0.0.1",
		CrawlOverride: &CrawlSettings{Enabled: true, MaxDepth: 2, MaxPages: 10, StartPath: "/base/"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	endpoints, err := orch.Store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	paths := map[string]bool{}
	for _, e := range endpoints {
		paths[e.Path] = true
	}
	if !paths["/base/"] || !paths["/base/child"] {
		t.Errorf("CrawlOverride.StartPath=/base/ did not reach the base path's own pages -- endpoints found: %v", paths)
	}
	if paths["/other"] {
		t.Errorf("crawl starting at /base/ unexpectedly reached /other (only linked from \"/\", which StartPath should bypass) -- endpoints found: %v", paths)
	}
}

// TestOptions_CrawlOverride_StartPath_ZeroValue_DefaultsToRoot pins
// down backward compatibility: CrawlSettings{}'s StartPath zero value
// (empty string) must still start the crawl at "/", exactly like
// every pre-existing CrawlOverride caller already relies on.
func TestOptions_CrawlOverride_StartPath_ZeroValue_DefaultsToRoot(t *testing.T) {
	srv := startPathTestServer()
	defer srv.Close()

	orch := buildOrchestratorAgainstRealStore(t, srv, false)
	result, err := orch.Run(context.Background(), Options{
		Target:        "127.0.0.1",
		CrawlOverride: &CrawlSettings{Enabled: true, MaxDepth: 2, MaxPages: 10},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	endpoints, err := orch.Store.Endpoints().ListByScanJob(context.Background(), result.ScanID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	paths := map[string]bool{}
	for _, e := range endpoints {
		paths[e.Path] = true
	}
	if !paths["/"] || !paths["/other"] {
		t.Errorf("CrawlOverride with StartPath unset (zero value) did not crawl from \"/\" as before -- endpoints found: %v", paths)
	}
	if paths["/base/"] {
		t.Errorf("crawl starting at \"/\" unexpectedly reached /base/ (unlinked from root) -- endpoints found: %v", paths)
	}
}

// TestOptions_CrawlOverride_StartPath_DoesNotMutateSharedPipeline
// mirrors TestOptions_CrawlOverride_DoesNotMutateSharedPipeline
// (policy_options_test.go) for the new field specifically: after a
// scan using CrawlOverride.StartPath, o.Pipeline.CrawlStartPath itself
// must be unchanged -- the same per-scan-copy guarantee every other
// CrawlSettings field already has.
func TestOptions_CrawlOverride_StartPath_DoesNotMutateSharedPipeline(t *testing.T) {
	srv := startPathTestServer()
	defer srv.Close()

	orch := buildOrchestratorAgainstRealStore(t, srv, false)
	before := orch.Pipeline.CrawlStartPath
	_, err := orch.Run(context.Background(), Options{
		Target:        "127.0.0.1",
		CrawlOverride: &CrawlSettings{Enabled: true, MaxDepth: 2, MaxPages: 10, StartPath: "/base/"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if orch.Pipeline.CrawlStartPath != before {
		t.Errorf("o.Pipeline.CrawlStartPath was mutated by a scan using CrawlOverride: before=%q after=%q", before, orch.Pipeline.CrawlStartPath)
	}
}
