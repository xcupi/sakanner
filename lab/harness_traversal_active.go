// Phase 3.27 Path Traversal Active Detection lab fixtures.
//
// This file extends vuln.scanner.test (harness_vuln.go) with form/
// JSON/path-location vulnerable fixtures -- closing the gaps
// registerPathTraversalAPI (Phase 3.6, query-GET-only) left open. It
// does NOT modify registerPathTraversalAPI or any of its existing
// routes -- every new fixture here is additive, reusing the SAME
// travSynthFS synthetic filesystem and path.Clean(path.Join("public",
// file)) logic every existing /files/download/* fixture already uses,
// never a real filesystem call.
package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

// travResolve mirrors /files/download/vulnerable's own resolution
// logic exactly (harness_vuln.go) -- the one shared helper every new
// fixture below reuses.
func travResolve(file string) (content string, ok bool) {
	resolved := path.Clean(path.Join("public", file))
	content, ok = travSynthFS[resolved]
	return content, ok
}

func registerPathTraversalActive(mux *http.ServeMux) {
	// Form-location (same resolution logic as /files/download/vulnerable).
	mux.HandleFunc("/files/download/vulnerable-form", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		content, ok := travResolve(r.FormValue("file"))
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "not found")
			return
		}
		fmt.Fprint(w, content)
	})

	// JSON-body-location. Reachable only via a DIRECTLY-persisted
	// Parameter in tests (Location: "json", Provenance:
	// "REQUEST_INPUT"), not through a real crawl -- the crawler cannot
	// yet discover a live JSON REQUEST_INPUT parameter, the same
	// honest, pre-existing Phase 3.19 limitation reaffirmed for the
	// fourth consecutive "-active" detector phase. Still a REAL,
	// genuinely vulnerable HTTP endpoint.
	mux.HandleFunc("/files/download/vulnerable-json", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			File string `json:"file"`
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err == nil {
			_ = json.Unmarshal(raw, &payload) // tolerate empty/malformed body -- the JSON-location baseline probe has none seeded
		}
		w.Header().Set("Content-Type", "text/plain")
		content, ok := travResolve(payload.File)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "not found")
			return
		}
		fmt.Fprint(w, content)
	})

	// Path-location is registered OUTSIDE this mux entirely -- see
	// travPathLocationPrefix/travPathLocationHandler/
	// travPathLocationBypass below, and vulnAppHandler's own wrapping
	// in harness_vuln.go -- because *http.ServeMux would otherwise
	// intercept and 301-redirect it before this handler ever runs.
}

// travPathLocationPrefix is the literal path prefix the path-location
// fixture matches on. It is intercepted OUTSIDE the *http.ServeMux
// (vulnAppHandler wraps the assembled mux with travPathLocationBypass)
// rather than registered via mux.HandleFunc, because *http.ServeMux
// unconditionally 301-redirects any request whose decoded r.URL.Path
// contains ".." to its cleaned equivalent BEFORE any handler runs --
// confirmed directly against the stdlib (net/http.ServeMux.Handler ->
// cleanPath) during this phase's development. That auto-cleaning would
// silently defeat the very traversal attempt this fixture exists to
// demonstrate, regardless of what the handler itself would have done
// with the raw value. Bypassing it here is not "faking" support: it
// exercises a realistic routing shape -- a handler that trusts a raw
// path segment without going through a normalizing router -- which is
// exactly how real path-traversal-via-path-segment vulnerabilities
// exist in the wild (naive custom routers, CGI-style path handling,
// frameworks that expose the raw segment before normalization).
const travPathLocationPrefix = "/files/download/path/"

func travPathLocationHandler(w http.ResponseWriter, r *http.Request) {
	file := strings.TrimPrefix(r.URL.Path, travPathLocationPrefix)
	w.Header().Set("Content-Type", "text/plain")
	content, ok := travResolve(file)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "not found")
		return
	}
	fmt.Fprint(w, content)
}

// travPathLocationBypass wraps the fully-assembled vuln app mux,
// intercepting travPathLocationPrefix requests before they ever reach
// mux.ServeHTTP -- see travPathLocationPrefix's own doc comment for
// why this is necessary. Every other request passes through to mux
// completely unchanged.
func travPathLocationBypass(mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, travPathLocationPrefix) {
			travPathLocationHandler(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
