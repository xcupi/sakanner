// Phase 3.23 Path Parameter Discovery & Active Detection Foundation
// fixtures.
//
// Every fixture here is reachable via real <a href> links (never a
// single bare link -- internal/parameters.InferPathInputs requires AT
// LEAST TWO endpoints, same method, differing only in the last
// segment, before it ever infers a path parameter -- see
// docs/phase-3-23-path-parameters.md section 1.2), proving real-crawl
// path discovery end to end, not a directly-persisted shortcut.
// Numeric identifiers reuse the already-reviewed SQLi vulnerability
// shape (sqliSimulateQuery, unchanged); the non-numeric slug pair
// reuses the already-reviewed reflected-XSS shape. The version-segment
// pair is a pure negative fixture: no vulnerability of any kind, it
// exists only to prove docs/phase-3-23-path-parameters.md section
// 2.2's exclusion holds through a REAL crawl, not just a unit test.
package lab

import (
	"fmt"
	"net/http"
	"strings"
)

func registerPathParameters(mux *http.ServeMux) {
	mux.HandleFunc("/paths/index", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
<h1>Phase 3.23 path parameter fixtures</h1>
<ul>
<li><a href="/users/1">user 1</a> / <a href="/users/2">user 2</a> / <a href="/users/3">user 3</a> (numeric path ID, SQLi-vulnerable)</li>
<li><a href="/products/widget-a">widget-a</a> / <a href="/products/widget-b">widget-b</a> (non-numeric slug path ID, reflected-XSS-vulnerable)</li>
<li><a href="/api/v1/status">v1 status</a> / <a href="/api/v2/status">v2 status</a> (version segment -- must NEVER be inferred as a path parameter)</li>
</ul>
</body></html>`)
	})

	// /users/{id} -- numeric, SQLi-vulnerable. Identical,
	// already-reviewed vulnerability shape as /sqli/vulnerable, reached
	// via a path segment instead of a query parameter -- manual
	// TrimPrefix, matching the lab's own established style for
	// path-shaped fixtures (e.g. /idor/vulnerable/user/, Phase 3.5),
	// since Go's net/http mux has no named-path-parameter concept this
	// codebase relies on anywhere.
	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		status, body := sqliSimulateQuery(id)
		w.WriteHeader(status)
		w.Write([]byte(body))
	})

	// /products/{slug} -- non-numeric identifier, reflected-XSS-
	// vulnerable. Identical, already-reviewed vulnerability shape as
	// /xss/reflected/vulnerable, reached via a path segment.
	mux.HandleFunc("/products/", func(w http.ResponseWriter, r *http.Request) {
		slug := strings.TrimPrefix(r.URL.Path, "/products/")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>Product: %s</p></body></html>", slug) // deliberately unescaped
	})

	// /api/v1/status, /api/v2/status -- a pure negative fixture. Never
	// vulnerable to anything; exists only to prove the version-segment
	// exclusion (section 2.2) holds through a real crawl.
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("v1 ok"))
	})
	mux.HandleFunc("/api/v2/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("v2 ok"))
	})
}
