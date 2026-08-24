// Phase 3.21/3.22 Form Request Discovery & Active Body Mutation
// fixtures.
//
// This file adds ONE dedicated page (/forms/index) demonstrating every
// HTML form shape the form discovery/reconstruction/mutation pipeline
// must handle -- GET form, POST form (application/
// x-www-form-urlencoded), hidden fields, textarea, select, checkbox/
// radio, a CSRF-like hidden token, a relative action, an absolute
// out-of-scope action, and (Phase 3.22) a genuinely separate,
// separately-in-scope second host -- plus real <form> elements
// pointing at the ALREADY-REVIEWED /sqli/vulnerable (GET),
// /sqli/form/vulnerable (POST), and /xss/reflected/form-vulnerable
// (POST) fixtures, reusing their existing vulnerability logic
// verbatim. This proves the crawler's OWN form discovery feeds the
// pipeline end to end -- it is not a new vulnerability shape, and
// "kitchen-sink"/"relative-target" below are never vulnerable to
// anything.
package lab

import (
	"fmt"
	"net/http"
)

// registerFormMutation registers /forms/index and its own action
// targets. formSecondHostAddr (Phase 3.22) is second-service.scanner.test's
// real, already-allocated listener address (host:port) -- its own
// standalone app is registered separately (formSecondHostHandler,
// harness_vuln.go), started before vulnAppHandler is built.
func registerFormMutation(mux *http.ServeMux, formSecondHostAddr string) {
	mux.HandleFunc("/forms/index", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>
<h1>Phase 3.21/3.22 form fixtures</h1>

<form method="GET" action="/sqli/vulnerable">
  <input type="text" name="id" value="1">
  <button>Search (GET form, query-location, SQLi)</button>
</form>

<form method="POST" action="/sqli/form/vulnerable">
  <input type="text" name="id" value="1">
  <button>Search (POST form, form-location, SQLi)</button>
</form>

<form method="POST" action="/xss/reflected/form-vulnerable">
  <input type="text" name="q" value="test">
  <button>Search (POST form, form-location, reflected XSS)</button>
</form>

<form method="POST" action="/ssrf/vulnerable-form">
  <input type="text" name="url" value="https://status.fixture.test/">
  <button>Fetch (POST form, form-location, SSRF)</button>
</form>

<form method="POST" action="/api/ping/vulnerable-form">
  <input type="text" name="host" value="127.0.0.1">
  <button>Ping (POST form, form-location, command injection)</button>
</form>

<form method="POST" action="/files/download/vulnerable-form">
  <input type="text" name="file" value="index.html">
  <button>Download (POST form, form-location, path traversal)</button>
</form>

<form method="POST" action="/redirect/open/vulnerable-form">
  <input type="text" name="next" value="/dashboard">
  <button>Go (POST form, form-location, open redirect)</button>
</form>

<form method="POST" action="/ssti/vulnerable-form">
  <input type="text" name="name" value="guest">
  <button>Greet (POST form, form-location, SSTI)</button>
</form>

<form method="POST" action="kitchen-sink">
  <input type="hidden" name="csrf_token" value="lab-fixed-csrf-token">
  <input type="text" name="display_name" value="alice">
  <textarea name="bio">hello there</textarea>
  <select name="theme"><option value="light">Light</option><option value="dark" selected>Dark</option></select>
  <input type="checkbox" name="newsletter" value="1">
  <input type="radio" name="visibility" value="public" checked>
  <input type="radio" name="visibility" value="private">
  <button>Save (hidden/textarea/select/checkbox/radio/CSRF -- discovery-fidelity only, never vulnerable)</button>
</form>

<form method="POST" action="relative-target">
  <input type="text" name="q" value="test">
  <button>Relative action (resolves to /forms/relative-target)</button>
</form>

<form method="POST" action="http://external.scanner.test/steal">
  <input type="text" name="secret" value="test">
  <button>Out-of-scope action (must never authorize a Target against external.scanner.test)</button>
</form>

<form method="POST" action="http://second-service.scanner.test:%s/echo/vulnerable">
  <input type="text" name="id" value="1">
  <button>Separately in-scope second host (SQLi, Phase 3.22 section 7)</button>
</form>
</body></html>`, secondHostPort(formSecondHostAddr))
	})

	mux.HandleFunc("/forms/kitchen-sink", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("saved"))
	})
	mux.HandleFunc("/forms/relative-target", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("received"))
	})
}

// secondHostPort extracts just the port from formSecondHostAddr
// (host:port) -- second-service.scanner.test's own listener always
// binds to 127.0.0.27 (ipFormSecondHost), so only the dynamically-
// allocated port varies between test runs.
func secondHostPort(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[i+1:]
		}
	}
	return addr
}
