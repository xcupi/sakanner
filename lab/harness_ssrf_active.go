// Phase 3.25 SSRF Active Detection Foundation lab fixtures.
//
// This file extends vuln.scanner.test (harness_vuln.go) with
// form/JSON/path-location SSRF fixtures, a blind-only (response never
// reveals fetch outcome) fixture, and a redirect-through fixture --
// closing the gap Phase 3.4's own registerSSRF (query-location only)
// left open. It does NOT modify registerSSRF, lab/callback.go, or
// ssrfInternalHandler -- every new fixture here is additive, reusing
// the SAME "restrict to loopback destinations only" safety-net
// principle /ssrf/vulnerable already established, duplicated (not
// shared) here so that already-tested handler is never touched. See
// docs/phase-3-25-ssrf-active-detection.md section 10.
package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ssrfActiveFetchLoopbackOnly performs a server-side fetch of target,
// restricted to loopback destinations only -- mirrors
// /ssrf/vulnerable's own inline safety net (harness_vuln.go) exactly,
// duplicated rather than shared so that already-tested handler is
// never modified by this phase.
func ssrfActiveFetchLoopbackOnly(target string) (status int, body string) {
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return http.StatusBadRequest, "bad url"
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return http.StatusBadGateway, "fixture safety net: only 127.0.0.0/8 destinations are permitted from this lab fixture"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return http.StatusBadGateway, fmt.Sprintf("fetch failed: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return http.StatusOK, fmt.Sprintf("fetched %s: %s", target, respBody)
}

// registerSSRFActive adds this phase's own routes onto vuln.scanner.test's
// existing mux -- called once from vulnAppHandler, mirroring
// lab/harness_path_parameters.go's own registerPathParameters(mux)
// precedent (Phase 3.23).
func registerSSRFActive(mux *http.ServeMux) {
	// Form-location (Phase 3.21-style POST form field) -- genuinely
	// vulnerable, identical fetch logic to /ssrf/vulnerable.
	mux.HandleFunc("/ssrf/vulnerable-form", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		status, body := ssrfActiveFetchLoopbackOnly(r.FormValue("url"))
		w.WriteHeader(status)
		w.Write([]byte(body))
	})

	// JSON-body-location. Reachable only via a DIRECTLY-persisted
	// Parameter in tests (Location: "json", Provenance:
	// "REQUEST_INPUT"), not through a real crawl -- the crawler
	// cannot yet discover a live JSON REQUEST_INPUT parameter, an
	// honest, pre-existing Phase 3.19 limitation this phase does not
	// close (see docs/phase-3-25-ssrf-active-detection.md and
	// docs/phase-3-19-acceptance-test.md's own identical note for
	// xssactive). Still a REAL, genuinely vulnerable HTTP endpoint,
	// proving the detector's own mutation/execution against a real
	// server even though discovery itself is out of scope here.
	mux.HandleFunc("/ssrf/vulnerable-json", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			URL string `json:"url"`
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil || json.Unmarshal(raw, &payload) != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		status, body := ssrfActiveFetchLoopbackOnly(payload.URL)
		w.WriteHeader(status)
		w.Write([]byte(body))
	})

	// Path-location -- the target URL is a URL-path-escaped segment
	// (mutation.applyPath's own established escaping, Phase 3.23,
	// handles round-tripping this correctly). Two example links (see
	// the index page this phase adds to /forms/index) give
	// internal/parameters.InferPathInputs the >=2-distinct-value
	// evidence it requires.
	mux.HandleFunc("/ssrf/fetch/", func(w http.ResponseWriter, r *http.Request) {
		encoded := strings.TrimPrefix(r.URL.Path, "/ssrf/fetch/")
		target, err := url.PathUnescape(encoded)
		if err != nil {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		status, body := ssrfActiveFetchLoopbackOnly(target)
		w.WriteHeader(status)
		w.Write([]byte(body))
	})

	// Blind-only: genuinely fetches server-side (in a goroutine,
	// modeling an async/queued job -- task section 3's own "blind
	// SSRF" scenario) but NEVER reveals the fetch outcome in its own
	// response, regardless of success/failure -- the ONLY meaningful
	// proof available for this endpoint is callback (Mode B)
	// correlation. Proves Mode B alone, with Mode A structurally
	// impossible against this specific endpoint.
	mux.HandleFunc("/ssrf/vulnerable-blind", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		go func() {
			_, _ = ssrfActiveFetchLoopbackOnly(target)
		}()
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("queued"))
	})

	// Redirect-through: a tiny redirector, restricted to loopback
	// destinations, proving "callback through redirect" (task section
	// 12) works entirely via the TARGET APPLICATION's own outbound
	// http.Client (which follows redirects by default) -- when
	// /ssrf/vulnerable's own url parameter points HERE with ?to=<the
	// real callback URL>, the vuln app's own client follows the
	// redirect and reaches the callback with zero detector-side
	// redirect-specific code.
	mux.HandleFunc("/ssrf/redirect-bounce", func(w http.ResponseWriter, r *http.Request) {
		to := r.URL.Query().Get("to")
		u, err := url.Parse(to)
		if err != nil || u.Hostname() == "" {
			http.Error(w, "bad url", http.StatusBadRequest)
			return
		}
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "fixture safety net: only 127.0.0.0/8 redirect destinations are permitted from this lab fixture", http.StatusBadGateway)
			return
		}
		http.Redirect(w, r, to, http.StatusFound)
	})
}
