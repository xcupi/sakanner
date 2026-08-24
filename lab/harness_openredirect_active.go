// Phase 3.28 Open Redirect Active Detection lab fixtures.
//
// Extends vuln.scanner.test (harness_vuln.go) with form/JSON/path-
// location vulnerable fixtures, plus the false-positive-resistance
// fixtures the task requires -- closing the gaps registerOpenRedirect
// (Phase 3, query-only, two fixtures) left open. Does NOT modify
// registerOpenRedirect or either of its existing routes
// (/redirect/open/vulnerable, /redirect/open/safe) -- every new
// fixture here is additive.
//
// OpenRedirectDestination is the SAME operator-configured, known,
// out-of-scope destination the detector's own New() is given in
// production/lab wiring -- "external.scanner.test" is the lab's
// already-established "guaranteed never in scope" hostname (reused
// throughout the lab for unrelated out-of-scope proofs since Phase
// 3.21), not a new convention invented for this phase.
package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// OpenRedirectDestination is the operator-configured destination URL
// this lab's own openredirectactive.New() call (wherever tests
// construct one) and every "vulnerable" fixture below are proven
// against.
const OpenRedirectDestination = "http://external.scanner.test/sakanner-lab-redirect-marker"

func registerOpenRedirectActive(mux *http.ServeMux) {
	// --- Vulnerable: form/JSON/path locations, zero validation,
	// mirroring /redirect/open/vulnerable's own existing (query)
	// behavior exactly. All 3 of the detector's own payload variants
	// (absolute/protocol-relative/percent-encoded) succeed against
	// these -- see docs/phase-3-28-open-redirect-active.md section 5
	// for why no separate bypass-specific fixture is needed.
	mux.HandleFunc("/redirect/open/vulnerable-form", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		next := r.FormValue("next")
		if next == "" {
			w.Write([]byte("ok"))
			return
		}
		http.Redirect(w, r, next, http.StatusFound)
	})

	mux.HandleFunc("/redirect/open/vulnerable-json", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Next string `json:"next"`
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err == nil {
			_ = json.Unmarshal(raw, &payload) // tolerate empty/malformed body -- the JSON baseline probe has none seeded
		}
		if payload.Next == "" {
			w.Write([]byte("ok"))
			return
		}
		http.Redirect(w, r, payload.Next, http.StatusFound)
	})

	// Path-location is registered OUTSIDE this mux entirely -- see
	// openRedirectPathLocationPrefix/Handler/Bypass below, and
	// vulnAppHandler's own wrapping in harness_vuln.go -- because
	// *http.ServeMux collapses the "//" inside an injected absolute
	// URL's own "scheme://" down to a single slash (path.Clean
	// collapses ANY run of repeated slashes, not just ".." segments)
	// and 301-redirects to the collapsed path before this handler
	// would ever run, corrupting the payload into a schemeless,
	// hostless value -- the same class of ServeMux auto-cleaning
	// artifact discovered for dot-segments in Phase 3.27
	// (travPathLocationPrefix), now hit again via double-slash
	// collapsing instead of dot-segment collapsing.

	// --- Negative controls -------------------------------------------

	// Same-origin validated: a relative path is safe ONLY if it is not
	// ALSO protocol-relative ("//host/..." starts with "/" but is a
	// full authority change in every browser and in
	// url.ResolveReference) -- a naive "starts with /" check alone
	// would itself be a real, common bypass this fixture must not
	// reproduce (caught during this phase's own unit-test development,
	// see docs/phase-3-28-acceptance-test.md DEFECTS FOUND AND FIXED).
	mux.HandleFunc("/redirect/safe-origin", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.Write([]byte("ok"))
			return
		}
		origin := "http://" + r.Host
		isRelative := strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//")
		if isRelative || strings.HasPrefix(next, origin) {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})

	// Relative-only: strips any scheme/authority component from the
	// input, redirecting only to the resulting path -- can never leave
	// the origin regardless of input shape (absolute, protocol-
	// relative, or otherwise).
	mux.HandleFunc("/redirect/relative-only", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.Write([]byte("ok"))
			return
		}
		if idx := strings.Index(next, "://"); idx >= 0 {
			next = next[idx+3:]
			if s := strings.IndexByte(next, '/'); s >= 0 {
				next = next[s:]
			} else {
				next = "/"
			}
		}
		if strings.HasPrefix(next, "//") {
			next = "/" + strings.TrimLeft(next, "/")
		}
		http.Redirect(w, r, next, http.StatusFound)
	})

	// Reflection only: echoes the value in the response BODY, never
	// issues a 3xx -- proves reflection alone is never sufficient.
	mux.HandleFunc("/redirect/reflect-only", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "you will be redirected to: %s", next)
	})

	// Tracking decoy: a SAFE, same-origin Location header that happens
	// to embed the raw injected payload as a query-string VALUE. The
	// literal destination-host substring appears in the Location
	// header TEXT, but the ACTUAL resolved destination is the app's
	// own origin -- proves the detector's exact-match-after-resolve
	// requirement, never a substring check.
	mux.HandleFunc("/redirect/tracking-decoy", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		http.Redirect(w, r, "/dashboard?ref="+next, http.StatusFound)
	})

	// --- Redirect chains ------------------------------------------------

	// Two-hop chain: an in-scope intermediate hop, then the
	// operator-configured out-of-scope destination -- genuinely
	// vulnerable (the chain DOES ultimately leave scope).
	mux.HandleFunc("/redirect/chain/out-of-scope", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.Write([]byte("ok"))
			return
		}
		http.Redirect(w, r, "/redirect/chain/hop2?next="+next, http.StatusFound)
	})
	mux.HandleFunc("/redirect/chain/hop2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	})

	// Two-hop chain that stays entirely in scope -- a negative
	// control for "redirect chain that ultimately remains in scope".
	mux.HandleFunc("/redirect/chain/in-scope", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.Write([]byte("ok"))
			return
		}
		http.Redirect(w, r, "/redirect/chain/hop2-safe", http.StatusFound)
	})
	mux.HandleFunc("/redirect/chain/hop2-safe", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("dashboard"))
	})
}

// openRedirectPathLocationPrefix is the literal path prefix the
// path-location fixture matches on -- intercepted OUTSIDE the
// *http.ServeMux (vulnAppHandler wraps the assembled mux with
// openRedirectPathLocationBypass) for the same reason
// travPathLocationPrefix (Phase 3.27) is: ServeMux's own path-cleaning
// would otherwise corrupt the injected payload before this handler
// ever sees it. Two example links (see harness_vuln.go's index
// additions) give internal/parameters.InferPathInputs the
// >=2-distinct-value evidence it requires.
const openRedirectPathLocationPrefix = "/redirect/open/next/"

func openRedirectPathLocationHandler(w http.ResponseWriter, r *http.Request) {
	next := strings.TrimPrefix(r.URL.Path, openRedirectPathLocationPrefix)
	if next == "" {
		w.Write([]byte("ok"))
		return
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// openRedirectPathLocationBypass wraps the fully-assembled vuln app
// mux, intercepting openRedirectPathLocationPrefix requests before
// they ever reach mux.ServeHTTP -- see
// openRedirectPathLocationPrefix's own doc comment for why. Every
// other request passes through to mux completely unchanged.
func openRedirectPathLocationBypass(mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, openRedirectPathLocationPrefix) {
			openRedirectPathLocationHandler(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
