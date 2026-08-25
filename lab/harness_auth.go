// Phase 3.14/3.15 Authentication & Session-Aware Discovery test
// fixtures.
//
// This file extends the lab (harness.go/harness_vuln.go/harness_inputs.go)
// with a dedicated authentication fixture app: a public endpoint, a
// realistic form-based login endpoint (preserving a hidden CSRF field,
// rejecting bad credentials with no cookie set -- never the "always
// 200" trap), and a small authenticated page graph exercising every
// Phase 3.15 discovery/scope scenario (a profile page, a settings page
// with a real multi-field-type form, a query-parameterized page, a
// JSON API endpoint, a logout/session-invalidation endpoint, and two
// authenticated links to/redirects toward an out-of-scope host). It
// does NOT modify Start's, StartWithVulnerabilities', or
// StartWithInputFixtures' own behavior -- every earlier phase's tests
// are entirely unaffected by this file's existence (the only
// harness.go-adjacent change this phase made is this file's own new
// Lab.AuthAddr field, mirroring VulnAddr/SSRFInternalAddr/InputsAddr's
// own precedent).
//
// Account A and Account B below are TEST-ONLY, intentionally
// hard-coded credentials -- see lab/README.md "Which credentials
// exist." They authenticate against nothing but this in-memory fixture
// and must never be reused anywhere outside the lab.
//
// Page graph (see docs/phase-3-15-authenticated-crawling.md "Lab
// architecture" for the full rationale):
//
//	/ (public)  -->  /public, /login, /account
//	/account (auth)  -->  /dashboard, /profile
//	/dashboard (auth)  -->  /api/data, /search?q=hello (Phase 3.19: reflected-XSS-vulnerable),
//	                        /lookup?id=1 (Phase 3.20: SQLi-vulnerable),
//	                        /lookup-form (Phase 3.21: SQLi-vulnerable POST form, with a CSRF hidden field),
//	                        /search-form (Phase 3.22: reflected-XSS-vulnerable POST form),
//	                        /orders/1, /orders/2 (Phase 3.23: SQLi-vulnerable path segment)
//	/profile (auth)  -->  /settings, external.scanner.test (link),
//	                      /redirect-to-external
//	/settings (auth)  -->  /items?category=books
//	/logout (auth, NOT linked -- reached only by a test that calls it
//	         directly, so it never prematurely ends the ordinary crawl)
package lab

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const ipAuth = "127.0.0.26" // auth.scanner.test

// Account A/B: deterministic, documented, lab-only test credentials
// (Phase 3.14 task section 10's "provide deterministic test
// credentials"). Never used anywhere outside this fixture.
const (
	AccountAUsername = "userA"
	AccountAPassword = "Str0ngPass-A-fixture-only"
	AccountBUsername = "userB"
	AccountBPassword = "Str0ngPass-B-fixture-only"
)

const authSessionCookieName = "sakanner_session"

const authLoginPageHTML = `<html><body>
<h1>Log in</h1>
<form action="/login" method="post">
	<input type="hidden" name="csrf_token" value="lab-fixed-csrf-token">
	<input type="text" name="username">
	<input type="password" name="password">
	<input type="submit" value="Log in">
</form>
</body></html>`

// StartWithAuthFixtures builds and starts everything
// StartWithInputFixtures does (itself a superset of the vuln lab, a
// superset of the base Phase 2 lab), plus this file's own
// authentication fixture app -- additive, never changes any earlier
// Start* function's own behavior.
func StartWithAuthFixtures(gt *GroundTruth) (*Lab, error) {
	l, err := StartWithInputFixtures(gt)
	if err != nil {
		return nil, err
	}
	if err := l.startAuthFixtures(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (l *Lab) startAuthFixtures() error {
	srv, err := newServerOn(ipAuth, newAuthApp().handler())
	if err != nil {
		return err
	}
	l.servers = append(l.servers, srv)
	l.AuthAddr = srv.Listener.Addr().String()

	l.Resolver.Hosts["auth.scanner.test"] = []net.IP{net.ParseIP(ipAuth)}
	return nil
}

// authApp is a small, realistic, in-memory session-based login
// application -- one fixed account map, one server-side session store
// (cookie value -> username), guarded by a mutex since the lab's HTTP
// handlers run concurrently.
type authApp struct {
	mu       sync.Mutex
	sessions map[string]string // session token -> username
}

func newAuthApp() *authApp {
	return &authApp{sessions: map[string]string{}}
}

func (a *authApp) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Deliberately links to /account but NOT /dashboard: /dashboard
		// is only discoverable via a link inside /account's own
		// AUTHENTICATED response body (see requireSession's handler for
		// /account below) -- so a crawl that never receives valid
		// session cookies can reach /account (and observe it refuse
		// access) but can never itself discover /dashboard at all. This
		// is what makes "authenticated endpoint discovered" an
		// observable difference in the crawler's own endpoint list, not
		// just a difference in response body content (see
		// phase3_14_auth_test.go's vertical-slice test).
		fmt.Fprint(w, `<html><body>
			<h1>auth.scanner.test</h1>
			<a href="/public">public</a>
			<a href="/login">login</a>
			<a href="/account">account</a>
		</body></html>`)
	})

	// A. Public endpoint (task section 10.A) -- no authentication
	// required, always reachable.
	//
	// Phase 3.18: also links to the new public JSON/API/JavaScript
	// discovery fixtures below (lab section 16 items 2-5, 10, 11) --
	// kept unauthenticated so these scenarios need no session
	// complexity; items 1/6/7/8 (GET API, authenticated API, Identity
	// A/B) are already fully covered by the existing /api/data
	// fixture, and item 9 (API discovered from HTML) by /dashboard's
	// existing link to /api/data -- no new fixture needed for either.
	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>public page, no auth required
			<a href="/api/nested">nested</a>
			<a href="/api/items">items</a>
			<a href="/api/malformed">malformed</a>
			<script src="/scripts/api-routes.js"></script>
		</body></html>`)
	})

	// Phase 3.18 task section 16 item 3/12: a nested JSON object
	// response, including a field ("profile_url") shaped like an API
	// resource reference -- proves RESPONSE_FIELD-provenance dot-path
	// discovery end to end through a real crawl, and gives a concrete
	// "resource reference in a response" case (task section 9).
	mux.HandleFunc("/api/nested", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"user":{"id":1001,"profile":{"email":"alice@example.test","profile_url":"/api/users/1001"}},"role":"admin"}`)
	})

	// Phase 3.18 task section 16 item 4: a JSON array field -- proves
	// the array-as-one-field representation (never descended into) is
	// reached live, not just in internal/parameters' own unit tests.
	mux.HandleFunc("/api/items", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items":[{"id":1},{"id":2},{"id":3}],"count":3}`)
	})

	// Phase 3.18 task section 16 item 5: a JSON-content-type response
	// with a syntactically invalid body -- proves malformed JSON is
	// handled gracefully (a warning, zero candidates, no crash, no
	// aborted scan) when reached through a REAL crawl, not just
	// ParseJSONBody's own unit tests.
	mux.HandleFunc("/api/malformed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"broken": `)
	})

	// Phase 3.18 task section 6/16 item 2: a JSON-POST-accepting
	// endpoint -- NOT reachable by the crawler itself (which never
	// issues anything but GET, see
	// docs/phase-3-18-api-json-discovery.md section 1), tested
	// directly via internal/mutation.Executor to prove the JSON ->
	// mutation bridge end to end against a real server: it requires a
	// specific CSRF-style header and echoes back the exact user_id it
	// received (never any other value), so a test can prove a mutated
	// request body actually changed what the server received.
	mux.HandleFunc("/api/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("X-Lab-Echo-Auth") != "lab-fixed-echo-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body) // pure echo -- lets a test assert the SERVER actually received the mutated body, not just that Mutate() produced one locally
	})

	// Phase 3.18 task section 16 item 10/11: a script whose text
	// contains API-route-shaped string literals, including one
	// pointing at the pre-existing out-of-scope external.scanner.test
	// host -- proves JS route extraction AND that an out-of-scope
	// JS-derived reference is never persisted as an endpoint (task
	// section 11).
	mux.HandleFunc("/scripts/api-routes.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `
			fetch("/api/nested");
			fetch("/api/items");
			var external = fetch("https://external.scanner.test/api/steal");
			var notARoute = "just a css/class-like string, not a call";
		`)
	})

	// B. Login endpoint (task section 10.B).
	mux.HandleFunc("/login", a.handleLogin)

	// C/D. Authenticated endpoints (task sections 10.C/10.D) -- both
	// gated on the same real server-side session lookup; two distinct
	// paths/markers so a test can independently confirm each is
	// reachable once authenticated.
	mux.HandleFunc("/account", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>Welcome, %s! <a href="/dashboard">dashboard</a> <a href="/profile">profile</a></body></html>`, username)
	}))
	mux.HandleFunc("/dashboard", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>Dashboard for %s -- DASHBOARD_DATA_MARKER <a href="/api/data">api</a> <a href="/search?q=hello">search</a> <a href="/lookup?id=1">lookup</a>
			<a href="/orders/1">order 1</a> <a href="/orders/2">order 2</a>
			<form method="POST" action="/lookup-form"><input type="hidden" name="csrf_token" value="lab-fixed-lookup-csrf-token"><input type="text" name="id" value="1"><button>lookup (POST form)</button></form>
			<form method="POST" action="/search-form"><input type="text" name="q" value="hello"><button>search (POST form)</button></form>
			<a href="/ssrf-fetch?url=https://status.fixture.test/">fetch (SSRF)</a>
			<a href="/ping-exec?host=127.0.0.1">ping (command injection)</a>
			<a href="/download-file?file=index.html">download (path traversal)</a>
			<a href="/redirect-me?next=/dashboard">go (open redirect)</a>
			<a href="/greet-me?name=guest">greet (SSTI)</a>
			<a href="/notes?note_id=5001">my note</a>
			<a href="/documents?doc_id=6001">my document</a>
			<a href="/shared?share_id=7001">shared object</a>
			<a href="/ping?request_id=1">ping</a>
			<a href="/archive?page=1">archive</a>
		</body></html>`, username)
	}))

	// Phase 3.20: an authenticated SQL-injection-vulnerable endpoint --
	// reuses harness_vuln.go's own sqliSimulateQuery (same package,
	// same already-reviewed vulnerability shape as /sqli/vulnerable),
	// now behind a session, so internal/detectors/sqliactive's
	// "authenticated requests, identity context" requirement is
	// provable against a REAL authenticated endpoint.
	mux.HandleFunc("/lookup", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		status, body := sqliSimulateQuery(r.URL.Query().Get("id"))
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))

	// Phase 3.25: an authenticated SSRF-vulnerable endpoint -- reuses
	// harness_ssrf_active.go's own ssrfActiveFetchLoopbackOnly (same
	// package, same already-reviewed loopback-only safety net every
	// other SSRF-active fixture uses), now behind a session, so
	// internal/detectors/ssrfactive's "authenticated requests, identity
	// context" requirement is provable against a REAL authenticated
	// endpoint, and -- run once per identity -- that each identity's
	// own probe only ever carries its own session's cookie.
	mux.HandleFunc("/ssrf-fetch", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		status, body := ssrfActiveFetchLoopbackOnly(r.URL.Query().Get("url"))
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))

	// Phase 3.26: an authenticated command-injection-vulnerable
	// endpoint -- reuses harness_cmdinjection_active.go's own
	// cmdInjectionMatch/cmdInjectionPattern (same safe, lab-only
	// protocol every other command-injection fixture uses), now behind
	// a session, mirroring /ssrf-fetch's Phase 3.25 precedent exactly.
	// Deliberately does NOT echo the raw "host" value back anywhere in
	// its response (unlike harness_vuln.go's own /api/ping/* fixtures,
	// which safely coexist alone on the unauthenticated lab) -- this
	// endpoint sits on the SAME authenticated scan as /search's own
	// genuine reflected-XSS fixture, and xssactive's own reflection
	// classifier (internal/detectors/xssactive/reflection.go) has no
	// Content-Type awareness, so an unescaped echo here would make this
	// fixture ALSO accidentally look like reflected XSS once both are
	// discovered in the same scan -- a real cross-fixture interaction
	// discovered during this phase's own regression, fixed by keeping
	// this fixture focused on demonstrating command injection only.
	mux.HandleFunc("/ping-exec", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		if token, ok := cmdInjectionMatch(cmdInjectionPattern, host); ok {
			fmt.Fprintf(w, "ping executed\n%s%s", cmdInjectionMarkerPrefix, token)
			return
		}
		fmt.Fprint(w, "ping executed")
	}))

	// Phase 3.27: an authenticated path-traversal-vulnerable endpoint --
	// reuses harness_traversal_active.go's own travResolve (same
	// travSynthFS synthetic filesystem every other traversal fixture
	// uses), now behind a session, mirroring /ping-exec's own Phase
	// 3.26 precedent -- including its own "never echo the raw value"
	// safety lesson: this handler never places the raw "file" value
	// anywhere in its response, only the resolved file's own content
	// (which is either legitimate static content or -- if the
	// traversal succeeds -- the protected marker itself), so it can
	// never accidentally look like reflected XSS to xssactive once
	// both fixtures are discovered in the same authenticated scan.
	mux.HandleFunc("/download-file", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		file := r.URL.Query().Get("file")
		w.Header().Set("Content-Type", "text/plain")
		content, ok := travResolve(file)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "not found")
			return
		}
		fmt.Fprint(w, content)
	}))

	// Phase 3.28: an authenticated open-redirect-vulnerable endpoint --
	// zero validation, mirroring /redirect/open/vulnerable's own
	// existing unauthenticated behavior exactly, now behind a session,
	// mirroring /download-file's Phase 3.27 precedent. A redirect
	// response carries no reflected body content at all, so the
	// cross-fixture reflected-XSS concern /ping-exec's own doc comment
	// describes does not apply here.
	mux.HandleFunc("/redirect-me", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.Write([]byte("ok"))
			return
		}
		http.Redirect(w, r, next, http.StatusFound)
	}))

	// Phase 3.29: an authenticated SSTI-vulnerable endpoint -- reuses
	// harness_ssti_active.go's own sstiSimulateRender (same package,
	// same fake, safe "template engine" every other SSTI fixture
	// uses), now behind a session, mirroring /redirect-me's Phase 3.28
	// precedent. Only ever reflects an HTML-escaped literal for
	// non-matching input, so it cannot accidentally look like
	// reflected XSS to xssactive once discovered in the same
	// authenticated scan as /search.
	mux.HandleFunc("/greet-me", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		if result, ok := sstiSimulateRender(name); ok {
			fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", result)
			return
		}
		fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", html.EscapeString(name))
	}))

	// Phase 3.21: the identical vulnerability, reached as a POST form
	// field instead of a query parameter -- proves form-location active
	// mutation works against a REAL authenticated endpoint, with a
	// genuine (though lab-fixed, non-secret) CSRF hidden field present
	// alongside the vulnerable "id" field, so a positive finding here
	// also proves the CSRF field survived every probe unchanged.
	mux.HandleFunc("/lookup-form", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		status, body := sqliSimulateQuery(r.FormValue("id"))
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))

	// Phase 3.23: the identical vulnerability, reached as a URL path
	// segment instead of a query parameter -- proves path-location
	// active mutation works against a REAL authenticated endpoint.
	// /orders/1 and /orders/2 are both linked from /dashboard so a real
	// crawl has the >=2-endpoints evidence internal/parameters.InferPathInputs
	// requires.
	mux.HandleFunc("/orders/", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		id := strings.TrimPrefix(r.URL.Path, "/orders/")
		status, body := sqliSimulateQuery(id)
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))

	// Phase 3.19: an authenticated reflected-XSS-vulnerable endpoint --
	// reuses this file's own session infrastructure so
	// internal/detectors/xssactive's "authenticated requests, identity
	// context" requirement is provable against a REAL authenticated
	// endpoint, not just an unauthenticated one. Deliberately
	// unescaped, mirroring lab/harness_vuln.go's own
	// /xss/reflected/vulnerable fixture exactly (same vulnerability
	// shape, now behind a session).
	mux.HandleFunc("/search", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>%s searched for: %s</p></body></html>", username, q) // deliberately unescaped
	}))

	// Phase 3.22: the identical vulnerability, reached as a POST form
	// field instead of a query parameter -- proves internal/detectors/xssactive's
	// new form-location adapter works against a REAL authenticated
	// endpoint, mirroring /lookup-form's own Phase 3.21 precedent for
	// SQLi.
	mux.HandleFunc("/search-form", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		q := r.FormValue("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>%s searched for: %s</p></body></html>", username, q) // deliberately unescaped
	}))

	// Phase 3.15 task section O.4: authenticated profile page. Also the
	// home of the two authenticated scope-adversarial links task
	// sections O.9/O.10 require: a plain link to the pre-existing
	// out-of-scope external.scanner.test host, and a link to this
	// file's own /redirect-to-external endpoint (an authenticated
	// redirect toward that same out-of-scope host).
	mux.HandleFunc("/profile", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>Profile for %s (user_id=%d) -- PROFILE_DATA_MARKER
			<a href="/settings">settings</a>
			<a href="http://external.scanner.test/">external site</a>
			<a href="/redirect-to-external">redirect test</a>
		</body></html>`, username, userIDFor(username))
	}))

	// Phase 3.15 task section O.6: authenticated page containing forms
	// -- a realistic multi-field-type settings form (hidden CSRF,
	// text, select, checkbox, radio -- task section D's exact list),
	// discovered by the SAME internal/parameters pipeline any other
	// form already is, no second implementation. POSTing without the
	// correct CSRF token is rejected, mirroring /login's own
	// hidden-field-preservation requirement.
	mux.HandleFunc("/settings", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil || r.FormValue("csrf_token") != "lab-fixed-settings-csrf-token" {
				http.Error(w, "missing or invalid csrf token", http.StatusBadRequest)
				return
			}
			w.Write([]byte("settings saved"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<form action="/settings" method="post">
				<input type="hidden" name="csrf_token" value="lab-fixed-settings-csrf-token">
				<input type="text" name="display_name" value="">
				<select name="theme"><option value="light">Light</option><option value="dark" selected>Dark</option></select>
				<input type="checkbox" name="newsletter" value="1">
				<input type="radio" name="visibility" value="public" checked>
				<input type="radio" name="visibility" value="private">
			</form>
			<a href="/items?category=books">items</a>
		</body></html>`)
	}))

	// Phase 3.15 task section O.7: authenticated page containing
	// parameters -- a query-parameterized page, discovered the same
	// way an unauthenticated query parameter already is.
	mux.HandleFunc("/items", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>items for category -- ITEMS_DATA_MARKER</body></html>`)
	}))

	// Phase 3.15 task section O.5: authenticated endpoint/API -- JSON,
	// not HTML, matching how a real authenticated API reference would
	// look; still recorded as a discovered Endpoint (crawler.Page
	// carries StatusCode/URL regardless of content type) even though
	// no further links are extracted from it.
	//
	// Phase 3.16 task section 16: the numeric user_id here always
	// reflects the CALLER's own session (via requireSession's lookup),
	// never any other account's -- Account A always gets 1001, Account
	// B always gets 1002, regardless of what either requests. This is
	// what proves "Account A session != Account B session" and
	// "Account A discovered data != Account B discovered data" (see
	// lab/phase3_16_multi_identity_test.go) WITHOUT the lab itself
	// being vulnerable to IDOR/BOLA in any way -- there is no code path
	// here that could ever return a different account's user_id; task's
	// explicit "do NOT make the lab automatically report an IDOR
	// finding."
	mux.HandleFunc("/api/data", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"user":%q,"user_id":%d,"marker":"API_DATA_MARKER"}`, username, userIDFor(username))
	}))

	// Phase 3.15 task section O.10 (redirect variant): an authenticated
	// endpoint that redirects to the pre-existing out-of-scope
	// external.scanner.test host -- safedial's own CheckRedirect must
	// refuse to follow it exactly as it would for an unauthenticated
	// redirect; authentication changes nothing about this check.
	mux.HandleFunc("/redirect-to-external", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		http.Redirect(w, r, "http://external.scanner.test/", http.StatusFound)
	}))

	// Phase 3.15 task section O.8: logout/session-expiration scenario.
	// Deliberately NOT linked from anywhere in the page graph above --
	// a test that wants to exercise session expiration calls this
	// directly (outside of a crawl), then crawls again with the (now
	// invalidated) session cookie to observe detectSessionExpired's
	// behavior. Linking it from the normal graph would make EVERY
	// authenticated crawl test racy against its own traversal order.
	mux.HandleFunc("/logout", a.requireSession(func(w http.ResponseWriter, r *http.Request, username string) {
		if c, err := r.Cookie(authSessionCookieName); err == nil {
			a.mu.Lock()
			delete(a.sessions, c.Value)
			a.mu.Unlock()
		}
		w.Write([]byte("logged out"))
	}))

	// Adversarial fixtures (task section 15 / section 8's scope
	// scenarios) -- deliberately NOT linked from "/", only reached by a
	// test that names the path directly, so the ordinary crawl/vertical
	// slice scenario above never touches them.
	mux.HandleFunc("/login-external-action", func(w http.ResponseWriter, r *http.Request) {
		// A login form whose action points at the pre-existing,
		// out-of-scope external.scanner.test host (established by
		// harness.go) -- task's "form action outside scope."
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="http://external.scanner.test/steal" method="post">
			<input type="text" name="username"><input type="password" name="password">
		</form></body></html>`)
	})
	registerAuthorizationFixtures(a, mux)

	mux.HandleFunc("/login-external-redirect", func(w http.ResponseWriter, r *http.Request) {
		// Validates credentials exactly like /login, but on success
		// redirects to the out-of-scope external.scanner.test instead of
		// /account -- task's "redirect outside scope."
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, strings.Replace(authLoginPageHTML, `action="/login"`, `action="/login-external-redirect"`, 1))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if !a.validCredentials(r.FormValue("username"), r.FormValue("password")) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "login failed")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: authSessionCookieName, Value: a.newSession(r.FormValue("username")), Path: "/"})
		http.Redirect(w, r, "http://external.scanner.test/", http.StatusFound)
	})

	// /subpath-app/* is a general-purpose (never DVWA-specific) fixture
	// for validating start-URL/base-path support: an application hosted
	// under a subpath that "/" has no link into at all, whose own login
	// handler additionally gates real-world-realistically on its own
	// named submit button being present in the POST body (a common
	// server-side idiom, e.g. PHP's own isset($_POST['do_login'])) --
	// proving BOTH that crawling can be pointed at a subpath AND that a
	// login form's submit-button field round-trips into the actual
	// submission, not merely its username/password fields.
	mux.HandleFunc("/subpath-app/", a.handleSubpathIndex)
	mux.HandleFunc("/subpath-app/login", a.handleSubpathLogin)
	mux.HandleFunc("/subpath-app/dashboard", a.requireSubpathSession(func(w http.ResponseWriter, r *http.Request, username string) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><h1>Subpath App Dashboard</h1><p>Welcome, %s.</p>
<a href="/subpath-app/profile?section=overview">View profile</a>
</body></html>`, username)
	}))
	mux.HandleFunc("/subpath-app/profile", a.requireSubpathSession(func(w http.ResponseWriter, r *http.Request, username string) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><p>Profile section: %s</p></body></html>`, r.URL.Query().Get("section"))
	}))

	return mux
}

const subpathAppSessionCookieName = "subpath_app_session"

// handleSubpathIndex is the application's own base/index page ("/" for
// a scan pointed at this subpath, exactly like a real application's
// index.php at e.g. /DVWA/) -- registered as its own Go ServeMux
// subtree pattern ("/subpath-app/") alongside the more specific exact
// routes below, so it only ever serves the base path itself. Mirrors
// a common real-world pattern (an unauthenticated visitor is bounced
// to the login page; an authenticated one sees the app's own landing
// page, which links deeper into the app) so that a crawl STARTING at
// this base path -- rather than at a page some other test's root
// fixture happens to link into -- can reach /subpath-app/dashboard
// purely through the base path's own in-app links, the same way a
// real crawl pointed at /DVWA/ reaches DVWA's own pages.
func (a *authApp) handleSubpathIndex(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(subpathAppSessionCookieName)
	if err != nil {
		http.Redirect(w, r, "/subpath-app/login", http.StatusFound)
		return
	}
	a.mu.Lock()
	username, ok := a.sessions[cookie.Value]
	a.mu.Unlock()
	if !ok {
		http.Redirect(w, r, "/subpath-app/login", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<html><body><h1>Subpath App</h1><p>Welcome, %s.</p>
<a href="/subpath-app/dashboard">Dashboard</a>
</body></html>`, username)
}

func (a *authApp) handleSubpathLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><form action="/subpath-app/login" method="post">
  <input type="hidden" name="csrf_token" value="lab-fixed-csrf-token">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" name="do_login" value="Log In">
</form></body></html>`)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.FormValue("csrf_token") != "lab-fixed-csrf-token" {
		http.Error(w, "missing or invalid csrf token", http.StatusBadRequest)
		return
	}
	// Gate real-world-realistically on the submit button's own name --
	// a request missing it (e.g. one built by code that drops
	// type="submit" fields) must be rejected exactly like DVWA itself
	// rejects one, so this fixture can prove the fix rather than merely
	// assert it.
	if r.FormValue("do_login") == "" {
		http.Error(w, "missing submit field", http.StatusBadRequest)
		return
	}
	username, password := r.FormValue("username"), r.FormValue("password")
	if !a.validCredentials(username, password) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "login failed: invalid credentials")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: subpathAppSessionCookieName, Value: a.newSession(username), Path: "/"})
	http.Redirect(w, r, "/subpath-app/dashboard", http.StatusFound)
}

func (a *authApp) requireSubpathSession(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(subpathAppSessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/subpath-app/login", http.StatusFound)
			return
		}
		a.mu.Lock()
		username, ok := a.sessions[cookie.Value]
		a.mu.Unlock()
		if !ok {
			http.Redirect(w, r, "/subpath-app/login", http.StatusFound)
			return
		}
		next(w, r, username)
	}
}

func (a *authApp) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, authLoginPageHTML)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// The hidden CSRF field must round-trip unmodified -- a submission
	// missing or altering it is rejected outright, exactly like
	// internal/auth's own basicLoginApp test fixture, so a real
	// production login flow's hidden-field-preservation is exercised
	// end-to-end here too, not only in internal/auth's unit tests.
	if r.FormValue("csrf_token") != "lab-fixed-csrf-token" {
		http.Error(w, "missing or invalid csrf token", http.StatusBadRequest)
		return
	}
	username, password := r.FormValue("username"), r.FormValue("password")
	if !a.validCredentials(username, password) {
		// Deliberately 401 with NO cookie set -- never "200 regardless of
		// credentials" (task section 4's explicit trap).
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "login failed: invalid credentials")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: authSessionCookieName, Value: a.newSession(username), Path: "/"})
	http.Redirect(w, r, "/account", http.StatusFound)
}

func (a *authApp) validCredentials(username, password string) bool {
	switch username {
	case AccountAUsername:
		return password == AccountAPassword
	case AccountBUsername:
		return password == AccountBPassword
	default:
		return false
	}
}

// AccountAUserID/AccountBUserID are Phase 3.16 task section 16's
// deterministic, distinct numeric identifiers for the two lab
// accounts -- "Account A: user_id = 1001, Account B: user_id = 1002."
const (
	AccountAUserID = 1001
	AccountBUserID = 1002
)

// userIDFor returns the numeric user_id for a lab username -- 0 for
// anything else (unreachable in practice, since every handler that
// calls this only ever does so with a username requireSession itself
// already validated against Account A/B).
func userIDFor(username string) int {
	switch username {
	case AccountAUsername:
		return AccountAUserID
	case AccountBUsername:
		return AccountBUserID
	default:
		return 0
	}
}

// newSession mints a fresh, random session token bound to username --
// deliberately random (not a deterministic function of username) so a
// fresh scan never reuses a previous scan's own session value, matching
// how a real application behaves; this does NOT make the SCANNER's own
// AUTHENTICATION STATE non-deterministic (task section 16) -- given the
// same credentials and the same lab, the scanner reaches the same
// State (AUTHENTICATED) and discovers the same account content every
// time, which is the property task section 16 actually requires, not
// byte-identical cookie values (see docs/phase-3-14-authentication.md
// "Determinism").
func (a *authApp) newSession(username string) string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	token := hex.EncodeToString(buf)
	a.mu.Lock()
	a.sessions[token] = username
	a.mu.Unlock()
	return token
}

func (a *authApp) requireSession(fn func(w http.ResponseWriter, r *http.Request, username string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(authSessionCookieName)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "unauthorized: please log in")
			return
		}
		a.mu.Lock()
		username, ok := a.sessions[c.Value]
		a.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "unauthorized: please log in")
			return
		}
		fn(w, r, username)
	}
}
