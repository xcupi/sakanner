// Phase 3 Security Test Laboratory fixtures.
//
// This file extends the Phase 2 Test Laboratory (harness.go) with a
// dedicated vulnerable/safe fixture pair for every vulnerability class
// the ground truth in ground-truth-vulnerabilities.yaml documents. It
// does NOT modify anything in harness.go -- Phase 2 tests keep calling
// Start() directly and are entirely unaffected by this file's existence.
// Phase 3 tests call StartWithVulnerabilities instead, which is a strict
// superset.
//
// IMPORTANT: no vulnerability detection is implemented anywhere in this
// codebase yet. Every handler below is a genuinely vulnerable (or
// genuinely safe) implementation -- the vulnerability is real
// application behavior, not a hard-coded fake finding -- but nothing
// here scans, exploits, or reports on it. That is Phase 3's job, not
// this lab's.
package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Fixed loopback addresses for the Phase 3 fixtures, continuing the
// numbering harness.go established (127.0.0.11-18 are Phase 2's; these
// are unused by anything else in the lab).
const (
	ipVuln           = "127.0.0.21" // vuln.scanner.test
	ipSSRFInternal   = "127.0.0.22" // ssrf-internal.scanner.test
	ipSSRFCallback   = "127.0.0.23" // Phase 3.4's out-of-band callback recorder (callback.go) -- not a DNS-resolvable lab hostname, only ever addressed by its literal IP:port (see docs/phase-3-4-ssrf.md "Callback architecture")
	ipFormSecondHost = "127.0.0.27" // second-service.scanner.test -- Phase 3.22's genuinely separate, separately-in-scope second host
)

// StartWithVulnerabilities builds and starts everything Start does, plus
// the Phase 3 vulnerability-fixture services. Phase 2 tests must keep
// using Start directly; this function is additive and never changes
// Start's own behavior.
func StartWithVulnerabilities(gt *GroundTruth) (*Lab, error) {
	l, err := Start(gt)
	if err != nil {
		return nil, err
	}
	if err := l.startVulnFixtures(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// SSRFInternalAddr and VulnAddr are set once startVulnFixtures runs, for
// tests that need to dial the fixtures' literal addresses directly
// (mirroring how harness.go exposes RedirectHTTPAddr for the same
// reason: some scenarios are tested by pointing production dialing code
// at a specific sub-path, not through the standard root-path-only
// probe/crawl flow).
func (l *Lab) startVulnFixtures() error {
	// The SSRF-internal service must exist before the vulnerable app's
	// SSRF handler is built, since ground truth points the fixture's own
	// "reachable internal service" at it.
	internalSrv, err := newServerOn(ipSSRFInternal, ssrfInternalHandler())
	if err != nil {
		return err
	}
	l.servers = append(l.servers, internalSrv)
	l.SSRFInternalAddr = internalSrv.Listener.Addr().String()

	// The second-host service must also exist before vulnAppHandler is
	// built, since /forms/index's own cross-origin (but separately
	// in-scope) form fixture needs its real, already-allocated address
	// -- see docs/phase-3-22-active-detection-coverage.md section 7 and
	// registerFormMutation's own doc comment.
	secondSrv, err := newServerOn(ipFormSecondHost, formSecondHostHandler())
	if err != nil {
		return err
	}
	l.servers = append(l.servers, secondSrv)
	l.FormSecondHostAddr = secondSrv.Listener.Addr().String()

	vulnSrv, err := newServerOn(ipVuln, vulnAppHandler(l.SSRFInternalAddr, l.FormSecondHostAddr))
	if err != nil {
		return err
	}
	l.servers = append(l.servers, vulnSrv)
	l.VulnAddr = vulnSrv.Listener.Addr().String()

	callback, callbackSrv, err := newSSRFCallbackServer(ipSSRFCallback)
	if err != nil {
		return err
	}
	l.servers = append(l.servers, callbackSrv)
	l.SSRFCallback = callback

	set := func(host, ip string) { l.Resolver.Hosts[host] = []net.IP{netParseIP(ip)} }
	set("vuln.scanner.test", ipVuln)
	set("ssrf-internal.scanner.test", ipSSRFInternal)
	set("second-service.scanner.test", ipFormSecondHost)

	return nil
}

func netParseIP(s string) net.IP { return net.ParseIP(s) }

// ssrfInternalHandler is the "internal service" the SSRF-vulnerable
// fixture can reach -- it is never added as a scan Target and carries no
// scope rule of its own; it exists purely so the SSRF fixture has a real
// (lab-internal, harmless) destination to demonstrably fetch.
func ssrfInternalHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"service":"ssrf-internal-fixture","status":"reached","note":"this response is only reachable via server-side requests from vuln.scanner.test's SSRF fixture -- if you are seeing this from anywhere else, something is misconfigured"}`))
	})
}

// formSecondHostHandler is second-service.scanner.test's own, entirely
// independent app -- Phase 3.22's genuinely separate, separately-
// in-scope second host (docs/phase-3-22-active-detection-coverage.md
// section 7). One fixture: a POST-form-vulnerable SQLi endpoint,
// reusing sqliSimulateQuery verbatim (same package, same
// already-reviewed vulnerability shape every other /sqli/* fixture
// uses) -- proving a cross-origin-but-in-scope form mutation reaches
// REAL active detection end to end, not merely that a Target with the
// right Host gets constructed.
func formSecondHostHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/echo/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		status, body := sqliSimulateQuery(r.FormValue("id"))
		w.WriteHeader(status)
		w.Write([]byte(body))
	})
	return mux
}

// vulnAppHandler registers every Phase 3 fixture pair. ssrfInternalAddr
// is the literal host:port of ssrf-internal.scanner.test's listener,
// needed so the SSRF-vulnerable handler has something real to fetch.
// formSecondHostAddr (Phase 3.22) is second-service.scanner.test's own
// listener address, needed so /forms/index's cross-origin-in-scope
// form fixture has a real, already-allocated port to point at.
func vulnAppHandler(ssrfInternalAddr, formSecondHostAddr string) http.Handler {
	mux := http.NewServeMux()

	registerIndex(mux)
	registerReflectedXSS(mux)
	registerStoredXSS(mux)
	registerSQLInjection(mux)
	registerAuthWeakness(mux)
	registerIDOR(mux)
	registerPathTraversal(mux)
	registerPathTraversalAPI(mux)
	registerPathTraversalActive(mux)
	registerLFI(mux)
	registerCommandInjectionAPI(mux)
	registerCommandInjectionActive(mux)
	registerSSRF(mux, ssrfInternalAddr)
	registerSSRFActive(mux)
	registerOpenRedirect(mux)
	registerOpenRedirectActive(mux)
	registerSSTIActive(mux)
	registerMisconfiguration(mux)
	registerInfoExposure(mux)
	registerInsecureCookies(mux)
	registerCORS(mux)
	registerMissingHeaders(mux)
	registerVulnerableComponent(mux)
	registerExposedAdmin(mux)
	registerDirectoryListing(mux)
	registerFormMutation(mux, formSecondHostAddr)
	registerPathParameters(mux)

	return openRedirectPathLocationBypass(travPathLocationBypass(mux))
}

// registerIndex serves the fixture app's root page, linking to every
// fixture pair (so the crawler can discover them) plus a link to the
// established Phase 2 out-of-scope host, exercising "a vulnerable
// endpoint links to an out-of-scope host" (see ground-truth-vulnerabilities.yaml's
// scope_enforcement_scenarios section).
func registerIndex(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><title>sakanner lab: vuln.scanner.test</title></head><body>
<h1>Phase 3 Security Test Laboratory fixtures</h1>
<p>Every link below is a deterministic, synthetic, local-only fixture. None of this is real software or real data.</p>
<ul>
<li><a href="/xss/reflected/vulnerable?q=test">reflected XSS (vulnerable)</a> / <a href="/xss/reflected/safe?q=test">safe</a></li>
<li><a href="/xss/reflected/attribute/vulnerable?name=test">reflected XSS: attribute context (vulnerable)</a> / <a href="/xss/reflected/attribute/safe?name=test">safe</a></li>
<li><a href="/xss/reflected/unrelated?q=test">reflected XSS: non-reflected parameter (negative fixture)</a></li>
<li><a href="/xss/reflected/static-decoy?q=test">reflected XSS: static decoy content (negative fixture)</a></li>
<li><a href="/xss/stored/vulnerable">stored XSS (vulnerable)</a> / <a href="/xss/stored/safe">safe</a></li>
<li><a href="/sqli/vulnerable?id=1">SQL injection (vulnerable)</a> / <a href="/sqli/safe?id=1">safe</a></li>
<li><a href="/sqli/boolean/vulnerable?id=1">SQL injection: boolean-only, no error text (vulnerable)</a> / <a href="/sqli/boolean/safe?id=1">safe</a></li>
<li><a href="/sqli/generic-error?id=1">SQL injection: generic unrelated error (negative fixture)</a></li>
<li><a href="/sqli/dynamic?id=1">SQL injection: dynamic normal response (negative fixture)</a></li>
<li><a href="/auth/weak-credentials">weak credentials (vulnerable)</a> / <a href="/auth/strong-credentials">safe</a></li>
<li><a href="/idor/vulnerable/user/1">IDOR (vulnerable)</a> / <a href="/idor/safe/user/1">safe</a></li>
<li><a href="/idor/api/resource/vulnerable?resource_id=resource-a">IDOR/BOLA: query-parameter object reference (vulnerable)</a> / <a href="/idor/api/resource/vulnerable?resource_id=resource-b">resource-b</a> / <a href="/idor/api/resource/safe?resource_id=resource-a">safe (resource-a)</a> / <a href="/idor/api/resource/safe?resource_id=resource-b">safe (resource-b)</a></li>
<li><a href="/idor/api/resource/safe?resource_id=resource-public">IDOR/BOLA: public resource (negative fixture)</a> / <a href="/idor/api/resource/safe?resource_id=does-not-exist">invalid resource ID (negative fixture)</a></li>
<li><a href="/idor/api/resource/generic?resource_id=resource-a">IDOR/BOLA: generic response, no protected-resource evidence (negative fixture)</a> / <a href="/idor/api/resource/generic?resource_id=resource-b">resource-b</a></li>
<li><a href="/files/traversal/vulnerable?name=readme.txt">path traversal (vulnerable)</a> / <a href="/files/traversal/safe?name=readme.txt">safe</a></li>
<li><a href="/files/download/vulnerable?file=index.html">path traversal: query-parameter download (vulnerable)</a> / <a href="/files/download/safe?file=index.html">safe</a></li>
<li><a href="/files/download/sanitized?file=index.html">path traversal: blocklist-sanitized (negative fixture)</a></li>
<li><a href="/files/download/by-id?file=1">path traversal: ID-based lookup, no path construction (negative fixture)</a></li>
<li><a href="/files/download/reflect?file=index.html">path traversal: reflection only (negative fixture)</a></li>
<li><a href="/files/download/generic?file=index.html">path traversal: generic response, no protected-resource evidence (negative fixture)</a></li>
<li><a href="/files/download/path/report-1.txt">path traversal: path-location, example 1 (vulnerable)</a> / <a href="/files/download/path/report-2.txt">example 2</a></li>
<li><a href="/files/lfi/vulnerable?page=home">LFI (vulnerable)</a> / <a href="/files/lfi/safe?page=home">safe</a></li>
<li><a href="/api/ping/vulnerable?host=127.0.0.1">command injection: ping endpoint (vulnerable)</a> / <a href="/api/ping/safe?host=127.0.0.1">safe</a></li>
<li><a href="/api/ping/sanitized?host=127.0.0.1">command injection: metacharacter-stripped (negative fixture)</a></li>
<li><a href="/api/ping/by-id?host=1">command injection: ID-based lookup, no command construction (negative fixture)</a></li>
<li><a href="/api/ping/reflect?host=127.0.0.1">command injection: reflection only (negative fixture)</a></li>
<li><a href="/api/ping/generic?host=127.0.0.1">command injection: generic response, no execution evidence (negative fixture)</a></li>
<li><a href="/api/ping/static-marker?host=127.0.0.1">command injection: static marker text unrelated to execution (negative fixture)</a></li>
<li><a href="/api/ping/vulnerable-windows?host=127.0.0.1">command injection: Windows cmd.exe-style separators (vulnerable)</a></li>
<li><a href="/api/ping/error?host=127.0.0.1">command injection: generic application error (negative fixture)</a></li>
<li><a href="/api/ping/host/127.0.0.1-a">command injection: path-location, example 1 (vulnerable)</a> / <a href="/api/ping/host/127.0.0.1-b">example 2</a></li>
<li><a href="/ssrf/vulnerable?url=http://ssrf-internal.scanner.test/">SSRF (vulnerable)</a> / <a href="/ssrf/safe?url=https://status.fixture.test/health">safe</a></li>
<li><a href="/ssrf/reflect-only?url=https://status.fixture.test/">SSRF: reflection only (negative fixture)</a></li>
<li><a href="/ssrf/store-only?url=https://status.fixture.test/">SSRF: stored but not fetched (negative fixture)</a></li>
<li><a href="/ssrf/client-fetch?url=https://status.fixture.test/">SSRF: client-side fetch only (negative fixture)</a></li>
<li><a href="/ssrf/validate-reject?url=https://status.fixture.test/">SSRF: validation rejects (negative fixture)</a></li>
<li><a href="/ssrf/vulnerable-blind?url=https://status.fixture.test/">SSRF: blind/OOB only, response never reveals fetch outcome (vulnerable)</a></li>
<li><a href="/ssrf/fetch/https%3A%2F%2Fstatus.fixture.test%2Fpath-1">SSRF: path-location, example 1 (vulnerable)</a> / <a href="/ssrf/fetch/https%3A%2F%2Fstatus.fixture.test%2Fpath-2">example 2</a></li>
<li><a href="/redirect/open/vulnerable?next=/dashboard">open redirect (vulnerable)</a> / <a href="/redirect/open/safe?next=/dashboard">safe</a></li>
<li><a href="/redirect/open/next/report-1">open redirect: path-location, example 1 (vulnerable)</a> / <a href="/redirect/open/next/report-2">example 2</a></li>
<li><a href="/redirect/safe-origin?next=/dashboard">open redirect: same-origin validated (negative fixture)</a></li>
<li><a href="/redirect/relative-only?next=/dashboard">open redirect: relative-only (negative fixture)</a></li>
<li><a href="/redirect/reflect-only?next=/dashboard">open redirect: reflection only, no redirect (negative fixture)</a></li>
<li><a href="/redirect/tracking-decoy?next=/dashboard">open redirect: tracking decoy (negative fixture)</a></li>
<li><a href="/redirect/chain/in-scope?next=/dashboard">open redirect: chain stays in scope (negative fixture)</a> / <a href="/redirect/chain/out-of-scope?next=/dashboard">chain leaves scope (vulnerable)</a></li>
<li><a href="/ssti/vulnerable?name=guest">SSTI (vulnerable)</a> / <a href="/ssti/safe?name=guest">safe</a> / <a href="/ssti/generic?name=guest">generic (negative fixture)</a></li>
<li><a href="/ssti/greet/guest-1">SSTI: path-location, example 1 (vulnerable)</a> / <a href="/ssti/greet/guest-2">example 2</a></li>
<li><a href="/misconfig/stacktrace/vulnerable">verbose error (vulnerable)</a> / <a href="/misconfig/stacktrace/safe">safe</a></li>
<li><a href="/info/exposure/vulnerable">info exposure (vulnerable)</a> / <a href="/info/exposure/safe">safe</a></li>
<li><a href="/cookies/insecure/vulnerable">insecure cookie (vulnerable)</a> / <a href="/cookies/insecure/safe">safe</a></li>
<li><a href="/cors/vulnerable">CORS misconfiguration (vulnerable)</a> / <a href="/cors/safe">safe</a></li>
<li><a href="/headers/missing/vulnerable">missing security headers (vulnerable)</a> / <a href="/headers/missing/safe">safe</a></li>
<li><a href="/component/vulnerable">known-vulnerable component (vulnerable)</a> / <a href="/component/safe">safe</a></li>
<li><a href="/admin/exposed">exposed admin panel (vulnerable)</a> / <a href="/admin/protected">safe</a></li>
<li><a href="/directory-listing/vulnerable/">directory listing (vulnerable)</a> / <a href="/directory-listing/safe/">safe</a></li>
<li><a href="/forms/index">Phase 3.21 form fixtures (GET/POST forms, hidden/textarea/select/checkbox/radio, CSRF token, relative action, out-of-scope action)</a></li>
<li><a href="/paths/index">Phase 3.23 path parameter fixtures (numeric/non-numeric path IDs, version segments)</a></li>
</ul>
<a href="http://external.scanner.test/">external reference (out of scope -- must never be dialed by the scanner)</a>
</body></html>`))
	})
}

// --- 1. Reflected XSS -------------------------------------------------
//
// Phase 3.2 added four fixtures here (attribute/vulnerable,
// attribute/safe, unrelated, static-decoy) alongside the original
// text-context pair from Phase 3, specifically to give
// internal/detectors/xssreflected something to distinguish: a second
// reflection CONTEXT (attribute, not just HTML text) and two distinct
// flavors of "reflection that must not become a finding" (a parameter
// that plainly isn't reflected at all, versus a page whose STATIC
// content happens to already contain XSS-payload-shaped text having
// nothing to do with the parameter -- proving the detector correlates
// its own probe marker, not just "does the page contain <script>
// anywhere").

func registerReflectedXSS(mux *http.ServeMux) {
	mux.HandleFunc("/xss/reflected/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>You searched for: %s</p></body></html>", q) // deliberately unescaped
	})
	mux.HandleFunc("/xss/reflected/safe", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>You searched for: %s</p></body></html>", htmlEscape(q))
	})

	// Attribute context: the value lands inside an HTML attribute
	// instead of text content -- vulnerable reflects it completely
	// unescaped (a literal `"` in the input breaks out of the
	// attribute), safe HTML-attribute-encodes it first.
	mux.HandleFunc("/xss/reflected/attribute/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><form><input type="text" name="name" value="%s" placeholder="enter your name"></form></body></html>`, name) // deliberately unescaped
	})
	mux.HandleFunc("/xss/reflected/attribute/safe", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><form><input type="text" name="name" value="%s" placeholder="enter your name"></form></body></html>`, htmlEscape(name))
	})

	// Phase 3.22: a POST-form-vulnerable reflected XSS endpoint --
	// deliberately reused, unmodified, error-free-of-any-vulnerability-
	// specific-logic mirror of /xss/reflected/vulnerable's own
	// identical unescaped-reflection shape, just reached via a form
	// field instead of a query parameter (matching /sqli/form/vulnerable's
	// own precedent from Phase 3.20). The real <form method="POST">
	// submitting to this lives on /forms/index (registerFormMutation).
	mux.HandleFunc("/xss/reflected/form-vulnerable", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		q := r.FormValue("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><p>You searched for: %s</p></body></html>", q) // deliberately unescaped
	})

	// Negative: the parameter exists but has NO effect on the response
	// at all -- there is nothing to reflect, safely or otherwise.
	mux.HandleFunc("/xss/reflected/unrelated", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><h1>Static page</h1><p>This page does not use its query parameters for anything.</p></body></html>`))
	})

	// Negative: the response's STATIC markup already contains
	// XSS-payload-shaped text (a documentation snippet showing an
	// example of vulnerable code), unconditionally, regardless of the
	// parameter -- a detector that just searches the page for
	// "<script>" rather than correlating its OWN probe marker would
	// false-positive here every single time.
	mux.HandleFunc("/xss/reflected/static-decoy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><h1>Security examples</h1><p>Example of vulnerable code (do not copy): <code>&lt;script&gt;alert(1)&lt;/script&gt; -- also shown raw for illustration: <script>legacyExampleWidget()</script></code></p></body></html>`))
	})

	// Phase 3.19: a JSON API endpoint that echoes a request body field
	// back verbatim in a JSON response -- internal/detectors/xssactive's
	// "JSON parameters where applicable" requirement, and a concrete
	// case for the ReflectionJSONString classification (a value
	// reflected inside a JSON response is not itself proof of HTML/JS
	// execution -- reported at lower confidence, see
	// docs/phase-3-19-active-detection.md section 8). Never itself
	// vulnerable to anything beyond "reflects what it was given" -- no
	// HTML is ever rendered by this endpoint.
	mux.HandleFunc("/xss/reflected/json-echo", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		echoed, _ := json.Marshal(map[string]string{"echo": body.Name})
		w.Write(echoed)
	})
}

// --- 2. Stored XSS ------------------------------------------------------
//
// State is a closure-local variable, not a package-level global, so
// every fresh Lab (every Start/StartWithVulnerabilities call, including
// across different tests in the same test binary) gets its own isolated
// storage -- a prior test's stored payload can never leak into a later
// one.

func registerStoredXSS(mux *http.ServeMux) {
	var mu sync.Mutex
	vulnComment := "(no comment submitted yet)"
	safeComment := "(no comment submitted yet)"

	mux.HandleFunc("/xss/stored/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			vulnComment = r.FormValue("comment")
			mu.Unlock()
			w.Write([]byte("submitted"))
			return
		}
		mu.Lock()
		c := vulnComment
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><form method="post"><input name="comment"><button>Submit</button></form><div id="comment">%s</div></body></html>`, c) // unescaped on output
	})
	mux.HandleFunc("/xss/stored/safe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mu.Lock()
			safeComment = r.FormValue("comment")
			mu.Unlock()
			w.Write([]byte("submitted"))
			return
		}
		mu.Lock()
		c := safeComment
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><form method="post"><input name="comment"><button>Submit</button></form><div id="comment">%s</div></body></html>`, htmlEscape(c))
	})
}

// --- 3. SQL injection (simulated -- no real database anywhere) ---------

type sqliRow struct{ ID, Name string }

func sqliFakeDB() []sqliRow {
	return []sqliRow{{"1", "alice"}, {"2", "bob"}, {"3", "admin"}}
}

func registerSQLInjection(mux *http.ServeMux) {
	mux.HandleFunc("/sqli/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		db := sqliFakeDB()
		// A naive, unparameterized "query" simulation: a bare quote is
		// treated as breaking out of a string literal, exactly like real
		// string-concatenated SQL would behave.
		if strings.Contains(id, "'") {
			if strings.Contains(strings.ToLower(id), `' or '1'='1`) {
				var names []string
				for _, row := range db {
					names = append(names, row.Name)
				}
				fmt.Fprintf(w, "results: %s", strings.Join(names, ", "))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "SQL syntax error near '%s' (simulated -- no real database exists in this fixture)", id)
			return
		}
		for _, row := range db {
			if row.ID == id {
				fmt.Fprintf(w, "results: %s", row.Name)
				return
			}
		}
		w.Write([]byte("results: (none)"))
	})
	mux.HandleFunc("/sqli/safe", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id") // always treated as an opaque, parameterized value -- quotes have no special meaning
		for _, row := range sqliFakeDB() {
			if row.ID == id {
				fmt.Fprintf(w, "results: %s", row.Name)
				return
			}
		}
		w.Write([]byte("results: (none)"))
	})

	// Phase 3.3 additions below: a pure BOOLEAN-differential vulnerable/
	// safe pair (no error text ever surfaces, unlike /sqli/vulnerable
	// above -- proving internal/detectors/sqli's boolean-based signal
	// works independently of its error-based one), plus two additional
	// "must not be a finding" negative shapes beyond simple
	// parameterization: a generically-erroring endpoint unrelated to
	// SQL, and a dynamic endpoint whose normal responses vary in ways
	// that have nothing to do with the parameter.

	// Boolean-only: a malformed/quoted id never produces an error --
	// it silently falls through to "no rows", exactly like a query
	// wrapped in a blanket try/catch that swallows DB exceptions. Only
	// the tautology case behaves differently (all rows), so the ONLY
	// way to detect this one is by comparing true vs. false conditions,
	// never by looking for error text.
	mux.HandleFunc("/sqli/boolean/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		db := sqliFakeDB()
		if strings.Contains(id, "'") {
			if strings.Contains(strings.ToLower(id), `' or '1'='1`) {
				var names []string
				for _, row := range db {
					names = append(names, row.Name)
				}
				fmt.Fprintf(w, "results: %s", strings.Join(names, ", "))
				return
			}
			w.Write([]byte("results: (none)")) // no error, ever -- the only signal is the true/false differential
			return
		}
		for _, row := range db {
			if row.ID == id {
				fmt.Fprintf(w, "results: %s", row.Name)
				return
			}
		}
		w.Write([]byte("results: (none)"))
	})
	mux.HandleFunc("/sqli/boolean/safe", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		for _, row := range sqliFakeDB() {
			if row.ID == id {
				fmt.Fprintf(w, "results: %s", row.Name)
				return
			}
		}
		w.Write([]byte("results: (none)"))
	})

	// Negative: ALWAYS returns a generic 500 regardless of input --
	// including a plain, unmodified baseline request -- and the error
	// text deliberately DOES contain a database-error-shaped phrase
	// ("Database error"), specifically so a detector that only checks
	// "does the probe response contain database-error wording" (without
	// also comparing against baseline behavior) would false-positive
	// here. A detector that correlates the probe's error against the
	// SAME baseline behavior must recognize nothing changed and stay
	// silent.
	mux.HandleFunc("/sqli/generic-error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Database error: something went wrong processing your request. Please try again later."))
	})

	// Negative: the response always includes a deterministic-but-
	// varying footer (a monotonically increasing request counter,
	// formatted to look like a timestamp/request-id) that has nothing
	// to do with the id parameter -- exercising response normalization.
	// The MEANINGFUL content ("results: (none)") never changes.
	var dynamicMu sync.Mutex
	dynamicRequestCount := 0
	mux.HandleFunc("/sqli/dynamic", func(w http.ResponseWriter, r *http.Request) {
		dynamicMu.Lock()
		dynamicRequestCount++
		n := dynamicRequestCount
		dynamicMu.Unlock()
		fmt.Fprintf(w, "results: (none)\n<!-- server-time: 2024-01-01T00:00:%02dZ request-id: %d -->", n%60, n)
	})

	// Phase 3.20: a POST-form-parameter vulnerable endpoint and a
	// JSON-body-parameter vulnerable endpoint -- the identical,
	// already-reviewed naive-string-concatenation simulation
	// /sqli/vulnerable already uses, just reached via a different
	// input location. No new "database," no new vulnerability shape.
	mux.HandleFunc("/sqli/form/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		status, body := sqliSimulateQuery(r.FormValue("id"))
		w.WriteHeader(status)
		w.Write([]byte(body))
	})
	mux.HandleFunc("/sqli/json/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		var reqBody struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&reqBody)
		_, resultBody := sqliSimulateQuery(reqBody.ID)
		w.Header().Set("Content-Type", "application/json")
		echoed, _ := json.Marshal(map[string]string{"result": resultBody})
		w.Write(echoed)
	})
}

// sqliSimulateQuery is the ONE naive, unparameterized "query"
// simulation every /sqli/* vulnerable fixture (query, form, JSON body
// alike) shares -- factored out here (Phase 3.20) so the form/JSON
// variants above are byte-for-byte the same vulnerability shape as the
// original /sqli/vulnerable, not a second, independently-maintained
// copy that could quietly drift. Returns (status, body) rather than
// writing directly, so both an http.ResponseWriter-backed handler and
// a JSON-wrapping handler can reuse it identically.
func sqliSimulateQuery(id string) (status int, body string) {
	db := sqliFakeDB()
	if strings.Contains(id, "'") {
		if strings.Contains(strings.ToLower(id), `' or '1'='1`) {
			var names []string
			for _, row := range db {
				names = append(names, row.Name)
			}
			return http.StatusOK, fmt.Sprintf("results: %s", strings.Join(names, ", "))
		}
		return http.StatusInternalServerError, fmt.Sprintf("SQL syntax error near '%s' (simulated -- no real database exists in this fixture)", id)
	}
	for _, row := range db {
		if row.ID == id {
			return http.StatusOK, fmt.Sprintf("results: %s", row.Name)
		}
	}
	return http.StatusOK, "results: (none)"
}

// --- 4. Authentication weakness (default/weak credentials) -------------
//
// All credentials here are synthetic, fixture-only strings with no
// relationship to any real system or account.

func registerAuthWeakness(mux *http.ServeMux) {
	mux.HandleFunc("/auth/weak-credentials", func(w http.ResponseWriter, r *http.Request) {
		u, p := r.URL.Query().Get("username"), r.URL.Query().Get("password")
		if u == "admin" && p == "admin" {
			w.Write([]byte("login successful: welcome admin"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("login failed"))
	})
	mux.HandleFunc("/auth/strong-credentials", func(w http.ResponseWriter, r *http.Request) {
		u, p := r.URL.Query().Get("username"), r.URL.Query().Get("password")
		if u == "testuser" && p == "Xk9#mP2vQ7zL!bR4-fixture-only" {
			w.Write([]byte("login successful"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("login failed"))
	})
}

// --- 5. IDOR / authorization ---------------------------------------------
//
// "Sessions" are a fixed, synthetic cookie->user mapping -- not real
// authentication, just enough state to demonstrate horizontal
// authorization failure deterministically.

func registerIDOR(mux *http.ServeMux) {
	mux.HandleFunc("/idor/vulnerable/user/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/idor/vulnerable/user/")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"%s","email":"user%s@fixture.test","note":"returned regardless of which session cookie was presented"}`, id, id)
	})
	mux.HandleFunc("/idor/safe/user/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/idor/safe/user/")
		sessionUser := ""
		if c, err := r.Cookie("session"); err == nil {
			sessionUser = strings.TrimPrefix(c.Value, "user")
		}
		if sessionUser != id {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"%s","email":"user%s@fixture.test"}`, id, id)
	})

	// Phase 3.5 addition: a QUERY-PARAMETER-based IDOR/BOLA fixture pair
	// -- the pair above uses a PATH segment for the object identifier
	// (/idor/vulnerable/user/{id}), which Phase 3.1's target-selection
	// model (internal/detection.BuildTargets) still only extracts
	// candidates from QUERY strings, not path segments -- see
	// ground-truth-vulnerabilities.yaml's requires_capability note on
	// VULN-IDOR-001 and docs/phase-3-5-idor-bola.md "Limitations" for
	// why that fixture therefore remains undetectable by any automated
	// detector even now, while THIS one (identical vulnerability class,
	// just a query parameter instead of a path segment) is what
	// internal/detectors/idor is actually verified against.
	//
	// Caller identity is a synthetic, clearly-labeled test-only header
	// (X-Test-Auth-User) -- not a real authentication scheme, not a
	// real session/token/cookie mechanism, and never validated against
	// anything beyond a fixed in-memory map of two synthetic users. See
	// docs/phase-3-5-idor-bola.md "Authentication assumptions."
	registerIDORAPI(mux)
}

type idorResource struct {
	Owner  string // "" for a public resource, otherwise "user-a"/"user-b"
	Marker string // synthetic, resource-specific marker -- proves exactly WHICH resource's content was returned
	Public bool
}

// idorAPIResources is the Phase 3.5 lab's synthetic multi-user
// resource ground truth: exactly what section 1 of the task asks for,
// nothing more. Both "vulnerable" and "safe" handlers below share this
// same data so the only difference between them is the authorization
// check itself.
var idorAPIResources = map[string]idorResource{
	"resource-a":      {Owner: "user-a", Marker: "RESOURCE_A_SECRET_MARKER"},
	"resource-b":      {Owner: "user-b", Marker: "RESOURCE_B_SECRET_MARKER"},
	"resource-public": {Public: true, Marker: "PUBLIC_RESOURCE_MARKER"},
}

func registerIDORAPI(mux *http.ServeMux) {
	// Vulnerable: returns whatever resource_id is asked for, in full,
	// regardless of the X-Test-Auth-User header -- no ownership check
	// at all.
	mux.HandleFunc("/idor/api/resource/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("resource_id")
		res, ok := idorAPIResources[id]
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"not found","id":"%s"}`, id)
			return
		}
		fmt.Fprintf(w, `{"id":"%s","owner":"%s","marker":"%s"}`, id, res.Owner, res.Marker)
	})

	// Safe: verifies the caller's identity (X-Test-Auth-User) against
	// the resource's owner before returning it -- a public resource is
	// returned to anyone, exactly like a real "intentionally public"
	// object would be.
	mux.HandleFunc("/idor/api/resource/safe", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("resource_id")
		res, ok := idorAPIResources[id]
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"not found","id":"%s"}`, id)
			return
		}
		if res.Public {
			fmt.Fprintf(w, `{"id":"%s","owner":"","marker":"%s","public":true}`, id, res.Marker)
			return
		}
		caller := r.Header.Get("X-Test-Auth-User")
		if caller == "" || caller != res.Owner {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		fmt.Fprintf(w, `{"id":"%s","owner":"%s","marker":"%s"}`, id, res.Owner, res.Marker)
	})

	// Negative: a generic, constant response regardless of resource_id
	// or caller -- exercises the "generic HTTP 200 without protected-
	// resource evidence" false-positive case. Deliberately never
	// reflects the requested id anywhere in its body.
	mux.HandleFunc("/idor/api/resource/generic", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
}

// --- 6. Path traversal (synthetic in-memory "filesystem" only) ---------

func registerPathTraversal(mux *http.ServeMux) {
	// A synthetic in-memory map, never the real filesystem. The
	// traversal-shaped key demonstrates that the vulnerable handler
	// performs no path containment check -- it happens to be a map
	// lookup here rather than a real os.Open, but the vulnerability
	// class (unsanitized path-like input reaching a resource lookup) is
	// the same one a real traversal bug exhibits.
	synthFiles := map[string]string{
		"readme.txt":                   "sakanner lab fixture: hello from the traversal fixture",
		"../../../etc/passwd":          "sakanner-lab-synthetic-fixture-file:not-a-real-passwd-file:0:0::/fixture:/bin/fixture",
		"..\\..\\..\\windows\\win.ini": "; sakanner lab synthetic fixture file, not a real Windows file",
	}
	mux.HandleFunc("/files/traversal/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		content, ok := synthFiles[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
			return
		}
		w.Write([]byte(content))
	})
	mux.HandleFunc("/files/traversal/safe", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		allowed := map[string]string{"readme.txt": "sakanner lab fixture: hello from the safe traversal fixture", "about.txt": "about this fixture"}
		content, ok := allowed[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
			return
		}
		w.Write([]byte(content))
	})
}

// travSynthFS is the Phase 3.6 lab's synthetic filesystem: a flat map
// keyed by CLEAN, relative-to-lab-root paths, never touching the real
// filesystem. "public/" is the allowed root every fixture is meant to
// restrict access to; "protected/" is a sibling directory a real
// application would never expose through the download endpoint --
// escaping into it via "../" is exactly the vulnerability class this
// phase detects. See docs/phase-3-6-path-traversal.md "Test lab
// architecture" for the full design, and ground-truth-vulnerabilities.yaml's
// VULN-TRAVERSAL-API-* entries for this fixture's ground truth.
var travSynthFS = map[string]string{
	"public/index.html":           "<html><body>PUBLIC_FILE_MARKER <!-- see also ../docs/readme for details, a normal file that happens to contain traversal-looking text --></body></html>",
	"public/public-marker.txt":    "PUBLIC_FILE_MARKER",
	"protected/secret-marker.txt": "PATH_TRAVERSAL_SECRET_MARKER",
	// Phase 3.27's own two path-location crawl-discovery example links
	// (/files/download/path/report-1.txt, report-2.txt) point here so
	// their baseline ("legitimate access") probe succeeds with a real
	// 200 body, exactly like every other example link's target already
	// must.
	"public/report-1.txt": "PUBLIC_FILE_MARKER report 1",
	"public/report-2.txt": "PUBLIC_FILE_MARKER report 2",
	// "public" (the directory itself, path.Clean(path.Join("public",
	// "")) with an empty file value) -- reachable only via
	// /files/download/vulnerable-json's baseline probe, whose
	// JSON-body location has no seeded value to mutate from
	// (detection.NewMutationRequest has no JSON-seeding mechanism), so
	// it legitimately arrives with an empty body/empty "file" field.
	// Without this entry the baseline 404s and the JSON fixture's own
	// looksAllowed reachability gate never opens.
	"public": "index of public/",
}

// travByIDFS is a SEPARATE, small ID->path allowlist for the
// /files/download/by-id negative fixture (section 11.3's "parameterized/
// safely resolved file access") -- deliberately never constructs a
// filesystem path from the request at all, so no traversal-shaped input
// can ever reach a path-join operation in the first place.
var travByIDFS = map[string]string{
	"1": travSynthFS["public/index.html"],
	"2": travSynthFS["public/public-marker.txt"],
}

// registerPathTraversalAPI is the Phase 3.6 addition: a QUERY-PARAMETER-
// based download endpoint family (`?file=`), matching Phase 3.1's
// existing query-parameter-only target-selection model -- unlike
// registerPathTraversal's `/files/traversal/*` pair above (Phase 3
// foundational work, parameter name "name", not in Phase 3.6's
// object-reference heuristic and never updated to use one -- see that
// fixture's ground-truth entry for why it stays out of reach of
// internal/detectors/traversal).
func registerPathTraversalAPI(mux *http.ServeMux) {
	// Vulnerable: naively joins the allowed root ("public") with the
	// untrusted "file" value and cleans the result -- path.Clean
	// legitimately resolves ".." segments (exactly like a real
	// filesystem/path-join traversal bug would), it just never verifies
	// the CLEANED result actually stayed inside "public/" before using
	// it as a lookup key. This is the positive fixture.
	mux.HandleFunc("/files/download/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		resolved := path.Clean(path.Join("public", file))
		content, ok := travSynthFS[resolved]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(content))
	})

	// Safe: resolves and cleans the same way, but then explicitly
	// verifies the cleaned path is still contained within "public/"
	// before ever using it as a lookup key -- proper canonicalization +
	// containment verification, not a substring blocklist. Section 3's
	// "secure fixture."
	mux.HandleFunc("/files/download/safe", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		resolved := path.Clean(path.Join("public", file))
		if resolved != "public" && !strings.HasPrefix(resolved, "public/") {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("forbidden: outside the allowed root"))
			return
		}
		content, ok := travSynthFS[resolved]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(content))
	})

	// Sanitized: a DIFFERENT (still-effective, against this lab's own
	// probe set) safety strategy than "safe" above -- rejects any
	// DECODED value containing ".." outright, before any path
	// construction happens at all. Since Go's own net/http query
	// parsing already decodes single-level percent-encoding (%2e, %2F)
	// before this handler ever sees the value, this blocklist check
	// catches every representation this project's detector generates
	// (raw, dot-encoded, slash-encoded, combined) uniformly -- see
	// docs/phase-3-6-path-traversal.md "Encoding handling" for why this
	// is honestly documented as "effective against this deterministic
	// probe set," not a universally unbeatable filter.
	mux.HandleFunc("/files/download/sanitized", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "..") {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("forbidden: traversal sequence rejected"))
			return
		}
		resolved := path.Clean(path.Join("public", file))
		content, ok := travSynthFS[resolved]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(content))
	})

	// By-ID: section 11.3's "parameterized/safely resolved file access"
	// -- the "file" parameter is just an opaque allowlist key, never
	// concatenated into a path at all. A traversal-shaped value is
	// simply not a valid key -- 404, same as any other unknown key.
	mux.HandleFunc("/files/download/by-id", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("file")
		content, ok := travByIDFS[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(content))
	})

	// Reflect: echoes the requested value back into the response --
	// never reads any file content, synthetic or otherwise. Proves the
	// detector distinguishes "the input string was reflected" from "the
	// protected file's content was returned" (section 10).
	mux.HandleFunc("/files/download/reflect", func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Requested file: %s", file)
	})

	// Generic: a fixed, constant response regardless of "file" or any
	// other input -- never reflects the requested resource at all.
	// Section 11.5's "generic HTTP 200 unrelated to requested file."
	mux.HandleFunc("/files/download/generic", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})
}

// --- 7. Local file inclusion (synthetic templates only) -----------------

func registerLFI(mux *http.ServeMux) {
	synthTemplates := map[string]string{
		"home":                       "welcome home",
		"../../../etc/passwd":        "sakanner-lab-synthetic-fixture-file:not-a-real-passwd-file",
		"php://filter/resource=home": "sakanner lab fixture: simulated PHP wrapper response, not a real interpreter",
	}
	mux.HandleFunc("/files/lfi/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "text/html")
		tmpl, ok := synthTemplates[page]
		if !ok {
			fmt.Fprintf(w, "<html><body>page not found: %s</body></html>", htmlEscape(page))
			return
		}
		fmt.Fprintf(w, "<html><body>%s</body></html>", tmpl)
	})
	mux.HandleFunc("/files/lfi/safe", func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		allowed := map[string]string{"home": "welcome home", "about": "about us"}
		w.Header().Set("Content-Type", "text/html")
		tmpl, ok := allowed[page]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("<html><body>not found</body></html>"))
			return
		}
		fmt.Fprintf(w, "<html><body>%s</body></html>", tmpl)
	})
}

// --- 7.5. Command injection (pure Go pattern matching only -- NEVER a
// real shell) ---------------------------------------------------------
//
// Phase 3.7 addition. Every handler below simulates "the application
// passed this value to a shell command" using nothing but Go string/
// regexp matching against a small, deterministic, LAB-ONLY grammar --
// none of them ever call os/exec, ever invoke a real shell, or ever
// touch a real system resource. The "vulnerable" behavior being
// demonstrated is realistic (unsanitized input reaching command
// construction), but the mechanism proving it is entirely synthetic:
// recognizing a fixed separator character immediately followed by the
// fake, lab-only "command name" cmdInjectionLabCommand and a
// caller-supplied correlation token, and echoing that token back
// wrapped in cmdInjectionMarkerPrefix. See
// docs/phase-3-7-command-injection.md "Test lab architecture" for the
// full design and why this is safe.

// cmdInjectionLabCommand is a deliberately fake command name -- not
// "echo", not any real shell builtin or binary -- so nothing about
// this fixture's grammar could ever be mistaken for, or accidentally
// generalize to, real shell syntax.
const cmdInjectionLabCommand = "sakanner_lab_echo"

// cmdInjectionMarkerPrefix plus a caller-supplied token is the only
// thing that ever constitutes "confirmed execution" -- see
// internal/detectors/cmdinjection's exact-match requirement.
const cmdInjectionMarkerPrefix = "COMMAND_INJECTION_MARKER:"

// cmdInjectionPattern recognizes ";", "|", or "&&", optional
// whitespace, the fake lab command name, whitespace, and a token (any
// non-whitespace run) -- and nothing else. Pure regexp matching against
// a Go string; no shell of any kind is ever invoked.
var cmdInjectionPattern = regexp.MustCompile(`(?:;|\||&&)\s*` + regexp.QuoteMeta(cmdInjectionLabCommand) + `\s+(\S+)`)

func registerCommandInjectionAPI(mux *http.ServeMux) {
	// Vulnerable: simulates an application that builds a shell command
	// from "host" with no sanitization -- if the recognized lab-only
	// grammar appears anywhere in the value, "execution" (a pure Go
	// regexp match) succeeds and the correlated marker is returned.
	// Otherwise the value is treated as an opaque, harmless string.
	mux.HandleFunc("/api/ping/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		if m := cmdInjectionPattern.FindStringSubmatch(host); m != nil {
			fmt.Fprintf(w, "PING %s: normal response (simulated, no real ping ever executed)\n%s%s", host, cmdInjectionMarkerPrefix, m[1])
			return
		}
		fmt.Fprintf(w, "PING %s: normal response (simulated, no real ping ever executed)", host)
	})

	// Safe: strict allowlist (hostname/IP-shaped characters only) --
	// rejects anything containing the shell metacharacters the
	// vulnerable grammar depends on, BEFORE any pattern matching is
	// even attempted. Covers both "safe argument handling" and "input
	// validation" (two distinct ground-truth fixtures, one endpoint --
	// see VULN-CMDI-API-NEG-001 / VULN-CMDI-API-VALIDATION-NEG-001).
	mux.HandleFunc("/api/ping/safe", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		if !cmdInjectionSafeHostPattern.MatchString(host) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid host: rejected (contains disallowed characters)"))
			return
		}
		fmt.Fprintf(w, "PING %s: normal response (simulated, no real ping ever executed)", host)
	})

	// Sanitized: a DIFFERENT (still effective, against this detector's
	// own probe set) strategy than "safe" above -- strips every
	// recognized shell separator character from the DECODED value
	// before attempting the same grammar match "safe"'s sibling
	// "vulnerable" handler would otherwise perform. Since every probe
	// variant needs one of ";", "|", "&" to introduce the lab command,
	// stripping those characters neutralizes the grammar regardless of
	// which encoding delivered it.
	mux.HandleFunc("/api/ping/sanitized", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		stripped := cmdInjectionMetacharacters.ReplaceAllString(host, "")
		if m := cmdInjectionPattern.FindStringSubmatch(stripped); m != nil {
			fmt.Fprintf(w, "PING %s: normal response (simulated)\n%s%s", host, cmdInjectionMarkerPrefix, m[1])
			return
		}
		fmt.Fprintf(w, "PING %s: normal response (simulated, metacharacters treated as plain text)", host)
	})

	// By-ID: "host" is only ever an opaque allowlist key -- never
	// concatenated into anything resembling a command at all. A
	// command-injection-shaped value is simply not a valid key.
	mux.HandleFunc("/api/ping/by-id", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("host")
		allowed := map[string]string{"1": "127.0.0.1", "2": "10.0.0.5"}
		w.Header().Set("Content-Type", "text/plain")
		target, ok := allowed[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("unknown host id"))
			return
		}
		fmt.Fprintf(w, "PING %s: normal response (simulated, no real ping ever executed)", target)
	})

	// Reflect: echoes the requested value back into the response --
	// never attempts any grammar match, never "executes" anything.
	// Proves the detector distinguishes "the input string was
	// reflected" from "the lab's simulated command actually ran"
	// (section 9).
	mux.HandleFunc("/api/ping/reflect", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Requested host: %s", host)
	})

	// Generic: a fixed, constant response regardless of "host" or any
	// other input.
	mux.HandleFunc("/api/ping/generic", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Static marker: ALWAYS includes the literal substring
	// "COMMAND_INJECTION_MARKER" in its response, regardless of input --
	// but never with a ":" and a real per-probe token following it. A
	// detector that only checked for the bare substring (rather than
	// the exact prefix+token combination) would false-positive here;
	// this fixture exists specifically to prove it doesn't (section
	// 4.7 / section 12's "marker exists in static content").
	mux.HandleFunc("/api/ping/static-marker", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "PING %s: normal response\n<!-- lab documentation: this fixture demonstrates COMMAND_INJECTION_MARKER text appearing in unrelated static content, never correlated with any real probe -->", host)
	})
}

// cmdInjectionSafeHostPattern allows only hostname/IPv4-shaped
// characters -- deliberately excludes every character the vulnerable
// grammar's separators need (";", "|", "&", whitespace).
var cmdInjectionSafeHostPattern = regexp.MustCompile(`^[a-zA-Z0-9.\-]+$`)

// cmdInjectionMetacharacters matches the exact separator characters the
// vulnerable grammar recognizes -- stripping them (not blocklisting
// substrings) is what "sanitized" demonstrates as a distinct strategy
// from "safe"'s allowlist.
var cmdInjectionMetacharacters = regexp.MustCompile(`[;|&]`)

// --- 8. SSRF -------------------------------------------------------------

func registerSSRF(mux *http.ServeMux, ssrfInternalAddr string) {
	mux.HandleFunc("/ssrf/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		u, err := url.Parse(target)
		if err != nil || u.Hostname() == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad url"))
			return
		}
		// LAB SAFETY NET -- not a fix to the vulnerability itself. This
		// fixture never validates WHICH lab-internal service is an
		// acceptable destination (that would be the actual fix a real
		// application needs); it only guarantees it can never reach
		// anything outside 127.0.0.0/8, so this lab can never make a
		// real external request no matter what URL a test (or, if
		// misused, anything else) supplies.
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte("fixture safety net: only 127.0.0.0/8 destinations are permitted from this lab fixture"))
			return
		}
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(target)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "fetch failed: %v", err)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		fmt.Fprintf(w, "fetched %s: %s", target, body)
	})
	mux.HandleFunc("/ssrf/safe", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		allowed := map[string]bool{"https://status.fixture.test/health": true}
		if !allowed[target] {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("destination not in allowlist"))
			return
		}
		// Deliberately never actually fetched, even for the allowlisted
		// case -- a real safe implementation would still only reach
		// pre-approved destinations; this fixture demonstrates the
		// allowlist check without needing a live dependency.
		w.Write([]byte("ok (allowlisted destination only)"))
	})

	// Phase 3.4 additions below: four more negative shapes beyond
	// "safe allowlist" (/ssrf/safe above), each a distinct reason a URL
	// parameter must NOT be flagged -- see
	// internal/detectors/ssrf and docs/phase-3-4-ssrf.md.

	// Negative: the URL is reflected into the response but NEVER
	// fetched server-side.
	mux.HandleFunc("/ssrf/reflect-only", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>you provided: %s</body></html>", htmlEscape(target))
	})

	// Negative: the URL is accepted and "stored" (discarded, in this
	// synthetic fixture -- no real persistence anywhere) as if
	// registering a webhook for later, asynchronous use -- but nothing
	// about handling THIS request ever fetches it.
	mux.HandleFunc("/ssrf/store-only", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("saved"))
	})

	// Negative: the URL is embedded in an <img> tag -- it would only
	// ever be fetched by a BROWSER rendering the page (client-side),
	// never by the server itself.
	mux.HandleFunc("/ssrf/client-fetch", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><img src="%s" alt="preview"></body></html>`, htmlEscape(target))
	})

	// Negative: validation requires the destination host to be an
	// allowlisted partner domain -- any probe's URL (always pointing at
	// the lab's own callback recorder) is rejected before any fetch is
	// even attempted.
	mux.HandleFunc("/ssrf/validate-reject", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		u, err := url.Parse(target)
		if err != nil || u.Hostname() != "partner.fixture.test" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("url not in allowed partner list"))
			return
		}
		w.Write([]byte("ok")) // unreachable for any probe this detector sends
	})

	_ = ssrfInternalAddr // documented in ground truth as the fixture's reachable internal target; not otherwise needed by this handler (the URL is caller-supplied, per the vulnerability)
}

// --- 9. Open redirect -----------------------------------------------------

func registerOpenRedirect(mux *http.ServeMux) {
	mux.HandleFunc("/redirect/open/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		http.Redirect(w, r, next, http.StatusFound) // no validation at all
	})
	mux.HandleFunc("/redirect/open/safe", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		allowed := map[string]bool{"/dashboard": true, "/profile": true}
		if !allowed[next] {
			next = "/dashboard"
		}
		http.Redirect(w, r, next, http.StatusFound)
	})
}

// --- 10. Security misconfiguration (verbose error / stack trace) -------

func registerMisconfiguration(mux *http.ServeMux) {
	mux.HandleFunc("/misconfig/stacktrace/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Traceback (most recent call last):\n"+
			`  File "app.py", line 42, in handle_request`+"\n"+
			"    result = db.execute(query)\n"+
			"sakanner.lab.fixture.SyntheticDatabaseError: connection to db-internal.fixture.test:5432 refused\n"+
			`DEBUG = True | SECRET_KEY = "sakanner-lab-fixture-not-a-real-secret-000111222"`+"\n")
	})
	mux.HandleFunc("/misconfig/stacktrace/safe", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("An unexpected error occurred. Please try again later."))
	})
}

// --- 11. Sensitive information exposure ---------------------------------

func registerInfoExposure(mux *http.ServeMux) {
	mux.HandleFunc("/info/exposure/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><!-- TODO: remove before prod. api_key=sk_test_SAKANNER_LAB_FIXTURE_0000000000 --><body>Welcome</body></html>`)
	})
	mux.HandleFunc("/info/exposure/safe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>Welcome</body></html>`)
	})
}

// --- 12. Insecure HTTP security configuration (cookie flags) -----------

func registerInsecureCookies(mux *http.ServeMux) {
	mux.HandleFunc("/cookies/insecure/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "synthetic-fixture-session-token-000", Path: "/"})
		w.Write([]byte("session set"))
	})
	mux.HandleFunc("/cookies/insecure/safe", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name: "session", Value: "synthetic-fixture-session-token-001", Path: "/",
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
		})
		w.Write([]byte("session set"))
	})
}

// --- 13. CORS misconfiguration -------------------------------------------

func registerCORS(mux *http.ServeMux) {
	mux.HandleFunc("/cors/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin) // reflects any origin
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":"sensitive-fixture-data"}`))
	})
	mux.HandleFunc("/cors/safe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://scanner.test") // fixed, specific origin
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":"sensitive-fixture-data"}`))
	})
}

// --- 14. Missing or weak security headers --------------------------------

func registerMissingHeaders(mux *http.ServeMux) {
	mux.HandleFunc("/headers/missing/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>no security headers here</body></html>"))
	})
	mux.HandleFunc("/headers/missing/safe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Write([]byte("<html><body>fully configured</body></html>"))
	})
}

// --- 15. Known vulnerable software/component ------------------------------
//
// Reuses this package's own current-jQuery fixture (appJS, jQuery 3.6.0,
// already embedded and used by scanner.test/js.scanner.test in Phase 2)
// for the safe counterpart, rather than duplicating it -- and a real,
// long-EOL jQuery version banner string for the vulnerable one. This
// directly exercises Phase 2's already-built technology/version
// fingerprinting: the version this fixture serves is exactly what a
// future Phase 3 "known vulnerable component" detector would need to
// read out of an already-populated Technology row.

func registerVulnerableComponent(mux *http.ServeMux) {
	mux.HandleFunc("/component/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><script src="/component/old-jquery.js"></script></head><body>legacy page</body></html>`))
	})
	mux.HandleFunc("/component/old-jquery.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		// A real jQuery 1.6.1 banner string (long past end-of-life,
		// affected by multiple real, public CVEs) used only as a
		// deterministic version-string fixture -- the file's actual
		// behavior is irrelevant here, only the banner sakanner's
		// fingerprinter reads.
		w.Write([]byte("/*! jQuery v1.6.1 jquery.com | jquery.org/license */"))
	})
	mux.HandleFunc("/component/safe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><script src="/component/current-jquery.js"></script></head><body>current page</body></html>`))
	})
	mux.HandleFunc("/component/current-jquery.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(appJS) // the same jQuery 3.6.0 fixture already used elsewhere in this lab
	})
}

// --- 16. Exposed administrative/debug endpoint ---------------------------

func registerExposedAdmin(mux *http.ServeMux) {
	mux.HandleFunc("/admin/exposed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>Admin Panel</h1><p>Synthetic fixture admin panel, no authentication required.</p></body></html>"))
	})
	mux.HandleFunc("/admin/protected", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sakanner-lab-fixture-admin-token-000" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>Admin Panel</h1></body></html>"))
	})
}

// --- 17. Directory listing -------------------------------------------------

func registerDirectoryListing(mux *http.ServeMux) {
	mux.HandleFunc("/directory-listing/vulnerable/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><ul><li><a href="config.bak">config.bak</a></li><li><a href="backup.sql">backup.sql</a></li></ul></body></html>`))
	})
	mux.HandleFunc("/directory-listing/safe/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden"))
	})
}

// htmlEscape is a tiny local wrapper so every "safe" handler above uses
// the exact same escaping call, matching the pattern already established
// in internal/reporting/markdown.go's mdEscape for the same reason
// (consistent, auditable escaping of untrusted-shaped content).
func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&#34;",
		"'", "&#39;",
	)
	return r.Replace(s)
}
