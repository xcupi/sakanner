# Phase 3.15: Authenticated Crawling & Session-Aware Discovery

## 1. Purpose

Phase 3.14 built the authentication foundation (`internal/auth`): profiles,
providers, a `Session` abstraction, and a login vertical slice. Phase
3.15 extends that foundation so the scanner can *maintain* an
authenticated session *while crawling*, discovering the authenticated
application's attack surface -- pages, forms, parameters, and API
references reachable only once logged in -- while never weakening scope
enforcement, secret protection, determinism, or isolation between
scans.

Given valid credentials supplied by the authorized operator, the
scanner establishes an authenticated session and safely discovers the
application's authenticated attack surface, preserving scope,
isolation, determinism, and secret protection. That is the entire
scope of this phase -- see section 12, "Explicitly out of scope," for
everything it deliberately does not do.

## 2. What already existed vs. what this phase added

Phase 3.14 already wired a `*auth.Session` into the crawl stage
(`internal/orchestration.Pipeline.AuthSession`, threaded into
`crawler.Options`), so "authenticated crawling" in the loosest sense
already worked. This phase's real work was found by testing that
integration harder, not by building a second one:

| Area | Phase 3.14 state | Phase 3.15 change |
|---|---|---|
| Cookie carrying | `Options.Cookies []*http.Cookie`, attached once per request | `Options.Jar http.CookieJar` -- the session's own live jar, handling every request AND redirect hop automatically, and capturing session-refresh cookies back into the session |
| Header carrying | Attached once per request, no per-hop re-check | `safedial.PinnedRoundTripper` -- shared with `internal/auth.Session.NewClient`, checked per actual outgoing request |
| Session expiration | Not detected at all | `internal/orchestration.detectSessionExpired` (401/403 detection) + `AuthCrawlStats`/`Result.SessionExpired` |
| Public vs. authenticated discovery | Not distinguished | `Result.CrawlSummary` (`PublicURLs`/`AuthenticatedURLs`/`AuthenticatedEndpoints`), `Result.AuthenticatedRequests` |
| CLI `--profile web --auth-profile <name>` together | Wired but never tested end to end | `TestScanCmd_ProfileWebAndAuthProfile_AuthenticatedCrawlDiscoversSecretPage` (tests/e2e) proves it through the real binary |
| CSRF field redaction | `csrf`/`csrf_token`/`xsrf` NOT in the sensitive-field blocklist | Added -- a real gap, found via a pre-existing Phase 3.13 test that (wrongly) asserted a CSRF field's raw value |
| Lab authenticated page graph | public/login/account/dashboard only | + profile, settings (multi-field-type form), items (parameterized), api/data (JSON), logout, two scope-adversarial fixtures |

## 3. Why a shared pinned transport

While building the Jar-based crawler redesign, an initial hypothesis
was tested: does `internal/crawler`'s Phase 3.14 approach (attach
cookies/headers once, on the request object, before the first
`client.Do()` call) leak them to a redirect target on a **different
host**? An early reproduction seemed to say yes -- but that
reproduction was flawed: it used two `httptest.NewServer` instances,
which both default to binding `127.0.0.1`, differing only by *port*.
Comparing hostnames (which `PinnedRoundTripper`, `net/http`'s own
`Client.do()`, and RFC 6265 cookie-domain matching all do) never even
looks at the port, so that test was never exercising cross-HOST
behavior at all.

Corrected reproduction, using genuinely distinct loopback IPs (matching
the `newIPServer` pattern already established in `internal/auth`'s own
tests):

```go
// two DIFFERENT hosts (127.0.0.50, 127.0.0.51), not the same host on
// different ports
client := &http.Client{}
req, _ := http.NewRequest("GET", mainSrv.URL+"/start", nil)
req.AddCookie(&http.Cookie{Name: "session", Value: "manually-added-value"})
req.Header.Set("Authorization", "Bearer secrettoken")
resp, _ := client.Do(req) // /start 302-redirects to evilSrv
// result: neither the cookie nor the Authorization header reached evilSrv
```

**Finding, corrected**: `net/http`'s own client already refuses to carry
a manually-set `Cookie`/`Authorization` header across a redirect to a
genuinely different host. Phase 3.14's original crawler implementation
was not leaking credentials cross-host. `safedial.PinnedRoundTripper`
was still built and adopted, for two reasons that remain real:

1. **Correctness of the shared mechanism itself.** `net/http`'s
   `Client.do()` copies headers from the *original* request onto every
   subsequent redirect hop's request object *before* a `RoundTripper`
   ever sees it. A `RoundTripper` that only *adds* a header on a host
   match and passes everything else through untouched will silently
   forward a header it added on an earlier hop to a later,
   different-host hop **within its own redirect chain** -- proven by
   `TestPinnedRoundTripper_StripsPreExistingHeaderOnMismatch` and
   `TestCrawl_ExtraHeadersNeverLeakToCrossHostRedirect` (both of which
   failed against an add-only implementation before the explicit
   strip-on-mismatch branch was added). This is a real, narrower gap
   than the one originally suspected, and the fix for it is the same
   shape either way.
2. **Defense in depth and DRY.** One shared, directly-tested mechanism
   enforcing a session's host-pinning at the transport layer, used by
   both `internal/auth.Session.NewClient` (the login flow) and
   `internal/crawler` (the authenticated crawl), independent of
   whatever a future Go version's own redirect behavior happens to do.

This whole investigation, including the correction, is intentionally
documented in full: a wrong initial finding, corrected by better
testing, is a more honest record than silently fixing the test and
keeping the overclaiming comment.

## 4. Architecture

```
Auth Profile (Phase 3.14)
        |
        v  Provider.Authenticate
Session (Jar + Headers, host-pinned)
        |
        v  Session.JarFor(host) / Session.HeadersFor(host)
crawler.Options{Jar, ExtraHeaders}
        |
        v  client.Jar = ...; client.Transport = &PinnedRoundTripper{...}
internal/crawler.Crawl
        |
        v  []crawler.Page (StatusCode, Links, Forms, Scripts)
internal/endpoints.Normalize / internal/parameters.Normalize
        |
        v  models.Endpoint / models.Parameter (unchanged, Phase 1/3.13)
internal/orchestration.crawlAndDiscoverEndpoints
        |
        v  models.AuthCrawlStats (transient, per-run)
internal/orchestrator.Result (AuthenticatedRequests, SessionExpired,
                               CrawlSummary)
        |
        v
cmd/scanner (Auth:/Crawl: output blocks)
```

`internal/crawler` still does not import `internal/auth` -- it accepts
`nethttp.CookieJar`/`map[string]string`, primitives it already
understood the *shape* of since Phase 3.14, decoupling preserved
literally, not just in spirit.

## 5. Session lifecycle during a crawl

1. `cmd/scanner` authenticates (Phase 3.14's pre-flight step, unchanged)
   and obtains a `*auth.Session`.
2. `Orchestrator.Run` threads it into a per-scan `Pipeline` copy
   (`scanPipeline`, unchanged from Phase 3.14 -- still never mutates
   the shared `Pipeline`).
3. For each crawl target, `crawlAndDiscoverEndpoints` computes
   `jar := session.JarFor(target.hostname)` and
   `headers := session.HeadersFor(target.hostname)` -- both return
   nil/empty unless `target.hostname` matches the session's own host.
4. If either is non-empty, the target's ENTIRE crawl (every page it
   fetches) is "authenticated" -- a session is attached once per
   target, not varied per page within it. This is why
   `AuthCrawlStats.PublicPages`/`AuthenticatedPages` are counted per
   target's whole page set, not per individual page.
5. The crawl uses the session's **own, live** jar (not a snapshot):
   `net/http/cookiejar.Jar.SetCookies`/`Cookies` are documented safe
   for concurrent use, so if the target sends a session-refresh cookie
   mid-crawl, it is captured back into the session automatically, the
   same way a real browser's cookie jar evolves.
6. Every request, authenticated or not, still passes through the exact
   same `safedial.Dialer`-built client every other stage in this
   codebase uses -- scope validated on the initial dial and on every
   redirect hop, unconditionally.

## 6. Session expiration

### Detection

`internal/orchestration.detectSessionExpired` inspects an
authenticated target's already-fetched pages (no extra network
request) for any `401`/`403` status code. If found,
`AuthCrawlStats.SessionExpired` is set, a warning is recorded, and the
scan continues.

### Session expiration policy (deterministic, by design)

- **No re-login is ever attempted mid-crawl.** This is what makes "avoid
  infinite re-login loops" true *by construction*, not by a retry-limit
  heuristic: there is no code path that re-authenticates during a
  crawl, so there is nothing that could loop.
- **Already-discovered results are always preserved.** A single
  target's 401/403 does not abort the scan -- `crawlAndDiscoverEndpoints`
  already treats one target's crawl failure as non-fatal (a
  pre-existing Phase 1 resilience pattern), and expiration detection
  reuses that same tolerance.
- **The scan completes and reports `SessionExpired: true`.** The
  operator decides what to do next (re-run with fresh credentials);
  the scanner does not guess.

### A false positive found and fixed

An earlier version of `detectSessionExpired` *also* flagged a page
whose final URL path matched the session's own login page, reasoning
that "the crawler landed back on the login page" is a strong expiration
signal. `TestPhase3_15_AuthenticatedCrawl_DiscoversFullPageGraph` (a
test asserting `SessionExpired == false` for a perfectly valid, fresh
session) caught this immediately: `lab/harness_auth.go`'s own root page
links to `/login` -- completely ordinary, most real sites do -- and an
authenticated crawl that simply follows that ordinary link was wrongly
flagged as expired.

Distinguishing "redirected BACK to login due to expiration" from
"linked to login normally" requires knowing each page's *pre-redirect*
requested path, which `crawler.Page` does not currently retain (only
the final, post-redirect URL). Rather than ship a heuristic proven to
false-positive on completely normal pages, the login-path check was
removed. `auth.Session.LoginURL` remains (harmless, not a secret,
already visible via `scanner auth profiles show`) for a future, more
precise implementation that also tracks pre-redirect paths. See
`internal/orchestration/pipeline.go`'s `detectSessionExpired` doc
comment for the full account.

**Known limitation**: this phase's session-expiration detection relies
solely on 401/403 status codes. A target that redirects an expired
session back to its login page with a `200` status (rather than
returning 401/403 directly) is not detected by this phase. This is
documented, not hidden.

## 7. Public vs. authenticated discovery

`orchestrator.Result` gained:

```go
AuthenticatedRequests int  // page fetches made with a session attached
SessionExpired        bool
CrawlSummary struct {
    PublicURLs             int
    AuthenticatedURLs      int
    AuthenticatedEndpoints int
}
```

All read back verbatim from `models.AuthCrawlStats` -- a transient,
non-persisted `ScanJob` field, mirroring Phase 3.13's `Warnings`
field's exact contract (computed once per `Pipeline.Run`, never
re-derived, never stored in the database). `cmd/scanner`'s `Auth:` and
`Crawl:` output blocks render these; both are entirely absent from a
scan that never authenticated (backward compatible with every
unauthenticated caller -- zero values, no blocks printed).

## 8. Parameter/form discovery

Reuses Phase 3.13's `internal/parameters` pipeline completely
unmodified -- an authenticated page's forms (hidden CSRF tokens, text,
select, checkbox, radio fields -- `lab/harness_auth.go`'s `/settings`
page exercises every one) are discovered exactly the way any
unauthenticated form already was. No second parameter-discovery
implementation was created.

## 9. Secret handling

- **CSRF field redaction (a real gap, fixed).** `internal/evidence`'s
  sensitive-field-name blocklist did not include `csrf`/`csrf_token`/
  `xsrf`/`xsrf_token` before this phase -- `password`, `token`,
  `session`, `api_key`, `authorization`, etc. were covered, but a
  discovered parameter literally named `csrf_token` was not. Found via
  a pre-existing Phase 3.13 lab test
  (`TestPhase3_13_InputDiscovery_QueryFormsDiscoveredEndToEnd`) that
  had been asserting the field's *raw, unredacted* value all along --
  itself the bug. Fixed in `internal/evidence/redact.go`; the
  pre-existing test's expectation corrected to require the redacted
  placeholder, not the raw value (a correction, not a weakening -- the
  old assertion was checking for exactly the wrong thing).
- **Everything Phase 3.14 already guaranteed still holds**, re-verified
  under authenticated crawling specifically: cookies/headers never
  logged, never in errors, host-pinned at three independent layers
  (`Session.CookiesFor`/`HeadersFor`/`JarFor`'s own host check,
  `PinnedRoundTripper`'s per-request check, RFC 6265 domain matching
  in the cookie jar itself), never persisted, never appearing in
  reports (`TestSecurity_AuthCredentials_NeverAppearInReportOrStatus`,
  extended and re-verified this phase).

## 10. Scope enforcement after authentication

**Discovered != authorized.** Nothing about authentication changes how
scope is checked -- every request, authenticated or not, is validated
by the exact same `internal/scope.Validator`/`internal/safedial.Dialer`
at the exact same points:

| Scenario | Mechanism | Test |
|---|---|---|
| Authenticated page linking to an out-of-scope host | Crawler's same-origin filter never enqueues it; even if it did, dial-time scope check refuses it | `TestPhase3_15_AuthenticatedLinkToOutOfScopeHost_NeverDialed` |
| Authenticated redirect to an out-of-scope host | `safedial`'s `CheckRedirect`, unconditionally | `TestPhase3_15_AuthenticatedRedirectToOutOfScopeHost_NotFollowed` |
| Protocol-relative link (`//evil.test/...`) | Same-origin filter compares the PARSED host | `TestCrawl_ProtocolRelativeLink_NotFollowed` |
| Userinfo-obfuscated link (`http://trusted@evil.test/`) | Same-origin filter uses `url.Parse`'s structured Host, not string matching | `TestCrawl_UserinfoObfuscatedLink_HostCorrectlyIdentified` |
| Form action outside scope (login or in-page) | Explicit `Validator.CheckHost` + dial-time check | Phase 3.14's own tests, re-verified |
| Sibling domain / subdomain not in scope | No special case at all -- an ordinary scope-rule miss | Covered by `internal/scope`'s own exhaustive test suite (unmodified) |

## 11. Determinism and concurrency

- **Determinism**: `TestPhase3_15_Determinism_RepeatedAuthenticatedScans_SameStructuralCounts`
  runs the identical scan 3 times, asserting identical endpoint/
  parameter/`AuthenticatedEndpoints` counts -- never byte-identical
  session tokens (intentionally random, matching real application
  behavior; see `lab/harness_auth.go`'s `newSession` doc comment for
  why token randomness and scanner-observable-state determinism are
  different properties).
- **Concurrency**: `net/http/cookiejar.Jar` is documented safe for
  concurrent `SetCookies`/`Cookies` calls, so sharing one session's jar
  across the concurrent per-target goroutines of ONE scan
  (`crawlAndDiscoverEndpoints`'s `errgroup`) is safe. Across scans,
  isolation is structural, not merely tested: every
  `Provider.Authenticate` call builds a brand-new jar (`cookiejar.New(nil)`
  in `formlogin.go`) -- no two `Session` values, from two different
  `Authenticate` calls, ever share the same jar pointer, even for the
  SAME auth profile. Proven under `-race` by
  `TestPhase3_15_ConcurrentScans_SameAuthProfile_NoCrossContamination`
  (three independent `Authenticate` calls against one profile, run
  concurrently) and Phase 3.14's own
  `TestPhase3_14_AccountAAndAccountB_IndependentSessions` (two
  different profiles/accounts).
- **Cancellation during authentication**: proven not to hang
  (`TestAdversarial_CancellationDuringAuthentication_NoHang`) and to
  report `AUTHENTICATION_FAILED`, never a false `AUTHENTICATED`.

## 12. Explicitly out of scope

This phase does **not** implement, and contains no code path for:

- Multi-account (Account A vs. Account B) comparison/IDOR automation --
  the lab has two independently authenticatable accounts (from Phase
  3.14) as groundwork; no comparison engine exists.
- Browser automation of any kind. The crawler discovers same-origin
  `<script src>` references (unchanged since Phase 1/3.4) but never
  executes JavaScript to obtain authentication or anything else. If a
  future capability genuinely requires browser execution, it should be
  built as a distinct, clearly-scoped provider/crawler backend --
  documented here as a real limitation, not attempted as a fragile
  partial implementation.
- CAPTCHA solving, MFA bypass, authentication bypass, credential
  brute forcing, password spraying, credential stuffing, or
  vulnerability exploitation of any kind.
- New vulnerability detectors -- every detector used in this phase's
  tests (`registerBenignDetectors`) is a pre-existing, unmodified one.
- Redirect-to-login-page expiration detection (see section 6's "Known
  limitation").

## 13. Lab architecture

`lab/harness_auth.go` (extended in place, not a new file --
`StartWithAuthFixtures` remains the entry point) now serves a small,
realistic authenticated page graph:

```
/ (public)  -->  /public, /login, /account
/account (auth)  -->  /dashboard, /profile
/dashboard (auth)  -->  /api/data
/profile (auth)  -->  /settings, external.scanner.test (link),
                      /redirect-to-external
/settings (auth)  -->  /items?category=books
/logout (auth, NOT linked -- reached only by a test that calls it
         directly, so it never prematurely ends an ordinary crawl)
```

`/dashboard` remains reachable **only** via a link inside `/account`'s
authenticated response body (the Phase 3.14 design this phase's own
page graph extends) -- this is what makes "authenticated endpoint
discovered" an observable difference in the discovered-endpoint LIST,
not merely a difference in response body content, and it is why
`TestPhase3_15_AuthenticatedCrawl_DiscoversFullPageGraph` and its
negative control (`TestPhase3_14_UnauthenticatedScan_NeverDiscoversDashboard`)
are meaningful tests, not tautologies.

`lab/` remains architecturally and physically isolated: no file under
`internal/`, `pkg/`, or `cmd/scanner/` was added to or modified to
depend on it. Re-verified this phase by physically removing `lab/` and
`tests/` from disk and rebuilding the production scanner successfully
(see the acceptance report).

## 14. CLI

```
scanner scan <target> --profile web --auth-profile <name>
```

`--profile web`/`--profile deep` is what actually enables crawling;
`--auth-profile` is what authenticates before it starts. Both flags are
independent and compose freely -- `--auth-profile` alone (default
"recon" profile, crawler disabled) authenticates but never crawls;
`--profile web` alone crawls unauthenticated; both together crawl
*authenticated*. `scanner scan --help` documents this combination
explicitly (see `cmd/scanner/scan.go`'s `Long` help text).

Output additions (both silently absent for an unauthenticated scan):

```
Auth:
  Profile:                lab-user
  Status:                 AUTHENTICATED
  Authenticated Requests: 37
  Session Expired:        No

Crawl:
  Public URLs:             12
  Authenticated URLs:      24
  Authenticated Endpoints: 31
```

No secret value is ever displayed. Dynamic shell completion of a
configured auth profile's *name* remains unimplemented, for the same
reason established in Phase 3.14 (`docs/phase-3-14-authentication.md`
section 14): confirmed empirically that cobra's `__complete` does not
run the config-loading `PersistentPreRunE` before a completion
callback, matching Phase 3.11.1's own precedent of not dynamically
completing scope rule IDs. The `--auth-profile`/`--profile` flag NAMES
themselves complete structurally (cobra's default behavior, free).

## 15. Known limitations (summary)

- Session-expiration detection: 401/403 only, not a redirect-to-login
  heuristic (section 6).
- No browser automation -- JavaScript-only authentication/navigation is
  not discoverable.
- No multi-account/IDOR comparison engine (deferred, explicitly, to a
  future phase).
- A session's cookie jar is shared read/write across concurrent
  per-target crawls within ONE scan (safe, per `cookiejar.Jar`'s own
  concurrency guarantee) but is never itself bounded in size --
  extremely long-running authenticated crawls could accumulate cookies
  without an eviction policy. Not observed as a practical problem in
  this phase's testing; noted for awareness.
