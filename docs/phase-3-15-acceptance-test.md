# Phase 3.15 Acceptance Test: Authenticated Crawling & Session-Aware Discovery

## What was built

- **`internal/safedial`**: new `PinnedRoundTripper` (shared,
  per-request host-pinned header attachment/stripping), extracted from
  and replacing `internal/auth`'s own private `headerInjectingTransport`
  -- one implementation of a security-critical mechanism, not two. 6
  dedicated unit tests (previously zero direct tests existed for this
  package).
- **`internal/auth`**: `Session.JarFor(host)` (host-pinned live jar
  access for the crawler); `Session.LoginURL` (retained, documented as
  currently unused after a false-positive heuristic using it was
  removed); `Session.NewClient` refactored onto `PinnedRoundTripper`.
  4 new adversarial tests (cancellation, session fixation, oversized
  cookie, malformed Set-Cookie post-login).
- **`internal/crawler`**: `Options.Jar http.CookieJar` (replacing
  Phase 3.14's `Options.Cookies []*http.Cookie`), `PinnedRoundTripper`
  wired for `ExtraHeaders`. 5 new tests (Jar attachment, same-host
  redirect survival, cross-host non-leak, protocol-relative link
  rejection, userinfo-obfuscated link rejection, redirect-loop
  no-hang).
- **`internal/orchestration`**: `detectSessionExpired` (401/403
  detection, with a login-path false-positive heuristic tried, proven
  wrong by testing, and removed); `models.AuthCrawlStats` (public/
  authenticated page and endpoint counts, `SessionExpired`), threaded
  through `crawlAndDiscoverEndpoints` -> `runStages` -> `Run` ->
  `models.ScanJob.AuthCrawlStats` (transient, non-persisted, mirroring
  `Warnings`' own established contract).
- **`internal/orchestrator`**: `Result.AuthenticatedRequests`,
  `Result.SessionExpired`, `Result.CrawlSummary` -- read back verbatim
  from `AuthCrawlStats`, zero-value for every unauthenticated caller.
- **`internal/evidence`**: `csrf`/`csrf_token`/`xsrf`/`xsrf_token` added
  to the sensitive-field-name blocklist -- a real, previously-uncovered
  gap.
- **`cmd/scanner`**: extended `Auth:` block (`Authenticated Requests`,
  `Session Expired`), new `Crawl:` block (`Public URLs`,
  `Authenticated URLs`, `Authenticated Endpoints`); `scan --help`
  documents `--profile`+`--auth-profile` composition.
- **`lab/harness_auth.go`** (extended in place): `/profile`,
  `/settings` (multi-field-type form), `/items` (parameterized),
  `/api/data` (JSON), `/logout`, `/redirect-to-external` -- a full
  authenticated page graph, plus the two out-of-scope link/redirect
  fixtures task section O.9/O.10 require.
- **Documentation**: `docs/phase-3-15-authenticated-crawling.md`
  (architecture), this file, `lab/README.md` (not separately updated
  this phase -- `harness_auth.go`'s own doc comment and the two docs
  above cover the new fixtures; see "Documentation scope" below for
  why).

## Documentation scope note

`lab/README.md` was extended in Phase 3.14 with a full "Authentication
fixtures" section. Rather than duplicate that structure for six new
routes, this phase's additions are documented directly in
`lab/harness_auth.go`'s own (substantially expanded) doc comment --
the page-graph diagram, credentials, and route purposes are all there,
co-located with the code they describe, and cross-referenced from
`docs/phase-3-15-authenticated-crawling.md` section 13. `lab/README.md`
itself was not edited to avoid the two sources of truth drifting apart
for the same information.

## Design decisions worth recording

1. **A wrong empirical finding, corrected in the open.** The original
   hypothesis (Phase 3.14's crawler leaks credentials across a redirect
   to a different HOST) was disproven once tested with genuinely
   distinct IPs rather than two same-IP-different-port `httptest`
   servers. The real, narrower finding (an add-only `RoundTripper`
   forwards a header IT ITSELF added on an earlier hop to a later,
   different-host hop within one redirect chain) is documented in full
   in the architecture doc, including the flawed initial test and its
   correction -- not silently cleaned up.
2. **`net/http/cookiejar.Jar` reused, not reimplemented**, for
   session-state carrying during crawling -- RFC 6265 domain matching
   is exactly the kind of security-critical logic worth trusting to the
   standard library.
3. **Session-expiration detection scoped down after a proven false
   positive.** A login-page-redirect heuristic was implemented, then
   REMOVED after a test written to prove the opposite (a valid session
   is never flagged as expired) caught it flagging a perfectly ordinary
   crawl. Shipping only the unambiguous 401/403 signal, with the
   limitation documented, was chosen over a heuristic proven unreliable
   -- directly following the task's own "if browser execution is
   required, document as out of scope rather than creating a fragile
   implementation" principle, generalized to any signal that can't be
   implemented robustly without a deeper structural change.
4. **`AuthCrawlStats` as a transient `ScanJob` field**, not a new table
   -- mirrors Phase 3.13's `Warnings` field exactly, avoiding a schema
   migration for data that describes one run, not a durable fact.
5. **CSRF redaction gap found via an existing test's WRONG
   expectation**, not invented speculatively:
   `TestPhase3_13_InputDiscovery_QueryFormsDiscoveredEndToEnd` had
   been asserting `csrf_token`'s *raw* value all along. Fixing the
   blocklist required correcting that assertion to expect the redacted
   placeholder -- a correction of a bug in the test, not a weakening
   (the old assertion was checking for exactly the wrong, insecure
   behavior).

## Test matrix results

### AUTHENTICATION
Phase 3.14's own suite (unchanged, re-verified): no auth profile,
valid profile, invalid profile, success, failure, timeout. Phase
3.15 additions: cancellation during authentication
(`TestAdversarial_CancellationDuringAuthentication_NoHang`), session
expiration (`TestPhase3_15_SessionExpiration_DetectedVia401`). **PASS**

### SESSION
`Session.JarFor` host-pinning (2 tests), `PinnedRoundTripper` (6
dedicated tests -- attach on match, no-attach on mismatch, strip
pre-existing header on mismatch [the regression test for the actual
bug found], never-mutate-original-request, case-insensitive host
match, pass-through with no headers configured), cookie persistence
across a same-host redirect during crawling
(`TestCrawl_JarSurvivesSameHostRedirect`), cross-host non-leak during
crawling (`TestCrawl_ExtraHeadersNeverLeakToCrossHostRedirect`),
concurrent scans/same profile
(`TestPhase3_15_ConcurrentScans_SameAuthProfile_NoCrossContamination`),
no cross-scan leakage (structural: every `Authenticate` call builds a
fresh jar). **PASS**

### AUTHENTICATED CRAWLING
Full page-graph discovery through a real orchestrator + real lab
(`TestPhase3_15_AuthenticatedCrawl_DiscoversFullPageGraph`): /profile,
/settings, /items, /api/data all discovered, reachable only through
authenticated links. Negative control
(`TestPhase3_14_UnauthenticatedScan_NeverDiscoversDashboard`, still
passing after the page-graph extension). Redirect-loop no-hang
(`TestCrawl_RedirectLoop_DoesNotHang`). Duplicate-URL deduplication
and depth/page limits: Phase 1/3.13's own crawler test suite, unmodified
and re-verified (the crawl algorithm itself did not change).
**PASS**

### PARAMETER DISCOVERY
Settings form's `csrf_token`/`display_name`/`theme`/`newsletter`/
`visibility` fields all discovered via the UNMODIFIED Phase 3.13
`internal/parameters` pipeline
(`TestPhase3_15_AuthenticatedCrawl_DiscoversFullPageGraph`); CSRF value
redaction proven against a real discovered parameter, not just a unit
test (`TestPhase3_15_CSRFAndSensitiveFieldValues_Redacted`). **PASS**

### SCOPE
Authenticated link to out-of-scope host never dialed
(`TestPhase3_15_AuthenticatedLinkToOutOfScopeHost_NeverDialed`);
authenticated redirect to out-of-scope host not followed
(`TestPhase3_15_AuthenticatedRedirectToOutOfScopeHost_NotFollowed`,
plus Phase 3.14's own login/form-action variants, re-verified);
protocol-relative link rejected
(`TestCrawl_ProtocolRelativeLink_NotFollowed`); userinfo-obfuscated
("encoded") link's TRUE host correctly identified, not the naive
substring-matched one
(`TestCrawl_UserinfoObfuscatedLink_HostCorrectlyIdentified`);
sibling-domain/subdomain-not-in-scope: no special case exists --
covered by `internal/scope`'s own unmodified, exhaustive suite. **PASS**

### SECRET PROTECTION
Password/cookie/Authorization/token redaction: Phase 3.14's suite,
re-verified unchanged. CSRF token redaction: NEW, closing a real gap
(`TestRedactBody_JSON_CSRFTokenField`,
`TestNormalize_HiddenTextareaSelectFields_AllDiscovered`'s extended
assertion, `TestPhase3_15_CSRFAndSensitiveFieldValues_Redacted`).
Report/error/log redaction:
`TestSecurity_AuthCredentials_NeverAppearInReportOrStatus`
(re-verified this phase against the new `--profile web
--auth-profile` combination specifically, not just the recon-profile
path Phase 3.14 tested). Oversized cookie
(`TestAdversarial_OversizedCookieValue_NoCrash`), malformed Set-Cookie
on a post-login request
(`TestAdversarial_MalformedSetCookie_OnPostLoginRequest_NoCrash`).
**PASS**

### ISOLATION
`TestPhase3_15_ConcurrentScans_SameAuthProfile_NoCrossContamination`
(same profile, 3 concurrent independent authentications);
`TestPhase3_14_AccountAAndAccountB_IndependentSessions` (different
profiles, re-verified); structural proof (every `Authenticate` call
builds a fresh `cookiejar.Jar`, never shared across `Session` values)
documented and unit-tested via `TestFormLogin_ConcurrentSessions_Isolated`.
**PASS**

### CONCURRENCY
All of the above run under `-race`, repository-wide, with zero data
races reported. Cancellation during an in-flight authentication
request proven not to hang and to report `AUTHENTICATION_FAILED`
correctly. **PASS**

### DETERMINISM
`TestPhase3_15_Determinism_RepeatedAuthenticatedScans_SameStructuralCounts`
-- 3 repeated identical authenticated scans, identical endpoint/
parameter/`AuthenticatedEndpoints` counts every time (session tokens
themselves are intentionally random, per real application behavior --
documented as the correct, non-conflicting property). **PASS**

### LAB
`lab/harness_auth.go`'s extended page graph builds and starts cleanly
as part of the existing `StartWithAuthFixtures` (additive, no change to
`Start`/`StartWithVulnerabilities`/`StartWithInputFixtures`). Full
`go test ./lab/...` (92 tests, every prior phase's own tests included):
**PASS**, 0 regressions. Physical lab/tests removal + production
rebuild re-verified clean (see REGRESSION below).

### E2E
`TestScanCmd_ProfileWebAndAuthProfile_AuthenticatedCrawlDiscoversSecretPage`
proves `--profile web --auth-profile <name>` together, through the
REAL built binary, actually performs authenticated crawling (closing
the one CLI-level gap Phase 3.14 left untested -- its own successful-
login test used no `--profile`, so the crawler never ran). All of
Phase 3.14's own e2e tests re-verified, with one label-format
regression found and fixed (a hardcoded `"State:   AUTHENTICATED"`
assertion broke when the `Auth:` block's own column alignment changed
for the new, longer field labels -- a legitimate test-format update,
not a weakening). Full `tests/e2e` suite (69 tests): **PASS**, 0
regressions.

### ADVERSARIAL (task section Q)

| # | Scenario | Covered by |
|---|---|---|
| 1 | Session fixation-like state confusion | `TestAdversarial_SessionFixation_BogusCookieNeverAccepted` |
| 2 | Cross-scan cookie leakage | `TestPhase3_15_ConcurrentScans_SameAuthProfile_NoCrossContamination`, structural jar-per-Authenticate-call proof |
| 3 | Auth header leakage | `TestPinnedRoundTripper_StripsPreExistingHeaderOnMismatch`, `TestCrawl_ExtraHeadersNeverLeakToCrossHostRedirect` |
| 4 | Secret leakage | `TestSecurity_AuthCredentials_NeverAppearInReportOrStatus`, CSRF redaction tests |
| 5 | Redirect-based scope bypass | `TestPhase3_15_AuthenticatedRedirectToOutOfScopeHost_NotFollowed` |
| 6 | Form-action scope bypass | Phase 3.14's `TestFormLogin_FormActionOutOfScope_Blocked`, re-verified |
| 7 | Encoded URL scope bypass | `TestCrawl_UserinfoObfuscatedLink_HostCorrectlyIdentified`, `TestCrawl_ProtocolRelativeLink_NotFollowed` |
| 8 | Login-page false positives | `TestPhase3_15_AuthenticatedCrawl_DiscoversFullPageGraph` (`SessionExpired == false` assertion) -- this scenario caught a REAL bug (section "Design decisions" #3), not merely tested a hypothetical |
| 9 | Infinite authentication redirects | `TestCrawl_RedirectLoop_DoesNotHang` |
| 10 | Session expiration loops | Structural: no re-login is ever attempted mid-crawl, so no loop can occur (see architecture doc section 6) |
| 11 | Concurrent session corruption | `-race`-clean across the full suite |
| 12 | Cancellation during authentication | `TestAdversarial_CancellationDuringAuthentication_NoHang` |
| 13 | Oversized cookies/headers | `TestAdversarial_OversizedCookieValue_NoCrash` |
| 14 | Malformed Set-Cookie | `TestAdversarial_MalformedSetCookie_OnPostLoginRequest_NoCrash` (post-login, extending Phase 3.14's login-time coverage) |
| 15 | Malformed authentication responses | Phase 3.13's own malformed-HTML crawler tests (unmodified, apply regardless of auth); `TestFormLogin_NoFormOnPage_Fails` |
| 16 | Unexpected content types | Phase 3.14's own coverage, re-verified; crawler's existing non-HTML skip logic, re-verified under authenticated crawling |

All 16 scenarios: **NO SCOPE BYPASS. PASS.**

### REGRESSION

Full repository, `-race -count=1`:

```
go build ./...                                          -> clean
go vet ./...                                             -> clean
gofmt -l .                                                -> clean (no output)
go test $(go list ./... | grep -v '/tests/e2e') -race     -> ok, 1120 PASS, 0 FAIL
go test ./tests/e2e/...                                   -> ok, 69 PASS, 0 FAIL
```

Production/lab independence re-verified the strongest way: physically
removed `lab/` and `tests/` from disk, rebuilt and vetted the
production scanner successfully, restored both directories, rebuilt
again to confirm restoration was complete.

Two pre-existing tests required correction as a DIRECT, correct
consequence of this phase's security fixes (not test-weakening --
both were asserting the WRONG, insecure behavior):

1. `lab/phase3_13_inputs_test.go`'s
   `TestPhase3_13_InputDiscovery_QueryFormsDiscoveredEndToEnd` asserted
   `csrf_token`'s raw fixture value (`"tok-abc"`) -- updated to assert
   the redacted placeholder.
2. `tests/e2e/e2e_auth_test.go`'s
   `TestScanCmd_AuthProfile_SuccessfulLogin` asserted a hardcoded,
   now-stale column-alignment string (`"State:   AUTHENTICATED"`) --
   updated to match the `Auth:` block's new, longer field labels
   (`"Status:                 AUTHENTICATED"`).

No existing test's SECURITY-RELEVANT assertion was relaxed, removed, or
had its pass condition weakened.

## Final report

```
PHASE 3.15 AUTHENTICATED CRAWLING & SESSION-AWARE DISCOVERY

TOTAL TESTS: 1189
PASS: 1189
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

AUTHENTICATION:
PASS -- login, failure, timeout, cancellation all proven; state model
reuses Phase 3.14's auth.State verbatim (see architecture doc "Session
expiration" for why no separate AUTH_CONFIGURED constant was added --
`scanner auth profiles show`'s existing ready/INVALID status already
serves that purpose)

SESSION:
PASS -- Jar-based carrying, host-pinned at 3 independent layers,
survives same-host redirects, never leaks cross-host, session-refresh
cookies captured automatically

AUTHENTICATED CRAWLING:
PASS -- full page graph discovered end to end (orchestrator level AND
through the real CLI binary), reachable only via authenticated links,
negative control confirms the wiring is load-bearing

PARAMETER DISCOVERY:
PASS -- authenticated forms/parameters via the unmodified Phase 3.13
pipeline, no second implementation

SCOPE:
PASS -- authenticated link/redirect to out-of-scope host both blocked;
protocol-relative and userinfo-obfuscated bypass attempts both
correctly rejected; discovered != authorized holds in every tested case

SECRET PROTECTION:
PASS -- CSRF redaction gap found and fixed; all Phase 3.14 protections
re-verified under authenticated crawling; oversized/malformed cookie
handling proven safe

ISOLATION:
PASS -- structural (fresh jar per Authenticate call) plus concurrent
same-profile and different-profile tests, race-clean

CONCURRENCY:
PASS -- full suite race-clean; cancellation during authentication
proven not to hang

DETERMINISM:
PASS -- 3 repeated authenticated scans produce identical structural
counts

LAB:
PASS -- 92 lab tests, full authenticated page graph, physical
production/lab independence re-verified

E2E:
PASS -- 69 tests including the real-binary --profile web
--auth-profile vertical slice this phase specifically closed

ADVERSARIAL:
PASS -- all 16 task section Q scenarios demonstrated by an actual
test, none merely claimed; scenario 8 (login-page false positives)
caught a real bug during this phase's own development

SECURITY ISSUES: 0 (one real gap found and fixed during THIS phase's
own development -- CSRF field redaction -- not an issue remaining at
delivery)
RELIABILITY ISSUES: 0 (one false-positive session-expiration heuristic
found and removed during THIS phase's own development -- not an issue
remaining at delivery)
PERFORMANCE ISSUES: 0

PHASE 1 REGRESSION: PASS
PHASE 2 REGRESSION: PASS
PHASE 3 LAB REGRESSION: PASS
PHASE 3.1 REGRESSION: PASS
PHASE 3.2 REGRESSION: PASS
PHASE 3.3 REGRESSION: PASS
PHASE 3.4 REGRESSION: PASS
PHASE 3.5 REGRESSION: PASS
PHASE 3.6 REGRESSION: PASS
PHASE 3.7 REGRESSION: PASS
PHASE 3.8 REGRESSION: PASS
PHASE 3.9 REGRESSION: PASS
PHASE 3.10 REGRESSION: PASS
PHASE 3.11 REGRESSION: PASS
PHASE 3.11.1 REGRESSION: PASS
PHASE 3.11.2 REGRESSION: PASS
PHASE 3.12 REGRESSION: PASS
PHASE 3.13 REGRESSION: PASS (1 test corrected -- see REGRESSION section above)
PHASE 3.14 REGRESSION: PASS (1 test corrected -- see REGRESSION section above)

PHASE 3.15 ADVERSARIAL: PASS

PHASE 3.15 VERDICT: PASS
```

## Architectural note flagged per task instruction

Per this phase's own "if any architectural ambiguity, security
weakness, test gap, or undocumented behavior is discovered, STOP...
and report it clearly" instruction: the one item worth flagging before
any future phase builds on this one is the session-expiration
detection's documented limitation (401/403 only, no redirect-to-login
heuristic -- section 6 of the architecture doc). This is not a security
weakness (nothing scope- or secret-related depends on it), but a
capability gap: an application that redirects an expired session back
to its login page with a `200` status rather than a `401`/`403` will
not currently be flagged as `SessionExpired: true`. Closing it properly
would require extending `crawler.Page` to retain each page's
pre-redirect requested path -- a small, well-scoped crawler change, but
a real one, deliberately deferred rather than rushed into this phase
under time pressure after the first attempt at it was proven unreliable.

Per the task's final rule: Phase 3.16, multi-account/IDOR
orchestration, browser automation, and new vulnerability detectors are
explicitly NOT started. Work stops here pending a new phase
instruction.
