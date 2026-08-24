# Phase 3.14 Acceptance Test: Authentication & Session Foundation

## What was built

- **`internal/auth`** (new package): `Type`/`State` enums, `Profile`/
  `ProfileConfig` (raw vs. resolved), `ResolveProfile` (env-var secret
  resolution + validation, zero network I/O), `Provider` interface +
  `NewProvider` factory, `FormLoginProvider` (the real login flow),
  `StaticProvider` (cookie/bearer_token/header, no network), `Session`
  (`CookiesFor`/`HeadersFor`/`NewClient`, all host-pinned), a small
  independent HTML login-form parser (`htmlform.go`), and
  redaction helpers reusing `internal/evidence.RedactedPlaceholder`.
- **`internal/safedial`**: one new exported method, `ResolveInScope` --
  an export of an already-existing private check, no behavior change.
- **`internal/config`**: `AuthenticationConfig`/`AuthProfileConfig`
  (raw, mapstructure-tagged, credential fields are env-var *names*
  only), structural `Validate()` (no env var reads).
- **`internal/crawler`**: `Options.Cookies`/`Options.ExtraHeaders` (two
  primitive fields), attached to every crawl request. No import of
  `internal/auth`.
- **`internal/orchestration`**: `Pipeline.AuthSession *auth.Session`;
  `crawlAndDiscoverEndpoints` derives host-pinned cookies/headers per
  target.
- **`internal/orchestrator`**: `Options.AuthSession`; `Result.AuthProfile`/
  `Result.AuthState`; `scanPipeline` extended to copy-and-attach a
  session without mutating the shared `Pipeline` (concurrency safety).
- **`cmd/scanner`**: `scanner auth profiles list`/`show <name>`;
  `scanner scan --auth-profile <name>`; exit code 5 (`exitAuthFailed`);
  an `Auth:` output block; `authenticateForScan` (the pre-flight
  authentication step, entirely outside the orchestrator).
- **`lab/harness_auth.go`** (new): `auth.scanner.test` fixture --
  `/public`, `/login` (GET+POST, hidden CSRF field, Account A/B),
  `/account`, `/dashboard` (session-cookie-gated, `/dashboard` reachable
  only via a link inside `/account`'s authenticated body),
  `/login-external-action`, `/login-external-redirect` (scope
  adversarial fixtures). `StartWithAuthFixtures` (additive, does not
  change any earlier `Start*`).
- **Documentation**: `docs/phase-3-14-authentication.md` (architecture),
  this file, `lab/README.md` updates.

## Design decisions worth recording

1. **Authentication runs entirely outside the orchestrator.**
   `cmd/scanner` authenticates BEFORE constructing an `Orchestrator`,
   passing an already-authenticated `*auth.Session` into `Options`.
   This keeps `internal/orchestrator`'s "sequencing only" architecture
   intact and makes "no scan job on auth failure" automatic rather
   than a special case.
2. **Crawler decoupling via primitives, not a shared type.**
   `crawler.Options` gained `[]*http.Cookie`/`map[string]string`, never
   an `*auth.Session` -- the crawler package has zero dependency on
   `internal/auth`, satisfying task section 9 literally, not just in
   spirit.
3. **`net/http/cookiejar.Jar` reused, not reimplemented.** Cookie
   domain-matching (RFC 6265) is exactly the kind of security-critical
   logic worth reusing from the standard library rather than
   hand-rolling; `Session.CookiesFor`'s own host check is a second,
   independent layer on top of it.
4. **`safedial.ResolveInScope` exported, not duplicated.** The
   login-host scope check is the identical logic `safedial` already
   used internally for redirect-target resolution -- exporting it
   avoided a second implementation of dial-time scope validation.
5. **No default-heuristic false positive on "always 200."** The
   default success heuristic (no explicit indicators configured)
   requires both a non-error status AND at least one captured cookie --
   directly defeats the exact trap task section 4 names.
6. **Zero persistence of session state.** A `Session` lives only in one
   process's memory. This is a deliberate tradeoff (no session reuse
   across separate CLI invocations) chosen because it makes "secrets
   never appear in evidence/reports" true by construction rather than
   by discipline -- documented explicitly in
   `docs/phase-3-14-authentication.md` section 9.
7. **`/dashboard` reachable only via an authenticated link.** The lab
   fixture was deliberately designed so the difference between an
   authenticated and unauthenticated crawl is directly observable in
   the discovered-endpoint list (not just response body content),
   making the vertical slice's "authenticated endpoint discovered"
   claim testable with the EXISTING `Endpoint` model (which carries no
   status code).
8. **Dynamic shell completion of profile names was attempted and
   reverted.** Empirical testing showed cobra's `__complete` does not
   run `PersistentPreRunE` (which populates the loaded config) before
   invoking a completion callback -- the same reason Phase 3.11.1 never
   dynamically completed scope rule IDs. Two tests initially written
   for this failed; rather than work around it with a second,
   parallel config-load path at completion time, the feature was
   dropped in favor of consistency with the established precedent
   (`docs/phase-3-14-authentication.md` section 14).

## Test matrix results

### AUTH PROFILE (config parsing, validation, secret resolution)
- `internal/config`: 7 tests (structural validation for all 4 types,
  duplicate names, missing required fields, YAML round-trip,
  env-vars-not-checked-at-load-time). **PASS**
- `internal/auth/config_test.go`: 20 tests (`ResolveProfile` for all 4
  types, missing/empty env vars, combined multi-error reporting,
  invalid URLs, unknown type, determinism, `FindProfileConfig`).
  **PASS**

### FORM LOGIN
- `internal/auth/formlogin_test.go`: 20 tests -- successful login,
  wrong username/password, empty credentials (no crash), no `<form>`
  found, login server unavailable, timeout, GET-method form, the
  "always 200" trap correctly rejected, explicit success/failure text
  indicators, `ExtraFields` submitted, hidden CSRF field preserved,
  malformed + duplicate `Set-Cookie` (no crash, still authenticates),
  2MB oversized response (bounded read, no hang), login URL/form
  action/redirect out of scope (blocked), 5 concurrent sessions
  isolated. **PASS**
- `lab/phase3_14_auth_test.go`: form login against the real,
  full-stack lab (see E2E below). **PASS**

### SESSION MANAGEMENT
- `internal/auth/session_test.go`: 8 tests -- `CookiesFor`/`HeadersFor`
  host-pinning (including case-insensitivity and nil-safety),
  `NewClient` header attachment only to the pinned host, header NOT
  forwarded across a redirect to a different host, `IsExpired`.
  **PASS**
- `internal/orchestrator/auth_test.go`: 5 tests -- `Result.AuthState`/
  `AuthProfile` population (both the unauthenticated default and a
  populated session), `scanPipeline`'s copy-not-mutate behavior for
  session-only, override-only, and both-together cases. **PASS**
- `internal/crawler`: 2 new tests -- cookies/headers attached to crawl
  requests; zero-value `Options` behaves identically to before this
  field existed (regression guard). **PASS**

### COOKIE SECURITY / SECRET REDACTION
- `internal/auth/security_test.go`: 5 tests -- `Profile.Redacted()`/
  `Session.Redacted()` blanket-scanned (`%+v` dump) for every secret
  value used in the test, `failSession`'s reason is secret-free,
  `UnknownProfileError` only echoes name/available list,
  `StateExpired` is a distinct state. **PASS**
- `internal/auth/static_test.go`: out-of-scope host error/failure
  reason checked to never contain the raw token value. **PASS**
- `tests/e2e/e2e_auth_test.go`: `TestSecurity_AuthCredentials_NeverAppearInReportOrStatus`
  -- an authenticated scan's `scan`/`status`/`report --format markdown`/
  `report --format json` output all checked for the raw password
  string. **PASS**

### SCOPE ENFORCEMENT
- `internal/auth/formlogin_test.go`: login URL outside scope, form
  action outside scope, redirect outside scope (evil host asserted
  NEVER dialed, via a `t.Error` inside its own handler). **PASS**
- `internal/auth/static_test.go`: out-of-scope host for a static
  (cookie/bearer/header) profile. **PASS**
- `lab/phase3_14_auth_test.go`: the same three scope scenarios re-run
  against the REAL, isolated lab with REAL scope rules (not a mock
  validator). **PASS**

### AUTHENTICATED REQUEST / VERTICAL SLICE
- `lab/phase3_14_auth_test.go`:
  `TestPhase3_14_VerticalSlice_AuthenticatedCrawlDiscoversDashboard` --
  the full required scenario: authorized target -> profile -> login ->
  session cookie -> authenticated crawl -> `/dashboard` discovered
  (reachable ONLY via an authenticated link) -> result recorded in
  `Result.AuthState`/persisted `Endpoint` rows. **PASS**
- `TestPhase3_14_UnauthenticatedScan_NeverDiscoversDashboard` --
  negative control proving the wiring is load-bearing, not a no-op.
  **PASS**

### LAB
- `lab/harness_auth.go` fixtures build and start cleanly as part of
  `StartWithAuthFixtures` (additive superset of `StartWithInputFixtures`
  -> `StartWithVulnerabilities` -> `Start`). Full `go test ./lab/...`
  suite (85 tests, every prior phase's own tests included): **PASS**,
  0 regressions.

### E2E (real built binary, `tests/e2e`)
- `TestAuthProfilesCmd_ListAndShow`, `_UnknownProfile`,
  `_NoneConfigured`: **PASS**
- `TestScanCmd_AuthProfile_SuccessfulLogin`: **PASS**
- `TestScanCmd_AuthProfile_WrongCredentials_ExitCode5_NoScanJob`:
  exit code 5 confirmed, "Scan ID:" absent from output (no scan job
  created), wrong password never appears in output. **PASS**
- `TestScanCmd_AuthProfile_UnknownProfileName_ExitCode5_NoScanJob`:
  **PASS**
- `TestScanCmd_NoAuthProfile_ReportsUnauthenticated`: no `Auth:` block
  printed when `--auth-profile` was never given. **PASS**
- `TestSecurity_AuthCredentials_NeverAppearInReportOrStatus`: **PASS**
- `TestShellCompletion_AuthSubcommands` (+ `--auth-profile` added to
  the existing `TestShellCompletion_ScanFlags` flag-name check):
  **PASS**
- 9/9 Phase-3.14-specific e2e tests pass; full `tests/e2e` suite (68
  tests, every prior phase's own tests included): **PASS**, 0
  regressions.

### ADVERSARIAL (task section 15's 23 numbered scenarios)

| # | Scenario | Covered by |
|---|---|---|
| 1 | Wrong username | `TestFormLogin_WrongUsername_Fails` |
| 2 | Wrong password | `TestFormLogin_WrongPassword_Fails`, `TestPhase3_14_WrongCredentials_AuthenticationFailed` |
| 3 | Empty credentials | `TestFormLogin_EmptyCredentials_NoCrash` |
| 4 | Malformed profile | `TestResolveProfile_UnknownType`, `TestResolveProfile_FormLogin_InvalidLoginURL`, `TestValidateRejectsBadValues` (config) |
| 5 | Missing environment variable | `TestResolveProfile_FormLogin_MissingEnvVars_CombinedError`, `TestResolveProfile_EmptyEnvVarValue_TreatedAsMissing` |
| 6 | Login endpoint outside scope | `TestFormLogin_LoginURLOutOfScope_Blocked`, `TestPhase3_14_*` (lab) |
| 7 | Redirect outside scope | `TestFormLogin_RedirectOutOfScope_NotFollowed`, `TestPhase3_14_RedirectOutOfScope_NotFollowed` (lab) |
| 8 | Form action outside scope | `TestFormLogin_FormActionOutOfScope_Blocked`, `TestPhase3_14_FormActionOutOfScope_NeverAuthenticated` (lab) |
| 9 | Cross-origin cookie | `TestSession_CookiesFor_HostPinned` |
| 10 | Authorization header leakage | `TestSession_NewClient_AttachesHeaderOnlyToPinnedHost`, `TestSession_NewClient_RedirectToDifferentHost_HeaderNotForwarded` |
| 11 | Cookie sent to wrong host | `TestSession_CookiesFor_HostPinned` (evil.test never receives app.test's cookie) |
| 12 | Session reuse across scans | `docs/phase-3-14-authentication.md` section 13 (no caching, architecturally); `TestPhase3_14_AccountAAndAccountB_IndependentSessions` |
| 13 | Concurrent authenticated scans | `TestFormLogin_ConcurrentSessions_Isolated`, `TestPhase3_14_AccountAAndAccountB_IndependentSessions`, `TestScanPipeline_SessionOnly_CopiesAndSetsAuthSession` |
| 14 | Authentication timeout | `TestFormLogin_Timeout_Fails` |
| 15 | Login server unavailable | `TestFormLogin_LoginServerUnavailable_Fails` |
| 16 | Extremely large response | `TestFormLogin_HugeResponse_BoundedRead` (2MB, bounded read, no hang) |
| 17 | Malformed Set-Cookie | `TestFormLogin_MalformedAndDuplicateSetCookie_NoCrashStillAuthenticates` |
| 18 | Duplicate cookies | same test as #17 |
| 19 | Expired session | `TestSession_IsExpired`, `TestSecurity_Session_ExpiredIsDistinctFromFailed` |
| 20 | Secrets in error messages | `TestFormLogin_WrongPassword_Fails`, `TestStaticProvider_OutOfScopeHost_Fails` |
| 21 | Secrets in logs | no log statement in `internal/auth` includes a secret value (code-reviewed; no logging framework call in the package touches `Username`/`Password`/`Token`/`HeaderValue`/`CookieHeader` at all) |
| 22 | Secrets in evidence | structurally impossible -- `internal/evidence`/`internal/reporting` never read a `Session` (see architecture doc section 9) |
| 23 | Secrets in reports | `TestSecurity_AuthCredentials_NeverAppearInReportOrStatus` |

All 23 scenarios: **NO SCOPE BYPASS. PASS.**

### REGRESSION

Full repository, every package, `-race -count=1`:

```
go build ./...                                          -> clean
go vet ./...                                             -> clean
gofmt -l .                                                -> clean (no output)
go test $(go list ./... | grep -v '/tests/e2e') -race     -> ok, 1101 PASS, 0 FAIL
go test ./tests/e2e/...                                   -> ok, 68 PASS, 0 FAIL
```

Every Phase 1-3.13 test file is unmodified except where a NEW field's
zero-value behavior needed an explicit regression guard alongside the
existing tests (`internal/crawler`'s `TestCrawl_NoCookiesOrHeaders_UnaffectedBehavior`,
`internal/orchestrator`'s `TestScanPipeline_NilOverrideAndSession_ReturnsSharedPipeline`)
-- no existing test's assertions were weakened, relaxed, or deleted.

### RACE

`go test ./... -race` (excluding `tests/e2e`, which execs a separate
built binary and is not itself subject to `-race`): clean, 0 data
races, across every package touched by this phase
(`internal/auth`, `internal/config`, `internal/crawler`,
`internal/orchestration`, `internal/orchestrator`, `lab`) and every
package untouched by it.

## Final report

```
PHASE 3.14 AUTHENTICATION FOUNDATION

TOTAL TESTS: 1169
PASS: 1169
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

AUTH PROFILE: PASS
FORM LOGIN: PASS
SESSION MANAGEMENT: PASS
COOKIE SECURITY: PASS
SECRET REDACTION: PASS
SCOPE ENFORCEMENT: PASS
AUTHENTICATED REQUEST: PASS
LAB: PASS
E2E: PASS
ADVERSARIAL: PASS
REGRESSION: PASS
RACE: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0

PHASE 3.14 VERDICT: PASS
```

"NOT IMPLEMENTED: 0" reflects that everything task sections 1-16
require WAS implemented and tested -- it does not mean every
conceivable authentication mechanism exists. JSON login, browser
automation, OAuth/OIDC, MFA, credential attacks, and multi-account
IDOR orchestration are correctly, deliberately absent (task's own
explicit exclusions -- see section 15 of the architecture doc), not
gaps against this phase's own required scope.

Per the task's final rule: Phase 3.15, browser automation,
multi-account IDOR orchestration, and new vulnerability detectors are
explicitly NOT started. Work stops here pending a new phase
instruction.
