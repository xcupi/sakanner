# Phase 3.14: Authentication & Session Foundation

## 1. Purpose

Phase 3.14 establishes a clean, secure, deterministic authentication/
session foundation later phases can build on. It does NOT add new
vulnerability detectors, browser automation, multi-account IDOR
orchestration, or any form of credential attack (brute force, password
spraying, credential stuffing, CAPTCHA/MFA bypass, authentication
bypass). See section 15 ("Limitations and explicitly out of scope") for
the complete list.

The one required, tested acceptance scenario is the vertical slice:

```
authorized target -> authentication profile -> login -> session cookie
obtained -> authenticated request -> authenticated endpoint discovered
-> result recorded
```

No vulnerability finding is required to prove this phase works.

## 2. Architecture

```
Authentication configuration (ProfileConfig)
        |
        v  ResolveProfile: env-var secret resolution, validation
Authentication profile (Profile)
        |
        v  NewProvider + Provider.Authenticate
Authenticated session/context (Session)
        |
        v  Session.CookiesFor / Session.HeadersFor / Session.NewClient
Crawler / HTTP client / detectors
```

All of this lives in the new `internal/auth` package -- self-contained,
independently testable, and depended on by exactly two existing
packages: `internal/orchestration` (threads a `*auth.Session` into the
crawl stage) and `internal/orchestrator` (carries `Options.AuthSession`
and reports `Result.AuthProfile`/`Result.AuthState`). `internal/auth`
itself depends only on `internal/scope`, `internal/safedial`,
`internal/dns` (transitively, via safedial), and `internal/evidence`
(for its redaction constant) -- the same small set of leaf packages
every other network-touching stage in this codebase already depends on.
It does **not** depend on `internal/crawler`, `internal/orchestration`,
or `internal/orchestrator` -- task section 9's "keep the authentication
layer independent from crawler implementation," generalized to every
downstream consumer.

### Where authentication happens

Authentication is a **pre-flight step**, performed entirely by the
caller (`cmd/scanner`) strictly *before* `internal/orchestrator.Orchestrator.Run`
is ever invoked -- never inside the orchestrator itself. This is the
same architectural pattern `--profile` already established in Phase
3.12 (`internal/policy.Resolve` runs first, its result is threaded
through `Options` as inert configuration) applied to authentication:

- `Options.AuthSession *auth.Session` is an *already-authenticated*
  session by the time `Run` sees it. The orchestrator performs zero
  authentication logic of its own -- it only reads
  `Options.AuthSession` to (a) thread it into the crawl stage and (b)
  report its `State`/`ProfileName` verbatim in `Result`.
- This is what makes "an invalid or failed authentication attempt
  creates no scan job" (task section 12) automatic rather than a
  special case the orchestrator's own stage sequence has to know
  about: if authentication fails, `cmd/scanner` simply never calls
  `Orchestrator.Run` at all.
- `internal/orchestrator`'s own package doc states "this package owns
  SEQUENCING ONLY" -- authentication living entirely outside it keeps
  that invariant intact.

### Authenticated crawling: the minimum viable interface

Task section 9 explicitly forbids redesigning the crawler this phase.
The integration is the smallest change that makes the vertical slice
real:

- `internal/crawler.Options` gained two new, purely primitive fields:
  `Cookies []*http.Cookie` and `ExtraHeaders map[string]string`. The
  crawler attaches them to every request it makes and otherwise knows
  nothing about sessions, profiles, or authentication -- it never
  imports `internal/auth`.
- `internal/orchestration.Pipeline` gained one field, `AuthSession
  *auth.Session`. Inside `crawlAndDiscoverEndpoints`, for each crawl
  target it computes `p.AuthSession.CookiesFor(target.scheme,
  target.hostname)` and `p.AuthSession.HeadersFor(target.hostname)` --
  both already host-pinned (return nil/empty for any host other than
  the session's own) -- and passes the result into `crawler.Options`.
- The initial port-scan/HTTP-probe/fingerprint stage remains
  unauthenticated by design. Only the crawl (and therefore input
  discovery, which reads the same already-fetched pages) benefits from
  a session in this phase. This is a deliberate, documented scope
  boundary, not an oversight -- extending authentication to the probe
  stage is straightforward future work (the same `Session.NewClient`
  helper `internal/auth` already exports would apply there unchanged)
  but was not necessary to prove the vertical slice.

Detectors and the evidence engine are entirely unaware that
authentication happened at all -- they consume `Endpoint`/`Parameter`
rows built from crawled pages exactly as before Phase 3.14; nothing
about their own code changed.

## 3. Authentication types

| Type | Constant | Requires a login request? | Config identifies |
|---|---|---|---|
| Form-based username/password | `form_login` | Yes | `login_url`, `username_env`, `password_env`, field names |
| HTTP session cookie (pre-obtained) | `cookie` | No | `cookie_env` (a raw `Cookie:` header value), `scope_host` |
| Bearer/API token | `bearer_token` | No | `token_env`, `scope_host` |
| Custom header | `header` | No | `header_name`, `header_value_env`, `scope_host` |

Only `form_login` performs a network request of its own
(`FormLoginProvider`); the other three (`StaticProvider`) simply build
a `Session` from an already-resolved credential the operator supplies,
after one scope check on the configured host.

The architecture leaves room for JSON login, browser-based
authentication, OAuth/OIDC, and MFA-assisted/manual authentication --
each would be one more `Type` constant and one more `Provider`
implementation, selected by `NewProvider`'s existing switch, with zero
changes to `Session`, `Profile`, the config shape, or any consumer.
None of these are implemented in this phase (task section 1: "do NOT
implement those future mechanisms yet").

## 4. Credential input

Credentials are never accepted as ordinary command-line arguments
(`--username`, `--password`). The only supported mechanism is a named
**authentication profile**, configured in YAML under
`authentication.profiles`, whose credential-bearing fields are
environment variable *names*, never values:

```yaml
authentication:
  profiles:
    - name: lab-user
      type: form_login
      login_url: http://auth.scanner.test/login
      username_env: SAKANNER_LAB_USERNAME
      password_env: SAKANNER_LAB_PASSWORD
      username_field: username
      password_field: password
```

`internal/config.AuthProfileConfig` carries this raw shape (mirroring
every other nested config struct -- `internal/config` never imports a
domain package's own types). `cmd/scanner` translates it field-by-field
into `internal/auth.ProfileConfig` (mirroring exactly how `internal/policy.ConfigView`
is already translated for `--profile`), and `auth.ResolveProfile` reads
the referenced environment variables:

```bash
export SAKANNER_LAB_USERNAME=userA
export SAKANNER_LAB_PASSWORD='Str0ngPass-A-fixture-only'
scanner scan auth.scanner.test --auth-profile lab-user
```

Reading `os.Getenv` is the *only* I/O `internal/auth`'s config layer
performs, and it happens lazily -- only when a profile is actually
resolved (CLI startup / `config.Load` never reads environment secrets
merely because a profile mentioning them exists in the file, so an
unrelated command like `scanner target list` never fails to start just
because a configured profile's secret isn't currently exported).

## 5. Auth profile: field-name flexibility

Nothing in `internal/auth` hard-codes `"username"`/`"password"` as
field names. A profile can describe:

```
POST /login
email=<username>
password=<password>
```

by setting `username_field: email` -- no scanner code changes. The
resolved `Profile.UsernameField`/`PasswordField` are simply the map
keys `FormLoginProvider` overwrites in the submitted form body; every
other field the login page's own `<form>` already contains (including
hidden fields such as a CSRF token) survives the round trip unmodified
-- see section 8.

## 6. Form login flow

`FormLoginProvider.Authenticate` implements task section 4's flow
exactly:

1. Validate the target is authorized (`safedial.Dialer.ResolveInScope`
   on the login URL's host).
2. Fetch the login page (bounded read, 512KB, matching
   `internal/crawler`/`internal/http`'s own body-sampling convention).
3. Identify the login form: the first `<form>` containing a
   password-type input if any exists, else the first `<form>` found at
   all (`htmlform.go`, a small, independent HTML walk -- see section 2
   for why this does not reuse `internal/crawler`'s own form parser).
4. Identify username/password fields: `Profile.UsernameField`/
   `PasswordField` (default `"username"`/`"password"`).
5. Submit credentials: every field the form already carried (hidden
   CSRF tokens included) plus the username/password overrides plus any
   configured `ExtraFields`.
6. Follow redirects via the same `safedial.Dialer`-built client every
   other stage uses -- scope-checked on every hop.
7. Capture resulting cookies via a standard `net/http/cookiejar.Jar`
   (RFC 6265 domain matching, not hand-rolled).
8. Validate success -- see section 7.
9. Return an `AUTHENTICATED` (or `AUTHENTICATION_FAILED`) `Session`.

## 7. Success/failure evaluation

Task section 4 explicitly forbids assuming HTTP 200 means success.
`evaluateSuccess` (`internal/auth/formlogin.go`) implements:

- If `failure_text_contains` is configured and the response body
  contains it, the login failed -- checked first, unconditionally.
- If `success_url_contains`/`success_text_contains` are configured,
  they alone govern (an explicit operator choice always wins).
- Otherwise (no indicators configured at all): the response must have
  a non-error status **and** the cookie jar must hold at least one
  cookie for the login host. A real session-based login always leaves
  some session state behind; an application that returns HTTP 200
  regardless of credentials, with no cookie, fails this default check
  -- this is the exact trap task section 4 names, and
  `TestFormLogin_Always200Trap_NotTreatedAsSuccess` proves it directly.

## 8. Session management

`Session` (`internal/auth/model.go`) carries:

- `Jar http.CookieJar` -- populated for `form_login`, nil otherwise.
- `Headers map[string]string` -- static headers for `cookie`/
  `bearer_token`/`header` types (`"Cookie"`, `"Authorization"`, or the
  operator-named header).
- `State`, `CreatedAt`, `ExpiresAt *time.Time` (nil unless a future
  provider that knows a concrete expiry sets it -- none does today),
  `FailureReason`.

A `Session` is reusable by every stage that needs it via three methods,
all **host-pinned** (see section 11):

- `CookiesFor(scheme, host string) []*http.Cookie`
- `HeadersFor(host string) map[string]string`
- `NewClient(dialer, hostname, ip, timeout, maxRedirects) *http.Client`
  -- builds a scope-safe client (via the caller-supplied
  `safedial.Dialer`, identical to `internal/http.Prober`/
  `internal/crawler`) with the session's cookies/headers attached only
  when `hostname` matches the session's own host.

Detectors and the evidence engine never see a `Profile`, only whatever
already-crawled `Endpoint`/`Parameter` data resulted from an
authenticated crawl -- they have no code path to a credential at all.

## 9. Cookie/header security

Cookies and tokens are treated as secrets throughout:

- **Never logged.** No log statement in `internal/auth` or its callers
  includes a header value, cookie value, username, or password.
- **Never in errors.** Every error `internal/auth` returns is checked
  by tests (`TestSecurity_FailSession_ReasonIsSecretFree`,
  `TestFormLogin_WrongPassword_Fails`, etc.) to contain no secret
  value.
- **Redaction reuses the existing mechanism.** `auth.RedactedPlaceholder`
  is `internal/evidence.RedactedPlaceholder` verbatim (task section 6's
  explicit "existing evidence redaction mechanisms must be reused"),
  not a second, potentially-drifting literal.
- **`Profile.Redacted()`/`Session.Redacted()`** are the only display-safe
  views this package offers: every credential field becomes a boolean
  (`HasPassword`, `HasToken`, ...) or a name-only list (header names,
  never values) -- `scanner auth profiles show` renders these, never
  the `Profile`/`Session` structs themselves.
- **Nothing is persisted.** A `Session` lives only in the memory of one
  `scanner scan` process invocation. No database table, no evidence
  record, no report field stores a cookie, token, username, or
  password. This is the strongest available guard against "secrets
  appearing in evidence/reports" (task section 15, scenarios 22-23):
  there is no code path through which they *could* appear, since
  `internal/reporting.Build`/`internal/evidence.BuildPackage` never
  read a `Session` at all. The tradeoff, stated plainly: an
  authenticated session cannot be resumed across separate `scanner
  scan` invocations (see section 13) -- re-authentication happens every
  time `--auth-profile` is given. This is the deliberate, documented
  choice for this phase; a future phase that wants session persistence
  would need to design an explicit, secure-at-rest representation
  (e.g. encrypted-at-rest, OS keychain-backed) rather than storing raw
  cookie/token bytes in the existing SQLite database.

## 10. Authentication state

```
UNAUTHENTICATED         -- no --auth-profile was given at all
AUTHENTICATING          -- in-flight (never a Provider's final return value)
AUTHENTICATED           -- login/setup succeeded
AUTHENTICATION_FAILED   -- attempted, did not succeed
AUTHENTICATION_EXPIRED  -- a caller-observed Session.ExpiresAt has passed
AUTHENTICATION_UNKNOWN  -- reserved for future session-persistence work
```

These are their own `auth.State` type -- never conflated with
`internal/orchestrator`'s `Status`/`DetectionState` enums. A scan's
overall outcome and its authentication outcome are independent facts:
an authenticated scan can still `FAIL` at SCOPE for an unrelated
reason, and (in principle) a scan status could be `COMPLETED` while
`AuthState` is `AUTHENTICATION_FAILED` if a caller other than
`cmd/scanner` chose to proceed anyway -- `cmd/scanner` itself never
does (see section 13).

`scanner scan` output distinguishes the three states task section 7
names exactly:

- No `--auth-profile` at all: no `Auth:` block is printed --
  "scan completed without authentication."
- `--auth-profile` given, login fails: `cmd/scanner` prints
  `Authentication FAILED for profile "...": <reason>` and exits
  (`exitAuthFailed = 5`) *before* any scan job exists --
  "authentication was attempted and failed."
- `--auth-profile` given, login succeeds: `Authentication succeeded
  for profile "..."`, then the scan proceeds and prints an `Auth:`
  block (`Profile: ...` / `State: AUTHENTICATED`) --
  "authenticated scan completed successfully."

## 11. Scope security

Authentication can never expand authorized scope. Every network
request `internal/auth` makes goes through the exact same
`internal/scope.Validator`/`internal/safedial.Dialer` every other stage
uses -- no new scope-validation logic exists in this package.
Concretely:

| Adversarial scenario (task section 8) | Enforcement mechanism |
|---|---|
| Login URL outside scope | `safedial.Dialer.ResolveInScope` (exported wrapper around the same check every redirect hop already uses) refuses to resolve/dial it |
| Redirect outside scope | `safedial.Dialer.NewClient`'s `CheckRedirect` re-checks scope on every hop and truncates the chain rather than following it -- reused unmodified |
| Form action outside scope | An explicit `Validator.CheckHost` check before submission (fast, clear error) *plus* the same dial-level check as above (defense in depth) |
| Cookie sent to wrong host | `Session.CookiesFor` refuses to release cookies for any host other than the session's own (checked first); the underlying `net/http/cookiejar.Jar`'s RFC 6265 domain matching is a second, independent layer |
| Authorization header leakage | `Session.HeadersFor`/`NewClient`'s `headerInjectingTransport` both check the request's actual host per-request, not once at client construction |
| Malicious redirect | Same mechanism as "redirect outside scope" -- no special-casing for intent, every redirect is checked identically |

`ResolveInScope` is a new *export* of an existing, unmodified private
`safedial` method (`resolveInScope`) -- no scope-validation behavior
changed, only its visibility.

## 12. Authentication-aware crawling: what changed, what didn't

- Changed: `crawler.Options` (+2 primitive fields),
  `orchestration.Pipeline` (+1 field, `AuthSession`),
  `orchestrator.Options`/`Result` (+`AuthSession`/+`AuthProfile`,
  `AuthState`).
- Unchanged: `crawler.Crawl`'s own algorithm (breadth-first, same-origin,
  depth/page bounds), every existing crawler test, the port-scan/probe/
  fingerprint stage, every detector, `internal/evidence`,
  `internal/correlation`, `internal/risk`.

## 13. Session lifecycle across scans

- **No caching.** `internal/orchestrator.Orchestrator` holds no
  session state of its own; a `Session` exists only as long as the
  `*auth.Session` value the caller passes into one `Options` literal.
  Two separate `scanner scan --auth-profile lab-user` invocations
  authenticate twice, independently -- there is no mechanism by which
  one process's session could leak into another's.
- **Concurrent scans are isolated.** `Orchestrator.scanPipeline` always
  returns a *copy* of the shared `Pipeline` when a session (or a crawl
  override) is supplied, never mutates the shared instance -- two
  concurrent `Run` calls with different sessions (or one with a
  session and one without) never race on or see each other's
  `AuthSession`. Proven directly (`TestScanPipeline_SessionOnly_CopiesAndSetsAuthSession`)
  and end-to-end against the real lab with two real accounts running
  concurrently (`TestPhase3_14_AccountAAndAccountB_IndependentSessions`).

## 14. CLI

```
scanner auth profiles list
scanner auth profiles show <name>
scanner scan <target> --auth-profile <name>
```

`scanner auth profiles show` never prints a raw credential value --
only booleans/names via `Profile.Redacted()`. An unknown profile name
fails immediately (`*auth.UnknownProfileError`, mirroring
`internal/policy.UnknownProfileError`'s exact style) with no network
activity. `scanner scan --auth-profile <invalid-or-failing>` fails
before any `Orchestrator` is even constructed -- exit code 5
(`exitAuthFailed`), no scan job created, deterministic error message.

### Shell completion

`--auth-profile`'s flag *name*, and the `auth`/`profiles`/`list`/`show`
subcommand names, complete automatically (cobra's structural
completion, no code required). Dynamic completion of a profile's
*value* (i.e. suggesting configured profile names) is deliberately
**not** implemented: it would require loading `config.yaml` at
completion time, and cobra's `__complete` machinery does not run the
root command's `PersistentPreRunE` (which populates the loaded config)
before invoking a completion callback -- confirmed empirically during
this phase's own development, not merely assumed. This mirrors Phase
3.11.1's own established precedent of not dynamically completing scope
rule IDs for the analogous reason (would require opening the database
at completion time; see `docs/phase-3-11-1-cli-ux.md` "Shell
completion").

## 15. Limitations and explicitly out of scope

Phase 3.14 does **not** implement, and this codebase contains no code
path for:

- MFA bypass, CAPTCHA bypass
- Credential brute forcing, password spraying, credential stuffing
- OAuth/OIDC automation
- Browser automation (headless or otherwise)
- JSON login (a login endpoint that expects a JSON request body rather
  than a form submission)
- CSRF-protected multi-step login flows beyond preserving a discovered
  login form's own hidden fields verbatim
- MFA-assisted/manual authentication
- Full IDOR/BOLA multi-account orchestration (an "Account A session
  vs. Account B session" comparison engine) -- the lab now has two
  independently-authenticatable accounts (`userA`/`userB`) as
  groundwork, but no comparison engine exists yet; see
  `lab/README.md` "Future expansion"
- Session persistence across process invocations (see section 9's
  tradeoff discussion)
- Authenticating the initial port-scan/HTTP-probe/fingerprint stage
  (only crawling/input discovery are authenticated in this phase; see
  section 2)

## 16. Determinism

Given the same target, the same auth profile, and the same lab state,
the scanner reaches the same `AuthState` and discovers the same
authenticated content every time. `ResolveProfile` is pure (no
network, no clock/random reads beyond `os.Getenv`) and
`TestResolveProfile_Deterministic` proves repeat calls are identical.
The lab's own session tokens are cryptographically random per login (a
real application's behavior) -- this does not make the *scanner's*
observable authentication state non-deterministic, since nothing the
scanner reports (`AuthState`, which endpoints were discovered, which
findings resulted) depends on the token's specific byte value, only on
whether a valid session was established at all. See
`lab/harness_auth.go`'s `newSession` doc comment for the same point
made at the fixture level.

## 17. Future extensions

The architecture supports, without further structural change:

```
Authentication
      |
      v
Session Context
      |
      v
Authenticated Crawler
      |
      v
Parameter Discovery
      |
      v
Detection
      |
      v
Evidence
```

and eventually:

```
Account A Session --+
                     +-- IDOR/BOLA Engine
Account B Session --+
```

Adding a new authentication `Type` (JSON login, OAuth/OIDC, browser-
based) is one new constant plus one new `Provider` implementation
selected by `NewProvider`'s existing switch -- `Session`, `Profile`,
the config shape, and every consumer (`internal/orchestration`,
`internal/orchestrator`, `cmd/scanner`) are unchanged. Authenticating
the port-scan/probe stage would reuse `Session.NewClient` directly.
Multi-account IDOR/BOLA testing would build on two independently
authenticated `Session` values (already fully supported: nothing
prevents authenticating twice, as `userA` and `userB`, within one
process) plus a comparison engine that does not yet exist.
