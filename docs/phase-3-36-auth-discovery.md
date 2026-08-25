# Phase 3.36: General Web Authentication Auto-Discovery

## 1. Purpose and scope

Before this phase, every authenticated scan required the operator to
know a target's exact login URL, username field name, and password
field name (`type: form_login`'s `login_url`/`username_field`/
`password_field`). This phase adds a second, additional authentication
type — `form_login_auto` — that discovers a conventional HTML
username/password login form automatically, so the operator only
needs to supply credentials and a `start_url` (any reachable
same-origin page on the app, not necessarily the login page itself).

**Deliberately limited scope**, per the task's own explicit
boundaries: only conventional HTML form-based username/password
login, resulting in session-cookie establishment. OAuth/OIDC, SAML,
CAPTCHA, MFA/2FA, WebAuthn, JavaScript-only/SPA auth flows, and
bearer-token/API-key discovery are all explicitly out of scope and
remain manual/explicit-only (`cookie`, `bearer_token`, `header`
profile types, unchanged).

**Not a DVWA-specific feature.** Every heuristic is application-
agnostic (generic English login vocabulary — "log in"/"sign in"/etc.,
HTML input `type`/`autocomplete`/name/label signals — never a
hardcoded path, field name, or string specific to any one
application). DVWA is used only as a real validation target (Section
7); nothing in production code references it.

## 2. Architecture review (before writing any code)

Read directly, not assumed from memory:

- `internal/auth/model.go` — the `Type` enum, `ProfileConfig`/
  `Profile` shapes.
- `internal/auth/provider.go` — `Provider` interface, `NewProvider`'s
  single Type-dispatch point.
- `internal/auth/formlogin.go` — the existing, fully-tested
  `form_login` flow: fetch page → find form → submit → evaluate
  success → build Session.
- `internal/auth/htmlform.go` — the existing HTML form parser
  (`findLoginForm`/`extractLoginForm`), which already resolves a
  form's action URL, detects a password-type input, and preserves
  every other field's original value (hidden CSRF tokens survive
  automatically).
- `internal/auth/config.go` — `ResolveProfile`'s per-Type resolution,
  `lookupEnv`'s "name the missing env var, never guess" pattern.
- `internal/config/config.go` — the mapstructure-tagged config schema
  and `AuthenticationConfig.Validate()`'s structural checks.
- `cmd/scanner/auth.go`, `cmd/scanner/identities.go`, `cmd/scanner/
  scan.go` — how a profile/identity becomes a `Session`
  (`authenticateForIdentity` → `ResolveIdentityProfile` →
  `performAuthentication` → `NewProvider` → `Provider.Authenticate`),
  and the existing `auth profiles`/`identities` inspection commands'
  display conventions.
- `internal/crawler` — confirmed **not** reused directly: the crawler
  is a same-origin *site* crawler (endpoint/input discovery across
  many pages, JS-technology detection, etc.); login-form discovery
  needs a much smaller, bounded, safety-critical primitive (fetch,
  parse forms, score, submit *at most once*) that doesn't belong in
  and doesn't need the crawler's own machinery. What **is** reused:
  the same `golang.org/x/net/html` parsing library the crawler also
  happens to depend on (a shared *library* dependency, not a package
  dependency on `internal/crawler` — `internal/auth` remaining
  independent of `internal/crawler` was already an explicit design
  choice from Phase 3.14, preserved here), and the exact same
  `safedial.Dialer`/`scope.Validator` every other network-touching
  package already uses.

## 3. Design

### 3.1 A new, additional Type — not a flag on form_login

`TypeFormLoginAuto = "form_login_auto"` (`internal/auth/model.go`).
Deliberately a distinct type rather than an "auto-detect" flag bolted
onto `form_login`: the two have different required config fields
(`start_url` vs. `login_url`) and different `Provider`
implementations. This guarantees an existing `form_login` profile's
behavior can never be silently altered by this addition — `NewProvider`
still dispatches `TypeFormLogin` to the exact same, untouched
`FormLoginProvider`.

### 3.2 Reuse over duplication: `submitCredentials`

The riskiest part of adding a second "submit a login form" code path
is having two independently-maintained implementations of "build the
POST body, submit, follow redirects, evaluate success" drift apart —
exactly the "second incompatible implementation" this codebase has
consistently avoided in every prior phase. `formlogin.go` was
refactored (pure extract-method, behavior-preserving — verified by
re-running every existing `form_login` test unchanged afterward) to
split `FormLoginProvider.Authenticate` into:

1. Its own fetch-the-login-page-and-find-the-form logic (unchanged).
2. A shared `submitCredentials(ctx, deps, p, client, jar, originHost,
   form, actionURL, sess)` — steps "fill in username/password →
   submit → follow redirects → evaluate success → build Session,"
   extracted verbatim.

`AutoFormLoginProvider.Authenticate` (`discover.go`) performs
discovery instead of using a configured `LoginURL`, then calls the
*exact same* `submitCredentials`. A real login submission is
therefore always the same code, regardless of whether the form was
configured or discovered — there is no second, separately-tested
submission path to drift.

### 3.3 Discovery algorithm (`internal/auth/discover.go`)

1. Scope-check and resolve `start_url`'s host (same
   `Dialer.ResolveInScope` every other path uses); build one
   scope-safe, cookie-jar-carrying `http.Client` (`newScopedDiscoveryClient`,
   shared with the read-only preview path — see 3.4).
2. Fetch the start page (ordinary redirects followed by the client's
   own `CheckRedirect`, which already re-validates scope on every
   hop).
3. Parse every `<form>` on the page (`parseForms`, factored out of
   the existing `findLoginForm` — same extraction logic, zero
   duplication). Any form with a `type="password"` input is a
   candidate; a page with none is not immediately a failure.
4. If no password-bearing form was found, collect same-origin
   "login-like" links (text or URL path containing generic login
   vocabulary — never a specific application's own wording), scored
   and sorted best-first, and fetch up to `maxDiscoveryPages` (3
   total, including the start page) of them, stopping at the first
   password-bearing form found on any of them.
5. Among the password-bearing form(s) on the winning page, pick the
   highest-scoring one (`scoreForm`) — the baseline gate is
   `HasPassword`; the score exists only to choose deterministically
   between *multiple* password-bearing forms on the *same* page
   (matrix item 11), never to decide whether something is a login
   form at all.
6. Identify the username field (`identifyUsernameField`): among the
   form's own text-like inputs (`text`/`email`/`tel`/`search` —
   never the password field or a non-text type), score by
   `autocomplete="username"/"email"` (strongest), `type="email"`,
   then a name/id/label containing generic username vocabulary
   ("user", "email", "login", "account"), falling back to the first
   plausible text field if nothing else distinguishes one — matching
   `findLoginForm`'s own established "if nothing distinguishes it,
   still deterministically take it" philosophy. Ties always break by
   document order (first field wins), never randomly.
7. Submit exactly once, via `submitCredentials` (3.2).

Bounds, all deliberately conservative: `maxDiscoveryPages = 3`,
`maxCandidateLinks = 20` (per page), one context timeout covering the
whole sequence (`Profile.Timeout`, same default as `form_login`), and
**exactly one credential submission ever**, regardless of how many
candidate pages/forms were examined — discovery itself never reads or
sends a credential; only the single, final `submitCredentials` call
does.

### 3.4 `scanner auth discover` — preview without authenticating

`DiscoverOnly(ctx, deps, startURL, timeout, maxRedirects)
(DiscoveryResult, error)` runs exactly the discovery phase (steps 1-6
above) and returns a small, non-secret result (login URL, method,
field names) — no credential is ever read, no form is ever submitted.
`scanner auth discover <start-url>` (`cmd/scanner/auth.go`) exposes
this directly, with `--username-env`/`--password-env` as an opt-in
extension that also performs the real login (via the same
`AutoFormLoginProvider` a `scan --identity`/`--auth-profile` would
use) — never silently guessing which mode the operator wants: giving
only one of the two flags is a clear, immediate error.

### 3.5 Config schema — minimal extension

`AuthProfileConfig` (`internal/config/config.go`) gains one new
field: `start_url` (`mapstructure:"start_url"`). No existing field
was renamed, removed, or repurposed. `AuthenticationConfig.Validate()`
gained one new `case "form_login_auto"` requiring `start_url` +
`username_env` + `password_env` — structurally identical in spirit to
`form_login`'s own existing requirement, substituting `start_url` for
`login_url`.

## 4. Safety

Every requirement below was specifically designed for and verified by
a test (Section 6), not merely asserted:

- **Scope never bypassed.** Discovery uses the identical
  `safedial.Dialer`/`scope.Validator`-backed client every other
  authenticated request in this codebase already uses — no new dial
  path exists. `TestDiscover_ScopeDenied_NeverFetchesAnything` proves
  a target with no `allow` rule is never fetched at all.
- **Same-origin, independent of and stricter than scope.** A same-origin
  check (scheme+host+port, fixed to the *original* `start_url` for
  the whole discovery run) gates every followed link *in addition to*
  the scope check — `TestDiscover_NeverFollowsCrossOriginLoginLink`
  proves this holds even when the cross-origin host is *also*
  in-scope.
- **Bounded, never brute-force.** At most 3 page fetches
  (`TestDiscover_BoundedPageFetches_NeverExceedsMax`, using a fixture
  with far more candidate links than the bound allows) and exactly
  one credential submission — this codebase never retries a failed
  login with a different guess, a different form, or a different
  field, and never attempts more than one password against one
  account.
- **Never submits to an unidentified form.** A password-type input is
  the mandatory, non-negotiable gate before any submission is even
  considered; a form with no identifiable username field, or a page
  with no password-bearing form anywhere within the bound, fails
  cleanly with no submission attempted at all
  (`TestDiscover_NoLoginFormAnywhere_FailsCleanly`).
- **Credentials never leak.** No error message, failure reason, log
  line, or CLI output ever contains a raw credential value —
  `TestDiscover_CredentialsNeverAppearInErrorMessages` greps every
  returned error/failure string for the actual (fake, test-only)
  credential values after deliberately triggering both a
  discovery-failure and a login-failure path. `scanner auth discover`
  never prints a credential either (verified at the CLI/e2e level,
  `TestAuthDiscover_WithCredentials_ActuallyAuthenticates`).
- **Session isolation preserved.** Two `AutoFormLoginProvider`
  instances (two identities sharing one `form_login_auto` profile,
  exactly like two identities already share one `form_login` profile)
  never share a cookie jar, client, or credential —
  `TestDiscover_TwoIdentities_IndependentSessionsAndCookies`.
- **A failed discovery/login never becomes a false "authenticated"
  state.** `AutoFormLoginProvider.Authenticate` always routes through
  `failSession`/`submitCredentials`'s own existing `evaluateSuccess`
  check (unchanged, the same conservative "non-error status AND a
  session cookie actually established, or an explicit configured
  indicator" heuristic `form_login` already uses) — there is no new,
  separate "did it work" heuristic for the auto path to get wrong.

## 5. Multi-identity

Unchanged architecture, reused as-is: an `Identity` still overrides a
referenced profile's own `username_env`/`password_env` (`internal/
auth/identity.go`'s `ResolveIdentityProfile`, untouched). Two
identities referencing the same `form_login_auto` profile authenticate
completely independently — each resolves to its own `Profile`, its own
`AutoFormLoginProvider`, its own client/jar/session, discovered and
submitted separately. `--identity`/`--authz-identity` work identically
to how they already do for `form_login` — no changes were needed in
`cmd/scanner/scan.go`'s identity-handling logic at all, since
`auth.NewProvider` already dispatches generically by `Type`.

This phase does **not** implement or change any IDOR/BOLA comparison
logic — `idor-active`'s own dual-identity comparison is unaffected and
unchanged; it simply now also works when both identities authenticate
via `form_login_auto` instead of `form_login`.

## 6. Testing

**Unit** (`internal/auth/discover_test.go`, 17 new tests, all against
real `httptest` fixtures built for this phase — no shared/mocked HTTP
layer): conventional form + `username`/`password` fields (matrix 1/2),
`type=email`+`autocomplete=email` field (3), non-standard password
field name identified by `type`, not name (4), hidden CSRF token
round-trips (5), relative (6) and absolute-same-origin (7) form
actions, POST submission (8), redirect-after-success cookie capture
(9), multiple forms with only the password-bearing one chosen (11), no
login form anywhere fails cleanly and stays bounded (12), cross-origin
form action blocked (13), same-origin login-link following (bonus),
cross-origin login-link never followed (bonus, safety), scope denial
never fetches anything (14), credentials never leak into errors (15),
two identities stay fully independent (16), bounded page-fetch count
enforced even against an adversarial link-farm fixture (bonus), and
`DiscoverOnly` never issues a POST / cleanly errors with no form
(bonus). Matrix item 10 (failed login) is exercised inline by several
of the above (wrong-credential assertions) plus dedicated e2e coverage
below.

**Backward compatibility** (matrix 17/18): the complete pre-existing
`internal/auth` test suite (formlogin/static/config/identity/
adversarial/security — everything that existed before this phase) was
re-run, unmodified, after every change in this phase and passes
identically — confirmed after the `htmlform.go` additive change, after
the `formlogin.go` extract-method refactor, and after the final
`discover.go`/config/CLI additions. `go test ./internal/auth/... -race`
passes with zero failures.

**E2E** (`tests/e2e/e2e_auth_discover_test.go`, 9 new tests, real
compiled binary, real local lab fixture — `lab/harness_auth.go`'s
existing, generic `/login` form, already used by every pre-existing
`form_login` e2e test, deliberately reused rather than building a new
fixture): `auth discover` preview finds the real form and never
authenticates; `auth discover` with credentials really authenticates
and never leaks the password into output; wrong credentials fail
cleanly (no panic); missing-argument/invalid-URL/only-one-of-two-flags
all produce clear errors; a full `scan --identity` using ONLY a
`form_login_auto` profile (no `login_url`/field names anywhere in
config) authenticates successfully end-to-end; the same with wrong
credentials fails with no panic. The complete pre-existing `auth`/
`identities`/`authorization` e2e suites (31 test functions across
`e2e_auth_test.go`, `e2e_identities_test.go`,
`e2e_authorization_test.go`) were re-run and pass unchanged.

## 7. DVWA validation (real, executed — not merely claimed)

Performed against the same locally-running DVWA instance used for the
manual authentication-architecture validation immediately preceding
this phase (`<dvwa-host>`). A **local-only** config
(`authentication.profiles[].start_url: "http://<dvwa-host>/DVWA/"`,
`type: form_login_auto`) was used — never committed, never added to
the repository, no DVWA-specific code added to sakanner itself.

Real, executed results:

1. **Discover the login page/form** — `scanner auth discover
   http://<dvwa-host>/DVWA/` followed DVWA's own redirect from
   `/DVWA/` to `/DVWA/login.php` and correctly reported it as the
   discovered login page.
2. **Discover username/password fields** — reported `Username field:
   username`, `Password field: password`, matching DVWA's real form
   exactly, with zero DVWA-specific configuration.
3. **Preserve the hidden CSRF token** — DVWA rejects any login
   request whose `user_token` doesn't match the session that issued
   it; the login below succeeding is direct proof the token round-
   tripped correctly (an incorrect/dropped token would have failed
   with DVWA's own "CSRF token is incorrect" response).
4. **Authenticate with supplied credentials** — `scanner auth discover
   ... --username-env ... --password-env ...` (credentials held only
   in transient shell environment variables, never written to any
   file, never printed) reported `Authentication succeeded.` /
   `Session cookies established: 2`.
5. **Establish the authenticated session** — confirmed above.
6. **Crawl authenticated pages afterward** — `scanner scan
   <dvwa-host> --ports 80 --profile web --identity dvwa-admin`
   (using the SAME `form_login_auto` profile, only `start_url`, no
   `login_url`) reported `Authenticated Requests: 2`, `Authenticated
   URLs: 2`, `Authenticated Endpoints: 3` — genuine authenticated
   crawling using the automatically-discovered session.

**Authentication validation and vulnerability detection validation
are different concerns (task's own explicit instruction).** The scan
above discovered zero query/form inputs at the shallow crawl
depth/page-count used, so no detector had anything eligible to test —
this reflects DVWA's own navigation structure and the crawl bounds
used, not an authentication defect (authentication itself is fully
proven above), and is unrelated to DVWA's separately-noted "Security
Level: impossible" setting (already documented in
`docs/dvwa-validation.md`, unchanged by this phase) which affects
vulnerability *detection*, not *authentication*, discovery.

## 8. Remaining limitations (honest, not fixed here — out of scope)

- Discovery only recognizes a *single-step* conventional HTML form
  (one page, one password field, one submission). Multi-step logins
  (username on one page, password on a next page), JavaScript-
  rendered forms, and anything requiring client-side script execution
  are not discoverable — `form_login`'s explicit configuration (or a
  future phase) remains the only option for those.
- `scanner auth discover` never writes a profile into your config
  file — it previews/exercises the mechanism, but you still hand-edit
  YAML to actually configure a `form_login_auto` profile for repeated
  use. The pre-existing "no CLI command to create/edit a profile" gap
  is unchanged by this phase.
- Discovery's scoring heuristics are necessarily general-purpose; an
  application with a genuinely unconventional form (e.g. no
  distinguishing username-field signal at all, multiple equally-
  plausible password fields) may pick the wrong field or form.
  `scanner auth discover` (no credentials) is the recommended way to
  verify what would be picked before relying on it for a real scan.
- No new bearer-token/API-key/OAuth discovery of any kind was added —
  explicitly out of scope per the task, unchanged.
