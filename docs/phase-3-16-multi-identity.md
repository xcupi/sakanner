# Phase 3.16: Multi-Identity Authentication & Account Context Foundation

## 1. Purpose

**Phase 3.16 provides identity/session context for future authorization
testing. It does not itself perform automated IDOR/BOLA detection.**

Phase 3.14 built one authenticated session per scan. Phase 3.15 made
that session usable during crawling. Phase 3.16 extends the model so a
scan can authenticate as one of several independently-configured
**identities** (Anonymous, Identity A, Identity B, ... -- the
architecture does not hard-code exactly two), each with its own
isolated session, and tags every resource that identity discovers with
which identity discovered it. That is the entire scope of this phase:

> Allow the scanner to establish, maintain, isolate, and use multiple
> authenticated identities so that future authorization testing can
> safely compare behavior across identities.

No detector in this codebase compares two identities' results. No code
path claims a finding merely because two identities exist. This phase
is groundwork, honestly labeled as such.

## 2. Identity vs. Auth Profile

These are two different concepts, deliberately not collapsed:

| | Auth Profile (Phase 3.14) | Identity (Phase 3.16) |
|---|---|---|
| Describes | **How** authentication is performed -- login URL, field names, success indicators, mechanism | **Who** is authenticating -- a security principal/session context |
| Configured under | `authentication.profiles` | `identities` |
| Credentials | References env vars directly | REFERENCES a profile, optionally OVERRIDING its credential env vars |
| Cardinality | One profile can serve many identities | Each identity uses exactly one profile |

Task's own example:

```yaml
authentication:
  profiles:
    - name: customer-login
      type: form_login
      login_url: https://shop.example.com/login
      username_field: email
      password_field: password
      username_env: SAKANNER_DEFAULT_USER   # used only if no identity overrides it
      password_env: SAKANNER_DEFAULT_PASS

identities:
  identities:
    - name: account-a
      auth_profile: customer-login
      username_env: SAKANNER_ACCOUNT_A_USER
      password_env: SAKANNER_ACCOUNT_A_PASS
    - name: account-b
      auth_profile: customer-login
      username_env: SAKANNER_ACCOUNT_B_USER
      password_env: SAKANNER_ACCOUNT_B_PASS
```

Both identities share `customer-login`'s login MECHANISM (same URL,
same field names, same success indicator) while authenticating as two
completely independent accounts. `internal/auth.ResolveIdentityProfile`
implements this: it looks up the referenced profile, then overwrites
only the credential fields (`UsernameEnv`/`PasswordEnv`/`TokenEnv`/
`CookieEnv`/`HeaderValueEnv`) the identity itself sets, leaving every
mechanism field (`LoginURL`, `UsernameField`, `SuccessTextContains`,
...) untouched. An identity that needs no override at all (the profile
is already single-account) works with nothing but `name`/`auth_profile`
set.

An "anonymous" identity needs no configuration at all: it is simply the
absence of `--identity`/`--auth-profile` -- `Result.AuthState` reports
`UNAUTHENTICATED`, exactly as every pre-Phase-3.14 scan already did.

## 3. Identity lifecycle

Three distinct state vocabularies exist, matched to three distinct
concerns -- never conflated:

| Vocabulary | Type | Describes |
|---|---|---|
| Scan state | `internal/orchestrator.Status` | Whether the PIPELINE finished (SCOPE/RECON/DETECTION/...) |
| Authentication state | `internal/auth.State` (Phase 3.14) | Whether ONE login/setup attempt succeeded -- a property of a `Session` |
| Identity state | `internal/auth.IdentityState` (Phase 3.16) | The LIFECYCLE of a configured security principal -- a superset of authentication state |

```
IDENTITY_CONFIGURED     -- structurally valid, not yet authenticated
IDENTITY_AUTHENTICATING -- in flight (never a final value)
IDENTITY_AUTHENTICATED  -- login succeeded
IDENTITY_AUTH_FAILED    -- login attempted, did not succeed
IDENTITY_EXPIRED        -- a caller determined the session's known expiry passed
IDENTITY_DISABLED       -- administratively turned off (identities[].disabled),
                            checked BEFORE any resolution or network activity
```

`IDENTITY_CONFIGURED` and `IDENTITY_DISABLED` have no `auth.State`
equivalent -- an identity can be in either state before a `Session` is
ever constructed at all. The other four map directly onto `auth.State`
(`identityStateFromAuthState`, the one place this mapping happens).
`scanner identities show <name>` reports `IDENTITY_CONFIGURED` (or
`IDENTITY_DISABLED`, or `INVALID` for a structurally broken reference)
without ever authenticating -- a pure, zero-network-I/O inspection,
exactly like `scanner auth profiles show` already was.

## 4. Multi-identity configuration

```yaml
identities:
  max_count: 10          # default; a hard resource limit (task section 20)
  identities:
    - name: account-a
      auth_profile: customer-login
      username_env: SAKANNER_ACCOUNT_A_USER
      password_env: SAKANNER_ACCOUNT_A_PASS
    - name: account-b
      auth_profile: customer-login
      disabled: false     # default
      username_env: SAKANNER_ACCOUNT_B_USER
      password_env: SAKANNER_ACCOUNT_B_PASS
```

Validated structurally by `internal/config.IdentitiesConfig.Validate`
at config-load time -- zero network I/O, zero env var reads (those are
checked lazily, only when an identity is actually resolved, exactly
matching `AuthenticationConfig`'s own established precedent so an
unrelated command never fails to start over a secret that isn't
currently exported):

- name required, non-empty
- names unique (no duplicates)
- `auth_profile` required, and must match an ACTUAL
  `authentication.profiles` entry (task's "reject invalid references")
- total identity count must not exceed `max_count` (default 10 --
  task's "enforce maximum identity count" / "explicit resource limits
  preventing unbounded identity creation")

Declaration order is preserved end to end -- `IdentitiesConfig.Identities`
is a plain slice, never re-sorted; `internal/auth.IdentityRegistry`
(mirroring `internal/policy.Registry`'s exact ordered-slice-plus-map
pattern) is what `scanner identities list` iterates, so identity order
in output never depends on Go map iteration order.

`internal/auth.NewIdentityRegistry` performs the identical
duplicate-name check independently -- defense in depth for any caller
that constructs `[]auth.IdentityConfig` directly without going through
`config.Load` (as this package's own tests do).

## 5. CLI

```
scanner identities list
scanner identities show <name>
scanner scan <target> --identity account-a
```

`--identity` is mutually exclusive with `--auth-profile`
(`cmd.MarkFlagsMutuallyExclusive`) -- an operator selects ONE
authentication mechanism per scan, either directly (a bare profile) or
through an identity wrapper, never both. Neither flag is required:
omitting both scans exactly as every pre-Phase-3.14 invocation did.

This phase deliberately does NOT implement `--identity
account-a,account-b` (multiple identities in one scan invocation) --
task's own explicit "do not implement speculative comparison semantics
yet." One scan authenticates as at most one identity; comparing two
identities' results means running two scans and comparing their
results, which this phase's identity-context tagging (section 7) makes
possible without inventing a comparison engine.

Scan output:

```
Auth:
  Identity:               account-a
  Profile:                customer-login
  Status:                 AUTHENTICATED
  Authenticated Requests: 37
  Session Expired:        No
```

`Identity:` is shown only when `--identity` was used; a bare
`--auth-profile` scan shows `Profile:`/`Status:`/etc. exactly as
before, with no `Identity:` line -- backward compatible with Phase
3.14/3.15 output byte-for-byte for that case.

`scanner identities show` never prints a credential value -- only
booleans/names via the same `Profile.Redacted()`/`Session.Redacted()`
mechanism `scanner auth profiles show` already uses.

### Shell completion

Structural completion (flag names, subcommand names) works
automatically. Dynamic completion of an identity NAME is not
implemented, for the identical, empirically-confirmed reason
established in Phase 3.14 (`docs/phase-3-14-authentication.md` section
14): cobra's `__complete` does not run the config-loading
`PersistentPreRunE` before a completion callback.

## 6. Session isolation

This is the most security-critical part of this phase, and it is
**structural**, not merely tested:

- Every `Provider.Authenticate` call builds a brand-new
  `cookiejar.Jar` (`cookiejar.New(nil)` in `formlogin.go`). No two
  `Session` values, from two different `Authenticate` calls -- even for
  the SAME auth profile, even for the SAME identity name run twice --
  ever share the same jar pointer.
- `Session.CookiesFor`/`HeadersFor`/`JarFor` are all host-pinned,
  checked per call, independent of `IdentityName` -- `IdentityName` is
  a display label, never part of the security check
  (`TestAdversarial_SessionFixation_IdentityNameNotPartOfSecurityCheck`
  pins this explicitly: changing a `Session`'s `IdentityName` after
  construction has zero effect on what it releases).
- `Orchestrator.scanPipeline` (Phase 3.14) copies, never mutates, the
  shared `Pipeline` when a session is attached -- unchanged this phase,
  and exactly what makes concurrent/sequential identity switching safe
  without a global mutable session (task section 14's explicit
  requirement).

Proven end to end against the real lab
(`lab/phase3_16_multi_identity_test.go`): two identities' cookie jars
are different objects; a direct HTTP request through each identity's
own session against `/api/data` returns that identity's OWN
`user_id` and never the other's; concurrent authentication and
crawling as both identities never cross-contaminates; four sequential
scans alternating A/B/A/A, reusing ONE `Orchestrator` instance, never
leak a previous scan's identity tag into the next.

## 7. Authenticated crawling

Reuses Phase 3.15's crawler/session integration completely unmodified
-- no second crawler was created. `--identity` differs from
`--auth-profile` only in ONE respect: the resulting `Session` also
carries `IdentityName` (set by `cmd/scanner`'s `authenticateForIdentity`
-- the ONE place in the entire codebase this field is ever populated;
`internal/auth` itself never sets it). Everything downstream --
`Session.JarFor`/`HeadersFor`, `crawler.Options.Jar`/`ExtraHeaders`,
`safedial.PinnedRoundTripper`, session-expiration detection -- is
exactly Phase 3.15's own mechanism, untouched.

## 8. Identity context on discovered resources

`models.Endpoint`/`models.Parameter` gained an `IdentityContext string`
field (migration `0009_identity_context.sql`), stamped in
`internal/orchestration.Pipeline.crawlAndDiscoverEndpoints` from
`Session.IdentityName` at the exact same point `ScanJobID`/
`HTTPServiceID`/`CreatedAt` are already stamped -- empty for an
unauthenticated crawl or a bare `--auth-profile` session (backward
compatible).

Two endpoints with identical `Path`/`Method`/`Source` discovered under
two different identities are never merged into one row: each identity
scan is its own `ScanJobID` (structural isolation, already true before
this phase), and `IdentityContext` makes that fact visible on the row
itself without a join back to the scan job.

`internal/detection.Target` gained the identical field, propagated
verbatim from the `Endpoint`/`Parameter` row it was built from
(`""` for an `HTTPService`-level target, since the probe stage is never
authenticated -- see `docs/phase-3-15-authenticated-crawling.md`
section 2). This is task section 15's "authorization-context model":
a future detector can read `Target.IdentityContext` to know which
identity made a request **without ever touching a `Session`, a
`Profile`, or any credential** -- `internal/detection` has no such
access to begin with (`BuildTargets` reads only already-persisted,
already-redacted rows). No detector in this codebase branches on this
field today.

## 9. Scope enforcement

Unmodified. Every request, under any identity or none, passes through
the exact same `internal/scope.Validator`/`internal/safedial.Dialer` at
the exact same points Phase 1-3.15 already established. Identity is
never consulted by scope logic at all -- there is no code path by
which an identity could expand what host/IP a scan may touch.
`TestPhase3_16_ScopeEnforcement_AppliesIndependentlyToBothIdentities`
proves both configured accounts are refused the identical out-of-scope
resource identically.

## 10. Secret handling

- `Identity.Redacted()` mirrors `Profile.Redacted()`/`Session.Redacted()`
  exactly -- booleans/names only, never a credential value.
- Identity NAMES (`"account-a"`) are operator-chosen labels, always
  safe to display -- never a credential, and this phase adds no new
  field anywhere that could carry one.
- `IdentityContext` (stored, reported) is an identity NAME, subject to
  the identical guarantee.
- Adversarially tested: identity names and auth-profile references
  containing shell/SQL/path-traversal/null-byte/newline-shaped content
  are handled as opaque strings (no shell execution, no raw SQL
  concatenation, no filesystem access keyed on either, anywhere in this
  codebase) -- accepted or cleanly rejected, never causing a crash or a
  collision between two distinct malicious names.
- `TestScanCmd_IdentityFlag_TwoIdentitiesAuthenticateIndependently`
  confirms neither account's password appears in either scan's own CLI
  output, including the OTHER account's output.

## 11. Concurrency model

No global mutable session exists anywhere in this design:

- `Session` is a per-`Authenticate`-call value.
- `Orchestrator`/`Pipeline` hold no identity-keyed shared state --
  `Options.AuthSession` is a per-`Run`-call parameter.
- `net/http/cookiejar.Jar.SetCookies`/`Cookies` are documented safe for
  concurrent use, which is what makes sharing ONE session's jar across
  the concurrent per-target crawl goroutines of a SINGLE scan safe --
  but that sharing never crosses identity boundaries, since each
  identity's `Session` has its own jar to begin with.

Proven under `-race`, repository-wide: simultaneous login as two
identities, simultaneous authenticated crawling, simultaneous full
scans, cancellation mid-authentication -- zero data races reported.

## 12. Resource limits

- `identities.max_count` (default 10) bounds configuration itself,
  checked before any identity is ever resolved.
- Every identity's own login attempt is bounded by its resolved
  `Profile.Timeout`/`MaxRedirects` (Phase 3.14, unchanged).
- No new unbounded resource was introduced: each identity's session
  carries exactly one cookie jar and one small header map; N identities
  means N such small objects, not N times any existing collection this
  codebase already bounds (crawl page counts, evidence limits, finding
  limits -- all pre-existing, untouched).
- Performance was measured qualitatively (task section 20's own
  explicit "do not optimize prematurely"): authenticating and crawling
  as 2 identities sequentially takes approximately 2x one identity's
  own time (each is an independent, full login + crawl), and
  concurrently takes approximately max(A, B) -- consistent with there
  being no shared bottleneck or lock contention between them beyond
  ordinary OS-level connection/goroutine scheduling. No dedicated
  benchmark suite was added; the lab's own concurrent-identity test
  completing in well under a second against 2 accounts and a realistic
  page graph was the practical signal checked.

## 13. Lab architecture

`lab/harness_auth.go` (extended in place, the same file Phase 3.14/3.15
already built) now includes, per task section 16:

- `AccountAUserID = 1001`, `AccountBUserID = 1002` -- deterministic,
  distinct numeric identifiers.
- `/api/data`'s JSON response and `/profile`'s HTML response both
  include the CALLER's own `user_id` -- always the account whose
  session made the request, via `requireSession`'s own lookup, never
  any other account's. There is no code path in this fixture that
  could return a different account's `user_id`: task's explicit "do
  NOT make the lab automatically report an IDOR finding" is satisfied
  by construction, not by omission.

This lets `lab/phase3_16_multi_identity_test.go` prove, directly at the
HTTP level (not merely inferred from configuration), that Account A's
session and Account B's session are functionally distinct: the SAME
endpoint, hit through each identity's own client, returns that
identity's own, and only its own, `user_id`.

## 14. Current limitations

- No cross-identity comparison engine -- explicitly deferred (task's
  own "do not implement automated IDOR detection").
- `--identity account-a,account-b` (multiple identities in one scan
  invocation) is not implemented -- deferred alongside comparison
  semantics, since a plausible use for it IS comparison.
- Identity-scoped rate limiting/resource quotas beyond `max_count` do
  not exist -- N identities in one CONFIG is bounded, but nothing
  currently limits how many identities one CLI invocation could
  theoretically be asked to run in sequence via a wrapper script; this
  is an operational, not architectural, gap (each individual scan is
  still fully bounded).
- Session-expiration detection inherits Phase 3.15's own documented
  limitation (401/403 only, no redirect-to-login heuristic) --
  unchanged this phase, and applies identically per identity.
