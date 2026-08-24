# Phase 3.16 Acceptance Test: Multi-Identity Authentication & Account Context Foundation

**Phase 3.16 provides identity/session context for future authorization
testing. It does not itself perform automated IDOR/BOLA detection.**

## What was built

- **`internal/auth`**: `IdentityState` (6 states) +
  `identityStateFromAuthState`; `IdentityConfig`, `Identity`,
  `NewIdentity`, `Identity.WithSession`, `IdentitySummary`,
  `Identity.Redacted`, `UnknownIdentityError`; `IdentityRegistry`
  (mirrors `internal/policy.Registry`'s ordered-slice-plus-map
  pattern); `ResolveIdentityProfile` (the credential-override
  mechanism). `Session.IdentityName` field (set only by
  `cmd/scanner`, never by `internal/auth` itself).
  17 unit tests, 6 adversarial tests.
- **`internal/config`**: `Config.Identities IdentitiesConfig`;
  `IdentitiesConfig`/`IdentityConfig`; `identities.max_count` (default
  10); structural validation (duplicate names, max count, invalid
  `auth_profile` references) at `Config.Validate()` time, zero network
  I/O. 5 table cases + 3 standalone tests.
- **`internal/storage`**: migration `0009_identity_context.sql` adds
  `identity_context` to `endpoints` and `parameters`.
  `pkg/models.Endpoint`/`Parameter` gained `IdentityContext string`.
  Storage layer (`internal/storage/sqlite/repos.go`) updated
  end-to-end (Create/Get/ListByScanJob). 1 round-trip test.
- **`internal/detection`**: `Target.IdentityContext string`,
  propagated verbatim in `BuildTargets`/`endpointTargets`. 1 test.
- **`internal/orchestrator`**: `Result.Identity string`, computed in
  `buildResult`, distinct from the pre-existing `Result.AuthProfile`.
  2 tests.
- **`internal/orchestration`**: `Pipeline.crawlAndDiscoverEndpoints`
  stamps `IdentityContext` onto every discovered `Endpoint`/`Parameter`
  from `AuthSession.IdentityName`.
- **`cmd/scanner`**: `identities list`/`identities show <name>`
  (`identities.go`); `scan --identity <name>` (mutually exclusive with
  `--auth-profile`); `authenticateForIdentity` +
  extracted-shared `performAuthentication`; `Auth:` block gained
  `Identity:` line; `--help` documents `--identity` including the
  non-IDOR disclaimer.
- **`lab/harness_auth.go`** (extended in place): `AccountAUserID =
  1001`, `AccountBUserID = 1002`, `userIDFor`; `/profile` and
  `/api/data` now report the caller's own `user_id`, deliberately never
  another account's -- no IDOR is introduced by the fixture itself.
- **Documentation**: `docs/phase-3-16-multi-identity.md`
  (architecture), this file.

## Design decisions worth recording

1. **Identity is a wrapper, not a duplicate mechanism.**
   `IdentityConfig` carries a profile REFERENCE plus optional
   credential-env overrides only -- login URL, field names, and success
   indicators are never re-specified per identity. Two identities can
   share one `auth_profile` and resolve to fully independent
   credentials (`ResolveIdentityProfile`, proven by
   `TestAdversarial_SharedAuthProfile_NoCredentialContamination`).
2. **Three separate state vocabularies, not one merged enum.**
   `orchestrator.Status` (scan progress), `auth.State` (one login
   attempt), and the new `auth.IdentityState` (identity lifecycle,
   including two states -- `IDENTITY_CONFIGURED`, `IDENTITY_DISABLED`
   -- that have no `auth.State` equivalent because they apply before a
   `Session` exists) are kept distinct, matching how Phase 3.14 already
   kept `orchestrator.Status` and `auth.State` distinct rather than
   inventing a single combined enum.
3. **`IdentityContext` is a plain string, not a new abstraction.** Task
   section 15 asked for "a way for a future detector to know which
   identity made a request." Rather than invent a `RequestContext`
   type, the existing Endpoint -> Parameter -> Target propagation chain
   (already used for `ScanJobID`, `HTTPServiceID`) was extended by one
   field. `internal/detection` already has no access to `Session` or
   credentials, so this satisfies the requirement with the smallest
   possible surface.
4. **No cross-identity comparison code was written anywhere**,
   including in the lab. `/api/data`'s `user_id` field lets a TEST
   compare two identities' raw responses directly, but nothing in
   `internal/detection`, `internal/orchestrator`, or `internal/orchestration`
   reads or compares one identity's discoveries against another's. This
   was checked explicitly, not merely assumed, before writing the final
   report below.
5. **`--identity account-a,account-b` was deliberately not built.**
   The task explicitly deferred multi-identity-per-scan comparison
   semantics; a plausible use for accepting a list would BE comparison,
   so building the flag without the semantics it implies would be
   misleading. `--identity` accepts exactly one name.
6. **No new bugs were found during this phase's own development** (see
   REGRESSION section below) -- unlike Phase 3.15, which found and
   fixed two real defects. Every compile error encountered while
   writing tests (a helper-name collision, a bad draft stub, missing
   imports, a bare-IP-as-hostname mistake, two unused test-server
   variables) was caught by `go vet`/`gofmt` before any test ran, and
   none of them were logic bugs in the production code. This is
   recorded honestly rather than manufacturing a "bug found and fixed"
   narrative to match the shape of prior phases' reports.

## Test matrix results

### IDENTITY MODEL
`IdentityState` construction/transitions, `identityStateFromAuthState`
covering all four mapped `auth.State` values plus the two states with
no `auth.State` equivalent, `NewIdentity`, `WithSession`,
`IdentitySummary`, `Identity.Redacted` (never exposes a credential),
`UnknownIdentityError`. `IdentityRegistry`: construction, duplicate-name
rejection, `Get`/`List`/`Names`, declaration-order preservation.
**PASS**

### AUTH PROFILE SEPARATION
`ResolveIdentityProfile`: unknown profile reference rejected, mechanism
fields (URL/field names/success indicator) never overridden by an
identity, credential fields (`Username`/`Password`/`Token`/`Cookie`/
`HeaderValue`) overridden independently per identity,
`TestResolveIdentityProfile_TwoIdentities_SameProfile_IndependentCredentials`
proves two identities sharing one profile resolve to fully independent
credentials, underlying `[]ProfileConfig` never mutated
(`TestAdversarial_SharedAuthProfile_NoCredentialContamination`).
**PASS**

### MULTI-IDENTITY AUTHENTICATION
`scanner identities list`/`show <name>` (structural inspection, zero
network I/O); `scanner scan --identity <name>` authenticates via the
resolved profile through the real Phase 3.14 `Provider`/`Authenticate`
machinery, unmodified; `--identity`/`--auth-profile` mutual exclusivity
enforced by cobra; unknown identity name exits cleanly (exit code 5, no
scan job created) rather than attempting a scan with a broken
reference. Two real accounts (Account A / Account B) authenticated
independently against the lab end to end
(`TestPhase3_16_EndToEnd_TwoIdentities_IsolatedSessionsAndDiscoveries`).
**PASS**

### SESSION ISOLATION
Structural: every `Provider.Authenticate` call builds a fresh
`cookiejar.Jar` -- no code path shares a jar pointer across two
`Session` values, identity or not (unchanged from Phase 3.14/3.15).
`CookiesFor`/`HeadersFor`/`JarFor` key only on `Host`, never on
`IdentityName`
(`TestAdversarial_SessionFixation_IdentityNameNotPartOfSecurityCheck`
proves reassigning `IdentityName` post-construction has zero effect on
access). Proven at the HTTP level against the real lab: Account A's and
Account B's sessions return their OWN, and only their own, `user_id`
from `/api/data`
(`TestPhase3_16_EndToEnd_TwoIdentities_IsolatedSessionsAndDiscoveries`).
Concurrent authentication + crawling as both identities simultaneously,
no cross-contamination, race-clean
(`TestPhase3_16_ConcurrentIdentities_AccountAAndB`). Four sequential
scans reusing ONE `Orchestrator` instance, alternating/repeating
identities, never leak a previous identity's tag into the next
(`TestPhase3_16_SequentialScans_AlternatingAndRepeatedIdentities`).
**PASS**

### AUTHENTICATED CRAWLING
Reuses Phase 3.15's crawler/session integration completely unmodified.
`--identity`'s only behavioral difference from `--auth-profile` is that
the resulting `Session` also carries `IdentityName`. Full page-graph
discovery proven per identity against the real lab
(`TestPhase3_16_EndToEnd_TwoIdentities_IsolatedSessionsAndDiscoveries`,
`TestScanCmd_ProfileWebAndIdentity_AuthenticatedCrawlDiscoversAccountMarker`).
**PASS**

### IDENTITY CONTEXT
`Endpoint`/`Parameter.IdentityContext` round-trips through SQLite
(`TestEndpointAndParameter_IdentityContext_RoundTrips`); stamped from
`AuthSession.IdentityName` during real crawling, empty for
unauthenticated/bare-profile crawls (backward compatible);
`detection.Target.IdentityContext` propagates verbatim from the
discovered row (`TestBuildTargets_IdentityContext_PropagatesFromEndpoint`);
`orchestrator.Result.Identity` distinct from the pre-existing
`Result.AuthProfile`
(`TestBuildResult_IdentityDistinctFromAuthProfile`,
`TestBuildResult_BareAuthProfile_NoIdentity`); end-to-end confirmation
that two identities scanning the same target produce structurally
separate, correctly-tagged discoveries
(`TestPhase3_16_EndToEnd_TwoIdentities_IsolatedSessionsAndDiscoveries`).
**PASS**

### SCOPE ENFORCEMENT
Unmodified `internal/scope`/`internal/safedial` path, identity never
consulted by any scope decision.
`TestPhase3_16_ScopeEnforcement_AppliesIndependentlyToBothIdentities`
proves both configured accounts are refused the identical out-of-scope
resource identically. **PASS**

### SECRET PROTECTION
`Identity.Redacted()` mirrors `Profile.Redacted()`/`Session.Redacted()`
exactly. Neither account's password appears in the other's (or its
own) CLI output, report, or log
(`TestScanCmd_IdentityFlag_TwoIdentitiesAuthenticateIndependently`).
Identity-name injection (shell/SQL/path-traversal/null-byte/newline/
10,000-char strings) handled as opaque, non-executable, non-colliding
labels (`TestAdversarial_IdentityNameInjection_ShapedStrings`,
`TestAdversarial_IdentityNameInjection_TwoDistinctShapedNames_NeverCollide`).
Malformed profile-reference injection rejected, never matches
unintended profile
(`TestAdversarial_MalformedIdentityProfileReference_Injection`). **PASS**

### SCAN ISOLATION
Every identity scan is its own `ScanJobID` (structural, pre-existing);
`IdentityContext` makes the association visible on each row without a
join. No merging of identical URLs discovered under different
identities. **PASS**

### CONCURRENCY
Full repository-wide suite, including all Phase 3.16 additions, passes
under `-race` with zero races reported.
`TestPhase3_16_ConcurrentIdentities_AccountAAndB` (true concurrent
goroutines authenticating+scanning as two identities);
`TestAdversarial_CancellationDuringIdentityAuthentication_NoHang`
(cancellation mid-login via the identity-resolution path specifically,
not just the bare-profile path). Construction helpers that can call
`t.Fatalf` are, per the established Phase 3.15 rule, always invoked
from the main test goroutine before any goroutine is spawned. **PASS**

### DETERMINISM
`TestPhase3_16_Determinism_RepeatedIdentityScans_SameStructuralCounts`
-- repeated identical identity-authenticated scans produce identical
structural endpoint/parameter counts and identical `IdentityContext`
values every time. Declaration order preserved end to end (config YAML
list order -> `IdentityRegistry.List()` -> CLI output), never dependent
on Go map iteration. **PASS**

### RESOURCE LIMITS
`identities.max_count` (default 10) enforced structurally at
`config.Validate()` time, before any network activity -- the task's
required "explicit resource limit preventing unbounded identity
creation." Each identity's own login is bounded by its resolved
profile's existing `Timeout`/`MaxRedirects` (Phase 3.14, unchanged). No
new unbounded collection was introduced; N identities means N small
per-session objects (one jar, one header map each), not N times any
pre-existing bounded resource (crawl page counts, evidence limits).
Qualitative performance observation (task explicitly says do not
optimize prematurely): 2 identities scanned sequentially take
approximately 2x one identity's own time; scanned concurrently,
approximately max(A, B) -- consistent with no shared bottleneck between
identities beyond ordinary OS-level scheduling. **PASS**

### LAB
`lab/harness_auth.go` extended in place: `AccountAUserID`/
`AccountBUserID`, `userIDFor`, `/profile` and `/api/data` report only
the caller's own `user_id` -- verified by reading the handler code that
no path can return a different account's ID (no IDOR is introduced by
the fixture). Full `go test ./lab/...`: every prior phase's own tests
re-verified alongside the new multi-identity tests, 0 regressions.
Physical `lab/`+`tests/` removal, production `go build`/`go vet`
success, restoration, and a confirming rebuild: re-verified this phase
(see REGRESSION below). **PASS**

### E2E
`scanner identities list`/`show <name>` through the real built binary;
unknown identity name (exit code 5, no scan job);
`--identity`/`--auth-profile` mutual exclusivity enforced by the real
CLI; `--profile web --identity <name>` performs real authenticated
crawling and discovers an account-specific marker through the actual
binary, not a mock; shell completion lists the new `identities`
subcommands. Full `tests/e2e` suite: 76 PASS, 0 FAIL. **PASS**

### ADVERSARIAL (task section 19)

| # | Scenario | Covered by |
|---|---|---|
| 1 | Shared auth-profile credential contamination | `TestAdversarial_SharedAuthProfile_NoCredentialContamination` |
| 2 | Identity name injection (shell/SQL/path/null-byte/newline/oversized) | `TestAdversarial_IdentityNameInjection_ShapedStrings` |
| 3 | Two distinct shaped names never collide | `TestAdversarial_IdentityNameInjection_TwoDistinctShapedNames_NeverCollide` |
| 4 | Malformed/injection-shaped profile reference | `TestAdversarial_MalformedIdentityProfileReference_Injection` |
| 5 | Session fixation via IdentityName reassignment | `TestAdversarial_SessionFixation_IdentityNameNotPartOfSecurityCheck` |
| 6 | Cancellation during identity-based authentication | `TestAdversarial_CancellationDuringIdentityAuthentication_NoHang` |
| 7 | Cross-identity session/cookie leakage | `TestPhase3_16_ConcurrentIdentities_AccountAAndB`, structural jar-per-Authenticate-call proof |
| 8 | Scope bypass via identity | `TestPhase3_16_ScopeEnforcement_AppliesIndependentlyToBothIdentities` |
| 9 | Secret leakage across identities | `TestScanCmd_IdentityFlag_TwoIdentitiesAuthenticateIndependently` |
| 10 | Unknown identity reference at CLI level | `TestScanCmd_IdentityFlag_UnknownIdentity_ExitCode5_NoScanJob` |
| 11 | Concurrent identity corruption | `-race`-clean across the full suite |
| 12 | Config-level: duplicate names, invalid profile refs, max_count exceeded | `internal/config` table + standalone tests |

All 12 scenarios: **NO CROSS-IDENTITY CONTAMINATION. PASS.**

### REGRESSION

Full repository, fresh run this phase:

```
go build ./...                                          -> clean
go vet ./...                                             -> clean
gofmt -l .                                                -> clean (no output)
go test $(go list ./... | grep -v '/tests/e2e') -race     -> ok, 1160 PASS, 0 FAIL (all 32 packages)
go test ./tests/e2e/...                                   -> ok, 76 PASS, 0 FAIL
```

Production/lab independence re-verified the strongest way: physically
removed `lab/` and `tests/` from disk, confirmed `grep -rl
"sakanner/lab"` outside `lab/` itself returns nothing, rebuilt and
vetted the production scanner successfully, restored both directories,
rebuilt again to confirm restoration was complete.

No pre-existing test required correction this phase (contrast Phase
3.15, which corrected two). No existing test's assertion was relaxed,
removed, or weakened.

## Final report

```
PHASE 3.16 MULTI-IDENTITY AUTHENTICATION & ACCOUNT CONTEXT FOUNDATION

TOTAL TESTS: 1236
PASS: 1236
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

IDENTITY MODEL:
PASS -- IdentityState (6 states), identityStateFromAuthState mapping,
IdentityRegistry mirroring policy.Registry's deterministic ordering,
Identity.Redacted never exposes a credential

AUTH PROFILE SEPARATION:
PASS -- Identity references a profile and overrides only credential
fields; mechanism fields (URL, field names, success indicator) are
never duplicated or overridden per identity; two identities sharing one
profile resolve to fully independent credentials

MULTI-IDENTITY AUTHENTICATION:
PASS -- scanner identities list/show, scan --identity, mutual
exclusivity with --auth-profile, two real accounts authenticated
independently end to end against the lab

SESSION ISOLATION:
PASS -- structural (fresh cookiejar.Jar per Authenticate call, host-
pinned access keyed only on Host, never IdentityName), proven at the
HTTP level (each identity's session returns only its own user_id),
concurrent and sequential identity switching both race-clean with zero
cross-contamination

AUTHENTICATED CRAWLING:
PASS -- Phase 3.15's crawler/session integration reused unmodified;
--identity differs from --auth-profile only in the IdentityName label
carried on the resulting Session

IDENTITY CONTEXT:
PASS -- Endpoint/Parameter/Target/Result all carry IdentityContext,
round-tripped through SQLite, propagated end to end, empty/backward-
compatible for unauthenticated and bare-auth-profile scans

SCOPE ENFORCEMENT:
PASS -- unchanged internal/scope path, identity never consulted by any
scope decision, both accounts refused an out-of-scope resource
identically

SECRET PROTECTION:
PASS -- no credential ever appears in CLI output, report, or log for
either identity; identity-name and profile-reference injection handled
as opaque, non-executable, non-colliding strings

SCAN ISOLATION:
PASS -- every identity scan is its own ScanJobID; IdentityContext makes
this visible without merging discoveries across identities

CONCURRENCY:
PASS -- full suite race-clean; true concurrent two-identity
authentication and crawling proven with zero data races; cancellation
mid-identity-login proven not to hang

DETERMINISM:
PASS -- repeated identity-authenticated scans produce identical
structural counts and identity tags; declaration order preserved end
to end, never dependent on map iteration

RESOURCE LIMITS:
PASS -- identities.max_count (default 10) enforced structurally before
any network activity; no new unbounded resource introduced; qualitative
sequential-vs-concurrent timing behaves as expected with no shared
bottleneck

LAB:
PASS -- Account A/B with distinct numeric user_ids, /profile and
/api/data report only the caller's own id, no IDOR introduced by the
fixture itself; physical production/lab independence re-verified

E2E:
PASS -- 76 tests including real-binary identities list/show,
--identity/--auth-profile mutual exclusivity, and --profile web
--identity authenticated crawling to an account-specific marker

ADVERSARIAL:
PASS -- all 12 task section 19 scenarios demonstrated by an actual
test, none merely claimed

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0
(no defect was found in production code during this phase's own
development; all compile-time mistakes caught by go vet/gofmt before
any test executed, none were logic bugs -- see "Design decisions" #6
in the accompanying acceptance-test document for the honest accounting
of this, in contrast to Phase 3.15 which found and fixed two real
defects)

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
PHASE 3.13 REGRESSION: PASS
PHASE 3.14 REGRESSION: PASS
PHASE 3.15 REGRESSION: PASS

PHASE 3.16 ADVERSARIAL: PASS

PHASE 3.16 VERDICT: PASS
```

## No architectural issue flagged

Per this phase's own "if an architectural weakness is found, fix it if
clearly in-scope, otherwise STOP and report" instruction: no
out-of-scope architectural weakness was found during this phase's
development. The one limitation worth carrying forward explicitly is
not new to this phase -- session-expiration detection's documented
401/403-only limitation (Phase 3.15, unchanged) applies identically,
independently, per identity, and remains exactly as capable/incapable
as it was before.

Per the task's final rule: automated IDOR/BOLA detection,
`--identity a,b` comparison semantics, and any new vulnerability
detector are explicitly NOT started. Work stops here pending a new
phase instruction.
