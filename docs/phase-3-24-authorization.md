# Phase 3.24: Authorization & IDOR/BOLA Detection Foundation

## 0. Scope discipline

This phase introduces exactly one new vulnerability class: horizontal
authorization failure (IDOR/BOLA), read-only, GET/HEAD-preferring, via
a single baseline+compare identity pair. No privilege escalation,
account takeover, credential/password attacks, CSRF detection, mass
assignment, SSRF, command injection, new SQLi/XSS techniques, path
traversal detection, or destructive testing.

## 1. Architecture review

Traced with exact citations, not assumed.

### 1.1 The central gap: every layer is hard-wired to ONE identity

- `auth.Session` (`model.go:180-193`) has no credential fields (only
  `Host`/`Jar`/`Headers`/`IdentityName`/etc.) -- safe to pass around,
  but `Provider.Authenticate` (`provider.go:27-29`) always returns
  exactly one `*Session` per call; **no dual-identity authentication
  function exists anywhere** (verified by repository-wide grep).
- `orchestrator.Options.AuthSession *auth.Session`
  (`orchestrator.go:96`) is a single pointer, threaded through
  `buildDetectionExecutor(ctx, session *auth.Session)`
  (`orchestrator.go:654-668`) into exactly one `mutation.SessionContext`
  → one `*detection.Executor`.
- `detection.Detector.Detect(ctx, t Target, x *Executor)`
  (`detector.go:177-198`) receives exactly one `*Executor`, already
  bound to one session -- this interface is **not changed** by this
  phase (task's own "do not rewrite existing detectors").
- `cmd/scanner scan --identity` (`scan.go:181`) is a `StringVar`
  (single value), `MarkFlagsMutuallyExclusive("auth-profile",
  "identity")` (`scan.go:182`). **Its own doc comment
  (`scan.go:148-150`) states outright**: *"This phase does not
  implement automated cross-identity comparison (IDOR/BOLA
  detection); it establishes the identity/session context a future
  phase would need for that."* This phase is that future phase.

### 1.2 The existing precedent: `internal/detectors/idor` (Phase 3.5)

A complete, working, but disabled-by-default detector already solves
"one detector needs more than one identity's credentials" --
`New([]AuthContext)` (`idor/detector.go:70-72`) takes a slice of
synthetic, pre-authenticated identity contexts
(`AuthContext{ID, Headers, OwnsResourceIDs}`, `idor/authcontext.go:26-30`),
looped over internally (`Detect`, `idor/detector.go:141`). Registered
with `idor.New(nil)` (`cmd/scanner/detectors.go:65`) and disabled
(`cmd/scanner/detectors.go:73-77`) because "this build does not ship...
at least 2 pre-authenticated AuthContext values plus resource-ownership
ground truth." **Critically, `idor` does not import `internal/mutation`
at all** -- it builds its own `*http.Request` and attaches each
`AuthContext`'s headers manually (`probeAs`, `idor/detector.go:307-326`),
routing around `Executor`'s single-session limitation entirely rather
than through the canonical mutation engine.

**Resolution, mirroring the naming-collision pattern established in
every prior phase (xssreflected→xssactive, sqli→sqliactive):** a NEW,
coexisting package, `internal/detectors/idoractive`, built on
`internal/mutation`'s canonical `Request`/`Mutate`/`Execute` model (per
task section 9's explicit "reuse internal/mutation, do not manually
construct HTTP requests" -- which the OLD `idor` package does not
satisfy). `internal/detectors/idor` is left completely untouched,
exactly as `internal/detectors/sqli`/`xssreflected` were in Phase
3.20/3.19.

### 1.3 What this means for `idoractive`'s own constructor

Following the SAME established pattern `idor.New([]AuthContext)`
already uses (a detector that needs more identity context than the
`Detector` interface's own `Detect(ctx, t, x)` provides gets it via
its OWN constructor, supplied by `cmd/scanner/detectors.go` before
`Registry.Register` is ever called -- `Register` itself takes nothing
but the already-constructed `Detector`, confirmed by reading
`registry.go` in full): `idoractive.New(compareExecutor
*detection.Executor, compareIdentity string)`. `compareExecutor` is a
SECOND `*detection.Executor`, built the exact same way
`buildDetectionExecutor` already builds the primary one -- just wrapping
a second `mutation.SessionContext` for a second, independently-
authenticated `*auth.Session`. No second scope validator, no second
resolver, no second HTTP client: the same `Executor`/`mutation.Executor`
type, constructed twice.

## 2. Authorization model -- reusing existing models, no new one

Per the task's own "introduce a canonical model only if existing
models cannot express the required semantics": they can, and do.

| Task's required concept | Existing model |
|---|---|
| Acting identity | `Target.IdentityContext` (baseline, already exists) |
| Baseline identity | Same -- the scan's own primary `--identity` |
| Compare identity | New: a plain `string` (identity name), carried on the new `idoractive.Detector` struct, never a credential |
| Target identity/object context | `Target.Parameter`/`Target.Value` (via the Parameter row) -- already exists |
| Original request | `mutation.Request` (`Origin: OriginOriginal`) -- already exists |
| Authorization-test request | `mutation.Request` (`Origin: OriginMutated`), executed via the COMPARE identity's own `*detection.Executor` -- reuses `detection.NewMutationRequest`/`mutation.Mutate` unchanged |
| Original response | `mutation.Response` -- already exists |
| Authorization-test response | `mutation.Response` -- already exists |
| Comparison result | `mutation.Compare(a, b) ComparisonResult` -- already exists, reused unchanged |

No new struct is introduced for any of these. `Finding`/`Evidence`
(via `detection.MutationEvidence`, unchanged) already carry everything
needed -- see section 12. The only genuinely new piece of state is the
compare identity's NAME (a label, never a credential) and its
`*detection.Executor` (never exposed on `Target` or `Finding` --
private to the detector, exactly like `x *Executor` is already private
to every other detector's own `Detect` call).

## 3. IDOR/BOLA testing principle -- the three-probe design

Neither "different response" nor "same response" is used as the sole
signal (task's own explicit prohibition). Three probes, all via the
SAME canonical mutation engine, distinguishing the required cases:

1. **Baseline** -- replay the EXACT original request (unmodified
   value) via the PRIMARY (baseline) identity's executor. Must be
   `mutation.OutcomeSuccess` AND pass `looksLikeSuccessfulObjectResponse`
   (section 10) -- otherwise `OutcomeSkipped` (no finding is ever
   claimed from a baseline that isn't itself clearly successful).
2. **Cross-test** -- the IDENTICAL request (same object value, same
   path/query/body) via the COMPARE identity's executor. This is what
   proves (or fails to prove) unauthorized access.
3. **Known-bad control** -- the SAME request shape, but with the
   object value mutated to a synthetic, guaranteed-nonexistent value
   (a fixed, deterministic sentinel, never a guess at a real ID),
   still via the COMPARE identity's executor. Establishes what "this
   endpoint denies/doesn't-have an object" looks like FROM THE COMPARE
   IDENTITY'S OWN PERSPECTIVE -- directly defeating the "same response
   for every object" / "generic API envelope" false-positive classes
   (task section 15 items 2-4): if the cross-test response is
   `mutation.Compare`-similar to the known-bad response rather than to
   the baseline, the endpoint is not actually identity-sensitive for
   this parameter, and no finding is produced.

**Finding requires ALL of:** baseline succeeds and looks like real
object content; cross-test succeeds AND looks like real object content
AND is structurally similar to baseline (`mutation.Compare`, reused
unchanged) AND is structurally DIFFERENT from the known-bad control.
Missing any one of these four conditions → `OutcomeNoFinding`,
never a partial/weak finding -- this is deliberately a single, high bar,
not a multi-tier confidence ladder like `sqliactive`'s: false positives
here are far more costly than in SQLi/XSS (task's own explicit "prefer
false negatives").

## 4. Horizontal authorization -- identity pairing

`Account A → Object A` (baseline) and `Account B → Object A`
(cross-test) is the primary case this phase proves, plus the
known-bad control (section 3) as `Account B`'s own negative baseline
-- this satisfies "the second request establishes the appropriate
comparison/baseline where possible" without requiring a SECOND crawl
authenticated as Account B (which this phase does not add -- see
section 6). `Object A`'s VALUE always comes from a REAL, discovered
Parameter (REQUEST_INPUT provenance, discovered under the PRIMARY
identity's own authenticated crawl) -- never invented.

Works across query/form/JSON/path locations because it operates on
`detection.Target` uniformly, exactly like `sqliactive`/`xssactive`
already do -- `Eligible` accepts any of `query`/`form`/`body`/`path`
(the same four locations those two detectors already support, unified
by Phase 3.19-3.23), gated further by the object-identifier name
heuristic (section 8).

## 5. Object context -- the identifier-vs-object distinction

`/users/123` is not automatically an authorization target merely
because `123` looks like an ID (task's own explicit warning). Two
independent, conservative gates, both required:

1. **Name-shape evidence** (`parameters.IsLikelyObjectIdentifier`, new
   -- section 8): the parameter's NAME must look like an object
   reference (`user_id`, `account_id`, `order_id`, ... or a generic
   `*_id`/`id` shape), not a structural/pagination/version/timestamp
   parameter.
2. **Discovery evidence** (already exists, reused): the Target's
   underlying Parameter must have `Provenance == "REQUEST_INPUT"`
   (already enforced by `BuildTargets`, unchanged) -- i.e. the
   application itself rendered/returned this exact value as something
   it accepts, not a value this phase invents. `idoractive.Eligible`
   adds no new provenance logic; `BuildTargets` already guarantees
   this for every location Phase 3.19-3.23 wired up.

This phase does NOT attempt to infer "who owns this object" from
crawl evidence beyond the above (task's own "do not invent object
ownership when no evidence exists" -- ownership is what the THREE-PROBE
comparison in section 3 exists to establish empirically, at request
time, not what discovery pre-classifies).

## 6. Identity pairing -- one pair, not a matrix

This phase deliberately supports exactly ONE baseline+compare identity
PAIR per scan (not N×M identity combinations) -- a proportionate,
well-scoped "foundation," matching the task's own canonical
Account-A/Account-B worked example throughout. `cmd/scanner scan`
gains one new flag, `--authz-identity <name>` (used ALONGSIDE the
existing `--identity <name>`, which becomes the baseline/primary
identity when authorization testing is requested) -- its mere presence
is what enables `idoractive` (mirroring the established
nil-dependency-means-disabled precedent from `ssrf`/`idor`/
`traversal`); no separate boolean flag is needed for "enable/disable."
Both identity names are resolved and validated via the EXISTING
`auth.IdentityConfig`/`ResolveIdentityProfile` lookup (unchanged) --
an unknown identity name fails immediately, before any network
activity, exactly like the existing `--identity` flag already does.

Authentication for both identities reuses `authenticateForIdentity`
(`scan.go:322`, unchanged) called TWICE -- once per identity, fully
sequential, each producing its own independent `*auth.Session`. No new
authentication code.

## 7. Session isolation

Reused, unchanged, from Phase 3.19's own `mutation.SessionContext`
host-pinning (`PinnedHost`, checked via `strings.EqualFold` before a
cookie jar is ever attached, `executor.go`) -- the SAME mechanism that
already keeps Phase 3.16/3.19's identity tests race-clean. The two
`*detection.Executor` values `idoractive` holds (baseline -- received
via the normal `Detect(ctx, t, x)` parameter, exactly like every other
detector -- and compare -- held as the detector's own field) are two
entirely independent `*mutation.Executor` wrappers with two
independent `SessionContext`s; nothing is shared or mutated between
them. Proven adversarially (section 15/24) with an HTTP-level cookie
assertion, mirroring Phase 3.21's own
`TestDetect_FormMutation_TwoIdentities_DistinctCookiesAtHTTPLevel`
precedent exactly.

## 8. Object-identifier classification

`parameters.IsLikelyObjectIdentifier(name string) bool` (new, in
`internal/parameters`, mirroring `IsLikelySecurityToken`'s exact
precedent -- a pure, name-based function, not a stored column, so
"future improvement of object-identifier classification" never
requires touching `idoractive` itself, satisfying task section 8's own
explicit forward-compatibility ask). Exact-matches a conservative
allowlist of common object-reference names (`user_id`, `account_id`,
`order_id`, `document_id`, `invoice_id`, `profile_id`, `customer_id`,
`resource_id`, `item_id`, `object_id`, plus bare `id`) and a generic
`*_id`/`*Id` suffix shape, while explicitly EXCLUDING known non-object
shapes the adversarial list names directly: pagination
(`page`/`limit`/`offset`/`per_page`/`size`), version
(`version`/`v`/`api_version`), timestamps (`timestamp`/`ts`/`date`/
`time`), and locale/format noise (`lang`/`locale`/`format`/`sort`/
`order`/`callback`) -- an explicit denylist checked BEFORE the
allowlist, so e.g. `order` (sort direction) is never confused with
`order_id` (an object reference).

## 9. Safe mutation -- reusing `internal/mutation` unchanged

`idoractive.Detect` builds its baseline/cross-test/known-bad requests
using `detection.NewMutationRequest`/`detection.NewTargetMutation`/
`mutation.Mutate` -- the EXACT SAME three calls `sqliactive`/`xssactive`
already use (Phase 3.19-3.23, unchanged). No detector-specific request
construction exists anywhere in this package. `NewTargetMutation`
already handles `LocationPath`'s `PathSegmentIndex` requirement
(Phase 3.23) and `FormFields` sibling-preservation (Phase 3.21) --
`idoractive` inherits both for free, exactly like the other two
detectors do. The ONLY new thing is which `*detection.Executor` a
given probe is issued through (baseline executor for probe 1, compare
executor for probes 2-3) -- never a new HTTP client, cookie jar, or
scope decision.

## 10. Response comparison -- reused, with one small, justified addition

`mutation.Compare` (Phase 3.17, unchanged) is reused directly for the
cross-test-vs-baseline and cross-test-vs-known-bad structural
comparisons (section 3). One new, small, `idoractive`-local classifier
is added -- `looksLikeSuccessfulObjectResponse(resp mutation.Response) bool`
-- since `mutation.Compare` answers "are these two responses similar
to EACH OTHER," not "does this ONE response look like real,
successfully-authorized content" (a genuinely new question this phase
needs answered that no existing primitive answers, per task section
10's own "extend it only if authorization semantics genuinely require
new capabilities"). Conservative, status-code-plus-shape based (NOT
status-code alone, per the task's own "200 ≠ automatically authorized,
403 ≠ automatically safe, 404 ≠ automatically safe"):
- Status code must be 2xx (a 3xx/4xx/5xx never counts as "successful
  object content," regardless of body).
- Body must be non-trivially-empty (bounded minimum length -- an empty
  or near-empty 200 is exactly task section 15 item 8's "empty
  object").
- Body must not match a small, conservative login-page/redirect-page
  signature set (case-insensitive substring check against a short,
  explicit list: `"log in"`, `"login"`, `"sign in"`, `"session
  expired"`, `"please authenticate"` -- deliberately narrow, mirroring
  every other narrow, explicit signature list already established in
  this codebase, e.g. `dbErrorPatterns`).

This function is used on ALL THREE probe responses -- the baseline
must pass it (else skip entirely), the cross-test must pass it (else
no finding), and the known-bad control is EXPECTED to fail it (or at
least differ structurally) in the common case, though it is not
independently required to fail it -- what matters is the STRUCTURAL
comparison between cross-test and known-bad (section 3), not this
classifier's verdict on the known-bad response by itself.

## 11. Proof of access -- evidence content

Every finding's evidence (via `detection.MutationEvidence`, unchanged)
carries: the baseline request/response (redacted, as
`MutationEvidence` already does for every other detector), the
cross-test request/response, and the known-bad control's request/
response -- three evidence items, mirroring `sqliactive`'s own
2-3-evidence-item convention. The `Observation`/`Reason` text
explicitly states the structural-similarity verdicts
(`StructurallyDifferent`/`BodyNormalizedIdentical` values) that led to
the finding, so a human reviewer can see EXACTLY why this was judged
unauthorized access, not just "trust the tool." Opportunistic
additional evidence: if the object's own identifier VALUE appears
verbatim in the baseline response body, this is noted in the
`Observation` text (stronger ownership corroboration) -- but never
REQUIRED for a finding (not every API echoes the ID back).

## 12. Finding model

`VulnerabilityType: "idor"` (new value, consistent with the existing
free-string convention `models.Finding.VulnerabilityType` already
uses -- `"sql_injection"`, `"reflected_xss"`, etc. -- no enum exists to
extend). `Finding.IdentityContext` is set to the COMPARE identity's
name (the identity that successfully accessed another account's
object -- the operationally meaningful one to flag, matching how
every other detector's `IdentityContext` already records "which
identity's session made the request that triggered this finding").
The baseline identity's name appears in the `Description` text (plain,
non-secret label, exactly like `IdentityContext` values already are)
and in the baseline evidence item's own `Observation`. No new `Finding`
field is added -- `Severity`/`Confidence`/`AffectedEndpoint`/
`AffectedParameter`/`Evidence` already carry everything section 12 of
the task requires. Flows through `internal/correlation`/`internal/risk`
identically to every other detector's finding (both packages remain
fully generic over `models.Finding`, re-confirmed unchanged since
Phase 3.19's own architecture review -- not re-verified from scratch,
since neither package has been touched by any phase since).

## 13. Scope enforcement

No new scope code. Every probe goes through `Executor.ExecuteMutation`
→ `mutation.Executor.Execute` → `resolveAndValidate` (unchanged since
Phase 3.17/3.22) for BOTH the baseline and compare executors
identically -- an out-of-scope host is refused the exact same way for
either identity's session. `idoractive` never constructs an absolute
URL, host, or redirect target of its own -- it only ever varies the
one named parameter's VALUE (section 9), so host/port/scheme confusion
via a mutated identifier value is structurally impossible, the same
argument already proven for path-location mutation in Phase 3.23
(section 3.1 of that phase's own doc) and reused here by the identical
reasoning: a mutated query/form/JSON VALUE can never become a new
`Request.Host`.

## 14. Cross-identity safety

`idoractive` never reads or logs a credential -- it only ever holds
two already-authenticated `*detection.Executor` values (each already
scrubbed of any raw credential by `auth.Session`'s own design, section
1.1) and two identity NAME strings. `MutationEvidence`'s existing
redaction (Phase 3.17, unchanged: sensitive header/cookie/field-name
values are never included in evidence content) applies identically to
both probes' evidence. Proven with a dedicated HTTP-level test
(section 7) that Account A's cookie never appears in a request or
finding attributed to Account B, and vice versa, both sequentially and
under true concurrent execution.

## 15. False-positive resistance -- the adversarial list, mapped to the design

| Task's adversarial case | How the three-probe design (section 3) handles it |
|---|---|
| Same response for every object (a page/envelope that never varies by identifier value at all) | Known-bad control structurally matches cross-test → no finding (this is the primary case the known-bad control exists for) -- proven live by the lab's own `/ping?request_id=` fixture (section 16) |
| Public object accessible by everyone, OR an object intentionally, legitimately shared between the two specific tested identities | **Honest, known limitation, not solved by this design**: if the object genuinely exists and genuinely returns real, identity-varying-looking content to both identities (as a real shared/collaborative object legitimately would), the known-bad control (a nonexistent value) correctly 404s -- so cross-test is structurally similar to baseline AND different from known-bad, the SAME signature a genuine authorization failure produces. Response-comparison-only IDOR detection cannot distinguish "this specific object is legitimately shared" from "this is a genuine authorization failure" without out-of-band knowledge of the intended access-control policy -- no dynamic BOLA-testing tool can (see OWASP's own guidance on this). This phase does NOT claim to solve it; the lab's own `/shared?share_id=` fixture (section 16) deliberately demonstrates it, and this is exactly why every finding this detector produces is framed as evidence for human review (task section 27's "PROVEN" language means "proven that identity B received identity A's specific object content," not "proven to be unintended by the application's own design") -- see docs/phase-3-24-acceptance-test.md for how the lab's own `/shared` test result is reported. |
| Generic 200 page | Fails `looksLikeSuccessfulObjectResponse`'s body-length/shape checks, or matches known-bad → no finding |
| Generic API envelope | Same -- if the envelope is identical regardless of ID, known-bad matches cross-test |
| Login redirect | Fails `looksLikeSuccessfulObjectResponse`'s login-signature check → no finding |
| 401/403 response | Fails the 2xx-status-code requirement → no finding |
| 404 response | Same |
| Empty object | Fails the body-length requirement → no finding |
| Cached response | Not specially detected (no cache-header logic is added -- out of this phase's own conservative scope); would manifest as cross-test matching baseline, which is only a finding if it ALSO differs from known-bad, i.e. only if the cached content is genuinely account-specific, which is the correct outcome either way |
| Non-object numeric parameter | Excluded at `Eligible` by the name-shape gate (section 8) |
| Version number | Excluded by the denylist in the name-shape gate |
| Pagination parameter | Same -- proven live by the lab's own `/archive?page=` fixture (section 16) |
| Timestamp parameter | Same |
| Random identifier with no object evidence | Every Target `idoractive.Eligible` is ever called with already came from a REQUEST_INPUT-provenance parameter -- `BuildTargets` never emits a Target for anything else -- so a value this phase never discovered is never tested |

## 16. Lab

New file, `lab/harness_authorization.go`, registering onto
`harness_auth.go`'s existing `authApp` mux (mirroring Phase 3.23's own
`registerPathParameters(mux)` precedent) -- reuses the SAME two
accounts Phase 3.16 already established (`AccountAUserID` = 1001,
`AccountBUserID` = 1002 -- not reinvented) and its own
`authApp`/`requireSession` session infrastructure unchanged. Five
endpoints, linked from the existing authenticated `/dashboard` page so
a real crawl-as-Account-A discovers all five:

- `/notes?note_id=5001` -- **vulnerable**: returns the note's content
  for ANY `note_id`, regardless of the caller's own identity -- no
  ownership check at all. The primary horizontal-authorization-failure
  proof object (Account A's own note).
- `/documents?doc_id=6001` -- **safe**: verifies the caller's own
  identity owns `doc_id` before returning anything; 403s a
  cross-identity request. Proves `idoractive` does not flag a
  correctly-defended endpoint.
- `/shared?share_id=7001` -- intentionally accessible to BOTH accounts
  by design -- the honest, documented limitation from section 15 above,
  not a bug.
- `/ping?request_id=1` -- a constant response regardless of value or
  caller -- proves the known-bad-control mechanism's actual solvable
  win (section 15's "same response for every object" row).
- `/archive?page=1` -- a plainly non-object, pagination-shaped
  parameter -- proves the name-shape gate (section 8) keeps this out of
  authorization testing entirely, before any request is ever issued.

No vulnerability is introduced into any production sakanner code by
this file -- it is lab-only, physically under `lab/`, exactly like
every other fixture file in this package.

## 17. What this phase intentionally does not implement

Privilege escalation, account takeover, credential/password attacks,
CSRF vulnerability detection, mass assignment, SSRF, command
injection, new SQLi/XSS techniques, path-traversal vulnerability
detection, business-logic exploitation beyond the three-probe
authorization comparison itself, destructive testing, N-identity
matrices (only one baseline+compare pair), a second discovery crawl
authenticated as the compare identity, and any new canonical model
beyond what sections 2/8 add.

## 18. CLI surface

One new flag, `--authz-identity <name>` (`cmd/scanner/scan.go`), used
alongside the existing `--identity <name>`. Validated BEFORE any
network activity, in this order: `--authz-identity` requires
`--identity` to also be set; the two names must differ; the named
identity must resolve via the existing `findIdentityConfig` lookup
(the SAME function `--identity` itself already uses) -- any failure
returns `exitAuthFailed` (exit code 5) with no scan job ever created,
identical to every existing `--identity`/`--auth-profile` validation
failure. No separate enable/disable boolean: the flag's mere presence
is the enable signal (mirroring the established
`ssrf.New(nil)`/`idor.New(nil)`/`traversal.New(nil)` "nil dependency
means disabled" precedent). Proven by
`tests/e2e/e2e_authorization_test.go`'s
`TestScanCmd_AuthzIdentity_RequiresIdentity_ExitCode5_NoScanJob`,
`TestScanCmd_AuthzIdentity_MustDifferFromIdentity_ExitCode5`,
`TestScanCmd_AuthzIdentity_UnknownIdentity_ExitCode5_NoScanJob`, and
`TestScanCmd_AuthzIdentity_Omitted_IdorActiveStaysDisabled`.

No new report/inspection command: `idor-active`'s findings flow
through the existing `scanner report`/`scanner detectors list`
commands unchanged, exactly like every other detector's findings
already do -- task's own "no separate reporting system."

## 19. Resource limits

No new limit configuration. Every probe issued through
`x.ExecuteMutation`/`d.compareExecutor.ExecuteMutation` is bounded by
the SAME, already-existing `cfg.Detection.RequestsPerSecond`/
`MaxRequestsPerRun`/`MaxMutationsPerParameter`/`MaxActiveRequestsPerScan`
settings every other active detector already obeys -- `idor-active`'s
compare executor is built with its own independent instance of these
SAME settings (`cmd/scanner/scan.go`'s `buildAuthzExecutor`), so it is
bounded exactly as strictly as the primary executor, never more
permissively.

The identities x endpoints x objects x parameters Cartesian product
this phase's task explicitly warns against does not arise structurally:
identities are fixed at exactly one pair (baseline + compare, section
6) rather than N, so the product collapses to endpoints x parameters --
the SAME bound `Eligible`/`BuildTargets` already impose on every other
active detector, unchanged. Per eligible target, `Detect` issues at
most 3 requests (baseline replay, cross-test replay, one known-bad
mutation) -- of which only the LAST charges against the mutation
budget (`original`'s `Origin == OriginOriginal` for the first two,
`OriginMutated` only for the known-bad control -- see
`mutation.Executor.Execute`'s own `chargeMutationBudget` gate) -- so
`idor-active` charges exactly ONE mutation per eligible target against
`MaxMutationsPerParameter`/`MaxActiveRequestsPerScan`, the smallest
possible charge for any active detector in this codebase.

## 20. Determinism

No new source of nondeterminism: target ordering comes from the SAME
already-deterministic `BuildTargets` output every other detector
consumes (Phase 3.19's own established discipline -- sorted keys, never
raw Go map iteration); identity pairing is fixed (one baseline, one
compare, never a set requiring its own ordering); evidence ordering
within a finding is always baseline, cross-test, known-bad, in that
fixed order (`finding.go`'s own literal `[]models.Evidence{...}`
slice, never assembled from a map). Proven by
`lab/phase3_24_authorization_test.go`'s
`TestPhase3_24_Determinism_RepeatedScans_SameFindingCount` (3 repeated
real-lab scans, identical `idor` finding count every time).

## 21. Concurrency

`idor-active` holds two independent `*detection.Executor` values (the
engine-supplied baseline `x`, and the constructor-supplied
`d.compareExecutor`), each wrapping its own independent
`*mutation.Executor`/`mutation.SessionContext`/cookie jar -- no shared
mutable state between them, and no shared mutable state on `*Detector`
itself (its only fields, `compareExecutor`/`compareIdentity`, are set
once at construction and never written again). Race-clean under `go
test -race`, proven by
`internal/detectors/idoractive/adversarial_test.go`'s
`TestAdversarial_SessionIsolation_ConcurrentScans_NeverCrossContaminate`
(20 concurrent `Detect` calls, independently-credentialed executor
pairs) and `lab/phase3_24_authorization_test.go`'s
`TestPhase3_24_ConcurrentIdentityPairs_NoCrossContamination` (two full
orchestrator scans, opposite baseline/compare directions, run truly
concurrently against the real lab).

## 22. Storage

No migration. Every value this phase persists already fits the
existing `models.Finding`/`models.Evidence` columns (`VulnerabilityType
= "idor"` is a free-string value, exactly like `"sql_injection"`/
`"reflected_xss"` before it -- no enum to extend; `IdentityContext` is
an existing column, Phase 3.19's own addition). No plaintext credential
is ever constructed by this package (section 1.1/14), so there is
nothing new to protect at the storage layer either.

## 23. Twenty-question architectural validation

1. **Does every authorization test reuse `internal/mutation` exclusively, with no detector-private HTTP construction?** Yes -- `Detect` calls only `detection.NewMutationRequest`, `detection.NewTargetMutation`, `mutation.Mutate`, and `Executor.ExecuteMutation` (`internal/detectors/idoractive/detector.go`); no `net/http` client is ever constructed in this package outside test files.
2. **Can two identities' credentials ever be constructed/held in the same value?** No -- `d.compareExecutor` and the engine-supplied `x` are two independently-constructed `*detection.Executor` values; `Detector` itself never holds a credential, only two already-authenticated executors and two plain identity-name strings. Proven at the HTTP layer by `TestAdversarial_SessionIsolation_HeadersNeverCrossIdentities`/`_ConcurrentScans_NeverCrossContaminate`.
3. **Does status code alone ever decide a finding?** No -- `looksLikeSuccessfulObjectResponse` requires 2xx AND body-length AND a login-signature check; `Detect` additionally requires structural similarity to baseline AND structural difference from the known-bad control (section 3). Proven by `TestDetect_CrossTestLoginRedirect_NoFinding`/`TestDetect_EmptyObjectResponse_NoFinding`.
4. **Does "different response" alone ever prove IDOR?** No -- a structurally different cross-test response is treated as evidence of correct DENIAL (`TestDetect_SafeOwnershipCheck_NoFinding`), never as evidence of a vulnerability.
5. **Does "same response" alone ever prove IDOR?** No -- a cross-test response identical to BOTH the baseline and the known-bad control is suppressed (`TestDetect_GenericResponseRegardlessOfValue_NoFinding`) -- same-as-baseline is necessary but never sufficient.
6. **Is object ownership ever invented from nothing?** No -- every tested value comes from `BuildTargets`' own REQUEST_INPUT-provenance discovery (section 5); `idor-active` never guesses or constructs an object identifier value of its own (the known-bad control uses a FIXED sentinel, never a guessed real ID).
7. **Does the detector assume every numeric-looking segment is an authorization target?** No -- `Eligible` gates on `parameters.IsLikelyObjectIdentifier`'s name-shape check (section 8), which explicitly excludes pagination/version/timestamp names regardless of whether the VALUE looks numeric. Proven by `TestEligible_NonObjectName_False` and the lab's own `/archive?page=` fixture (`TestPhase3_24_NonObjectParameter_ArchivePage_NeverEligible`).
8. **Does identity pairing reuse the Phase 3.16 identity model exclusively?** Yes -- both identities authenticate via the unmodified `auth.IdentityConfig`/`ResolveIdentityProfile`/`Provider.Authenticate`/`authenticateForIdentity` path; no second account/credential system exists anywhere in this phase.
9. **Are sessions proven isolated at the HTTP layer, not just by label?** Yes -- section 14/21's tests assert on the literal `Authorization`/cookie value the TEST SERVER observed, not on any in-process label.
10. **Does authorization test generation rely EXCLUSIVELY on parameter names?** The name-shape gate is the PRIMARY signal for this foundation phase (task's own "prioritize... but not exclusively" is satisfied by `IsLikelyObjectIdentifier` living in `internal/parameters` as an independently swappable function -- see section 8's own forward-compatibility note -- rather than inline in `idor-active`, so a future phase can add value-shape/discovery-context signals without touching the detection engine).
11. **Is a mutation ever anything other than "the same known-valid request, one value changed"?** Yes, always -- `original := detection.NewMutationRequest(t)` is reused verbatim for probes 1-2; only the known-bad control (probe 3) calls `Mutate`, and only the named parameter's value ever changes (section 9).
12. **Does response comparison reuse the existing primitive?** Yes -- `mutation.Compare`, unchanged, called twice per `Detect` (cross-test vs baseline, cross-test vs known-bad); the one new function, `looksLikeSuccessfulObjectResponse`, answers a genuinely different question (section 10) that `Compare` was never designed to answer.
13. **Does scope enforcement have a second, parallel implementation?** No -- both executors route through the identical `mutation.Executor.Execute` → `resolveAndValidate` path (section 13); zero scope-related code exists in `internal/detectors/idoractive`.
14. **Can a mutated identifier VALUE ever change the dial host?** No, structurally impossible -- proven by `TestAdversarial_KnownBadControl_NeverChangesHost`.
15. **Does the finding model express both the acting and baseline identity?** Yes -- `IdentityContext` carries the acting/compare identity (overriding `normalizeFinding`'s baseline default, section 12); the baseline identity's name appears in `Description`/evidence `Observation` text.
16. **Are credentials ever placed in a finding, evidence, or log line?** No -- only identity NAMES (plain, non-secret, operator-chosen labels, the same convention every prior phase already established) ever appear.
17. **Are resource limits deterministic and bounded, avoiding a combinatorial blow-up?** Yes -- section 19 (one identity pair, one mutation charged per eligible target).
18. **Is the CLI surface minimal, reusing existing scan/identity mechanisms?** Yes -- one flag, section 18, zero new authentication code (both identities authenticate via the existing, unmodified `authenticateForIdentity`).
19. **Does a real, full-pipeline test exist (not synthetic-only)?** Yes -- `tests/e2e/e2e_authorization_test.go`'s `TestScanCmd_AuthorizationDetection_HorizontalFailure_RealBinary` drives the actual compiled CLI binary against the real lab end to end; `lab/phase3_24_authorization_test.go` provides the equivalent orchestrator-direct proof.
20. **Does this phase honestly distinguish what it solves from what it cannot?** Yes -- section 15's "public/shared object" row and the lab's own `/shared` fixture (`TestPhase3_24_SharedObject_DocumentedLimitation`) document, rather than hide, the one adversarial case response-comparison-only IDOR detection cannot resolve.
