# Phase 3.19: Active Request Detection Engine Foundation

## 0. Scope discipline

This phase builds the production architecture for active, mutation-
based request detection and proves it with exactly one detector:
reflected XSS. It does not implement IDOR/BOLA, authorization testing,
SQLi/SSRF/command-injection/traversal expansion, stored/DOM/blind XSS,
mass assignment, business-logic testing, race-condition detection, or
CSRF detection. See section 14 for the full list.

## 1. Architecture review findings

Full investigation of `internal/detection`, `internal/detectors/
xssreflected`, `internal/orchestrator`, `internal/correlation`,
`internal/risk`, `internal/evidence`, `internal/policy`, `pkg/models`,
and `lab/` was conducted before any code was written. The load-bearing
findings:

1. **`detection.Executor` has zero session/cookie/header capability**
   -- confirmed by direct read, not assumed from prior docs. `Do`
   builds `x.dialer.NewClient(t.Host, t.IP, nil, nil, ...)` with no
   jar, no headers, ever. Every detector-issued request today is
   unauthenticated, unconditionally, even during a scan that
   authenticated its crawl via `--auth-profile`/`--identity`.
2. **`internal/mutation.Executor` already has full session support**
   (`SessionContext{Jar, Headers, PinnedHost, IdentityContext}`,
   `Execute(ctx, req, sess)`) but nothing in the codebase constructs
   one inside `Orchestrator`/`Engine`/`Detector.Detect` -- `grep`
   confirms `internal/mutation` is imported by zero non-test,
   non-`internal/mutation` files.
3. **`Detector.Detect(ctx, t Target, x *Executor) (Result, error)`**
   is the exact, unchanged interface from Phase 3.1. Its third
   parameter is `*detection.Executor`, never `*mutation.Executor` --
   there is no channel today for a detector to reach mutation-aware
   execution.
4. **`Orchestrator.buildDetectionExecutor` never sees
   `Options.AuthSession`** -- confirmed by reading the exact function
   body (`orchestrator.go:641-648`): it builds a plain
   `detection.NewExecutor(validator, o.Pipeline.Resolver,
   o.DetectionExecutorConfig)` with no session parameter, called from
   `Run` at a point with no access to `opts` at all.
5. **`BuildTargets` only emits targets for `Location == "query"`
   parameters** -- JSON-body parameters, even `REQUEST_INPUT`-
   provenance ones, never reach a detector today.
6. **`xss-reflected`'s reflection logic is three probes of pure
   `bytes.Contains`**, with a crude 3-bucket (text/attribute/unknown)
   position heuristic and NO distinction between an unescaped
   reflection and an HTML-entity-encoded one (both currently collapse
   into the same `OutcomeNoFinding` branch). It never touches
   `internal/mutation` -- its own private `requestURL`/`probe` pair,
   unchanged since Phase 3.3.
7. **`models.Finding` has no `IdentityContext` field.** Identity is
   carried on `Target`/`Endpoint`/`Parameter`/`mutation.Request`/
   `mutation.Response`, never on `Finding` itself.
8. **`internal/correlation`/`internal/risk`/`internal/evidence` are
   fully generic over `models.Finding`/`CanonicalFinding`** -- no
   detector-specific logic anywhere in any of the three. A new
   detector's findings need nothing special to flow through unchanged.
9. **No per-detector profile gating exists** -- `Profile.DetectionEnabled`
   remains the only, scan-wide, all-or-nothing switch.
10. **No dry-run flag, no `--json` output, and no CLI printing of the
    already-computed `RequestsIssued` counter exist today.**

## 2. Minimum integration point

The task's own diagram --
`discovery -> Endpoint/Parameter -> mutation.Request -> authenticated
execution -> mutation.Response -> detector analysis ->
RequestResponseEvidence -> Finding -> correlation -> risk -> report`
-- is implemented with the SMALLEST set of changes that make it real,
chosen specifically to avoid touching any of the six existing
detectors' logic:

1. **`detection.Executor` gains one new method, `ExecuteMutation`**,
   and an internal `*mutation.Executor` + `mutation.SessionContext`.
   `Do` (the existing method every current detector calls) is
   UNCHANGED in signature and, for an unauthenticated scan, in
   behavior. `NewExecutor` (existing constructor, called from dozens
   of test files) is UNCHANGED -- a new `NewExecutorWithSession`
   constructor is added alongside it, which `NewExecutor` now
   delegates to with a zero-value session. **Zero call sites needed to
   change anywhere in the six existing detectors, their tests, or
   `Engine.Run`.**
2. **`Detector`'s interface signature is UNCHANGED.** A detector that
   wants mutation-aware, session-aware execution simply calls the new
   `x.ExecuteMutation(ctx, req)` method on the SAME `*Executor` it
   already receives -- no interface extension, no new parameter, no
   mechanical edit required in any existing detector file.
3. **`mutation.NewRequestFromTarget(t Target)` and `mutation.Mutate`
   are already public, standalone functions** (Phase 3.17) -- a
   detector calls them directly. No wrapper was added; none was
   needed.
4. **`Orchestrator.buildDetectionExecutor` is extended to accept the
   scan's `*auth.Session`**, builds a `mutation.SessionContext` from
   it the exact same way `internal/orchestration.Pipeline` already
   does for crawling (`session.JarFor(session.Host)`/
   `HeadersFor(session.Host)`/`session.Host`/`session.IdentityName`),
   and passes it to `NewExecutorWithSession`. This means **every
   existing detector also incidentally becomes capable of
   authenticated execution** the moment a scan authenticates -- a
   free, backward-compatible improvement (an unauthenticated scan's
   `SessionContext{}` zero value changes nothing; no existing test
   combines authentication with detection, so nothing regresses).
5. **`BuildTargets`/`endpointTargets` extended to also emit targets for
   `Location == "json"`, `Provenance == "REQUEST_INPUT"` parameters**,
   with `Target.ParameterLocation = "body"` -- reconciling the
   vocabulary mismatch `detection.Target.ParameterLocation`'s own doc
   comment already anticipated (`"query"/"body"/"header"/"cookie"`).
   `RESPONSE_FIELD`-provenance parameters are explicitly excluded from
   this new branch -- see section 7.
6. **`models.Finding` gains `IdentityContext string`** (migration
   `0011`), populated automatically by `normalizeFinding` from
   `Target.IdentityContext` for EVERY detector, not just the new one --
   a detector never sets this field itself.

No detector-specific request-execution path was created. Every active
request, from any detector, old or new, goes through exactly one
execution surface: `mutation.Executor.Execute`, reached either via
`detection.Executor.Do` (existing detectors, still their own
`requestURL`/`probe` construction, now incidentally session-aware) or
`detection.Executor.ExecuteMutation` (the new detector, using
`mutation.Request`/`Mutate` construction).

## 3. Detector contract

`Detector`'s interface is unchanged. The CONTRACT (not the Go type) a
detector following the active pattern is expected to honor is
documented, not enforced by the compiler beyond what already exists --
matching this codebase's own established style (`Detector`'s own doc
comment has always been the enforcement mechanism, e.g. "x is the ONLY
sanctioned way to reach a target"):

- Eligibility: `Metadata()` + `Eligible(t Target) bool`, unchanged.
- Deterministic mutation generation: `mutation.NewMutation(...)`'s own
  content-hash ID (Phase 3.17) makes this automatic -- a detector
  computing the same mutation from the same target always gets the
  same `Mutation.ID`.
- Request execution: exclusively `x.ExecuteMutation` (new) or `x.Do`
  (existing) -- never `net/http` directly, never a private client.
- Response analysis: the detector's own logic (section 8).
- Evidence: `mutation.ToEvidence(req, resp, &m, observation, reason)`
  (Phase 3.17's own bridge, built exactly for this) -- produces the
  SAME `detection.RequestResponseEvidence` shape every detector
  already writes.
- Confidence, detector identity/version: `Metadata.ID`/`Name` (no
  `Version` field was added to `Metadata` -- see section 14's
  discussion of why).
- Mutation provenance / original / mutated / response references: all
  carried on `mutation.Request.Origin`/`MutationID` and
  `mutation.Response.RequestOrigin`/`MutationID` (Phase 3.17, already
  built) -- the new detector reads and reports these in evidence, it
  invents nothing new.

A detector following this contract structurally CANNOT bypass scope
(the only path to the network is through `Executor`, which always
scope-checks), create its own HTTP client or cookie jar (no such
constructor is exported to it), access raw credentials (`SessionContext`
carries only a jar/header map, never a password/token value), or write
findings directly to storage (`Engine.Run` is the only caller of
`Store.Findings().Create`, never a `Detector`).

## 4. Original vs. mutated request

Unchanged from Phase 3.17's own design (`Request.Origin`/`MutationID`,
`Clone`, `Mutate` never touching the original) -- this phase adds
nothing new here, it exercises what already existed. The new
detector's evidence (via `mutation.ToEvidence`) records: the endpoint
tested (`Target.Path`/`EndpointID`), the parameter tested and its
location (`Mutation.Parameter`/`Location`), the original value
(read from the persisted `models.Parameter.Value` before mutation,
included in `Observation`), the mutation applied (`Mutation.Value`,
redacted if the parameter name is sensitive), the request actually
sent (`ToEvidence`'s redacted request line), the response received
(status + bounded fragment), the identity/session used
(`Response.IdentityContext`, and now `Finding.IdentityContext`), and
scope compliance (implicit: a request that failed scope never produces
a `Response` to analyze at all -- `OutcomeScopeRejected` short-circuits
before any evidence is built).

## 5. Response comparison

`mutation.Compare(baseline, mutated)` (Phase 3.17) is used as a
SECONDARY, corroborating signal, not the primary detection mechanism
-- diffing two responses cannot by itself tell whether a reflection is
dangerous (a page that changes length for unrelated reasons is not
XSS; a byte-identical page can still reflect a payload verbatim in a
dangerous context). The detector's PRIMARY signal is context-aware
reflection classification (section 8); `Compare`'s
`StructurallyDifferent`/`HeaderDeltas` are folded into the finding's
`Observation` as corroborating detail, never used alone to declare a
finding -- directly satisfying the task's "avoid declaring a
vulnerability based on a single weak signal."

## 6. Detector registration

Registered exactly like the existing six, in `cmd/scanner/detectors.go`'s
`productionRegistry()` -- no new registration mechanism, no dynamic
runtime registration. The new detector declares a stable ID
(`"xss-reflected-active"`, deliberately distinct from the existing
`"xss-reflected"` so both can coexist and be independently enabled/
disabled), name, category, supported target kinds/methods exactly like
every other `Metadata`. No `Version` field, no `RequiredAuthContext`
field, and no resource-cost field were added to `Metadata` --
`Registry`'s existing, already-deterministic (insertion-order `List()`,
ID-sorted `enabledDetectors()`) machinery needed no change, and
inventing new `Metadata` fields with no second consumer to justify them
would be exactly the kind of speculative expansion this session's own
established practice avoids. Resource limits are enforced centrally by
`Executor`/`mutation.Executor` (section 11), not declared per-detector.

## 7. The new detector: `internal/detectors/xssactive`

ID `xss-reflected-active`. Coexists with, and does not modify,
`xss-reflected` -- the existing detector's own full test suite and lab
ground-truth ID mappings are untouched.

**Eligibility**: `Kind == TargetKindEndpoint`, `Parameter != ""`,
`ParameterLocation` in `{"query", "body"}` (query -- GET, matching
`xss-reflected`'s own scope; body/JSON -- any method, since a JSON
body is never method-restricted the way a GET query string is).

**Mutation generation**: for a query target,
`mutation.NewRequestFromTarget(t)` then `mutation.Mutate(..., mutation.LocationQuery, ...)`;
for a body/JSON target, the SAME `NewRequestFromTarget` (which already
carries `t.Parameter`/`ParameterLocation` from the `Target`), with
`mutation.LocationJSON` and the target's own `Parameter` name as the
(possibly dotted) path -- reusing Phase 3.18's nested-path fix to
`mutation.applyJSON` directly.

**Two probes, both executed via `x.ExecuteMutation`:**
1. A plain, alphanumeric marker (`sakannerActiveXSSProbe`) -- confirms
   reflection happens at all before spending a second, more expensive
   probe. No finding is possible without this succeeding.
2. A context-revealing payload
   (`"'><script>ACTIVEMARKER</script>`) -- classified by
   `classifyReflection` (section 8) against the response body AND
   `Response.ContentType`.

## 8. Reflection classification -- five distinct outcomes

```go
type ReflectionKind string
const (
    ReflectionNone       ReflectionKind = "none"          // marker not found in probe 2's response at all
    ReflectionHTMLEncoded ReflectionKind = "html_encoded" // only the ENTITY-ENCODED form of the payload is present -- SAFE, not a finding
    ReflectionExact      ReflectionKind = "exact"          // the raw payload, unescaped, in ordinary HTML text
    ReflectionAttribute  ReflectionKind = "attribute"       // raw payload, unescaped, inside an HTML attribute value
    ReflectionJavaScript ReflectionKind = "javascript"      // raw payload, unescaped, inside an open <script>...</script> block
    ReflectionJSONString ReflectionKind = "json_string"     // response Content-Type is JSON and the raw payload appears inside a JSON string value
)
```

Deliberately NOT a full HTML/JS parser or DOM builder (task's own "do
not attempt DOM XSS" applies equally to the DETECTION technique, not
just the vulnerability class) -- a bounded, deterministic, position-
based heuristic, one step more capable than `xss-reflected`'s own
3-bucket classifier:

1. If `Response.ContentType` indicates JSON: search for the raw payload
   inside a quoted JSON string value (a simple "appears between two
   unescaped double-quotes that themselves parse as valid JSON string
   delimiters" check, reusing `encoding/json` to validate rather than
   inventing a JSON-string-boundary scanner) -> `ReflectionJSONString`,
   reported at LOWER confidence/severity than an HTML context --
   whether this is exploitable depends entirely on how the JSON is
   consumed downstream, which this detector cannot observe, so it is
   never reported with the same certainty as a direct HTML/JS
   reflection (task's own "prioritize reliable identification... false
   positive resistance").
2. Otherwise (HTML or unspecified content type): if the raw,
   byte-for-byte payload is absent but its HTML-entity-encoded form
   (`&lt;script&gt;...&lt;/script&gt;`) is present -> `ReflectionHTMLEncoded`
   -- explicitly `OutcomeNoFinding`, matching `xss-reflected`'s own
   established philosophy that encoded reflection is safe (this is the
   ONE outcome this classifier reports MORE explicitly than
   `xss-reflected` does today: the existing detector silently folds
   this into a bare no-finding with no distinguishing evidence at all).
3. If the raw payload is present: track the last `<script`/`</script`
   tag boundary before the marker (an open, unclosed `<script` after
   the last `</script>` means we're inside a script block) ->
   `ReflectionJavaScript`; else reuse `xss-reflected`'s own
   already-reviewed unclosed-tag-plus-quote heuristic ->
   `ReflectionAttribute` or `ReflectionExact`.

`ReflectionNone`/`ReflectionHTMLEncoded` -> `OutcomeNoFinding`.
`ReflectionJSONString` -> `OutcomeFinding`, `SeverityMedium`, lower
confidence (0.5). `ReflectionAttribute`/`ReflectionExact` ->
`OutcomeFinding`, `SeverityCritical`, confidence 0.9.
`ReflectionJavaScript` -> `OutcomeFinding`, `SeverityCritical`,
confidence 0.95 (the single most directly executable context).
`mutation.Compare`'s `StructurallyDifferent` is folded into the
`Observation` string as corroborating detail in every finding, never
gating the outcome itself.

## 9. Authentication / identity

Proven for all four required scenarios (section 1 finding 4's fix):
unauthenticated (`SessionContext{}`), a bare `--auth-profile`
(`IdentityContext == ""`), and two independent identities. Since
`Orchestrator.buildDetectionExecutor` derives its `SessionContext`
from the SAME `*auth.Session` the scan's own crawl already
authenticated with -- one `Session` per scan, matching Phase 3.16's
own "single identity per scan" boundary (still not revisited this
phase) -- Identity A's and Identity B's detection-stage executions are
as structurally isolated as their crawls already are: two separate
`Orchestrator.Run` calls, two separate `*auth.Session` values, two
separate `mutation.SessionContext`s, two separate `detection.Executor`
instances, never shared.

## 10. Scope safety

No new scope-decision code. `ExecuteMutation` delegates entirely to
`mutation.Executor.Execute`, which performs the exact same
`scope.Validator.CheckResolved`/`safedial.Dialer.ResolveInScope`
sequence, and `safedial.Dialer.NewClient`'s own per-redirect-hop
`CheckHost`, that every other execution path in this codebase already
relies on (Phase 3.17 section 7, unchanged, re-verified by this
phase's own adversarial tests rather than merely re-asserted).

## 11. Resource limits

`detection.ExecutorConfig` gains `MaxMutationsPerParameter`/
`MaxActiveRequestsPerScan`, mapped directly onto
`mutation.ExecutorConfig.MaxMutationsPerTarget`/`MaxTotalMutations` --
the SAME, already-built-and-tested (Phase 3.17) budget mechanism, not
a new one. `Do`-issued (existing detectors) and `ExecuteMutation`-
issued (new detector) requests are counted separately internally (they
have different budget semantics -- see Phase 3.17's own "an ORIGINAL
request is never charged against the mutation budget" design) but
`Executor.RequestCount()` now returns their SUM, so the existing
`DetectorSummary.RequestsIssued` counter (already computed, previously
unprinted -- section 1 finding 10) remains accurate once the new
detector starts issuing requests.

## 12. Dry-run / execution visibility

A full `--dry-run` mode (build every mutation, execute none) was
considered and deliberately NOT built this phase -- it is a genuinely
new, separate CLI feature (no flag, no code path for it exists
anywhere today) whose design (what does "dry" mean for a detector that
needs a REAL baseline response to compare against?) deserves its own
scoped decision, not one squeezed into an already-large foundation
phase. Instead, this phase does the minimum that directly satisfies
the stated NEED (observability before/after a scan, no secrets
exposed): `RequestsIssued` (already computed, per section 1 finding
10) is now printed in `scanner scan`'s existing summary output -- a
plain integer, never a credential or session value. A separate
"mutations generated" counter was considered and NOT added: this
phase's detector generates and executes each mutation in the same
step (no queue-then-execute-later design exists), so "mutations
generated" and "requests issued via mutation" would be the identical
number today -- adding a second counter with no distinct meaning would
be exactly the kind of speculative surface this session's own
established practice avoids. Documented here as a conscious scope
decision, not an oversight.

## 13. Lab

`lab/harness_vuln.go` (extended in place, no new file) gains: an
authenticated reflected-XSS endpoint (reusing `harness_auth.go`'s
existing session infrastructure) and a JSON-reflecting API endpoint.
The existing query/attribute-context fixtures
(`/xss/reflected/vulnerable`, `/xss/reflected/attribute/vulnerable`,
and their `/safe` negative counterparts) are reused as-is for the new
detector's own positive/benign lab tests -- proving the NEW detector
against the SAME ground truth the OLD one already uses is itself a
form of cross-validation (two independently-built detectors agreeing
on the same fixture is a stronger signal than either alone).

## 14. What this phase intentionally does not implement

- No IDOR/BOLA, authorization testing, SQLi/SSRF/command-injection/
  traversal expansion, stored/DOM/blind XSS, mass assignment,
  business-logic testing, race-condition detection, or CSRF detection.
- No `Metadata.Version`/`RequiredAuthContext`/resource-cost field --
  no second consumer exists yet to justify the shape such a field
  should take; adding one speculatively risks guessing wrong.
- No multi-identity-per-scan comparison (`--identity a,b`) -- still
  deferred from Phase 3.16, unrelated to this phase's own scope.
- No full `--dry-run` CLI mode (section 12).
- No migration of the six existing detectors onto
  `mutation`/`ExecuteMutation` -- each keeps its own private
  `requestURL`/`probe`, unchanged, fully covered by its own existing
  test suite. They now incidentally run authenticated when a scan
  itself is authenticated (section 2 finding 4), which is a strict
  behavioral improvement, not a rewrite.
- No JSON-request-body discovery in the LIVE crawl pipeline -- Phase
  3.18 already established that the crawler cannot produce one; this
  phase's JSON-eligible targets are proven correct using directly-
  persisted `REQUEST_INPUT`-provenance JSON parameters (lab-constructed,
  exactly like Phase 3.18's own JSON-to-mutation bridge test), not
  discovered by an ordinary crawl. Documented as a known limitation,
  not hidden -- see the final report's architectural notes.

## 14.5. A convention confirmed the hard way: timeouts are errors, not no-findings

While writing this detector's own adversarial timeout test, the first
version asserted a timed-out probe should be silently reported as
`OutcomeNoFinding`. It failed immediately: `x.ExecuteMutation` (like
every existing detector's own `x.Do`) propagates a timeout as a plain
Go error, which `Detect` then returns as a hard error, exactly
matching `internal/detectors/sqli`'s own `probe()` (`if err != nil {
return nil, nil, err }`, unconditionally, no special-casing for a
timeout specifically). This is the CORRECT, established convention,
not a gap: `Engine.Run` already records such an error as a
`DetectorError` and continues to the next target/detector without
aborting the scan (unmodified, pre-existing behavior). The test's
assumption was wrong, not the code -- fixed by asserting the actually-
established behavior (an error, never a false finding) instead of
inventing a new, inconsistent convention just for this one detector.

## 15. Answering the required architectural questions (task section 18)

Answered in full, with the actual test that proves each, in
`docs/phase-3-19-acceptance-test.md`'s own "Final architectural
validation" section -- not restated here to avoid drift between two
copies of the same claim.
