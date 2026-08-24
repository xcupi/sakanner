# Phase 3.5: IDOR / BOLA Detector

sakanner's fourth real vulnerability detector. Implements
`detection.Detector` (`internal/detection`, Phase 3.1) unchanged --
nothing in the framework was modified to build this; see
[docs/phase-3-1-detection-engine.md](phase-3-1-detection-engine.md)
"How to implement a new detector" for the contract this follows, and
[docs/phase-3-4-ssrf.md](phase-3-4-ssrf.md) for the sibling detector
whose "registered but disabled, dependency-injected" pattern this one
also uses (for a different reason -- see "Authorization contexts"
below).

**IDOR (Insecure Direct Object Reference) / BOLA (Broken Object Level
Authorization)**: an object-level authorization failure where one
authorization context (a user, session, or API caller) can access
another context's object -- a record, file, order, document -- without
being authorized to. The defect is not that an object identifier
exists or can be changed; it's that the server never checks whether
the requester is allowed to see the specific object it returns.

## Core security principle

IDOR/BOLA detection *requires* an authorization context. This detector
never concludes a vulnerability exists merely because an object ID
exists, IDs are sequential, a request returns HTTP 200, or a UUID can
be substituted. It establishes, for every finding:

1. Resource R belongs to authorization context OWNER (operator-supplied
   ground truth -- never inferred, see "Resource ownership").
2. A *different* authorization context requests R.
3. The server returns a 2xx, non-empty response (`looksAllowed`).
4. The response is resource-specific -- it actually varies by the
   identifier requested (`isResourceSpecific`), not a constant page.

Only when all four hold does a finding get created. HTTP 200 alone is
never sufficient evidence -- see "Response validation."

## What this detector does NOT detect

Per the task's explicit scope boundary, none of the following are
implemented, attempted, or in any way exercised by this package:

- **Authentication bypass** -- the detector assumes valid,
  already-established authorization contexts exist; it never attempts
  to log in, forge, guess, or brute-force credentials.
- **Session hijacking / credential theft** -- headers are attached
  verbatim from operator configuration; nothing is captured, replayed
  from elsewhere, or extracted from another request.
- **CSRF** -- not a resource-authorization question; out of scope.
- **JWT cryptographic attacks** -- tokens (if any) are opaque
  configuration values to this detector; it never parses, forges, or
  attacks a JWT's signature or claims.
- **OAuth abuse** -- no OAuth flow of any kind is modeled or executed.
- **Role / administrative privilege escalation** -- this detector
  compares two *peer* contexts against each other's resources, never a
  low-privilege context against an admin-only function.
- **Account takeover** -- no credential or session is ever acquired,
  modified, or transferred between contexts.
- **Password attacks / brute force** -- no authentication surface is
  ever probed.
- **Post-exploitation / data extraction from real systems** -- this
  detector is verified exclusively against the local Phase 3 Test Lab;
  see "Adversarial testing."
- **LLM runtime integration** -- not applicable to any part of
  sakanner; this project is LLM-free by design.

## Architecture

```
internal/detectors/idor/
├── detector.go       Detector, Metadata, Eligible, Detect, finding construction
├── authcontext.go     AuthContext -- the minimal auth abstraction (see below)
└── normalize.go       normalizeBody / looksAllowed / isResourceSpecific

lab/harness_vuln.go   registerIDORAPI -- the query-parameter-based
                             multi-user fixture pair this detector is
                             actually verified against

cmd/scanner/detectors.go    productionRegistry() registers idor.New(nil),
                             then disables it -- see "Authorization contexts"
```

## Authorization contexts

Task section 4 asks: first check whether Phase 2 already supports
authenticated scanning; if not, do not invent a separate framework,
build a *minimal* lab-scoped abstraction instead.

**Finding**: Phase 2's recon and Phase 3.1's `detection.Target` carry
no concept of an authenticated session or identity at all -- every
request in every prior detector (`xssreflected`, `sqli`, `ssrf`) is
implicitly anonymous. There is nothing to reuse.

**Resolution**: `AuthContext` (`authcontext.go`), the deliberately
minimal abstraction the task allows:

```go
type AuthContext struct {
    ID              string
    Headers         map[string]string
    OwnsResourceIDs map[string]bool
}
```

- `Headers` are attached **verbatim** to every request made "as" this
  context (in the lab, `X-Test-Auth-User: user-a`; in principle
  `Authorization: Bearer <token>` or `Cookie: session=<value>` against
  a real target with a real session already established). The detector
  never establishes, logs in for, refreshes, or derives a credential
  itself -- it only ever attaches what was configured ahead of time.
- `OwnsResourceIDs` is **operator-supplied ground truth**, not
  something derived from a crawl or a response. This is the central
  design decision of this phase -- see "Resource ownership" below.

`New(contexts []AuthContext) *Detector` requires **at least 2**
contexts for any cross-context comparison to be possible; with fewer
(including nil/empty), every `Detect` call returns `OutcomeSkipped`
rather than doing anything, so incomplete configuration fails safe by
construction (`TestDetect_FewerThanTwoContexts_Skipped`,
`TestDetect_NoContexts_Skipped`).

**Not wired into production**: like `ssrf.New(nil)`,
`cmd/scanner/detectors.go`'s `productionRegistry()` registers
`idor.New(nil)` and immediately disables it (`r.SetEnabled(idor.ID,
false)`) -- `scanner detectors list` shows it exists, and its
`Prerequisites` metadata field explains exactly what's missing (at
least 2 `AuthContext` values, plus resource-ownership ground truth).
This build ships no production credential-management surface for
establishing real authorization contexts -- out of scope for this
phase, and, per the task, never to be built as an authentication
bypass or credential-acquisition mechanism.

## Resource ownership

Task section 9 is explicit: the detector "must NOT assume... resource
B belongs to another user" -- it must *know*. The only two sources of
that knowledge the task permits are controlled test-lab ground truth,
or supported application metadata; absent either, the required
behavior is NOT_APPLICABLE / INCONCLUSIVE, never a guess.

This detector satisfies that requirement by making ownership entirely
**operator-supplied configuration** (`AuthContext.OwnsResourceIDs`),
never inferred from crawl data, response content, or identifier shape.
`ownerOf(id)` does a linear scan of the configured contexts; if no
context claims the identifier, `Detect` returns `OutcomeSkipped`
immediately (`TestDetect_UnconfiguredResourceID_Skipped`) -- the
identifier is simply never tested, not assumed to belong to "some
other" context.

This also resolves the "public resource" case cleanly: a resource
nobody's `OwnsResourceIDs` claims (in the lab,
`resource-public`) is never evaluated at all --
`TestDetect_PublicResourceWithoutConfiguredOwnership_Skipped` and, at
the lab level, `VULN-IDOR-API-PUBLIC-NEG-001` confirm this directly.
An intentionally-shared object is correctly silent not because the
detector recognizes "this one's public," but because nothing ever
configures an owner for it -- which is exactly the operator's
responsibility to get right, and exactly what "return
NOT_APPLICABLE/INCONCLUSIVE rather than reporting a vulnerability"
means in practice.

## Candidate selection

```go
SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint}
SupportedMethods:     []string{http.MethodGet}
```

plus `Eligible(t)` requiring the parameter's **name** to match one of
the task's own six examples: `id`, `user_id`, `account_id`,
`order_id`, `document_id`, `resource_id` (case-insensitive).

**Path-based object references are out of reach.** Phase 3.1's
`detection.BuildTargets` only extracts candidate parameters from QUERY
strings, never path segments -- the same documented limitation
`xssreflected`/`sqli`/`ssrf` all carry. This means the *original*
Phase 3 lab fixture, `/idor/vulnerable/user/{id}` (path-based,
predates this phase), remains permanently undetectable by this or any
Phase-3.1-based detector; its ground-truth entry
(`VULN-IDOR-001`) was updated to document this precisely rather than
left stale. A **new**, query-parameter-based fixture pair
(`/idor/api/resource/vulnerable` / `/idor/api/resource/safe`, both
taking `?resource_id=`) was added to the lab specifically so this
detector has something query-based to actually detect -- see
"Test lab fixtures" below. Extending `BuildTargets` to extract path
segments was considered and rejected: it would mean redesigning Phase
3.1 for this phase's benefit, which the task explicitly forbids absent
a genuine defect in the framework itself (there isn't one).

## Baseline and cross-resource testing

For a single candidate `(endpoint, parameter=resource_id, id=<discovered value>)`:

1. **Resolve ownership.** `owner := ownerOf(id)`. No configured owner
   -> `OutcomeSkipped` (section 9's NOT_APPLICABLE).
2. **Owner baseline.** Probe the endpoint *as the owner*
   (`probeAs(ctx, x, t, *owner)`) -- the owner's own headers attached,
   the identifier **never substituted** (this detector only ever
   changes the *caller identity*, never the resource identifier in the
   request itself -- the identifier under test is whatever Phase 2's
   recon already discovered).
   - Not `isAnalyzable` (not text/JSON/XML) -> `OutcomeSkipped`.
   - Not `looksAllowed` (the owner can't even access their own
     resource) -> `OutcomeNoFinding` -- nothing to compare against.
   - Not `isResourceSpecific` (a generic/constant response) ->
     `OutcomeNoFinding` -- see "Response validation."
3. **Cross-context probes.** For every *other* configured context,
   probe the same URL with that context's headers. A denied response
   (`!looksAllowed`, i.e. 401/403/404/anything non-2xx-or-empty) is
   silently skipped -- correct behavior, not evidence of anything. An
   *allowed* response is recorded as a `crossAttempt`, with
   `matchesOwner := normalizeBody(otherBody) == normalizeBody(ownerBody)`.
4. **Decide.** No `crossAttempt`s at all -> `OutcomeNoFinding` (every
   other context was correctly denied). One or more -> exactly one
   aggregated `Finding` covering all of them.

This is a **single-target, stateless** algorithm -- no state
accumulates across separate `Detect` calls, and exactly `2` requests
are issued to the target application per candidate with the lab's
2-context configuration (owner baseline + 1 cross probe); this scales
linearly with the number of configured contexts, never combinatorially
(see "Request limits").

## Response validation

Two independent, deliberately simple checks, neither of which parses
or "understands" the body's content beyond byte-level comparison
(`normalize.go`):

- **`looksAllowed(statusCode, body)`** -- 2xx status AND a non-empty
  body. Distinguishes denial (401/403/404/app-specific error) from
  actual access; status alone still isn't the whole story, hence the
  second check.
- **`isResourceSpecific(body, id)`** -- `bytes.Contains(body, []byte(id))`.
  A response that never varies by the identifier requested (a
  constant `{"status":"ok"}`-shaped body, task section 14's "generic
  success page") can never be trusted as evidence that a *specific*
  protected object was returned, no matter what status code came back
  or which identity requested it. This check runs against the
  **owner's own baseline only** -- if the owner's own resource
  response is generic, the whole candidate is abandoned
  (`OutcomeNoFinding`) before any cross-context probe is even
  evaluated as evidence.

Confirmation of *unauthorized access specifically* (not just "some
other 2xx") additionally requires `matchesOwner`: the cross-context
response, after digit-run normalization, is byte-identical to the
owner's own baseline -- i.e. the cross context received the *same*
resource content the real owner does. See "Confidence" for how a
cross response that's merely allowed-but-not-identical is still
reported, at a lower tier.

### Applying the Phase 3.3 lesson -- but differently

Phase 3.3 (`sqli`) discovered, via broad adversarial testing, that
comparing raw response bodies across two different *injected payload
strings* produces false positives on any endpoint that merely echoes
its input verbatim. Phase 3.4 (`ssrf`) applied the fix proactively via
`stripPayload`.

This detector's design sidesteps that failure mode structurally,
rather than needing an equivalent strip step: it never injects a
different *payload* into the URL at all -- every probe uses the exact
same `t.URL` (same identifier), varying only the **caller's headers**.
There is no payload string to leak into the body and corrupt the
comparison. The false-positive class this detector *is* susceptible to
is a different one -- "the response is generic/constant regardless of
input" -- and that is exactly what `isResourceSpecific` exists to
catch (see "Revert-and-verify" in the acceptance report for direct
proof this guard is load-bearing).

## Method coverage

Only `GET` is supported (`SupportedMethods: []string{http.MethodGet}`).
Per task sections 12-13: READ (GET) is the primary, always-safe path;
write-method testing (POST/PUT/PATCH) against a real, non-lab target
risks mutating state the scanner has no business mutating, and DELETE
against a real system is explicitly forbidden regardless of any
detected vulnerability. Rather than fake partial support, this
detector's `Eligible` simply never returns true for a non-GET target
-- an honest `NOT_APPLICABLE` for every non-GET candidate by
construction, consistent with the task's "if a method isn't safely
supported, return NOT_APPLICABLE, do not fake support."

## Confidence and severity

| Signal | Severity | Confidence | Rationale |
|---|---|---|---|
| At least one cross-context response byte-identical (normalized) to the owner's baseline | critical | 0.9 | Confirmed unauthorized access to the *specific* protected object -- "HIGH: valid context + ownership established + cross-user request + protected-resource evidence confirmed" |
| Cross-context response allowed (2xx, non-empty) but not identical to the owner's baseline | high | 0.55 | Access was observed, but full protected-resource confirmation is incomplete -- "MEDIUM: context valid + cross-resource access observed + ownership evidence incomplete" |
| Every cross-context probe denied, or the owner's own baseline isn't resource-specific | -- | -- | `OutcomeNoFinding` |
| No configured owner for the identifier | -- | -- | `OutcomeSkipped` (NOT_APPLICABLE) |

No `LOW` tier is fabricated: the task permits (and this detector uses)
`OutcomeSkipped`/NOT_APPLICABLE for genuinely ambiguous cases (missing
ownership, non-analyzable content) rather than inventing a
low-confidence finding just to have three tiers. Severity reuses
`pkg/models.Severity` unchanged; not every IDOR is reported as
`critical` -- only a fully confirmed match is, matching the Phase 3
ground truth's `severity: critical` for `VULN-IDOR-API-001`.

## Evidence

Every finding's `Evidence` is one
`detection.NewRequestResponseEvidence`, deliberately structured to
answer the task's WHO/WHAT/OWNER/EXPECTED/ACTUAL/PROOF/CONCLUSION
shape (section 18) without storing a full response body:

- **WHO** -- the affected authorization context ID(s), in the
  `Request` line and the `Observation` field's `who=`.
- **WHAT** -- the resource identifier, `Observation`'s `what=` and
  `Payload`.
- **OWNER** -- the configured owner's context ID, `Observation`'s
  `owner=`.
- **EXPECTED** -- always `denied` (`Observation`'s `expected=denied`)
  -- what should have happened.
  the
- **ACTUAL** -- the cross-context response's status text
  (`Observation`'s `actual=`).
- **PROOF** -- `Observation`'s `proof_matches_owner_baseline=` (true
  only for the `critical` tier), plus a bounded (±80 byte)
  `ResponseFragment` around the identifier.
- **CONCLUSION** -- `Reason`, a full sentence distinguishing "confirmed
  unauthorized access to a specific protected object" from "access
  observed but confirmation incomplete."

No full response body is ever persisted -- only the bounded fragment,
matching every other Phase 3.x detector's evidence-storage discipline.

## Finding

Uses `pkg/models.Finding` unchanged -- no new schema, per task section
17. `VulnerabilityType` is `"idor"`; `Title`, `Severity`, `Confidence`,
`AffectedParameter`, `Description`, `Remediation`, and `Evidence` are
set by the detector; the engine's `normalizeFinding` (Phase 3.1,
unchanged) fills `ID`, `ScanID`, `DetectorID`, `Host`, `Port`, `URL`,
`Method`, `AffectedEndpoint`, `Source`, and timestamps.

## Deduplication

Reuses `internal/detection.Deduplicate` (Phase 3.1) unmodified. This
detector reports **at most one finding per (endpoint, parameter)
candidate**, aggregating every confirmed cross-context access into
that single finding's evidence -- not one finding per direction (e.g.
"A→B" and "B→A" as two separate findings). This is a deliberate design
choice, documented here per the task's explicit requirement to justify
it either way:

Phase 3.1's dedup key (`DetectorID + Host + Port + AffectedEndpoint +
Method + AffectedParameter + VulnerabilityType`) has no
resource-identifier or authorization-context field, so two logically
distinct directions against the *same* endpoint+parameter would
already collide and be treated as duplicates by the engine's own
(unmodified) dedup pass even if the detector tried to emit them
separately. Extending the dedup key to carry that information would
mean redesigning Phase 3.1's framework for this one detector's
benefit -- explicitly against the task's "do not redesign Phase 3.1
unless a genuine defect is discovered" instruction, and no defect
exists here (the aggregated-evidence approach fully reports every
confirmed direction; nothing is lost, only combined into one finding).

## Test lab fixtures

Two fixture pairs exist for IDOR/BOLA in the Phase 3 Test Lab; only the
second is detectable by this Phase-3.1-based detector (see "Candidate
selection"):

| Fixture | Endpoint | Detectable? |
|---|---|---|
| `VULN-IDOR-001` (original, path-based) | `/idor/vulnerable/user/{id}` | No -- path segment, not a query parameter (documented limitation) |
| `VULN-IDOR-NEG-001` | `/idor/safe/user/{id}` | No -- same reason |
| `VULN-IDOR-API-001` (Phase 3.5 addition, positive) | `GET /idor/api/resource/vulnerable?resource_id=` | **Yes** |
| `VULN-IDOR-API-NEG-001` (proper 403) | `GET /idor/api/resource/safe?resource_id=resource-a` (as user-b) | **Yes** |
| `VULN-IDOR-API-PUBLIC-NEG-001` (public resource) | `GET /idor/api/resource/safe?resource_id=resource-public` | **Yes** |
| `VULN-IDOR-API-INVALID-NEG-001` (proper 404) | `GET /idor/api/resource/safe?resource_id=does-not-exist` | **Yes** |
| `VULN-IDOR-API-GENERIC-NEG-001` (generic 200, no evidence) | `GET /idor/api/resource/generic?resource_id=resource-a` | **Yes** |

`lab/harness_vuln.go`'s `registerIDORAPI` implements the new
pair against a shared, synthetic `idorAPIResources` map (`resource-a`
owned by `user-a`, `resource-b` owned by `user-b`, `resource-public`
owned by nobody) with three handlers:

- `/idor/api/resource/vulnerable` -- returns the requested resource's
  full JSON body (including its synthetic marker, e.g.
  `RESOURCE_A_SECRET_MARKER`) regardless of the `X-Test-Auth-User`
  header. This is the positive fixture.
- `/idor/api/resource/safe` -- verifies `X-Test-Auth-User == resource.Owner`
  (or the resource is `Public`) before returning it; otherwise 403.
  Covers the "proper 403" negative, the "public resource" negative
  (no ownership check needed because it's meant to be shared), and,
  via an ID absent from `idorAPIResources`, the "proper 404" negative.
- `/idor/api/resource/generic` -- always returns the fixed
  `{"status":"ok"}`, regardless of `resource_id` or caller. Covers the
  "generic HTTP 200 without protected-resource evidence" negative.

No destructive or write-method fixture was added -- consistent with
"Method coverage" above, this detector never tests POST/PUT/PATCH/DELETE.

## Ground truth

`lab/ground-truth-vulnerabilities.yaml` carries 5 new IDOR
entries for the query-parameter fixture pair (`VULN-IDOR-API-001` plus
4 negatives), each with `id`, `type: idor`, `authentication_required`,
`endpoint`, `method`, `parameter`, and (positives only)
`expected_evidence.response_contains` naming the exact synthetic
marker string. `VULN-IDOR-001`'s `requires_capability` field was
updated (not left stale) to explain precisely why it remains
undetectable and to point at `VULN-IDOR-API-001` as the fixture this
detector is actually verified against. Positives: 17 base classes + 1
(Phase 3.2) + 1 (Phase 3.3) + 1 (Phase 3.5, `VULN-IDOR-API-001`) = 20.
Negatives: 17 + 3 + 3 + 4 (Phase 3.4) + 4 (Phase 3.5) = 31.

## Authentication safety

All credentials are synthetic and lab-only (`X-Test-Auth-User:
user-a`/`user-b`) -- explicitly **not** a real authentication scheme
(no JWT, no session cookie, no OAuth token). The detector never
requests, stores, guesses, or bypasses real credentials; it assumes
valid authorization contexts already exist and were supplied by the
operator ahead of time. Authentication bypass is explicitly out of
scope (see "What this detector does NOT detect").

## Scope enforcement

Every probe goes through `detection.Executor.Do` -- the same
scope-validated, rate-limited, timeout-bounded request path every
other detector uses; `probeAs` never builds its own `http.Client` or
bypasses scope in any way.
`TestDetect_OutOfScope_ReturnsErrorWithoutDialing` (unit) and
`TestPhase3_5_IDORDetector_ScopeEnforcementStaysActiveDuringDetection`
(integration -- a real scan job whose `ScopeSnapshot` authorizes only
`vuln.scanner.test`, tested against a manufactured `Target` pointing at
the Phase 2 lab's real `scanner.test` host) both confirm zero requests
reach an out-of-scope host. A scope bypass here would be an automatic
Phase 3.5 failure; none was found.

## Request limits

- **Linear in the number of configured contexts**, never
  combinatorial: exactly 1 owner-baseline request + (N-1) cross-context
  requests per candidate, where N is the number of configured
  `AuthContext` values (2 in the lab -> 2 total requests per
  candidate). No candidate-selection or comparison step scales with
  the number of *resources* discovered elsewhere on the target --
  each candidate is evaluated independently, using only the single
  identifier Phase 2's recon already discovered for it.
- **Timeout / concurrency / rate limiting**: inherited unchanged from
  the shared `detection.Executor`, identical to every other Phase 3.x
  detector -- no detector-specific network controls exist or are
  needed.
- `TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests` runs 10
  candidates concurrently and asserts exactly `10 × 2 = 20` total
  target requests -- no request multiplication, confirmed under
  `-race`.

## Error handling and cancellation

- **401/403/404** -- handled by `looksAllowed` returning false; never
  interpreted as an IDOR (the opposite would be the actual defect).
- **Invalid/expired credential context** -- a context whose `Headers`
  the target rejects behaves identically to any other denied response;
  `TestDetect_ExpiredOrInvalidCredentialContext_NoFinding` confirms no
  finding results.
- **Connection failure / timeout** -- `probeAs` propagates the
  `Executor.Do` error via `fmt.Errorf("idor: ... probe: %w", err)`;
  `Detect` returns that error rather than a Result, consistent with
  every other Phase 3.x detector's error-isolation contract.
- **Malformed resource ID in the original URL / malformed JSON
  response** -- `parameterValue` and the byte-level comparisons never
  parse the identifier or the body as structured data, so malformed
  input is handled as an ordinary string with no special-casing needed
  (`TestAdversarial_MalformedJSONResponse_NoCrash`,
  `TestAdversarial_MalformedResourceIDInOriginalURL_NoCrash`).
- **Cancellation** -- checked implicitly at every `Executor.Do` call
  (owner baseline and every cross-context probe); a cancellation mid-baseline
  or mid-cross-probe surfaces as the propagated context error, and no
  request is issued after cancellation
  (`TestDetect_ContextCancellation_ReturnsError`,
  `TestDetect_CancellationDuringBaseline`).

## Limitations

- **GET query parameters only** -- see "Candidate selection" and
  "Method coverage."
- **Parameter-name heuristic only** -- Phase 2's recon has no
  parameter-value-shape classification, the same documented gap every
  Phase 3.x detector carries; "if existing reconnaissance data
  contains stronger evidence, prefer that" doesn't currently apply.
- **Path-segment object references are undetectable** -- see
  "Candidate selection"; `VULN-IDOR-001`/`VULN-IDOR-NEG-001` remain out
  of reach.
- **No production authorization-context infrastructure ships in this
  build** -- see "Authorization contexts." The detector is fully
  built, tested, and verified against the real Phase 3 Test Lab's own
  synthetic contexts; wiring it to a real, operator-supplied credential
  source is future work, deliberately out of this phase's scope.
- **Digit-run-only response normalization** -- the same documented
  limitation `sqli`/`ssrf` carry: non-digit dynamic content (e.g. a
  UUID that regenerates per request) is not normalized away, which
  could in principle prevent `matchesOwner` from reaching `true` for
  an otherwise-confirmed case -- the finding would still be reported,
  just at the `high`/0.55 tier instead of `critical`/0.9, never
  silently dropped.
- **Read-only (GET) IDOR only** -- write-object (POST/PUT/PATCH) IDOR
  testing is not implemented; per task section 13, this was
  deliberately deprioritized behind READ as the primary, always-safe
  path.
