# Phase 3.23 Acceptance Test: Path Parameter Discovery & Active Detection Foundation

This phase closes exactly one proven gap: path-location parameters
were never discovered by the live pipeline
(`internal/parameters.InferPathInputs` had zero callers). No new
vulnerability class, no IDOR/BOLA detection, no authorization testing,
no mass assignment, SSRF, command injection, or path-traversal
vulnerability detection, no time-based SQLi, no new platform
integrations. See
[docs/phase-3-23-path-parameters.md](phase-3-23-path-parameters.md)
for the full architecture review, performed and documented before any
implementation.

## What was built

The architecture review found `InferPathInputs` already implemented
the conservative, evidence-based design the task asks for (≥2 same-
method endpoints differing only in the last segment; only the last
segment ever considered variable; duplicate observations collapse
correctly; deterministic) -- it was simply never wired up, and its
computed segment index was discarded rather than persisted. The actual
work:

- **`parameters.Limits.MaxPathSegments`** (new, default 20) and
  `InferPathInputs`'s signature changed to `(eps, limits) Result`
  (safe -- zero callers to break), routing its output through the same
  `candidateAggregator` discipline `Normalize`/`NormalizeJSONResponses`
  already use.
- **`Candidate.PathSegmentIndex`**, **`models.Parameter.PathSegmentIndex`**
  (migration `0013`, `-1` sentinel for every non-path row),
  **`detection.Target.PathSegmentIndex`** -- threaded through the same
  three layers `FormFields` was threaded through in Phase 3.21.
- **Version-segment exclusion** (`/v1`/`/v2` never inferred) and,
  discovered mid-development, an **identifier-shape gate**
  (`looksLikeIdentifier`) -- see design decision 2 below for why the
  latter was added.
- **`internal/orchestration.crawlAndDiscoverEndpoints`**: a third
  discovery pass, scoped per-crawl-target exactly like the existing
  query/form and JSON-response passes, persisting path candidates as
  Parameters.
- **`detection.BuildTargets`/`endpointTargets`**: a fourth parameter
  map (`pathParamsByEndpointID`), routing `Location == "path" &&
  Provenance == "REQUEST_INPUT"` parameters into Targets. No same-
  origin gate needed -- path mutation is host-safe by construction
  (section 3.1 of the design doc).
- **`detection.NewTargetMutation`** (new, in `mutation_bridge.go`): the
  one shared helper both detectors now call instead of
  `mutation.NewMutation` directly, centralizing the
  `PathSegmentIndex`-aware `mutation.NewPathMutation` construction.
- **`sqliactive`/`xssactive`**: one `case "path":` arm each in
  `Eligible` and their location switch, plus the switch to
  `NewTargetMutation` at their existing Mutation-construction call
  sites. No other line in either package changed.
- **`lab/harness_path_parameters.go`** (new): `/users/{id}` (numeric,
  SQLi-vulnerable), `/products/{slug}` (non-numeric, reflected-XSS-
  vulnerable), `/api/v1/status` + `/api/v2/status` (version-segment
  negative fixture). **`lab/harness_auth.go`**: `/orders/{id}`
  (authenticated, SQLi-vulnerable path segment), linked from
  `/dashboard`. **`lab/harness_vuln.go`**: a genuinely separate second
  lab host (`second-service.scanner.test`, Phase 3.22 leftover
  infrastructure, unrelated to this phase's own additions beyond
  reuse).
- **`cmd/scanner/inputs.go`**: confirmed, by reading it in full,
  already fully generic over `Location` -- zero code changes needed
  (section 11 of the design doc).
- Documentation: `docs/phase-3-23-path-parameters.md` (architecture,
  written before implementation), this file.

## Architecture review (task section 1)

Full findings in the design doc's own section 1. The single most
consequential: `InferPathInputs` has zero live callers anywhere,
confirmed by exhaustive grep -- not a weak signal, no signal at all.
The second-most consequential, identified during the review itself
(not discovered as a surprise later): path inference must be scoped
per-HTTPService, since `PathEndpoint` carries no host information and
pooling endpoints across services would let two unrelated sites both
exposing `/users/123` be incorrectly treated as one logical family.

## Design decisions and defects found during development

1. **A real, pre-existing double-encoding defect in
   `mutation.applyPath`'s escaped mode**, latent since Phase 3.17 and
   only now exercised by a live HTTP request (Phase 3.23 is the first
   thing in this codebase to ever build a real request from an
   escaped path mutation). `url.PathEscape`'d the value BEFORE storing
   it into `req.Path`, but `Request.URL()` builds a plain
   `url.URL{Path: ...}` with no `RawPath` override -- `url.URL.String()`
   always escapes `Path` once more when serializing, so every `%` the
   pre-escape introduced was escaped AGAIN, corrupting the value on
   the wire (`url.PathEscape("1' OR '1'='1")` followed by
   `url.URL{Path:...}.String()` produced `%2527%2520OR...`, not the
   correct `%27%20OR...`). Reproduced with a regression test FIRST
   (`TestMutate_Path_Escaped_ValueWithSpecialCharacters_URLRoundTrips`,
   confirmed failing before the fix), then fixed (remove the pre-
   escape; `applyPath` now mirrors `applyQuery`'s own established
   pattern of relying on the standard library's single escaping
   pass), then re-verified passing. A related, genuinely PRE-EXISTING
   (not caused or worsened by this fix) limitation was found and
   explicitly documented with its own passing test
   (`TestMutate_Path_Verbatim_KnownLimitation_StillAutoEscapedByURLString`):
   `EncodingVerbatim` cannot achieve true byte-for-byte unescaped
   output for `LocationPath` with the current `Request.URL()` design
   (unlike query/form, which have their own raw-output escape
   hatches) -- out of scope to fix since neither detector this phase
   touches ever requests verbatim encoding for any location.
2. **A real, more significant false-positive defect in
   `InferPathInputs`'s own evidence rule**, discovered when
   `TestPhase3_18_FullCrawl_JSONAndAPIDiscovery` (an existing,
   previously-passing Phase 3.18 test, untouched by this phase) started
   failing the moment path inference was wired into the live pipeline.
   The "≥2 endpoints, same method, last segment differs" rule cannot
   distinguish a genuinely templated resource (`/api/{id}`, many
   instances of ONE resource) from several DIFFERENT, statically-named
   sibling endpoints that merely share a parent prefix -- an extremely
   common real-world REST shape. `/api/nested`, `/api/items`,
   `/api/malformed` (three real, unrelated endpoints from the lab's
   own pre-existing Phase 3.18 fixtures) satisfied the rule and were
   incorrectly inferred as a fake `"api_value"` path parameter,
   colliding with an existing JSON-discovered parameter of the same
   name on the same endpoint. Reproduced with a regression test FIRST
   (`TestInferPathInputs_DistinctStaticSiblingEndpoints_NeverConflated`),
   then fixed with a narrow, well-justified additional gate
   (`looksLikeIdentifier`): every distinct value at the varying
   position must be all-numeric OR contain a digit, hyphen, or
   underscore -- the shape real-world numeric/UUID/hex/slug
   identifiers overwhelmingly share, and ordinary lowercase static
   resource names essentially never do. Deliberately a narrower net
   than the original rule: prefer a false negative (missing a
   legitimately templated resource whose sample values happen to look
   like bare words) over a false positive (fabricating a parameter,
   and therefore a mutation target, from unrelated static endpoints) --
   consistent with the version-segment exclusion's own, identically-
   reasoned precedent (section 2.2 of the design doc). One of this
   phase's own new tests
   (`TestInferPathInputs_VersionShapedButMixedWithNonVersion_StillInferred`)
   was itself premised on the OLD, looser rule and had to be corrected
   (renamed, assertion reversed) once the new gate revealed its own
   premise was too permissive.
3. **A pre-existing e2e test's own "boundedness" assertion was
   invalidated by design, not broken.**
   `TestScanCmd_DeepProfile_CrawlsMoreThanWeb_ButBounded` (unrelated to
   path parameters at the time it was written) used its own synthetic
   30-page chain fixture with URLs shaped `/p/{n}?id={n}` -- BEFORE
   this phase, each crawled page contributed roughly one eligible
   target (the query parameter `id`), so the test asserted
   `EligibleTargets < totalPages` as its own "the crawl is bounded, not
   unlimited" proof. Once path-parameter discovery was wired up, the
   SAME fixture's `/p/{n}` segment is now ALSO correctly inferred as a
   path-location eligible target -- exactly the intended, correct
   behavior this phase adds -- so `EligibleTargets` can legitimately
   exceed the page count even though the crawl itself is exactly as
   bounded as before (38 eligible targets from a crawl that still only
   visited under 30 pages). Fixed by moving the boundedness assertion
   to the `Crawl: Public URLs` metric (the actual page-crawl-budget
   figure), which is what "deep is not unlimited" was always actually
   about -- the deep-discovers-more-than-web comparison stays on
   `EligibleTargets`, unchanged and still meaningful. This is
   documented as "invalidated by design" rather than "broken" because
   the OLD assertion's implicit premise (one eligible target per page)
   was never actually guaranteed by anything before this phase either
   -- Phase 3.23 is simply the first change that made the premise
   visibly false.
4. **A registry mismatch, self-caught immediately.** The first version
   of the XSS-via-non-numeric-path-segment lab test used
   `formMutationOrchestrator` (Phase 3.21), which registers only
   `sqli-active` -- `xss-reflected-active` never ran, so the test
   failed with an unrelated `sql_injection` finding instead of the
   expected `reflected_xss` one. Fixed by switching to
   `coverageOrchestrator` (Phase 3.22), which registers both.

## Test matrix results

### PATH PARAMETER DISCOVERY
Already correctly designed (architecture review); this phase adds
`Provenance`/`PathSegmentIndex` population and wiring. Proven via a
REAL crawl of `/paths/index`
(`TestPhase3_23_FullCrawl_SQLiViaNumericPathSegment_ReachesActiveDetection`,
`TestPhase3_23_FullCrawl_XSSViaNonNumericPathSegment_ReachesActiveDetection`).
**PASS**

### CANONICALIZATION
Numeric IDs, non-numeric slugs (hyphenated), version segments (never
inferred), static numeric paths (never inferred, pre-existing),
duplicate paths with different values (remain distinguishable, never
collapsed) -- each has a dedicated unit test
(`TestInferPathInputs_VariableLastSegment_Numeric`,
`TestInferPathInputs_NonNumericVariation_UsesValueSuffix`,
`TestInferPathInputs_VersionSegment_NeverInferred`,
`TestInferPathInputs_StaticPath_NoVariation_NoInput`) and a lab-level
real-crawl proof
(`TestPhase3_23_FullCrawl_VersionSegment_NeverInferredOrTargeted`,
`TestPhase3_23_FullCrawl_DuplicatePathValues_RemainDistinguishable`).
UUIDs/hex identifiers are covered by the same evidence rule and the
same `looksLikeIdentifier` gate (both contain digits) -- no dedicated
fixture was needed beyond the existing numeric/slug pair to prove the
gate's own logic, which is format-agnostic by design. **PASS**

### DUPLICATE HANDLING
`TestPhase3_23_FullCrawl_DuplicatePathValues_RemainDistinguishable`
proves `/users/1`, `/users/2`, `/users/3` remain three distinct
`Parameter` rows sharing one logical name (`user_id`) -- task section
8's own IDOR-foundation requirement. **PASS**

### MUTATION CORRECTNESS
`mutation.applyPath` needed no logic change beyond the escaped-mode
fix (design decision 1) -- re-verified via the existing
`TestMutate_Path_ReplacesSegment`/`TestMutate_Path_IndexOutOfRange_Errors`
plus the new regression test. **PASS**

### XSS PATH MUTATION / SQLI PATH MUTATION
Unit: `TestDetect_PathSegmentVulnerable_Finding`/
`TestDetect_PathSegmentSafeParameterized_NoFinding` (sqliactive),
`TestDetect_PathSegmentReflection_Finding`/
`TestDetect_PathSegmentEscaped_NoFinding` (xssactive). Lab, via a REAL
crawl: see "PATH PARAMETER DISCOVERY" above. E2E, through the real
binary: `TestScanCmd_ActivePathParameter_SQLiViaNumericSegment_RealBinary`.
**PASS**

### AUTHENTICATION / MULTI-IDENTITY / SESSION ISOLATION
No new authentication code. Proven against the real, authenticated
`/orders/{id}` fixture
(`TestPhase3_23_AuthenticatedPathSegment_FindingWithIdentityContext`,
`TestPhase3_23_IdentityAAndB_PathSegment_IndependentFindingsNoContamination`,
`TestPhase3_23_ConcurrentIdentityScans_PathSegment_NoRaceNoContamination`)
and through the real binary
(`TestScanCmd_ActivePathParameter_AuthenticatedOrders_RealBinary`).
**PASS**

### SCOPE ENFORCEMENT / REDIRECTS / ENCODED PATHS
Path mutation is host-safe by construction -- `applyPath` only ever
rewrites `req.Path`, never `Host`/`Scheme`/`Port`. Proven, not merely
asserted: `TestDetect_PathSegment_RealSQLiProbes_NeverChangeHost`
(detector-level, real probes), `TestAdversarial_PathMutation_AbsoluteURLConfusionValue_NeverChangesHost`
(mutation-level, an adversarial value shaped like a full absolute
URL), and the pre-existing, re-verified
`TestAdversarial_ScopeBypass_EncodedPathNeverChangesDialTarget`.
Redirects unchanged -- reused `safedial` machinery. **PASS**

### IDOR FOUNDATION
Not implemented (by design) -- the existing concrete-Endpoint-per-
value model already gives a future phase what it needs, proven by
"DUPLICATE HANDLING" above. No authorization-specific heuristic,
`internal/correlation`, or `internal/risk` code was touched. **PASS**
(as a foundation; explicitly NOT a detection capability)

### RESOURCE LIMITS
`MaxPathSegments` (new, unit-tested:
`TestInferPathInputs_MaxPathSegments_DeepPathSkipped`),
`MaxInputsPerEndpoint`/`MaxTotalInputs` (reused via the aggregator,
`TestInferPathInputs_MaxTotalInputs_Capped`), and
`MaxActiveRequestsPerScan` (reused, already Location-agnostic,
`TestPhase3_23_ActiveRequestLimit_BoundsPathMutationRequests`).
**PASS**

### DETERMINISM
`TestInferPathInputs_Deterministic` (unit, pre-existing, re-verified)
and `TestPhase3_23_Determinism_RepeatedCrawls_SamePathDiscoveryAndTargets`
(lab, 3 repeated real crawls). **PASS**

### CONCURRENCY
`TestPhase3_23_ConcurrentIdentityScans_PathSegment_NoRaceNoContamination`
-- two identities' scans running as true concurrent goroutines, race-
clean. **PASS**

### SQLITE PERSISTENCE
`TestParameter_PathSegmentIndex_RoundTripAndDefault` -- a path
Parameter's index round-trips correctly; a non-path Parameter's index
is forced to `-1` at `Create` time regardless of what the caller's
struct literal left in the field (mirroring the established
`Provenance`-defaulting pattern). **PASS**

### CLI / E2E BEHAVIOR
`scanner inputs --location path` requires zero code changes (confirmed
by reading `cmd/scanner/inputs.go` in full) -- proven live via
`TestScanCmd_ActivePathParameter_SQLiViaNumericSegment_RealBinary`,
which also checks the JSON report's `Parameters`/`Findings` arrays
directly. **PASS**

### ADVERSARIAL

| Scenario | Covered by |
|---|---|
| Numeric IDs | `TestInferPathInputs_VariableLastSegment_Numeric`, `TestPhase3_23_FullCrawl_SQLiViaNumericPathSegment_ReachesActiveDetection` |
| UUID-like values | Same evidence rule + `looksLikeIdentifier` gate (format-agnostic, both contain digits) |
| Version segments | `TestInferPathInputs_VersionSegment_NeverInferred`, `TestPhase3_23_FullCrawl_VersionSegment_NeverInferredOrTargeted` |
| Static numeric paths | `TestInferPathInputs_StaticPath_NoVariation_NoInput` (pre-existing, re-verified) |
| Distinct static sibling endpoints (new false-positive class) | `TestInferPathInputs_DistinctStaticSiblingEndpoints_NeverConflated` |
| Encoded paths | `TestAdversarial_ScopeBypass_EncodedPathNeverChangesDialTarget` (pre-existing, re-verified) |
| Traversal-like path value | `TestAdversarial_ScopeBypass_EncodedPathNeverChangesDialTarget`'s own `..`-containing payload |
| Absolute URL/path confusion | `TestAdversarial_PathMutation_AbsoluteURLConfusionValue_NeverChangesHost` |
| Path mutation attempting to change host | Same, plus `TestDetect_PathSegment_RealSQLiProbes_NeverChangeHost` |
| Identity A/B contamination | `TestPhase3_23_IdentityAAndB_PathSegment_IndependentFindingsNoContamination` |
| Resource limits | `TestInferPathInputs_MaxPathSegments_DeepPathSkipped`, `TestInferPathInputs_MaxTotalInputs_Capped`, `TestPhase3_23_ActiveRequestLimit_BoundsPathMutationRequests` |
| Determinism | `TestInferPathInputs_Deterministic`, `TestPhase3_23_Determinism_RepeatedCrawls_SamePathDiscoveryAndTargets` |
| Concurrency | `TestPhase3_23_ConcurrentIdentityScans_PathSegment_NoRaceNoContamination` |
| SQLite persistence | `TestParameter_PathSegmentIndex_RoundTripAndDefault` |

All scenarios: **NO SECURITY BOUNDARY FAILURE. PASS.**

### REGRESSION

```
go build ./...                                          -> clean
go vet ./...                                             -> clean
gofmt -l .                                                -> clean (no output)
go test $(go list ./... | grep -v '/tests/e2e') -race -v  -> ok, 1470 PASS, 0 FAIL (35 packages with tests)
go test ./tests/e2e/... -v -timeout 25m                   -> ok, 95 PASS, 0 FAIL
```

Note: the default `go test` 10-minute timeout was exceeded on the
first e2e run (53/95 tests had completed cleanly when it fired) --
purely a test-harness artifact of the e2e suite's own accumulated size
across every prior phase (Phase 3.19-3.23 each added several 60+
second real-crawl tests), not a hang or a regression. Re-run with an
explicit `-timeout 25m`, the full suite passed cleanly. Recorded here
rather than silently re-run and forgotten.

Explicit regression re-verification for every prior phase named in the
task (3.14, 3.15, 3.16, 3.17, 3.18, 3.19, 3.20, 3.21, 3.22): every own
test suite re-verified passing, including
`TestPhase3_18_FullCrawl_JSONAndAPIDiscovery` (design decision 2 above
-- a REAL regression this phase's own live-wiring caused, caught and
fixed, not merely re-run unchanged). Production/lab independence
re-verified: physically removed `lab/` and `tests/`, confirmed `go
build ./...`/`go vet ./...` succeed with both absent, restored both,
rebuilt again to confirm restoration. **PASS**

### RACE

Full non-e2e suite, every package, `-race -count=1`, standalone: clean,
zero races reported. **PASS**

## Final architectural validation (task section 14)

1. **Does a real crawl now discover path parameters?** Yes -- proven
   via a real crawl of `/paths/index` and `/orders/{id}`.
2. **Are path parameters persisted as canonical Parameters?** Yes --
   `Location: "path"`, same `models.Parameter` shape as every other
   location, `PathSegmentIndex` the only new field.
3. **Can BuildTargets route them into active detection?** Yes --
   `pathParamsByEndpointID`, no same-origin gate needed.
4. **Does the existing mutation engine mutate path values correctly?**
   Yes, after fixing the real, pre-existing double-encoding defect
   (design decision 1) -- proven with a regression test.
5. **Do authenticated requests preserve the correct session?** Yes,
   unconditionally, with zero form-specific code -- unchanged since
   Phase 3.19.
6. **Does IdentityContext survive the entire path-detection
   pipeline?** Yes, proven at the label level and via true concurrent
   goroutines.
7. **Can XSS active test path parameters?** Yes -- the 2-line adapter.
8. **Can SQLi active test path parameters?** Yes -- the 2-line
   adapter.
9. **Can scope enforcement prevent host/path mutation bypasses?** Yes
   -- host-safe by construction, proven adversarially with an
   absolute-URL-shaped payload value.
10. **Are path values preserved sufficiently for future IDOR/BOLA
    work?** Yes -- concrete Endpoint/Parameter rows per distinct
    value, consistently named, proven never collapsed.
11. **Are duplicate/path normalization rules deterministic?** Yes,
    proven directly across 3 repeated real crawls.
12. **Are existing query/form/JSON behaviors unchanged?** Yes -- every
    pre-existing detector's own suite re-verified passing unchanged;
    only `sqliactive`/`xssactive` gained the 2-line path adapter each,
    additively.

Every answer is yes.

## Final report

```
PHASE 3.23 PATH PARAMETER DISCOVERY & ACTIVE DETECTION FOUNDATION

TOTAL TESTS: 1565
PASS: 1565
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0

DEFECTS FOUND AND FIXED:
1. mutation.applyPath double-encoding (pre-existing since Phase 3.17,
   never exercised by a live request before this phase) -- fixed,
   regression test added first.
2. InferPathInputs false positive on distinct static sibling endpoints
   sharing a prefix (a real gap in the evidence rule, only surfaced
   once wired into the live pipeline) -- fixed with a narrow,
   well-justified identifier-shape gate, regression test added first.

REMAINING LIMITATIONS:
1. EncodingVerbatim cannot achieve true byte-for-byte unescaped output
   for LocationPath (pre-existing, unrelated to this phase's own
   changes; nothing in this codebase currently requests it).
2. The identifier-shape gate is deliberately conservative: a
   legitimately templated resource whose sample values happen to look
   like bare words (no digit, hyphen, or underscore) will not be
   inferred -- a stated false-negative trade-off, not a silent gap.
3. header/cookie parameter locations still have no discovery source
   (unchanged since Phase 3.13, out of this phase's own scope).

ARCHITECTURAL FINDINGS:
InferPathInputs had zero live callers (confirmed by exhaustive grep,
not assumed) -- the ONLY reason path parameters never reached active
detection was that nothing ever invoked an already-correct, already-
tested function. Wiring it into the live pipeline surfaced two real,
previously-latent defects (see above) that no amount of unit testing
against synthetic inputs alone would have caught -- both were only
found because this phase insisted on a REAL crawl -> REAL persistence
-> REAL BuildTargets -> REAL mutation -> REAL HTTP request path, not
a unit-only proof.

PHASE 3.23 VERDICT: PASS
```

Per the task's final rule: no IDOR/BOLA, authorization testing, access-
control testing, mass assignment, SSRF, command injection, path-
traversal vulnerability detection, new vulnerability classes, time-
based SQLi, or new platform integrations were implemented. Stopping
here -- Phase 3.24 is not started.
