# Phase 3.20 Acceptance Test: SQL Injection Active Detector

This phase adds the second production-grade active detector on Phase
3.19's mutation-based detection architecture: SQL injection, via
error-based and boolean-differential detection. No SSRF, command
injection, path traversal, IDOR/BOLA, authorization testing,
stored/DOM/blind XSS, mass assignment, business-logic testing,
database dumping, destructive SQL, OS command execution, automated
exploitation, or time-based SQLi was implemented. See
[docs/phase-3-20-sqli.md](phase-3-20-sqli.md) section 0 for the full
scope discipline this document assumes.

## What was built

- **`internal/detectors/sqliactive`** (new package, ID `sqli-active`):
  a second, independent SQL injection detector built entirely on
  `detection.NewMutationRequest`/`mutation.NewMutation`/`Mutate`/
  `Executor.ExecuteMutation`/`mutation.Compare`/
  `detection.MutationEvidence` -- zero private HTTP client, zero
  private request construction. Coexists with, and does not modify,
  the pre-existing `internal/detectors/sqli` (Phase 3.3). Four probes
  per eligible target (baseline, error, true-condition,
  false-condition); a four-tier confidence rubric
  (`errorIsSpecific && booleanDiff` -> Critical/0.95 down to
  `errorFamily == "generic"` alone -> Medium/0.3, nothing ->
  no finding).
- **`internal/detectors/sqliactive/errorpatterns.go`**: an
  independently-reimplemented copy of `internal/detectors/sqli`'s own
  `dbErrorPatterns` table (per-family substring lists, generic as a
  lower-confidence fallback) -- not imported, preserving the
  established convention that no detector package imports another
  detector's package.
- **`internal/detectors/sqliactive/signals.go`**: `computeSignals`
  (error-family correlation against baseline; boolean-differential via
  payload-stripped `mutation.Compare`) and `classify` (the four-tier
  rubric above).
- **`cmd/scanner/detectors.go`**: registers `sqliactive.New()`
  alongside the eight existing detectors (now 8 registered total,
  6 enabled by default).
- **`lab/harness_vuln.go`**: `sqliSimulateQuery` factored out of the
  pre-existing `/sqli/vulnerable` handler (returns `(status, body)`
  rather than writing directly, so it can be reused by value); two new
  fixtures, `/sqli/form/vulnerable` and `/sqli/json/vulnerable`,
  reusing the identical, already-reviewed vulnerability shape.
- **`lab/harness_auth.go`**: `/lookup?id=` -- an authenticated
  SQL-injection-vulnerable endpoint (session-gated, reuses
  `sqliSimulateQuery`), linked from `/dashboard`.
- **`lab/phase3_20_sqli_active_test.go`** (new, 11 tests): real
  orchestrator + real lab integration tests -- unauthenticated
  positive (full crawl), benign negative, boolean-only positive, form-
  location boundary (negative), JSON `REQUEST_INPUT` positive,
  authenticated positive with identity context, identity A/B
  isolation, concurrent identity scans, resource-limit exhaustion,
  determinism.
- **`tests/e2e/e2e_active_sqli_test.go`** (new, 5 tests): the real
  built binary against the real, isolated lab -- unauthenticated
  positive, benign negative (via structured JSON report parsing, not
  markdown substring matching), authenticated positive, identity A/B,
  concurrent scans.
- **Documentation**: `docs/phase-3-20-sqli.md` (architecture, written
  before implementation), this file.

## Architecture review (task section 1)

Full findings in the architecture doc's own section 1. The most
consequential: Phase 3.19 already provides everything this detector
needs (`ExecuteMutation`, `mutation.Compare`, `MutationEvidence`,
session threading, JSON target extension) -- no engine-level change
was required at all, unlike Phase 3.19 itself, which had to fix a real
gap in `detection.Executor`. This phase is a pure consumer of
Phase 3.19's architecture, which is itself evidence that architecture
generalized correctly to a second detector.

## Design decisions and defects found during development

1. **A real test-authoring mistake, self-corrected.**
   `TestDetect_ErrorBasedVulnerable_Finding` initially asserted
   `Confidence >= 0.9`. It measured 0.75: the fixture's error text
   ("SQL syntax error ... (simulated ...)") matches only the GENERIC
   pattern in `dbErrorPatterns`, not any family-specific one, so
   `errorIsSpecific=false`; combined with `booleanDiff=true`,
   `classify()` correctly lands in the "boolean alone" tier (0.75),
   not the top tier (0.95) -- this is correct, intended behavior, not
   a bug. Fixed the assertion, then added
   `TestDetect_MySQLFamilyErrorPlusBoolean_TopConfidenceTier` (a
   genuinely MySQL-shaped error message) to explicitly exercise the
   0.95 top tier, since the original fixture never did.
2. **A real, pre-existing data race, self-caught while writing this
   phase's own concurrent-identity lab test.** `authenticateIdentity`
   (`lab/phase3_16_multi_identity_test.go`, Phase 3.16) calls
   `t.Setenv` to pass credentials through env-var indirection. Calling
   it from two goroutines at once -- exactly what
   `TestPhase3_19_ConcurrentIdentityScans_NoRaceNoContamination`
   (Phase 3.19) and this phase's own
   `TestPhase3_20_ConcurrentIdentityScans_NoRaceNoContamination` both
   did -- races on `testing.T`'s own internal bookkeeping, regardless
   of `t.Parallel`. This was NOT caught during Phase 3.19's own
   regression sweep (its final report claimed a clean `-race` run);
   re-running that exact pre-existing test in isolation under `-race`
   during this phase reproduced the race deterministically, proving it
   was a real, previously-undetected gap in that regression sweep, not
   a new defect this phase introduced. Fixed in BOTH tests identically:
   both identities now authenticate SEQUENTIALLY before the goroutines
   are spawned, and only `orch.Run` itself executes concurrently --
   which is what "concurrent identity SCANS" actually needs to prove
   (session isolation under concurrent scanning), not concurrent
   authentication. Re-verified: both tests now pass clean under
   `-race`, repeatedly.
3. **Form-location parameters remain architecturally unreachable, and
   this phase does not change that.** `BuildTargets`
   (`internal/detection/targets.go`) only ever routes
   `Location=="query"` or `Location=="json"&&Provenance=="REQUEST_INPUT"`
   parameters into Targets; a `Location=="form"` parameter matches
   neither switch arm and produces no Target at all -- the same,
   unchanged boundary Phase 3.18/3.19 already documented. Proven,
   rather than merely re-asserted, by
   `TestPhase3_20_FormParameter_ReachesActiveDetection`: a directly-
   persisted form-location parameter against `/sqli/form/vulnerable`
   produces zero findings through the real `BuildTargets`->`Engine.Run`
   pipeline. Separately, `sqliactive.Detect` itself only ever maps
   `ParameterLocation=="body"` to `mutation.LocationJSON` (never to
   the distinct `mutation.LocationForm`), since the only way `"body"`
   currently reaches a Target at all is via the JSON extension -- so
   even if a future phase wires form-location parameters into
   `BuildTargets`, this detector's own location mapping would need a
   corresponding update too. Both facts are stated together here, not
   left implicit. `/sqli/form/vulnerable` remains a genuinely useful
   fixture: it is reachable by constructing a `detection.Target`
   directly (as `detector_test.go` effectively exercises via its own
   local httptest-based form-shaped handler), just not yet by the real
   crawl-driven pipeline.

## Test matrix results

### A. SQL INJECTION DETECTOR
`sqliactive` proven end to end (unit + lab + e2e); no detector-specific
HTTP execution path exists anywhere -- verified by inspection (no
`net/http.Client`/`cookiejar`/`scope.` construction inside the
package beyond the imported `mutation.Request`/`Response` types
themselves reference). **PASS**

### B. ERROR-BASED DETECTION
`matchDBError` against `dbErrorPatterns` (mysql/postgresql/mssql/
sqlite/oracle/generic families); an error-probe signature is only
trusted as evidence when it does NOT already match the same family in
the baseline response (`TestComputeSignals_ErrorAlreadyInBaseline_NoSignal`,
and end to end against `/sqli/generic-error`, whose baseline itself
already contains database-error-shaped wording). **PASS**

### C. BOOLEAN-DIFFERENTIAL DETECTION
True/false probe bodies stripped of their own payload text (raw,
HTML-encoded, URL-encoded) before comparison via `mutation.Compare`,
reusing its digit-run body normalization
(`TestComputeSignals_ReflectedPayload_StrippedBeforeCompare`,
`TestComputeSignals_DigitOnlyDifference_NoBooleanSignal`); proven
against the pure-boolean `/sqli/boolean/vulnerable` fixture (no error
text ever surfaces) both at the lab level
(`TestPhase3_20_BooleanOnlyEndpoint_Finding`) and unit level
(`TestDetect_BooleanOnlyVulnerable_Finding`). **PASS**

### D. TIME-BASED SQLI
Explicitly NOT implemented -- see
[docs/phase-3-20-sqli.md](phase-3-20-sqli.md) section 4 for the
rationale (the shared, concurrently-used `Executor` cannot yet
distinguish a deliberate delay from ordinary scan-concurrency jitter).
**NOT IMPLEMENTED (by design, documented)**

### E. PAYLOAD SAFETY
Four payloads total, all read-only: `"1"` (control), `"'"`
(syntax-breaking quote), `"1' OR '1'='1"`/`"1' AND '1'='2"`
(tautology/contradiction) -- identical to `internal/detectors/sqli`'s
own already-reviewed set, reused verbatim. No `DROP`/`DELETE`/
`UPDATE`/`INSERT`/`CREATE`, no stacked query, no out-of-band callback,
anywhere in the package (verified by inspection). **PASS**

### F. FALSE-POSITIVE RESISTANCE
Five distinct negative fixtures, each independently proven silent:
generic unconditional 500 with database-error wording
(`/sqli/generic-error`, `TestDetect_GenericUnconditionalError_NoFinding`),
dynamic/unstable response unrelated to the parameter (`/sqli/dynamic`,
`TestDetect_DynamicUnstableResponse_NoFinding`), safe/parameterized
query/boolean pairs (`TestDetect_SafeParameterized_NoFinding`,
`TestPhase3_20_BenignEndpoints_NoFinding`), reflected-payload text
(`TestComputeSignals_ReflectedPayload_StrippedBeforeCompare`), rate
limiting and parameter-validation errors
(`TestDetect_RateLimitedResponse_NoFinding`,
`TestDetect_ParameterValidationError_NoFinding`). **PASS**

### G. AUTHENTICATION
`buildDetectionExecutor` (Phase 3.19, reused unchanged) threads a real
`*auth.Session` into `mutation.SessionContext`; proven against the
real, authenticated `/lookup` lab fixture
(`TestPhase3_20_AuthenticatedPositive_FindingWithIdentityContext`) and
through the real CLI binary
(`TestScanCmd_ActiveSQLi_AuthenticatedPositive_RealBinary`). **PASS**

### H. MULTI-IDENTITY
Two independent identities each produce their own, correctly-tagged
finding with zero cross-contamination, proven sequentially, via TRUE
concurrent goroutines (`TestPhase3_20_ConcurrentIdentityScans_NoRaceNoContamination`,
race-clean after the fix in design decision 2 above), and through the
real CLI binary as separate subprocesses
(`TestScanCmd_ActiveSQLi_IdentityAAndB_IndependentScans_RealBinary`,
`TestScanCmd_ActiveSQLi_ConcurrentScans_RealBinary`). **PASS**

### I. SCOPE ENFORCEMENT
No new scope-decision code anywhere -- reused entirely from
`mutation.Executor.Execute`. Adversarial proof specific to this
detector's own request path: an out-of-scope redirect target's content
never becomes a finding (`TestDetect_RedirectToOutOfScopeHost_NeverFollowed`),
a session header never leaks across that same redirect
(`TestDetect_SessionNeverLeaksToOutOfScopeHost`), and a denied-scope
target is never dialed at all
(`TestDetect_DeniedScope_ErrorsAndNoRequestsIssued`). **PASS**

### J. RESPONSE COMPARISON
`mutation.Compare` reused directly (not reimplemented) as the boolean-
differential primitive, with SQLi-specific payload-stripping applied
BEFORE the comparison, not as a post-hoc filter. **PASS**

### K. EVIDENCE
`detection.MutationEvidence` used directly -- baseline + probe
evidence items per finding, mirroring `internal/detectors/sqli`'s own
two-evidence-item convention. Password never appears in a generated
report (`TestScanCmd_ActiveSQLi_AuthenticatedPositive_RealBinary`'s
own explicit assertion). **PASS**

### L. CORRELATION / RISK
No detector-specific logic exists in `internal/correlation` or
`internal/risk` -- confirmed by architecture review, not merely
assumed; `sqliactive`'s findings use the identical `models.Finding`
shape every other detector already produces. **PASS**

### M. RESOURCE LIMITS
`ExecutorConfig.MaxActiveRequestsPerScan` proven centrally enforced
against a real, multi-parameter vuln lab scan: a budget of 1 total
mutation still completes cleanly with a small, bounded finding count,
not an unbounded one
(`TestPhase3_20_ActiveRequestLimit_BoundsRequestsNotUnbounded`).
**PASS**

### N. DETERMINISM
Three repeated scans against the same lab target produce an identical
finding count and identical severity for the same endpoint
(`TestPhase3_20_Determinism_RepeatedScans_SameStructuralResult`).
**PASS**

### O. LAB
11 new lab test functions
(`lab/phase3_20_sqli_active_test.go`), 3 new minimal fixtures
(`/sqli/form/vulnerable`, `/sqli/json/vulnerable`, `/lookup`) -- no
vulnerability-specific lab logic beyond what already existed
(`sqliSimulateQuery` factored out, not reimplemented). Full `lab`
suite (126 tests, including every prior phase's own) re-verified
clean. **PASS**

### P. E2E
5 new e2e tests (`tests/e2e/e2e_active_sqli_test.go`) against the REAL
built binary and the REAL, isolated lab -- unauthenticated positive,
benign negative (structured JSON report parsing), authenticated
positive, identity A/B, concurrent scans. Full `tests/e2e` suite (86
tests) re-verified clean. **PASS**

### Q. ADVERSARIAL (task section 16)

| # | Scenario | Covered by |
|---|---|---|
| 1 | URL-encoded parameter name | `TestDetect_URLEncodedParameterName_NoCrash` |
| 2 | Nested JSON parameter | `TestDetect_NestedJSONParameter_MutatesCorrectPath` |
| 3 | Duplicate query parameter name | `TestDetect_DuplicateQueryParameterName_NoCrash` |
| 4 | Empty parameter name | `TestDetect_EmptyParameterName_HandledOrSkipped` |
| 5 | Boolean-typed parameter value | `TestDetect_BooleanTypedParameterValue_NoCrash` |
| 6 | Very large response body | `TestDetect_VeryLargeResponseBody_BoundedNoCrash` (bounded read, `maxBodySample`) |
| 7 | Malformed host | `TestDetect_MalformedHost_NoCrash` |
| 8 | Cancellation during active request | `TestDetect_ContextCancelled_ReturnsPromptlyNoHang` |
| 9 | Detector/executor timeout | `TestDetect_ExecutorTimeout_ReportedAsDetectorErrorNotFinding` |
| 10 | Rate-limited response | `TestDetect_RateLimitedResponse_NoFinding` |
| 11 | Parameter validation error | `TestDetect_ParameterValidationError_NoFinding` |
| 12 | Redirect scope bypass | `TestDetect_RedirectToOutOfScopeHost_NeverFollowed` |
| 13 | Session leak across redirect | `TestDetect_SessionNeverLeaksToOutOfScopeHost` |
| 14 | Safe/parameterized negative | `TestDetect_SafeParameterized_NoFinding` |
| 15 | Generic unrelated database error | `TestDetect_GenericUnconditionalError_NoFinding` |
| 16 | Unstable/dynamic application response | `TestDetect_DynamicUnstableResponse_NoFinding` |
| 17 | Out-of-scope denial | `TestDetect_DeniedScope_ErrorsAndNoRequestsIssued` |
| 18 | JSON-body positive detection | `TestDetect_JSONBodyVulnerable_Finding` |
| 19 | Reflected-payload false positive | `TestComputeSignals_ReflectedPayload_StrippedBeforeCompare` |
| 20 | Error text unconditionally present in baseline | `TestComputeSignals_ErrorAlreadyInBaseline_NoSignal` |
| 21 | Trivial/digit-only response difference | `TestComputeSignals_DigitOnlyDifference_NoBooleanSignal` |
| 22 | Concurrent identity scans | `TestPhase3_20_ConcurrentIdentityScans_NoRaceNoContamination`, `TestScanCmd_ActiveSQLi_ConcurrentScans_RealBinary` |
| 23 | Request-limit exhaustion | `TestPhase3_20_ActiveRequestLimit_BoundsRequestsNotUnbounded` |
| 24 | Determinism across repeated scans | `TestPhase3_20_Determinism_RepeatedScans_SameStructuralResult` |
| 25 | Form-location parameter boundary | `TestPhase3_20_FormParameter_ReachesActiveDetection` |

All 25 scenarios: **NO SECURITY BOUNDARY FAILURE. PASS.**

### R. REGRESSION

```
go build ./...                                          -> clean
go vet ./...                                             -> clean
gofmt -l .                                                -> clean (no output)
go test $(go list ./... | grep -v '/tests/e2e') -race -v  -> ok, 1387 PASS, 0 FAIL (35 packages with tests, +1 for internal/detectors/sqliactive)
go test ./tests/e2e/... -v                                -> ok, 86 PASS, 0 FAIL
```

Note: an initial combined run (both suites launched concurrently to
save wall-clock time) produced 2 spurious 60s timeout failures under
resource contention
(`TestSSRFCallbackServer_NeverProxiesRegardlessOfInput`,
`TestPhase3_1_CancellationDuringDetection` -- both pre-existing tests,
untouched by this phase). Re-run alone, uncontended, both suites
passed clean with zero failures; this is recorded here rather than
silently discarded, per the standing instruction to document rather
than hide anything observed.

Production/lab independence re-verified: physically removed `lab/`
and `tests/`, confirmed `go build ./...`/`go vet ./...` succeed with
both absent, confirmed (after investigating one false-positive grep
match against a doc comment stating the opposite) that no production
or test file outside `lab/` itself imports `sakanner/lab`, restored
both, rebuilt again to confirm restoration. Every existing
vulnerability detector's own test suite (sqli, ssrf, traversal,
xssreflected, xssactive, cmdinjection, idor) re-verified passing
unchanged -- none was touched. **PASS**

### S. RACE

Full repository, every package, `-race -count=1`, run standalone
(uncontended): clean, zero races reported, including every concurrent
test this phase added or fixed (concurrent identity scans at both the
lab level and, via separate real subprocesses, the e2e level). One
real, pre-existing race (design decision 2 above) was found and fixed
during this phase's own development. **PASS**

## Final architectural validation (task section 18)

1. **Can a second active detector reuse the canonical mutation.Request
   without any engine change?** Yes -- `detection.NewMutationRequest(t)`
   used directly, unmodified; zero changes to `internal/detection`'s
   engine code were needed for this phase (unlike Phase 3.19, which
   had to build the capability this phase only consumes).
2. **Can it execute through the central authenticated executor?** Yes
   -- `Executor.ExecuteMutation`, session-aware whenever the scan
   itself authenticated.
3. **Does every request pass through scope enforcement?** Yes --
   delegates entirely to `mutation.Executor.Execute`; proven
   adversarially (redirect, denied-scope target, items 12/13/17 in the
   adversarial table).
4. **Can the existing response-comparison infrastructure
   (`mutation.Compare`) be reused for boolean-differential detection
   without modification?** Yes -- used directly, with SQLi-specific
   payload-stripping layered in front of it, not inside it.
5. **Is error-based detection resistant to unrelated database errors?**
   Yes -- an error signature is only trusted when it does NOT already
   match the baseline response's own signature
   (`/sqli/generic-error`'s unconditional 500 stays silent).
6. **Is boolean-differential detection resistant to reflected-payload
   and trivial-difference false positives?** Yes -- payload text
   (raw/HTML-encoded/URL-encoded) is stripped before comparison, and
   `mutation.Compare`'s existing digit-run normalization absorbs
   incidental numeric drift.
7. **Can JSON-body and query parameters both reach detection?** Yes,
   with the same honest caveat Phase 3.19 already documented: proven
   via a directly-persisted parameter
   (`TestPhase3_20_JSONRequestInputParameter_ReachesActiveDetection`),
   since the crawler still cannot produce a live JSON request body.
8. **Can POST-form parameters reach detection?** No, not through the
   real crawl-driven pipeline -- `BuildTargets` never routes
   `Location=="form"` parameters into Targets at all (design decision
   3 above). This is an honest limitation, not a hidden gap: proven
   explicitly by `TestPhase3_20_FormParameter_ReachesActiveDetection`
   rather than left untested.
9. **Can identity A and B execute independently, including under true
   concurrency?** Yes, proven sequentially, concurrently (in-process,
   after fixing the pre-existing `t.Setenv` race), and concurrently via
   separate real subprocesses (e2e), with explicit cross-contamination
   checks in every case.
10. **Can evidence identify the exact mutation and probe that produced
    a finding?** Yes -- every probe's `mutation.Mutation`/`Response`
    flows through `detection.MutationEvidence` into the finding's
    evidence items unchanged.
11. **Can the existing correlation and risk engines consume the
    finding without modification?** Yes, confirmed by architecture
    review: both remain fully generic over `models.Finding`.
12. **Can the report reproduce the finding without exposing
    credentials?** Yes -- proven directly: the authenticated e2e test
    asserts the real account password never appears in the generated
    report.
13. **Are active-request limits centrally enforced for this
    detector too, not just for xssactive?** Yes -- the identical
    `ExecutorConfig.MaxActiveRequestsPerScan` mechanism, proven against
    a real, multi-parameter scan producing a small, bounded finding
    count under a tight budget.
14. **Does adding this second detector require duplicating any
    HTTP/session/scope logic?** No -- `sqliactive` contains zero HTTP
    client construction, zero cookie/session handling, and zero
    scope-decision code of its own; this is the concrete proof that
    Phase 3.19's architecture generalizes to more than one detector.

13 of 14 answers are an unqualified yes. Question 8's "no" is stated
plainly, with the specific test that proves the boundary rather than
merely asserting it -- not hidden.

## Final report

```
PHASE 3.20 SQL INJECTION ACTIVE DETECTOR

TOTAL TESTS: 1473
PASS: 1473
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 1 (time-based SQLi -- by design, documented in docs/phase-3-20-sqli.md section 4)

SQL INJECTION DETECTOR: PASS
ERROR-BASED DETECTION: PASS
BOOLEAN-DIFFERENTIAL DETECTION: PASS
TIME-BASED SQLI: NOT IMPLEMENTED (by design, documented)
PAYLOAD SAFETY: PASS
FALSE-POSITIVE RESISTANCE: PASS
AUTHENTICATION: PASS
MULTI-IDENTITY: PASS
SCOPE ENFORCEMENT: PASS
RESPONSE COMPARISON: PASS
EVIDENCE: PASS
CORRELATION / RISK: PASS
RESOURCE LIMITS: PASS
DETERMINISM: PASS
LAB: PASS
E2E: PASS
ADVERSARIAL: PASS
REGRESSION: PASS
RACE: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0
(one real, PRE-EXISTING data race -- authenticateIdentity's t.Setenv
called from two goroutines, present since Phase 3.19 and undetected by
its own regression sweep -- was found and fixed during THIS phase's
development, in both the Phase 3.19 and Phase 3.20 concurrent-identity
tests; one test-authoring mistake about confidence-tier expectations
was also self-caught and corrected. Both documented in full; neither
is an issue remaining at delivery.)

PHASE 3.20 VERDICT: PASS
```

## Architectural limitations flagged per task instruction

1. **POST-form parameters do not reach active detection through the
   real crawl-driven pipeline** -- `BuildTargets` never routes
   `Location=="form"` parameters into Targets (unchanged since Phase
   3.18); this phase adds fixtures for it
   (`/sqli/form/vulnerable`) and an explicit test proving the boundary
   (`TestPhase3_20_FormParameter_ReachesActiveDetection`), but does not
   close the gap, since doing so is a `BuildTargets`/crawler-level
   change out of this phase's own stated scope (reuse Phase 3.19's
   architecture, do not modify the engine). A future phase that wants
   this would need to extend `BuildTargets` to route form-location
   parameters (mirroring the JSON extension) AND extend
   `sqliactive.Detect`'s location mapping to use
   `mutation.LocationForm` instead of always assuming JSON for
   `ParameterLocation=="body"`.
2. **Time-based SQLi is not implemented** -- see
   [docs/phase-3-20-sqli.md](phase-3-20-sqli.md) section 4; the shared,
   concurrently-used `Executor` cannot yet reliably distinguish a
   deliberate database delay from ordinary scan-concurrency timing
   jitter.
3. **JSON parameters reach active detection as a proven capability,
   not yet a live-crawl-driven discovery path** -- unchanged from
   Phase 3.19's own identical, already-documented limitation.
4. **`internal/detectors/sqli` was not migrated onto
   `internal/mutation`** -- it keeps its own private `requestURL`/
   `probe` pair, fully covered by its own pre-existing test suite,
   deliberately left untouched (task's own "do not modify working,
   tested code" principle, applied identically to Phase 3.19's
   treatment of `xssreflected`).

Per the task's final rule: no SSRF, command injection, path traversal,
IDOR/BOLA, authorization testing, stored/DOM/blind XSS, mass
assignment, business-logic testing, database dumping, destructive SQL,
OS command execution, automated exploitation, or time-based SQLi was
implemented. Stopping here -- Phase 3.21 is not started.
