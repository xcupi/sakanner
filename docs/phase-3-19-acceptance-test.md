# Phase 3.19 Acceptance Test: Active Request Detection Engine Foundation

This phase establishes the production architecture for active,
mutation-based request detection and proves it with exactly one
detector: reflected XSS. No IDOR/BOLA, authorization testing, SQLi/
SSRF/command-injection/traversal expansion, stored/DOM/blind XSS, mass
assignment, business-logic testing, race-condition detection, or CSRF
detection was implemented. See
[docs/phase-3-19-active-detection.md](phase-3-19-active-detection.md)
section 0 for the full scope discipline this document assumes.

## What was built

- **`internal/detection.Executor`**: gained `ExecuteMutation` (a new,
  additive method wrapping an internal `*mutation.Executor` +
  `mutation.SessionContext`) and `NewExecutorWithSession`. `Do`
  (every existing detector's own call) is unchanged in signature and,
  for an unauthenticated scan, in behavior -- it now ALSO attaches this
  scan's session when one is present, a small, additive fix (not a
  rewrite) that gives every pre-existing detector incidental
  authenticated execution for free.
- **An import-cycle correction**: `internal/mutation` no longer
  imports `internal/detection` (it never should have depended upward
  in the first place) -- `NewRequestFromTarget`/`ToEvidence` moved to
  `internal/detection` as `NewMutationRequest`/`MutationEvidence`.
  Documented in full, including why, in
  [phase-3-19-active-detection.md](phase-3-19-active-detection.md)
  section 2 and in `internal/detection/mutation_bridge.go`'s own doc
  comment.
- **`internal/detection.BuildTargets`**: extended to also emit Targets
  for `Location == "json"`, `Provenance == "REQUEST_INPUT"` parameters
  (`ParameterLocation: "body"`) -- `RESPONSE_FIELD`-provenance JSON
  parameters remain explicitly excluded, preserving task section 18's
  "response field != request parameter" distinction at the one place
  JSON parameters are allowed to become active-detection targets at
  all.
- **`models.Finding.IdentityContext`** (migration `0011`), populated
  automatically by `normalizeFinding` for EVERY detector, never by a
  detector itself.
- **`internal/orchestrator.buildDetectionExecutor`**: now accepts the
  scan's `*auth.Session` and threads a `mutation.SessionContext` into
  the detection-stage executor -- closing the gap where detection-stage
  requests were unconditionally unauthenticated regardless of whether
  the scan itself authenticated.
- **`internal/detectors/xssactive`** (new package): the first active
  detector, ID `xss-reflected-active`, built entirely on
  `mutation.NewRequestFromTarget`-equivalent (`detection.NewMutationRequest`)/
  `mutation.Mutate`/`Executor.ExecuteMutation`/`mutation.Compare`/
  `detection.MutationEvidence` -- zero private HTTP client, zero
  private request construction. Coexists with, and does not modify,
  the pre-existing `xss-reflected` (Phase 3.3).
- **`cmd/scanner/detectors.go`**: registers `xssactive.New()` alongside
  the six existing detectors.
- **`cmd/scanner/scan.go`**: prints the already-computed
  `RequestsIssued` counter (previously computed, never shown).
- **`lab/harness_auth.go`**: new `/search` authenticated reflected-XSS
  fixture. **`lab/harness_vuln.go`**: new `/xss/reflected/json-echo`
  JSON-reflection fixture.
- **Documentation**: `docs/phase-3-19-active-detection.md`
  (architecture, written before implementation), this file.

## Architecture review (task section 1)

Full findings in the architecture doc's own section 1. The two most
consequential: (1) `detection.Executor` had zero session capability,
confirmed by direct code read, not assumed from prior phases' own
documentation of it as a "gap" -- it needed an actual code change, not
just acknowledgment; (2) `BuildTargets` only ever emitted `query`-
location targets, so JSON parameters (even `REQUEST_INPUT`-provenance
ones) structurally could not reach any detector before this phase.

## Design decisions and defects found during development

1. **A real, self-caught import cycle.** Extending `detection.Executor`
   to use `internal/mutation` collided with `internal/mutation`
   already importing `internal/detection` (for `Target`/
   `RequestResponseEvidence`, a Phase 3.17 design choice). Fixed by
   inverting the dependency -- `internal/mutation` now depends on
   nothing in `internal/detection`; the Target/RequestResponseEvidence-
   aware bridge functions moved to `internal/detection` itself. This
   is the correct architecture (`internal/mutation` was always meant
   to be the lower-level package), not a workaround. 8 tests moved
   with the functions (from `internal/mutation` to
   `internal/detection`), all re-verified passing unchanged.
2. **A real test-authoring mistake, self-corrected.** The first
   version of the executor timeout test asserted a timed-out probe
   should be silently reported as `OutcomeNoFinding`. It failed
   immediately: every existing detector (confirmed against
   `internal/detectors/sqli`'s own `probe()`) propagates a network
   error, including a timeout, as a hard `Detect` error -- the
   established, correct convention, since `Engine.Run` already
   records such an error as a `DetectorError` and continues without
   aborting the scan. Fixed by asserting the actually-established
   behavior instead of inventing an inconsistent one for this single
   detector. See architecture doc section 14.5.
3. **`BuildTargets`'s existing test needed splitting, not weakening.**
   `TestBuildTargets_NonQueryLocationParameters_NoTargets` asserted a
   bare JSON parameter (no explicit `Provenance`) produced no target --
   no longer correct, since the storage layer's own established
   default backfills an unset `Provenance` to `"REQUEST_INPUT"` (Phase
   3.18), which now deliberately DOES produce a target. Split into
   three precise tests: form/path parameters still never become
   targets, a `RESPONSE_FIELD` JSON parameter still never does, and a
   `REQUEST_INPUT` JSON parameter now correctly does.
4. **The registered-detector count changed mechanically.** One
   existing e2e test hardcoded "Registered: 6" -- updated to 7, the
   only e2e fallout from adding a 7th detector (verified by running
   the full e2e suite before and after; no other test's exact-count
   assertion was affected, including tests that scan the real vuln lab
   where BOTH `xss-reflected` and `xss-reflected-active` now fire on
   the same target -- every such test uses `strings.Contains`, never
   an exact finding count).
5. **`Do`'s session attachment is additive, not a rewrite.** Rather
   than reimplementing `Do` on top of `mutation.Executor` (which would
   have risked subtle response-shape/behavior differences across all
   six existing detectors), `Do`'s existing safedial-based
   implementation was kept byte-for-byte, with 3 lines added
   (host-pinned jar/header attachment, mirroring
   `auth.Session.NewClient`'s own exact pattern) -- the lowest-risk
   path to "every existing detector incidentally becomes
   authentication-capable."

## Test matrix results

### A. ACTIVE DETECTION ENGINE
`Executor.ExecuteMutation` proven end to end (unit + lab + e2e); no
detector-specific HTTP execution path exists anywhere -- verified by
inspection (`xssactive` contains no `net/http` client construction,
only `mutation.NewRequestFromTarget`(-equivalent)/`Mutate`/
`x.ExecuteMutation`). **PASS**

### B. REQUEST EXECUTION
`ExecuteMutation` delegates entirely to `mutation.Executor.Execute` --
the exact Phase 3.17 scope-safe, session-aware, resource-bounded path,
re-verified under this phase's own adversarial suite (redirect scope
bypass, session non-leak to an out-of-scope host, cancellation,
timeout). **PASS**

### C. MUTATION INTEGRATION
`mutation.NewMutation`/`Mutate`/`Compare` used directly by `xssactive`,
for both query (escaped) and JSON-body (dot-path-ready, though this
phase's own probes are flat) locations; the original request is never
disturbed (`TestMutate_NeverModifiesOriginal`-class guarantee,
unchanged from Phase 3.17, re-exercised by every `Detect` test in this
package). **PASS**

### D. REFLECTED XSS
Five reflection contexts (`none`, `html_encoded`, `exact`, `attribute`,
`javascript`, `json_string` -- six named outcomes) each independently
unit-tested (`reflection_test.go`, 8 tests) and each independently
proven through a real `Detect` call against a real `httptest.Server`
(`detector_test.go`, 10 tests: text/attribute-context positive,
HTML-encoded negative, not-reflected negative, static-decoy
false-positive-resistance negative, JSON-response positive/negative,
denied-scope). **PASS**

### E. AUTHENTICATION
`buildDetectionExecutor` correctly threads a real `*auth.Session` into
`mutation.SessionContext`; proven against the real, authenticated
`/search` lab fixture (`TestPhase3_19_AuthenticatedPositive_FindingWithIdentityContext`)
and through the real CLI binary
(`TestScanCmd_ActiveXSS_AuthenticatedPositive_RealBinary`). **PASS**

### F. MULTI-IDENTITY
Two independent identities each produce their own, correctly-tagged
finding with zero cross-contamination, proven at the lab level
(sequential and TRUE CONCURRENT goroutines,
`TestPhase3_19_IdentityAAndB_IndependentFindingsNoContamination`,
`TestPhase3_19_ConcurrentIdentityScans_NoRaceNoContamination`) and
through the real CLI binary
(`TestScanCmd_ActiveXSS_IdentityAAndB_IndependentScans_RealBinary`,
`TestScanCmd_ActiveXSS_ConcurrentScans_RealBinary`). **PASS**

### G. SCOPE ENFORCEMENT
No new scope-decision code anywhere. Adversarial proof specific to
this detector's own request path: an out-of-scope redirect target's
content never becomes a finding
(`TestDetect_RedirectToOutOfScopeHost_NeverFollowed`), and a session
header never leaks across that same redirect
(`TestDetect_SessionNeverLeaksToOutOfScopeHost`) -- both against
GENUINELY distinct loopback IPs (not the same-host-different-port
mistake corrected in Phase 3.17/3.18). Denied-scope targets are never
dialed at all (`TestDetect_DeniedScope_ErrorsAndNoRequestsIssued`,
hit-count assertion on the target server itself). **PASS**

### H. RESPONSE COMPARISON
`mutation.Compare` used as corroborating detail (folded into
`Observation`), never as the sole basis for a finding -- the PRIMARY
signal is always context-aware reflection classification. Re-verified
unchanged from Phase 3.17's own exhaustive suite; no detector-specific
comparison logic was written. **PASS**

### I. EVIDENCE
`detection.MutationEvidence` (the relocated Phase 3.17 bridge) used
directly -- baseline + context-probe evidence items, exactly mirroring
`internal/detectors/sqli`'s own two-evidence-item convention.
Sensitive-field redaction re-verified via the moved test suite
(`TestMutationEvidence_SensitiveParameterName_ValueRedacted`,
`TestMutationEvidence_SensitiveQueryValueInRequestLine_Redacted`).
Password never appears in a generated report
(`TestScanCmd_ActiveXSS_AuthenticatedPositive_RealBinary`'s own
explicit assertion). **PASS**

### J. CORRELATION
No detector-specific logic exists anywhere in `internal/correlation` --
confirmed by architecture review (section 1), not merely assumed;
`xssactive`'s findings use the identical `models.Finding` shape every
other detector already produces. **PASS**

### K. RISK
Same conclusion for `internal/risk` -- fully generic over
`CanonicalFinding`, confirmed by architecture review. **PASS**

### L. RESOURCE LIMITS
`ExecutorConfig.MaxMutationsPerParameter`/`MaxActiveRequestsPerScan`
mapped directly onto Phase 3.17's own `mutation.Executor` budget
mechanism -- proven centrally enforced, not merely documented
(`TestPhase3_19_ActiveRequestLimit_BoundsRequestsNotUnbounded`: a
budget of 1 total mutation against a real, multi-parameter vuln lab
scan still completes cleanly with a small, bounded finding count, not
an unbounded one). **PASS**

### M. LAB
6 new lab test functions, 2 new minimal fixtures (`/search`,
`/xss/reflected/json-echo`) -- no vulnerability-specific lab logic
beyond what already existed; the pre-existing Account A/B fixture
continues to exist unchanged, no IDOR was implemented or asserted.
Full `lab` suite (116 tests, including every prior phase's own)
re-verified clean. **PASS**

### N. E2E
6 new e2e tests (3 in `e2e_active_xss_test.go`, plus 1 mechanical
count-update fallout fix) against the REAL built binary and the REAL,
isolated lab -- authenticated positive, identity A/B, concurrent scans,
all through `scanner scan` -> `scanner report`. Full `tests/e2e` suite
(81 tests) re-verified clean. **PASS**

### O. ADVERSARIAL (task section 16)

| # | Scenario | Covered by |
|---|---|---|
| 1 | Mutation escaping | Reused, re-verified: Phase 3.17's own exhaustive suite |
| 2 | Malformed JSON | Reused, re-verified: Phase 3.18's own suite; `TestDetect_JSONBodyNoReflection_NoFinding` for this detector's own JSON path |
| 3 | Nested JSON | Reused, re-verified: Phase 3.18's own `mutation.applyJSON` nested-path suite |
| 4 | Duplicate parameters | Reused, re-verified: Phase 3.17/3.18's own suites |
| 5 | Encoded parameters | Reused, re-verified: Phase 3.17/3.18's own suites |
| 6 | Empty parameters | `TestDetect_EmptyParameterValue_NoCrash` |
| 7 | Very large parameters | `TestDetect_VeryLargeResponseBody_BoundedNoCrash` (~800KB response, bounded read) |
| 8 | Out-of-scope mutation | `TestDetect_DeniedScope_ErrorsAndNoRequestsIssued` |
| 9 | Redirect scope bypass | `TestDetect_RedirectToOutOfScopeHost_NeverFollowed` |
| 10 | Authentication failure | Reused, unchanged: `internal/auth`'s own suite |
| 11 | Expired session | Reused, unchanged: Phase 3.15's own suite |
| 12 | Identity A/B isolation | `TestPhase3_19_IdentityAAndB_IndependentFindingsNoContamination` |
| 13 | Concurrent identity scans | `TestPhase3_19_ConcurrentIdentityScans_NoRaceNoContamination`, `TestScanCmd_ActiveXSS_ConcurrentScans_RealBinary` |
| 14 | Cancellation during active request | `TestDetect_ContextCancelled_ReturnsPromptlyNoHang` |
| 15 | Request-limit exhaustion | `TestPhase3_19_ActiveRequestLimit_BoundsRequestsNotUnbounded` |
| 16 | Detector timeout | `TestDetect_ExecutorTimeout_ReportedAsDetectorErrorNotFinding` |
| 17 | Duplicate finding generation | `TestDetect_RepeatedDetect_SameTarget_DeterministicDeduplicatableFindings` (identical dedup-relevant fields across repeated runs -- `Deduplicate`'s own existing key logic, unmodified, handles the rest) |
| 18 | Reflected but non-executable content | `TestDetect_QueryHTMLEncoded_SafeNoFinding` |
| 19 | HTML-encoded reflection | Same as 18 |
| 20 | JSON-only reflection | `TestDetect_JSONBodyReflection_Finding` |

All 20 scenarios: **NO SECURITY BOUNDARY FAILURE. PASS.**

### P. REGRESSION

```
go build ./...                                          -> clean
go vet ./...                                             -> clean
gofmt -l .                                                -> clean (no output)
go test $(go list ./... | grep -v '/tests/e2e') -race     -> ok, 1338 PASS, 0 FAIL (34 packages, +1 for internal/detectors/xssactive)
go test ./tests/e2e/...                                   -> ok, 81 PASS, 0 FAIL
```
Production/lab independence re-verified: physically removed `lab/` and
`tests/`, confirmed `grep -rl "sakanner/lab"` outside `lab/` itself
returns nothing, rebuilt and vetted successfully, restored both,
rebuilt again to confirm. Every existing vulnerability detector's own
test suite (sqli, ssrf, traversal, xssreflected, cmdinjection, idor)
re-verified passing unchanged -- none was touched beyond `Do`'s own
additive session-attachment fix, which changes nothing for an
unauthenticated scan. **PASS**

### Q. RACE

Full repository, every package, `-race -count=1`: clean, zero races
reported, including every new concurrent test this phase added
(concurrent identity scans at both the lab level and, via separate
real subprocesses, the e2e level). **PASS**

## Final architectural validation (task section 18)

1. **Can an active detector reuse the canonical mutation.Request?**
   Yes -- `detection.NewMutationRequest(t)` builds one directly from a
   `Target`; `xssactive` uses nothing else to construct its requests.
2. **Can it execute through the central authenticated executor?** Yes
   -- `Executor.ExecuteMutation`, which is session-aware whenever the
   scan itself authenticated (`buildDetectionExecutor`).
3. **Does every request pass through scope enforcement?** Yes --
   `ExecuteMutation` delegates entirely to `mutation.Executor.Execute`,
   which performs the identical `scope.Validator`/`safedial.Dialer`
   sequence every other execution path in this codebase already uses;
   proven adversarially (redirect, denied-scope target).
4. **Can authenticated crawling feed active detection?** Yes --
   proven end to end against the real `/search` fixture, both in the
   lab and through the real CLI binary.
5. **Can JSON parameters reach active detection?** Yes, with an honest
   caveat: `BuildTargets` now emits a Target for any `REQUEST_INPUT`-
   provenance JSON parameter, and `xssactive` correctly detects
   reflection in a JSON response from one -- proven via a directly-
   persisted parameter (`TestPhase3_19_JSONRequestInputParameter_ReachesActiveDetection`),
   since the crawler still cannot produce a live JSON REQUEST body
   (Phase 3.18's own, unchanged, honestly-documented architectural
   fact) -- this is a proven CAPABILITY, not yet a live-crawl-driven
   discovery path for this specific input shape.
6. **Can identity A and B execute independently?** Yes, proven
   sequentially, concurrently (in-process), and concurrently via
   separate real subprocesses (e2e), with explicit cross-contamination
   checks in every case.
7. **Can evidence identify the exact mutation?** Yes --
   `MutationID`/`Origin` are carried on every `mutation.Request`/
   `Response` and reflected into the evidence's `Parameter`/`Payload`/
   `Observation` fields via `detection.MutationEvidence`.
8. **Can the existing correlation engine consume the finding?** Yes,
   confirmed by architecture review: `internal/correlation` is fully
   generic over `models.Finding`.
9. **Can the existing risk engine score it?** Yes, same conclusion for
   `internal/risk`.
10. **Can the report reproduce the finding without secrets?** Yes --
    proven directly: the authenticated e2e test asserts the real
    account password never appears in the generated markdown report.
11. **Are active-request limits centrally enforced?** Yes --
    `ExecutorConfig.MaxMutationsPerParameter`/`MaxActiveRequestsPerScan`,
    proven against a real, multi-parameter scan producing a small,
    bounded finding count under a tight budget, not an unbounded one.
12. **Can a future detector be added without duplicating HTTP/session
    logic?** Yes -- `xssactive` itself is the proof: it contains zero
    HTTP client construction, zero cookie/session handling, and zero
    scope-decision code of its own.

Every answer is yes; the one honest caveat (question 5) is stated
plainly, not hidden.

## Final report

```
PHASE 3.19 ACTIVE DETECTION ENGINE FOUNDATION

TOTAL TESTS: 1419
PASS: 1419
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

ACTIVE DETECTION ENGINE: PASS
REQUEST EXECUTION: PASS
MUTATION INTEGRATION: PASS
REFLECTED XSS: PASS
AUTHENTICATION: PASS
MULTI-IDENTITY: PASS
SCOPE ENFORCEMENT: PASS
RESPONSE COMPARISON: PASS
EVIDENCE: PASS
CORRELATION: PASS
RISK: PASS
RESOURCE LIMITS: PASS
LAB: PASS
E2E: PASS
ADVERSARIAL: PASS
REGRESSION: PASS
RACE: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0
(one real import-cycle design flaw -- internal/mutation depending
upward on internal/detection -- was found and corrected during THIS
phase's own development, by inverting the dependency to its
architecturally correct direction; one test-authoring mistake about
timeout-handling convention was also self-caught and corrected. Both
documented in full; neither is an issue remaining at delivery.)

PHASE 3.19 VERDICT: PASS
```

## Architectural limitations flagged per task instruction

1. **JSON parameters reach active detection as a proven capability,
   not yet a live-crawl-driven discovery path** -- the crawler still
   cannot produce a live JSON request body (Phase 3.18's own,
   unchanged architectural fact). A future phase that wants a REAL
   crawl to discover a JSON REQUEST_INPUT parameter would need to
   extend crawling itself (e.g. submitting a discovered form
   declaring JSON submission), which remains explicitly out of scope
   here, exactly as it was in Phase 3.18.
2. **`Metadata` gained no `Version`/`RequiredAuthContext`/resource-cost
   field** -- deliberately deferred; no second consumer exists yet to
   justify a specific shape, and guessing one risks getting it wrong
   before a real need clarifies it.
3. **No `--dry-run` CLI mode** -- `RequestsIssued` is now printed
   (previously computed, never shown), which satisfies the immediate
   observability need without inventing a new, separately-scoped CLI
   feature.
4. **The five existing detectors were not migrated onto
   `internal/mutation`** -- each keeps its own private `requestURL`/
   `probe` pair, fully covered by its own pre-existing test suite,
   now incidentally capable of authenticated execution via `Do`'s
   additive fix (a strict improvement, not a rewrite).

Per the task's final rule: no IDOR/BOLA, authorization testing,
SQLi/SSRF/command-injection/traversal expansion, stored/DOM/blind
XSS, mass assignment, business-logic testing, race-condition
detection, or CSRF detection were implemented. Stopping here --
Phase 3.20 is not started.
