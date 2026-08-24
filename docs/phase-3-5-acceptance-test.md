# Phase 3.5 Acceptance Test: IDOR / BOLA Detector

Scope: `internal/detectors/idor` (the detector and its `AuthContext`
abstraction), the 5 new Phase 3 Test Lab query-parameter IDOR fixtures
(`lab/harness_vuln.go`'s `registerIDORAPI`), its registration in
`cmd/scanner/detectors.go`'s `productionRegistry()` (disabled -- see
below), and the integration tests proving it works end to end through
the unmodified Phase 3.1 detection engine. See
[docs/phase-3-5-idor-bola.md](phase-3-5-idor-bola.md) for the full
architecture writeup this test verifies against.

`scanner detectors list` now shows all four real detectors:

```
ID             STATUS    CATEGORY               NAME
xss-reflected  enabled   injection              Reflected XSS Detector
sqli           enabled   injection              SQL Injection Detector
ssrf           disabled  ssrf                   SSRF Detector
idor           disabled  broken_access_control  IDOR / BOLA Detector
```

`idor` is registered but **disabled** -- it requires at least 2
operator-configured `AuthContext` values (synthetic pre-authenticated
identities) plus resource-ownership ground truth, neither of which
this build ships production infrastructure for (see "Authorization
contexts" in [docs/phase-3-5-idor-bola.md](phase-3-5-idor-bola.md));
`scanner detectors list` honestly reflects that rather than silently
omitting it, and its `Prerequisites` metadata field explains why. It
is fully built, tested, and verified against the real Phase 3 Test
Lab's own synthetic multi-user fixtures -- "disabled in production" is
a statement about missing operator configuration, not about the
detector's own completeness.

## What was built

- `internal/detectors/idor/detector.go`: `Detector` implementing
  `detection.Detector` (Phase 3.1, unmodified) -- `Metadata`,
  `Eligible` (object-reference parameter-name heuristic), `Detect`
  (owner baseline + cross-context probing + response validation),
  confidence tiering, aggregated finding construction.
- `internal/detectors/idor/authcontext.go`: `AuthContext` -- the
  minimal, lab-scoped authentication/ownership abstraction (headers
  attached verbatim, ownership operator-supplied, never inferred).
- `internal/detectors/idor/normalize.go`: `normalizeBody`,
  `looksAllowed`, `isResourceSpecific` -- the response-validation
  primitives.
- `lab/harness_vuln.go`: `registerIDORAPI` -- 3 new handlers
  (`/idor/api/resource/vulnerable`, `/idor/api/resource/safe`,
  `/idor/api/resource/generic`) sharing a synthetic `idorAPIResources`
  ground-truth map (`resource-a`→`user-a`, `resource-b`→`user-b`,
  `resource-public`→nobody), plus 8 new crawlable links in the lab's
  index page.
- `lab/ground-truth-vulnerabilities.yaml`: 5 new findings
  (`VULN-IDOR-API-001` positive, 4 negatives) and an updated
  `requires_capability` note on the pre-existing `VULN-IDOR-001`
  explaining why it stays undetectable -- positives 19→20, negatives
  27→31.
- `lab/comparison_test.go`, `lab/phase3_lab_test.go`:
  updated fixture-count assertions (20 positives / 31 negatives).
- `cmd/scanner/detectors.go`: `productionRegistry()` now registers
  `idor.New(nil)`, then disables it alongside `ssrf`.
- Tests: 41 unit/adversarial top-level tests (45 including subtests)
  in `internal/detectors/idor`, 3 integration tests (7 including
  subtests) in `lab/phase3_5_idor_test.go`.

## Ground-truth comparison (integration, against the real lab)

`TestPhase3_5_IDORDetector_MatchesGroundTruth` runs real recon
(`orchestration.Pipeline`, crawling enabled) against the real
`vuln.scanner.test` lab, runs the real `idor` detector -- configured
with the lab's own two synthetic `AuthContext` values (`user-a`
owning `resource-a`, `user-b` owning `resource-b`) -- through the real
`detection.Engine`, and compares persisted findings against every
query-parameter-based `idor`-typed ground-truth fixture (the original
path-based `VULN-IDOR-001`/`VULN-IDOR-NEG-001` pair is excluded from
this comparison -- see "Known limitations"):

| Fixture | Expected | Actual | Result |
|---|---|---|---|
| VULN-IDOR-API-001 (`/idor/api/resource/vulnerable`) | FINDING | FINDING | true_positive |
| VULN-IDOR-API-NEG-001 (`/idor/api/resource/safe`, proper 403) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-IDOR-API-PUBLIC-NEG-001 (`/idor/api/resource/safe`, public resource) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-IDOR-API-INVALID-NEG-001 (`/idor/api/resource/safe`, proper 404) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-IDOR-API-GENERIC-NEG-001 (`/idor/api/resource/generic`, generic 200) | NO FINDING | NO FINDING | (correctly absent) |

```
True Positives:  1
False Positives: 0
False Negatives: 0
Duplicates:      0
```

The engine ran the detector against **all 116 targets** the recon
crawl produced from the whole lab (every vulnerability class's
fixtures, not just IDOR's own), across 14 eligible (detector, target)
pairs, issuing 10 requests total -- passing on the **first attempt**,
with no false-positive class discovered the hard way (unlike Phase
3.3's SQLi) because this detector's design sidesteps that specific bug
class structurally rather than needing to patch around it after the
fact -- see "Applying the Phase 3.3 lesson -- but differently" in
[docs/phase-3-5-idor-bola.md](phase-3-5-idor-bola.md).
`TestPhase3_5_IDORDetector_NegativeFixturesProduceNoFinding`
additionally checks each of the 4 negative fixtures individually
(table-driven, one subtest per fixture ID mapped to its exact
`resource_id`), all passing.

## Revert-and-verify: false-negative and false-positive directions

Per the task's "do not weaken tests to achieve PASS" instruction, both
directions were verified against the working detector by temporarily
reintroducing a specific defect, confirming the affected test fails
for the *expected* reason, then reverting.

1. **False-negative direction**: immediately before the `len(crosses)
   == 0` check in `Detect`, `crosses` was temporarily forced to `nil`
   -- discarding every genuine cross-context observation. Re-running
   `TestPhase3_5_IDORDetector_MatchesGroundTruth` failed exactly as
   expected:
   ```
   0 findings created
   VULN-IDOR-API-001 | FINDING | NO FINDING | false_negative
   True Positives: 0
   False Negatives: 1
   TruePositives = 0, want 1
   FalseNegatives = 1, want 0
   ```
   Confirming the test genuinely catches a detection regression, not
   just a cosmetic one.
2. **False-positive direction**: the `isResourceSpecific` guard on the
   owner's own baseline was bypassed (`if false &&
   !isResourceSpecific(...)`), defeating the "generic response" check.
   Since `/idor/api/resource/generic` always returns the identical
   `{"status":"ok"}` regardless of caller or resource, bypassing the
   guard let that constant response be treated as valid evidence --
   and because the cross-context probe against the same generic
   endpoint returns the *same* constant body, `matchesOwner` evaluated
   true, producing a spurious `critical`/0.9-confidence finding.
   Re-running the same test failed exactly as expected:
   ```
   2 findings created
   (unexpected) (actual: /idor/api/resource/generic) | NO FINDING | FINDING | false_positive
   True Positives: 1
   False Positives: 1
   FalsePositives = 1, want 0
   ```
   Confirming `isResourceSpecific` is genuinely load-bearing against
   the exact false-positive class task section 14 names ("a generic
   success page").

Both defects were reverted; `go build ./...`, the full
`internal/detectors/idor` package suite, and
`go test ./lab/... -race -run TestPhase3_5 -v` were all re-run
and confirmed clean after restoration.

## Acceptance quality gate

| Requirement | Status |
|---|---|
| Positive IDOR fixture detected | PASS (1/1, TruePositives = TotalExpected) |
| Zero false positives on negative fixtures | PASS (across all 116 real recon targets, first attempt) |
| Zero duplicate findings | PASS (Phase 3.1's dedup, reused unmodified) |
| Ownership never inferred, only operator-configured | PASS (see below) |
| Scope enforcement passes | PASS |
| Cancellation (including mid-baseline) passes | PASS |
| Timeout handling passes | PASS |
| Method coverage honestly limited (GET only) | PASS -- `Eligible` never returns true for non-GET |
| False-positive guard (`isResourceSpecific`) proven load-bearing | PASS (see revert-and-verify above) |
| No critical security issues | PASS (see Security review below) |

## Resource ownership (CRITICAL, per the task)

Task section 9 forbids inferring "resource B belongs to another user"
from anything other than controlled test-lab ground truth or supported
metadata. This detector satisfies that by making ownership entirely
**operator-supplied configuration** (`AuthContext.OwnsResourceIDs`),
never derived from crawl data, response content, or identifier shape:

- `TestDetect_UnconfiguredResourceID_Skipped` confirms an identifier no
  configured context claims is never evaluated at all --
  `OutcomeSkipped`, not a guess.
- `TestDetect_PublicResourceWithoutConfiguredOwnership_Skipped` and, at
  the lab level, `VULN-IDOR-API-PUBLIC-NEG-001`, confirm the same
  property specifically for an intentionally-public resource: it's
  silent not because the detector recognizes "this one's public," but
  because nothing ever claims ownership of it.
- `TestAdversarial_SequentialIDsAloneNeverImplyIDOR` and
  `TestAdversarial_UUIDResourceIDsWorkIdentically` directly confirm the
  detector never reasons about identifier *form* (sequential, numeric,
  UUID, opaque) at all -- only configured ownership and observed
  cross-context response behavior matter.

No case was found where the detector reported a finding based on
identifier shape, guessed ownership, or a status code alone.

## Scope enforcement

`TestDetect_OutOfScope_ReturnsErrorWithoutDialing` (unit, denying
validator, zero requests reach the server) and
`TestPhase3_5_IDORDetector_ScopeEnforcementStaysActiveDuringDetection`
(integration -- a real scan job whose `ScopeSnapshot` authorizes only
`vuln.scanner.test`, tested against a manufactured `Target` pointing at
the Phase 2 lab's real, running `scanner.test` host) both confirm
`Executor.RequestCount() == 0` for the denied target and that `Detect`
returns an error rather than silently skipping. No scope bypass was
found. Per the task's explicit instruction, a scope bypass here would
have been an automatic Phase 3.5 failure.

## Adversarial testing (section 32)

Performed only against the controlled Phase 3 Test Lab and synthetic
`httptest` servers -- no external targets, no real applications, no
real accounts, per the task's explicit constraint.

| Scenario | Test | Result |
|---|---|---|
| Sequential IDs alone | `TestAdversarial_SequentialIDsAloneNeverImplyIDOR` | never implies IDOR by itself |
| UUID identifiers | `TestAdversarial_UUIDResourceIDsWorkIdentically` | identical handling to numeric/opaque IDs |
| Invalid resource ID | `TestDetect_InvalidResourceID_404NoFindingViaOwnerBaseline` | no finding (owner baseline itself fails) |
| Same-user resource access | `TestDetect_OwnerAccessingOwnResource_NoFindingAtAll` | no finding -- not a cross-context request at all |
| Cross-user resource access (vulnerable) | `TestDetect_VulnerableCrossAccess_HighConfidenceFinding` | correctly flagged, `critical`/0.9 |
| Public/globally-accessible resource | `TestDetect_PublicResourceWithoutConfiguredOwnership_Skipped`, `VULN-IDOR-API-PUBLIC-NEG-001` | correctly silent |
| Proper 403 | `TestDetect_SecureEndpoint_NoFinding`, `VULN-IDOR-API-NEG-001` | correctly silent |
| Proper 404 | `TestDetect_InvalidResourceID_404NoFindingViaOwnerBaseline`, `VULN-IDOR-API-INVALID-NEG-001` | correctly silent |
| Generic 200 without protected-resource evidence | `TestDetect_GenericResponseNoProtectedResourceEvidence_NoFinding`, `VULN-IDOR-API-GENERIC-NEG-001`, revert-and-verify (false-positive direction) | correctly silent; guard proven load-bearing |
| Missing owner metadata in response | `TestAdversarial_MissingOwnerMetadataInResponse_StillEvaluatesOnPresenceOfID` | still evaluates correctly on identifier presence alone |
| Stale/expired/invalid credential context | `TestDetect_ExpiredOrInvalidCredentialContext_NoFinding` | treated as an ordinary denial |
| Duplicate resources configured to two owners | `TestAdversarial_DuplicateResourcesConfiguredToTwoOwners_UsesFirstMatch` | deterministic, documented first-match behavior, no crash |
| Duplicate requests/findings | `TestDetect_IdenticalFindingsAcrossTwoRunsDeduplicate` | Phase 3.1 dedup collapses them |
| Malformed JSON response | `TestAdversarial_MalformedJSONResponse_NoCrash` | no crash |
| Malformed resource ID in URL | `TestAdversarial_MalformedResourceIDInOriginalURL_NoCrash` | no crash |
| Unusual status codes (204/301/429/503) | `TestAdversarial_UnusualStatusCodes_NoCrashNoFalsePositive` (4 subtests) | no crash, no false positive |
| Out-of-scope target | `TestDetect_OutOfScope_ReturnsErrorWithoutDialing`, `TestPhase3_5_IDORDetector_ScopeEnforcementStaysActiveDuringDetection` | zero requests |
| Cancellation (mid-baseline specifically) | `TestDetect_CancellationDuringBaseline` | terminates correctly, no data race |
| Timeout | `TestDetect_Timeout_ReturnsError` | correct error |
| Connection failure | `TestDetect_ConnectionFailure_ReturnsError` | correct error |
| Redirects | inherited from `Executor`'s `MaxRedirects=0` default, unchanged from every prior detector | scanner never follows |

## Security review (section 33)

- **Authorization-context confusion**: `ownerOf` does a deterministic
  linear scan; `TestAdversarial_DuplicateResourcesConfiguredToTwoOwners_UsesFirstMatch`
  confirms a misconfigured overlap resolves deterministically (first
  match) rather than panicking or behaving unpredictably. This is a
  configuration-correctness responsibility of the operator, documented
  as such.
- **Credential leakage**: `AuthContext.Headers` are attached verbatim
  to outgoing requests only; nothing is logged, persisted into
  `Evidence`, or exposed in any finding -- evidence carries context
  *IDs* (e.g. `"user-b"`), never header values or token contents.
- **Cross-scan credential reuse**: each `Detector` instance is
  constructed once per registry with its own fixed `contexts` slice;
  nothing shares mutable authentication state across scans or
  goroutines (`Detector` holds no mutable state of its own).
- **Scope bypass**: none found -- see "Scope enforcement" above.
- **Accidental external access**: every probe goes through
  `detection.Executor.Do`, the same choke point every prior detector
  uses; `probeAs` never constructs its own `http.Client`.
- **Request amplification**: strictly linear in configured contexts
  (N-1 cross probes + 1 baseline), never combinatorial across
  discovered resources -- see "Request limits" in
  [docs/phase-3-5-idor-bola.md](phase-3-5-idor-bola.md).
- **Authorization-state leakage between findings**: each `Detect` call
  is independent and stateless; a `crossAttempt` from one candidate is
  never carried into another candidate's evaluation.
- **Sensitive response storage**: only a bounded (±80 byte) fragment is
  ever persisted in `Evidence`; full response bodies are read into a
  256KB-capped buffer for in-memory comparison only, never stored.
- **Unsafe redirects**: `MaxRedirects` defaults to `0`, inherited,
  unmodified.
- **Race conditions**: the full suite runs under `-race` throughout
  this phase, including the concurrency test
  (`TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests`, 10
  concurrent candidates) and the cancellation test
  (`TestDetect_CancellationDuringBaseline`, rewritten to use
  `atomic.Int32` rather than a plain counter, avoiding the exact
  data-race class Phase 3.3's analogous test previously required a fix
  for). Zero races detected.

No new security issue was introduced; ownership remains strictly
operator-configured throughout.

## Regression

Full suite, `go test -race -count=1 -v ./...`, run after every change
in this phase (including both revert-and-verify exercises) and again
as the final check:

```
TOTAL TESTS: 679 (456 top-level + 223 subtests)
PASS:        679
FAIL:        0
```

All 23 tested packages report `ok` (`cmd/scanner` and several stub
packages have no tests, by design, same as every prior phase). `gofmt
-l .`, `go build ./...`, and `go vet ./...` are all clean.
`golangci-lint` is not installed on this machine (unchanged from every
prior phase) -- `go vet` is what's available and was run. The CLI
binary was rebuilt (`go build -o bin/scanner ./cmd/scanner`) and
`scanner detectors list` confirmed to show all four registered
detectors with the correct enabled/disabled state.

- **Phase 1 regression**: unchanged packages all pass, no file under
  any of them was touched in this phase.
- **Phase 2 regression**: unchanged, all pass.
- **Phase 3 Test Lab regression**: all original fixture pairs, scope-
  enforcement scenarios, and prior authentication coverage remain
  unchanged and passing; lab changes were purely additive (3 new
  handlers, 8 new crawlable links, 5 new ground-truth entries, updated
  fixture-count assertions from 19/27 to 20/31).
  `TestPhase3Lab_ScanAndCompareAgainstGroundTruth` correctly reports
  the updated 20 expected positives for a recon-only run.
- **Phase 3.1 regression**: `internal/detection` and
  `internal/detection/detectiontest` completely unchanged; all their
  unit and integration tests pass unchanged.
- **Phase 3.2 regression**: `internal/detectors/xssreflected`
  completely unchanged; all its tests pass unchanged.
- **Phase 3.3 regression**: `internal/detectors/sqli` completely
  unchanged; all its tests pass unchanged.
- **Phase 3.4 regression**: `internal/detectors/ssrf` completely
  unchanged; all its tests pass unchanged -- confirming all four real
  detectors coexist in the registry without interfering with each
  other's results.

## Known limitations

Documented in full in
[docs/phase-3-5-idor-bola.md](phase-3-5-idor-bola.md) "Limitations":
GET query parameters only, parameter-name heuristic only (no stronger
recon evidence available yet), path-segment object references remain
permanently undetectable by this or any Phase-3.1-based detector (the
original `VULN-IDOR-001`/`VULN-IDOR-NEG-001` fixture pair), no
production authorization-context infrastructure ships in this build
(by design -- operator-supplied credentials only, never established or
bypassed by the scanner), digit-run-only response normalization,
read-only (GET) IDOR only. None of these caused a missed positive or
an unresolved false positive against the Phase 3 Test Lab's
query-parameter-based fixtures.

## Final report

```
PHASE 3.5 IDOR / BOLA DETECTOR
TOTAL TESTS: 679 (456 top-level + 223 subtests)
PASS: 679
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

TRUE POSITIVES: 1
FALSE POSITIVES: 0
FALSE NEGATIVES: 0
DUPLICATES: 0

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0

PHASE 1 REGRESSION: PASS
PHASE 2 REGRESSION: PASS
PHASE 3 LAB REGRESSION: PASS
PHASE 3.1 REGRESSION: PASS
PHASE 3.2 REGRESSION: PASS
PHASE 3.3 REGRESSION: PASS
PHASE 3.4 REGRESSION: PASS

PHASE 3.5 ADVERSARIAL: PASS

PHASE 3.5 VERDICT: PASS
```

Not proceeding to Phase 3.6, not implementing another detector, not
implementing authentication bypass/privilege escalation/credential
attacks/account takeover/real-world cross-user testing/LLM runtime
functionality, per the task's explicit instruction to stop after this
report.
