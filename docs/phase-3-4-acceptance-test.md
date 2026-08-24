# Phase 3.4 Acceptance Test: SSRF Detector

Scope: `internal/detectors/ssrf` (the detector and its `CallbackClient`
interface), `lab/callback.go` (`SSRFCallbackServer`, the real
local out-of-band recorder), its registration in
`cmd/scanner/detectors.go`'s `productionRegistry()` (disabled -- see
below), the 4 new Phase 3 Test Lab negative fixtures it's verified
against, and the integration tests proving it works end to end through
the unmodified Phase 3.1 detection engine. See
[docs/phase-3-4-ssrf.md](phase-3-4-ssrf.md) for the full architecture
writeup this test verifies against.

`scanner detectors list` now shows all three real detectors:

```
ID             STATUS    CATEGORY   NAME
xss-reflected  enabled   injection  Reflected XSS Detector
sqli           enabled   injection  SQL Injection Detector
ssrf           disabled  ssrf       SSRF Detector
```

`ssrf` is registered but **disabled** -- it requires an
operator-configured, network-reachable out-of-band callback service
this build does not ship (see "Callback architecture" in
[docs/phase-3-4-ssrf.md](phase-3-4-ssrf.md)); `scanner detectors list`
honestly reflects that rather than silently omitting it, and its
`Prerequisites` metadata field explains why. It is fully built, tested,
and verified against the real Phase 3 Test Lab's own callback server
(`lab.SSRFCallbackServer`) -- "disabled in production" is a
statement about missing external infrastructure, not about the
detector's own completeness.

## What was built

- `internal/detectors/ssrf/detector.go`: `Detector` implementing
  `detection.Detector` (Phase 3.1, unmodified) -- `Metadata`,
  `Eligible` (parameter-name heuristic), `Detect` (baseline + callback
  probe + bounded callback poll + behavioral fallback), confidence
  tiering, evidence construction.
- `internal/detectors/ssrf/callback.go`: `CallbackClient` interface +
  `Observation` -- the out-of-band correlation contract.
- `internal/detectors/ssrf/normalize.go`: `normalizeBody`,
  `stripPayload` (the Phase 3.3 false-positive fix, applied here
  proactively from the start), `containsFetchErrorPhrase`.
- `lab/callback.go`: `SSRFCallbackServer` -- a real, local,
  non-forwarding HTTP recorder implementing `ssrf.CallbackClient`,
  wired into `StartWithVulnerabilities` on a new fixed loopback address
  (`127.0.0.23`), exposed as `Lab.SSRFCallback`.
- `lab/harness_vuln.go`: 4 new SSRF negative fixtures
  (`/ssrf/reflect-only`, `/ssrf/store-only`, `/ssrf/client-fetch`,
  `/ssrf/validate-reject`) -- no new positive fixture was needed;
  `/ssrf/vulnerable` (existing since Phase 3) already covers "basic
  SSRF URL fetch through a query parameter" exactly.
- `cmd/scanner/detectors.go`: `productionRegistry()` now registers
  `ssrf.New(nil)`, then disables it.
- `lab/ground-truth-vulnerabilities.yaml`: 4 new negative findings
  (`VULN-SSRF-REFLECT-NEG-001`, `VULN-SSRF-STORE-NEG-001`,
  `VULN-SSRF-CLIENTFETCH-NEG-001`, `VULN-SSRF-VALIDATEREJECT-NEG-001`)
  -- positives unchanged at 19, negatives 23→27.
- `lab/comparison_test.go`, `lab/phase3_lab_test.go`:
  updated fixture-count assertions and added 4 new raw-HTTP-behavior
  subtests for the new fixtures.
- Tests: 43 unit tests (`internal/detectors/ssrf`, including
  `correlation_test.go` and `adversarial_test.go`), 6 integration tests
  against the real Phase 3 lab (3 in `lab/phase3_4_ssrf_test.go`,
  3 callback-security tests in `lab/callback_test.go`).

## Ground-truth comparison (integration, against the real lab)

`TestPhase3_4_SSRFDetector_MatchesGroundTruth` runs real recon
(`orchestration.Pipeline`, crawling enabled) against the real
`vuln.scanner.test` lab, runs the real `ssrf` detector -- wired to the
real, local `SSRFCallbackServer`, not a mock -- through the real
`detection.Engine`, and compares persisted findings against every
`ssrf`-typed ground-truth fixture:

| Fixture | Expected | Actual | Result |
|---|---|---|---|
| VULN-SSRF-001 (`/ssrf/vulnerable`) | FINDING | FINDING | true_positive |
| VULN-SSRF-NEG-001 (`/ssrf/safe`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-SSRF-REFLECT-NEG-001 (`/ssrf/reflect-only`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-SSRF-STORE-NEG-001 (`/ssrf/store-only`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-SSRF-CLIENTFETCH-NEG-001 (`/ssrf/client-fetch`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-SSRF-VALIDATEREJECT-NEG-001 (`/ssrf/validate-reject`) | NO FINDING | NO FINDING | (correctly absent) |

```
True Positives:  1
False Positives: 0
False Negatives: 0
Duplicates:      0
```

The engine ran the detector against **all 105 targets** the recon
crawl produced from the whole lab (every vulnerability class's
fixtures, not just SSRF's own), issuing 12 requests across 6 eligible
(detector, target) pairs -- proving the zero-false-positive result
holds across a realistic, broad target set on the **first attempt**
(unlike Phase 3.3, which found and fixed a real bug; see "Applying the
Phase 3.3 lesson" below for why this one didn't).
`TestPhase3_4_SSRFDetector_NegativeFixturesProduceNoFinding`
additionally checks each of the 5 negative fixtures individually, all
passing.

## Applying the Phase 3.3 lesson proactively

Phase 3.3's SQLi detector found a real false-positive class during its
own adversarial testing: comparing baseline vs. probe response bodies
directly misfires on any endpoint that merely echoes its parameter,
since the two payload strings differ from each other regardless of any
real backend behavior. This detector's `stripPayload` (`normalize.go`)
was built in **from the start**, not discovered the hard way a second
time -- `TestDetect_ReflectedCallbackURLDoesNotCauseFalsePositive` and
`TestAdversarial_URLEncodedEchoOfCallbackURLStillStripped` cover it at
the unit level, and the real-lab integration test's zero-false-positive
result on the first run is the practical confirmation this worked.

## Revert-and-verify: false-negative and false-positive directions

Per the task's "do not weaken tests to achieve PASS" instruction, both
directions were verified against the working detector:

1. **False-negative direction**: the observed-callback branch was
   temporarily forced to always see zero observations. Re-running
   `TestPhase3_4_SSRFDetector_MatchesGroundTruth` failed exactly as
   expected -- not by dropping to zero true positives (the detector's
   behavioral fallback still produced *a* finding for `/ssrf/vulnerable`,
   since its response genuinely differs from baseline), but with
   `actual severity ("medium") does not match ground truth's expected
   severity ("critical")` -- proving the test's severity-match assertion
   catches a confidence-tier regression even when a finding is still
   produced.
2. **False-positive direction**: `Detect` was temporarily forced to
   always return a maximum-confidence finding immediately. Re-running
   the same test failed exactly as expected: `FalsePositives = 5, want
   0` (fired on all 5 other SSRF-related endpoints in the lab).

Both were reverted; the full suite was re-run and confirmed clean after
each.

## Acceptance quality gate

| Requirement | Status |
|---|---|
| Positive SSRF fixture detected | PASS (1/1, TruePositives = TotalExpected) |
| Zero false positives on negative fixtures | PASS (across all 105 real recon targets, first attempt) |
| Zero duplicate findings | PASS (Phase 3.1's dedup, reused unmodified) |
| Scope enforcement passes | PASS (see below -- explicitly distinguished from "the vulnerable app may fetch the callback") |
| Cancellation (including mid-callback-wait) passes | PASS |
| Timeout handling passes | PASS |
| Callback correlation/isolation passes | PASS (unrelated/stale/cross-scan/duplicate/token-collision, all tested) |
| Callback security passes | PASS (never proxies, never forwards -- see below) |
| No critical security issues | PASS (see Security review below) |

## Scope enforcement (CRITICAL, per the task)

The task draws an explicit distinction this detector's design and
tests preserve throughout:

- **The vulnerable application** may perform a server-side request to
  the controlled callback service -- that's the entire premise of
  detection (`/ssrf/vulnerable` doing exactly this is what
  `VULN-SSRF-001`'s true positive proves).
- **The scanner itself** must never actively access an out-of-scope
  destination. `TestDetect_OutOfScope_ReturnsErrorWithoutDialing`
  (unit, denying validator, zero requests reach the server) and
  `TestPhase3_4_SSRFDetector_ScopeEnforcementStaysActiveDuringDetection`
  (integration -- a real scan job whose `ScopeSnapshot` authorizes only
  `vuln.scanner.test`, tested against a manufactured `Target` pointing
  at the Phase 2 lab's real, running `scanner.test` host) both confirm
  `Executor.RequestCount() == 0` for the denied target.
  `TestAdversarial_DangerousOriginalParameterValueNeverDialed` further
  proves the detector never uses a target's *original* (Phase-2-
  discovered) parameter value as a destination -- only its own callback
  URL is ever injected.

No scope bypass was found. Per the task's explicit instruction, a
scope bypass here would have been an automatic Phase 3.4 failure.

## Callback security

`SSRFCallbackServer`'s handler contains **zero outbound network calls**
in its own implementation -- it cannot become an open proxy because
there is no code path that ever dials out.
`TestSSRFCallbackServer_NeverProxiesRegardlessOfInput` sends a request
carrying proxy-shaped headers (`X-Forward-To`, a cloud-metadata-shaped
`X-Proxy-Target`, a spoofed `Location`) and confirms the response is
the identical fixed `200 ok` every request gets, regardless of content.
`TestSSRFCallbackServer_RecordsOnlyNecessaryMetadata` confirms only
method/path/remote-addr/timestamp are ever recorded.

## Adversarial testing (section 28)

Performed only against the controlled lab / synthetic local servers --
no external targets, no internal networks, no cloud metadata, per the
task's explicit constraint.

| Scenario | Test | Result |
|---|---|---|
| URL reflection | `TestDetect_ReflectedCallbackURLDoesNotCauseFalsePositive`, `TestDetect_NoServerSideFetch_NoFinding` | no false positive |
| Token collision (hypothetical) | `TestAdversarial_TokenCollision_StillCorrelatesToTheSharedToken` | correlates correctly |
| Duplicate callbacks | `TestCorrelation_DuplicateCallbacksStillOneFinding` | one finding, not one per callback |
| Stale callbacks | `TestCorrelation_StaleCallbackFromPreviousScanNeverMatchesNewToken` | isolated correctly |
| Delayed callbacks | `TestCorrelation_CallbackArrivesDuringPolling`, `TestCorrelation_CallbackArrivesAfterTimeout` | both paths correct |
| Callback from another scan | `TestCorrelation_CallbackFromAnotherScanIsolated` | isolated correctly |
| Callback from another parameter/token | `TestCorrelation_UnrelatedCallbackDoesNotAffectAnotherToken` | isolated correctly |
| Redirects | inherited from `Executor`'s `MaxRedirects=0` default, unchanged from `sqli`/`xssreflected` | scanner never follows |
| URL encoding | `TestAdversarial_URLEncodedEchoOfCallbackURLStillStripped` | no false positive |
| Malformed URLs | `TestAdversarial_MalformedTargetURLNeverPanics` | no crash |
| Unusual schemes (original parameter value) | `TestAdversarial_DangerousOriginalParameterValueNeverDialed` | never dialed |
| Timeout | `TestDetect_Timeout_ReturnsError` | correct error |
| Cancellation (mid-wait specifically) | `TestDetect_CancellationWhileWaitingForCallback` | terminates immediately |
| Out-of-scope destinations | `TestDetect_OutOfScope_ReturnsErrorWithoutDialing`, `TestPhase3_4_SSRFDetector_ScopeEnforcementStaysActiveDuringDetection` | zero requests |
| Callback service abuse attempts | `TestSSRFCallbackServer_NeverProxiesRegardlessOfInput` | zero effect on behavior |
| Duplicate query parameter | `TestAdversarial_DuplicateQueryParameterInOriginalURL_NoCrash` | no crash |
| Unusual status codes | `TestAdversarial_UnusualStatusCodes_NoCrashNoFalsePositive` (5 subtests) | no crash, no false positive |

## Security review (section 29)

- **SSRF in the scanner itself**: impossible by construction -- every
  request to the target goes through `Executor.Do`, bound to the
  target's own scope-validated host/IP; the only "payload" is the
  detector's own callback URL.
- **Scope bypass**: none found.
- **Open proxy behavior**: the callback server cannot proxy anything --
  no code path in it makes an outbound call.
- **Arbitrary callback forwarding**: not possible -- confirmed directly.
- **Unsafe URL parsing**: `requestURL`/`probe` only ever build a request
  against `t.URL` with the parameter substituted; malformed original
  values are handled without panicking
  (`TestAdversarial_MalformedTargetURLNeverPanics`).
- **Redirect bypass**: `MaxRedirects` defaults to `0`; inherited,
  unmodified.
- **DNS rebinding concerns**: not applicable to this detector
  specifically -- it never resolves a hostname itself; `Executor`/
  `safedial` (unchanged) already dial by literal, pre-resolved IP.
- **Uncontrolled network access**: capped at 2 target requests per
  candidate, always.
- **Resource exhaustion**: `maxBodySample` (256KB) bounds every read;
  bounded callback polling (200ms max); no permanent goroutines.
- **Callback authentication/correlation weaknesses**: correlation is by
  a per-probe `uuid.NewString()` token embedded in the URL path -- see
  "Callback isolation and correlation" in
  [docs/phase-3-4-ssrf.md](phase-3-4-ssrf.md) for the full test
  coverage of this property.

No new network-security bypass was introduced; the scanner remains
incapable of becoming an unrestricted SSRF proxy.

## Regression

Full suite, `go test -race -count=1 -v ./...`, run after every change in
this phase (including both revert-and-verify exercises) and again as
the final check:

```
TOTAL TESTS: 622 (412 top-level + 210 subtests)
PASS:        622
FAIL:        0
```

All 21 tested packages report `ok` (`cmd/scanner` has no tests, by
design, same as every prior phase). `gofmt -l .`, `go build ./...`, and
`go vet ./...` are all clean. `golangci-lint` is not installed on this
machine (unchanged from every prior phase) -- `go vet` is what's
available and was run.

- **Phase 1 regression**: unchanged packages all pass, no file under
  any of them was touched in this phase.
- **Phase 2 regression**: unchanged, all pass.
- **Phase 3 Test Lab regression**: all original fixture pairs, scope-
  enforcement scenarios, and authentication coverage remain unchanged
  and passing; lab changes were purely additive (a new callback server
  component, 4 new SSRF negative fixtures, 4 new ground-truth entries,
  updated fixture-count assertions). `TestPhase3Lab_ScanAndCompareAgainstGroundTruth`
  still correctly reports the unchanged 19 expected positives for a
  recon-only run (Phase 3.4 added no new positive).
- **Phase 3.1 regression**: `internal/detection` and
  `internal/detection/detectiontest` completely unchanged; all their
  unit and integration tests pass unchanged.
- **Phase 3.2 regression**: `internal/detectors/xssreflected` completely
  unchanged; all its tests pass unchanged.
- **Phase 3.3 regression**: `internal/detectors/sqli` completely
  unchanged; all its tests pass unchanged -- confirming all three real
  detectors coexist in the registry without interfering with each
  other's results.

## Known limitations

Documented in full in [docs/phase-3-4-ssrf.md](phase-3-4-ssrf.md)
"Limitations": GET query parameters only, parameter-name heuristic only
(no stronger recon evidence available yet), no production callback
infrastructure ships in this build (by design -- no third-party
infrastructure is ever touched by this project), digit-run-only
response normalization, no redirect-chain-aware detection. None of
these caused a missed positive or an unresolved false positive against
the Phase 3 Test Lab's fixtures.

## Final report

```
PHASE 3.4 SSRF DETECTOR
TOTAL TESTS: 622 (412 top-level + 210 subtests)
PASS: 622
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

PHASE 3.4 ADVERSARIAL: PASS

PHASE 3.4 VERDICT: PASS
```

Not proceeding to Phase 3.5, not implementing another detector, not
implementing exploitation/internal network enumeration/cloud metadata
access/data extraction, per the task's explicit instruction to stop
after this report.
