# Phase 3.6 Acceptance Test: Path Traversal Detector

Scope: `internal/detectors/traversal` (the detector and its
`TraversalCase` known-case abstraction), the 6 new Phase 3 Test Lab
query-parameter path traversal fixtures
(`lab/harness_vuln.go`'s `registerPathTraversalAPI`), its
registration in `cmd/scanner/detectors.go`'s `productionRegistry()`
(disabled -- see below), and the integration tests proving it works end
to end through the unmodified Phase 3.1 detection engine. See
[docs/phase-3-6-path-traversal.md](phase-3-6-path-traversal.md) for the
full architecture writeup this test verifies against.

`scanner detectors list` now shows all five real detectors:

```
ID              STATUS    CATEGORY               NAME
xss-reflected   enabled   injection              Reflected XSS Detector
sqli            enabled   injection              SQL Injection Detector
ssrf            disabled  ssrf                   SSRF Detector
idor            disabled  broken_access_control  IDOR / BOLA Detector
path-traversal  disabled  broken_access_control  Path Traversal Detector
```

`path-traversal` is registered but **disabled** -- it requires at least
1 operator-configured `TraversalCase` (a known relative traversal path
plus its confirmation marker), which this build does not ship
production infrastructure for (see "Known traversal cases" in
[docs/phase-3-6-path-traversal.md](phase-3-6-path-traversal.md));
`scanner detectors list` honestly reflects that rather than silently
omitting it. It is fully built, tested, and verified against the real
Phase 3 Test Lab's own synthetic multi-file fixture -- "disabled in
production" is a statement about missing operator configuration, not
about the detector's own completeness.

## What was built

- `internal/detectors/traversal/detector.go`: `Detector` implementing
  `detection.Detector` (Phase 3.1, unmodified) -- `Metadata`,
  `Eligible` (path-like parameter-name heuristic), `Detect`
  (legitimate-access reference + not-found reference + bounded
  encoded-variant probing), confidence tiering, aggregated finding
  construction.
- `internal/detectors/traversal/cases.go`: `TraversalCase` -- the
  minimal, lab-scoped known-case abstraction (canonical relative path +
  confirmation marker, operator-supplied, never inferred).
- `internal/detectors/traversal/variants.go`: `traversalVariants` --
  derives a small, fixed, deduplicated set of encoded representations
  (raw, dot-encoded, slash-encoded, combined) from a canonical path.
- `internal/detectors/traversal/normalize.go`: `normalizeBody`,
  `stripPayload` (the Phase 3.3 false-positive fix, applied here after
  being caught by this phase's own unit tests -- see "Issue found and
  fixed" below), `looksAllowed`, `containsMarker`.
- `lab/harness_vuln.go`: `registerPathTraversalAPI` -- 6 new
  handlers (`/files/download/vulnerable`, `/safe`, `/sanitized`,
  `/by-id`, `/reflect`, `/generic`) sharing a synthetic `travSynthFS`
  map (`public/index.html`, `public/public-marker.txt` ->
  `PUBLIC_FILE_MARKER`; `protected/secret-marker.txt` ->
  `PATH_TRAVERSAL_SECRET_MARKER`), plus 5 new crawlable links in the
  lab's index page.
- `lab/ground-truth-vulnerabilities.yaml`: 8 new findings
  (`VULN-TRAVERSAL-API-001` positive, 7 negatives) and an updated
  `requires_capability` note on the pre-existing `VULN-TRAVERSAL-001`
  explaining why it stays undetectable -- positives 20->21, negatives
  31->38.
- `lab/comparison_test.go`, `lab/phase3_lab_test.go`:
  updated fixture-count assertions (21 positives / 38 negatives).
- `cmd/scanner/detectors.go`: `productionRegistry()` now registers
  `traversal.New(nil)`, then disables it alongside `ssrf`/`idor`.
- Tests: 51 unit/adversarial top-level tests (55 including subtests) in
  `internal/detectors/traversal`, 3 integration tests (10 including
  subtests) in `lab/phase3_6_traversal_test.go`.

## Ground-truth comparison (integration, against the real lab)

`TestPhase3_6_TraversalDetector_MatchesGroundTruth` runs real recon
(`orchestration.Pipeline`, crawling enabled) against the real
`vuln.scanner.test` lab, runs the real `path-traversal` detector --
configured with the lab's own single synthetic `TraversalCase`
(`../protected/secret-marker.txt` / `PATH_TRAVERSAL_SECRET_MARKER`) --
through the real `detection.Engine`, and compares persisted findings
against every query-parameter-based `path_traversal`-typed ground-truth
fixture (the original path-based `VULN-TRAVERSAL-001`/`-NEG-001` pair
is excluded from this comparison -- see "Known limitations"):

| Fixture | Expected | Actual | Result |
|---|---|---|---|
| VULN-TRAVERSAL-API-001 (`/files/download/vulnerable`) | FINDING | FINDING | true_positive |
| VULN-TRAVERSAL-API-NEG-001 (`/files/download/safe`, proper containment) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-TRAVERSAL-API-SANITIZED-NEG-001 (`/files/download/sanitized`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-TRAVERSAL-API-BYID-NEG-001 (`/files/download/by-id`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-TRAVERSAL-API-REFLECT-NEG-001 (`/files/download/reflect`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-TRAVERSAL-API-GENERIC-NEG-001 (`/files/download/generic`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-TRAVERSAL-API-INVALID-NEG-001 (`/files/download/safe`, 404) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-TRAVERSAL-API-PUBLICTEXT-NEG-001 (`/files/download/safe`, legit access with "../"-shaped body text) | NO FINDING | NO FINDING | (correctly absent) |

```
True Positives:  1
False Positives: 0
False Negatives: 0
Duplicates:      0
```

The engine ran the detector against **all 128 targets** the recon
crawl produced from the whole lab (every vulnerability class's
fixtures, not just path traversal's own), across 6 eligible (detector,
target) pairs, issuing 33 requests total.
`TestPhase3_6_TraversalDetector_NegativeFixturesProduceNoFinding`
additionally checks each of the 7 negative fixtures individually
(table-driven, one subtest per fixture ID mapped to its exact
resource/ID value), all passing.

## Issue found and fixed during this phase

Unlike Phase 3.4 (SSRF) and Phase 3.5 (IDOR), which applied the Phase
3.3 reflected-parameter lesson proactively from the start, this
detector's first draft **did not** -- its MEDIUM-confidence signal
(traversal probe allowed AND differing from a "not found" reference)
compared raw response bodies directly. This was caught immediately by
this phase's own unit test, `TestDetect_ReflectionOnly_NoFinding`,
before any lab integration testing ran:

```
detector_test.go:306: Outcome = finding, want OutcomeNoFinding --
reflecting the input string is not evidence a file was read
```

**Root cause**: the `/files/download/reflect` fixture echoes whatever
value it's given back into its response body
(`"Requested file: <value>"`). The not-found reference probe and a
traversal-variant probe use two DIFFERENT substituted values, so their
echoed text differs from each other trivially -- with no file access of
any kind involved. This is the exact same bug class Phase 3.3's `sqli`
detector discovered via broad adversarial testing.

**Fix**: `stripPayload` (mirroring `ssrf`'s existing implementation)
removes each response's own injected value -- in its raw, HTML-escaped,
and URL-escaped forms -- before the two bodies are compared. A second,
more subtle issue surfaced immediately after: an ENCODED traversal
variant (e.g. `%2e%2e/protected/secret-marker.txt`) is echoed back by a
reflecting endpoint in its **decoded** form (`../protected/secret-marker.txt`,
what `net/http`'s own query parsing produces), not the wire-level
percent-encoded bytes -- stripping the raw wire form alone left the
decoded echo unstripped, still triggering the same false positive for
encoded variants specifically. `decodedForm` (URL-decoding the variant
before stripping) fixes this completely.

**Verification**: `TestDetect_ReflectionOnly_NoFinding` passes after
the fix; the real-lab integration test's zero-false-positive result
(including on `/files/download/reflect`) is the practical confirmation.
This is the class of bug the project's own established discipline
(broad unit + adversarial testing before integration) is specifically
designed to catch early -- and it did.

## Revert-and-verify: false-negative and false-positive directions

Per the task's "do not weaken tests to achieve PASS" instruction, both
directions were verified against the working detector by temporarily
reintroducing a specific defect, confirming the affected test fails for
the expected reason, then reverting.

1. **False-negative direction**: immediately before the
   `len(confirmed) == 0 && len(suspicious) == 0` check in `Detect`,
   both slices were temporarily forced to `nil` -- discarding every
   genuine observation. Re-running
   `TestPhase3_6_TraversalDetector_MatchesGroundTruth` failed exactly
   as expected:
   ```
   0 findings created
   VULN-TRAVERSAL-API-001 | FINDING | NO FINDING | false_negative
   TruePositives = 0, want 1
   FalseNegatives = 1, want 0
   ```
2. **False-positive direction**: the marker-confirmation check was
   bypassed (`if true || containsMarker(...)`), making ANY allowed
   response automatically "confirmed" regardless of content.
   Re-running the same test failed exactly as expected:
   ```
   3 findings created
   VULN-TRAVERSAL-API-001 | FINDING | FINDING | true_positive
   (unexpected) (actual: /files/download/reflect) | NO FINDING | FINDING | false_positive
   (unexpected) (actual: /files/download/generic) | NO FINDING | FINDING | false_positive
   FalsePositives = 2, want 0
   ```
   Confirming `containsMarker` is genuinely load-bearing against
   exactly the two false-positive classes it exists to prevent
   (reflection, and a generic constant response).

Both defects were reverted; `go build ./...`, the full
`internal/detectors/traversal` package suite, and
`go test ./lab/... -race -run TestPhase3_6 -v` were all re-run
and confirmed clean after restoration.

## Acceptance quality gate

| Requirement | Status |
|---|---|
| Positive traversal fixture detected | PASS (1/1, TruePositives = TotalExpected) |
| Zero false positives on negative fixtures | PASS (across all 128 real recon targets) |
| Zero duplicate findings | PASS (Phase 3.1's dedup, reused unmodified) |
| Known cases never inferred, only operator-configured | PASS (see below) |
| Scope enforcement passes | PASS |
| Scanner filesystem safety passes | PASS (see below -- static + behavioral proof) |
| Cancellation (including mid-baseline) passes | PASS |
| Timeout handling passes | PASS |
| Response-size limit passes | PASS (oversized-response test) |
| Method coverage honestly limited (GET only) | PASS -- `Eligible` never returns true for non-GET |
| Reflected-parameter false-positive guard proven load-bearing | PASS (found + fixed during this phase, then confirmed via revert-and-verify) |
| No critical security issues | PASS (see Security review below) |

## Known traversal cases (CRITICAL, per the task)

Task section 9 forbids inferring a vulnerability from anything other
than controlled test-lab ground truth or supported metadata; section 7
further restricts probes to ONLY the synthetic protected file in the
local lab. This detector satisfies both by making the specific
traversal representation and its confirmation marker entirely
**operator-supplied configuration** (`TraversalCase`), never derived
from crawl data, response content, or identifier shape:

- `TestDetect_NoConfiguredCases_Skipped` confirms zero configured cases
  means `Detect` does nothing at all -- `OutcomeSkipped`, not a guess.
- `TestAdversarial_DuplicateResourcesConfiguredToTwoOwners_UsesFirstMatch`-equivalent
  discipline: `TestAdversarial_DuplicateTraversalCasesConfigured_SingleFindingNotInflated`
  confirms a misconfigured operator (the same case listed 3 times)
  still resolves deterministically to one finding, never inflated or
  crashing.
- The detector never reasons about identifier FORM (numeric, UUID,
  path shape) at all -- only whether a configured case's marker was
  actually observed in a response.

No case was found where the detector reported a finding based on a
value it wasn't explicitly told to check for.

## Scanner filesystem safety

`internal/detectors/traversal` operates ENTIRELY over HTTP -- verified
two independent ways:

- **Static**: `TestSourceNeverCallsLocalFileReadAPIs` reads this
  package's own non-test source files and asserts they never contain
  `os.Open(`, `os.OpenFile(`, `os.ReadFile(`, `ioutil.ReadFile(`, or
  `os.Create(` -- a mechanically-enforced guarantee that survives
  future edits.
- **Behavioral**: `TestDetect_MaliciousOriginalValue_NeverTouchesLocalFilesystem`
  runs `Detect` from a temporary, otherwise-empty working directory
  with discovered/configured values shaped like real sensitive local
  paths (`/etc/shadow`, `~/.ssh/id_rsa`, `~/.aws/credentials`,
  `/proc/self/environ`, a Windows SAM path) and confirms the temp
  directory has exactly 0 entries afterward -- proof nothing was
  created, read, or otherwise touched locally.

No local filesystem access of any kind occurs anywhere in this
detector's code path.

## Scope enforcement

`TestDetect_OutOfScope_ReturnsErrorWithoutDialing` (unit) and
`TestPhase3_6_TraversalDetector_ScopeEnforcementStaysActiveDuringDetection`
(integration -- a real scan job whose `ScopeSnapshot` authorizes only
`vuln.scanner.test`, tested against a manufactured `Target` pointing at
the Phase 2 lab's real `scanner.test` host) both confirm zero requests
reach an out-of-scope host. No scope bypass was found; per the task's
explicit instruction, one here would have been an automatic Phase 3.6
failure.

## Adversarial testing (section 30)

Performed only against synthetic `httptest` servers -- no external
targets, no real applications, no real filesystem access, per the
task's explicit constraint.

| Scenario | Test | Result |
|---|---|---|
| Basic `../` traversal | `TestDetect_VulnerableTraversal_HighConfidenceFinding` | correctly flagged, `critical`/0.9 |
| Encoded traversal (naive raw-string blocklist bypass) | `TestAdversarial_EncodingBypassesNaiveRawBlocklist_StillConfirms` | correctly flagged |
| Double-encoded traversal (not effective in this lab) | `TestAdversarial_DoubleEncodedVariantNotEffective_NoFinding` | correctly silent, no false assumption |
| Mixed separators / URL normalization | `TestTraversalVariants_GeneratesExpectedEncodings` | correct variant set generated |
| Traversal string reflection | `TestDetect_ReflectionOnly_NoFinding` | correctly silent (found + fixed this phase) |
| Generic 200 response | `TestDetect_GenericResponse_NoFinding` | correctly silent |
| Secure canonicalization / containment | `TestDetect_SecureCanonicalization_NoFinding` | correctly silent |
| Parameterized/ID-based access | `TestDetect_ByIDLookup_NoFinding` | correctly silent |
| 403 | `TestDetect_403Handling_NoFinding` | correctly silent |
| 404 | `TestDetect_404Handling_NoFinding` | correctly silent |
| Dynamic (digit-based) response | `TestAdversarial_DynamicDigitContent_NoFalsePositive` | correctly silent |
| Duplicate query parameter | `TestAdversarial_DuplicateQueryParameter_NoCrash` | no crash, normal detection unaffected |
| Duplicate probes / duplicate configured cases | `TestAdversarial_DuplicateTraversalCasesConfigured_SingleFindingNotInflated` | one finding, not inflated |
| Timeout | `TestDetect_Timeout_ReturnsError` | correct error |
| Cancellation (mid-baseline specifically) | `TestDetect_CancellationDuringBaseline` | terminates correctly, no data race |
| Oversized response | `TestDetect_OversizedResponse_TruncatedNotUnbounded` | bounded read, no crash |
| Malformed (binary) response | `TestAdversarial_MalformedResponseBody_NoCrash` | no crash |
| Out-of-scope target | `TestDetect_OutOfScope_ReturnsErrorWithoutDialing`, `TestPhase3_6_TraversalDetector_ScopeEnforcementStaysActiveDuringDetection` | zero requests |
| Scanner local filesystem isolation | `TestSourceNeverCallsLocalFileReadAPIs`, `TestDetect_MaliciousOriginalValue_NeverTouchesLocalFilesystem` | zero local access, static + behavioral proof |
| Unusual status codes (204/301/429/503) | `TestAdversarial_UnusualStatusCodes_NoCrashNoFalsePositive` (4 subtests) | no crash, no false positive |

## Security review (section 31)

- **Local filesystem access / arbitrary file reads**: impossible by
  construction -- see "Scanner filesystem safety" above.
- **Path traversal inside the scanner itself**: not applicable -- this
  detector never constructs a local filesystem path from any input.
- **Scope bypass**: none found.
- **Unsafe redirects**: `MaxRedirects` defaults to `0`, inherited,
  unmodified from `Executor`/`safedial`.
- **Response memory exhaustion**: `maxBodySample` (256KB) bounds every
  read via `io.LimitReader`; confirmed directly
  (`TestDetect_OversizedResponse_TruncatedNotUnbounded`).
- **Malformed path handling**: `requestURL`/`probe` build a request
  against `t.URL` with the parameter substituted; malformed original
  values (`TestAdversarial_MalformedResponseBody_NoCrash`, the
  filesystem-safety test's dangerous-path values) are handled without
  panicking.
- **URL decoding inconsistencies**: the exact subject of "Encoding
  handling" and the reflected-parameter bug fixed during this phase --
  `decodedForm` and `stripPayload` together ensure decoded and raw
  representations are compared consistently.
- **Race conditions**: the full suite runs under `-race` throughout
  this phase, including the concurrency test
  (`TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests`, 10
  concurrent candidates) and the cancellation test (using
  `atomic.Int32`, avoiding the exact data-race class Phase 3.3's
  analogous test previously required a fix for). Zero races detected.

No new security issue was introduced; the scanner never becomes
vulnerable to path traversal through target-controlled input, and never
reads from its own filesystem based on any request or response content.

## Regression

Full suite, `go test -race -count=1 -v ./...`, run after every change
in this phase (including both revert-and-verify exercises) and again
as the final check:

```
TOTAL TESTS: 752 (510 top-level + 242 subtests)
PASS:        752
FAIL:        0
```

All 24 tested packages report `ok` (`cmd/scanner` and several stub
packages have no tests, by design, same as every prior phase). `gofmt
-l .`, `go build ./...`, and `go vet ./...` are all clean.
`golangci-lint` is not installed on this machine (unchanged from every
prior phase) -- `go vet` is what's available and was run. The CLI
binary was rebuilt (`go build -o bin/scanner ./cmd/scanner`) and
`scanner detectors list` confirmed to show all five registered
detectors with the correct enabled/disabled state.

- **Phase 1 regression**: unchanged packages all pass, no file under
  any of them was touched in this phase.
- **Phase 2 regression**: unchanged, all pass.
- **Phase 3 Test Lab regression**: all original fixture pairs, scope-
  enforcement scenarios, and prior authentication coverage remain
  unchanged and passing; lab changes were purely additive (6 new
  handlers, 5 new crawlable links, 8 new ground-truth entries, updated
  fixture-count assertions from 20/31 to 21/38).
  `TestPhase3Lab_ScanAndCompareAgainstGroundTruth` correctly reports
  the updated 21 expected positives for a recon-only run.
- **Phase 3.1 regression**: `internal/detection` and
  `internal/detection/detectiontest` completely unchanged; all their
  unit and integration tests pass unchanged.
- **Phase 3.2 regression**: `internal/detectors/xssreflected`
  completely unchanged; all its tests pass unchanged.
- **Phase 3.3 regression**: `internal/detectors/sqli` completely
  unchanged; all its tests pass unchanged.
- **Phase 3.4 regression**: `internal/detectors/ssrf` completely
  unchanged; all its tests pass unchanged.
- **Phase 3.5 regression**: `internal/detectors/idor` completely
  unchanged; all its tests pass unchanged -- confirming all five real
  detectors coexist in the registry without interfering with each
  other's results.

## Known limitations

Documented in full in
[docs/phase-3-6-path-traversal.md](phase-3-6-path-traversal.md)
"Limitations": GET query parameters only, parameter-name heuristic only
(no stronger recon evidence available yet), path-segment object
references remain permanently undetectable by this or any
Phase-3.1-based detector (the original
`VULN-TRAVERSAL-001`/`-NEG-001` fixture pair, for two independent
reasons), no automatic discovery of a real target's protected
resources (known cases only, operator-supplied), no production
`TraversalCase` configuration ships in this build, single-level
encoding only (double-encoding not supported, honestly documented
rather than silently claimed), digit-run-only response normalization,
read-only (GET) traversal only. None of these caused a missed positive
or an unresolved false positive against the Phase 3 Test Lab's
query-parameter-based fixtures.

## Final report

```
PHASE 3.6 PATH TRAVERSAL DETECTOR
TOTAL TESTS: 752 (510 top-level + 242 subtests)
PASS: 752
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
PHASE 3.5 REGRESSION: PASS

PHASE 3.6 ADVERSARIAL: PASS

PHASE 3.6 VERDICT: PASS
```

Not proceeding to Phase 3.7, not implementing another detector, not
reading real OS files, not accessing real credentials or cloud
metadata, not implementing LFI/RFI exploitation, arbitrary file
download, or post-exploitation, per the task's explicit instruction to
stop after this report.
