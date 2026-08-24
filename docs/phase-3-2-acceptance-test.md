# Phase 3.2 Acceptance Test: Reflected XSS Detector

Scope: `internal/detectors/xssreflected` (the detector itself), its
registration in `cmd/scanner/detectors.go`'s `productionRegistry()`,
the 4 new Phase 3 Test Lab fixtures it's verified against, and the
integration tests proving it works end to end through the unmodified
Phase 3.1 detection engine. See
[docs/phase-3-2-reflected-xss.md](phase-3-2-reflected-xss.md) for the
full architecture writeup this test verifies against.

**Real detector.** Unlike Phase 3.1's acceptance test, this one is
about an actual, working reflected-XSS detector — `scanner detectors
list` now shows `xss-reflected  enabled  injection  Reflected XSS
Detector`, verified directly against the built binary.

## What was built

- `internal/detectors/xssreflected/detector.go`: `Detector` implementing
  `detection.Detector` (Phase 3.1, unmodified) — `Metadata`, `Eligible`,
  `Detect` (a 3-probe reflection/context/validation pipeline),
  `classifyContext`, `validationPayload`, evidence construction. No
  change to any Phase 3.1 file (`internal/detection/*`) was needed or
  made.
- `cmd/scanner/detectors.go`: `productionRegistry()` now registers
  `xssreflected.New()` — the registry is no longer empty.
- `lab/harness_vuln.go`: 4 new reflected-XSS fixtures
  (`/xss/reflected/attribute/vulnerable`, `/xss/reflected/attribute/safe`,
  `/xss/reflected/unrelated`, `/xss/reflected/static-decoy`), linked
  from the lab's index page so the crawler discovers them.
- `lab/ground-truth-vulnerabilities.yaml`: 4 new findings
  (`VULN-XSS-REFLECTED-ATTR-001/NEG-001`,
  `VULN-XSS-REFLECTED-UNRELATED-NEG-001`,
  `VULN-XSS-REFLECTED-DECOY-NEG-001`) — positives 17→18, negatives
  17→20, documented inline as "Phase 3.2 additions."
- `lab/comparison_test.go`, `lab/phase3_lab_test.go`:
  updated fixture-count assertions (17→18/20) and added 4 new
  raw-HTTP-behavior subtests for the new fixtures — no existing
  assertion was weakened, only counts corrected to match intentionally
  added fixtures.
- Tests: 27 unit tests (`internal/detectors/xssreflected`), 2
  integration tests against the real Phase 3 lab
  (`lab/phase3_2_reflected_xss_test.go`, one of which itself runs
  4 fixture-scoped subtests).

## Ground-truth comparison (integration, against the real lab)

`TestPhase3_2_ReflectedXSSDetector_MatchesGroundTruth` runs real recon
(`orchestration.Pipeline`, crawling enabled) against the real
`vuln.scanner.test` lab, runs the real `xss-reflected` detector through
the real `detection.Engine`, and compares persisted findings against
every `reflected_xss`-typed ground-truth fixture:

| Fixture | Expected | Actual | Result |
|---|---|---|---|
| VULN-XSS-REFLECTED-001 (`/xss/reflected/vulnerable`) | FINDING | FINDING | true_positive |
| VULN-XSS-REFLECTED-ATTR-001 (`/xss/reflected/attribute/vulnerable`) | FINDING | FINDING | true_positive |
| VULN-XSS-REFLECTED-NEG-001 (`/xss/reflected/safe`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-XSS-REFLECTED-ATTR-NEG-001 (`/xss/reflected/attribute/safe`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-XSS-REFLECTED-UNRELATED-NEG-001 (`/xss/reflected/unrelated`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-XSS-REFLECTED-DECOY-NEG-001 (`/xss/reflected/static-decoy`) | NO FINDING | NO FINDING | (correctly absent) |

```
True Positives:  2
False Positives: 0
False Negatives: 0
Duplicates:      0
```

Every true positive's `AffectedEndpoint`, `Severity` (`high`, matching
ground truth), and evidence presence were additionally asserted to
match ground truth exactly (`EndpointMatches`/`SeverityMatches`/
`EvidenceMatches` all `true`) — not just "a finding of the right type
existed somewhere." `TestPhase3_2_ReflectedXSSDetector_NegativeFixturesProduceNoFinding`
additionally checks each of the 4 negative fixtures individually,
one subtest per fixture, all passing.

The engine also ran the detector against **all 89 targets** the recon
crawl produced from the whole lab (every vulnerability class's
fixtures, not just reflected-XSS's own), issuing 24 requests across 16
eligible (detector, target) pairs — proving the false-positive result
above holds across a realistic, broad target set, not a narrow,
favorable one.

## Revert-and-verify: both directions

Per the task's "do not weaken tests to achieve PASS" instruction, two
deliberate, temporary regressions were introduced and confirmed caught,
then reverted:

1. **False-negative direction**: `Detect` was temporarily forced to
   always return `OutcomeNoFinding`. Re-running
   `TestPhase3_2_ReflectedXSSDetector_MatchesGroundTruth` failed exactly
   as expected: `TruePositives = 0, want 2`, `FalseNegatives = 2, want
   0`.
2. **False-positive direction**: `Detect` was temporarily forced to
   always return a `Finding` when the marker wasn't reflected at all.
   Re-running the same test failed exactly as expected:
   `FalsePositives = 4, want 0` (it fired on 4 unrelated endpoints
   across the lab, not just the 2 reflected-XSS negative fixtures --
   proving the test's assertion generalizes across the whole target
   set, not just the fixtures it was written against).

Both regressions were reverted; the full suite was re-run and confirmed
clean after each revert.

## Acceptance quality gate (section 27)

| Requirement | Status |
|---|---|
| All positive reflected-XSS fixtures detected | PASS (2/2, TruePositives = TotalExpected) |
| Zero false positives on negative fixtures | PASS (FalsePositives = 0, across all 89 real recon targets, not just the negative fixtures) |
| Zero duplicate findings | PASS (Duplicates = 0 -- Phase 3.1's own dedup, reused unmodified) |
| Scope enforcement passes | PASS (see below) |
| Cancellation passes | PASS (`TestDetect_ContextCancellation_ReturnsError`) |
| Timeout handling passes | PASS (`TestDetect_Timeout_ReturnsError`) |
| Phase 1 regression passes | PASS |
| Phase 2 regression passes | PASS |
| Phase 3 Test Lab regression passes | PASS |
| Phase 3.1 regression passes | PASS |
| Race tests pass | PASS (`go test -race -count=1 ./...`, 0 failures) |
| No critical security issues | PASS (see Security review below) |

## Scope enforcement

- `TestDetect_OutOfScope_ReturnsErrorWithoutDialing` (unit): a denying
  scope validator results in an error and zero requests reaching the
  server.
- `TestDetect_OriginalParameterValueCannotRedirectProbesElsewhere`
  (unit): even when a target's *original*, already-discovered parameter
  value looks like a reference to an out-of-scope host
  (`http://external.example/evil`, URL-encoded), every probe still only
  dials the target's own `t.Host`/`t.IP` -- the detector never parses a
  parameter value or response body as something to dial.
- `TestPhase3_2_ReflectedXSSDetector_NegativeFixturesProduceNoFinding`
  (integration): runs the real detector, through the real `Executor`,
  built from the real scan job's `ScopeSnapshot`, against the real lab.
- Redirect-to-out-of-scope and crawler-never-follows-out-of-scope-link
  are properties of the shared `safedial`/crawler layer this detector
  doesn't touch -- covered by Phase 2/3's own existing, unmodified scope
  tests (`TestPhase3Lab_CrawlerNeverFollowsOutOfScopeLinkFromVulnApp`,
  `TestPhase3Lab_OpenRedirectToOutOfScopeIsTruncated`), both still
  passing.

No scope bypass was found. A scope bypass would have been an automatic
failure per the task's explicit instruction; none occurred.

## Error handling

| Scenario | Test | Result |
|---|---|---|
| Connection failure | `TestDetect_ConnectionFailure_ReturnsError` | error returned, no crash |
| Timeout | `TestDetect_Timeout_ReturnsError` | error returned |
| Cancellation | `TestDetect_ContextCancellation_ReturnsError` | error returned |
| Unsupported content type | `TestDetect_NonHTMLContentType_Skipped` | `OutcomeSkipped`, not an error, not a finding |
| Server error status | (no special-cased handling; body still analyzed like any other response) | consistent with "the detector should handle content types, not status codes, specially" |

A single detector error/panic never stopping the rest of a scan is a
Phase 3.1 framework guarantee (`Engine.Run`'s panic recovery and error
isolation), exercised again here in
`TestPhase3_2_ReflectedXSSDetector_MatchesGroundTruth`'s
`summary.Errors` assertion (0 errors on a clean run) and implicitly by
every other detector still running normally alongside a hypothetically
failing one (proven generically in Phase 3.1's own
`TestEngine_DetectorErrorDoesNotStopOtherDetectors`, unchanged).

## Security review (section 23)

- **SSRF**: every probe dials `t.Host`/`t.IP` only, through the shared
  `Executor`; no parameter value or response content is ever parsed as
  a URL to fetch. See "Scope enforcement" above.
- **Scope bypass**: none found (see above).
- **Unsafe redirects**: the detector doesn't build its own `http.Client`
  or configure redirect policy — it inherits `safedial`'s existing,
  unmodified, scope-re-validated-per-hop redirect handling via
  `Executor`.
- **Uncontrolled network requests**: hard-capped at 3 per candidate;
  `TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests` proves
  exactly `candidates × 3` total requests under concurrency, no more.
- **Command injection / arbitrary file access**: not applicable --
  this detector performs only HTTP GET requests and in-memory string
  comparison; it never shells out, opens a file, or evaluates any
  response content as code.
- **Resource exhaustion**: `maxBodySample` (256KB) bounds every
  response read; `Executor`'s shared rate limiter, concurrency
  semaphore, and total-request budget bound aggregate load, unchanged
  from Phase 3.1.
- **Unsafe response processing**: response bodies are only ever
  compared as byte slices (`bytes.Contains`) or scanned for structural
  characters (`classifyContext`) -- never parsed as HTML/JS/templates,
  never evaluated, never deserialized.
- **Oversized response handling**: `io.LimitReader(resp.Body,
  maxBodySample)` caps every read; a response larger than 256KB is
  simply truncated to that bound, not rejected or mishandled.

No new network-security bypass was introduced.

## Regression

Full suite, `go test -race -count=1 -v ./...`, run after every change in
this phase (including both revert-and-verify exercises) and again as
the final check:

```
TOTAL TESTS: 477 (302 top-level + 175 subtests)
PASS:        477
FAIL:        0
```

All 19 tested packages report `ok` (`cmd/scanner` has no tests, by
design, same as every prior phase). `gofmt -l .`, `go build ./...`, and
`go vet ./...` are all clean. `golangci-lint` is not installed on this
machine (unchanged from every prior phase) -- `go vet` is what's
available and was run.

- **Phase 1 regression**: unchanged packages (`internal/config`,
  `internal/storage/sqlite`, `internal/scope`, `internal/target`,
  `internal/dns`, `internal/ports`, `internal/http`,
  `internal/fingerprint`, `internal/logging`, `internal/orchestration`,
  `internal/reporting`, `pkg/models`, `tests/e2e`) all pass, no file
  under any of these was touched in this phase.
- **Phase 2 regression**: `internal/crawler`, `internal/discovery`,
  `internal/endpoints`, `pkg/plugins` unchanged, all pass. `lab`'s
  Phase 2 suite untouched and passing.
- **Phase 3 Test Lab regression**: all of Phase 3's original 17-class
  fixture pairs, scope-enforcement scenarios, and authentication
  coverage remain unchanged and passing; the only lab changes were
  additive (4 new reflected-XSS fixtures, 4 new ground-truth entries,
  updated fixture-count assertions to match). `TestPhase3Lab_ScanAndCompareAgainstGroundTruth`
  still correctly reports zero findings for a recon-only run (updated
  from 17→18 expected, matching the new fixture count) -- this phase
  did not change that test's own logic, only the count it compares
  against.
- **Phase 3.1 regression**: `internal/detection` and
  `internal/detection/detectiontest` completely unchanged; all 45 of
  their unit tests plus the 6 `lab/phase3_1_detection_test.go`
  integration tests (still using the mock detector, unaffected by a
  real detector now also existing) pass unchanged.

## Known limitations

Documented in full in
[docs/phase-3-2-reflected-xss.md](phase-3-2-reflected-xss.md)
"Limitations": GET query parameters only (no POST/form-body parameter
surface exists yet in Phase 2's recon model), two reflection contexts
(`html_text`/`html_attribute` -- script/URL/CSS-context reflection is
reported at reduced confidence via the `unknown` context path rather
than misclassified), no response-content-derived probing, no
session/authentication handling. None of these caused a missed positive
or a false positive against the Phase 3 Test Lab's fixtures -- they are
honestly-scoped absences of *future* capability, not gaps discovered
during this acceptance pass.

## Final report

```
PHASE 3.2 REFLECTED XSS DETECTOR
TOTAL TESTS: 477 (302 top-level + 175 subtests)
PASS: 477
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

TRUE POSITIVES: 2
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

PHASE 3.2 VERDICT: PASS
```

Not proceeding to Phase 3.3, not implementing another detector, per the
task's explicit instruction to stop after this report.
