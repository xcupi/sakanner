# Phase 3.3 Acceptance Test: SQL Injection Detector

Scope: `internal/detectors/sqli` (the detector itself), its
registration alongside `xssreflected` in `cmd/scanner/detectors.go`'s
`productionRegistry()`, the 4 new Phase 3 Test Lab fixtures it's
verified against, and the integration tests proving it works end to end
through the unmodified Phase 3.1 detection engine. See
[docs/phase-3-3-sqli.md](phase-3-3-sqli.md) for the full architecture
writeup this test verifies against.

`scanner detectors list` now shows both real detectors:

```
ID             STATUS   CATEGORY   NAME
xss-reflected  enabled  injection  Reflected XSS Detector
sqli           enabled  injection  SQL Injection Detector
```

verified directly against the built binary.

## What was built

- `internal/detectors/sqli/detector.go`: `Detector` implementing
  `detection.Detector` (Phase 3.1, unmodified) -- `Metadata`,
  `Eligible`, `Detect` (a 4-probe baseline/error/boolean-true/
  boolean-false sequence), signal correlation, confidence tiering, and
  evidence construction.
- `internal/detectors/sqli/errorpatterns.go`: a maintainable,
  data-driven database-error-signature table covering 5 families
  (MySQL/MariaDB, PostgreSQL, MSSQL, SQLite, Oracle) plus a generic
  fallback.
- `internal/detectors/sqli/normalize.go`: `normalizeBody` (digit-run
  collapsing for response normalization) and `stripPayload` (the fix
  for a real false positive found during this phase -- see
  "Adversarial testing" below).
- `cmd/scanner/detectors.go`: `productionRegistry()` now registers both
  `xssreflected.New()` and `sqli.New()`.
- `lab/harness_vuln.go`: 4 new SQLi fixtures
  (`/sqli/boolean/vulnerable`, `/sqli/boolean/safe`,
  `/sqli/generic-error`, `/sqli/dynamic`), linked from the lab's index
  page.
- `lab/ground-truth-vulnerabilities.yaml`: 4 new findings
  (`VULN-SQLI-BOOLEAN-001/NEG-001`, `VULN-SQLI-GENERIC-ERROR-NEG-001`,
  `VULN-SQLI-DYNAMIC-NEG-001`) -- positives 18→19, negatives 20→23,
  documented inline as "Phase 3.3 additions."
- `lab/comparison_test.go`, `lab/phase3_lab_test.go`:
  updated fixture-count assertions (19/23) and added new
  raw-HTTP-behavior subtests for the new fixtures -- no existing
  assertion was weakened.
- Tests: 59 unit tests (`internal/detectors/sqli`, including a
  dedicated `adversarial_test.go`), 2 integration tests against the
  real Phase 3 lab (`lab/phase3_3_sqli_test.go`, one of which runs
  4 fixture-scoped subtests).

## Ground-truth comparison (integration, against the real lab)

`TestPhase3_3_SQLiDetector_MatchesGroundTruth` runs real recon
(`orchestration.Pipeline`, crawling enabled) against the real
`vuln.scanner.test` lab, runs the real `sqli` detector through the real
`detection.Engine`, and compares persisted findings against every
`sql_injection`-typed ground-truth fixture:

| Fixture | Expected | Actual | Result |
|---|---|---|---|
| VULN-SQLI-001 (`/sqli/vulnerable`) | FINDING | FINDING | true_positive |
| VULN-SQLI-BOOLEAN-001 (`/sqli/boolean/vulnerable`) | FINDING | FINDING | true_positive |
| VULN-SQLI-NEG-001 (`/sqli/safe`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-SQLI-BOOLEAN-NEG-001 (`/sqli/boolean/safe`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-SQLI-GENERIC-ERROR-NEG-001 (`/sqli/generic-error`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-SQLI-DYNAMIC-NEG-001 (`/sqli/dynamic`) | NO FINDING | NO FINDING | (correctly absent) |

```
True Positives:  2
False Positives: 0
False Negatives: 0
Duplicates:      0
```

Every true positive's `AffectedEndpoint`, `Severity` (`critical`,
matching ground truth), and evidence presence were additionally
asserted to match ground truth exactly. The engine ran the detector
against **all 97 targets** the recon crawl produced from the whole lab
(every vulnerability class's fixtures, not just SQLi's own), issuing 80
requests across 20 eligible (detector, target) pairs -- proving the
zero-false-positive result holds across a realistic, broad target set.
`TestPhase3_3_SQLiDetector_NegativeFixturesProduceNoFinding`
additionally checks each of the 4 negative fixtures individually, all
passing.

## Adversarial testing: a real false positive was found and fixed

Per the task's section 33, adversarial testing was performed against
the real, broad target set the Phase 3 lab's recon crawl produces --
**not** narrowed to the SQLi-specific fixtures. This surfaced a genuine
bug before any revert-and-verify exercise was needed:

**The bug**: the detector's first working version compared true/false
probe response bodies directly. Six unrelated endpoints from *other*
vulnerability classes' fixtures -- `/files/lfi/vulnerable` (echoes an
unrecognized `page` value into a "not found" message),
`/redirect/open/vulnerable` (Go's `http.Redirect` auto-generates a body
containing the `Location` value), and all four reflected-XSS
endpoints (`/xss/reflected/vulnerable`, `/xss/reflected/safe`,
`/xss/reflected/attribute/vulnerable`, `/xss/reflected/attribute/safe`)
-- were flagged as SQL injection. In every case, the endpoint simply
**echoes its parameter back**; the true-condition and false-condition
probe *payloads* are different strings from each other, so the
responses differed textually for a reason that had nothing to do with
SQL.

```
Fixture               | Expected   | Actual  | Result
(unexpected)/files/lfi/vulnerable        | NO FINDING | FINDING | false_positive
(unexpected)/redirect/open/vulnerable    | NO FINDING | FINDING | false_positive
(unexpected)/xss/reflected/vulnerable    | NO FINDING | FINDING | false_positive
(unexpected)/xss/reflected/safe          | NO FINDING | FINDING | false_positive
(unexpected)/xss/reflected/attribute/vulnerable | NO FINDING | FINDING | false_positive
(unexpected)/xss/reflected/attribute/safe       | NO FINDING | FINDING | false_positive
True Positives:  2   False Positives: 6   False Negatives: 0   Duplicates: 0
```

**Root cause**: `computeSignals` compared raw (normalized-for-digits-only)
true/false bodies with no accounting for the parameter itself being
reflected into the response.

**Fix**: `stripPayload` (`internal/detectors/sqli/normalize.go`) removes
each body's *own* probe payload (raw, HTML-entity-encoded,
URL-percent-encoded) before comparison. Re-running the exact same test
against the exact same 97-target lab crawl:

```
True Positives:  2   False Positives: 0   False Negatives: 0   Duplicates: 0
```

Per the task's explicit instruction not to weaken tests, this was
**not** fixed by narrowing what the detector is tested against -- the
integration test still runs against the full, unfiltered 97-target
lab crawl.

**Regression coverage added**: `TestComputeSignals_NoFalsePositiveWhenPayloadEchoedRaw`,
`...HTMLEscaped`, `TestComputeSignals_GenuineDifferenceStillDetectedAfterStripping`
(`classify_test.go`), `TestStripPayload_*` (`normalize_test.go`), and
`TestDetect_ReflectedParameterUnrelatedToSQL_NoFinding` (`detector_test.go`)
lock this in at three levels (the pure function, the signal-correlation
step, and end-to-end `Detect`).

**Verified the regression tests actually catch it**: `stripPayload`'s
call sites were temporarily reverted and the suite re-run --
`TestDetect_ReflectedParameterUnrelatedToSQL_NoFinding` failed with
`Outcome = finding, want OutcomeNoFinding`, and
`TestPhase3_3_SQLiDetector_MatchesGroundTruth` failed reproducing the
exact same 6 false positives shown above. The fix was then restored and
the full suite re-confirmed clean.

### Adversarial test coverage (`adversarial_test.go`)

| Scenario | Test | Result |
|---|---|---|
| Malformed, very long parameter value | `TestAdversarial_MalformedVeryLongParameterValue_NoCrash` | no crash, no finding |
| Duplicate query parameter in original URL | `TestAdversarial_DuplicateQueryParameterInOriginalURL_NoCrash` | no crash, no finding |
| Unusual status codes (204/301/403/429/503) | `TestAdversarial_UnusualStatusCodes_NoCrashNoFalsePositive` | no crash, no false positive (5 subtests) |
| Double-encoded parameter value | `TestAdversarial_EncodedParameterValueRoundTrips` | no crash, no finding |
| Empty response body | `TestAdversarial_EmptyResponseBody_NoCrash` | no crash |
| Dynamic/unstable response length | `TestDetect_DynamicContentUnrelatedToParameter_NoFinding` | no false positive |
| Generic error unrelated to probe | `TestDetect_GenericErrorEverywhere_NoFinding`, `TestComputeSignals_ErrorSuppressedWhenBaselineAlreadyErrors` | no false positive |
| Repeated identical scans | `TestDetect_IdenticalFindingsAcrossTwoRunsDeduplicate` | idempotent, no duplicates |
| Reflected parameter (the bug above) | `TestDetect_ReflectedParameterUnrelatedToSQL_NoFinding` + friends | no false positive (post-fix) |
| Timeout / cancellation / out-of-scope | `TestDetect_Timeout_ReturnsError`, `TestDetect_ContextCancellation_ReturnsError`, `TestDetect_CancellationDuringBaseline`, `TestDetect_OutOfScope_ReturnsErrorWithoutDialing` | correct error/isolation behavior |

## Revert-and-verify: false-negative and false-positive directions

In addition to the reflected-parameter bug above (a real defect found
and fixed), the standard two-direction regression check was performed
on the corrected detector:

1. **False-negative direction**: `classify` was temporarily forced to
   always return "no finding." `TestPhase3_3_SQLiDetector_MatchesGroundTruth`
   failed exactly as expected: `TruePositives = 0, want 2`,
   `FalseNegatives = 2, want 0`.
2. **False-positive direction**: `classify` was temporarily forced to
   always return a maximum-confidence finding. Re-running the same test
   failed exactly as expected: `FalsePositives = 18, want 0` (fired on
   18 unrelated endpoints across the full lab).

Both were reverted; the full suite was re-run and confirmed clean after
each.

## Acceptance quality gate (section 27-equivalent)

| Requirement | Status |
|---|---|
| All positive SQLi fixtures detected | PASS (2/2, TruePositives = TotalExpected) |
| Zero false positives on negative fixtures | PASS (after the stripPayload fix; FalsePositives = 0 across all 97 real recon targets) |
| Zero duplicate findings | PASS (Phase 3.1's dedup, reused unmodified) |
| Scope enforcement passes | PASS |
| Timeout/cancellation handling passes | PASS |
| Detector errors isolated | PASS (inherited from Phase 3.1's `Engine.Run`, unchanged) |
| No critical security issues | PASS (see Security review below) |

## Security review (section 29)

- **SSRF / arbitrary network access**: every probe dials `t.Host`/`t.IP`
  only, through the shared `Executor`; no parameter value or response
  content is ever parsed as a URL to fetch.
- **Scope bypass**: none found.
- **Command injection**: not applicable -- this detector never shells
  out or evaluates response content as code.
- **Arbitrary file access**: not applicable -- no filesystem access of
  any kind.
- **Destructive database interaction**: impossible by construction --
  every payload is read-only (`OR`/`AND` boolean conditions, a single
  quote); the detector never sends `DROP`/`DELETE`/`UPDATE`/`INSERT`/
  `ALTER`/`CREATE` or any statement-terminator-based stacked query.
- **Data extraction**: not attempted -- no `UNION SELECT`, no column/
  table enumeration, no attempt to read beyond what the endpoint
  already returns for a normal request.
- **Resource exhaustion**: hard-capped at 4 requests per candidate;
  `TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests` proves
  exactly `candidates × 4` total requests under concurrency.
- **Unsafe/oversized response processing**: `maxBodySample` (256KB)
  bounds every read via `io.LimitReader`; bodies are only ever compared
  as byte slices or scanned for known-phrase substrings -- never parsed,
  evaluated, or deserialized.

No new network-security bypass was introduced.

## Regression

Full suite, `go test -race -count=1 -v ./...`, run after every change in
this phase (including the bug-fix and both revert-and-verify exercises)
and again as the final check:

```
TOTAL TESTS: 555 (363 top-level + 192 subtests)
PASS:        555
FAIL:        0
```

All 20 tested packages report `ok` (`cmd/scanner` has no tests, by
design, same as every prior phase). `gofmt -l .`, `go build ./...`, and
`go vet ./...` are all clean. `golangci-lint` is not installed on this
machine (unchanged from every prior phase) -- `go vet` is what's
available and was run.

- **Phase 1 regression**: unchanged packages all pass, no file under
  any of them was touched in this phase.
- **Phase 2 regression**: `internal/crawler`, `internal/discovery`,
  `internal/endpoints`, `pkg/plugins` unchanged, all pass. `lab`'s
  Phase 2 suite untouched and passing.
- **Phase 3 Test Lab regression**: all of Phase 3's original fixture
  pairs, scope-enforcement scenarios, and authentication coverage
  remain unchanged and passing; lab changes were purely additive (4 new
  SQLi fixtures, 4 new ground-truth entries, updated fixture-count
  assertions). `TestPhase3Lab_ScanAndCompareAgainstGroundTruth` still
  correctly reports zero findings for a recon-only run (19→ now
  reflects the running total including Phase 3.2's addition too).
- **Phase 3.1 regression**: `internal/detection` and
  `internal/detection/detectiontest` completely unchanged; all 45 of
  their unit tests plus the 6 `lab/phase3_1_detection_test.go`
  integration tests (mock detector) pass unchanged.
- **Phase 3.2 regression**: `internal/detectors/xssreflected` completely
  unchanged; all 27 of its unit tests plus both
  `lab/phase3_2_reflected_xss_test.go` integration tests pass
  unchanged -- confirming the two real detectors coexist in the
  registry (`productionRegistry()`) without interfering with each
  other's results.

## Known limitations

Documented in full in [docs/phase-3-3-sqli.md](phase-3-3-sqli.md)
"Limitations": GET query parameters only, digit-run-only response
normalization (non-digit dynamic content is a documented gap), no
time-based blind SQLi detection (no timing-measurement primitive exists
in Phase 3.1 yet), no stacked-query/second-order detection, five
database families plus a generic fallback. None of these caused a
missed positive or an unresolved false positive against the Phase 3
Test Lab's fixtures.

## Final report

```
PHASE 3.3 SQL INJECTION DETECTOR
TOTAL TESTS: 555 (363 top-level + 192 subtests)
PASS: 555
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
PHASE 3.2 REGRESSION: PASS

PHASE 3.3 ADVERSARIAL: PASS

PHASE 3.3 VERDICT: PASS
```

Not proceeding to Phase 3.4, not implementing another detector, not
implementing exploitation/database enumeration/data extraction, per the
task's explicit instruction to stop after this report.
