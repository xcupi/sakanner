# Phase 3.8 Acceptance Test: Finding Correlation & Deduplication Engine

Scope: `internal/correlation` (the canonical finding model, identity
algorithm, evidence merging, confidence/severity consolidation,
grouping, and relationship logic), and
`lab/phase3_8_correlation_test.go` (the integration test proving
real output from all six existing detectors composes correctly with
the new engine). See
[docs/phase-3-8-finding-correlation.md](phase-3-8-finding-correlation.md)
for the full architecture writeup this test verifies against.

This phase touched **no existing code** outside `internal/correlation`
and its own new test files -- no detector, no `pkg/models`, no
`internal/detection`, no `internal/storage`, and no `cmd/scanner` file
was modified. See "Detector independence" in
[docs/phase-3-8-finding-correlation.md](phase-3-8-finding-correlation.md)
for why this was possible and deliberate.

## What was built

- `internal/correlation/model.go`: `CanonicalFinding`, `Asset`,
  `HTTPContext`, `Resource`, `Status`, `EvidenceItem` -- task section
  1's canonical model.
- `internal/correlation/identity.go`: `Identity`, `computeIdentity`,
  and every normalization function (`normalizeHost`, `normalizeMethod`,
  `normalizeVulnerabilityType`, `normalizePath`, `normalizePort`,
  `schemeOf`, `pathOf`, `parameterLocation`, `resourceIdentifier`) --
  task sections 2-4, 17-19.
- `internal/correlation/consolidate.go`: severity/confidence ordinal
  comparison (`maxSeverity`, `minSeverity`, `confidenceTier`),
  `evidenceSignature` (the content-addressed hash "repeated identical
  evidence" is measured against), `evidenceItemsOf`.
- `internal/correlation/engine.go`: `Engine` (`Ingest`/`Findings`/
  `Len`), `bucket`/`group` (the bounded, order-independent
  consolidation state), `IngestResult` -- task sections 5-12, 21, 31-33.
- `internal/correlation/ordering.go`: `sortCanonicalFindings` -- task
  section 22.
- `internal/correlation/group.go`: `GroupByEndpoint` -- task section
  15.
- `internal/correlation/relationship.go`: `Relationships` -- task
  sections 13-14.
- `internal/correlation/fixtures_test.go`: synthetic finding
  generators for all 6 detector types -- task section 23.
- `lab/phase3_8_correlation_test.go`: runs all 6 real detectors
  (configured exactly as each own Phase 3.x lab test configures them)
  against the real lab, feeds the persisted findings through the new
  engine, and verifies the canonical output shape -- task section 34.
- Tests: 103 unit/security/performance/concurrency tests in
  `internal/correlation`, 1 integration test against real detector
  output in `lab`.

## Ground-truth comparison: real detector output through the new engine

`TestPhase3_8_Correlation_RealDetectorOutputProducesCanonicalFindings`
runs real recon and all six real, correctly-configured detectors
through the real `detection.Engine` against the real
`vuln.scanner.test` lab, then feeds every persisted `models.Finding`
into a fresh `correlation.Engine`:

```
Engine.Run: 142 targets considered, 129 detector runs, 8 findings created, 340 requests issued
Correlation: 8 raw findings -> 8 canonical findings
GroupByEndpoint: 8 groups; Relationships: 28 pairs
```

8 raw findings in, 8 canonical findings out -- Phase 3.1's own,
simpler dedup pass had already collapsed everything to exactly one
finding per genuinely distinct vulnerable fixture before persistence,
so this run demonstrates the new engine adds **zero** false merges and
**zero** lost findings when composed after an already-clean pipeline,
which is exactly the "detector independence" property this phase set
out to prove. Per-type counts match the real lab's own ground truth
exactly: `reflected_xss`=2 and `sql_injection`=2 (each of those two
detectors has two genuinely distinct positive fixtures -- the
Phase 3.2/3.3 attribute-context/boolean-only additions -- see those
phases' own acceptance reports), and `ssrf`/`idor`/`path_traversal`/
`command_injection`=1 each.

## Issue found and fixed during this phase

`TestSecurity_ConflictingSeverityAcrossResubmissions_NoCrash` (one of
the malformed/adversarial-input tests task section 30 requires)
uncovered a real bug in `minSeverity`, not just confirmed the absence
of one:

**Root cause**: `rankOfSeverity` returns `-1` for a severity string
outside the 5 recognized values. `minSeverity`'s first draft compared
ranks directly, so an unrecognized/garbage severity (rank `-1`, the
numeric minimum) would incorrectly WIN a "min-within-evidence-
signature-group" comparison against a legitimate `critical` finding
sharing the same evidence -- silently downgrading a real, confirmed
finding's severity down to `info` whenever a malformed resubmission
happened to carry the same evidence content.

**Fix**: `minSeverity` now excludes any unrecognized value (rank < 0)
from ever winning, regardless of which argument position it's in -- a
recognized severity always beats an unrecognized one. See "A
garbage-input bug found and fixed during this phase" in
[docs/phase-3-8-finding-correlation.md](phase-3-8-finding-correlation.md)
for the full before/after trace.

**Verification**: the test passes after the fix; the full package
suite and the real-lab integration test were both re-run clean.

## Revert-and-verify: identity distinctness and deduplication

Per the task's "do not weaken tests to achieve PASS" instruction, both
core invariants were verified by temporarily breaking them and
confirming the correct tests fail for the correct reason, then
reverting.

1. **Distinctness direction**: `Identity.VulnerabilityType` was
   temporarily forced to a constant, collapsing every vulnerability
   type into one identity dimension. `TestEngine_AllSixDetectorTypesProduceCanonicalFindings`
   failed exactly as expected (all 6 types reported "missing"). This
   also surfaced a genuine test-quality bug of its own:
   `TestComputeIdentity_DistinguishesVulnerabilityTypes` initially
   PASSED even with the bypass active, because its two fixtures
   differed in `ParameterLocation` too (the sqli fixture's URL didn't
   contain the overridden parameter name in its query string) --
   meaning the test was accidentally testing two dimensions at once
   instead of isolating vulnerability type. Fixed by aligning both
   fixtures' URLs so every OTHER identity component matches exactly;
   re-running the bypass against the FIXED test then failed correctly:
   ```
   XSS and SQLi on the identical endpoint/parameter must never share a FindingID
   ```
2. **Deduplication direction**: `Identity.Key()` was temporarily
   appended with a monotonically incrementing counter, defeating all
   deduplication. Re-running the full positive-dedup suite failed
   exactly as expected -- all 8 of `TestDedup_*`
   (`ExactDuplicate`, `SameFindingDifferentProbe`,
   `SameFindingDifferentEvidence`, `URLHostnameCaseDifference`,
   `DefaultPortDifference`, `TrailingSlashNormalization`,
   `RepeatedScannerResult`, `DuplicateDetectorOutput`) reported
   `Findings() returned 2 (or more), want 1`.

Both defects were reverted; `go build ./...`, the full
`internal/correlation` package suite, and
`go test ./lab/... -race -run TestPhase3_8 -v` were all re-run
and confirmed clean after restoration.

## Acceptance criteria (task section 35)

| Requirement | Status |
|---|---|
| Exact duplicates collapse | PASS (`TestDedup_ExactDuplicate`, revert-and-verify) |
| Probe duplicates collapse | PASS (`TestDedup_SameFindingDifferentProbe`, `TestEvidenceMerge_DoesNotCreateOneFindingPerProbe`) |
| Evidence merges correctly | PASS (see Evidence merge tests below) |
| Different vulnerability types remain separate | PASS (`TestNoMerge_XSSAndSQLi`, `TestNoMerge_SQLiAndSSRF`, `TestNoMerge_IDORAndPathTraversal`, revert-and-verify) |
| Different endpoints remain separate | PASS (`TestNoMerge_DifferentEndpoints`) |
| Different parameters remain separate | PASS (`TestNoMerge_DifferentParameters`, `TestNoMerge_DifferentParameterLocations`) |
| Scan isolation works | PASS (see Scan isolation below) |
| Resource identity is preserved | PASS (`TestComputeIdentity_ResourceAwareForIDOR`, `TestNoMerge_DifferentResourcesWhereIdentityRequiresDistinction`) |
| Stable finding IDs | PASS (`TestFindingID_StableAcrossRepeatedComputation`, `TestFindingID_LooksLikeAContentHashNotARandomUUID`) |
| Deterministic output | PASS (see Deterministic output below) |
| No data races | PASS (full suite run under `-race`, see Concurrency below) |
| No security issues | PASS (see Security below; 1 issue found and fixed during this phase, not present in the final state) |
| No regression | PASS (see Regression below) |

## Evidence merge tests (task section 26)

| Test | Result |
|---|---|
| Two distinct evidence items both retained | PASS |
| Repeated (byte-identical) evidence appears exactly once | PASS |
| 10 probes against one endpoint/parameter never create 10 findings | PASS |

**EVIDENCE MERGE TESTS: PASS**

## Confidence consolidation (task sections 10, 27)

| Test | Result |
|---|---|
| LOW + LOW → LOW | PASS |
| LOW + MEDIUM → MEDIUM | PASS |
| MEDIUM + HIGH → HIGH | PASS |
| HIGH + HIGH → HIGH | PASS |
| Repeated identical evidence never increases confidence | PASS |
| ...and this holds regardless of arrival order | PASS |
| Independent (non-duplicate) evidence CAN raise confidence to HIGH | PASS |

**CONFIDENCE CONSOLIDATION: PASS**

## Severity consolidation (task sections 11, 28)

| Test | Result |
|---|---|
| LOW + MEDIUM → MEDIUM | PASS |
| MEDIUM + HIGH → HIGH | PASS |
| Repeated identical evidence never upgrades severity | PASS |
| Severity is never arbitrarily upgraded (5x identical LOW stays LOW) | PASS |

**SEVERITY CONSOLIDATION: PASS**

## Scan isolation (task sections 16, 29)

| Test | Result |
|---|---|
| Identical finding, two independent scans → 2 separate canonical findings | PASS |
| Evidence never crosses scan boundaries | PASS |
| Relationships never computed across scans | PASS |
| Holds under 20-way concurrent scan completion (`-race`) | PASS |

**SCAN ISOLATION: PASS**

## Deterministic output (task section 22)

| Test | Result |
|---|---|
| Sorted by host, port, path, vulnerability type, parameter, FindingID | PASS |
| Output order independent of `Ingest` call order | PASS |
| Output order stable across repeated `Findings()` calls | PASS |
| Evidence selection under the eviction cap is deterministic across repeated calls | PASS |
| Real-lab integration run reproduces identical order across repeated `Findings()` calls | PASS |

**DETERMINISTIC OUTPUT: PASS**

## Concurrency (task section 32)

All run under `go test -race`:

| Test | Result |
|---|---|
| Concurrent insert (50 goroutines, distinct identities) -- no lost/duplicated inserts | PASS |
| Concurrent deduplication (200 goroutines, identical identity) -- exactly 1 canonical record | PASS |
| Concurrent evidence merge (100 goroutines, 10 distinct evidence values) -- exactly 10 evidence items, no data race | PASS |
| Concurrent scan completion (20 independent scans) -- no cross-scan leak | PASS |
| Mixed concurrent read (`Findings()`) and write (`Ingest`) | PASS |

**CONCURRENCY: PASS** -- zero data races detected across the entire
package's test suite, including every other test file (all run under
`-race` as standard practice throughout this project).

## Resource exhaustion (task section 31)

| Scenario | Result |
|---|---|
| 5000 distinct findings | ~125ms, all 5000 retained |
| 10000 duplicate submissions of one identity | ~180ms, collapses to 1 finding, evidence bounded |
| 2000 distinct-evidence submissions to one identity | ~77ms, evidence bounded to `maxEvidenceItemsPerFinding` |
| Bucket count stays at 1 regardless of duplicate volume (20000 submissions) | PASS |
| Heap growth under 50000 duplicate submissions | ~4.6KB (well under the 50MB smoke-test ceiling) |

No quadratic behavior observed or expected: `Ingest` is O(1) amortized
per finding (map insert + O(k) bucket work, k = the small, fixed
`maxEvidenceGroupsPerFinding` constant); `Findings()` is O(b log b) in
the number of distinct identities for the final sort.

**RESOURCE EXHAUSTION: PASS**

## Security review (task sections 30-31)

- **Source never touches filesystem/network/shell**: confirmed via
  `go/parser` AST import inspection (not string search) -- this
  package imports neither `os/exec`, `syscall`, `net`, nor `net/http`.
- **Extremely long host/parameter/evidence** (up to 1MB/50MB): no
  crash; evidence content is truncated to `maxEvidenceContentBytes`.
- **Invalid Unicode / null bytes / control characters**: no crash --
  every operation is byte-level string handling, never assumes valid
  UTF-8 structure.
- **Malformed URLs** (empty, garbage, oversized, unparseable): no
  crash -- `schemeOf`/`pathOf`/`parameterLocation`/`resourceIdentifier`
  all degrade to safe defaults on a parse error rather than propagating
  one.
- **Duplicate evidence fields within one finding**: deduplicated
  correctly, same as across findings.
- **Conflicting severity across resubmissions**: the real bug described
  above, found and fixed during this phase.
- **Conflicting confidence values (out of the normal 0-1 range)**: no
  crash; MIN/MAX arithmetic handles them without special-casing (a
  detector-side data-quality concern, out of this phase's scope).
- **Malformed/oversized finding IDs**: no crash -- `Finding.ID` is
  detector bookkeeping the correlation package never reads as part of
  its own `Identity`.
- **A completely empty `models.Finding{}`**: produces one degenerate
  canonical finding, not a panic.
- **2000 findings combining several malformed dimensions at once**: no
  crash.

**SECURITY ISSUES: 0** (1 found, fixed, and verified fixed during this
phase -- see "Issue found and fixed" above; none remain in the final
state).

## Regression

Full suite, `go test -race -count=1 -v ./...`, run after every change
in this phase (including both revert-and-verify exercises) and again
as the final check:

```
TOTAL TESTS: 921 (660 top-level + 261 subtests)
PASS:        921
FAIL:        0
```

All 26 tested packages report `ok` (`cmd/scanner` and several stub
packages have no tests, by design, same as every prior phase). `gofmt
-l .`, `go build ./...`, and `go vet ./...` are all clean.
`golangci-lint` is not installed on this machine (unchanged from every
prior phase) -- `go vet` is what's available and was run. The CLI
binary was rebuilt (`go build -o bin/scanner ./cmd/scanner`) and
`scanner detectors list` confirmed unchanged (this phase touched no
`cmd/scanner` file).

- **Phase 1 regression**: unchanged packages all pass, no file under
  any of them was touched in this phase.
- **Phase 2 regression**: unchanged, all pass.
- **Phase 3 Test Lab regression**: unchanged, all pass -- this phase
  added a new integration test file but modified no existing lab
  fixture, ground-truth entry, or harness function.
- **Phase 3.1 regression**: `internal/detection` completely unchanged;
  all its tests pass unchanged.
- **Phase 3.2 regression**: `internal/detectors/xssreflected`
  completely unchanged; all its tests pass unchanged.
- **Phase 3.3 regression**: `internal/detectors/sqli` completely
  unchanged; all its tests pass unchanged.
- **Phase 3.4 regression**: `internal/detectors/ssrf` completely
  unchanged; all its tests pass unchanged.
- **Phase 3.5 regression**: `internal/detectors/idor` completely
  unchanged; all its tests pass unchanged.
- **Phase 3.6 regression**: `internal/detectors/traversal` completely
  unchanged; all its tests pass unchanged.
- **Phase 3.7 regression**: `internal/detectors/cmdinjection`
  completely unchanged; all its tests pass unchanged -- confirming all
  six real detectors' own test suites are entirely unaffected by the
  new correlation layer's existence.

## Final report

```
TOTAL TESTS: 921 (660 top-level + 261 subtests)
PASS: 921
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

DUPLICATE INPUT CASES: 8 (task section 24's exact positive-dedup scenarios)
DEDUPLICATED SUCCESSFULLY: 8

FALSE MERGES: 0
EXPECTED SEPARATE FINDINGS: 10 (task section 25's exact negative-dedup scenarios, all correctly kept separate)

EVIDENCE MERGE TESTS: PASS
CONFIDENCE CONSOLIDATION: PASS
SEVERITY CONSOLIDATION: PASS
SCAN ISOLATION: PASS
DETERMINISTIC OUTPUT: PASS
CONCURRENCY: PASS
RESOURCE EXHAUSTION: PASS

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
PHASE 3.6 REGRESSION: PASS
PHASE 3.7 REGRESSION: PASS

PHASE 3.8 ADVERSARIAL: PASS

PHASE 3.8 VERDICT: PASS
```

Not proceeding to Phase 3.9, not implementing risk scoring, CVSS, new
vulnerability detectors, exploitation, LLM functionality, or report
generation beyond structured canonical findings, per the task's
explicit instruction to stop after this report.
