# Phase 3.1 Acceptance Test: Vulnerability Detection Engine (Core)

Scope: the detection **framework** built in this phase --
`internal/detection` (Detector interface, Registry, Executor, target
selection, finding normalization/deduplication, Engine lifecycle),
`internal/detection/detectiontest` (the Mock test-fixture detector),
CLI integration (`scanner detectors list`, `scanner findings
--detector/--severity`, `scanner findings show`), the `pkg/models.Finding`
field additions and their migration, and the Phase 3 Test Lab
integration tests. See [docs/phase-3-1-detection-engine.md](phase-3-1-detection-engine.md)
for the full architecture writeup this test verifies against.

**No real vulnerability detector was implemented.** Every claim below
about "a detector" refers to `detectiontest.Mock`, a configurable
test-fixture detector that never claims to detect a real vulnerability
(see that package's doc comment) and is never registered in production
(`cmd/scanner/detectors.go`'s `productionRegistry()` registers nothing).
`scanner detectors list` against the built binary prints "no detectors
registered" -- verified directly, not assumed.

## What was built

- `pkg/models.Finding`: six new fields (`DetectorID`, `Host`, `Port`,
  `URL`, `Method`, `Source`), migration `0007_finding_detector_fields.sql`,
  `internal/storage/sqlite/repos.go` updated. All pre-existing Finding
  fields/behavior unchanged.
- `internal/detection`: `Detector` interface (3 methods), `Registry`
  (register/get/list/enable-disable, duplicate-ID rejection), `Executor`
  (the only sanctioned request path -- scope check, rate limit,
  concurrency bound, request budget, safedial-backed dial), `BuildTargets`
  (target selection from Phase 2 recon: HTTPService + Endpoint +
  query-parameter targets), `normalizeFinding`/`Deduplicate`/
  `FilterBySeverity`/`FilterByDetector`, `RequestResponseEvidence`
  (structured evidence), `Engine.Run` (the full lifecycle: selection,
  bounded-concurrent execution, panic/error isolation, cancellation,
  deduplication, persistence).
- `internal/detection/detectiontest`: `Mock`, a configurable Detector
  test fixture (never registered in production).
- `internal/config`: `DetectionConfig` (workers, rate limit, timeout,
  redirects, user agent, request budget) -- defined and validated, ready
  for a future phase's `scanner scan`/`scanner detect` wiring, but **not
  yet wired into any live command**, since zero real detectors exist to
  run today; the field's only current production consumer is
  documentation and tests. This is a deliberate scope boundary, not an
  oversight -- see "Known limitations" below.
- CLI: `scanner detectors list`, `scanner findings --detector/--severity`,
  `scanner findings show <finding-id>`.
- `internal/reporting/markdown.go`: Findings table extended with a
  Detector column; empty-state text no longer claims "not implemented in
  Phase 1" (stale even before this phase).
- Tests: 45 unit tests in `internal/detection` (registry, executor,
  finding normalization/dedup/filtering, target selection, full engine
  lifecycle), 6 integration tests in `lab/phase3_1_detection_test.go`
  running the real `orchestration.Pipeline` + `detection.Engine` against
  the real Phase 3 vuln lab.

## Acceptance criteria

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Detector interface exists | PASS | `internal/detection/detector.go` |
| 2 | Detector registry works | PASS | `TestRegistry_*` (11 tests) |
| 3 | Detector lookup works | PASS | `TestRegistry_RegisterAndGet`, `TestRegistry_GetUnknownIDNotFound` |
| 4 | Detector lifecycle works | PASS | `TestEngine_*` (12 tests) + `TestPhase3_1_*` (6 tests) |
| 5 | Target eligibility works | PASS | `TestEngine_OnlyEligibleDetectorRunsAgainstMatchingTargetKind`, `TestEngine_EligibleFuncFiltersFurtherThanMetadata`, `TestPhase3_1_DetectorSelectionByPrerequisites` |
| 6 | Finding model works | PASS | `TestNormalizeFinding_*` (4 tests), `TestFindingCRUD_WithEvidenceAndReferences` (extended) |
| 7 | Evidence model works | PASS | `TestNormalizeFinding_EvidenceGetsIDsAndFindingID`, `TestEngine_FindingIsNormalizedAndPersisted` |
| 8 | Severity works | PASS | `TestNormalizeFinding_DefaultSeverityFromMetadata`, `TestFilterBySeverity` |
| 9 | Confidence works | PASS | modeled on existing `Finding.Confidence`; exercised in `TestEngine_FindingIsNormalizedAndPersisted` |
| 10 | Deduplication works | PASS | `TestDeduplicate_*` (4 tests), `TestEngine_RerunIsIdempotentViaDeduplication`, `TestPhase3_1_MockDetectorFindingEvidencePersistedAndDeduplicated` |
| 11 | Scope enforcement works | PASS | `TestExecutor_DeniedScopeNeverDials`, `TestEngine_ScopeEnforcedThroughExecutor`, `TestPhase3_1_ScopeEnforcementStaysActiveDuringDetection` (real lab, real ScopeSnapshot) -- see "Scope enforcement regression check" below |
| 12 | Request execution is controlled | PASS | `TestExecutor_*` (7 tests: denial, budget, cancellation, rate limiting, nil-IP rejection) |
| 13 | Concurrency is controlled | PASS | `errgroup.SetLimit`; `TestEngine_ConcurrentExecutionUnderRace`, full suite run under `-race` |
| 14 | Cancellation works | PASS | `TestExecutor_ContextCancellationUnblocksImmediately`, `TestEngine_CancellationStopsBeforeAllTargetsRun`, `TestPhase3_1_CancellationDuringDetection` |
| 15 | Detector errors are isolated | PASS | `TestEngine_DetectorErrorDoesNotStopOtherDetectors`, `TestEngine_DetectorPanicIsRecoveredAndDoesNotCrashTheRun`, `TestPhase3_1_DetectorErrorAndPanicDoNotStopTheRun` |
| 16 | Persistence works | PASS | `TestEngine_FindingIsNormalizedAndPersisted`, storage-layer round trip in `TestFindingCRUD_WithEvidenceAndReferences` |
| 17 | CLI integration works | PASS | manual verification below |
| 18 | Mock detector tests pass | PASS | all of the above use `detectiontest.Mock` |
| 19 | Phase 3 Test Lab integration works | PASS | `lab/phase3_1_detection_test.go`, 6/6 |
| 20 | Phase 1 regression passes | PASS | see Regression below |
| 21 | Phase 2 regression passes | PASS | see Regression below |
| 22 | Phase 3 Test Lab regression passes | PASS | see Regression below |
| 23 | Race tests pass | PASS | `go test -race -count=1 ./...`, 0 failures |
| 24 | Documentation is complete | PASS | `docs/phase-3-1-detection-engine.md`, this document |

## Scope enforcement regression check

Per the task's explicit instruction to "add regression tests
specifically proving this," a revert-and-verify was performed: the
`Executor.Do` scope check was temporarily removed and the suite re-run.

- `TestPhase3_1_ScopeEnforcementStaysActiveDuringDetection` **failed**
  as expected, via `Executor.RequestCount() = 1, want 0` -- proving the
  test actually exercises this code path.
- Interestingly, `TestExecutor_DeniedScopeNeverDials` (the internal unit
  test) still passed even with `Executor`'s own check removed, because
  `safedial.Dialer` (the shared dialer every stage in this codebase
  uses) performs its own independent scope check immediately before the
  real TCP dial -- true defense in depth, confirmed to actually
  function as a second, independent layer rather than being dead code.
- The check was restored; the full suite was re-run and confirmed
  clean.

This means an out-of-scope target is rejected twice, independently, by
two different layers (`Executor.Do` and `safedial.Dialer`) before any
socket is ever opened -- and both layers were proven to matter, not just
assumed to.

## CLI integration -- manual verification

Run against the built binary (`bin/scanner`):

```
$ scanner detectors list
no detectors registered (Phase 3.1 ships the detection framework only -- see docs/phase-3-1-detection-engine.md)

$ scanner findings --scan <job-with-one-seeded-finding>
ID                 SEVERITY  DETECTOR       TITLE                        ENDPOINT                   STATUS
finding-cli-smoke  high      mock-detector  [TEST FIXTURE] mock finding  /xss/reflected/vulnerable  unvalidated

$ scanner findings --scan <job> --severity low
no findings

$ scanner findings --scan <job> --detector mock-detector
ID                 SEVERITY  DETECTOR       TITLE                        ENDPOINT                   STATUS
finding-cli-smoke  high      mock-detector  [TEST FIXTURE] mock finding  /xss/reflected/vulnerable  unvalidated

$ scanner findings show finding-cli-smoke
ID:          finding-cli-smoke
Scan:        job-cli-smoke
Detector:    mock-detector
...
Evidence (1):
  [1] kind=text
      poc content
```

All five commands were executed against a real (throwaway, deleted
afterward) SQLite database seeded with one finding via the storage
layer directly -- not just read from source. `scanner detectors list`
against a completely fresh, empty database was also verified separately
to print the "no detectors registered" message, confirming the honest
empty-registry state.

## Known limitations (documented, not hidden)

- **No real detector exists.** This phase is explicitly scoped to not
  include one; `scanner findings` against a real scan job returns
  exactly what `TestPhase3Lab_ScanAndCompareAgainstGroundTruth`
  (Phase 3 lab, unchanged) already asserts: zero findings.
- **`DetectionConfig` is not yet wired into `scanner scan`.** The
  config section, its defaults, and its validation all exist and are
  tested (`internal/config`), but no CLI command currently constructs an
  `Executor`/`Engine` from it in a live scan -- that wiring belongs with
  the first real detector (Phase 3.x), so it can be exercised with
  something that actually produces findings rather than a permanently
  empty run.
- **Parameter discovery is query-string-only.** `BuildTargets` extracts
  candidate parameters only from query strings already present on
  crawled URLs (`internal/parameters` remains an unimplemented stub from
  Phase 1 scaffolding) -- form field names are not represented as
  parameter targets. Documented in
  `docs/phase-3-1-detection-engine.md` "Target selection."
- **No prerequisite *gating*.** `Metadata.Prerequisites` is
  documentation only (mirrors `requires_capability` in the Phase 3
  ground truth); nothing in the engine currently blocks a detector from
  running if its declared prerequisites aren't met, since Phase 3.1 has
  no capability-negotiation model to check against yet.

None of these limitations affect the framework's own correctness --
they are honestly-scoped absences of *future* functionality, in the
same spirit as the Phase 3 lab's own `requires_capability` fields.

## Regression

Full suite, `go test -race -count=1 -v ./...`, run after every change in
this phase and again as the final check:

```
TOTAL TESTS: 436 (273 top-level + 163 subtests)
PASS:        436
FAIL:        0
```

All 18 tested packages report `ok` (`cmd/scanner` has no tests, by
design -- its logic is thin CLI wiring exercised through the other
packages' tests and the manual verification above).
`gofmt -l .`, `go build ./...`, and `go vet ./...` are all clean.
`golangci-lint` is not installed on this machine (same as every prior
phase in this repo) -- `go vet` is what's available and was run.

- **Phase 1 regression**: `internal/config`, `internal/storage/sqlite`,
  `internal/scope`, `internal/target`, `internal/dns`, `internal/ports`,
  `internal/http`, `internal/fingerprint`, `internal/logging`,
  `internal/orchestration`, `internal/reporting`, `pkg/models`,
  `tests/e2e` -- all unchanged in behavior, all passing. The only
  Phase-1-era files touched were `pkg/models.go` (additive fields
  only), `internal/storage/sqlite/repos.go` (additive columns only),
  and `internal/reporting/markdown.go` (a findings-table column
  addition + a stale empty-state message fix) -- none of Phase 1's own
  tests needed changes, and none were weakened.
- **Phase 2 regression**: `internal/crawler`, `internal/discovery`,
  `internal/endpoints`, `pkg/plugins` -- all unchanged, all passing.
  `lab`'s Phase 2 suite (`harness_test.go`, `lab_test.go`,
  `redirect_test.go`, `groundtruth_test.go`) untouched and passing.
- **Phase 3 Test Lab regression**: `lab`'s Phase 3 suite
  (`phase3_lab_test.go`, `comparison_test.go`, `groundtruth_vuln.go`'s
  loader tests) untouched and passing, including
  `TestPhase3Lab_ScanAndCompareAgainstGroundTruth`, which still
  correctly reports zero actual findings against the lab's 17 expected
  positives -- proving this phase did not accidentally start producing
  fake or premature detection results.

## Final report

```
PHASE 3.1 DETECTION ENGINE
TOTAL TESTS: 436 (273 top-level + 163 subtests)
PASS: 436
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0 (real vulnerability detectors are explicitly out of scope for this phase)

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0

PHASE 1 REGRESSION: PASS
PHASE 2 REGRESSION: PASS
PHASE 3 LAB REGRESSION: PASS

PHASE 3.1 VERDICT: PASS
```

Not proceeding to Phase 3.2 (a real detector implementation) per the
task's explicit instruction to stop after this report.
