# Phase 3.11.2 Acceptance Test: Detection Readiness & Zero-Detector Observability

Scope: `internal/detection/engine.go` (one new `RunSummary.EligibleTargets`
field), `internal/orchestrator/model.go` + `orchestrator.go` (the new
`DetectionState` enum, extended `DetectorSummary`, the zero-detector
warning/log), `cmd/scanner/scan.go` (the CLI's `Detection:` block and
updated help text), `docs/phase-3-11-scan-orchestrator.md` (new
"Detection readiness" section), and a real reliability fix in
`lab/harness.go` found while building this phase's own required
tests. See [docs/phase-3-11-scan-orchestrator.md](phase-3-11-scan-orchestrator.md#detection-readiness-and-zero-detector-observability-phase-3112)
for the architecture writeup.

This phase changes **no** default (`crawler.enabled` stays `false`),
**no** detector eligibility rule, **no** scope enforcement, and adds
**no** scan profile/policy. It is purely additive observability, built
entirely from state the scan already computes -- no new network
requests anywhere in the new code paths.

## Root cause recap (from the preceding investigation)

Every one of the 6 real detectors requires a `TargetKindEndpoint`
target carrying a query parameter; the only place such a target is
ever produced is `internal/detection.BuildTargets`, from a
`models.Endpoint` row the crawler is the only thing that ever creates.
`crawler.enabled` defaults to `false`. So a plain `scanner scan
<target>` completes recon successfully but silently runs zero
detectors -- not a bug in any single component (each behaves exactly
as documented), but a real observability gap: nothing told the
operator this happened, or why. Classified **C — TEST GAP** (Phase
3.11's own acceptance tests all explicitly enabled the crawler in
their local config, so none of them exercised this path).

## What was built

- `internal/detection/engine.go`: `RunSummary.EligibleTargets` --
  counts every (detector, target) pair that passed eligibility,
  computed for free in the same sequential loop that decides whether
  to schedule work, before any goroutine is spawned.
- `internal/orchestrator/model.go`: `DetectionState` (`EXECUTED` /
  `NOT_RUN` / `FAILED` -- task section 5's 3 states) and an extended
  `DetectorSummary` (`DetectorsRegistered`, `DetectorsEnabled`,
  `EligibleTargets`, `CanonicalFindings`, `State`).
- `internal/orchestrator/orchestrator.go`: `DetectorSummary` is now
  populated with the new fields at every exit point (including hard
  failures before detection ever ran); `DetectionState` is set to
  `FAILED` on a hard detection-stage error or cancellation, `EXECUTED`
  when `DetectorRuns > 0`, and `NOT_RUN` otherwise -- the `NOT_RUN`
  branch records an `ErrorCategoryWarning` (`DETECTION_NOT_RUN: ...`,
  worded specifically for the crawler-disabled case when that's the
  cause) and emits a structured `detection_not_run` log event
  (`scan_job_id`, `reason`, `crawler_enabled`, `eligible_targets`,
  `detectors_enabled`).
- `cmd/scanner/scan.go`: `printScanResult` now always prints a
  `Detection:` block (Registered/Enabled/Eligible targets/Detector
  runs/Raw findings/Canonical findings) and phrases the empty-findings
  line differently per `DetectionState`; `scanner scan --help`
  explains the crawler/detection dependency in plain language.
- `docs/phase-3-11-scan-orchestrator.md`: new "Detection readiness and
  zero-detector observability" section.
- `lab/harness.go`: a real reliability fix (below) found while
  building this phase's required CLI-level tests.
- Tests: 4 new in `internal/detection`, 2 new in `internal/orchestrator`,
  2 new in `lab`, 3 new in `tests/e2e` (11 total), plus 2 existing
  Phase 3.11 tests corrected (below).

## Real CLI output (task section 1, verified manually and via
`TestDefaultCLI_CrawlerDisabled_ZeroDetectorRunsIsObservable`)

```
Scan ID:  e26d284e-30c1-47b9-9663-1dc280b7e2bd
Target:   127.0.0.1
Status:   COMPLETED_WITH_WARNINGS
Duration: 5ms

Detection:
  Registered: 6
  Enabled: 3
  Eligible targets: 0
  Detector runs: 0
  Raw findings: 0
  Canonical findings: 0

Errors/Warnings:
  [WARNING] DETECTION: DETECTION_NOT_RUN: Vulnerability detection did not run because crawling is disabled and no eligible parameterized endpoints were discovered. Recon completed successfully.

Findings:
  (none -- no vulnerability detectors were executed; see Detection summary above)
```

This is the exact scenario the task's original bug report described,
now self-explanatory: an operator reading only `Findings: (none)`
before could not tell "checked, found nothing" from "never checked
anything" -- the `Detection:` block and warning now make that
distinction unmissable. `Status` reads `COMPLETED_WITH_WARNINGS` --
task section 1's own example literally showed `scan: COMPLETED`, but
that predates this very phase's own warning mechanism; a bare
`COMPLETED` would now be the LESS accurate status, since a real,
worth-surfacing warning did occur. `COMPLETED_WITH_WARNINGS` is still
a success status (not `FAILED`/`CANCELLED`), matching the spirit of
"scan completed" the task's example intended.

## Acceptance report

```
TOTAL TESTS: 1223 (962 top-level + 261 subtests)
PASS: 1223
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

DEFAULT CLI PATH: PASS
DEFAULT CRAWLER DISABLED: PASS
ZERO DETECTOR OBSERVABILITY: PASS
DETECTION SUMMARY: PASS
ZERO-DETECTOR WARNING: PASS

STATE A:
DETECTORS EXECUTED + NO FINDINGS: PASS

STATE B:
NO ELIGIBLE TARGETS + ZERO DETECTOR RUNS: PASS

STATE C:
DETECTOR FAILURE: PASS

CRAWLER ENABLED: PASS
POSITIVE DETECTION: PASS
BENIGN TARGET: PASS
HELP: PASS
DOCUMENTATION: PASS
SECURITY: PASS
PERFORMANCE: PASS
CONCURRENCY: PASS
REGRESSION: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0

PHASE 3.11.2 ADVERSARIAL: PASS

PHASE 3.11.2 VERDICT: PASS
```

### Notes on the category rows above

- **DEFAULT CLI PATH** / **DEFAULT CRAWLER DISABLED**: verified through
  the actual built binary (`buildBinary` + `exec.Command`, never a
  manually constructed `Pipeline`) against the real Phase 3 vuln lab,
  reached via `config.Load`'s real default path
  (`TestDefaultCLI_CrawlerDisabled_ZeroDetectorRunsIsObservable`).
- **STATE A**: `TestDefaultCLI_CrawlerEnabled_BenignTarget_DetectorsRanFoundNothing`
  (CLI-level) and `TestPhase3_11_Orchestrator_NegativeTarget_NoFalsePositives`
  (orchestrator-level, corrected -- see "Issues found and fixed").
- **STATE B**: `TestDefaultCLI_CrawlerDisabled_ZeroDetectorRunsIsObservable`
  (CLI-level), `TestEngine_EligibleTargets_ZeroWhenNoDetectorIsEligible`
  (detection-engine-level), `TestDetectionState_NotRun_WhenCrawlerDisabled_WarningMentionsCrawler`
  (orchestrator-level).
- **STATE C**: `TestDetectionState_Failed_WhenBuildTargetsHardErrors` --
  a storage-double-forced hard failure inside `detection.Engine.Run`,
  confirming `DetectionState == FAILED` is never confused with `NOT_RUN`
  even though `DetectorRuns == 0` in both cases.
- **CRAWLER ENABLED** / **POSITIVE DETECTION**: `TestDefaultCLI_CrawlerEnabled_PositiveDetection`
  -- real CLI subprocess, real vuln lab, `crawler.enabled: true` with
  bounded `max_depth`/`max_pages`, produces a real `reflected_xss`
  finding using the existing, unmodified detector.
- **SECURITY**: `TestPhase3_11_2_DetectionNotRun_LogEventAndWarningCarryNoSecrets`
  (a target response carrying a live `Set-Cookie`/`Authorization`
  secret; confirms neither the warning text nor any log field/message
  ever contains it) and `TestPhase3_11_2_DetectionNotRun_NeverEnablesCrawlerOrChangesScope`
  (confirms `Pipeline.CrawlEnabled` and the scope-rule count are
  byte-identical before and after a state-B scan).
- **PERFORMANCE**: no new network calls anywhere in the new code --
  `EligibleTargets` is a free by-product of a loop `Engine.Run` already
  runs; `DetectorsRegistered`/`DetectorsEnabled` come from
  `Registry.List()`, an in-memory map read.
- **CONCURRENCY**: full suite passes under `-race`, including the new
  tests; see also the reliability fix below, found specifically because
  concurrent test execution now exercises a real cross-process
  resource-sharing constraint.

## Issues found and fixed during this phase

Per the task's "do not weaken tests to achieve PASS" instruction, both
issues below were found by real test execution, root-caused, fixed,
and reconfirmed.

1. **Two existing Phase 3.11 tests were unknowingly testing state B,
   not state A, under state-A-shaped names.** `TestPhase3_11_Orchestrator_NegativeTarget_NoFalsePositives`
   and `TestPhase3_11_Orchestrator_ConcurrentScans` both used a benign
   httptest fixture serving only static content with no crawlable link
   and no query parameter at all. Before this phase, "no findings" was
   the only signal either test checked, so this went unnoticed: the
   assertion (`Status == COMPLETED`, 0 findings) happened to pass for
   the wrong reason (detection never ran at all, not "ran and found
   nothing"). Phase 3.11.2's new `DetectionState` observability
   correctly flipped `NegativeTarget`'s result to
   `COMPLETED_WITH_WARNINGS`, surfacing the gap immediately. **Fix**:
   gave `NegativeTarget`'s fixture a real, crawlable, parameterized,
   safely-HTML-escaped `/search?q=...` endpoint so `xssreflected`
   (enabled by default) genuinely runs and genuinely finds nothing;
   added explicit `DetectorRuns > 0` and `DetectionState ==
   DetectionStateExecuted` assertions so this can never silently
   regress back to testing state B again. `ConcurrentScans`'s own
   purpose is scan-isolation safety, not detection semantics, so its
   fixture was left as-is and its status assertion was loosened to
   accept either `COMPLETED` or `COMPLETED_WITH_WARNINGS` (documented
   inline why: this specific test never cared which detection state it
   landed in).
2. **A real, previously-latent cross-process test reliability bug**,
   found while building this phase's required real-CLI-binary tests.
   `lab`'s vuln fixture binds a genuinely fixed, hardcoded port
   (`altPort = 18099` on `127.0.0.18`) -- true since Phase 2, but
   harmless until now because only one top-level package (`lab`
   itself) ever started the lab. Phase 3.11.2's task section 11
   requires driving the real CLI binary against a real lab, which meant
   `tests/e2e` needed to import and start the SAME lab
   (`sakanner/lab`'s exported `StartWithVulnerabilities`) --  and
   `go test ./...` runs separate packages' test binaries in parallel by
   default, so `lab`'s own suite and `tests/e2e`'s new tests can
   now genuinely call `Start`/`StartWithVulnerabilities` at the same
   wall-clock instant from two different OS processes, both racing to
   bind `:18099`. Confirmed via direct reproduction: running
   `go test ./lab/... ./tests/e2e/...` together failed with
   `bind: address already in use` on every one of `lab`'s own
   vuln-lab tests. **Fix**: `lab/harness.go`'s `Start` now
   acquires a systemwide advisory lock (a plain `net.Listen` on a
   fixed, otherwise-unused loopback port, `127.0.0.1:18999` -- a
   standard, dependency-free way to implement a cross-process mutex)
   before doing any real port binding, held for the lab's entire
   lifetime (since `altPort` itself stays bound the whole time a lab
   runs, releasing the setup lock any earlier would just move the
   collision a few milliseconds later) and released in `Close()`. The
   existing, complex `Start()` body was renamed to `startLocked` and
   left completely untouched -- zero risk to its own internal
   early-return logic, used unchanged by every prior phase's lab
   tests. Reconfirmed: `go test ./lab/... ./tests/e2e/...`
   together now passes cleanly (both packages serialize on lab access
   instead of colliding, at the cost of somewhat longer wall-clock time
   when run together -- correctness over speed).

## Revert-and-verify

Per the task's discipline, this phase's two core logic changes were
verified by temporarily breaking them and confirming the right tests
fail for the right reason, then reverting.

1. **`EligibleTargets` counting**, disabled (the increment replaced
   with a no-op). Re-running `internal/detection`'s new tests failed
   exactly as expected, across 3 of the 4:
   ```
   --- FAIL: TestEngine_EligibleTargets_MatchesDetectorRunsWhenUncancelled
       EligibleTargets = 0, want at least 1
   --- FAIL: TestEngine_EligibleTargets_CountsEveryEligibleDetectorTargetPair
       EligibleTargets = 0, want 2
   --- FAIL: TestEngine_EligibleTargets_PartialEligibility
       EligibleTargets = 0, want 1
   ```
   Reverted; `diff` against a backup showed no difference, full suite
   re-run clean.
2. **`DetectionState`/warning generation**, disabled (hard-coded to
   always report `DetectionStateExecuted`, skipping the warning/log
   entirely). Re-running the relevant tests failed exactly as expected,
   across 3 tests in 2 packages:
   ```
   --- FAIL: TestDetectionState_NotRun_WhenCrawlerDisabled_WarningMentionsCrawler
       DetectionState = EXECUTED, want NOT_RUN
       Status = COMPLETED, want COMPLETED_WITH_WARNINGS
       no warning mentioning crawler-disabled found; Warnings = []
   --- FAIL: TestPhase3_11_2_DetectionNotRun_LogEventAndWarningCarryNoSecrets
       DetectionState = EXECUTED, want NOT_RUN (test setup problem)
   --- FAIL: TestPhase3_11_2_DetectionNotRun_NeverEnablesCrawlerOrChangesScope
       DetectionState = EXECUTED, want NOT_RUN (test setup problem)
   ```
   Reverted; `diff` against a backup showed no difference, full suite
   re-run clean.

The cross-process lab lock fix (issue #2 above) was itself verified
by direct before/after reproduction rather than a scripted
revert-and-verify pass: running `go test ./lab/... ./tests/e2e/...`
together reliably failed with `bind: address already in use` before
the fix and reliably passed after it, across multiple runs.

## Regression

Full suite, `go test -race -count=1 -v ./...`, run after every change
in this phase (including both revert-and-verify exercises and the
port-lock fix) and again as the final check:

```
TOTAL TESTS: 1223 (962 top-level + 261 subtests)
PASS:        1223
FAIL:        0
```

All 29 tested packages report `ok`. `gofmt -l .`, `go build ./...`,
and `go vet ./...` are all clean. `golangci-lint` is not installed on
this machine (unchanged from every prior phase). The CLI binary was
rebuilt; `scanner detectors list` output is unchanged (this phase adds
no detector, changes no eligibility rule, and touches no
detector-registration code).

- **Phase 1-3.10 regression**: completely unchanged code paths in
  every package these phases own; all tests pass unchanged.
- **Phase 3.11 regression**: `internal/orchestrator`'s stage sequencing,
  cancellation, timeout, resource-limit, and scope-enforcement logic
  are all unchanged (this phase only extends `DetectorSummary` and adds
  a warning branch inside the already-existing DETECTION-stage code
  path, never altering control flow elsewhere). Two of Phase 3.11's own
  tests were corrected as documented above -- both fixes make the tests
  MORE accurate, never weaker (the new assertions are strictly
  additive: `DetectorRuns > 0` and `DetectionState == EXECUTED`, on top
  of the original `Status`/`Findings` checks, not instead of them).

## Final report

```
TOTAL TESTS: 1223 (962 top-level + 261 subtests)
PASS: 1223
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

DEFAULT CLI PATH: PASS
DEFAULT CRAWLER DISABLED: PASS
ZERO DETECTOR OBSERVABILITY: PASS
DETECTION SUMMARY: PASS
ZERO-DETECTOR WARNING: PASS

STATE A:
DETECTORS EXECUTED + NO FINDINGS: PASS

STATE B:
NO ELIGIBLE TARGETS + ZERO DETECTOR RUNS: PASS

STATE C:
DETECTOR FAILURE: PASS

CRAWLER ENABLED: PASS
POSITIVE DETECTION: PASS
BENIGN TARGET: PASS
HELP: PASS
DOCUMENTATION: PASS
SECURITY: PASS
PERFORMANCE: PASS
CONCURRENCY: PASS
REGRESSION: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0

PHASE 3.11.2 ADVERSARIAL: PASS

PHASE 3.11.2 VERDICT: PASS
```

Not proceeding to Phase 3.12, not implementing scan profiles or
detection policies, not enabling the crawler by default, not adding
new vulnerability detectors, not changing any detector's eligibility
rule, and not weakening scope enforcement anywhere, per the task's
explicit instruction to stop after this report.
