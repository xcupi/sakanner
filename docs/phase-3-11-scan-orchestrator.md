# Phase 3.11: Automated Scan Orchestrator & End-to-End Pipeline

## Purpose

`internal/orchestrator` sequences sakanner's ENTIRE existing pipeline
into one call: a raw operator-supplied target string goes in, and a
final, ordered set of `evidence.FindingPackage` values (finding + risk
assessment + evidence + reproduction) comes out. It owns sequencing,
lifecycle, state, progress, cancellation, timeouts, error isolation,
and resource limits -- nothing else. Every actual unit of work (scope
checking, recon, candidate discovery, detection, correlation, risk
scoring, evidence building) is delegated to the existing package that
already implements it; this layer never reimplements or forks any of
that logic.

## Architecture

```
raw target string
       |
       v
   [ SCOPE ]        internal/target.Parse + internal/scope.Validator
       |             (fast pre-flight check; Pipeline.Run re-checks
       |              authoritatively regardless -- defense in depth)
       v
[ RECON + DISCOVERY ]   internal/orchestration.Pipeline.Run
       |                 (one atomic call: asset discovery, DNS,
       |                  ports, HTTP probing, fingerprinting, crawl,
       |                  endpoint extraction)
       v
[ DETECTION + VERIFICATION ]  internal/detection.Engine.Run
       |                       (registry-driven detector execution;
       |                        each detector verifies internally)
       v
  [ CORRELATION ]     internal/correlation.Engine.Ingest/Findings
       v
     [ RISK ]         internal/risk.AssessAll + Rank
       v
   [ EVIDENCE ]       internal/evidence.BuildPackage (per finding)
       v
  [ FINALIZATION ]    aggregate into Result
```

## Detector independence

Like every phase since 3.8, this package contains no vulnerability-
specific logic. It never branches on `VulnerabilityType`, never
constructs a detector, and never inspects a `Finding`'s contents beyond
generic fields (`ScanID`, `Severity`, `FindingID`) needed for
aggregation and log correlation.

## Stages and the state machine

Task section 2 names 9 explicit stages: `SCOPE`, `RECON`, `DISCOVERY`,
`DETECTION`, `VERIFICATION`, `CORRELATION`, `RISK`, `EVIDENCE`,
`FINALIZATION`. Each has its own lifecycle
(`PENDING → RUNNING → COMPLETED|FAILED|CANCELLED`, plus `SKIPPED` for a
stage never reached because an earlier one ended the scan) tracked in
`ScanState` (`internal/orchestrator/state.go`), a thread-safe struct
guarded by a single mutex. External callers only ever observe a
`StateSnapshot` -- an immutable deep copy returned by `Snapshot()` --
never the live struct.

### Why RECON+DISCOVERY, and DETECTION+VERIFICATION, are bundled

Two pairs of the 9 named stages are executed as ONE call into an
existing package, because that package has no intra-run stage hooks to
attach finer-grained progress to, and adding them would mean modifying
Phase 1's `orchestration.Pipeline` or Phase 3.1's `detection.Engine` --
outside this phase's stated scope ("do not duplicate recon
functionality," "individual detectors must not orchestrate the entire
scan," implicitly: this phase integrates, it doesn't refactor earlier
phases):

- **RECON + DISCOVERY**: `orchestration.Pipeline.Run` performs asset
  discovery, DNS resolution, port scanning, HTTP probing, technology
  fingerprinting, and (if enabled) crawling + endpoint extraction as
  one atomic, blocking call. Both stages transition to RUNNING
  together and COMPLETED together.
- **DETECTION + VERIFICATION**: every one of the 6 real detectors
  performs its own verification internally, as part of a single
  `Detect()` call (see Phase 3.10/3.11's evidence-integration work
  below) -- there is no separate "verify" step any real detector
  exposes today. Both stages transition together for the same reason.

This is documented, not hidden: `docs/phase-3-11-acceptance-test.md`'s
progress and stage tests confirm the bundling is consistent and that
progress still never claims 100% before `FINALIZATION` itself
completes.

## Scan state model

Minimum fields (task section 3), in `model.go`/`state.go`:

```go
type StateSnapshot struct {
    ScanID, Target string
    Status Status                 // QUEUED/RUNNING/COMPLETED/
                                   // COMPLETED_WITH_WARNINGS/FAILED/CANCELLED
    CurrentStage Stage
    Stages []StageProgress        // one per stage, each with its own status
    StartedAt time.Time
    CompletedAt *time.Time
    Duration time.Duration
    ProgressPercent int
    Counters Counters             // hosts/services/requests/findings/etc.
    Errors []ScanError            // categorized, see "Error model"
    FindingsCount int
}
```

`StatusCompletedWithWarnings` is this phase's own addition beyond the
5 states task section 3 lists literally: the scan reached
`FINALIZATION` cleanly (never cancelled, never hard-failed) but at
least one detector error, resource-limit truncation, or other
non-fatal issue was recorded along the way (task section 34's "clearly
distinguish successful detector results, failed detectors, and partial
scan state"). A run with zero warnings/errors is plain `COMPLETED`.

## Scan ID propagation (task section 4)

`Orchestrator.Run` generates one `scanID` (a fresh UUID) at the very
start and threads it through every downstream call:
`orchestration.RunOptions.ScanJobID` (a small, additive field this
phase added to `internal/orchestration.RunOptions` -- empty means
"generate one internally," exactly the pre-3.11 behavior, so this is
fully backward compatible with `cmd/scanner scan --target <id>`'s
original recon-only path), `detection.RunOptions.ScanJobID`,
`correlation`/`risk`/`evidence`'s own `ScanID`/`FindingID` fields
(already propagated by those packages from `models.Finding.ScanID`),
and every structured log line via `logging.WithScanJob`. Two
independent scans always get independent IDs and independent
`ScanState` instances -- verified directly by
`TestPhase3_11_Orchestrator_ScanIsolation`.

## Target validation and scope enforcement (task sections 5-6)

`resolveAndRegisterTarget` (`target.go`) reuses `internal/target.Parse`
unchanged (no new formats), then performs a FAST pre-flight scope check
against the CURRENT `models.ScopeRule` snapshot via
`scope.NewValidator`/`CheckHost`/`CheckIP` -- the exact same interface
`orchestration.Pipeline` and `internal/http`'s prober already use. This
is explicitly **defense in depth, not the sole safeguard**:
`Pipeline.Run` independently re-checks scope against its own snapshot
before ANY host/port/HTTP work begins, and `detection.Executor`
re-checks again before every dial. A revert-and-verify exercise
(disabling this layer's own check) confirmed the deeper layer alone
still caught an out-of-scope target -- see the acceptance report.

## Detector registry and scheduling (task sections 9-10)

`Orchestrator.DetectionRegistry` is caller-supplied (e.g.
`cmd/scanner`'s own `productionRegistry()`) -- the orchestrator never
registers a detector itself. `DetectionExecutorConfig`
(`detection.ExecutorConfig`) and `DetectionConcurrency` bound,
respectively, in-flight HTTP requests and concurrent (detector,
target) pairs -- both pre-existing Phase 3.1 knobs, reused unchanged. A
FRESH `detection.Executor` is built once per scan (`buildDetectionExecutor`),
against THIS scan's own scope-rule snapshot -- never a shared,
possibly stale instance held across scans.

## Detector failure isolation (task section 11)

`detection.Engine.Run` already isolates a single detector's failure
(recovering panics, catching per-`Detect()`-call errors) without
aborting the run -- this phase adds nothing to that mechanism, only
surfaces its `RunSummary.Errors` as `ErrorCategoryDetector`-tagged
`ScanError`s and drives the final `COMPLETED_WITH_WARNINGS` status.
`TestPhase3_11_Orchestrator_DetectorFailureIsolation_ScanContinues`
registers a detector that always errors alongside the real 6 and
confirms the scan still completes with every other detector's findings
intact.

## Hard failure (task section 12)

| Condition | Category | Stage |
|---|---|---|
| Malformed target (`target.Parse` error) | `FATAL` | SCOPE |
| Target out of scope | `FATAL` | SCOPE (or RECON, if the deeper Pipeline-level check catches it instead -- still fails the scan, never a bypass) |
| Storage failure loading scope rules / listing findings | `STAGE` | whichever stage was in progress |
| `detection.Engine.Run` returning a hard error (a finding failed to persist) | `STAGE` | DETECTION |
| `orchestration.Pipeline.Run` returning a non-scope, non-cancellation error (backend selection failure, etc.) | `STAGE` | RECON |

Both categories terminate the scan; `FATAL` is reserved specifically
for the named conditions task section 12 lists (bad input, scope,
resource exhaustion), `STAGE` covers everything else that still ends
the run, so an operator can tell "your input/authorization was the
problem" apart from "something inside the scanner broke."

## Cancellation and timeouts (task sections 13-14)

`context.Context` is threaded through every stage. Every stage boundary
checks `ctx.Err()` immediately after the stage's own call returns, in
addition to whatever that call's own error already signals -- mirroring
`orchestration.Pipeline.Run`'s own established
`if runErr == nil && ctx.Err() != nil { runErr = ctx.Err() }` pattern.
`terminalStatus` (checked FIRST, before considering whether the run
otherwise looked clean) guarantees a cancelled/timed-out run is always
reported `CANCELLED`, never `COMPLETED` -- task section 13's central
safety property, verified directly by
`TestPhase3_11_Orchestrator_CancelBeforeStart` and
`TestPhase3_11_Orchestrator_StageTimeout_NeverMarksCompleted` (the
latter uses a deterministic 1-nanosecond `StageTimeout` rather than a
timing race, guaranteeing the very first stage cannot complete).

Three independent timeout knobs (task section 14): `Limits.ScanTimeout`
(wraps the whole `ctx` once, at the top of `Run`), `Limits.StageTimeout`
(wraps each stage's own sub-call individually, via
`withStageTimeout`), and the pre-existing per-detector/per-request
timeouts (`detection.ExecutorConfig.Timeout`, `HTTPConfig.Timeout`) --
unchanged, simply passed through. Every timeout is a plain
`context.WithTimeout` derivation; nothing bypasses Go's own
context-cancellation propagation, so cleanup (releasing the
concurrent-scan slot, `state.Finish`) always runs via `defer`
regardless of which timeout fired.

**`Result` finalization ordering** -- the one subtle correctness
property this phase's own development caught via a real bug (see the
acceptance report's issues list): the `Result` returned by `Run` MUST
be built strictly AFTER `ScanState.Finish(status)` has already run,
never before, or every returned `Result.Status` reads a stale
`RUNNING` snapshot. `Run` uses named return values
(`result Result, err error`) with every early exit doing a naked
`return`; a single `defer` is the ONLY place `result`/`err` are ever
assigned, and it calls `state.Finish` before `o.buildResult`.

## Progress (task sections 15-16)

```
SCOPE          5%
RECON/DISCOVERY   45%   (bundled checkpoint -- see above)
DETECTION/VERIFICATION  80%   (bundled checkpoint -- see above)
CORRELATION   88%
RISK          92%
EVIDENCE      97%
FINALIZATION 100%
```

`ScanState.ProgressPercent()` returns the HIGHEST checkpoint among
every stage currently `COMPLETED` -- never derived from elapsed time, a
timer, or an estimate. A stage that is merely `RUNNING` does not move
progress; only a real `CompleteStage` call does (task section 16's
"use completed work units," applied at stage granularity, since
Phase 1's `Pipeline.Run` and Phase 3.1's `detection.Engine.Run` are
each one atomic, blocking call with no intra-run hook this phase can
attach finer progress to without modifying those packages -- an
honestly documented limitation, not a fabricated finer-grained number).
100% is only reachable by `FINALIZATION` itself completing -- verified
directly by `TestProgress_Never100BeforeFinalizationCompletes`.

## Result aggregation (task sections 17, 21-25)

Detector output never reaches the final `Result` directly: every raw
`models.Finding` flows through `correlation.Engine.Ingest`/`Findings()`
(deduplication), then `risk.AssessAll`/`Rank` (scoring, deterministic
ordering), then `evidence.BuildPackage` (per surviving, ranked
assessment). `Result.Findings` is exactly `risk.Rank`'s own output
order, mapped 1:1 through `evidence.BuildPackage` -- the orchestrator
never reorders it (task section 25).

```go
type Result struct {
    ScanID, Target string
    Status Status
    StartedAt, CompletedAt time.Time
    Duration time.Duration
    ReconSummary ReconSummary        // via internal/reporting.Build
    DetectorSummary DetectorSummary  // from detection.RunSummary
    Findings []evidence.FindingPackage
    Errors []ScanError
    Warnings []string
    Summary FindingsSummary          // total/critical/high/medium/low/info
}
```

`ReconSummary` is read back from storage via `internal/reporting.Build`
-- the exact same aggregation `scanner status` already relies on
(task section 7's "integration of existing modules"), not re-queried
from scratch.

## Real evidence integration (task sections 18-20) -- CRITICAL requirement

Phase 3.10 shipped with an honestly documented limitation: every real
detector emitted exactly ONE combined `models.Evidence` item per
finding, so Phase 3.10's evidence engine classified every real
finding's evidence as `VERIFICATION` -- `BASELINE`/`PROBE` were fully
modeled and tested, but never populated for real detector output. This
phase's investigation (reading all 6 detectors' `Detect()`
implementations in full) found that **5 of the 6 real detectors
already fetch and hold a genuine control ("baseline") request/response
in memory** -- used in real differential logic (sqli's error-family
suppression, ssrf's stripped-body/fetch-error-phrase diff, idor's
owner-vs-cross-context comparison, traversal's legitimate-access and
not-found baselines, cmdinjection's reachability gate) -- and then
discarded it once `Detect()` returned, never persisting it as its own
evidence record.

This phase closes that gap WITHOUT changing any detection algorithm,
payload, threshold, or severity/confidence assignment:

1. `pkg/models` gained two new `EvidenceKind` values:
   `EvidenceKindBaseline` and `EvidenceKindProbe` (generic,
   detector-independent vocabulary -- alongside the pre-existing
   `EvidenceKindRequestResponse`/`EvidenceKindText`/`EvidenceKindScreenshot`).
2. `internal/detection/evidence.go` gained
   `NewTypedRequestResponseEvidence(kind, id, findingID, e)` -- a
   one-line generalization of the existing
   `NewRequestResponseEvidence` (which now just calls it with
   `EvidenceKindRequestResponse`, its original, unchanged behavior).
3. Each of the 5 detectors with real, already-computed baseline data
   (`sqli`, `ssrf`, `idor`, `traversal`, `cmdinjection`) now ALSO
   appends a `EvidenceKindBaseline`-tagged record describing that
   control request/response -- purely surfacing data already fetched,
   never a new HTTP request. `idor` and `traversal` additionally
   surface their extra already-computed cross-context/variant attempts
   (beyond the one folded into the main evidence item) as
   `EvidenceKindProbe`-tagged records.
4. `reflected_xss` is the one detector with genuinely **no** baseline
   to surface -- all three of its probes inject a payload; none sends
   an unmodified control value. This is documented, not treated as a
   gap to fabricate around (task section 20: "if the detector cannot
   provide one of these: record the reason explicitly. Do not
   fabricate evidence").
5. `internal/evidence`'s engine now maps `EvidenceKindBaseline`/
   `EvidenceKindProbe` onto `EvidenceTypeBaseline`/`EvidenceTypeProbe`
   (`evidenceTypeForKind` in `engine.go`) instead of defaulting
   everything to `VERIFICATION` -- the one place this distinction
   crosses into Phase 3.10's package, kept generic (switches on the
   kind value only, never a detector ID).

Verified end to end against the REAL lab, not just unit-level: `lab/phase3_11_orchestrator_test.go`'s `TestPhase3_11_Orchestrator_FullPositiveLab` runs all 6 real detectors through the real
recon → detection → correlation → risk → evidence pipeline and asserts
`EvidenceTypeBaseline` is actually present for `sql_injection`, `ssrf`,
`idor`, `path_traversal`, and `command_injection`, and absent for
`reflected_xss` -- exactly matching the investigation's findings, and
directly satisfying "do not merely test the data structures."

`internal/evidence.limitationsFor` was also corrected to check for a
real `EvidenceTypeBaseline` ITEM (the thing that changed this phase)
rather than only the unrelated, still-unpopulated `Baseline
*DifferentialEvidence` structured-diff field, so a finding's own
`limitations[]` text now honestly reflects which case it's in.

## Resource limits and backpressure (task sections 32-33)

```go
type Limits struct {
    MaxConcurrentScans int           // default 5
    MaxFindings        int           // default 1000
    ScanTimeout        time.Duration // default 0 (no bound)
    StageTimeout       time.Duration // default 0 (no bound)
}
```

`MaxConcurrentScans` is enforced by a fixed-size buffered channel
(`acquireScanSlot`/`releaseScanSlot`) -- a caller starting one more
concurrent scan than the limit BLOCKS on the channel send (a bounded
queue, task section 33), never spawns an unbounded goroutine, and
unblocks the instant an earlier scan's slot frees; it also respects
context cancellation while waiting. `MaxFindings` is enforced AFTER
Phase 3.9's deterministic risk-based ranking (never before, and never
reordering afterward) -- the kept findings are always the
highest-priority prefix, and a `Limits.MaxFindings`-truncation warning
is recorded, never silently dropped. `MaxRequests`/response-size/
evidence-item bounds are all pre-existing knobs
(`detection.ExecutorConfig.MaxRequests`, `evidence.Limits`) simply
wired through, not reimplemented.

## Error model (task sections 26-28)

Five categories (`ErrorCategory`): `FATAL`, `STAGE`, `DETECTOR`,
`REQUEST`, `WARNING` -- see "Hard failure" above for Fatal/Stage, and
"Detector failure isolation" for Detector. `WARNING` covers non-fatal,
still-worth-surfacing facts (a resource limit was reached). A single
`ScanError{Category, Stage, DetectorID, Message, OccurredAt}` carries
enough correlation to answer "what stage, what detector, when" without
needing timing correlation, matching task section 28's requirement.
Structured logging (`log/slog`, via `logging.WithScanJob`) emits
`scan_started`, `stage_started`, `stage_completed`, `detector_started`/
`detector_completed` (bracketing the whole DETECTION stage -- see
"bundling" above for why per-detector-call granularity isn't
available), `finding_created`/`finding_deduplicated` (from
`correlation.Engine.Ingest`'s own per-input `IngestResult.Status`),
`risk_calculated`, `evidence_created`, and
`scan_completed`/`scan_failed`/`scan_cancelled`. No secret is ever
logged: every log call passes only IDs, stage names, counts, and
category labels -- never a `RequestResponseEvidence` field, which
could carry a redacted-but-still-sensitive-looking value; secrets are
Phase 3.10's `internal/evidence` package's own, already-tested
responsibility, never re-touched here.

## Idempotency (task section 29)

Re-ingesting the same set of `models.Finding` rows through
`correlation.Engine.Ingest` a second time produces the SAME
`CanonicalFinding.FindingID`s (a content hash, not a counter) and
collapses to the same deduplicated set -- this is Phase 3.8's own,
unmodified guarantee, simply relied upon rather than re-implemented.

## CLI integration (task sections 45-46)

`scanner scan <target>` (a new positional-argument form of the
existing `scan` command) runs the full pipeline via
`internal/orchestrator.Orchestrator` and prints Scan ID / Target /
Status / Duration, any recorded errors/warnings, and findings grouped
by severity (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`), each row showing
ID/Type/URL/Parameter/Severity/Confidence/Risk/Priority, followed by a
totals summary. The ORIGINAL `scanner scan --target <id>` flag-based
form (Phase 1 recon-only, no detection/correlation/risk/evidence) is
completely unchanged -- both forms share one `buildPipeline` helper,
factored out without altering its field-by-field construction.

Exit codes (a new, additive convention -- every other command keeps
`main.go`'s original "any error exits 1"):

| Code | Meaning |
|---|---|
| 0 | Scan completed (`COMPLETED` or `COMPLETED_WITH_WARNINGS`) |
| 1 | Generic/unexpected error (e.g. no target supplied at all) |
| 2 | Scan reached `FAILED` (invalid target, out-of-scope target, internal stage failure) |
| 3 | Scan was `CANCELLED` (timeout or interrupt) |

## Security controls

- No `os/exec`, `syscall`, or `net/http` import anywhere in
  `internal/orchestrator` (statically enforced, `security_test.go`) --
  the orchestrator reaches the network ONLY through its
  caller-supplied `Pipeline`/`Executor`, both of which already enforce
  scope via `safedial.Dialer`.
- Malformed/adversarial target strings (empty, control characters,
  shell metacharacters, oversized, malformed URLs, RTL-override/BOM
  sequences) never panic -- routed through the same `target.Parse` +
  `scope.Validator` path every real target uses, exercised directly in
  `TestSecurity_MalformedTarget_NoCrash`.
- No credential/secret ever appears in a structured log line --
  `TestPhase3_11_LogCorrelation_NoSecretsLogged` scans every captured
  log record and attribute for Authorization/Bearer/Cookie-shaped
  content against a real scan run.

## Determinism (task section 43)

Repeated runs of the same target produce identical finding counts,
vulnerability types, evidence-type sequences, risk scores, and
priorities (verified directly against the real lab,
`TestPhase3_11_Orchestrator_Determinism_RepeatedRunsSameFindingIdentitiesAndOrder`).
Evidence CONTENT (not type, not count) is explicitly excluded from that
comparison for `command_injection` and `ssrf`: both detectors
deliberately embed a freshly generated, per-probe-unpredictable
correlation token (a UUID / random callback token) as their core
confirmation mechanism -- an existing, unchanged Phase 3.7/3.4 design
choice, not a determinism defect. Two independent scans are expected
to carry different tokens; the SAME scan re-queried twice (Phase
3.8/3.10's own hash-determinism tests, unchanged) still produces
byte-identical evidence.

## Detection readiness and zero-detector observability (Phase 3.11.2)

Reconnaissance (host/port/HTTP discovery, technology fingerprinting)
runs identically whether or not crawling is enabled -- it has no
dependency on it. Vulnerability **detection** is different: every
detector currently implemented (Phase 3.2-3.7) only ever accepts a
`TargetKindEndpoint` target carrying a query parameter
(`Eligible()` requires `t.Kind == TargetKindEndpoint && t.Parameter !=
"" && t.ParameterLocation == "query"` in every one of the 6 real
detectors), and the ONLY place such a target is ever produced is
`internal/detection.BuildTargets`, from a `models.Endpoint` row --
which the crawler is the ONLY thing that ever creates
(`orchestration.Pipeline.crawlAndDiscoverEndpoints`, gated on
`CrawlEnabled`). `crawler.enabled` defaults to `false`
(`internal/config`), so **a plain `scanner scan <target>` with no
config override completes recon successfully but runs zero
detectors** -- not because the target has no vulnerabilities, but
because no eligible target ever existed for any current detector to
examine. This was found via real CLI usage, root-caused, and
classified as a test/observability gap (not a wiring defect: every
component behaves exactly as its own documentation already said it
would) -- see `docs/phase-3-11-2-acceptance-test.md`.

### Detection summary

`Result.DetectorSummary` reports enough to answer "did detection even
run, and why" without parsing log text (task section 13):

```go
type DetectorSummary struct {
    DetectorsRegistered int            // static registry fact, always populated
    DetectorsEnabled    int            // static registry fact, always populated
    TargetsConsidered   int            // every target BuildTargets produced
    EligibleTargets     int            // (detector, target) pairs that passed Eligible()
    DetectorRuns        int            // pairs that actually completed
    RawFindingsCreated  int
    CanonicalFindings   int
    Duplicates          int
    RequestsIssued      int64
    ErrorCount          int
    State               DetectionState // EXECUTED / NOT_RUN / FAILED -- see below
}
```

### Three states, never conflated (task section 5)

- **`DetectionStateExecuted`** (state A): `DetectorRuns > 0`. Detectors
  actually ran; `Findings == 0` here is a real, meaningful negative
  result ("checked, found nothing").
- **`DetectionStateNotRun`** (state B): the DETECTION stage completed
  cleanly but `EligibleTargets == 0` -- most commonly the
  crawler-disabled case above. `Findings == 0` here means "nothing was
  examined," never "checked and found nothing." A warning
  (`ErrorCategoryWarning`, message prefixed `DETECTION_NOT_RUN:`) is
  recorded, and `Result.Status` becomes `COMPLETED_WITH_WARNINGS`
  rather than a bare `COMPLETED` -- the scan still succeeded at
  everything it was configured to do, but an operator reading only
  `Status`/`Findings` should not conclude "no vulnerabilities exist."
  A structured `detection_not_run` log event (`scan_job_id`, `reason`,
  `crawler_enabled`, `eligible_targets`, `detectors_enabled`) is
  emitted alongside it.
- **`DetectionStateFailed`** (state C): eligible targets may well have
  existed, but the DETECTION stage itself did not complete (a hard
  error from `detection.Engine.Run`, or cancellation/timeout during
  it) -- distinct from a single detector's own isolated failure (which
  still produces state A with a per-detector `ErrorCategoryDetector`
  warning, since the stage itself completed).

The CLI (`scanner scan <target>`) prints a `Detection:` block
(Registered/Enabled/Eligible targets/Detector runs/Raw findings/
Canonical findings) unconditionally, and phrases the empty-findings
line differently per state (`scanner scan --help` documents this).
None of this changes `crawler.enabled`'s default, scope enforcement,
or any detector's eligibility rule -- it is purely additive
observability, computed from state the scan already has (no additional
network requests, per task section 16).

**Phase 3.12 added a 4th state**, `DetectionStateDisabledByProfile`,
for when a scan profile (e.g. `recon`) excludes detection entirely by
policy -- deliberately distinct from state B ("attempted, nothing
eligible"), since "never attempted" and "attempted and found nothing
to attempt" are different claims. See
docs/phase-3-12-scan-profiles.md section 10 for the full detail; this
document's own states A/B/C above are unmodified by that addition.

## Limitations

- RECON+DISCOVERY and DETECTION+VERIFICATION each report progress as
  one bundled checkpoint rather than smoothly interpolating within the
  stage, because the packages they call (`orchestration.Pipeline`,
  `detection.Engine`) are each one atomic call with no intra-run
  progress hook -- adding one would mean modifying those packages,
  outside this phase's integration-only scope.
- `reflected_xss` has no BASELINE evidence, structurally (no control
  request exists in that detector to surface) -- documented, not a
  defect.
- A structured baseline-vs-observed differential (`Diff()` in
  `internal/evidence/reproduction.go`, Phase 3.10) is still never
  computed for real findings, even though a real BASELINE item now
  usually exists alongside the VERIFICATION item -- wiring that
  comparison up would mean this package (or `internal/evidence`)
  interpreting two detector-specific evidence blobs together, edging
  toward vulnerability-specific logic this phase's strict scope
  excludes; `limitationsFor` reports this honestly per finding.
