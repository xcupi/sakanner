# Phase 3.1: Vulnerability Detection Engine (Core)

**Status: this is the detection FRAMEWORK only.** sakanner ships zero
real vulnerability detectors as of this document. `internal/detection`
is the registry, lifecycle, request-execution, normalization,
deduplication, and persistence machinery a future detector (SQL
injection, reflected/stored XSS, SSRF, IDOR, path traversal, LFI, auth
bypass, ...) will plug into -- none of those are implemented here, and
nothing in this document claims otherwise. `scanner detectors list`
against an unmodified build prints "no detectors registered" and that
is the honest, correct state of Phase 3.1.

## Why a framework before any detector

Every one of the 17 vulnerability classes the [Phase 3 Test
Lab](phase-3-test-lab.md) already has fixtures for needs the same
surrounding machinery: a way to say "I exist and what I look for," a
way to decide which of Phase 2's recon output I should even look at, a
controlled way to make HTTP requests that can never bypass scope
enforcement, a common finding shape, a way to avoid reporting the same
bug twice, and a place those findings get persisted. Building that once
here means every future detector is a small, self-contained addition --
see "How to implement a new detector" below -- rather than each one
re-deriving scope-safety, concurrency control, and persistence
independently (which is exactly the kind of drift a security scanner
can least afford).

## Architecture

```
Recon (Phase 2, unchanged)
  |
  v
BuildTargets            -- turns HTTPServices/Endpoints/Technologies
  |                         for one scan job into []Target
  v
Engine.Run
  |-- Registry.enabledDetectors()      detector selection: registered + enabled
  |-- per (detector, target) pair:
  |     supportsTarget(Metadata, t)    cheap pre-filter (kind/method)
  |     Detector.Eligible(t)           detector's own finer filter
  |     Detector.Detect(ctx, t, x)     detection logic; x = Executor
  |          x.Do(ctx, t, req)         scope check -> rate limit ->
  |                                    concurrency slot -> safedial
  |-- normalizeFinding(...)            Finding Normalization
  |-- Deduplicate(existing, found)     Finding Deduplication
  v
Store.Findings().Create(...)          Finding Storage (pkg/models.Finding,
                                       already-existing SQLite schema)
  |
  v
scanner findings / scanner findings show / reporting (JSON + Markdown)
```

## Package layout

```
internal/detection/
├── doc.go                  package overview
├── detector.go             Detector interface, Metadata, Target, Result, Outcome
├── registry.go              Registry: Register/Get/List/SetEnabled
├── executor.go               Executor: the only sanctioned request path
├── targets.go                 BuildTargets: target selection from Store
├── finding.go                  normalizeFinding, Deduplicate, Filter{Severity,Detector}
├── evidence.go                  RequestResponseEvidence (structured evidence)
├── engine.go                     Engine.Run: the lifecycle above
├── *_test.go                     framework unit tests (39 tests)
└── detectiontest/
    └── mock.go                    Mock: a test-fixture Detector -- NOT a real detector,
                                    never registered in production

cmd/scanner/detectors.go     `scanner detectors list` (production registry: always empty today)
cmd/scanner/findings.go      `scanner findings [--detector] [--severity]`, `scanner findings show <id>`
lab/phase3_1_detection_test.go   integration tests against the real Phase 3 lab
```

## Detector interface

```go
type Detector interface {
	Metadata() Metadata
	Eligible(t Target) bool
	Detect(ctx context.Context, t Target, x *Executor) (Result, error)
}
```

Deliberately three methods, not the dozen a maximalist reading of "ID,
name, category, target types, methods, prerequisites, detection logic,
evidence, severity, confidence" might suggest -- `Metadata()` carries
every *declarative* fact (ID, Name, Category, SupportedTargetTypes,
SupportedMethods, Prerequisites, DefaultSeverity) as one struct, so the
interface itself stays small (see `internal/detection/detector.go`).
`Eligible` is a fast, no-I/O check for anything Metadata can't express
declaratively (e.g. "this endpoint's path looks numeric-ID-shaped").
`Detect` does the actual work and is the only place a detector performs
I/O -- exclusively through the `Executor` passed to it.

`Result.Outcome` is one of `OutcomeNoFinding` ("checked, not
vulnerable" -- success, not an error), `OutcomeFinding` (with
`Result.Findings`, usually one entry, occasionally more for multiple
payload variants), or `OutcomeSkipped` (rare -- `Eligible` should
already have filtered this out). A non-nil error from `Detect` means
the detector itself malfunctioned (a request error, an unparseable
response) and is recorded as a `DetectorError`, kept entirely distinct
from both a finding and a clean no-finding result.

## Detector lifecycle

```
Input (a Target)
  -> Eligibility check    supportsTarget(Metadata, t) then Detector.Eligible(t)
  -> Detection             Detector.Detect(ctx, t, x)
  -> Evidence               (the detector builds this itself, typically via
                             detection.NewRequestResponseEvidence)
  -> Finding                Result.Findings, if Outcome == OutcomeFinding
  -> Normalization           normalizeFinding fills ID/ScanID/DetectorID/
                             Host/Port/URL/Method/timestamps/Source
  -> Deduplication            Deduplicate against both this run's other
                             findings AND whatever's already persisted
  -> Persistence               Store.Findings().Create
```

A detector never sees "prerequisite check" as its own interface method
-- Phase 3.1 has no separate capability-negotiation step, because
nothing in Phase 2's recon output today varies in a way a detector would
need to query for at runtime (the fixed set of TargetKind/Method values
already covers what's known). `Metadata.Prerequisites` instead
*documents* a capability gap honestly (e.g. "authenticated differential
probing"), mirroring exactly how
`lab/ground-truth-vulnerabilities.yaml`'s `requires_capability`
field already does for the lab's own fixtures -- both exist so a reader
(or `scanner detectors list`) can see *why* a registered detector might
still never fire, not to gate execution.

## Target selection

`BuildTargets` (`internal/detection/targets.go`) is what keeps the
engine from "blindly running every detector against every asset": it
loads one scan job's Services/Hosts/HTTPServices/Endpoints/Technologies
and produces:

- One `TargetKindHTTPService` Target per successfully-probed
  HTTPService (its base URL, `"/"`, with that service's fingerprinted
  Technologies attached directly -- no second Store round trip needed
  for a component-version detector).
- One `TargetKindEndpoint` Target per discovered Endpoint (crawled
  page, link, form action, or script), plus one *additional* Target per
  query-string parameter name found on that endpoint's path.

That last point is a known, honestly-documented capability gap:
`internal/parameters` is still an unimplemented stub (Phase 1
scaffolding), so a query string observed on a crawled URL is the only
parameter surface available today -- a form field name is not, since
`models.Endpoint` carries no field list. This is the same kind of gap
`requires_capability` documents for individual fixtures, just at the
target-selection layer instead.

The engine then applies its own cheap filter (`supportsTarget`, using
`Metadata.SupportedTargetTypes`/`SupportedMethods`) before ever calling
a detector's `Eligible` -- two layers of "don't bother this detector
with a target it can never care about."

## Finding model

No new finding model was invented. `pkg/models.Finding` already existed
(Phase 1 scaffolding, populated by nothing until now) with
`Severity`/`Confidence`/`AffectedEndpoint`/`AffectedParameter`/
`ValidationStatus`/`Evidence`/`Remediation`. Phase 3.1 adds exactly the
fields that were genuinely missing -- `DetectorID`, `Host`, `Port`,
`URL`, `Method`, `Source` (migration
`internal/storage/migrations/0007_finding_detector_fields.sql`) -- and
maps the task's requested field list onto what already existed rather
than duplicating it: "status" is `ValidationStatus`
(unvalidated/confirmed/false_positive), "timestamp" is
`FirstSeen`/`LastSeen` (already two timestamps, more informative than
one). `AffectedEndpoint`/`AffectedParameter` keep their pre-existing,
path-only semantics (matching how the Phase 3 lab's own ground truth
already keys on them); `URL` is new and holds the full request URL a
detector actually probed.

`normalizeFinding` (`internal/detection/finding.go`) fills in every
field a detector isn't expected to set itself, while never overwriting
anything the detector already populated -- a detector only needs to
return `VulnerabilityType`, `Title`, and ideally `Severity`/`Confidence`/
`Evidence`; everything else (`ID`, `ScanID`, `DetectorID`,
`Host`/`Port`/`URL`/`Method`, `AffectedEndpoint`/`AffectedParameter`,
`Source`, timestamps) comes from the `Target` and `Detector.Metadata()`.

## Evidence model

`RequestResponseEvidence` (`internal/detection/evidence.go`) is the one
structured shape every detector should use: `Request`, `Response`,
`StatusCode`, `Headers`, `ResponseFragment`, `Parameter`, `Payload`,
`Observation`, `Reason`. `NewRequestResponseEvidence` JSON-marshals it
into `models.Evidence.Content` (`Kind:
models.EvidenceKindRequestResponse`) rather than becoming a new,
separately-persisted model -- `models.Evidence`/`Finding` already exist
and are already wired through storage end to end; this is the
structured shape that goes *into* the existing `Content` string field,
not a schema change. A detector author should never populate
`Request`/`Response` with credentials or session tokens observed in the
exchange -- capture only what demonstrates the vulnerability (e.g.
redact an `Authorization` header's value, keep only its presence).

## Severity and confidence

Severity reuses `pkg/models.Severity`'s existing five-value scale
(info/low/medium/high/critical) unchanged -- no new model, no CVSS
scoring (explicitly out of scope). Confidence is `Finding.Confidence
float64` (already existed), by convention `0.0`-`1.0`; nothing enforces
a particular scale beyond that, since no real detector calibrates it
yet. Severity and confidence are independent: a detector can validly
report high severity with low confidence (a shape not yet fully
determined) or the reverse.

## Deduplication

`dedupKey` (`internal/detection/finding.go`) identifies a finding's
identity as `(DetectorID, Host, Port, AffectedEndpoint, Method,
AffectedParameter, VulnerabilityType)` -- the same detector reporting
the same vulnerability type at the same host/port/endpoint/method/
parameter is one finding, however many times a scan (or repeated scans
of the same job) produces it. This extends
`lab/comparison.go`'s own matching key (`VulnerabilityType` +
`AffectedEndpoint`) with the extra fields a real multi-host,
multi-detector engine needs to stay precise, while remaining consistent
with it.

`Deduplicate(existing, found)` consults BOTH the findings produced in
the current run AND whatever is already persisted for the scan job
(loaded once at the start of `Engine.Run`) -- deduplication is
idempotent across repeated `Engine.Run` calls against the same job, not
just within one call. `TestEngine_RerunIsIdempotentViaDeduplication` and
`TestPhase3_1_MockDetectorFindingEvidencePersistedAndDeduplicated` prove
this directly: running detection twice against the same scan job
persists the finding exactly once.

## Scope enforcement

**This is the framework's most important property.** `Executor`
(`internal/detection/executor.go`) is the *only* sanctioned way a
detector reaches a target -- `Detector.Detect` receives an `*Executor`,
never a raw `*http.Client` or `net.Dialer`, and the interface gives it
no other way to open a connection. `Executor.Do`:

1. Re-validates `t.Host`/`t.IP` via `scope.Validator.CheckResolved` --
   the SAME centralized `internal/scope` authority every other stage
   (ports, HTTP probing, crawling) already uses, never a
   detector-private or weaker check.
2. Waits on a shared `*rate.Limiter` and a bounded concurrency
   semaphore (both `ctx`-aware, so cancellation unblocks immediately).
3. Enforces a hard total-request ceiling for the whole `Executor`
   lifetime (`ExecutorConfig.MaxRequests`, from
   `config.DetectionConfig.MaxRequestsPerRun`).
4. Dials through `safedial.Dialer.NewClient` -- the exact same
   resolve-once, dial-by-IP, redirect-re-validated-per-hop logic
   `internal/http` and `internal/crawler` already share. `safedial`
   performs its own scope check again internally before every dial,
   independent of step 1 above -- true defense in depth, not
   redundancy for its own sake. This was verified directly: a
   deliberate, temporary removal of `Executor`'s own check (step 1) was
   still caught by `TestPhase3_1_ScopeEnforcementStaysActiveDuringDetection`
   via `Executor.RequestCount()`, even though `safedial`'s independent
   check still blocked the actual TCP dial -- proving both layers
   contribute, not just one silently covering for the other.

A detector cannot build its own `http.Client`, cannot resolve a
hostname itself, and cannot retry around a scope denial -- `Executor` is
the choke point, by construction (there is no other way to reach a
`Target`'s network address from inside a `Detector` implementation).

## Request execution and rate limiting

`ExecutorConfig` (built from `config.DetectionConfig` in production, see
`internal/config/config.go`) bounds: `Concurrency` (in-flight requests
across the whole Executor), `Limiter` (a `*golang.org/x/time/rate.Limiter`
-- the exact same rate-limiting primitive `internal/ports`/`internal/http`
already use, one limiter for the whole detection stage, matching the
existing one-limiter-per-stage convention), `Timeout`, `MaxRedirects`,
`UserAgent`, and `MaxRequests` (the total-request ceiling above). None
of this is detector-configurable -- a detector receives an already-built
`*Executor` and has no way to raise its own limits.

## Concurrency

`Engine.Run` uses `golang.org/x/sync/errgroup` with `SetLimit`, the same
bounded-worker-pool pattern `orchestration.Pipeline` already uses for
its own stages (`scanPorts`, `probeAndFingerprint`) -- never an
unbounded `go func()` per target. Every `(detector, target)` pair that
passes eligibility runs as one bounded goroutine; results are collected
under a mutex. `TestEngine_ConcurrentExecutionUnderRace` (30 targets,
concurrency 8) and the full suite's `-race` flag together are what prove
this is actually safe, not just bounded.

## Error isolation

A `Detector.Detect` call is wrapped in its own `defer recover()`: a
panic is caught and recorded as a `DetectorError` exactly like any other
detector failure, never propagated to crash `Engine.Run` or cancel other
in-flight detector calls. A returned error is likewise recorded in
`RunSummary.Errors` and logged, but the `errgroup`'s own error return is
deliberately never used for this (every worker function returns `nil`
unconditionally) -- returning a real error through the errgroup would
cancel its shared context and, through that, abort every *other*
in-flight detector call too, which is the opposite of "a detector
failure must not crash the entire scan."
`TestEngine_DetectorErrorDoesNotStopOtherDetectors`,
`TestEngine_DetectorPanicIsRecoveredAndDoesNotCrashTheRun`, and their
real-lab counterparts in `lab/phase3_1_detection_test.go` prove
both a failing and a panicking detector leave a concurrently-running
working detector's finding intact.

## Cancellation

`Engine.Run` takes `ctx` and passes it through the `errgroup`'s derived
context to every detector call and every `Executor.Do`. A cancelled
`ctx` stops new detector goroutines from starting (checked at the top of
each), unblocks any `Executor.Do` currently waiting on the rate limiter
or concurrency semaphore, and is reflected in
`RunSummary.Cancelled`. `Run` still returns a valid summary rather than
hanging or returning a bare error -- `TestEngine_CancellationStopsBeforeAllTargetsRun`
and `TestPhase3_1_CancellationDuringDetection` (a 50ms deadline against
20+ real lab-derived targets, each requiring a 200-300ms simulated
detection) prove this against both synthetic and real recon data.

## Persistence

Findings are written through the existing `storage.Store.Findings()`
repository -- no second database, no new storage abstraction.
`Engine.Run` loads existing findings for the scan job once (for
cross-run deduplication), then creates each newly-deduplicated finding
via `Store.Findings().Create`. `FilterBySeverity`/`FilterByDetector`
(`internal/detection/finding.go`) are small in-memory helpers over
`ListByScanJob`'s result -- not new repository methods -- satisfying
"retrieve findings by detector"/"by severity" without adding
storage-layer surface area for what a caller can filter cheaply itself.

## CLI

```
scanner detectors list                          # registry contents (empty in this build)
scanner findings --scan <id>                     # existing command, now supports:
scanner findings --scan <id> --detector <id>     #   --detector filter
scanner findings --scan <id> --severity <level>  #   --severity filter
scanner findings show <finding-id>               # new: one finding's full detail + evidence
```

`scanner detectors list` against `productionRegistry()` (`cmd/scanner/detectors.go`)
-- which registers nothing -- prints `no detectors registered (Phase 3.1
ships the detection framework only ...)`, not a fabricated list. This
was verified by running the built binary directly (see
`docs/phase-3-1-acceptance-test.md`).

## How to implement a new detector without modifying the core engine

1. Implement `detection.Detector` (three methods: `Metadata`,
   `Eligible`, `Detect`) in a new file/package.
2. In `Detect`, build an `*http.Request` against `t.URL`/`t.Path` (or a
   derived URL/parameter probe) and call `x.Do(ctx, t, req)` -- never
   `http.Get`, never a custom `http.Client`.
3. On a positive result, build evidence via
   `detection.NewRequestResponseEvidence` and return
   `Result{Outcome: OutcomeFinding, Findings: []models.Finding{{...}}}`
   -- set at least `VulnerabilityType`/`Title`; `normalizeFinding` fills
   the rest.
4. Register it: `registry.Register(myDetector{})` wherever
   `productionRegistry()` (`cmd/scanner/detectors.go`) is built.

No change to `Registry`, `Engine`, `Executor`, `BuildTargets`,
`normalizeFinding`, or `Deduplicate` is ever required for a new
detector -- `internal/detection/detectiontest.Mock` is the proof: it
implements the exact same three-method interface a real detector would,
and every lifecycle test in this document runs it through the
unmodified framework.
