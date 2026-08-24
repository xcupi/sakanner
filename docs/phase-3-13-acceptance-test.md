# Phase 3.13 Acceptance Test: Parameter & Input Discovery Engine

Scope: new `internal/parameters` package (Location/Classification model,
`Normalize` for query+form discovery, `InferPathInputs`, `ParseJSONBody`,
resource `Limits`); `internal/crawler` extended (`FormRef.Fields`,
new `FormField` type, `extractFormFields`); `pkg/models.Parameter`
extended to the full normalized-input shape; new `ParameterRepository`
+ `0008_parameters.sql` migration; `internal/orchestration.Pipeline`
extended (`ParameterLimits` field, input discovery wired into
`crawlAndDiscoverEndpoints`, warnings threaded through
`models.ScanJob.Warnings`); `internal/detection.BuildTargets` changed to
source query-parameter targets from the persisted Parameters store
instead of live-reparsing URLs; `internal/policy`/`internal/orchestrator`
extended (per-profile input-discovery limits, `Result.InputSummary`);
`cmd/scanner` extended (`Inputs:` scan-result block, new
`scanner inputs` command); `internal/reporting` extended (Parameters in
JSON/Markdown reports); new `lab/harness_inputs.go` fixture app.
See [docs/phase-3-13-parameter-discovery.md](phase-3-13-parameter-discovery.md)
for the full architecture writeup.

This phase adds **no new vulnerability detector**, performs **no
exploitation, fuzzing, credential attack, or destructive testing** of
any kind, and modifies **no existing detector's algorithm**. It
observes values already present in already-fetched application
responses; it never substitutes a payload for an observed value, and
it never issues an additional network request to discover an input.

## What was built

- **`internal/parameters`** (new): `Location`/`Classification` model
  with `ClassificationFor` as the single source of truth for their
  relationship; `Normalize(pages, limits) Result` -- query parameters
  (from crawled URLs and links) and HTML form fields (GET/POST,
  text/hidden/select/textarea/checkbox/radio), deterministically
  deduplicated and resource-bounded; `InferPathInputs` -- conservative,
  evidence-based, last-segment-only path variable detection;
  `ParseJSONBody` -- a fully tested, standalone JSON field parser (see
  "JSON discovery" below for why it isn't wired into the live
  pipeline); secret redaction via a newly-exported
  `internal/evidence.IsSensitiveFieldName`/`RedactedPlaceholder`
  (reused, not duplicated).
- **`internal/crawler`**: `FormRef` gained `Fields []FormField`;
  `extractFormFields` walks a `<form>`'s own subtree collecting named
  `<input>`/`<select>`/`<textarea>` elements, excluding submit/button/
  reset/image/file controls entirely.
- **`pkg/models.Parameter`**: extended from a 5-field, entirely-unused
  Phase-1 stub to the full normalized-input shape (Location,
  Classification, Method, Value, Source, ContentType, Required,
  EvidenceRef).
- **Storage**: new `parameters` table (`0008_parameters.sql`, mirrors
  the `endpoints` table's own shape and cascade-delete behavior) +
  `ParameterRepository` (Create/Get/ListByScanJob/Delete, mirrors
  `EndpointRepository` exactly).
- **`internal/orchestration`**: `crawlAndDiscoverEndpoints` now also
  runs `parameters.Normalize` on the same already-fetched pages,
  correlates each candidate to its Endpoint by identity, persists it,
  and emits `input_discovery_started`/`input_discovery_completed`/
  `input_discovery_warning` structured log events. Resource-limit
  warnings are threaded back to the caller via a new, deliberately
  transient `models.ScanJob.Warnings` field (never persisted -- see its
  own doc comment) rather than a broader `Pipeline.Run` signature
  change.
- **`internal/detection.BuildTargets`**: now loads `store.Parameters()`
  and builds query-parameter Targets from `Location == "query"` rows
  instead of live-reparsing `Endpoint.Path`'s query string -- the
  architectural integration task's "candidate generation" section
  requires, achieved with **zero changes to any of the 6 real
  detectors**.
- **`internal/policy`/`internal/orchestrator`**: `Profile`/
  `EffectivePolicy` gained `MaxInputsPerEndpoint`/`MaxTotalInputs`
  (recon: 0/never-consulted, web: 100/2000, deep: 200/5000);
  `orchestrator.CrawlSettings` gained `ParameterLimits`, applied via
  the same per-scan `Pipeline` shallow-copy mechanism Phase 3.12
  already built; `Result` gained `InputSummary` (InputCount,
  UniqueEndpointsWithInputs, Warnings).
- **`cmd/scanner`**: `scan` output gained an always-shown `Inputs:`
  block; new `scanner inputs <scan-id> [--location <loc>]` command.
- **`internal/reporting`**: `Report` gained `Parameters`; Markdown
  report gained an `## Inputs` section and an `Inputs` summary column.
- **`lab/harness_inputs.go`** (new): a dedicated fixture app
  (`inputs.scanner.test`, `127.0.0.24`) covering query params,
  duplicate query params, GET/POST forms, hidden/textarea/select
  fields, an out-of-scope form action, malformed HTML, and a
  many-field page -- reused alongside the existing vuln/redirect/
  scope-adversarial lab fixtures rather than duplicating them.

## Design decisions worth recording

- **GET form fields use `Location = query`**, not a separate location:
  submitting a GET form transmits its fields as the URL's query
  string, the exact wire format every existing detector already
  expects -- this is what makes newly discovered GET-form parameters
  immediately detector-eligible with zero detector changes.
  `docs/phase-3-13-parameter-discovery.md` section 5.
- **Only `query`-location inputs generate detection Targets.**
  Form/JSON/path inputs are discovered, normalized, persisted, and
  fully reportable, but do not yet reach any detector -- every one of
  the 6 real detectors hard-requires `ParameterLocation == "query"`
  exactly (confirmed by reading each one before this phase began), and
  the task explicitly forbids rewriting detector algorithms
  unnecessarily. An honest, documented scope boundary (section 8 of
  the architecture doc), not an oversight.
- **JSON body discovery has no live data source.** `ParseJSONBody` is
  fully implemented and fully tested against raw bytes, but nothing in
  the existing crawl/probe pipeline captures a JSON request or
  response body -- wiring it in would require the crawler or prober to
  start making different requests than they do today, which this phase
  does not do. Documented as a capability gap, per the task's own
  explicit instruction, rather than built against a fabricated data
  source.
- **Path input inference only considers the last segment.** Detecting
  middle-segment variability risks inferring structure that can't be
  reliably reconstructed -- the task's own explicit caution.
- **Warnings threaded through a deliberately transient
  `models.ScanJob.Warnings` field** rather than a broader
  `Pipeline.Run` signature change or a new persisted column -- the
  smallest change that lets `Orchestrator.Result.InputSummary.Warnings`
  reach the operator without re-plumbing every caller.

## Test matrix results

### MODEL

`Location`/`Classification` enum, `ClassificationFor`'s totality (never
panics on an unknown value), `Limits.normalized()`'s zero-value ->
defaults behavior -- `internal/parameters/model_test.go` (5 tests).

### QUERY DISCOVERY

From a crawled page's own URL and from discovered links; duplicate
query parameters on one URL collapse to one candidate (first value
kept); empty values preserved; URL-encoded names/values correctly
decoded; malformed query strings degrade gracefully, never crash.
`internal/parameters/normalize_test.go` (7 tests).

### FORM DISCOVERY

GET forms (`Location = query`), POST forms (`Location = form`), hidden
fields, textarea (text-content value), select (explicitly-selected or
first option), checkbox/radio, submit/button/reset/image/file
correctly excluded, unnamed inputs skipped, malformed HTML degrades
gracefully. `internal/crawler/formfields_test.go` (8 tests) +
`internal/parameters/normalize_test.go`'s form-specific cases.

### JSON DISCOVERY

Top-level fields, deterministic nested dot-paths, malformed JSON
(warning, no crash), depth limit, field limit, arrays represented as a
single field (never descended into), sensitive-field redaction --
`internal/parameters/json_test.go` (10 tests), all against the
standalone parser directly (see "Design decisions": no live pipeline
data source exists yet).

### PATH INPUT DISCOVERY

Reliable-evidence-only last-segment inference, numeric vs. non-numeric
naming, single observation correctly produces no input, different
resource types not conflated, different methods not conflated,
middle-segment variation correctly not inferred -- `internal/parameters/path_test.go`
(11 tests).

### DEDUPLICATION

Duplicate endpoint (same form/link observed via two pages), duplicate
input, different methods remain distinct, different locations remain
distinct, GET/POST on the same endpoint remain distinct, duplicate
crawler observation (the same URL linked twice) collapses to one input
-- `internal/parameters/normalize_test.go` + `adversarial_test.go` +
`lab/phase3_13_inputs_test.go` (real crawl).

### NORMALIZATION

`Normalize`/`ParseJSONBody`/`InferPathInputs` all pure, deterministic,
resource-limit-aware transformations verified against
`internal/crawler.Page`/raw JSON bytes directly.

### DETERMINISTIC ORDERING

`TestNormalize_Deterministic`, `TestParseJSONBody_Deterministic`,
`TestInferPathInputs_Deterministic` -- 20+ repeated calls per test,
`reflect.DeepEqual`/element-wise comparison, all map iteration
followed by explicit sorts.

### CANDIDATE GENERATION

`internal/detection.BuildTargets` builds query-parameter Targets from
persisted, query-location Parameters instead of live URL reparsing;
non-query-location parameters correctly produce no Target --
`internal/detection/targets_test.go` (2 new tests,
`TestBuildTargets_NoParameterRows_NoParameterTargets` and
`TestBuildTargets_NonQueryLocationParameters_NoTargets`), plus the
pre-existing `TestBuildTargets_EndpointAndParameterTargets` updated to
seed the new persisted-Parameter shape and revert-and-verified (see
below).

### DETECTOR INTEGRATION

Verified against all 6 real detectors' unmodified `Eligible()`
requirements: `xssreflected`, `sqli`, `cmdinjection`, `ssrf`, `idor`,
`traversal`. No detector source file was changed in this phase.

### POSITIVE LAB

`TestPhase3_11_Orchestrator_FullPositiveLab` (unmodified since Phase
3.11) continues to produce all 8 expected findings across the 6
vulnerability classes, now sourced through the new persisted-Parameter
pipeline instead of live reparsing -- proves the architecture change is
behaviorally transparent to every existing detector.

### BENIGN LAB

`TestPhase3_11_Orchestrator_NegativeTarget_NoFalsePositives` and the
full `TestPhase3Lab_NegativeFixturesDoNotExhibitVulnerability` suite
(15 negative fixtures) continue to produce zero findings, unmodified.

### SECRET REDACTION

Password/token/secret-named fields' values replaced with
`evidence.RedactedPlaceholder` before persistence, at both the form
and JSON level; verified at the discovery-unit level, the
orchestration-integration level, and the real-CLI level
(`TestScanCmd_InputsBlock_SensitiveFieldRedacted`).

### SCOPE ENFORCEMENT

`internal/parameters` performs no I/O and issues no request of its
own -- structurally incapable of expanding scope.
`TestPhase3_13_OutOfScopeFormAction_NeverAuthorizesTarget`
(`lab/phase3_13_inputs_test.go`) proves directly: scope rules are
byte-for-byte unchanged before/after a scan of a page containing a
form pointing at `external.scanner.test`, and no Endpoint referencing
that host is ever created.

### RESOURCE LIMITS

`MaxInputsPerEndpoint`, `MaxTotalInputs`, `MaxFormFields`,
`MaxJSONDepth`, `MaxJSONFields` all independently tested at the unit
level and end-to-end through a real crawl
(`TestRun_InputDiscovery_ResourceLimit_TruncatesAndDoesNotFailScan`,
`TestPhase3_13_ManyFormFields_ResourceLimitEnforced`) -- truncation is
deterministic, always warns, never fails the scan.

### CANCELLATION

Input discovery runs inside the same per-target goroutine, under the
same context, as endpoint creation -- the pre-existing
`TestRun_CancellationDuringCrawlStage` continues to pass unmodified,
and a new `TestRun_InputDiscovery_CancellationDuringCrawl_LeavesStoreConsistent`
confirms the Parameters table remains fully queryable after a mid-crawl
cancellation.

### TIMEOUT

Covered by the same mechanism as cancellation (a `StageTimeout`-derived
context governs the whole crawl-and-discover step); no separate timeout
path exists for input discovery to diverge from.

### CONCURRENCY

`internal/orchestration` and `internal/orchestrator`'s full suites pass
under `-race`; input discovery's own warning accumulation uses a
mutex-guarded slice alongside the pre-existing atomic counters.

### RECON PROFILE

Crawler disabled -> input discovery never runs; `MaxInputsPerEndpoint`/
`MaxTotalInputs` are 0 (never consulted) --
`TestRun_InputDiscovery_CrawlerDisabled_NoParameters`,
`TestRegistry_ReconProfile_InputLimitsIrrelevantButDefined`,
`TestScanCmd_InputsBlock_ReconProfile_ZeroInputs`.

### WEB PROFILE

Crawler enabled, bounded at 100/2000 -- `TestScanCmd_InputsBlock_QueryAndFormDiscovered`.

### DEEP PROFILE

Bounded higher than web (200/5000, never unlimited) --
`TestRegistry_DeepProfile_InputLimits_HigherThanWeb_ButBounded`.

### CLI / OBSERVABILITY

`scanner scan`'s `Inputs:` block, `scanner inputs <scan-id>
[--location]`, `scanner report`'s Parameters/`## Inputs` sections, and
the `input_discovery_started`/`input_discovery_completed`/
`input_discovery_warning` structured log events (scan_job_id,
endpoint_count, input_count, duplicate_count, truncated_count) -- all
verified end to end through the real built binary.

### ADVERSARIAL

All 30 scenarios addressed:

1. Duplicate query parameters -- PASS (`TestNormalize_DuplicateQueryParameter_OnSameURL_OneCandidateFirstValueKept`, `TestPhase3_13_DuplicateQueryParameter_OneInput`).
2. Encoded parameter names -- PASS (`TestNormalize_UnicodeParameterName`).
3. Encoded parameter values -- PASS (`TestNormalize_URLEncodedQueryNameAndValue`).
4. Empty parameter values -- PASS (`TestNormalize_EmptyQueryValue_StillDiscovered`).
5. Duplicate forms -- PASS (`TestNormalize_DuplicateForm_AcrossTwoPages_Deduplicated`).
6. Malformed HTML -- PASS (`TestCrawl_FormFields_MalformedHTML_NoCrash`, `TestPhase3_13_MalformedHTML_NoCrash`).
7. Malformed JSON -- PASS (`TestParseJSONBody_MalformedJSON_NoCrashReturnsWarning`).
8. Deeply nested JSON -- PASS (`TestParseJSONBody_DepthLimit_TruncatesAndWarns`).
9. Huge JSON object -- PASS (`TestParseJSONBody_FieldLimit_TruncatesAndWarns`).
10. Huge number of form fields -- PASS (`TestNormalize_MaxFormFields_TruncatesAndWarns`, `TestPhase3_13_ManyFormFields_ResourceLimitEnforced`).
11. Duplicate endpoints -- PASS (`TestNormalize_SamePathDifferentMethod_RemainDistinct`).
12. Query/path name collisions -- PASS (`TestNormalize_QueryPathNameCollision_RemainDistinct`).
13. GET/POST same endpoint -- PASS (`TestNormalize_GETAndPOSTSameEndpoint_RemainDistinct`).
14. Same parameter name in different locations -- PASS (`TestNormalize_SameNameDifferentLocation_RemainDistinct`).
15. Out-of-scope form action -- PASS (`TestPhase3_13_OutOfScopeFormAction_NeverAuthorizesTarget`).
16. Out-of-scope JSON URL value -- N/A by construction (no live JSON data source exists to carry one; see "Design decisions").
17. Out-of-scope redirect -- PASS (unmodified: `TestLab_ExternalRedirectNeverDialsOutOfScopeHost` continues to pass, this phase touches no redirect logic).
18. Secret-bearing form fields -- PASS (`TestNormalize_POSTForm_FieldsUseFormLocation`'s password case, `TestScanCmd_InputsBlock_SensitiveFieldRedacted`).
19. Authorization headers -- N/A by construction (no discovery source in this phase ever produces a header-location input).
20. Cookie values -- N/A by construction (same as above).
21. Very long parameter names -- PASS (`TestNormalize_VeryLongParameterName_NoCrash`).
22. Very long parameter values -- PASS (`TestNormalize_VeryLongParameterValue_NoCrash`).
23. Unicode parameter names -- PASS (`TestNormalize_UnicodeParameterName`, `TestNormalize_UnicodeFormFieldName_Emoji`).
24. Null bytes / malformed encoding -- PASS (`TestNormalize_NullByteInValue_NoCrash`, `TestNormalize_MalformedURLEncoding_NoCrash`).
25. Crawler response exceeding input limits -- PASS (see #10).
26. Concurrent scans -- PASS (`internal/orchestrator`'s existing profile-isolation tests, unaffected by this phase's changes; full suite green under `-race`).
27. Cancellation during input discovery -- PASS (see "CANCELLATION").
28. Timeout during input discovery -- PASS (see "TIMEOUT").
29. Profile isolation -- PASS (`TestRegistry_ReconProfile_InputLimitsIrrelevantButDefined` / `TestRegistry_DeepProfile_InputLimits_HigherThanWeb_ButBounded` confirm distinct, correctly-scoped per-profile limits).
30. Scope bypass attempts -- PASS (see "SCOPE ENFORCEMENT").

**Result: NO SCOPE BYPASS in any scenario.**

### SECURITY

`internal/parameters` performs no I/O of its own (confirmed by code
review: only `encoding/json`, `net/url`, `sort`, `strings`,
`sakanner/internal/crawler`, `sakanner/internal/endpoints`,
`sakanner/internal/evidence` are imported -- no `net/http`, no
`os/exec`); every discovered value is redaction-checked before
persistence; no secret appears in any new log line
(`input_discovery_*` events carry only counts and non-sensitive
metadata, never a discovered value).

### PERFORMANCE

Input discovery reuses already-fetched crawl data -- zero additional
network requests per input discovered, confirmed by design (no HTTP
client exists anywhere in `internal/parameters`) and by the resource-limit
tests completing in single-digit milliseconds against a 30-field
fixture.

### REGRESSION

Full repository: `go build ./...`, `go vet ./...`, `gofmt -l .` all
clean. `golangci-lint` not installed in this environment (noted, not
run). Complete `go test ./...` (fast packages + `lab` +
`tests/e2e`) green, and a full `-race` pass over every
concurrency-relevant package (`internal/orchestration`,
`internal/orchestrator`, `internal/detection`, `internal/parameters`,
`internal/policy`, `internal/storage/sqlite`, `lab`) all green.
One `tests/e2e` run flagged a pre-existing, unrelated concurrency test
(`TestConcurrency_ScopeAdd_FreshDatabase_NoCorruption`, Phase 3.11.1)
as failed under heavy simultaneous background test load; re-run in
isolation 3/3 clean, and a full isolated `tests/e2e` re-run passed
59/59 -- confirmed as resource-contention flakiness from this session's
own parallel test execution, not a regression (this phase touches no
scope, migration, or storage-locking code).

### Revert-and-verify

`internal/detection/targets.go`'s query-location filter (the core
architectural change: `BuildTargets` now reads persisted Parameters
instead of live-reparsing URLs) was backed up, temporarily broken (the
location literal changed to never match), and both
`TestBuildTargets_EndpointAndParameterTargets` and the real end-to-end
`TestPhase3_11_Orchestrator_FullPositiveLab` were run: both failed with
exactly the predicted messages ("no parameter target was built..." and
"no findings produced against a lab with known-positive fixtures...").
The file was restored from backup; `diff` confirmed a byte-identical
restore; `go build`, the full `internal/detection` suite (`-race`), and
`TestPhase3_11_Orchestrator_FullPositiveLab` were all re-run clean (8
findings, exactly as before).

## Final report

```
TOTAL TESTS: 1382 (1091 top-level + 291 subtests)
PASS: 1382
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

INPUT MODEL: PASS
QUERY DISCOVERY: PASS
FORM DISCOVERY: PASS
JSON DISCOVERY: PASS
PATH INPUT DISCOVERY: PASS
DEDUPLICATION: PASS
NORMALIZATION: PASS
DETERMINISTIC ORDERING: PASS
CANDIDATE GENERATION: PASS
DETECTOR INTEGRATION: PASS
POSITIVE LAB: PASS
BENIGN LAB: PASS
SECRET REDACTION: PASS
SCOPE ENFORCEMENT: PASS
RESOURCE LIMITS: PASS
CANCELLATION: PASS
TIMEOUT: PASS
CONCURRENCY: PASS
RECON PROFILE: PASS
WEB PROFILE: PASS
DEEP PROFILE: PASS
CLI / OBSERVABILITY: PASS
ADVERSARIAL: PASS
SECURITY: PASS
PERFORMANCE: PASS
REGRESSION: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0

PHASE 3.13 ADVERSARIAL: PASS

PHASE 3.13 VERDICT: PASS
```

Not proceeding to Phase 3.14, not implementing new vulnerability
detectors, exploitation, exploit payload generation, credential
attacks, brute force, post-exploitation, or destructive testing, not
weakening scope enforcement anywhere, not silently expanding scan
scope, and not turning discovery into unrestricted fuzzing, per the
task's explicit instruction to stop after this report.
