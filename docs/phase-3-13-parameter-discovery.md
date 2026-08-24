# Phase 3.13: Parameter & Input Discovery Engine

## 1. Purpose

Before this phase, "what can a detector test" was decided entirely by
`internal/detection.BuildTargets` re-parsing the query string on an
already-crawled `models.Endpoint`'s path, live, every time detection
ran. Nothing represented an HTML form's fields at all -- `models.Endpoint`
had no field list, and every detector's own doc comment (and
`docs/phase-3-1-detection-engine.md`) honestly documented this as a
known capability gap.

The Parameter & Input Discovery Engine (`internal/parameters`) closes
that gap: it discovers and normalizes every application input sakanner
can reliably observe -- URL query parameters, HTML form fields (GET and
POST), and (where evidence supports it) variable URL path segments --
into one canonical `pkg/models.Parameter` representation, persisted
once per scan, that both existing detectors and future reporting can
consume without re-parsing anything themselves.

This phase adds **no new vulnerability detector** and performs **no
exploitation, fuzzing, or payload injection** of any kind -- it
observes values already present in already-fetched application
responses.

## 2. Architecture

```
Target
 -> Recon
 -> Crawler                          (internal/crawler, extended: forms now carry Fields)
 -> Endpoint Discovery                (internal/endpoints.Normalize)
 -> Parameter & Input Discovery       (internal/parameters.Normalize)     <- NEW
 -> Normalized Input Model            (pkg/models.Parameter, persisted)   <- NEW
 -> Detector Candidate Generation     (internal/detection.BuildTargets, extended)
 -> Existing Detectors                (unmodified: xssreflected, sqli, cmdinjection, ssrf, idor, traversal)
```

`internal/parameters` is a pure, I/O-free package -- exactly like
`internal/endpoints.Normalize`, which it deliberately mirrors: given
already-fetched `[]crawler.Page` data, it returns a deterministic
`Result{Candidates, Warnings, DuplicateCount}`. It performs no network
requests of its own ("discovery must not become 100 inputs -> 100
network requests" -- task's explicit requirement).

`internal/orchestration.Pipeline.crawlAndDiscoverEndpoints` calls
`parameters.Normalize` on the SAME pages it already fetched for
`endpoints.Normalize`, in the same per-target goroutine, immediately
after creating that target's `Endpoint` rows -- so it can correlate
each discovered `Candidate` back to the exact `Endpoint.ID` it belongs
to (both functions compute the identical `(path, method, source)`
identity from the same page data) before persisting it as a
`models.Parameter`.

`internal/detection.BuildTargets` no longer re-parses `Endpoint.Path`'s
query string live -- it loads `store.Parameters()`, filters to
`Location == "query"`, and turns those into the exact same
`Target{Parameter, ParameterLocation: "query"}` shape it always
produced, so every existing detector's `Eligible()` check continues to
match Targets exactly as before. See section 8.

## 3. Input sources implemented

| # | Source | Where | Status |
|---|---|---|---|
| 1 | URL query parameters | `internal/parameters.addQueryCandidates`, from a crawled page's own URL or a discovered link | Implemented |
| 2 | HTML form fields | `internal/crawler.extractFormFields` (new) + `internal/parameters.addFormCandidates` | Implemented |
| 3 | GET form parameters | Same as above; `Location = query` (see section 5) | Implemented |
| 4 | POST form parameters | Same as above; `Location = form` | Implemented |
| 5 | Text input fields | `internal/crawler.extractFormFields` (`type="text"` and the HTML default when `type` is omitted) | Implemented |
| 6 | Hidden input fields | `type="hidden"` | Implemented |
| 7 | Select fields | `<select>`, value = the explicitly `selected` `<option>`, or the first `<option>` otherwise | Implemented |
| 8 | Textarea fields | `<textarea>`, value = its text content | Implemented |
| 9 | Checkbox/radio fields | `type="checkbox"`/`type="radio"` | Implemented (discovery only; every occurrence is kept, including repeated same-named radio options, so no value is silently lost) |
| 10 | JSON request bodies | `internal/parameters.ParseJSONBody` | Implemented as a **standalone, fully tested parser** -- **not wired into the live pipeline** (see section 6: no existing capture point has a real JSON body to hand it) |
| 11 | URL path segments | `internal/parameters.InferPathInputs` | Implemented, conservatively (see section 7) |
| 12 | Existing endpoint metadata | Endpoint identity (`path`/`method`/`source`) reused from `internal/endpoints.Normalize`, never re-derived independently | Implemented |

Submit/button/reset/image/file `<input>` controls are excluded from
discovery entirely (`crawler.nonInputControlTypes`) -- task's "do not
treat submit buttons as vulnerability parameters," extended to file
uploads (this phase implements no file upload of any kind, and a
file's meaningful surface is its content, not a string value this
model represents).

## 4. The normalized input model

`pkg/models.Parameter`:

```go
type Parameter struct {
    ID, ScanJobID, EndpointID string
    Name           string
    Location       string // query, path, form, json, header, cookie
    Classification string // PARAMETER, PATH_INPUT, FORM_FIELD, JSON_FIELD (derived from Location, never independent)
    Method         string
    Value          string // observed value, redacted if the name looks sensitive
    Source         string // url_query, html_form, json_body, path_inference
    ContentType    string
    Required       *bool  // nil unless discovery evidence actually established it
    EvidenceRef    string
    CreatedAt      time.Time
}
```

`Location` is the closed, explicit vocabulary task requires --
`internal/parameters.Location`'s 6 constants. `Classification` is
**always** derived from `Location` via `parameters.ClassificationFor`,
never set independently, so the two can never disagree ("the location
remains authoritative").

## 5. Location semantics: why GET form fields use `query`

A GET form field is modeled with `Location = query`, not a dedicated
"GET form" location, because that is where its value is actually
transmitted: submitting a GET form serializes its fields into the
URL's query string -- the exact wire format the 6 existing detectors
already understand. This is deliberate, and is what makes newly
discovered GET-form parameters immediately eligible for detection with
**zero detector changes** (see section 8).

`Source` (a separate field: `url_query` vs `html_form`) still records
*how* the input was found, so a query parameter observed directly on a
crawled URL and one recovered from a GET form's fields remain
distinguishable in the data, even though they share a `Location`.

## 6. JSON body discovery: an honest capability gap

`internal/parameters.ParseJSONBody(body []byte, limits Limits) Result`
is fully implemented and fully tested (`internal/parameters/json_test.go`):
top-level fields, deterministic dot-path nested fields
(`user.address.city`), a configurable depth limit, a configurable
field-count limit, and graceful handling of malformed JSON (a
warning, never a panic or an aborted scan).

**Nothing in the live pipeline calls it.** Neither `internal/crawler`
(which only ever issues GET requests) nor `internal/http.Prober`
(which discards the response body after technology fingerprinting,
and never issues anything but GET either) captures a JSON request or
response body anywhere today. Wiring `ParseJSONBody` into the live
pipeline would require either the crawler or prober to start making
different requests than they currently do -- a change this phase
deliberately does not make, per its own explicit "do not introduce
active behavior beyond passive extraction from what crawling already
fetches."

This is the same discipline `docs/phase-3-1-detection-engine.md`
already established for query-string-only parameter discovery, and
`katana.go`'s own documented limitations: **a real, honest capability
gap is documented, not silently worked around with a fabricated data
source or a fragile heuristic.** The moment a future phase adds real
JSON body capture, `ParseJSONBody` is ready to consume it immediately.

## 7. Path input inference: why only the last segment

`internal/parameters.InferPathInputs` looks for RELIABLE evidence that
a URL's LAST path segment is variable: at least two endpoints, same
HTTP method, identical in every segment except the last, where the
last segment's observed value differs (e.g. `/users/123` and
`/users/456`). It does **not** attempt to detect variability at an
arbitrary middle segment (e.g. `/users/123/edit` vs `/users/456/profile`
does not infer position 1 is variable) -- reasoning about combinations
of positions risks inferring structure that cannot be reliably
reconstructed, which is exactly what the task's "do not invent
semantics that cannot be reconstructed" warns against. This is a
deliberate, documented scope boundary.

Naming is a conservative heuristic, not a guarantee: the preceding
static segment, trailing "s" stripped (`users` -> `user`), suffixed
`_id` when every observed value is purely numeric, else `_value`; a
single-segment path with no preceding static segment falls back to the
generic name `segment_id`/`segment_value`.

Path-location inputs are discovered, normalized, and persisted, but --
like form/JSON inputs -- do not yet feed any detector (see section 8).

## 8. Detector compatibility: why only `query`-location inputs generate Targets

All 6 real detectors (`xssreflected`, `sqli`, `cmdinjection`, `ssrf`,
`idor`, `traversal`) hard-require `Target.ParameterLocation == "query"`
exactly, in every one of their `Eligible()` methods -- confirmed by
reading every detector's source before this phase began. This phase
does **not** modify any detector, per its own explicit "do not rewrite
detector algorithms unnecessarily."

`internal/detection.BuildTargets` therefore only turns `Location ==
"query"` Parameters into detection Targets -- form (`Location ==
"form"`), JSON (`Location == "json"`), and path (`Location == "path"`)
inputs are discovered, normalized, persisted, and fully reportable
(`scanner inputs`, `scanner report`), but do not yet reach any
detector. This is an honest, documented scope boundary, not an
oversight: extending detector eligibility to non-query locations is
future work, out of this phase's stated scope ("do not change the
vulnerability logic unless required to consume the new model" --
consuming query-location inputs required no detector change at all,
since GET-form fields already arrive shaped exactly like a query
parameter; consuming form/JSON/path inputs would).

Task's own acceptance criterion 7 ("existing detectors receive
normalized candidates") is satisfied for the location every detector
actually consumes: `BuildTargets` no longer parses a raw URL itself for
that purpose (`Existing detectors should not have to parse ... raw
URLs themselves` -- literally true now for the query-parameter path,
which is sourced from the persisted, deduplicated Parameters table,
not a live `url.ParseQuery` call).

## 9. Resource limits

`internal/parameters.Limits`:

| Field | Default | Purpose |
|---|---|---|
| `MaxInputsPerEndpoint` | 100 | Bounds candidates kept per endpoint |
| `MaxTotalInputs` | 2000 | Bounds candidates kept per whole scan |
| `MaxFormFields` | 200 | Bounds fields read from any one `<form>` |
| `MaxJSONDepth` | 10 | Bounds `ParseJSONBody`'s object nesting |
| `MaxJSONFields` | 500 | Bounds `ParseJSONBody`'s total fields |

Reaching a limit truncates deterministically (never an arbitrary
subset -- `Normalize`'s own stable sort runs before truncation) and
always appends a warning string to `Result.Warnings`; it never fails
the scan. These warnings are threaded up through
`internal/orchestration.Pipeline.Run`'s returned `models.ScanJob.Warnings`
field (a deliberately transient, non-persisted field -- see its own
doc comment) into `internal/orchestrator.Result.InputSummary.Warnings`,
so an operator sees them without having to read logs.

## 10. Profile interaction

Input discovery has **no independent enable/disable toggle** -- it is
gated by, and runs entirely inside, the same crawl step
`Pipeline.CrawlEnabled` already gates (task's own "PROFILE
INTERACTION: input discovery should remain disabled unless the
existing recon implementation already performs passive input
extraction ... do not introduce active behavior"). Since discovery only
ever reads pages the crawler already fetched, "crawling is on" already
means "passive extraction from that crawl is on" -- there is nothing
further to toggle.

- **`recon` profile**: crawler disabled -> input discovery never runs.
  `MaxInputsPerEndpoint`/`MaxTotalInputs` are 0 on this profile,
  documented as never-consulted (mirrors `CrawlMaxDepth`/`CrawlMaxPages`'s
  own 0-when-irrelevant convention).
- **`web` profile**: crawler enabled -> input discovery enabled, bounded
  at `parameters.DefaultLimits()`'s own values (100/2000).
- **`deep` profile**: crawler enabled with wider bounds -> input
  discovery enabled with correspondingly wider (but still finite)
  bounds (200/5000).

`internal/orchestrator.CrawlSettings` (Phase 3.12's per-scan override
struct) gained a `ParameterLimits parameters.Limits` field, applied via
the exact same per-scan `Pipeline` shallow-copy mechanism
`CrawlEnabled`/`CrawlMaxDepth`/`CrawlMaxPages` already use -- no new
override mechanism was invented.

## 11. Scope enforcement

**Input discovery cannot expand scope, under any circumstance.** It
operates entirely on already-fetched page content; it makes no request
of its own. A form whose `action` points to an out-of-scope host, or a
JSON value that happens to look like a URL, is recorded (where
discovered) purely as data -- the referenced host is never dialed,
never added to scope, and never becomes a scan target.
`TestPhase3_13_OutOfScopeFormAction_NeverAuthorizesTarget`
(`lab/phase3_13_inputs_test.go`) proves this directly: scope
rules are byte-for-byte unchanged before/after a scan whose in-scope
page contains a form pointing at `external.scanner.test`, and no
Endpoint referencing that host is ever created.

## 12. Secret redaction

Every discovered value is checked against
`internal/evidence.IsSensitiveFieldName` (a small, newly-exported
wrapper around evidence's own existing blocklist -- reused, not
duplicated) before being persisted; a match replaces the value with
`internal/evidence.RedactedPlaceholder`. `Authorization`/`Cookie`/
`Set-Cookie` are never modeled as discoverable inputs in the first
place (no discovery source in this phase produces `header`/`cookie`
location inputs at all -- see section 3's table).

## 13. CLI

- `scanner scan <target> --profile ...` output gained an `Inputs:`
  block (Discovered / Unique endpoints with inputs / Warnings),
  unconditionally shown, mirroring the Detection block's own
  always-shown precedent.
- `scanner inputs <scan-id> [--location <loc>]` (new) lists every
  discovered input for a scan job.
- `scanner report` (JSON and Markdown) gained a `Parameters`/`## Inputs`
  section.

## 14. Determinism

`Normalize`, `ParseJSONBody`, and `InferPathInputs` are all pure
functions with no dependency on map iteration order, goroutine
completion order, wall-clock time, or randomness -- every internal map
use is followed by an explicit sort before producing output. The same
input always produces byte-identical output
(`TestNormalize_Deterministic`, `TestParseJSONBody_Deterministic`,
`TestInferPathInputs_Deterministic`).

## 15. Limitations

- Header/cookie input discovery is not implemented -- no existing
  capture mechanism identifies application-controlled custom headers
  (task's own conditional: "if existing request capture identifies
  application-controlled custom inputs, the model MAY represent
  them" -- none does today).
- JSON body discovery has no live data source (section 6).
- Form/JSON/path-location inputs do not yet feed any detector (section 8).
- Path input inference only detects last-segment variability (section 7).
- The katana external-crawler backend produces no `Forms`/`Links` data
  at all (a pre-existing, Phase 2-documented limitation --
  `internal/crawler/katana.go`), so form-field discovery only has real
  data to work with when the native crawler backend is in use.
