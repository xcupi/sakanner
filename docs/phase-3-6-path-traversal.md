# Phase 3.6: Path Traversal Detector

sakanner's fifth real vulnerability detector. Implements
`detection.Detector` (`internal/detection`, Phase 3.1) unchanged --
nothing in the framework was modified to build this; see
[docs/phase-3-1-detection-engine.md](phase-3-1-detection-engine.md)
"How to implement a new detector" for the contract this follows, and
[docs/phase-3-5-idor-bola.md](phase-3-5-idor-bola.md) for the sibling
detector whose "registered but disabled, dependency-injected known-case
knowledge" pattern this one also uses.

**Path traversal / controlled LFI**: unsanitized path-like input
reaching a file/resource lookup, allowing access outside an intended
directory root. This detector tests for exactly that behavior -- it
never reads a real file, never enumerates a filesystem, and never goes
beyond confirming that a specific, known, synthetic protected resource
was returned when it should have been denied.

## Core security principle

This detector must never read arbitrary files from the scanner's own
filesystem, and must only interact with controlled targets inside the
Phase 3 Test Lab. Every "path" this package ever handles is data
carried in an HTTP request or response -- never an argument to a local
filesystem API. See "Scanner filesystem safety" below for how this is
enforced and tested, not just asserted.

All vulnerability validation uses synthetic files created specifically
for the test lab (`PATH_TRAVERSAL_SECRET_MARKER`, `PUBLIC_FILE_MARKER`)
-- never `/etc/passwd`, Windows credential files, SSH keys, cloud
credentials, or any other real sensitive path.

## What this detector does NOT do

Per the task's explicit scope boundary, none of the following are
implemented, attempted, or in any way exercised by this package:

- **Reading real OS files** -- every fixture this detector is verified
  against is a synthetic, in-memory map (`lab/harness_vuln.go`'s
  `travSynthFS`); this package itself never calls `os.Open`,
  `os.ReadFile`, or any other local-file-reading API (see "Scanner
  filesystem safety").
- **Accessing `/etc/passwd`, Windows SAM/SYSTEM hives, SSH keys, cloud
  credentials, or application secrets** -- never targeted, never
  referenced as a probe payload anywhere in this codebase.
- **Filesystem enumeration** -- the detector tests exactly the
  operator-configured `TraversalCase` values it's given; it never
  brute-forces directory listings or guesses at unknown paths.
- **Arbitrary file download** -- a confirmed finding proves the
  *capability* exists (a specific known synthetic resource was
  returned); nothing about confirming it downloads, saves, or exposes
  arbitrary target content to the operator.
- **LFI/RFI exploitation, remote code execution, command injection** --
  out of scope entirely; this is detection of an access-control defect,
  never an attempt to leverage one.
- **Executing retrieved file content** -- responses are only ever
  compared as bytes/strings; nothing is parsed, interpreted, or
  executed.
- **Post-exploitation** -- detection stops the moment evidence is
  gathered; no finding ever triggers a further, more invasive probe.

## Architecture

```
internal/detectors/traversal/
├── detector.go              Detector, Metadata, Eligible, Detect, finding construction
├── cases.go                  TraversalCase -- the operator-configured known-case knowledge
├── variants.go                traversalVariants -- small, deterministic encoding-variant generator
└── normalize.go                normalizeBody / stripPayload / looksAllowed / containsMarker

lab/harness_vuln.go   registerPathTraversalAPI -- the query-parameter-
                             based /files/download/* fixture family

cmd/scanner/detectors.go    productionRegistry() registers traversal.New(nil),
                             then disables it -- see "Known traversal cases"
```

## Known traversal cases

Task section 7 is explicit: "The probes should target ONLY the
synthetic protected file in the local test lab" -- this detector is not
a general unknown-target fuzzer. It cannot invent knowledge of what a
real target's protected resource is, any more than
[the SSRF detector](phase-3-4-ssrf.md) can invent knowledge of an
internal network's layout, or
[the IDOR detector](phase-3-5-idor-bola.md) can invent knowledge of who
owns a resource. All three resolve this the same way: a small,
constructor-injected dependency carrying operator-supplied ground
truth.

```go
type TraversalCase struct {
    RelativePath string // canonical, unencoded traversal representation
    Marker       string // byte sequence confirming the SPECIFIC protected resource
}
```

`RelativePath` is the canonical form (e.g.
`"../protected/secret-marker.txt"`); the detector derives a small,
fixed set of alternative wire encodings from it itself (see "Encoding
handling") -- the operator does not enumerate encodings. `Marker` is
never a real secret; in the lab, the literal string
`PATH_TRAVERSAL_SECRET_MARKER`.

`New(cases []TraversalCase) *Detector` requires **at least 1**
configured case; with none (including nil/empty), every `Detect` call
returns `OutcomeSkipped` rather than doing anything
(`TestDetect_NoConfiguredCases_Skipped`).

**Not wired into production**: like `ssrf.New(nil)` and `idor.New(nil)`,
`cmd/scanner/detectors.go`'s `productionRegistry()` registers
`traversal.New(nil)` and immediately disables it
(`r.SetEnabled(traversal.ID, false)`) -- `scanner detectors list` shows
it exists, and its `Prerequisites` metadata field explains what's
missing. This build ships no mechanism for automatically discovering
what a real target's protected resources are; that is deliberately out
of scope (task section 5 permits, but does not require, this detector
to invent that knowledge -- and section 9's evidence requirements make
inventing it unsafe to attempt).

## Candidate selection

```go
SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint}
SupportedMethods:     []string{http.MethodGet}
```

plus `Eligible(t)` requiring the parameter's **name** to match one of
the task's own thirteen examples: `file`, `filename`, `filepath`,
`path`, `file_path`, `document`, `document_path`, `template`,
`resource`, `download`, `attachment`, `image`, `directory`
(case-insensitive).

**Path-segment object references are out of reach**, the same
documented limitation `xssreflected`/`sqli`/`ssrf`/`idor` all carry:
Phase 3.1's `detection.BuildTargets` only extracts candidate parameters
from QUERY strings, never path segments. The *original* Phase 3 lab
fixture, `/files/traversal/vulnerable` (parameter `name`, predates this
phase), remains permanently undetectable for a second, independent
reason too: its parameter name (`name`) isn't in this detector's
heuristic list at all. Its ground-truth entry
(`VULN-TRAVERSAL-001`) documents this precisely. A **new**,
query-parameter-based fixture family
(`/files/download/vulnerable`+siblings, parameter `file`) was added to
the lab specifically so this detector has something to actually detect
-- see "Test lab architecture" below.

## Test lab architecture

`lab/harness_vuln.go`'s `travSynthFS` is a flat, in-memory map --
never the real filesystem -- keyed by CLEAN, relative-to-lab-root
paths:

```
public/index.html            -- PUBLIC_FILE_MARKER (plus decorative "../" text, see below)
public/public-marker.txt     -- PUBLIC_FILE_MARKER
protected/secret-marker.txt  -- PATH_TRAVERSAL_SECRET_MARKER
```

`public/` is the allowed root every fixture is meant to restrict access
to; `protected/` is a sibling directory a real application would never
expose through the download endpoint -- escaping into it via `../` is
exactly the vulnerability class this phase detects (task section 4's
ground truth: allowed root `public/`, protected resource
`protected/secret-marker.txt`).

Six new endpoints under `/files/download/*` (see
`registerPathTraversalAPI`):

| Endpoint | Behavior | Role |
|---|---|---|
| `/files/download/vulnerable` | `path.Clean(path.Join("public", file))`, no containment check | **Positive** |
| `/files/download/safe` | Same resolution, but verifies the cleaned result stays under `public/` before use | Proper canonicalization + containment |
| `/files/download/sanitized` | Rejects any DECODED value containing `".."` outright, before path construction | A different (still effective, against this detector's own probe set), blocklist-based strategy |
| `/files/download/by-id` | `file` is only ever an opaque allowlist key (`"1"`, `"2"`), never concatenated into a path | Parameterized/safely-resolved access |
| `/files/download/reflect` | Echoes the requested value; never reads any file content | Reflection-only negative |
| `/files/download/generic` | Fixed `{"status":"ok"}` regardless of input | Generic-200 negative |

## Baseline and traversal probing

For a single candidate `(endpoint, parameter=file, value=<discovered>)`:

1. **Legitimate-access reference.** Probe `t.URL` unchanged (the
   already-discovered value, exactly as `xssreflected`/`sqli`/`ssrf`/`idor`
   all treat their own baselines). Not analyzable (non-text/JSON/XML)
   -> `OutcomeSkipped`. Not allowed (2xx, non-empty) -> `OutcomeNoFinding`
   -- nothing to use as a reference.
2. **Not-found reference.** Probe the SAME parameter with a
   deliberately nonexistent value
   (`sakannerTraversalBaseline-3f8c9a2e-does-not-exist.txt`) --
   characterizes what "denied/not found" looks like for this specific
   endpoint.
3. **Traversal probes.** For every configured `TraversalCase`, for
   every derived encoding variant (bounded, see "Encoding handling"):
   probe with that variant substituted for the parameter.
   - Denied (`!looksAllowed`) -> skip, correctly denied.
   - `containsMarker(body, case.Marker)` -> **confirmed**; stop trying
     further variants for this case (already proven).
   - Otherwise, allowed AND genuinely different from the not-found
     reference (see "Response validation" for exactly how) ->
     **suspicious**.
4. **Decide.** Any confirmed attempt -> one aggregated Finding, HIGH
   tier. No confirmed but some suspicious -> one aggregated Finding,
   MEDIUM tier. Neither -> `OutcomeNoFinding`.

This is a single-target, stateless algorithm -- no state accumulates
across separate `Detect` calls.

## Encoding handling

`traversalVariants(relPath string) []string` derives a small, fixed,
deduplicated set from the canonical `RelativePath` -- explicitly NOT a
payload dictionary (task section 7):

1. **Raw**: `relPath` unchanged (e.g. `../protected/secret-marker.txt`).
2. **Dot-encoded**: every `..` replaced with `%2e%2e`.
3. **Slash-encoded**: every `/` replaced with `%2F`.
4. **Combined**: both replacements applied.

Each variant is sent **verbatim on the wire** -- `requestURL` builds
the request's `RawQuery` by hand rather than through
`url.Values.Encode()`, specifically so an already-percent-encoded
representation is never re-escaped (which would turn `%2e` into `%252e`
and silently defeat the point of testing an encoded representation at
all). `TestRequestURL_SendsPercentEncodedVariantsRawOnWire` proves this
directly, by inspecting `r.URL.RawQuery` on the wire.

**Honest limitation, stated explicitly**: this project's own lab runs
on Go's `net/http`, whose query-string decoding normalizes
single-level percent-encoding (`%2e`, `%2F`) uniformly *before* any
handler ever sees the value -- meaning `/files/download/vulnerable`
succeeds identically for all four representations above (confirmed
directly: `TestDetect_VulnerableTraversal_HighConfidenceFinding` and
the real-lab integration test both pass using whichever representation
the loop reaches first, which is always the raw one). The encoding
variants still matter and are still correctly exercised --
`TestAdversarial_EncodingBypassesNaiveRawBlocklist_StillConfirms`
demonstrates a concrete case where they do: a naive defense that
blocklists the literal `".."` substring on the **raw**, not-yet-decoded
query string blocks the raw representation but is bypassed by an
encoded one, which Go's own decoding still normalizes before the
application's real (still-vulnerable) logic runs. Double-encoded
representations (`%252e%252e%252f`) are deliberately NOT generated --
nothing in this project's lab performs a second decode pass, so testing
for it would exercise a scenario this build can never deterministically
demonstrate either direction of; `TestAdversarial_DoubleEncodedVariantNotEffective_NoFinding`
confirms the detector degrades to a clean `NoFinding`, never a false
assumption, when none of its representations happen to match.

## Response validation

Two independent checks (`normalize.go`), mirroring the discipline
`idor`/`ssrf` established:

- **`looksAllowed(statusCode, body)`** -- 2xx status AND non-empty body.
  Distinguishes denial (401/403/404/app-specific) from actual access;
  status alone is never the whole story.
- **`containsMarker(body, marker)`** -- `bytes.Contains`, with an empty
  marker guarded to never trivially match. Task section 9's "strong
  evidence: protected synthetic marker appears in response."

### The reflected-parameter false positive, encountered and fixed here too

The MEDIUM tier's "allowed AND differs from the not-found reference"
signal is, by itself, exactly the bug class Phase 3.3 (`sqli`)
discovered: an endpoint that merely **echoes** its input (task section
10's "reflection vs file access", concretely `/files/download/reflect`)
differs from ANY other probe's echoed text trivially, with no real file
access involved. This was caught during THIS phase's own unit testing
(`TestDetect_ReflectionOnly_NoFinding` initially failed) and fixed the
same way `ssrf` applies proactively: `stripPayload` (raw, HTML-escaped,
and URL-escaped forms) removes each response's own injected value
before the two bodies are compared, using the **decoded** form of
whatever representation was sent (a reflecting endpoint echoes back
what `net/http`'s own query decoding produced, not the wire-level
percent-encoded bytes) -- `decodedForm` handles that translation.
`TestDetect_ReflectionOnly_NoFinding` and
`TestStripPayload_RemovesURLEscapedForm` cover this directly.

### Dynamic content

`normalizeBody`'s digit-run collapsing (identical to
`sqli`/`ssrf`/`idor`) neutralizes ordinary request-scoped dynamism
(timestamps, counters) shared between the not-found reference and a
probe response, mirroring the project's established
`/sqli/dynamic`-style negative fixture pattern --
`TestAdversarial_DynamicDigitContent_NoFalsePositive` confirms this
directly. **Documented limitation, consistent with every sibling
detector**: non-digit dynamic content (a rotating word, random
non-numeric token) is not normalized away -- no detector in this
project handles that case either.

## Method coverage

Only `GET` is supported. Per task sections 12-13: READ is the primary,
always-safe path; write-method testing risks mutating state the
scanner has no business mutating, and DELETE is explicitly forbidden
regardless of any detected vulnerability. `Eligible` simply never
returns true for a non-GET target -- an honest NOT_APPLICABLE by
construction, never faked support.

## Confidence and severity

| Signal | Severity | Confidence | Rationale |
|---|---|---|---|
| At least one traversal representation returned the configured marker verbatim | critical | 0.9 | Confirmed unauthorized access to the SPECIFIC protected resource -- "HIGH: protected synthetic file content is confirmed" |
| No marker confirmed, but at least one representation was allowed AND genuinely differs from the not-found reference (after stripping the reflected value) | high | 0.55 | "MEDIUM: strong traversal behavior exists but protected content confirmation is incomplete" |
| Every representation denied, OR allowed responses are indistinguishable from "not found" once reflection is accounted for | -- | -- | `OutcomeNoFinding` |
| No configured case, or the legitimate-access reference itself fails | -- | -- | `OutcomeSkipped` / `OutcomeNoFinding` |

No `LOW` tier is fabricated, for the same reason
[the IDOR detector](phase-3-5-idor-bola.md) skips one: task section 9
explicitly forbids reporting on weak evidence alone (HTTP 200 alone,
response-length-changed alone, path-string-reflected alone) -- every
signal a LOW tier could be built from is exactly one of those three.
Rather than inventing a fourth, weaker signal just to populate a third
tier, anything short of MEDIUM's bar (allowed AND genuinely,
reflection-adjusted different from a real reference) resolves to
`OutcomeNoFinding`. Severity reuses `pkg/models.Severity` unchanged;
not every traversal indication is reported as critical -- only a fully
confirmed match is, matching the Phase 3 ground truth's
`severity: critical` for `VULN-TRAVERSAL-API-001`.

## Evidence

Every finding's `Evidence` is one
`detection.NewRequestResponseEvidence`, structured to answer task
section 16's exact shape without storing a full response body:

- **TARGET** / **PARAMETER** -- `t.Path`, `t.Parameter`, in
  `Observation`'s `target=`/`parameter=`.
- **ORIGINAL** -- the originally-discovered value, `Observation`'s
  `original=`.
- **PROBE** -- the specific traversal representation that produced the
  best (confirmed, or else suspicious) evidence, `Observation`'s
  `probe=` and `Payload`.
- **EXPECTED** -- always `denied` (`Observation`'s `expected=denied`).
- **ACTUAL** -- the probe's status code, `Observation`'s `actual=`.
- **PROOF** -- `Observation`'s `proof_marker_matched=` (true only for
  the confirmed/HIGH tier), plus a bounded (±80 byte)
  `ResponseFragment` centered on the marker (or the probe value, if the
  marker itself never appeared -- the MEDIUM case).
- **CONCLUSION** -- `Reason`, a full sentence distinguishing "confirmed
  unauthorized access to a specific resource" from "traversal-shaped
  access observed but confirmation incomplete."

No full response body is ever persisted -- only the bounded fragment,
matching every other Phase 3.x detector's evidence-storage discipline.

## Finding

Uses `pkg/models.Finding` unchanged -- no new schema. `VulnerabilityType`
is `"path_traversal"`; `Title`, `Severity`, `Confidence`,
`AffectedParameter`, `Description`, `Remediation`, and `Evidence` are
set by the detector; the engine's `normalizeFinding` (Phase 3.1,
unchanged) fills `ID`, `ScanID`, `DetectorID`, `Host`, `Port`, `URL`,
`Method`, `AffectedEndpoint`, `Source`, and timestamps.

## Deduplication

Reuses `internal/detection.Deduplicate` (Phase 3.1) unmodified. This
detector reports **at most one finding per (endpoint, parameter)
candidate**, aggregating every confirmed/suspicious attempt across
every configured case and every encoding variant into that single
finding's evidence -- not one finding per payload. Phase 3.1's dedup
key (`DetectorID + Host + Port + AffectedEndpoint + Method +
AffectedParameter + VulnerabilityType`) has no payload/encoding field,
so extending it to distinguish payloads would mean redesigning Phase
3.1 for this one detector's benefit -- against the task's explicit
"do not redesign Phase 3.1 unless a genuine defect is discovered"
instruction, and no defect exists here.
`TestAdversarial_DuplicateTraversalCasesConfigured_SingleFindingNotInflated`
confirms even a misconfigured operator (the same case listed 3 times)
never produces more than one finding per `Detect` call.

## Scope enforcement

Every probe goes through `detection.Executor.Do` -- the same
scope-validated, rate-limited, timeout-bounded request path every
other detector uses; `probe`/`probeRaw` never build their own
`http.Client` or bypass scope in any way.
`TestDetect_OutOfScope_ReturnsErrorWithoutDialing` (unit) and
`TestPhase3_6_TraversalDetector_ScopeEnforcementStaysActiveDuringDetection`
(integration -- a real scan job whose `ScopeSnapshot` authorizes only
`vuln.scanner.test`, tested against a manufactured `Target` pointing at
the Phase 2 lab's real `scanner.test` host) both confirm zero requests
reach an out-of-scope host. A scope bypass here would be an automatic
Phase 3.6 failure; none was found.

## Scanner filesystem safety (CRITICAL, per the task)

This package's ENTIRE implementation operates over HTTP -- there is no
code path in it that constructs a local filesystem path from any
input, trusted or otherwise. This is verified two ways, not just
asserted:

- **Static guarantee**: `TestSourceNeverCallsLocalFileReadAPIs` reads
  this package's own non-test `.go` source files and asserts they never
  contain `os.Open(`, `os.OpenFile(`, `os.ReadFile(`,
  `ioutil.ReadFile(`, or `os.Create(` -- a belt-and-suspenders,
  mechanically-enforced guarantee that survives future edits to this
  package, not just a one-time code-review claim.
- **Behavioral guarantee**: `TestDetect_MaliciousOriginalValue_NeverTouchesLocalFilesystem`
  runs `Detect` from a temporary, otherwise-empty working directory
  with both a discovered parameter value AND a configured
  `TraversalCase.RelativePath` shaped like an attempt to reach real,
  sensitive local paths (`/etc/shadow`, `~/.ssh/id_rsa`,
  `~/.aws/credentials`, `/proc/self/environ`, a Windows SAM path) and
  confirms the temp directory has exactly 0 entries afterward -- proof,
  not just an absence of an error, that nothing was created, read, or
  otherwise touched locally. Every such value simply becomes an HTTP
  query-string byte sequence sent to the synthetic lab server, which
  has no matching resource and returns 404.

Traversal payloads remain data passed to the target throughout; this
detector never interprets them as anything else.

## Request limits

- **Bounded per candidate**: 2 reference requests (legitimate-access +
  not-found) + up to `maxVariantsPerCase` (8) requests per configured
  case, with an early-exit as soon as a case is confirmed. With the
  lab's single configured case, this is 3 requests in the common
  (confirmed-on-first-variant) case, and never more than `2 + 8×len(cases)`.
- **No combinatorial explosion**: candidates are evaluated
  independently; nothing scales with the number of OTHER candidates or
  resources on the target.
- **Timeout / concurrency / rate limiting**: inherited unchanged from
  the shared `detection.Executor`, identical to every other Phase 3.x
  detector.
- `TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests` runs 10
  candidates concurrently and asserts exactly `10 × 3 = 30` total
  target requests -- no request multiplication, confirmed under
  `-race`.

## Response size limits

`maxBodySample` (256KB) bounds every read via `io.LimitReader`,
identical to every other Phase 3.x detector.
`TestDetect_OversizedResponse_TruncatedNotUnbounded` sends a response 4x
larger than the cap and confirms the detector still completes cleanly
(truncated comparison, no unbounded memory growth, no crash).

## Error handling and cancellation

- **403/404** -- handled by `looksAllowed` returning false; never
  interpreted as traversal.
- **Malformed response body (binary/non-UTF8)** -- `containsMarker` and
  `normalizeBody` operate on raw bytes/runes without assuming valid
  UTF-8 structure; `TestAdversarial_MalformedResponseBody_NoCrash`
  confirms no panic.
- **Connection failure / timeout** -- `probe`/`probeRaw` propagate the
  `Executor.Do` error via `fmt.Errorf("traversal: ... probe: %w", err)`;
  `Detect` returns that error rather than a Result.
- **Duplicate query parameter** -- `requestURL`'s `q.Del(t.Parameter)`
  removes every occurrence before re-adding exactly one;
  `TestAdversarial_DuplicateQueryParameter_NoCrash` confirms normal
  detection still succeeds.
- **Cancellation** -- checked implicitly at every `Executor.Do` call
  (legitimate-access reference, not-found reference, every variant
  probe); `TestDetect_ContextCancellation_ReturnsError` and
  `TestDetect_CancellationDuringBaseline` (using `atomic.Int32` to
  avoid a data race, the same fix Phase 3.3's analogous test required)
  confirm no further request is issued after cancellation.

## Limitations

- **GET query parameters only** -- see "Candidate selection" and
  "Method coverage."
- **Parameter-name heuristic only** -- Phase 2's recon has no
  parameter-value-shape classification, the same documented gap every
  Phase 3.x detector carries.
- **Path-segment object references are undetectable** -- see
  "Candidate selection"; `VULN-TRAVERSAL-001`/`VULN-TRAVERSAL-NEG-001`
  remain out of reach for two independent reasons (path-based AND
  wrong parameter name).
- **No automatic discovery of a real target's protected resources** --
  see "Known traversal cases." This detector confirms KNOWN, configured
  cases; it does not (and, per task section 9's evidence requirements,
  safely cannot) discover unknown ones.
- **No production TraversalCase configuration ships in this build** --
  the detector is fully built, tested, and verified against the real
  Phase 3 Test Lab's own synthetic fixture; wiring it to real,
  operator-supplied knowledge of a real target's file layout is future
  work, deliberately out of this phase's scope.
- **Single-level encoding only** -- see "Encoding handling"; a target
  requiring a genuine double-decode to be exploitable is out of reach,
  honestly documented rather than silently unsupported.
- **Digit-run-only response normalization** -- the same documented
  limitation `sqli`/`ssrf`/`idor` carry: non-digit dynamic content is
  not normalized away.
- **Read-only (GET) traversal only** -- write-method testing is not
  implemented; per task sections 12-13, deliberately deprioritized
  behind READ as the primary, always-safe path.
