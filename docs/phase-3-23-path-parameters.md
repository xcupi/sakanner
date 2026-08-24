# Phase 3.23: Path Parameter Discovery & Active Detection Foundation

## 0. Scope discipline

This phase closes exactly one proven gap: path-location parameters are
never discovered by the live pipeline. No new vulnerability class, no
IDOR/BOLA detection, no authorization testing, no mass assignment,
SSRF, command injection, or path-traversal detection, no time-based
SQLi, no new platform integrations.

## 1. Architecture review

### 1.1 Tracing the current (pre-3.23) behavior, precisely

`internal/parameters.InferPathInputs` (`path.go:40`) is a real,
complete, already-tested pure function. Confirmed by an exhaustive
repository grep (Phase 3.22's own finding, re-verified here): it has
**zero callers** anywhere in `internal/orchestration` or any other
production package. Nothing in the live pipeline ever produces a
`Location == "path"` `models.Parameter` row. `internal/detection.BuildTargets`
has no switch arm for `path` (it only handles `query`/`json`/`form`).
`internal/mutation.applyPath` (`mutate.go:345-358`) is complete and
tested but, like `applyHeader`/`applyCookie`, has never been invoked
by any live `Target`. This is confirmed, not assumed -- every claim
above was re-verified by direct reading during this phase, not carried
over from Phase 3.22's own report.

### 1.2 What `InferPathInputs` already gets right

Reading it in full: it already implements exactly the conservative,
evidence-based design this phase's own task text asks for.
- Requires **at least 2 endpoints**, same HTTP method, identical in
  every segment except the last, with the last segment differing
  (`path.go:64-74`) -- a single observed value never becomes a path
  input (handles "static numeric paths" correctly already: `/users/123`
  observed alone infers nothing).
- Only the **last** segment is ever considered variable -- a
  deliberate, documented scope boundary (not "middle segments could
  also vary," which would require reasoning about combinations this
  phase does not need).
- **Duplicate observations collapse correctly**: `distinct` is a
  `map[string]bool` (a set), so `/users/123` observed twice (e.g. via
  both a link and a crawl) contributes one entry, not two -- "duplicate
  paths with different values" only fires evidence when the values
  actually differ.
- **Deterministic**: candidates are sorted by `(EndpointPath,
  EndpointMethod)`; prefix processing itself iterates over a
  lexicographically sorted key slice, never raw map iteration order.

### 1.3 What this phase must add (the actual gap)

1. **Wiring**: nothing calls `InferPathInputs`. This phase adds the
   third discovery pass to `internal/orchestration.crawlAndDiscoverEndpoints`
   (alongside the existing query/form pass and the JSON-response
   pass), scoped per-crawl-target exactly like both existing passes
   -- see 1.4 for why this scoping matters.
2. **`PathSegmentIndex` is computed but discarded.** `path.go:66`
   computes `last` (the 0-based index of the varying segment) but the
   `Candidate` built at `path.go:90-93` never records it -- only the
   segment's string `Value`. Without this index, nothing downstream
   could tell `mutation.applyPath` (which requires an explicit
   `PathSegmentIndex int`, `mutate.go:57-62`) which segment to
   mutate. This phase adds `Candidate.PathSegmentIndex`,
   `models.Parameter.PathSegmentIndex`, and `detection.Target.PathSegmentIndex`
   -- one integer, threaded through the same three layers
   `FormFields` was threaded through in Phase 3.21.
3. **`Provenance` is left unset.** Every other `Candidate` producer in
   this package explicitly sets `Provenance: ProvenanceRequestInput`
   (a documented convention: "never left to a zero-value default, so
   a future new candidate source can never accidentally inherit an
   unintended meaning," `normalize.go:34-39`). `InferPathInputs`
   currently does not. Fixed to match.
4. **No resource limit is applied to `InferPathInputs`'s own output.**
   Unlike `Normalize`/`NormalizeJSONResponses`, which both route their
   candidates through `candidateAggregator.finalize(limits)`
   (`MaxInputsPerEndpoint`/`MaxTotalInputs`), `InferPathInputs`
   currently returns an uncapped slice. Section 9 below.
5. **`BuildTargets` has no `path` routing arm.** Section 5.
6. **Neither `sqliactive` nor `xssactive` has a `path` case in
   `Eligible` or their location switch**, and neither ever calls
   `mutation.NewPathMutation` (the only constructor that carries
   `PathSegmentIndex`) -- both currently call the plain
   `mutation.NewMutation` unconditionally.

### 1.4 Why path inference must be scoped per-HTTPService (a real, self-caught risk)

`PathEndpoint` (the type `InferPathInputs` groups over) carries no
host information at all -- only `Path`/`Method`/`Source`. If this
function were ever called with endpoints pooled across MULTIPLE
HTTPServices in one scan (e.g., two entirely different sites that both
happen to expose `/users/123`), it would incorrectly treat them as one
logical endpoint family and infer a shared path parameter across
services that have nothing to do with each other. `internal/orchestration.crawlAndDiscoverEndpoints`'s
existing loop is already structured per-`crawlTarget` (one target =
one HTTPService's own crawled pages) -- wiring `InferPathInputs` INSIDE
that per-target loop, using only that target's own `endpoints.Normalize(pages)`
output, avoids this cross-service leakage by construction, the same
way query/form/JSON discovery already avoid it. Documented here as a
real risk that was identified and designed around, not discovered
after the fact.

## 2. Canonical path representation

**Decision: no template string (e.g. `/users/{id}`) is stored
anywhere.** The existing model already represents the relationship
correctly without one:
- Each CONCRETE path (`/users/123`, `/users/456`) is its own
  `models.Endpoint` row (unchanged -- `endpoints.Normalize` already
  keys by the literal path).
- Each gets its own `models.Parameter` row, `Location: "path"`,
  carrying the CONCRETE `Value` ("123", "456") and a
  CONSISTENTLY-DERIVED `Name` (`pathInputName`, unchanged -- e.g.
  "user_id" for both, since both were inferred from the same
  same-method, same-prefix group).
- The "logical endpoint family" is recoverable by querying
  `Parameter.Name` + `Location == "path"` + the shared endpoint path
  prefix -- exactly what a future IDOR phase needs (section 8) --
  without a new field. Introducing a template-string field would be
  redundant (nothing would ever consume it -- `mutation.applyPath`
  operates on a segment INDEX against a concrete path, never a
  template) and risks drifting out of sync with the concrete data it
  would describe.

### 2.1 Numeric identifiers, UUIDs, hex, slugs, mixed alphanumeric

The EVIDENCE requirement (≥2 distinct observed values under an
identical same-method prefix) is format-agnostic -- it works
identically whether the varying segment holds `123`/`456`, two UUIDs,
two hex strings, or two slugs. No format-specific detection is needed
for the evidence rule itself. `pathInputName`'s existing binary
`allNumeric` check exists ONLY to choose a cosmetic suffix
(`_id` vs `_value`) for the human-readable `Parameter.Name` -- it is
not, and does not need to be, a security-relevant distinction. This
phase makes no change to that heuristic: adding UUID/hex-specific
naming would be a purely cosmetic enhancement with no bearing on
whether an input becomes a mutation target, and is not implemented
(matching the task's own "only implement classifications that can be
justified by existing evidence").

### 2.2 Version segments (`/v1/`, `/v2/`) -- a real, justified exclusion

**Finding:** the existing evidence rule, applied naively, would
misclassify an API version as a variable path input. Two endpoints
`/api/v1` and `/api/v2` (same method) share the prefix `api`, and `v1`
!= `v2` satisfies the `len(distinct) >= 2` rule -- `InferPathInputs`
would infer a fuzzable "api_value" parameter from what is actually a
STRUCTURAL ROUTING segment, not application data. This is a real,
identified risk, not a hypothetical: this phase adds one narrow,
justified exclusion -- if EVERY distinct value at the varying position
matches `^v[0-9]+$` (case-insensitive), no path input is created for
that group. This is the same class of decision as
`nonInputControlTypes` excluding submit buttons from form discovery
(Phase 3.13): a narrow, evidence-motivated exclusion for a segment
shape that is overwhelmingly a routing artifact, not user/attacker-
controlled data, stated and justified explicitly rather than silently
added.

### 2.3 Static numeric paths, duplicate paths with different values

Both already correctly handled by the pre-existing `len(distinct) < 2`
check and the `distinct` set's own deduplication -- see 1.2. No new
code needed; re-verified with new tests (section 13) rather than left
as an assumption.

## 3. Active mutation

`mutation.applyPath` (`mutate.go:345-358`) needs **no logic change**
-- it is already complete: trims the leading `/`, splits on `/`,
bounds-checks `PathSegmentIndex`, escapes (or not, per `Encoding`) the
new value, rejoins. `detection.NewMutationRequest` needs **no change**
either -- `req.Path = t.Path` already copies the endpoint's full,
concrete path (with the ORIGINAL segment value already in place) for
every Target regardless of location; `Mutate`'s `applyPath` is what
subsequently replaces exactly the one indexed segment. This mirrors
exactly how form-location mutation needed no engine change in Phase
3.21 -- the gap is entirely upstream (discovery, routing) and in the
detector's own Mutation-construction call, not in `internal/mutation`
itself.

**One new, small, shared helper**: `detection.NewTargetMutation(t
Target, loc mutation.Location, payload string, encoding mutation.Encoding)
mutation.Mutation`, added to `mutation_bridge.go` alongside
`NewMutationRequest`. It centralizes the ONE piece of
location-specific knowledge every active detector would otherwise
have to duplicate: a path-location parameter needs
`mutation.NewPathMutation` (which also needs `PathSegmentIndex`),
every other location uses the plain `mutation.NewMutation`. Both
`sqliactive` and `xssactive` call this instead of `mutation.NewMutation`
directly -- a one-line change at each of their existing Mutation-
construction call sites, not a rewrite of either detector's own
probing/classification logic.

### 3.1 Host safety, by construction

`applyPath` only ever mutates `req.Path`; it has no code path that can
touch `req.Host`/`req.Scheme`/`req.Port`. Unlike form actions (which
carry a genuine, independently-resolved destination URL, Phase 3.21's
own `ActionOrigin` concern), a path segment's value becomes part of
the PATH STRING on the SAME already-resolved host, never reinterpreted
as a new authority -- confirmed by reading `Request.URL()`
(`request.go:84-94`), which builds the final URL from `Scheme`/`Host`/
`Port` and `Path` as independent struct fields, never by re-parsing a
string that could smuggle a new host in. This means path mutation
needs no cross-origin resolution logic of any kind (unlike Phase
3.22's form-action work) -- proven with an adversarial test (section
13) rather than merely asserted.

## 4. XSS / SQLi integration

Both detectors gain: one `case "path":` arm in `Eligible` (any method
-- a path segment's mutability has nothing to do with HTTP method,
unlike a GET-only query string), one `case "path": loc = mutation.LocationPath`
arm in `Detect`'s existing location switch, and their Mutation-
construction call sites switched to `detection.NewTargetMutation`
(section 3). No other line in either package changes -- `reflection.go`/
`finding.go` (xssactive) and `signals.go`/`finding.go` (sqliactive)
already operate purely on `mutation.Response`, oblivious to which
`Location` produced it, exactly as they already were for `form`
(Phase 3.21/3.22).

## 5. Target routing

`BuildTargets`/`endpointTargets` gains a fourth parameter map
(`pathParamsByEndpointID`, mirroring the existing three), filtered
`Location == "path" && Provenance == "REQUEST_INPUT"`. Each such
Parameter becomes one Target with `ParameterLocation: "path"` and
`PathSegmentIndex` copied from the Parameter. No same-origin gate is
needed (section 3.1 -- path mutation is host-safe by construction). No
deduplication logic is needed beyond what already exists: `/users/123`
and `/users/456` are genuinely DIFFERENT `Endpoint` rows (task section
8's own requirement), so they naturally produce DIFFERENT Targets --
this is correct, not a duplicate to collapse.

`RESPONSE_FIELD`-provenance path candidates are impossible in
practice (nothing produces one -- `InferPathInputs` always sets
`REQUEST_INPUT`), but the provenance filter is still applied
explicitly, mirroring the JSON/form branches' own established
discipline of never assuming a filter is unreachable.

## 6. Authentication / multi-identity

No new code (section 1.3's list is exhaustive) -- authentication and
`IdentityContext` flow through `Executor.ExecuteMutation` identically
regardless of `ParameterLocation`, unchanged since Phase 3.19. Proven,
not merely asserted, per the lab/e2e tests in section 13.

## 7. Scope enforcement

No new scope code -- reused entirely, unchanged. Section 3.1 already
establishes path mutation cannot change the dial target by
construction; the adversarial test matrix (section 13) proves this
directly (a malicious path-segment payload never changes
`Request.Host`) rather than relying on the architectural argument
alone.

## 8. IDOR foundation (explicitly NOT full IDOR detection)

Section 2's design (concrete `Endpoint`/`Parameter` rows per distinct
value, consistently named) already gives a future IDOR phase exactly
what it needs: query `Parameter{Name: "user_id", Location: "path"}`
rows grouped by name, cross-reference `IdentityContext` and `Value`
per row. No authorization-specific heuristic, no cross-identity
comparison logic, and no "same resource, different account" detection
is implemented this phase -- `models.Finding`/`internal/correlation`/
`internal/risk` are not touched at all.

## 9. Resource limits

Two additions to `parameters.Limits`:
- **`MaxPathSegments`** (new field, default 20): a `PathEndpoint`
  whose path has more segments than this is skipped entirely before
  grouping -- prevents pathological, deeply-nested URLs from adding
  unbounded prefix-grouping work.
- `InferPathInputs`'s signature changes to `(eps []PathEndpoint,
  limits Limits) Result` (matching `Normalize`/`NormalizeJSONResponses`'s
  established shape exactly -- safe, since it has zero callers to
  break) and routes its output through the same `candidateAggregator`
  discipline (`MaxInputsPerEndpoint`/`MaxTotalInputs`) those two
  functions already use, rather than returning an uncapped slice.

Mutation-side request-count limits need no new code:
`ExecutorConfig.MaxActiveRequestsPerScan`/`MaxMutationsPerTarget` are
already `Location`-agnostic (Phase 3.17/3.19, unchanged) -- adding
path-location eligible Targets adds new eligible Targets within the
SAME already-bounded budget, not a new request path (identical
reasoning to Phase 3.22's own resource-limit finding for
`xssactive`'s form/JSON coverage).

## 10. Storage

One migration, `0013_path_parameters.sql`: `ALTER TABLE parameters ADD
COLUMN path_segment_index INTEGER NOT NULL DEFAULT -1` (a Go zero
`int` would collide with a genuine segment index of `0`, so `-1`
signals "not a path parameter" / "not yet set" -- every pre-3.23 row
backfills to `-1`, never `0`). Fully backward compatible: no existing
column changes meaning, no existing row's interpretation changes.

## 11. CLI / reporting

**Already fully supports this -- confirmed by reading
`cmd/scanner/inputs.go` in full.** The `--location` flag's own help
text already lists `path` as an accepted value
(`inputs.go:106`), and the table-rendering loop has no
per-location branching at all -- it prints whatever `Location`/`Name`/
`Value` a `Parameter` row carries, generically. Once path parameters
are persisted, `scanner inputs <scan-id>` and `scanner inputs
<scan-id> --location path` display them with zero code changes. No
new CLI command is added (matching the task's own "do not create a
new vulnerability-specific CLI command," and there is nothing left to
add for the general-purpose one).

## 11.5 A real, pre-existing defect discovered and fixed during development

`mutation.applyPath`'s `EncodingEscaped` branch pre-escaped `m.Value`
via `url.PathEscape` before storing it into `req.Path` -- but
`Request.URL()` builds a plain `url.URL{Path: r.Path, ...}` with no
`RawPath` override, so `url.URL.String()` (via `EscapedPath()`)
**always** escapes `Path` exactly once when serializing. Pre-escaping
here meant every `%` the pre-escape introduced was escaped a SECOND
time, double-encoding the value on the wire -- confirmed directly:
`url.PathEscape("1' OR '1'='1")` followed by placing the result into
`url.URL{Path: ...}.String()` produced `%2527%2520OR...`, not the
correct single-escaped `%27%20OR...`. This was never caught earlier
because the only pre-existing test
(`TestMutate_Path_ReplacesSegment`) checked `req.Path`'s raw string
value directly, never the actual URL a real HTTP request would use --
Phase 3.23's own detector integration is the first thing in this
codebase to ever build a real HTTP request from an escaped path
mutation. Per the task's own instruction, a regression test
(`TestMutate_Path_Escaped_ValueWithSpecialCharacters_URLRoundTrips`)
was written FIRST, confirmed to reproduce the defect, then the fix was
applied (remove the pre-escape; `applyPath` now stores `m.Value`
unmodified, exactly mirroring `applyQuery`'s own established pattern
of relying on the standard library's own single escaping pass), then
re-verified. A related, PRE-EXISTING (not caused or worsened by this
fix) limitation was identified and explicitly documented with its own
passing test
(`TestMutate_Path_Verbatim_KnownLimitation_StillAutoEscapedByURLString`):
`EncodingVerbatim` cannot achieve genuinely byte-for-byte, unescaped-
on-the-wire path output with the current `Request.URL()` design
(unlike query/form, which have their own raw-output escape hatches) --
out of scope to fix here since neither `sqliactive` nor `xssactive`
ever requests verbatim encoding for any location.

## 12. What this phase intentionally does not implement

IDOR/BOLA detection, authorization/access-control testing, mass
assignment, SSRF, command injection, path-traversal VULNERABILITY
detection (path parameter MUTATION is implemented; testing for
traversal as a vulnerability class is not), new vulnerability classes,
time-based SQLi, new platform integrations, a path-template/canonical-
string storage field (section 2), UUID/hex-specific naming heuristics
(section 2.1), header/cookie discovery (unchanged, out of scope).
