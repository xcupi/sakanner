# Phase 3.18: API & JSON Input Discovery Foundation

## 0. Scope discipline

This phase is infrastructure only. It does not implement, and must not
be read as implying, IDOR/BOLA detection, authorization testing, mass
assignment detection, or any other vulnerability logic. A successful
result of this phase is a COUNT ("discovered 12 API endpoints, 37 JSON
inputs"), never a FINDING ("IDOR found"). See section 14 for the full
list of what is intentionally not built.

## 1. Architecture review findings

Full investigation of `internal/parameters`, `internal/crawler`,
`internal/http`, `internal/mutation`, `internal/orchestration`,
`internal/endpoints`, `pkg/models`, and storage was conducted before
any code was written. The load-bearing findings:

1. **The crawler never issues a non-GET request, ever.** `nativeCrawler.fetchAndParse`
   hardcodes `http.MethodGet`. Forms are *parsed* (Action/Method/Fields
   extracted from markup) but never *submitted*. This means Phase
   3.13's `ParseJSONBody` -- designed around "a captured **request**
   body" -- has no live request body anywhere in this codebase to
   consume. **"Wiring the JSON parser into the live pipeline" can only
   mean, honestly, consuming a JSON RESPONSE body from an
   already-GET-fetched resource** -- not a request body, because the
   crawler never sends one. This is stated plainly rather than
   glossed over, matching this codebase's established practice
   (Phase 3.13's own "JSON body discovery: an honest capability gap"
   section, Phase 3.15's session-expiration-heuristic writeup) of
   documenting a real architectural boundary instead of quietly
   working around it.
2. **`crawler.Page` retains no body, no Content-Type, at all** --
   `fetchAndParse` reads the Content-Type header purely to decide
   whether to parse as HTML, then (for any non-HTML response) returns
   immediately WITHOUT reading the body at all. The JSON body of an
   API response the crawler already fetched over the wire is
   currently thrown away unread.
3. **`internal/orchestration.discoverJavaScriptTechnologies` already
   fetches every same-origin script's body** (for fingerprinting) and
   already enforces cross-origin exclusion + a body-size bound before
   this phase touches it -- the natural, already-reviewed insertion
   point for JS route extraction, not a new fetch path.
4. **No API/content-type classification signal exists anywhere** --
   `models.Endpoint`/`models.HTTPService` have no such field; the only
   existing "signal" is `Endpoint.Source` (`"crawl"|"link"|"form"|
   "javascript"`), which encodes HOW a URL was found, never WHETHER it
   looks like an API.
5. **`detection.BuildTargets` only emits Targets for `Location ==
   "query"` Parameters** -- JSON/form-located parameters are
   discovered, persisted, and reportable today, but structurally
   cannot reach a detector. `detection.Target.ParameterLocation`'s own
   vocabulary (`"query"/"body"/"header"/"cookie"`) already anticipates
   a `"body"` value for exactly this case; nothing sets it yet.
6. **`mutation.applyJSON` (Phase 3.17) only mutates a single, flat,
   top-level JSON key.** A discovered nested parameter name
   (`"user.profile.email"`, `ParseJSONBody`'s own dot-path convention)
   would, fed naively into `mutation.NewMutation`, set a literal
   top-level key SPELLED `"user.profile.email"` rather than descending
   into nested structure -- silently wrong, not merely incomplete.
   This phase fixes it (section 6).

## 2. The REQUEST_INPUT / RESPONSE_FIELD / DISCOVERED_ROUTE distinction

This is the single most important design decision in this phase, and
it falls directly out of finding 1 above. Since the ONLY live JSON
data this phase can honestly capture is a RESPONSE body (never a
request body the crawler itself never sends), and the task's own
section 18 explicitly forbids treating a response field as a writable
request parameter, `models.Parameter` gains a new field:

```go
Provenance string // "REQUEST_INPUT" | "RESPONSE_FIELD"
```

- **`REQUEST_INPUT`** (the default, and the ONLY value every existing
  Phase 3.13 discovery source -- query strings, HTML forms -- has ever
  produced): this input was observed being ACCEPTED by the
  application (it appeared in a URL a page actually links to, or a
  form the application actually renders for submission). A future
  detector may treat this as a plausible thing to mutate and send.
- **`RESPONSE_FIELD`** (new this phase): this field was observed IN A
  RESPONSE BODY -- an API returned it, which proves nothing about
  whether the application accepts it back as an input. A future
  detector must NOT treat this as automatically writable; it is
  attack-surface intelligence ("this API mentions a `user_id` field,
  an `orders` array"), not a confirmed input.
- **`DISCOVERED_ROUTE`** is not a `Parameter` concept at all -- a
  JS-derived or HTML-derived URL is a candidate `Endpoint`, not an
  input. See section 4.

The migration backfills every EXISTING Parameter row (all of which
predate this distinction, and all of which were discovered exactly the
way `REQUEST_INPUT` is now defined) to `Provenance = 'REQUEST_INPUT'`
via the column's own `DEFAULT` -- not a placeholder value, the
factually correct backfill (see section 9).

## 3. Live JSON response capture

`crawler.Page` gains two fields:
```go
ResponseBody []byte // populated only for a JSON-content-type response
ContentType  string // the response's own Content-Type header, always recorded
```
`fetchAndParse` is extended, not rewritten: the existing "is this
HTML" branch is unchanged byte-for-byte; a NEW branch checks whether
the Content-Type indicates JSON (`strings.Contains(ct, "json")`,
matching this codebase's existing HTML-detection idiom exactly) and,
only then, reads a BOUNDED body (`maxCrawlBodySample`, the SAME
512KiB constant the HTML path already uses -- no new limit invented).
Every other content type (images, other binary, plain text) is
untouched: no body read, exactly as before. `ContentType` is now
always recorded regardless of branch, a strictly additive,
backward-compatible change (nothing previously read this field,
because it didn't exist).

`internal/parameters` gains `NormalizeJSONResponses(pages []crawler.Page,
limits Limits) Result`, mirroring `Normalize`'s existing dedup/sort/
cap structure (factored into a shared private helper so the two don't
duplicate that logic), calling the EXISTING `ParseJSONBody` (only
change: it now takes an explicit `Provenance` parameter, stamped onto
every Candidate it returns -- see section 2) against each JSON-typed
page's `ResponseBody`. `Source` is `json_response` (new constant,
distinct from `json_body`, which remains reserved for the day a real
request body becomes available). Every Candidate's `EndpointPath/
Method("GET")/Source(SourceCrawl)` matches exactly the `SourceCrawl`
Endpoint row `endpoints.Normalize` already produces for that same
page's own URL -- the identical correlation key
`internal/orchestration.crawlAndDiscoverEndpoints` already uses for
query/form candidates, unchanged.

**Malformed JSON**: `ParseJSONBody`'s existing behavior (a `Result`
with zero Candidates and a `Warnings` entry, never a panic, never an
aborted scan) is reused as-is -- this phase adds no new malformed-input
handling because none was needed; the existing implementation was
already correct for this case, just unreached.

## 4. API endpoint classification

`models.Endpoint` gains:
```go
APICandidate        bool
APIEvidence         string // comma-joined reasons, e.g. "response_content_type_json,path_heuristic"
ResponseContentType string
```
`internal/endpoints.ClassifyAPI(page crawler.Page) (candidate bool,
evidence []string)` computes this ONLY for `SourceCrawl`-derived
endpoints (the ones this phase has direct fetch evidence for -- a
`SourceLink`/`SourceForm` endpoint is a reference found ON a page, not
a page this scan has itself fetched, so there is no response evidence
to classify it with YET; if that URL is later itself crawled, it gets
its own `SourceCrawl` row with real evidence then).

Evidence signals, in the order they are checked, NEVER used alone as
the only possible reason (multiple signals may co-occur):
1. `page.ContentType` indicates JSON -- strong, direct evidence
   (`"response_content_type_json"`).
2. The path matches a conservative REST-API shape heuristic (a
   segment literally named `api`, OR a path ending in a purely numeric
   segment following a plural-looking resource segment, e.g.
   `/users/42`) -- `"path_heuristic"`. Per the task's explicit
   instruction, this is recorded as a WEAKER, clearly-labeled signal,
   never presented as equivalent certainty to content-type evidence --
   a caller reading `APIEvidence` can see exactly which signal(s) fired
   and judge accordingly; `APICandidate` alone never claims more
   certainty than the evidence backing it actually supports.

`APICandidate` is `true` if either signal fires; `APIEvidence` always
names which one(s). An endpoint with `APICandidate == false` (the
default, and the ONLY possible value for every pre-Phase-3.18 scan,
preserving `models.Endpoint`'s existing meaning exactly per task's
"do not change the meaning of the existing Endpoint model unless
necessary" -- necessary here only to ADD information, never to change
what any existing field already meant).

## 5. JavaScript API route discovery

New: `internal/endpoints.ExtractAPIRoutes(scriptBody []byte, base
*url.URL, limits JSLimits) []string`. Deliberately conservative, per
the task's own explicit constraints -- no JS interpreter, no
execution, no browser dependency:

- A single, tightly-scoped regex matches a quoted string literal
  (`"..."`or `'...'`) that is either an absolute `http(s)://` URL or a
  path starting with `/`, appearing as the first argument to one of a
  small, fixed set of call-shapes this codebase treats as reliable
  evidence of an API reference: `fetch(`, `.get(`, `.post(`, `.put(`,
  `.patch(`, `.delete(`, `axios.` -- NOT every quoted string in the
  file (which would produce enormous false-positive noise from CSS
  classes, log messages, unrelated literals).
- Bounded: `JSLimits{MaxRoutesPerScript, MaxScriptBytesScanned}`
  (defaults: 50 routes/script, the same 512KiB body bound the fetch
  itself already enforces) -- truncates deterministically, never scans
  an unbounded string.
- Deduplicated and sorted before being returned -- deterministic
  output regardless of regex match iteration order.

Wired into the EXISTING `discoverJavaScriptTechnologies` (which
already fetches every same-origin script body for fingerprinting) --
not a second fetch pass. For each extracted route: an ABSOLUTE URL is
checked against `dialer.Validator.CheckHost` (the exact
`scope.Validator` the whole pipeline already uses, reached via the
`*safedial.Dialer` this function already receives) BEFORE it is ever
persisted as an Endpoint candidate; an out-of-scope absolute reference
is simply never recorded (dropped, not persisted, not queued for a
crawl) -- see section 8's rationale for why "drop" rather than
"record but mark unauthorized" was chosen. A RELATIVE route is
same-origin by construction (resolved against the script's own base
URL, exactly like `crawler.resolve` already does for links) and needs
no separate check. Qualifying routes are persisted as `models.Endpoint`
rows with `Source: "javascript_route"` (new source constant, distinct
from the EXISTING `"javascript"` source, which means "this URL IS a
`<script src>` reference" -- an entirely different thing from "this
URL was found INSIDE a script's own text," which is what
`"javascript_route"` means), `Method: "GET"` (the only method a bare
string literal can be conservatively assumed to use), `APICandidate:
true`, `APIEvidence: "javascript_reference"`.

**Not automatically crawled.** A JS-derived route is recorded for
visibility/reporting -- it is never added to the crawl queue, never
fetched by this phase. Widening the crawl frontier based on an
unvalidated string literal extracted from a script (which could
easily be a stale/wrong/attacker-influenced string) is a real behavior
change this phase deliberately does not make; a future phase that
wants to ACT on a JS-derived route (fetch it, classify its response)
can do so deliberately, as new, explicit, reviewed behavior.

## 6. JSON parameter model and nested paths

No second JSON parameter representation was created -- `parameters.Candidate`/
`models.Parameter` (already the Phase 3.13 model) are reused as-is,
only gaining the one `Provenance` field described in section 2.
`ParseJSONBody`'s existing dot-path nested representation
(`"user.profile.email"`) and array-as-one-field representation
(`"items"` is one Candidate whose Value is the array's compact JSON
form, never descended into) are UNCHANGED -- both were already
correctly and deterministically implemented in Phase 3.13, just
unreached; this phase reaches them, it does not redesign them.

## 7. JSON to mutation integration -- `mutation.applyJSON` fixed for nested paths

`internal/mutation.applyJSON` (Phase 3.17) is extended, not replaced,
to interpret a dotted `Mutation.Parameter` as a nested path descent
rather than a single flat key -- fixing finding 6 above. Implementation
(`mutate.go`):

```go
func setJSONPathEscaped(body []byte, segments []string, value string) ([]byte, error)
func setJSONPathVerbatim(body []byte, segments []string, value string) ([]byte, error)
```
Both recurse one path segment at a time: unmarshal the current level
into `map[string]json.RawMessage`, either set the leaf value (escaped:
`json.Marshal(value)`, always producing valid JSON; verbatim: the raw
string, unvalidated) or recurse into the child object (creating an
empty `{}` if the key doesn't exist yet), then re-marshal. **Escaped**
mode marshals every level normally (`json.Marshal(obj)` -- always
valid, since only valid sub-values are ever embedded). **Verbatim**
mode cannot do this: `encoding/json` validates/compacts every
`json.RawMessage` it marshals as part of a larger structure (the exact
bug Phase 3.17's own top-level verbatim JSON mutation hit and fixed --
see `docs/phase-3-17-acceptance-test.md` "Design decisions" #1), so a
genuinely malformed verbatim leaf must be spliced into its parent (and
that parent into ITS parent, recursively, all the way to the root) by
STRING CONCATENATION, not RawMessage embedding -- generalizing Phase
3.17's own splice technique to every level of a path, not just the
top. A single-segment path (`"q"`, no dots) behaves byte-for-byte
identically to Phase 3.17's original implementation -- proven by
re-running every one of Phase 3.17's own `TestMutate_JSON_*` tests
unchanged after this rewrite.

**A real, worth-documenting interaction, found while writing the lab's
own JSON-to-mutation bridge test.** `setJSONPathEscaped`/
`setJSONPathVerbatim` both re-marshal via `map[string]json.RawMessage`
at every level, which (a standard library guarantee, not a bug)
ALWAYS re-serializes keys in alphabetical order -- so a mutated body's
key order can differ from the original request's own literal wire
order whenever that original wasn't already alphabetical. This is
semantically meaningless (JSON object key order carries no meaning),
but `mutation.Compare`'s body normalization (Phase 3.17, digit-run
collapsing only) is a plain byte-string operation, not JSON-aware --
it cannot tell "the same JSON, keys reordered" apart from "genuinely
different JSON" without becoming a JSON-canonicalizing comparator,
which was deliberately not built (the same "do not over-normalize"
discipline Phase 3.17's own `Compare` design already follows -- see
`docs/phase-3-17-request-mutation.md` section 8). A future detector
comparing a JSON mutation's response against its baseline should be
aware that `StructurallyDifferent` can be `true` purely because of
this key-reordering artifact, independent of any real behavioral
difference from the target -- documented here as a known limitation,
not silently worked around.

An existing key that is present but is NOT itself a JSON object (e.g.
`{"user":"not-an-object"}`, mutating `"user.email"`) produces a clear
error ("existing body is not a JSON object") rather than silently
corrupting data -- `json.Unmarshal` of a JSON string into
`map[string]json.RawMessage` fails naturally, and that failure is
surfaced, not swallowed.

**Deliberately not wired into `BuildTargets`/`Engine.Run`.** Per
section 2, only `Provenance: REQUEST_INPUT` parameters are even
conceptually eligible to become a mutation target -- and this phase's
own live discovery mechanism (section 3) produces exclusively
`RESPONSE_FIELD` parameters, which must NOT automatically become
mutation targets (that would be exactly the "response field = request
parameter" mistake task section 18 forbids). The bridge
(`parameters.Candidate`/`models.Parameter` -> `mutation.Mutation`) is
built as a general-purpose, tested, documented CAPABILITY --
proven end to end in the lab against a real JSON POST endpoint via
`internal/mutation.Executor` directly (not through the crawler, which
cannot POST) -- available for a future detector to call once one
exists that has its own reasoning for which `REQUEST_INPUT` JSON
fields are worth mutating. Nothing in THIS phase automatically
constructs or sends a mutated JSON request against anything discovered
live.

## 8. Scope enforcement

No new scope-decision code was written anywhere in this phase --
section 5's `dialer.Validator.CheckHost` check is the SAME centralized
`scope.Validator` every other stage already uses, reached through the
SAME `*safedial.Dialer` already passed into
`discoverJavaScriptTechnologies`. An out-of-scope JS-derived absolute
URL is dropped before persistence (never recorded as an Endpoint row
at all) rather than "recorded but marked unauthorized" -- a
deliberately simpler, strictly safer choice than inventing a new
"observation without an endpoint" storage concept this phase does not
otherwise need: dropping guarantees such a reference can never later
be mistaken for an authorized target by any downstream code that reads
the `endpoints` table, which a "recorded-but-flagged" design would
require every future consumer to remember to check.

## 9. Storage

Migration `0010_api_json_discovery.sql`:
```sql
ALTER TABLE endpoints ADD COLUMN api_candidate INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpoints ADD COLUMN api_evidence TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN response_content_type TEXT NOT NULL DEFAULT '';
ALTER TABLE parameters ADD COLUMN provenance TEXT NOT NULL DEFAULT 'REQUEST_INPUT';
```
Backward compatible by construction: an old scan's existing `endpoints`
rows read back with `api_candidate = 0` (false) -- they were never
classified before either, so this is not a behavior change, only new
information becoming available going forward. An old scan's existing
`parameters` rows read back with `provenance = 'REQUEST_INPUT'` -- the
factually correct backfill (every one of them WAS discovered the way
that value now means), not a placeholder. No secret is persisted by
either new column. No response/request BODY is persisted anywhere --
`crawler.Page.ResponseBody` is transient, in-memory, consumed by
`NormalizeJSONResponses` within the same scan run and never written to
storage itself (only the derived, already-redacted `Parameter` rows
are persisted, exactly like every other `parameters.Candidate` source
already works).

## 10. Resource limits

- `NormalizeJSONResponses` reuses the EXACT SAME `parameters.Limits`
  (`MaxJSONDepth`, `MaxJSONFields`, `MaxInputsPerEndpoint`,
  `MaxTotalInputs`) `Normalize`/`ParseJSONBody` already enforce -- no
  new knob was needed for JSON-response bounding, only a new call site
  for existing, already-reviewed limits.
- Response body capture is bounded by the crawler's existing
  `maxCrawlBodySample` (512KiB) -- the same constant, not a new one.
- JS route extraction is bounded by the new, small `endpoints.JSLimits`
  (section 5) -- max routes per script, reusing the existing script
  body size bound.
- Arrays remain non-recursed (section 6) -- the existing, already
  correct bound on "maximum array elements inspected" is zero
  per-element inspection, by design, unchanged from Phase 3.13.
- No new unbounded loop exists anywhere in this phase's code --
  every new traversal (JSON walk, script regex scan, route dedup) is
  bounded by an existing or newly-introduced explicit limit.

## 11. Determinism

`ParseJSONBody`'s existing sort-by-name-then-walk-sorted-keys
determinism is unchanged and reused as-is for response bodies too.
`NormalizeJSONResponses` follows `Normalize`'s exact
group/sort/cap/finalize structure (factored into a shared helper, not
duplicated ad hoc). `ExtractAPIRoutes`'s output is deduplicated and
sorted before returning. `ClassifyAPI`'s evidence list is built in a
fixed, declared check order (content-type first, then path heuristic),
never from map iteration. No new code in this phase iterates a Go map
for any externally visible ordering without an explicit sort.

## 12. Authentication / identity

No new authentication code. `crawlAndDiscoverEndpoints`'s existing
`identityName` computation (Phase 3.16, unchanged) is stamped onto
every NEW Endpoint/Parameter row this phase produces (JS-route
endpoints, RESPONSE_FIELD parameters) exactly the same way it already
stamps query/form-derived rows -- one variable, computed once per
target, reused for every row that target's crawl produces, including
the new ones.

## 13. Consistency across query/form/JSON/path

A future detector distinguishes location via the SAME, single
`Parameter.Location` string this codebase has used since Phase 3.13
(`"query"/"path"/"form"/"json"/"header"/"cookie"`) -- this phase adds
no second vocabulary. The one addition, `Provenance`, is orthogonal to
`Location` (a `REQUEST_INPUT` or a `RESPONSE_FIELD` can each, in
principle, have any `Location`, though in practice this phase's own
discovery sources only ever produce `Location: "json"` for
`RESPONSE_FIELD` rows) -- a detector filters on `Location` to know
WHERE a value would be transmitted, and on `Provenance` to know
WHETHER it was ever confirmed accepted, two independent, composable
questions.

## 14. What this phase intentionally does not implement

- No IDOR/BOLA detection, no authorization testing, no mass-assignment
  detection, no comparison of Identity A's vs. Identity B's discovered
  data for any security conclusion.
- No SQLi/XSS/SSRF/command-injection/CSRF expansion.
- No arbitrary fuzzing, no automatic construction of mutated requests
  against anything discovered live (section 7).
- No full JavaScript interpreter, no JS execution, no browser
  automation dependency (section 5).
- No automatic crawling of JS-derived routes (section 5).
- No wiring of the JSON-to-mutation bridge into `BuildTargets`/
  `Engine.Run` (section 7) -- it is a proven, tested, available
  capability, not a live pipeline stage.
- No new generic CLI attack surface (`scanner api attack ...` or
  similar) -- `scanner inputs`'s existing output is extended with
  `Provenance`/API-indicator columns only (section 15... see acceptance
  doc for exact CLI changes).
- No config/profile-specific JSON-discovery knobs -- this capability is
  gated by the SAME `CrawlEnabled` flag input discovery already uses
  (crawling off means nothing to discover from, exactly as before);
  see `docs/phase-3-13-parameter-discovery.md`'s own "profile
  interaction" precedent, unchanged.

## 15. How a future detector consumes this foundation

```go
// Query the store for REQUEST_INPUT-provenance JSON parameters --
// these, and only these, are plausible mutation targets.
params, _ := store.Parameters().ListByScanJob(ctx, scanJobID)
for _, p := range params {
    if p.Location != "json" || p.Provenance != "REQUEST_INPUT" {
        continue
    }
    // Build a mutation target -- nested dot-paths now work correctly
    // (section 7).
    m := mutation.NewMutation(mutation.LocationJSON, p.Name, payload,
        mutation.EncodingEscaped, p.EndpointID, p.ID, p.IdentityContext)
    mutated, err := mutation.Mutate(originalRequest, m, mutation.Policy{})
    // ... execute, compare, interpret -- entirely the future
    // detector's own logic, none of it in this package.
}

// Separately, RESPONSE_FIELD-provenance rows are read as attack-
// surface intelligence, never as something to mutate directly:
for _, p := range params {
    if p.Provenance == "RESPONSE_FIELD" {
        // "this API mentions a field named p.Name" -- informs what a
        // detector might construct and test, but is not itself a
        // confirmed input.
    }
}

// API-candidate endpoints, including JS-derived ones, are queryable
// via the SAME Endpoint rows every other endpoint already uses:
endpoints, _ := store.Endpoints().ListByScanJob(ctx, scanJobID)
for _, e := range endpoints {
    if e.APICandidate {
        // e.APIEvidence explains why; e.Source == "javascript_route"
        // distinguishes a JS-discovered candidate from a crawled one.
    }
}
```
No detector built this way needs its own JSON parser, HTTP client,
authentication logic, scope logic, or mutation engine -- all are
provided by `internal/parameters`, `internal/mutation`, and the
packages both already reuse, exactly as task section 12 asks for.
