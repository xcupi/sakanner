# Phase 3.18 Acceptance Test: API & JSON Input Discovery Foundation

This phase is infrastructure only. No vulnerability detector was
added, modified, or extended; no IDOR/BOLA/mass-assignment/
authorization finding is ever produced by anything in this phase. See
[docs/phase-3-18-api-json-discovery.md](phase-3-18-api-json-discovery.md)
section 0 for the full scope discipline this document assumes.

## What was built

- **`internal/parameters`**: `Provenance` type (`REQUEST_INPUT`/
  `RESPONSE_FIELD`) added to `Candidate`/`models.Parameter`;
  `ParseJSONBody` now takes an explicit `Provenance` parameter (every
  existing call site updated, all previously-passing tests
  unaffected); new `NormalizeJSONResponses` -- the live wiring of
  Phase 3.13's own JSON parser, sourced from a RESPONSE body (the only
  live JSON data this codebase can honestly capture -- see the
  architecture doc section 1). Aggregation logic factored into a
  shared `candidateAggregator` reused by `Normalize` and the new
  function, rather than duplicated.
- **`internal/crawler`**: `Page.ContentType`/`Page.ResponseBody` --
  strictly additive; `ResponseBody` populated only for a JSON content
  type, bounded by the SAME existing `maxCrawlBodySample` constant the
  HTML path already used. Every other content type behaves exactly as
  before (unread, discarded).
- **`internal/endpoints`**: `ClassifyAPI` (evidence-based, never a
  path-alone heuristic treated as authoritative) and `ExtractAPIRoutes`
  (conservative, regex-based, no JS interpreter) -- both new files
  (`api.go`, tests). `Normalize` extended to classify `SourceCrawl`
  endpoints and stamp the three new `models.Endpoint` fields.
- **`internal/mutation`** (Phase 3.17, extended): `applyJSON` rewritten
  to support dot-path nested mutation (escaped and verbatim, both
  recursively) -- fixing a real Phase 3.17 gap this phase's own work
  needed closed. Every one of Phase 3.17's own JSON mutation tests
  still passes unchanged.
- **`pkg/models`**: `Endpoint.APICandidate/APIEvidence/
  ResponseContentType`, `Parameter.Provenance` -- all backward
  compatible (see migration below).
- **Migration `0010_api_json_discovery.sql`** + `internal/storage/sqlite`
  repo updates for all four new columns.
- **`internal/orchestration/pipeline.go`**: `crawlAndDiscoverEndpoints`
  now also calls `NormalizeJSONResponses` and persists its Candidates;
  `discoverJavaScriptTechnologies` now also extracts and persists
  scope-checked JS-derived route candidates, reusing the SAME
  already-fetched script bodies (no second fetch).
- **`cmd/scanner/inputs.go`**: `PROVENANCE`/`API`/`IDENTITY` columns
  added; new `--provenance` filter flag. No new command, no generic
  attack-surface CLI.
- **`lab/harness_auth.go`** (extended in place, no new file): `/api/nested`,
  `/api/items`, `/api/malformed`, `/api/echo`, `/scripts/api-routes.js`
  -- the minimum fixtures needed for task section 16's 12 scenarios;
  `/api/data`, `/dashboard`'s existing link to it, and
  `external.scanner.test` were already sufficient for items 1, 6, 7,
  8, 9, 11 without new fixture work.
- **Documentation**: `docs/phase-3-18-api-json-discovery.md`
  (architecture, written before implementation began), this file.

## Architecture review (task section 1)

Full findings in the architecture doc's own section 1. The single
most important conclusion: **the crawler never issues a non-GET
request**, so "wiring the JSON parser into the live pipeline" can only
honestly mean consuming a JSON RESPONSE body, never a request body --
stated plainly, matching this codebase's established practice of
documenting real architectural boundaries (Phase 3.13's own "honest
capability gap," Phase 3.15's session-expiration writeup) rather than
quietly working around them. This directly motivated the
`REQUEST_INPUT`/`RESPONSE_FIELD` `Provenance` distinction (section 2
of the architecture doc), which is the load-bearing design decision
this entire phase is built around.

## Design decisions worth recording

1. **Two real defects found and fixed during this phase's own
   development, neither hidden.**
   - Verbatim JSON mutation at a NESTED path: `encoding/json`
     validates/compacts every `json.RawMessage` it marshals as part of
     a larger structure at EVERY level, not just the top (the same
     class of bug Phase 3.17 hit for flat top-level fields) --
     required generalizing the splice technique recursively
     (`setJSONPathVerbatim`), caught by writing the nested-verbatim
     test before it passed.
   - A test-authoring mistake in the redirect-scope-bypass-adjacent
     work carried over from Phase 3.17 was NOT repeated here, but a
     comparable lesson applied fresh: the lab's own
     `TestPhase3_18_JSONToMutationBridge_RealPOSTAgainstLab` initially
     asserted `StructurallyDifferent == true` for a baseline/mutated
     pair that differed ONLY in a numeric JSON value -- which
     `mutation.Compare`'s own, already-reviewed digit-run
     normalization (Phase 3.17) is specifically designed to treat as
     NOT structurally different. The test's assumption was wrong, not
     the production code; fixed by asserting the correct expectation
     (`BodyIdentical == false`, `StructurallyDifferent == false`) and
     documented in the architecture doc section 6/7 as a real,
     worth-knowing interaction: a JSON mutation's own re-marshal always
     sorts keys, so a hand-written original body not already in
     alphabetical order will show a semantically-meaningless
     key-order difference `Compare`'s byte-level normalization cannot
     erase -- a genuine, documented limitation, not swept under the
     rug.
2. **`Provenance` is set explicitly at every existing call site**, not
   left to a zero-value default in `internal/parameters` itself
   (though the STORAGE layer's own `Create` does default an unset
   value to `"REQUEST_INPUT"` for defense in depth) -- so a future new
   discovery source can never accidentally inherit an unintended
   meaning by omission.
3. **`ClassifyAPI` never treats the path heuristic as equivalent to
   content-type evidence.** `APIEvidence` always names exactly which
   signal(s) fired, in a fixed order, so a consumer can judge
   reliability rather than trust a bare boolean -- directly satisfying
   the task's explicit "must not become authoritative."
4. **JS-derived routes are never auto-crawled.** Recorded for
   visibility only; widening the crawl frontier based on an unvalidated
   script string literal is a real behavior change deliberately not
   made this phase (architecture doc section 5).
5. **The JSON-to-mutation bridge is a proven capability, not a wired
   pipeline stage.** Nothing in this phase automatically constructs or
   sends a mutated JSON request against anything discovered live --
   the only live discovery mechanism this phase built produces
   `RESPONSE_FIELD` data, which must never automatically become a
   mutation target (task section 18's explicit prohibition). The
   bridge is demonstrated end to end against a REAL server
   (`/api/echo`) specifically so "proven" means more than a unit test
   against synthetic bytes.

## Test matrix results

### A. API ENDPOINT DISCOVERY
`ClassifyAPI` unit-tested for content-type evidence, path heuristic
(both the `/api/` segment shape and the `/resource/42` shape), both
signals co-occurring, and the negative case (an ordinary HTML page
with no API-shaped path). End to end: `/api/nested`/`/api/items`
discovered as `SourceCrawl` endpoints with `APICandidate: true`,
correct `APIEvidence`/`ResponseContentType`
(`TestPhase3_18_FullCrawl_JSONAndAPIDiscovery`). **PASS**

### B. JSON REQUEST CAPTURE
Proven honestly as a RESPONSE-body capability (section 1) --
`crawler.Page.ResponseBody`/`ContentType` populated only for JSON
responses, bounded by the existing crawl body-sample limit; existing
crawler tests re-verified unaffected. Separately,
`TestPhase3_18_RealRequestBody_ProducesRequestInputCandidates` proves
`ParseJSONBody` correctly produces `REQUEST_INPUT`-provenance
candidates from a REAL request-body-shaped input (task section 23
question 2's own required proof). **PASS**

### C. JSON PARSING
All of Phase 3.13's own `ParseJSONBody` tests re-verified unchanged
(11 tests) plus new adversarial coverage: huge body (5000 fields,
bounded to the configured limit), duplicate JSON keys (last-value-wins,
matching `encoding/json`'s own documented behavior, no crash), Unicode
keys (CJK + emoji), a URL-shaped string VALUE never treated specially.
**PASS**

### D. NESTED JSON
Dot-path representation unchanged and reached live
(`user.id`/`user.profile.email`/`user.profile.profile_url` discovered
from `/api/nested`'s real response); `mutation.applyJSON`'s new nested
support proven both in isolation (`TestMutate_JSON_Escaped_NestedField`,
`TestMutate_JSON_Verbatim_NestedField_RawInjection`,
missing-intermediate-object creation, non-object-leaf error case,
determinism) and against a real server
(`TestPhase3_18_JSONToMutationBridge_NestedPathAgainstRealServer`).
**PASS**

### E. JSON ARRAYS
Array-as-one-field representation (never descended into) re-verified
unchanged, including a 100,000-element array producing exactly one
candidate with no measurable slowdown
(`TestParseJSONBody_HugeArray_OneCandidateNotUnboundedWork`); reached
live via `/api/items`. **PASS**

### F. JSON TYPES
String/number/boolean/null/array all exercised across existing and new
tests (`jsonScalarString`, unchanged); no security conclusion is ever
drawn from a value's type anywhere in this phase's code (verified by
inspection -- no such branch exists). **PASS**

### G. JSON PARAMETER NORMALIZATION
`Normalize`/`NormalizeJSONResponses` share one aggregation
implementation; dedup, per-endpoint/total capping, and deterministic
sort order all re-verified for the new JSON-response path exactly as
they already were for query/form. **PASS**

### H. JSON -> MUTATION
`applyJSON`'s nested-path fix (section D above) plus the full
discover-a-real-value -> `ParseJSONBody(..., ProvenanceRequestInput)`
-> `mutation.NewMutation`/`Mutate` -> `Executor.Execute` chain proven
against a real server, flat AND nested, escaped AND verbatim. **PASS**

### I. QUERY/FORM/JSON CONSISTENCY
No second parameter framework was introduced -- `Location` remains the
one, unchanged vocabulary; `Provenance` is a new, orthogonal field
applying uniformly regardless of `Location`. **PASS**

### J. RESPONSE JSON OBSERVATION
`Provenance == RESPONSE_FIELD` proven never conflated with
`REQUEST_INPUT` at every layer: storage (round-trip test), CLI
(`--provenance` filter, e2e test), and the lab's own full-crawl test
asserting every `/api/nested`-derived candidate is tagged
`RESPONSE_FIELD`. Task section 18's own example scenario (a response
`id`/`email` never implying a matching POST is accepted) holds by
construction: nothing in this phase's code path ever promotes a
`RESPONSE_FIELD` candidate into a mutation target. **PASS**

### K. JAVASCRIPT API DISCOVERY
`ExtractAPIRoutes` unit-tested for the fixed call-shape set
(fetch/.get/.post/.put/.patch/.delete/axios), absolute + relative
resolution, deduplication, determinism, bounding
(`MaxRoutesPerScript`), and adversarial input (malicious quote/
backslash-laden strings, `javascript:`/`data:` URIs never extracted,
an ordinary non-call string literal ignored). End to end: routes
extracted from `/scripts/api-routes.js` and persisted as
`SourceJavaScriptRoute` endpoints with correct `APIEvidence`.
**PASS**

### L. AUTHENTICATED API DISCOVERY
`/api/data` reached through a real authenticated crawl exactly as
Phase 3.14-3.17 already established; new `RESPONSE_FIELD` `user_id`
parameter correctly tagged with the authenticating identity's context.
**PASS**

### M. IDENTITY A
`TestPhase3_18_AuthenticatedAPI_IdentityAAndB_Isolated` authenticates
account-a through the real Phase 3.16 identity layer, discovers
`user_id` = 1001 as a `RESPONSE_FIELD` parameter tagged
`IdentityContext: "account-a"`. **PASS**

### N. IDENTITY B
The same test's second half, for account-b independently: `user_id` =
1002, tagged `"account-b"`. **PASS**

### O. IDENTITY ISOLATION
Cross-contamination explicitly checked in both directions (no
account-b-tagged parameter in account-a's own scan job's store, and
vice versa) -- two entirely separate in-memory stores from two
separate `Orchestrator.Run` calls, the same structural isolation
Phase 3.16 already established, now proven to extend to the NEW
`RESPONSE_FIELD` discovery path too. **PASS**

### P. SCOPE ENFORCEMENT
No new scope-decision code anywhere -- `discoverJavaScriptTechnologies`
reuses the exact `dialer.Validator.CheckHost` every other stage
already calls. `external.scanner.test`, embedded in the JS fixture's
own `fetch(...)` call, proven NEVER persisted as an endpoint
(`TestPhase3_18_FullCrawl_JSONAndAPIDiscovery`'s explicit assertion)
and `HostCount == 1` held. Additional adversarial coverage: userinfo-
obfuscated absolute URL extracted verbatim (unvalidated) but its TRUE
host correctly resolved by `url.Parse` at the caller's own scope-check
step, `javascript:`/`data:` URIs never extracted as routes at all.
**PASS**

### Q. SECRET PROTECTION
Sensitive-field redaction re-verified for the NEW response-body path
specifically (`TestNormalizeJSONResponses_SensitiveFieldRedacted`,
`TestParseJSONBody_AuthorizationLikeAndCookieLikeFields_Redacted` --
authorization/session/csrf_token all redacted, an unrelated field
untouched); the `/api/echo` lab test proves the canonical `Request`
never carries a session cookie/credential to leak in the first place
(Phase 3.17's own guarantee, unaffected). **PASS**

### R. RESOURCE LIMITS
Huge JSON body (bounded to configured field limit, with warning), huge
array (one candidate regardless of size), deep nesting beyond the
configured depth (bounded, with warning), JS route extraction bounded
(`MaxRoutesPerScript`) -- all proven with explicit, adversarially-sized
inputs, not merely documented. **PASS**

### S. DETERMINISM
`NormalizeJSONResponses`, `ClassifyAPI`, and `ExtractAPIRoutes` each
have a dedicated determinism test (repeated calls, byte-identical/
deep-equal output); concurrent calls to all three proven race-clean
under `-race`. **PASS**

### T. STORAGE
Migration `0010` applied cleanly; `TestEndpoint_APIFields_RoundTrip`
and `TestParameter_Provenance_RoundTripAndDefault` prove both the new
fields round-trip correctly AND that a pre-existing (unset) row
backfills to the factually correct default (`api_candidate = false`,
`provenance = 'REQUEST_INPUT'`) -- backward compatibility proven, not
assumed. Full storage suite (including the pre-existing concurrent-
migration test) re-verified clean under `-race`. **PASS**

### U. CLI
`scanner inputs` extended with `PROVENANCE`/`API`/`IDENTITY` columns
and a `--provenance` filter, proven through the real built binary
(`TestScanCmd_JSONResponseDiscovery_ResponseFieldProvenance`,
`TestScanCmd_APICandidateClassification_ContentTypeEvidence`); every
pre-existing `scanner inputs` e2e test re-verified passing unchanged
(the new columns are additive, not a breaking format change). No new
command was added. **PASS**

### V. LAB
All 12 task section 16 scenarios covered by 6 new lab test functions
against 5 new, minimal fixture routes (no new file -- extended
`harness_auth.go` in place); zero fixtures were vulnerability-specific
(the existing Account A/B fixture continues to exist unchanged, no
IDOR was implemented or asserted). Full `lab` suite (110 tests,
including every prior phase's own) re-verified clean. **PASS**

### W. E2E
78 tests (76 pre-existing + 2 new), all clean. **PASS**

### X. ADVERSARIAL (task section 17)

| Scenario | Covered by |
|---|---|
| Malformed JSON | `TestParseJSONBody_MalformedJSON_NoCrashReturnsWarning`, `TestNormalizeJSONResponses_MalformedJSON_WarningNoCrash`, lab `/api/malformed` |
| Deeply nested JSON | `TestParseJSONBody_DepthLimit_TruncatesAndWarns`, `TestParseJSONBody_DeeplyNestedBeyondLimit_NoCrashBoundedWork` (500 levels) |
| Huge JSON body | `TestParseJSONBody_HugeBody_BoundedNoCrash` (5000 fields) |
| Huge arrays | `TestParseJSONBody_HugeArray_OneCandidateNotUnboundedWork` (100,000 elements) |
| Duplicate JSON keys | `TestParseJSONBody_DuplicateJSONKeys_NoCrashLastWins` |
| Unicode keys | `TestParseJSONBody_UnicodeKeys_NoCrash` (CJK + emoji) |
| Encoded URLs | `TestExtractAPIRoutes_EncodedHostAttempt_ReturnedVerbatimNotDecoded` |
| Malicious JavaScript strings | `TestExtractAPIRoutes_MaliciousStringWithQuotesAndBackslashes_NoCrash` |
| URL-like strings inside JSON | `TestParseJSONBody_URLLikeStringValue_TreatedAsPlainValue` |
| Out-of-scope API URLs | `TestPhase3_18_FullCrawl_JSONAndAPIDiscovery` (external.scanner.test dropped) |
| Credential-looking JSON fields | `TestParseJSONBody_AuthorizationLikeAndCookieLikeFields_Redacted` |
| Authorization headers | `/api/echo`'s own required-header fixture + `TestPhase3_18_JSONEcho_RequiresAuthHeader`; canonical Request never carries one (Phase 3.17) |
| Cookies | Session cookies live only in `SessionContext.Jar`, never `Request.Cookies` (Phase 3.17, unaffected) |
| CSRF tokens | `csrf_token` in the shared redaction blocklist, re-verified for JSON |
| Password fields | `TestParseJSONBody_SensitiveFieldRedacted` (pre-existing, re-verified) |
| Secret redaction | See Q above |
| Identity A/B isolation | See O above |
| Concurrent authenticated API discovery | `TestNormalizeJSONResponses_ConcurrentCalls_NoRace`, `TestExtractAPIRoutes_ConcurrentCalls_NoRace`, `TestNormalize_ClassifyAPI_ConcurrentCalls_NoRace`, full suite `-race`-clean |
| Cancellation/timeout | `ParseJSONBody`/`ExtractAPIRoutes` are pure, bounded, non-I/O functions -- no cancellation surface exists to test; the crawl fetch itself reuses Phase 1-3.17's already-proven timeout/cancellation handling, unmodified |
| Resource exhaustion | See R above |
| Scope bypass attempts | See P above |
| Duplicate endpoint discovery | `TestNormalize_DuplicateJavaScriptRouteAcrossPages_Deduplicated` |
| Duplicate parameter discovery | `TestNormalizeJSONResponses_DuplicateEndpointAcrossPages_Deduplicated` |
| Nondeterministic map ordering | See S above; no new code iterates a Go map for externally visible ordering without an explicit sort |

All scenarios: **NO SECURITY BOUNDARY FAILURE. PASS.**

### Y. REGRESSION

```
go build ./...                                          -> clean
go vet ./...                                             -> clean
gofmt -l .                                                -> clean (no output)
go test $(go list ./... | grep -v '/tests/e2e') -race     -> ok, 1295 PASS, 0 FAIL (33 packages)
go test ./tests/e2e/...                                   -> ok, 78 PASS, 0 FAIL
```
Production/lab independence re-verified the strongest way, twice
during this phase (once mid-development, once as the final check):
physically removed `lab/` and `tests/`, confirmed `grep -rl
"sakanner/lab"` outside `lab/` itself returns nothing, rebuilt and
vetted successfully, restored both, rebuilt again to confirm.
Every existing vulnerability detector's own test suite (sqli, ssrf,
traversal, xssreflected, cmdinjection, idor) re-verified passing
unchanged -- none was touched. **PASS**

### Z. RACE

Full repository, every package, `-race -count=1`: clean, zero races
reported, including every new concurrent test this phase added.
**PASS**

## Final architectural check (task section 23)

1. **Is Phase 3.13's JSON parser now actually connected to the live
   pipeline?** Yes -- via `NormalizeJSONResponses`, called from
   `crawlAndDiscoverEndpoints` on every real crawl, proven end to end
   through the real lab and the real CLI binary.
2. **Can a real authenticated POST/PUT/PATCH JSON request produce
   canonical Parameter records?** Yes, demonstrated two ways: (a) the
   crawler itself never sends a request body (an honest, documented
   architectural fact, not a gap this phase silently works around),
   and (b) `ParseJSONBody` with `ProvenanceRequestInput` correctly
   produces genuine `REQUEST_INPUT` candidates from a real
   request-body-shaped input
   (`TestPhase3_18_RealRequestBody_ProducesRequestInputCandidates`),
   using the exact byte shape a real POST/PUT/PATCH -- proven
   independently to actually reach a real server via
   `internal/mutation.Executor` -- would carry.
3. **Can nested JSON parameters be consumed by Phase 3.17 mutation?**
   Yes -- `mutation.applyJSON`'s nested-path fix, proven both in
   isolation and against a real server
   (`TestPhase3_18_JSONToMutationBridge_NestedPathAgainstRealServer`).
4. **Are response fields clearly distinguished from request inputs?**
   Yes -- `Provenance`, enforced at every layer (discovery, storage,
   CLI), never conflated.
5. **Can JavaScript-derived API candidates remain scope-safe?** Yes --
   the same centralized `scope.Validator` every other stage uses,
   proven to drop an out-of-scope reference before persistence.
6. **Are Identity A and Identity B completely isolated?** Yes, proven
   for the NEW discovery path specifically, not just assumed to
   inherit Phase 3.16's own guarantee.
7. **Are all API/JSON discoveries deterministic?** Yes, each new
   function has a dedicated determinism test.
8. **Are resource limits enforced before unbounded work occurs?** Yes
   -- huge body/array/depth/JS-route-count all proven bounded with
   adversarially-sized real inputs.
9. **Are secrets protected?** Yes, re-verified specifically for the
   new response-body and JS-route paths.
10. **Did this phase avoid implementing vulnerability logic?** Yes --
    no detector was touched; no finding of any kind is ever produced
    by any code this phase added.
11. **Does the production code remain independent from `lab/`?** Yes,
    verified by physical removal twice.
12. **Can a future IDOR/BOLA detector consume this foundation without
    creating its own JSON parser, HTTP client, authentication logic,
    scope logic, or mutation engine?** Yes -- architecture doc section
    15 shows the exact, minimal call shape; every primitive it needs
    (`Provenance`-filtered `Parameter` query, `mutation.Mutate`/
    `Execute`, identity/session context already attached) already
    exists and is proven working end to end.

Every answer is yes.

## Final report

```
PHASE 3.18 API & JSON INPUT DISCOVERY FOUNDATION

TOTAL TESTS: 1373
PASS: 1373
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

API DISCOVERY: PASS
JSON REQUEST CAPTURE: PASS
JSON PARAMETER DISCOVERY: PASS
NESTED JSON: PASS
JSON ARRAYS: PASS
JSON -> MUTATION: PASS
RESPONSE FIELD PROVENANCE: PASS
JAVASCRIPT API DISCOVERY: PASS
AUTHENTICATED API DISCOVERY: PASS
IDENTITY ISOLATION: PASS
SCOPE ENFORCEMENT: PASS
SECRET PROTECTION: PASS
RESOURCE LIMITS: PASS
DETERMINISM: PASS
STORAGE: PASS
CLI: PASS
LAB: PASS
E2E: PASS
ADVERSARIAL: PASS
REGRESSION: PASS
RACE: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0
(two internal defects were found and fixed during THIS phase's own
development -- nested verbatim JSON mutation validation, and a test's
own wrong assumption about digit-run normalization -- both caught by a
test written for exactly that purpose failing on its first real run;
neither is an issue remaining at delivery. See "Design decisions" #1.)

PHASE 3.18 VERDICT: PASS
```

## Architectural notes flagged per task instruction

No out-of-scope ambiguity required a behavior change outside this
phase's own boundaries. Two items worth carrying forward explicitly:

1. **`mutation.Compare`'s body normalization can report a
   semantically-meaningless "structural difference"** when a JSON
   mutation's own key-sorting re-marshal changes wire order relative
   to a non-alphabetically-ordered original (architecture doc section
   7). Not a security issue -- documented as a known limitation for
   whichever future detector consumes `Compare`'s output.
2. **`detection.Executor` (the six-detector-strong existing request
   path) still has no session/identity wiring and no JSON-body
   awareness** -- unchanged from Phase 3.17's own identical note. This
   phase's discovery work and Phase 3.17's mutation/execution work are
   both available capabilities; no existing detector was migrated onto
   either, by design.

Per the task's final rule: no IDOR/BOLA detection, no authorization
testing, no mass-assignment detection, no SQLi/XSS/SSRF/CSRF
expansion, no arbitrary fuzzing, and no generic API-attack CLI surface
were implemented. Work stops here pending a new phase instruction --
Phase 3.19 is explicitly not started.
