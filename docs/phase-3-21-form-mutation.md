# Phase 3.21: Form Request Discovery & Active Body Mutation Foundation

## 0. Scope discipline

This phase closes the Phase 3.20 documented limitation: POST-form
parameters never reach active detection. It is FOUNDATION ONLY. No new
vulnerability detector, no IDOR/BOLA, no authorization testing, no
mass assignment detection, no CSRF vulnerability detection, no file
upload testing, no SSTI/XXE/deserialization, no business-logic
testing, no new CLI commands, no time-based SQLi. `sqliactive` is
extended by the minimum adapter needed to consume `LocationForm`; no
other detector is modified.

## 1. Architecture review

### 1.1 How HTML POST forms are currently discovered

Already fully implemented, since Phase 3.13 — this phase does **not**
need to add form discovery. `internal/crawler.extractRefs`
(`crawler.go:280-295`) records one `FormRef{Action, Method, Fields}`
per `<form>` on every crawled page, with `Action` always resolved to
an absolute URL against the page's own base (`resolve`, mirroring the
`<a href>`/`<script src>` resolution). `extractFormFields`
(`crawler.go:332-379`) walks the form's subtree collecting every named
`<input>`/`<select>`/`<textarea>`, excluding submit/button/image/reset/
file controls (`nonInputControlTypes`, `crawler.go:320-322`).
`FormField{Name, Type, Value}` already carries the raw HTML `type`
attribute (`"hidden"`, `"text"`, `"checkbox"`, `"select"`,
`"textarea"`, ...) — this is used below.

**Finding 1 (gap):** unlike `<a href>` links, which are filtered to
same-origin *before* being added to `page.Links`
(`crawler.go:242-249`), form actions are recorded with **no**
same-origin filtering at all (`crawler.go:250`: `page.Forms = forms`,
unconditional). A form whose action points at a different host is
still discovered as a `FormRef` with that host's absolute URL.

### 1.2 / 1.3 How form fields become Parameter records, and their Location

Also already implemented. `internal/parameters.addFormCandidates`
(`normalize.go:277-303`) converts each `FormRef` into one `Candidate`
per named field: `Location = LocationForm` (`"form"`, already a
defined value in `internal/parameters.Location`'s enum,
`model.go:11`) for a POST (or any non-GET) form, or `LocationQuery`
for a GET form (a GET form's fields are transmitted as the URL's
query string, so it reuses the same location every other query
parameter already uses — `docs/phase-3-13-parameter-discovery.md`'s
own established rationale, unchanged). `Provenance` is always
`ProvenanceRequestInput` — every field the application itself renders
for submission is, by definition, something it accepts as an input.
These candidates are persisted as `models.Parameter` rows exactly like
query parameters (`pipeline.go:814-830`).

**Finding 2 (gap):** `Candidate` (`normalize.go:24-40`) and
`models.Parameter` (`models.go:296-359`) carry `Name`/`Location`/
`Value`/`Source`/`ContentType`/`Provenance`, but **not** the field's
HTML `type` attribute — `crawler.FormField.Type` is read by
`extractFormFields` but discarded by `addFormCandidates`, which never
reads `f.Type` at all. There is currently no way to determine, from a
persisted `Parameter`, whether the field that produced it was hidden.

### 1.4 How HTTP method and content type are represented

Already fully preserved. `Candidate.EndpointMethod`/`Parameter.Method`
carries the form's own `Method` (`form.Method`, uppercased at
discovery, `crawler.go:293`). `Candidate.ContentType`/
`Parameter.ContentType` is set to `"application/x-www-form-urlencoded"`
for a POST form (`normalize.go:280`), `""` for a GET form (query
strings have no body content type). No gap here.

### 1.5 Whether the original form action is preserved

Partially. `FormRef.Action` (an absolute URL) is preserved as far as
`internal/endpoints.Normalize` and `internal/parameters.addFormCandidates`,
both of which call `endpoints.PathOf(form.Action)` — and `PathOf`
(`endpoints.go:96-108`) **strips the host entirely**, keeping only
path(+query). Neither `Candidate` nor `models.Parameter` nor
`models.Endpoint` has any field that could carry a host, scheme, or
port (verified by reading every field of all three types in full).
This is the central finding of this review — see 1.7 below for the
consequence.

### 1.6 Whether the original request body is preserved

**No — this is the second central finding.** A `detection.Target` is
built per (endpoint, ONE parameter) pair
(`internal/detection/targets.go:170-186`, `endpointTargets`); nothing
anywhere aggregates a form's OTHER sibling field values onto the
Target that represents one specific field. `detection.NewMutationRequest`
(`mutation_bridge.go:38-64`) never sets `Body` on the `mutation.Request`
it builds — confirmed by reading the full function: no `Body:` key
appears in the returned struct literal. This means that if a form
target were wired into `BuildTargets` today exactly as-is, the
"original" (baseline) request `Mutate` clones and mutates would have
an **empty** body — every sibling field (including a CSRF token, and
every other legitimate field the target application's validation logic
may require) would be silently absent from every mutated request, not
merely left unmutated. `mutation.applyForm` (`mutate.go:188-211`) is
correct about *preserving what's in `req.Body` when it mutates one
field* — the defect is that nothing ever puts the form's other field
values into `req.Body` in the first place. Section 3 below designs the
fix.

### 1.7 Whether BuildTargets can currently produce mutation-capable targets for form inputs

**No.** `BuildTargets`/`endpointTargets`
(`internal/detection/targets.go:100-108, 170-186`) only route
`Location == "query"` or `Location == "json" && Provenance ==
"REQUEST_INPUT"` parameters into `Target`s — `Location == "form"`
matches neither switch arm and produces no Target at all. This is
exactly the Phase 3.20-documented limitation, confirmed by direct
re-reading of the current file, not merely re-asserted from memory.

**Finding 3 (a second, worse gap discovered while investigating
Finding 3):** `internal/endpoints.Normalize`
(`endpoints.go:38-86`) assigns **every** endpoint — regardless of
`Source` (`SourceCrawl`/`SourceLink`/`SourceForm`/`SourceJavaScript`)
— to the SAME `HTTPServiceID`: the crawl target currently being
crawled (`pipeline.go:788`: `e.HTTPServiceID = target.httpServiceID`,
unconditional, no per-source branch). Combined with Finding 1 (forms
are never same-origin-filtered) and 1.5 (the action's host is
irrecoverably stripped before persistence): a form whose action points
at a **different host** — in scope or not — is, under the current data
model, **structurally indistinguishable from a same-origin form**. If
`BuildTargets` were extended to route form parameters into Targets
using `Target.Host`/`IP`/`Port` exactly as it does for query/JSON
parameters today (both of which always derive from the Endpoint's own
`HTTPServiceID`), a cross-origin form's fields would silently become a
Target dialed against the *crawled page's own* host — never the
form's real destination. This is **not** a scope bypass (the request
never reaches an unvalidated host; `Target.Host`/`IP` always trace
back to an already-scope-validated `HTTPService`), but it **is** a
correctness defect: the form's real target (which may be a
legitimately different in-scope host+port, e.g. a separate API
service) is silently never reached, and an out-of-scope form's fields
are silently treated as if they belong to the in-scope page instead of
simply being excluded. Section 5 designs the fix: a same-origin gate,
applied uniformly to any Endpoint whose `Source == "form"`
(POST-form-body or GET-form-query alike), mirroring the precedent
`<a href>` already sets (a cross-origin reference is discovered but
never promoted to something the scanner acts on).

This is the single most consequential finding of this review — it
determines the entire design of sections 2, 3, and 5 below.

### 1.8 How mutation currently represents form bodies

**Already fully implemented and correct — no core engine change is
needed.** `mutation.LocationForm` already exists in the `Location`
enum (`mutate.go:24`), and `Mutate`'s `case LocationForm:` branch
(`mutate.go:142-145`) calls `applyForm` (`mutate.go:188-211`), which:
parses the existing `req.Body` as `application/x-www-form-urlencoded`
via `url.ParseQuery` (treating an empty body as an empty value set —
the same convention every other Location follows), sets or
verbatim-splices the one named parameter, re-serializes via
`url.Values.Encode()` (escaped) or manual concatenation (verbatim),
and always sets `req.ContentType = "application/x-www-form-urlencoded"`.
This is a genuinely complete, already-tested (Phase 3.17) mechanism.
The gap is entirely upstream of it: nothing builds a `Target` with
`ParameterLocation == "form"` in the first place (1.7), and nothing
seeds the baseline `req.Body` with the form's other fields before
`Mutate` is ever called (1.6).

### 1.9 / 1.10 Whether authenticated sessions and identity context survive form mutation

Yes, unconditionally, with zero form-specific code needed. Every
active-detection request — regardless of `Location` — flows through
`Executor.ExecuteMutation` → `mutation.Executor.Execute`, which is
session-aware whenever `buildDetectionExecutor` (Phase 3.19) threaded
a session in; `Target.IdentityContext` is copied onto every `Mutation`/
`Request`/`Finding` (`detection.NewMutationRequest`,
`mutation.NewMutation`, `normalizeFinding`) the same way for every
Location. This machinery is Location-agnostic by construction — it
never inspects `ParameterLocation` at all. No changes needed here;
verified by (re-)reading `mutation_bridge.go` and
`internal/orchestrator/orchestrator.go`'s `buildDetectionExecutor` in
full.

### 1.11 / 1.12 Whether scope is checked against the final destination, and whether redirects can bypass it

Yes for the FINAL NETWORK HOP: `mutation.Executor.Execute` (unchanged,
reused) delegates to the identical `scope.Validator`/`safedial.Dialer`
sequence every other execution path already uses, and redirects are
handled by `safedial`'s own `CheckRedirect`, already adversarially
proven not to leak session state or follow an out-of-scope redirect
(Phase 3.17/3.19's own test suites, re-verified unchanged this phase).

**However** (this is Finding 3 restated from the angle of section 8's
adversarial requirements): the scope check that matters for FORM
DISCOVERY specifically is not "does `safedial` refuse to dial an
out-of-scope host" (it already does, and always has) — it is "does a
form whose action names a different host ever get treated as if its
fields belong to the CURRENT, in-scope host's endpoint instead of
being excluded outright." Today it does (Finding 3); this phase closes
that gap at the `BuildTargets` level (section 5), not by changing
`safedial`/`scope.Validator` (neither needs to change; the fix is
entirely about which Targets get built in the first place).

### 1.13 Whether CSRF tokens / hidden fields are distinguishable from ordinary parameters

**No, currently.** Confirmed by Finding 2 (1.3 above): the HTML
`type` attribute is discarded before persistence, so "was this field
hidden" is not recoverable from a `Parameter` row. Separately,
`internal/evidence.sensitiveFieldNames` (`redact.go:36-63`) already
exact-matches `csrf`/`csrf_token`/`xsrf`/`xsrf_token` (added in Phase
3.15, for the `/settings` fixture's own hidden field) and redacts
their **value** at discovery time — but this is a value-redaction
concern (protecting what gets logged/reported/persisted), not a
targeting concern (deciding whether a field should ever be offered as
something a detector can choose to mutate). No such targeting-level
classification exists anywhere today. Section 2/5 add one.

### 1.14 Whether multipart/form-data exists anywhere in the current architecture

No — confirmed by grep across `internal/crawler`, `internal/parameters`,
`internal/mutation`: no reference to `multipart`, `boundary`, or
`mime/multipart` exists anywhere in this codebase outside vendored
dependencies. `nonInputControlTypes` already excludes `"file"` inputs
entirely from discovery (`crawler.go:320-322`, Phase 3.13's own
decision, unchanged: "a file upload's meaningful attack surface is its
content, not a string value this model represents"). This phase does
not add multipart support — file upload testing is explicitly out of
scope (task section 17), and every discoverable form field this
codebase models is a plain string value, which `application/
x-www-form-urlencoded` fully represents.

### 1.15 Whether there is a canonical HTTP-body representation that can safely support form mutation

Yes: `mutation.Request.Body []byte` + `mutation.Request.ContentType
string` (`request.go:49-50`), already the single representation every
Location's `apply*` function writes into. No second, parallel body
representation is needed or introduced by this phase — the fix is
entirely about (a) who is allowed to become a `Target` at all
(sections 2, 5) and (b) seeding that one existing `Body` field
correctly before `Mutate` runs (section 3).

## 2. Canonical form input model — what this phase adds

Three small, additive fields, each with a documented, narrow purpose.
Nothing is removed or renamed; every existing consumer of `Candidate`/
`models.Parameter`/`models.Endpoint` continues to compile and behave
identically for non-form data (every new field defaults to its Go
zero value, and is only ever populated for `Source == "form"` /
form-derived data).

1. **`parameters.Candidate.FieldType string`** — the raw HTML `type`
   attribute (`crawler.FormField.Type`, already available, previously
   discarded). `""` for every non-form candidate (query, JSON).
2. **`models.Parameter.Hidden bool`** — `true` iff `FieldType ==
   "hidden"`. Answers task section 2's "whether the field was hidden"
   directly, without inventing a new enum.
3. **`models.Endpoint.ActionOrigin string`** — the form action's
   normalized `scheme://host:port` origin, computed from `form.Action`
   *before* `PathOf` strips it, populated only for `Source == "form"`
   rows (`""` for every other source, including every row that existed
   before this migration). This is the field that makes Finding 3's
   fix possible: `BuildTargets` can now compare a form endpoint's
   `ActionOrigin` against the HTTPService it would otherwise dial, and
   simply exclude a mismatch, exactly as `<a href>` cross-origin links
   are already excluded from being followed at all.

**"Whether the field appears to be a CSRF/security token"** is
answered by a new, conservative, name-based pure function,
`parameters.IsLikelySecurityToken(name string) bool` — not a persisted
column. Every input needed (the field's `Name`) is already persisted;
recomputing this from a name is cheap, always in sync with the
function's own definition (never a stale, independently-maintained
boolean that could drift), and mirrors `evidence.IsSensitiveFieldName`'s
own precedent of being a pure function over a name, not a stored flag.
It exact-matches known token field names (`csrf`, `csrf_token`,
`xsrf`, `xsrf_token`, `authenticity_token`, `nonce`,
`requestverificationtoken`, `anti_csrf`) and additionally flags any
name containing `csrf`/`xsrf`/`verificationtoken` or ending in
`_token` — deliberately broader than `evidence.sensitiveFieldNames`
(which exact-matches only, by design, for its own redaction purpose),
since this function's purpose (do not offer this field as a mutation
target) tolerates a slightly wider net without any downside: a
false-positive here just means one legitimate field is never
independently fuzzed, which is not a detection-completeness problem
this phase is trying to solve.

Migration: one new file, `internal/storage/migrations/0012_form_reconstruction.sql`,
adding `hidden INTEGER NOT NULL DEFAULT 0` to `parameters` and
`action_origin TEXT NOT NULL DEFAULT ''` to `endpoints`, matching
migration `0009`'s own precedent of touching two tables in one file
when both changes belong to the same feature.

## 3. Form request reconstruction — design

The mechanism is: give a form-derived `Target` the values of its
sibling fields, so the baseline request `NewMutationRequest` builds
already looks like a complete, real form submission, and `Mutate`'s
existing, unmodified `applyForm`/`applyQuery` then correctly leave
every field except the one targeted untouched.

- **`detection.Target.FormFields map[string]string`** (new field) —
  populated by `BuildTargets` from every sibling `Location`-matching
  Parameter of the SAME Endpoint (all `form`-location parameters for a
  `form`-location Target; all `query`-location parameters for a
  `query`-location Target whose Endpoint's `Source == "form"`). `nil`
  for every Target this phase does not touch (query/JSON from
  non-form sources, path, header, cookie) — zero behavior change for
  them.
- **`NewMutationRequest`** (extended, additively): when
  `t.ParameterLocation == "form"`, seeds `req.Body` from
  `url.Values(t.FormFields).Encode()` and `req.ContentType =
  "application/x-www-form-urlencoded"`; when `t.ParameterLocation ==
  "query"` and `t.FormFields` is non-empty (a GET-form target), merges
  `t.FormFields` into the already-parsed `Query` (URL-embedded values,
  if any, take precedence — matching how the URL is the single source
  of truth for every other query target today). For every other
  Target, behavior is byte-for-byte unchanged (empty `FormFields` is a
  no-op).
- `url.Values.Encode()` sorts keys internally (standard library
  guarantee) — this is what makes using a plain `map[string]string`
  for `FormFields` safe for determinism (task section 12) without
  needing an ordered-pairs structure of its own.
- A field whose name matches `parameters.IsLikelySecurityToken` is
  **excluded from becoming its own Target** (never independently
  mutated) but **is still included in `FormFields`** (present,
  positionally correct) for every OTHER field's mutation — this is
  what "preserve these fields during form mutation unless the
  selected mutation target is explicitly that field" means in
  practice.

**Honest limitation, stated plainly (task section 7 tension):** a
security-token-named field's stored `Value` may itself already be
`evidence.RedactedPlaceholder` (Phase 3.15's own redaction, unchanged,
exact-match on `csrf`/`csrf_token`/`xsrf`/`xsrf_token`) — the real
token value is never persisted, by design, so it cannot be recovered
here. A reconstructed request against an application that strictly
validates its CSRF token will typically be rejected by that
application (400/403) rather than silently succeed with a forged
token. This is a SAFE failure mode (no finding is ever fabricated from
a rejected, malformed submission — `sqliactive`'s own baseline-must-
succeed gate, `if baseline.response.Outcome != mutation.OutcomeSuccess
{ return OutcomeSkipped }`, already handles this without any new code),
not a silent security gap — but it does mean this phase cannot prove
successful mutation against a form whose OTHER fields include a
strictly-validated CSRF token. The lab fixtures (section 9) are
designed around this fact: the fixture proving end-to-end SQLi-via-
form-mutation deliberately has no CSRF check (mirroring
`/sqli/form/vulnerable`, already built in Phase 3.20), while a
SEPARATE, dedicated fixture proves CSRF-field presence/preservation
structurally without requiring the submission to actually succeed
past that check.

Resolving a relative form action against the page URL, handling
duplicate field names (first-seen value kept — the same convention
`addQueryCandidates` already uses, `normalize.go:259`), and handling
empty/hidden/textarea/select/checkbox/radio fields are **all already
correctly implemented** by the existing crawler/discovery code (1.1
above) — this phase adds no new HTML-parsing logic.

## 4. Mutation engine integration

`mutation.LocationForm`/`applyForm` need no logic change (1.8). The
only new code in `internal/mutation` is in the bridge function
(`NewMutationRequest`, described in section 3) — `internal/mutation`
itself is untouched. Section 4's own required test matrix (spaces,
plus signs, ampersands, equals signs, percent encoding, Unicode, empty
values, duplicate parameters, malformed original values, special
characters) is partially covered by Phase 3.17's existing
`TestMutate_Form_Escaped`/`TestMutate_Form_Verbatim_NoExistingBody`
(`mutate_test.go:70-100`) and the adversarial suite
(`adversarial_test.go:317`) — this phase adds the specific cases not
already covered (Unicode, plus-sign/space ambiguity, encoded
ampersands/equals, malformed existing body) as new tests, rather than
re-deriving `applyForm` itself.

## 5. BuildTargets integration

`endpointTargets` gains a `formParamsByEndpointID` map (parallel to
the existing `jsonParamsByEndpointID`, filtered the same way:
`Location == "form" && Provenance == "REQUEST_INPUT"`). A form-derived
Target (or a query-derived Target whose Endpoint's `Source == "form"`)
is only built when `e.ActionOrigin == "" || e.ActionOrigin ==
currentOrigin` (Finding 3's fix) — `currentOrigin` computed from the
same `scheme, host, port` `endpointTargets` already has in scope for
every other Target it builds. A parameter whose `Name` matches
`parameters.IsLikelySecurityToken` is skipped (not built as its own
Target) but still contributes to `FormFields`. `RESPONSE_FIELD`
provenance remains excluded exactly as it already is for JSON
(unchanged condition, just mirrored). Existing query/JSON Target
construction is entirely unmodified — the same-origin gate and
`FormFields` population only apply to `form`-location Targets and to
query-location Targets whose Endpoint's `Source == "form"`; every
other query/JSON Target (the overwhelming majority — ordinary crawled/
linked URLs) is built by the exact same code path, unchanged, as
before this phase.

## 6. Active detection integration — the minimum sqliactive adapter

`sqliactive.Eligible` gains one switch arm: `case "form": return true`
(mirrors the existing `"body"` arm's permissiveness — any method).
`sqliactive.Detect`'s location selection becomes a three-way switch
(`query` → `mutation.LocationQuery`, `form` → `mutation.LocationForm`,
`body` → `mutation.LocationJSON`) instead of the current two-way
if/else. No other line in `internal/detectors/sqliactive` changes —
`probe`, `computeSignals`, `classify`, `finding`, `stripPayload` all
already operate purely on `mutation.Response`/`mutation.Request`,
oblivious to which `Location` produced them. This is the "minimum
adapter" task section 10 asks for, and doubles as this phase's
concrete proof that a second detector-side integration point (after
Phase 3.20's own JSON-body wiring) requires touching only a few lines,
not a redesign.

## 7. What this phase intentionally does not implement

- No multipart/form-data (1.14) — no discoverable field in this
  codebase's model needs it (file inputs already excluded since Phase
  3.13).
- No CSRF vulnerability detection — CSRF fields are identified and
  preserved structurally (section 3), never fuzzed, never assessed for
  a missing/bypassable check.
- No recovery of a redacted security-token's real value — stated as
  an honest limitation (section 3), not silently worked around.
- No cross-origin form submission, even to an in-scope different
  host/port — Finding 3's fix EXCLUDES a cross-origin form's fields
  from becoming a Target at all, rather than attempting to dial a
  second host from within a single Endpoint's own Target construction
  (which would require re-resolving and re-scope-validating a second
  host mid-`BuildTargets`, a materially bigger change this phase does
  not need to make to close the Phase 3.20 limitation, which was
  specifically about SAME-origin POST forms).
- `xssactive` and every other pre-existing detector are untouched;
  only `sqliactive` gains the location adapter (section 6).
