# Phase 3.22: Active Detection Coverage & Target Routing Completion

## 0. Scope discipline

This phase introduces NO new vulnerability class. It brings `xssactive`
to the same canonical mutation coverage `sqliactive` already has
(query/form/JSON), makes `BuildTargets`' routing rule explicit and
uniform, and resolves (or explicitly declines to force) the two
remaining Phase 3.21 limitations. No IDOR/BOLA, authorization testing,
mass assignment, CSRF detection, SSRF/traversal/command-injection
active detection, SSTI, XXE, deserialization, file upload
vulnerabilities, business-logic vulnerabilities, or time-based SQLi
was implemented.

## 1. Architecture review

Answers to the task's own 12 numbered questions, each verified by
direct reading of the current code (not assumed from prior phases'
documentation).

### 1.1 Which ParameterLocation values can currently be discovered?

`internal/parameters.Location`'s enum has six values:
`query`/`path`/`form`/`json`/`header`/`cookie`. Of these, only THREE
are ever actually produced by a live discovery source:
- **`query`** -- `addQueryCandidates` (crawled/linked URL query
  strings) and `addFormCandidates` for a GET form (`normalize.go:277-282`).
- **`form`** -- `addFormCandidates` for a POST/non-GET form
  (`normalize.go:279`).
- **`json`** -- `ParseJSONBody`, fed by `NormalizeJSONResponses`
  (RESPONSE bodies only, Provenance always `RESPONSE_FIELD`) and, per
  Phase 3.18/3.19's own documented boundary, never by a live REQUEST
  body (the crawler issues nothing but GET).

**`path` is NEVER produced by the live pipeline.**
`internal/parameters.InferPathInputs` (`path.go:40`) is a real,
fully-implemented, fully-tested pure function -- but grep across the
entire repository (excluding its own package and tests) finds **zero
callers**. `internal/orchestration` never invokes it. This is the
single most consequential finding for section 6 below: there is no
live provenance for a path parameter today, full stop -- not "weak
provenance," literally none, because nothing ever persists one.

`header`/`cookie` are, per `parameters/doc.go`'s own long-standing
statement, "not yet discovered by any source" -- still true, unchanged,
not a new finding.

### 1.2 Which ParameterLocation values can currently reach BuildTargets?

Exactly the three live-discovered ones: `query` (any source, any
provenance -- unchanged since Phase 3.13), `json` (only
`Provenance == "REQUEST_INPUT"`, Phase 3.19), `form` (only
`Provenance == "REQUEST_INPUT"`, Phase 3.21) -- with Phase 3.21's own
same-origin gate applied to both `query`-from-a-form-source and
`form`-location parameters. `path`/`header`/`cookie` have no routing
arm in `BuildTargets`'s switch at all (`targets.go`) -- consistent
with 1.1, since nothing ever produces a `path` Parameter row to route
in the first place.

### 1.3 Which ParameterLocation values can currently reach active mutation?

`internal/mutation.Mutate`'s own `Location` enum
(`query`/`form`/`json`/`path`/`header`/`cookie`) is a strict superset
of what ever reaches it in practice: `applyPath`/`applyHeader`/
`applyCookie` are complete, tested, callable functions
(`mutate.go:345-379`) that no live caller ever invokes, because no
`Target` with `ParameterLocation` of `"path"`/`"header"`/`"cookie"` is
ever built by `BuildTargets`. This is intentional, layered design (the
mutation engine is a general-purpose primitive; target selection is
the gate that decides what's safe to expose) -- not a bug, and not
something this phase changes for header/cookie (task gives no mandate
for those; only path is explicitly addressed, in section 6).

### 1.4 / 1.5 Which ParameterLocation values do sqliactive/xssactive support?

`sqliactive` (Phase 3.20/3.21): `query`, `form`, `body` (its own
vocabulary for JSON) -- explicit three-way switch in `Detect`, verified
by reading the current file.

`xssactive` (Phase 3.19, **unchanged until this phase**): only
`query` and `body` -- `Eligible`'s switch has no `"form"` arm at all
(falls to `default: return false`), and `Detect`'s location selection
is a two-way `if t.ParameterLocation == "body"`. **This is the primary
gap section 3 closes** -- confirmed by direct reading of
`internal/detectors/xssactive/detector.go`, not assumed.

### 1.6 Do query, JSON, and form targets carry equivalent provenance?

Yes, uniformly, since Phase 3.21 -- every `Target` carries
`ScanJobID`/`HTTPServiceID`/`EndpointID`/`IdentityContext` regardless
of `ParameterLocation`; `FormFields` is populated for form-sourced
Targets and `nil` (a no-op) for every other kind. Nothing about a
Target's shape differs by location beyond the location-specific fields
(`FormFields` only meaningful for form/query-from-form). Confirmed by
re-reading `internal/detection/detector.go`'s `Target` struct and
`targets.go`'s `endpointTargets` in full.

### 1.7 / 1.8 Authentication/session and IdentityContext preserved identically for all?

Yes -- both flow through `Executor.ExecuteMutation` →
`mutation.Executor.Execute`/`SessionContext`, which is entirely
`Location`-agnostic (it operates on `mutation.Request`, which by the
time it reaches `Execute` no longer carries `ParameterLocation` as
anything more than a label already baked into `Body`/`Query`/
`ContentType`). `IdentityContext` is copied onto `Mutation`/`Request`/
`Finding` the same way regardless of location. No per-location branch
exists anywhere in this path.

### 1.9 Does scope validation occur consistently for all?

Yes for the CURRENT three routed locations, via the single
`mutation.Executor.resolveAndValidate` (`executor.go:214-233`) every
request passes through. This function has an important, previously-
unexercised capability, central to section 7 below: when `req.IP ==
nil`, it resolves AND scope-validates the host FRESH via
`x.dialer.ResolveInScope` -- the exact same function `internal/auth`
uses for the identical purpose. Every Target `BuildTargets` has ever
constructed (through Phase 3.21) always populated `IP` from the
already-resolved `HTTPService`, so this nil-IP path, while fully
implemented and documented since Phase 3.17, had never actually been
exercised by a real `BuildTargets`-constructed Target until this
phase's own section 7 work.

### 1.10 / 1.11 Same request model for all; any detector's own mutation logic?

Yes, one model (`mutation.Request`/`Mutation`), confirmed by reading
both `xssactive` and `sqliactive` in full: neither constructs an
`http.Request`, an `http.Client`, or a cookie jar of its own anywhere.
Both call only `detection.NewMutationRequest`, `mutation.NewMutation`/
`Mutate`, and `x.ExecuteMutation`. No duplicated mutation logic exists
in either detector today.

### 1.12 Can any discovered input type never reach active detection?

Yes, precisely two, both already known and both addressed explicitly
below rather than left implicit:
1. **Path parameters** -- never discovered live at all (1.1), so
   "never reaches active detection" is not a routing gap to close but
   a discovery gap that was never actually wired up. Section 6.
2. **A cross-origin (but possibly separately in-scope) form action's
   fields** -- Phase 3.21 documented this as a limitation. Section 7
   re-examines it now that `resolveAndValidate`'s nil-IP capability
   (1.9) is understood precisely.

Also, unchanged, pre-existing, not new findings: `RESPONSE_FIELD`-
provenance JSON fields (deliberately excluded, Phase 3.18/3.19); a
live JSON REQUEST body still cannot be crawl-discovered (the crawler
issues only GET); `header`/`cookie` locations have no discovery source
at all.

## 2. Primary objective: routing consistency

`BuildTargets`' routing rule, made explicit (was previously true in
practice but stated only in scattered comments):

```
REQUEST_INPUT, Location ∈ {query, form, json}   → Target (subject to same-origin gate for form-sourced endpoints)
RESPONSE_FIELD                                   → never a Target, any Location
Location ∈ {path, header, cookie}                → never a Target (no live discovery source; header/cookie additionally require an explicit Policy allowlist even inside internal/mutation itself)
```

No path segment is ever treated as an injectable parameter merely
because Phase 3.13's `InferPathInputs` function COULD theoretically
produce one -- it produces nothing today because nothing calls it.
Section 6 keeps it that way, explicitly.

## 3. xssactive integration

Minimum adapter, identical in shape to `sqliactive`'s own Phase 3.21
adapter: `Eligible` gains `case "form": return true`; `Detect`'s
`loc` selection becomes a three-way switch (`form` →
`mutation.LocationForm`, `body` → `mutation.LocationJSON`, default →
`mutation.LocationQuery`). Every other line in `xssactive` --
`reflection.go`'s classification, `finding.go`'s evidence/severity
construction -- is untouched: both already operate purely on
`mutation.Response`, oblivious to which Location produced it, exactly
as `sqliactive`'s `computeSignals`/`classify` do. `FormFields`
preservation, the same-origin gate, and security-token exclusion are
ALL already centralized in `BuildTargets`/`NewMutationRequest` (Phase
3.21) -- `xssactive` needs zero code for any of them, which is itself
the proof that Phase 3.21's design generalizes to a second detector,
not just `sqliactive`.

## 4. sqliactive consistency

Already explicit and deterministic (Phase 3.21's own three-way
switch, re-verified unchanged). No payload strategy change. Time-based
SQLi remains explicitly not implemented -- no new probe, no new
timing logic, anywhere in this phase.

## 5. Target routing (formalized)

`endpointTargets` already implements the rule in section 2; this phase
adds no new location arm to the switch (query/form/json remain the
only three), only the cross-origin resolution described in section 7.
An unsupported location is never silently reinterpreted as another
one -- `path`/`header`/`cookie` simply produce no Target, which IS the
"explicitly reported as unsupported" behavior in practice (no Target
means no detector ever sees that parameter; nothing claims coverage it
doesn't have).

## 6. Path parameters: NOT implemented, by evidence, not by assumption

Per 1.1/1.12: `InferPathInputs` is never called. There is zero live
provenance for a path parameter anywhere in the current system. Per
the task's own explicit instruction ("if reliable provenance does NOT
exist: leave path parameters out of active detection and document
this clearly") -- this phase makes NO change to path-parameter
handling. `InferPathInputs` remains a tested, unwired function,
exactly as it has been since Phase 3.13. Wiring it into the live
pipeline (and then into `BuildTargets`/mutation) would be a
DISCOVERY-layer change, not a routing-layer one -- out of this phase's
own stated scope ("active detection coverage," not "new discovery
sources").

## 7. Cross-origin form actions: resolved, not merely documented

Phase 3.21 excluded a form endpoint entirely whenever
`e.ActionOrigin != currentOrigin`, regardless of whether the other
origin was separately in scope. Re-examining this with 1.9's finding
in hand: `mutation.Executor.resolveAndValidate` already resolves AND
scope-validates a request's host FRESH, via the SAME
`safedial.Dialer.ResolveInScope` path every other component uses,
whenever `Request.IP == nil`. This is not a second, independent scope-
resolution path -- it is the SAME one, already exercised elsewhere in
this codebase (`internal/auth`), simply never previously fed a
`Request` whose `IP` was nil.

**Resolution:** when a form endpoint's `ActionOrigin` differs from its
own `HTTPService`'s origin, `endpointTargets` now parses `ActionOrigin`
and builds that endpoint's Targets with the PARSED scheme/host/port
and `IP` left `nil`, instead of skipping them. At execution time,
`Execute` resolves and scope-validates that host exactly as it would
for any other target this codebase dials -- a separately in-scope
destination succeeds; an out-of-scope one is refused with the same
`OutcomeScopeRejected` any other denied target gets (a safe failure,
reported as a detector error, never a finding). A malformed
`ActionOrigin` (should not occur in practice, since `originOf` always
produces a well-formed value or empty string, but handled defensively)
falls back to the Phase 3.21 skip behavior rather than guessing.

**A deliberate, unforced consequence, not a bug:** the authenticated
session's cookie jar is host-pinned (`SessionContext.PinnedHost`,
Phase 3.19, unchanged) -- a cross-origin mutation's `Host` will not
equal `PinnedHost`, so it correctly runs UNAUTHENTICATED even during
an authenticated scan. Sharing session credentials across origins
without explicit operator configuration would be a real security
regression this phase does not introduce; if the cross-origin
destination also requires authentication, this is the same limitation
any single-identity, single-origin session model already has, not
something new. Not forced further -- exactly what the task instructs
when the alternative would require a broader architecture change.

## 8. Authentication + multi-identity

No new authentication code (per 1.7/1.8) -- proven per detector/
location combination in the lab and e2e suites (section headings
below), including two identities running CONCURRENTLY with explicit
cookie-level (not just label-level) isolation checks, reusing the
Phase 3.21 pattern (`TestDetect_FormMutation_TwoIdentities_DistinctCookiesAtHTTPLevel`)
extended to cover xssactive's own form/JSON paths too.

## 9. Lab

New fixtures, minimal, reusing existing vulnerability logic wherever
possible:
- `/xss/reflected/form-vulnerable` (unauthenticated POST form,
  reflected -- the one genuinely new XSS fixture; query and JSON
  reflected-XSS fixtures already exist since Phase 3/3.19).
- `/search-form` (authenticated POST form, reflected -- mirrors the
  existing `/search` query fixture exactly, added to `harness_auth.go`
  alongside `/lookup-form`).
- A same-host-different-port fixture and a genuinely separately-in-
  scope second host, to prove section 7's resolution positively (not
  merely its negative/exclusion case, which Phase 3.21 already
  covered).

## 10. Response comparison + evidence

Unchanged -- `mutation.Compare`/`detection.MutationEvidence` remain
the sole comparison/evidence path for both detectors, confirmed by
reading both files in full; no parallel evidence shape was introduced.

## 11. Resource limits

No new limit needed -- `ExecutorConfig.MaxActiveRequestsPerScan`/
`MaxMutationsPerTarget`/`MaxTotalMutations` are already Location- and
detector-agnostic (Phase 3.17/3.19/3.20, unchanged); adding
`xssactive`'s form/JSON eligibility does not add a new REQUEST PATH,
only new eligible Targets within the SAME already-bounded budget.

## 12. What this phase intentionally does not implement

IDOR/BOLA, authorization testing, mass assignment, CSRF detection,
SSRF/path-traversal/command-injection active detection, SSTI, XXE,
deserialization, file upload vulnerabilities, business-logic
vulnerabilities, time-based SQLi, path-parameter discovery or
mutation, header/cookie parameter discovery.
