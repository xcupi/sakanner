# Phase 3.21 Acceptance Test: Form Request Discovery & Active Body Mutation Foundation

This phase closes the Phase 3.20 documented limitation: POST-form
parameters never reached active detection. It is FOUNDATION ONLY. No
new vulnerability detector, IDOR/BOLA, authorization testing, mass
assignment detection, CSRF vulnerability detection, file upload
testing, SSTI/XXE/deserialization, business-logic testing, new
vulnerability-specific CLI commands, or time-based SQLi was
implemented. `sqliactive` is extended by the minimum adapter needed to
consume `LocationForm`; no other detector is modified. See
[docs/phase-3-21-form-mutation.md](phase-3-21-form-mutation.md) for
the full architecture review, performed and documented BEFORE any
implementation, per the task's own explicit instruction.

## What was built

The architecture review (section 1 of the design doc) found that form
DISCOVERY (crawler → `Candidate` → `Parameter`) and form MUTATION
(`mutation.LocationForm`/`applyForm`) were both **already fully
implemented**, since Phase 3.13 and Phase 3.17 respectively. The
actual gap was narrower than the task's own framing suggested: three
things, and only three:

1. **`BuildTargets` never routed `Location == "form"` parameters into
   `Target`s at all** (the literal Phase 3.20 limitation).
2. **Nothing seeded a form's sibling field values onto the baseline
   request** before `Mutate` touched one field, so even a wired-up
   form Target would have silently dropped every other field
   (including a CSRF token) from the reconstructed submission.
3. **A form's real destination host was discarded before persistence**
   (`endpoints.PathOf` strips it), making a cross-origin form action
   structurally indistinguishable from a same-origin one -- a
   correctness gap discovered DURING the architecture review, not
   assumed from the task text.

Everything built this phase closes exactly these three gaps, plus the
CSRF/security-token handling task section 7 requires:

- **`pkg/models.Endpoint.ActionOrigin`** (migration `0012`): the form
  action's normalized origin, captured before `PathOf` discards it,
  populated only for `Source == "form"` rows.
- **`pkg/models.Parameter.Hidden`** (migration `0012`): whether the
  originating HTML input carried `type="hidden"`.
- **`parameters.Candidate.FieldType`**: the raw HTML input type,
  propagated from `crawler.FormField.Type` (previously read, then
  discarded) through to `Hidden`.
- **`parameters.IsLikelySecurityToken`**: a conservative, name-based
  heuristic identifying CSRF/anti-forgery fields, used to exclude them
  from becoming their own active-mutation `Target`.
- **`internal/endpoints.originOf`**: computes a form action's
  normalized `scheme://host:port`, called once, before the host is
  discarded.
- **`detection.Target.FormFields map[string]string`**: a form's other
  already-discovered field values, carried on every Target belonging
  to that form.
- **`detection.BuildTargets`/`endpointTargets`**: a new
  `formParamsByEndpointID` map (mirrors the existing JSON one); a
  same-origin gate (`e.ActionOrigin == "" || e.ActionOrigin ==
  currentOrigin`) applied to BOTH form-location and (for a
  form-sourced endpoint) query-location Targets; security-token-named
  parameters excluded from becoming their own Target while still
  contributing to `FormFields`.
- **`detection.NewMutationRequest`**: seeds `Body`/`ContentType` (form
  location) or merges into `Query` (query location, URL value takes
  precedence) from `t.FormFields`.
- **`internal/detectors/sqliactive`**: the minimum adapter -- `case
  "form": return true` in `Eligible`, `case "form": loc =
  mutation.LocationForm` in `Detect`'s location switch. No other line
  changed.
- **`lab/harness_form_mutation.go`** (new): `/forms/index` -- real GET
  form, real POST form (both wrapping the already-reviewed
  `/sqli/vulnerable`/`/sqli/form/vulnerable` fixtures), a kitchen-sink
  form (hidden/textarea/select/checkbox/radio/CSRF, never vulnerable),
  a relative-action form, an out-of-scope-action form.
  **`lab/harness_auth.go`**: `/lookup-form` -- the authenticated
  POST-form-vulnerable fixture (with a CSRF hidden field), linked from
  `/dashboard`.
- **Documentation**: `docs/phase-3-21-form-mutation.md` (architecture,
  written before implementation), this file.

## Architecture review (task section 1)

Full findings in the design doc's own section 1, framed as answers to
the task's own 15 numbered questions. The single most consequential
finding (Finding 3): a form's real destination host is discarded
before persistence, and every endpoint (regardless of source) is
unconditionally assigned the crawled page's own `HTTPServiceID` --
meaning a cross-origin form action was, before this phase,
structurally indistinguishable from a same-origin one. This was
**not** a scope bypass (a `Target`'s `Host`/`IP` always trace back to
an already-validated `HTTPService` regardless), but it WAS a
correctness gap this phase closes at the source (`ActionOrigin`),
rather than papering over downstream.

## Design decisions and defects found during development

1. **A real, self-caught test-fallout defect, expected and handled.**
   `TestBuildTargets_FormAndPathLocationParameters_NoTargets` (Phase
   3.19/3.20) explicitly asserted the OLD limitation. Split into
   `TestBuildTargets_PathLocationParameter_NoTargets` (unchanged
   assertion) and a new `TestBuildTargets_FormRequestInputParameter_BecomesFormTarget`
   (the new, deliberate behavior) -- mirroring exactly how Phase 3.19
   itself split the JSON-parameter test out of this same test's
   earlier ancestor. The equivalent Phase 3.20 lab test
   (`TestPhase3_20_FormParameter_ReachesActiveDetection`) was updated
   the same way, in place, since its own doc comment explicitly
   predicted this exact fallout ("if BuildTargets' own scope boundary
   changed without this test being updated").
2. **A real test-design defect, self-caught: crawl page-budget
   exhaustion.** The vuln lab's own index page has grown to 40+ links
   across every prior phase's own fixtures; `/forms/index` (this
   phase's own link) is appended at the end of that list.
   `sqliActiveOrchestrator`'s (Phase 3.20) `CrawlMaxPages: 30` does not
   reliably reach it within one breadth-first crawl. Fixed with a
   DEDICATED helper (`formMutationOrchestrator`, `CrawlMaxPages: 100`)
   rather than raising the shared Phase 3.20 helper's own budget --
   this affects only this phase's own tests, not Phase 3.20's already-
   reported results. The equivalent e2e-level defect (`--profile web`
   hardcodes `CrawlMaxPages: 20` in `internal/policy`'s registry,
   silently ignoring config overrides) was fixed by routing those two
   e2e tests through the config-driven "legacy" policy path instead
   (omitting `--profile`, setting `crawler.enabled`/`max_pages` in
   config) -- a real, if narrow, discovery about how `--profile`
   precedence works that would have produced a flaky, budget-dependent
   test if left as `--profile web`.
3. **`findSQLi`'s "first match" helper is not precise enough once
   multiple `sql_injection` findings coexist in one scan.** The full
   vuln-lab crawl now produces THREE independent sql_injection
   findings (`/sqli/vulnerable`, `/sqli/boolean/vulnerable`, and the
   new `/sqli/form/vulnerable`-via-form). `TestPhase3_21_FullCrawl_POSTForm_ReachesActiveDetection`
   was written to search for the SPECIFIC endpoint
   (`/sqli/form/vulnerable`) rather than reuse `findSQLi`'s ambiguous
   first-match semantics.
4. **A deliberate, honest limitation: CSRF token VALUE fidelity.** A
   security-token-named field's stored `Value` is Phase 3.15's own
   redacted placeholder, not the real token -- the real value is never
   persisted, by design. A reconstructed request against an
   application that strictly validates that token will typically be
   rejected (safe failure, no fabricated finding), not silently
   succeed. `/lookup-form` (the fixture proving end-to-end form
   mutation against a REAL authenticated endpoint) deliberately does
   not validate its own CSRF field, mirroring `/sqli/form/vulnerable`'s
   own pre-existing no-CSRF-check design -- exactly as planned in the
   design doc's own section 3, not a workaround discovered after the
   fact.

## Test matrix results

### A. FORM DISCOVERY
Already fully implemented since Phase 3.13 (architecture review 1.1);
this phase adds `FieldType` propagation (`TestNormalize_HiddenTextareaSelectFields_AllDiscovered`,
extended; `TestNormalize_QueryCandidate_FieldTypeAlwaysEmpty`) and
`ActionOrigin` capture (`TestNormalize_FormSameOrigin_ActionOriginMatchesPage`,
`TestNormalize_FormCrossOrigin_ActionOriginReflectsRealDestination`,
`TestNormalize_NonFormSources_ActionOriginAlwaysEmpty`, `TestOriginOf`).
Proven via a REAL crawl of `/forms/index`
(`TestPhase3_21_FullCrawl_KitchenSinkForm_FieldsDiscoveredWithCorrectHidden`).
**PASS**

### B. FORM PARAMETER MODEL
`models.Parameter.Hidden`/`models.Endpoint.ActionOrigin` round-trip
through real SQLite storage (`TestParameter_Hidden_RoundTripAndDefault`,
`TestEndpoint_ActionOrigin_RoundTrip`), backward-compatible defaults
(`false`/`""`) confirmed for every pre-existing row shape.
`parameters.IsLikelySecurityToken` unit-tested directly
(`TestIsLikelySecurityToken_KnownNames`,
`TestIsLikelySecurityToken_OrdinaryFieldNames`,
`TestIsLikelySecurityToken_WhitespaceTrimmedCaseInsensitive`).
**PASS**

### C. FORM REQUEST RECONSTRUCTION
`Target.FormFields` seeds `NewMutationRequest`'s baseline `Body`/
`Query` (`TestNewMutationRequest_FormLocation_SeedsBodyFromFormFields`,
`TestNewMutationRequest_QueryLocation_FormSourced_MergesFormFieldsIntoQuery`,
`TestNewMutationRequest_QueryLocation_URLValueTakesPrecedenceOverFormFields`,
`TestNewMutationRequest_NoFormFields_BodyStaysEmpty` for backward
compatibility). Relative-action resolution and duplicate/hidden/
textarea/select/checkbox/radio field handling were ALREADY correct
(architecture review 1.1/section 3) -- re-verified, not re-derived,
via the crawler's own pre-existing suite plus two new adversarial
cases (`TestCrawl_FormFields_CheckboxWithoutValue_EmptyValueNotCrash`,
`TestCrawl_FormFields_MultipartEnctype_NonFileFieldsStillDiscovered`).
Never a second HTTP execution path: `sqliactive` still calls only
`x.ExecuteMutation`. **PASS**

### D. FORM MUTATION
`mutation.LocationForm`/`applyForm` needed no logic change
(architecture review 1.8) -- 7 new tests close the specific gaps in
task section 4's own matrix the pre-existing suite didn't already
cover: spaces/plus/ampersand/equals/percent/Unicode in both existing
and mutated values, empty existing/mutated values, duplicate existing
field names, and a malformed existing body (surfaces as an error, not
silent corruption). **PASS**

### E. BUILD TARGETS
`formParamsByEndpointID` + same-origin gate + security-token exclusion,
proven at the unit level (`TestBuildTargets_FormRequestInputParameter_BecomesFormTarget`,
`TestBuildTargets_FormCrossOriginAction_NoTarget`,
`TestBuildTargets_GETFormQueryParameter_CrossOrigin_NoTarget`) and via
a REAL crawl
(`TestPhase3_21_FullCrawl_RelativeFormAction_ResolvedAndTargetable`,
`TestPhase3_21_FullCrawl_OutOfScopeFormAction_NeverBecomesTarget`,
`TestPhase3_21_FullCrawl_CSRFField_NeverBecomesItsOwnTarget_ButIsPreservedForSiblings`).
Existing query/JSON Target construction is byte-for-byte unmodified
for every non-form-sourced endpoint (see section G). **PASS**

### F. ACTIVE DETECTION INTEGRATION
The minimum `sqliactive` adapter (2 switch arms) proven positive
(`TestDetect_FormBodyVulnerable_Finding`), negative
(`TestDetect_FormBodySafeParameterized_NoFinding`), and for sibling-
field preservation end to end
(`TestDetect_FormBody_SiblingFieldsPreserved` -- the server itself
asserts on a field OTHER than the one being mutated). Proven via a
REAL crawl for both GET-form (query-location) and POST-form
(form-location) parameters
(`TestPhase3_21_FullCrawl_GETForm_ReachesActiveDetection`,
`TestPhase3_21_FullCrawl_POSTForm_ReachesActiveDetection`) and through
the real CLI binary
(`TestScanCmd_ActiveFormMutation_POSTForm_RealBinary`). No other
detector was modified. **PASS**

### G. BACKWARD COMPATIBILITY
Every existing query/JSON/path/header/cookie Target, every existing
detector (`xssreflected`, `xssactive`, `sqli`, `cmdinjection`, `ssrf`,
`idor`, `traversal`), and every prior phase's own test suite re-
verified passing unchanged. `Target.FormFields` is `nil` for every
Target this phase does not touch -- confirmed directly
(`TestNewMutationRequest_NoFormFields_BodyStaysEmpty`). **PASS**

### H. AUTHENTICATION
Reused entirely, unchanged, from Phase 3.19 -- no form-specific
authentication code exists anywhere (architecture review 1.9/1.10).
Proven against the real, authenticated `/lookup-form` fixture
(`TestPhase3_21_AuthenticatedPOSTForm_FindingWithIdentityContext`) and
through the real CLI binary
(`TestScanCmd_ActiveFormMutation_AuthenticatedPOSTForm_RealBinary`).
**PASS**

### I. MULTI-IDENTITY / SESSION ISOLATION
Two independent identities each produce their own, correctly-tagged
`/lookup-form` finding with zero cross-contamination, proven at the
lab level
(`TestPhase3_21_IdentityAAndB_POSTForm_IndependentFindingsNoContamination`)
and through the real CLI binary as separate subprocesses
(`TestScanCmd_ActiveFormMutation_IdentityAAndB_IndependentScans_RealBinary`).
Task section 6's own explicit "verify this at the HTTP/session level,
not merely through labels" is satisfied by
`TestDetect_FormMutation_TwoIdentities_DistinctCookiesAtHTTPLevel`: two
independently-sessioned executors' form mutations are inspected at the
target server's own `Cookie` header, not by comparing
`IdentityContext` strings. **PASS**

### J. SCOPE ENFORCEMENT
Finding 3's fix, proven at every layer: unit
(`TestBuildTargets_FormCrossOriginAction_NoTarget`,
`TestBuildTargets_GETFormQueryParameter_CrossOrigin_NoTarget`), lab
(`TestPhase3_21_FullCrawl_OutOfScopeFormAction_NeverBecomesTarget` --
confirms the endpoint IS discovered/visible, but its field never
becomes a Target), and e2e through the real binary
(`TestScanCmd_ActiveFormMutation_OutOfScopeAction_NeverBecomesFinding`).
A relative action resolves and remains targetable
(`TestPhase3_21_FullCrawl_RelativeFormAction_ResolvedAndTargetable`).
Final network execution is unchanged -- still `mutation.Executor.Execute`'s
existing `scope.Validator`/`safedial.Dialer` sequence, re-verified
(not re-derived) via the pre-existing SSRF/redirect adversarial suite.
**PASS**

### K. CSRF TOKEN PRESERVATION
`IsLikelySecurityToken` excludes a CSRF-shaped field from becoming its
own Target while keeping it in `FormFields` for every sibling
mutation -- proven at the unit level
(`TestDetect_FormBody_SiblingFieldsPreserved`,
`TestBuildTargets_FormRequestInputParameter_BecomesFormTarget`) and
via a REAL crawl
(`TestPhase3_21_FullCrawl_CSRFField_NeverBecomesItsOwnTarget_ButIsPreservedForSiblings`).
Value fidelity is an honest, documented limitation (design decision 4
above), not a silent gap. **PASS**

### L. SECRET PROTECTION
No new secret-handling code -- `evidence.IsSensitiveFieldName`'s
pre-existing redaction (Phase 3.15, unchanged) already covers
`csrf`/`csrf_token`/`xsrf`/`xsrf_token`; the real value is never
persisted, confirmed directly
(`TestPhase3_21_FullCrawl_KitchenSinkForm_FieldsDiscoveredWithCorrectHidden`).
Password never appears in a generated report
(`TestScanCmd_ActiveFormMutation_AuthenticatedPOSTForm_RealBinary`'s
own explicit assertion). **PASS**

### M. RESOURCE LIMITS
No new resource-limit mechanism was needed -- `parameters.Limits.MaxFormFields`
(Phase 3.13, unchanged) already bounds form field discovery;
`ExecutorConfig.MaxActiveRequestsPerScan` (Phase 3.17/3.19, unchanged)
already bounds total mutation requests, uniformly across every
`Location` including the new `"form"` one. Both re-verified via their
own pre-existing suites, not re-derived. **PASS**

### N. DETERMINISM
Repeated crawls of the same lab target produce identical form
parameter counts and identical form Target counts
(`TestPhase3_21_Determinism_RepeatedCrawls_SameFormDiscoveryAndTargets`).
`Target.FormFields` uses a plain `map[string]string`, safe for
determinism because every consumer (`url.Values.Encode()`) sorts keys
internally rather than depending on map iteration order -- stated
explicitly in the design doc (section 3) and the code's own comments,
not merely assumed. **PASS**

### O. LAB
20 new lab test functions across 2 files
(`lab/phase3_21_form_mutation_test.go`: 9;
`internal/detectors/sqliactive/adversarial_test.go`: 1 HTTP-level
session-isolation test; the remainder distributed across
`internal/mutation`, `internal/detection`, `internal/parameters`,
`internal/endpoints`, `internal/crawler`, and
`internal/storage/sqlite`), 2 new minimal fixture files
(`lab/harness_form_mutation.go`, plus `/lookup-form` added to
`lab/harness_auth.go`) -- no new vulnerability-specific lab logic
beyond what already existed (`sqliSimulateQuery` reused, not
reimplemented). Full `lab` suite re-verified clean under `-race`.
**PASS**

### P. E2E
4 new e2e tests
(`tests/e2e/e2e_active_form_mutation_test.go`) against the REAL built
binary and the REAL, isolated lab -- POST-form positive, out-of-scope-
action negative, authenticated positive, identity A/B. Full
`tests/e2e` suite re-verified clean. **PASS**

### Q. ADVERSARIAL (task section 14)

| # | Scenario | Covered by |
|---|---|---|
| 1 | Duplicate form names | `TestCrawl_FormFields_CheckboxAndRadio` (crawler, pre-existing, re-verified); `TestMutate_Form_DuplicateExistingFieldName_FirstValueWins` (mutation, new) |
| 2 | Empty fields | `TestMutate_Form_EmptyExistingValue_Preserved`, `TestMutate_Form_MutatedValueItselfEmpty` |
| 3 | Malformed percent encoding | `TestMutate_Form_MalformedExistingBody_ReturnsError` |
| 4 | Unicode | `TestMutate_Form_ExistingBody_SpacesPlusAmpersandEqualsPercentUnicode`, `TestMutate_Form_MutatedValueContainsSpacesPlusAmpersandEqualsPercentUnicode`, `TestNewMutationRequest_FormFields_SpecialCharactersRoundTrip` |
| 5 | Plus/space ambiguity | Same as #4 |
| 6 | Encoded ampersands | Same as #4 |
| 7 | Encoded equals signs | Same as #4 |
| 8 | Duplicate submit buttons | `TestCrawl_FormFields_SubmitAndButtonExcluded` (pre-existing, re-verified: submit/button are excluded entirely, so duplicates are structurally impossible) |
| 9 | Checkbox without value | `TestCrawl_FormFields_CheckboxWithoutValue_EmptyValueNotCrash` |
| 10 | Relative action traversal | `TestPhase3_21_FullCrawl_RelativeFormAction_ResolvedAndTargetable` |
| 11 | Absolute out-of-scope action | `TestBuildTargets_FormCrossOriginAction_NoTarget`, `TestPhase3_21_FullCrawl_OutOfScopeFormAction_NeverBecomesTarget`, `TestScanCmd_ActiveFormMutation_OutOfScopeAction_NeverBecomesFinding` |
| 12 | Redirect to out-of-scope host | Reused, re-verified unchanged: Phase 3.17/3.19's own `mutation.Executor`/`safedial` adversarial suite (Target/Host/IP are unaffected by ParameterLocation) |
| 13 | Same host different port | `TestOriginOf` (port-sensitive origin comparison; a different port never equals `currentOrigin`) |
| 14 | Subdomain confusion | `TestOriginOf` (`sub.example.com` origin is distinct from `example.com`'s) |
| 15 | Identity A/B session contamination | `TestPhase3_21_IdentityAAndB_POSTForm_IndependentFindingsNoContamination`, `TestDetect_FormMutation_TwoIdentities_DistinctCookiesAtHTTPLevel` |
| 16 | CSRF token leakage | `TestPhase3_21_FullCrawl_KitchenSinkForm_FieldsDiscoveredWithCorrectHidden` (value redacted at discovery) |
| 17 | Secret leakage | `TestScanCmd_ActiveFormMutation_AuthenticatedPOSTForm_RealBinary` (password never in report) |
| 18 | Oversized forms | Reused, unchanged: `parameters.Limits.MaxFormFields` (Phase 3.13's own `TestNormalize_MaxFormFields_TruncatesAndWarns`) |
| 19 | Excessive field counts | Same as #18 |
| 20 | Deterministic ordering | `TestPhase3_21_Determinism_RepeatedCrawls_SameFormDiscoveryAndTargets` |
| 21 | Cancellation during form execution | Reused, unchanged: `TestDetect_ContextCancelled_ReturnsPromptlyNoHang` (Phase 3.20, Location-agnostic) |
| 22 | Concurrent form mutation | `TestPhase3_21_IdentityAAndB_POSTForm_IndependentFindingsNoContamination`'s own two-orchestrator pattern; reused concurrency guarantees from Phase 3.19/3.20 |
| 23 | Malformed Content-Type | `applyForm` always sets `ContentType` explicitly on output regardless of input state (`mutate.go:209`, unchanged); no code path reads an attacker-controlled Content-Type when constructing a mutation |
| 24 | Unsupported form encoding (multipart) | `TestCrawl_FormFields_MultipartEnctype_NonFileFieldsStillDiscovered` -- non-file fields still discovered without crash; multipart is not implemented (documented limitation, not silently mishandled) |

All 24 scenarios: **NO SECURITY BOUNDARY FAILURE. PASS.**

### R. REGRESSION

```
go build ./...                                          -> clean
go vet ./...                                             -> clean
gofmt -l .                                                -> clean (no output)
go test $(go list ./... | grep -v '/tests/e2e') -race -v  -> ok, 1427 PASS, 0 FAIL (35 packages with tests)
go test ./tests/e2e/... -v                                -> ok, 90 PASS, 0 FAIL
```

Production/lab independence re-verified: physically removed `lab/` and
`tests/`, confirmed `go build ./...`/`go vet ./...` succeed with both
absent, confirmed no production or test file outside `lab/` itself
imports `sakanner/lab`, restored both, rebuilt again to confirm
restoration. Every existing detector's own test suite re-verified
passing unchanged -- only `internal/detectors/sqliactive` was touched
(the 2-switch-arm adapter), and only additively. **PASS**

### S. RACE

Full non-e2e suite, every package, `-race -count=1`: clean, zero races
reported, including the new HTTP-level session-isolation test and
every concurrent lab/e2e test this phase added. **PASS**

## Final architectural validation (task section 15)

1. **Can a real HTML POST form now produce REQUEST_INPUT Parameters?**
   Yes -- already true since Phase 3.13 (architecture review 1.1/1.2);
   re-verified via a real crawl of `/forms/index`.
2. **Can those Parameters reach BuildTargets?** Yes -- this phase's
   central fix: `formParamsByEndpointID`, gated by same-origin and
   security-token exclusion.
3. **Can BuildTargets create a form-location detection target?** Yes
   -- `ParameterLocation == "form"`, distinct from `"body"` (JSON).
4. **Can mutation produce application/x-www-form-urlencoded?** Yes --
   `mutation.applyForm`, unchanged since Phase 3.17, now actually
   reached via a real Target for the first time.
5. **Can exactly one form parameter be mutated?** Yes -- `Mutate`
   always targets exactly the one named `m.Parameter`; every sibling
   field is seeded via `FormFields` and left untouched.
6. **Are untouched fields preserved?** Yes, proven with the target
   server itself asserting on a field OTHER than the mutated one
   (`TestDetect_FormBody_SiblingFieldsPreserved`).
7. **Does the request use the existing authenticated session?** Yes,
   unconditionally, with zero form-specific code -- proven against a
   real authenticated fixture and at the raw Cookie-header level.
8. **Does multi-identity isolation remain intact?** Yes, proven at the
   label level and, separately, at the HTTP/cookie level (task section
   6's own explicit requirement).
9. **Does scope enforcement happen before network execution?** Yes --
   unchanged `mutation.Executor.Execute` path; ADDITIONALLY, a
   cross-origin form's fields never even reach that path, since they
   never become a Target in the first place (Finding 3's fix).
10. **Can redirects never escape scope?** Yes -- unchanged, reused
    `safedial`/`scope.Validator` machinery, unaffected by
    ParameterLocation.
11. **Can an existing active detector consume the form target?** Yes
    -- `sqliactive`, via the 2-switch-arm minimum adapter (task
    section 10's own explicit ask).
12. **Does a real lab POST parameter reach active detection end to
    end?** Yes -- proven via a REAL crawl (not a directly-persisted
    shortcut) discovering `/forms/index`'s own `<form method=POST>`,
    all the way through to a `sql_injection` finding on
    `/sqli/form/vulnerable`.
13. **Are CSRF/security tokens preserved safely?** Structurally yes
    (presence, positionally correct, in every sibling mutation); value
    fidelity is an honest, stated limitation (design decision 4) --
    not hidden.
14. **Are secrets redacted?** Yes -- reused, unchanged Phase 3.15
    mechanism; re-verified via a real crawl and a real e2e report.
15. **Are resource limits enforced?** Yes -- reused, unchanged
    mechanisms (`MaxFormFields`, `MaxActiveRequestsPerScan`), both
    already Location-agnostic.
16. **Is behavior deterministic?** Yes, proven directly across 3
    repeated real crawls; `FormFields`' map-based representation is
    safe by construction (`url.Values.Encode()` sorts keys).
17. **Are existing JSON/query detectors unchanged?** Yes --
    `xssactive` untouched; `sqliactive`'s own query/JSON code paths
    untouched (only the location switch gained one new arm each in
    `Eligible`/`Detect`); every pre-existing detector's own suite
    re-verified passing unchanged.
18. **Is the lab still physically independent?** Yes -- re-verified by
    physically removing `lab/`/`tests/`, rebuilding clean, restoring.
19. **Are there any remaining architectural gaps?** Yes, stated
    plainly: (a) a cross-origin form's fields are discovered but
    deliberately never become an active-mutation Target, even when the
    other host is ALSO in scope -- a materially bigger change (second-
    host re-resolution mid-`BuildTargets`) this phase does not attempt,
    since Phase 3.20's own limitation was specifically about
    SAME-origin POST forms; (b) a CSRF-shaped field's real value is
    never recoverable once redacted at discovery time, by design; (c)
    multipart/form-data is not implemented anywhere in this codebase
    (file inputs already excluded since Phase 3.13) -- non-file fields
    of a multipart form are still discovered correctly, but no genuine
    multipart body is ever constructed for mutation.

Every answer is yes except the two honest, explicitly-scoped
exclusions in question 13 (value fidelity) and question 19(a)/(c)
(cross-origin, multipart) -- stated plainly, not hidden.

## Final report

```
PHASE 3.21 FORM REQUEST DISCOVERY & ACTIVE BODY MUTATION FOUNDATION

TOTAL TESTS: 1517
PASS: 1517
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

FORM DISCOVERY: PASS
FORM PARAMETER MODEL: PASS
FORM REQUEST RECONSTRUCTION: PASS
FORM MUTATION: PASS
BUILD TARGETS: PASS
ACTIVE DETECTION INTEGRATION: PASS
AUTHENTICATION: PASS
MULTI-IDENTITY: PASS
SESSION ISOLATION: PASS
SCOPE ENFORCEMENT: PASS
CSRF TOKEN PRESERVATION: PASS
SECRET PROTECTION: PASS
RESOURCE LIMITS: PASS
DETERMINISM: PASS
LAB: PASS
E2E: PASS
ADVERSARIAL: PASS
REGRESSION: PASS
RACE: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0
(Two real, self-caught test-design defects were found and fixed during
THIS phase's own development: a stale test asserting the very
limitation this phase closes, and a crawl page-budget exhaustion that
would have made two new tests flaky/order-dependent. Both documented
in full; neither is an issue remaining at delivery.)

PHASE 3.21 VERDICT: PASS
```

## Remaining limitations (stated per task instruction, not hidden)

1. **Cross-origin form actions never become active-mutation Targets,
   even when the other host is separately in scope.** Closing this
   would require `BuildTargets` to re-resolve and re-scope-validate a
   SECOND host mid-target-construction -- a materially larger change
   than this phase's own stated goal (the Phase 3.20 limitation was
   specifically about same-origin POST forms).
2. **A CSRF/security-token field's real submitted value is never
   recoverable** once redacted at discovery time (Phase 3.15's own
   secret-protection design, unchanged) -- a reconstructed request
   against a strictly-validating application will typically be
   rejected, a safe failure mode, not a silent one.
3. **Multipart/form-data is not implemented anywhere in this
   codebase** -- non-file fields of a multipart-enctype form are still
   correctly discovered (proven), but no genuine multipart body is
   ever constructed for mutation; file inputs remain excluded from
   discovery entirely (unchanged since Phase 3.13, file upload testing
   explicitly out of scope).
4. **`xssactive` was not extended with the same form adapter** --
   task section 10 asks for "an existing active detector" as the
   integration consumer, not every detector; `sqliactive` is that
   proof. A future phase wanting form-location XSS detection would add
   the identical 2-switch-arm adapter to `xssactive`.

Per the task's final rule: no IDOR/BOLA, authorization testing, mass
assignment detection, CSRF vulnerability detection, file upload
vulnerability detection, SSTI, XXE, deserialization, business-logic
vulnerabilities, new vulnerability-specific CLI commands, or
time-based SQLi were implemented. Stopping here -- Phase 3.22 is not
started.
