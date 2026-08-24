# Phase 3.22 Acceptance Test: Active Detection Coverage & Target Routing Completion

This phase introduces NO new vulnerability class. It brings `xssactive`
to the same canonical mutation coverage `sqliactive` already has
(query/form/JSON), makes `BuildTargets`' routing rule explicit, and
resolves the Phase 3.21 cross-origin-form limitation rather than
merely re-documenting it. No IDOR/BOLA, authorization testing, mass
assignment, CSRF detection, SSRF/traversal/command-injection active
detection, SSTI, XXE, deserialization, file upload vulnerabilities,
business-logic vulnerabilities, or time-based SQLi was implemented.
See [docs/phase-3-22-active-detection-coverage.md](phase-3-22-active-detection-coverage.md)
for the full architecture review, performed and documented before any
implementation.

## What was built

The architecture review found the actual gap was narrow: `xssactive`
had no `"form"` arm in `Eligible` or its location switch (confirmed by
direct reading, not assumed) -- everything else (`FormFields`
preservation, the same-origin gate, security-token exclusion,
authentication, identity, evidence) was already centralized in
`BuildTargets`/`NewMutationRequest` since Phase 3.21 and needed zero
new code to cover a second detector. Separately, re-examining Phase
3.21's own cross-origin-form limitation with `mutation.Executor.resolveAndValidate`'s
nil-IP capability precisely understood (it already resolves AND
scope-validates a request's host FRESH via the SAME
`safedial.Dialer.ResolveInScope` path every other component uses)
showed that limitation could be resolved cleanly, not merely
re-documented.

- **`internal/detectors/xssactive`**: the minimum adapter -- `case
  "form": return true` in `Eligible`, a three-way switch in `Detect`'s
  location selection. No other line changed; `reflection.go`/
  `finding.go` untouched.
- **`internal/detection/targets.go`**: `endpointTargets` now parses a
  form-sourced endpoint's `ActionOrigin` when it differs from its own
  `HTTPService`'s origin, and builds that endpoint's Targets with the
  PARSED scheme/host/port and `IP` left `nil` -- letting
  `mutation.Executor.resolveAndValidate` resolve and scope-validate
  the REAL destination fresh, exactly as it already does for any other
  nil-IP request. A malformed `ActionOrigin` falls back to Phase
  3.21's original skip behavior (`routable = false`) rather than
  guessing.
- **`lab/harness_vuln.go`**: `/xss/reflected/form-vulnerable` (the one
  genuinely new vulnerability fixture -- POST-form-reflected XSS,
  reusing `/xss/reflected/vulnerable`'s identical unescaped-reflection
  logic); `formSecondHostHandler`/`ipFormSecondHost` -- a genuinely
  separate, second lab host (`second-service.scanner.test`,
  `127.0.0.27`) with its own POST-form-vulnerable SQLi endpoint,
  proving section 7's resolution positively.
- **`lab/harness_form_mutation.go`**: `/forms/index` gains two new
  forms -- one to `/xss/reflected/form-vulnerable`, one to the second
  host's `/echo/vulnerable` (cross-origin, separately in scope).
- **`lab/harness_auth.go`**: `/search-form` (authenticated
  POST-form-vulnerable reflected XSS, mirroring `/lookup-form`'s own
  Phase 3.21 precedent for SQLi), linked from `/dashboard`.
- **Documentation**: `docs/phase-3-22-active-detection-coverage.md`
  (architecture, written before implementation), this file.

## Architecture review (task section 1)

Full findings in the design doc's own section 1, answering the task's
12 numbered questions. The two most consequential: (1) `path`-location
parameters are NEVER discovered by the live pipeline at all --
`internal/parameters.InferPathInputs` is a real, fully-tested function
with **zero callers** anywhere outside its own package, confirmed by
an exhaustive repository-wide grep, not assumed; (2)
`mutation.Executor.resolveAndValidate`'s nil-IP resolution path
(`executor.go:214-233`) was already fully implemented and documented
since Phase 3.17, but had never actually been exercised by a real
`BuildTargets`-constructed Target until this phase's own section 7
work -- reusing it, rather than building something new, is what makes
section 7's resolution clean rather than forced.

## Design decisions and defects found during development

1. **Two real, self-caught test-fallout defects, both expected and
   handled the same way established in Phase 3.20/3.21.**
   `TestEligible_FormLocation_False` (xssactive) explicitly asserted
   the OLD limitation this phase closes -- renamed to
   `TestEligible_FormAnyMethod_True` with its assertion reversed, its
   own doc comment stating why. `TestBuildTargets_FormCrossOriginAction_NoTarget`/
   `TestBuildTargets_GETFormQueryParameter_CrossOrigin_NoTarget`
   (Phase 3.21) asserted the OLD "cross-origin form excluded outright"
   behavior -- renamed to
   `TestBuildTargets_FormCrossOriginAction_TargetsRealDestinationWithNilIP`/
   `TestBuildTargets_GETFormQueryParameter_CrossOrigin_TargetsRealDestination`,
   now asserting the new, deliberate resolution (a Target IS built,
   pointed at the parsed ActionOrigin, with `IP == nil`). A THIRD test,
   `TestBuildTargets_FormMalformedActionOrigin_NoTarget`, was added to
   keep the original defensive "never guess a host" behavior covered
   for the one case it still applies to (an unparseable ActionOrigin).
2. **`TestPhase3_21_FullCrawl_OutOfScopeFormAction_NeverBecomesTarget`
   required a more careful fix than a simple rename.** Its OLD
   assertion ("no Target for the out-of-scope field") is no longer
   true by design -- a Target IS now built (correctly, per section 7).
   Renamed to `..._NeverBecomesFinding` and rewritten to assert the
   ACTUAL security invariant that must hold regardless of how Targets
   are constructed: the Target's `Host`/`IP` are correct
   (`external.scanner.test`, `nil`), but scope enforcement at
   EXECUTION time must still refuse to ever dial it, so no FINDING can
   ever result. This is a stronger, more correct test than the one it
   replaced -- it would have caught a bug the old test structurally
   could not (a hypothetical regression where Target construction is
   right but execution-time scope enforcement is somehow bypassed).
3. **A scope-rule ID collision, self-caught immediately.** The first
   version of `TestPhase3_22_FullCrawl_SeparatelyInScopeSecondHost_ReachesActiveDetection`
   passed two `models.ScopeRule` values with unset (empty-string) IDs
   -- `scopeRuleRepo.Create` has no auto-ID behavior (confirmed by
   reading it), so the second `Create` call failed on a UNIQUE
   constraint. Fixed by giving both rules explicit, distinct IDs --
   every other single-scope-rule test in this codebase never needed
   this because it only ever created one.
4. **A real, PRE-EXISTING, intermittent reliability defect was
   discovered during this phase's own e2e regression sweep --
   unrelated to any Phase 3.22 code path.**
   `TestConcurrency_ScopeAdd_FreshDatabase_NoCorruption`
   (`tests/e2e/e2e_scope_ux_test.go`, pre-existing, not touched this
   phase) launches 10 separate CLI subprocesses concurrently, each
   independently opening the SAME brand-new (nonexistent-until-first-
   touch) SQLite database file -- meaning all 10 race to run schema
   migration on first connect. `internal/storage/sqlite.New` already
   sets a 5-second `busy_timeout` pragma
   (`sqlite.go:139`), which is sufficient for ordinary concurrent
   write contention against an ALREADY-migrated database, but is not
   always sufficient for this specific "N processes race to create AND
   migrate a not-yet-existing file" scenario: one run in the full
   suite failed with `sqlite: ping: database is locked (5)
   (SQLITE_BUSY)` and a resulting rule count of 9 instead of 10.
   Re-running this ONE test in isolation 3 times reproduced it once
   (1/3), confirming a genuine, low-frequency race rather than
   environment noise from this session's own tooling. Re-running the
   FULL e2e suite once more, standalone, passed cleanly (93/93,
   including this test) -- consistent with a low-probability race, not
   a deterministic regression. This is NOT fixed in this phase: the
   root cause is in `internal/storage/sqlite`'s connection/migration
   bootstrap strategy for a not-yet-existing database file, entirely
   unrelated to detection routing, and a correct fix (e.g., an
   advisory lock or WAL-mode-aware migration guard shared across every
   CLI invocation) deserves its own focused review rather than a rushed
   change made incidentally while verifying an unrelated phase. Recorded
   here in full, per this session's own established practice of never
   silently discarding an observed defect -- see "Remaining
   limitations" below.

## Test matrix results

### XSS QUERY
Unchanged since Phase 3.19 -- re-verified passing.  **PASS**

### XSS FORM
New this phase. Unit: `TestDetect_FormBodyReflection_Finding`,
`TestDetect_FormBodyEscaped_NoFinding`,
`TestDetect_FormBody_SiblingFieldsPreserved` (mirrors
`sqliactive`'s own Phase 3.21 sibling-preservation proof exactly).
Lab, via a REAL crawl of `/forms/index`'s new `<form method=POST>`:
`TestPhase3_22_FullCrawl_XSSViaPOSTForm_ReachesActiveDetection`. E2E,
through the real binary: `TestScanCmd_ActiveXSSForm_RealBinary`.
**PASS**

### XSS JSON
Unchanged since Phase 3.19 -- re-verified passing. Proven at unit and
lab level via a directly-persisted parameter (the crawler still
cannot produce a live JSON REQUEST body -- Phase 3.18's own,
unchanged architectural fact); no e2e-binary test exists for this
combination, for the identical reason none existed before this phase
-- stated explicitly here, not silently omitted. **PASS**

### SQLI QUERY / SQLI FORM
Unchanged since Phase 3.20/3.21 -- re-verified passing, including
through the real binary. **PASS**

### SQLI JSON
Unchanged since Phase 3.20 -- same JSON/e2e boundary as XSS JSON
above. **PASS**

### CANONICAL MUTATION
Confirmed by re-reading both `xssactive` and `sqliactive` in full:
neither constructs an `http.Request`, `http.Client`, or cookie jar of
its own; both call only `detection.NewMutationRequest`,
`mutation.NewMutation`/`Mutate`, `x.ExecuteMutation`. **PASS**

### TARGET ROUTING
The routing rule (section 2 of the design doc) is now explicit in code
and comments: `REQUEST_INPUT` + `Location ∈ {query, form, json}` →
Target (subject to the same-origin/cross-origin-resolution logic for
form-sourced endpoints); `RESPONSE_FIELD` → never; `path`/`header`/
`cookie` → never (no live discovery source for any of them). Proven at
the unit level for every branch, including the new cross-origin
resolution and its malformed-input fallback. **PASS**

### AUTHENTICATION / MULTI-IDENTITY / SESSION ISOLATION
No new authentication code. Proven per detector/location combination:
`TestPhase3_22_AuthenticatedXSSForm_FindingWithIdentityContext`,
`TestPhase3_22_IdentityAAndB_XSSForm_IndependentFindingsNoContamination`,
and through the real binary
(`TestScanCmd_ActiveXSSForm_AuthenticatedPOSTForm_RealBinary`,
`TestScanCmd_ActiveXSSForm_IdentityAAndB_IndependentScans_RealBinary`).
Session isolation at the raw HTTP/cookie level (not just label
comparison) was already proven for `sqliactive`'s own form path in
Phase 3.21 (`TestDetect_FormMutation_TwoIdentities_DistinctCookiesAtHTTPLevel`)
-- the identical, Location-agnostic mechanism now covers `xssactive`
too, with no new test needed to re-prove the same underlying code
path. **PASS**

### SCOPE ENFORCEMENT / REDIRECT SAFETY
Section 7's resolution proven in both directions: positively
(`TestPhase3_22_FullCrawl_SeparatelyInScopeSecondHost_ReachesActiveDetection`
-- a genuinely separate, separately in-scope host reached via a
cross-origin form action produces a REAL finding, via a REAL second
lab server) and negatively
(`TestPhase3_22_FullCrawl_SecondHostNotInScope_NoFindingAgainstIt`,
`TestPhase3_21_FullCrawl_OutOfScopeFormAction_NeverBecomesFinding`
(updated, design decision 2)). Same-host-different-port and subdomain
confusion proven at the routing level
(`TestPhase3_22_BuildTargets_SameHostDifferentPort_TreatedAsCrossOrigin`,
`TestPhase3_22_BuildTargets_SubdomainConfusion_TreatedAsCrossOrigin`).
Redirect safety unchanged -- reused, re-verified `safedial`/
`scope.Validator` machinery. **PASS**

### RESPONSE COMPARISON / EVIDENCE / SECRET PROTECTION
Unchanged -- `mutation.Compare`/`detection.MutationEvidence` remain
the sole path for both detectors. Password never appears in a
generated report (`TestScanCmd_ActiveXSSForm_AuthenticatedPOSTForm_RealBinary`'s
own explicit assertion). **PASS**

### RESOURCE LIMITS
No new limit needed -- `ExecutorConfig.MaxActiveRequestsPerScan` etc.
are already Location- and detector-agnostic; adding `xssactive`'s
form/JSON eligibility adds new eligible Targets within the SAME
already-bounded budget, not a new request path. **PASS**

### DETERMINISM
`TestPhase3_22_Determinism_RepeatedCrawls_SameXSSFormFindings` --
repeated crawls produce identical XSS-via-form finding counts. No new
map-iteration dependency was introduced (the cross-origin resolution
logic is a pure, deterministic parse of a single string). **PASS**

### LAB
8 new lab test functions
(`lab/phase3_22_active_detection_coverage_test.go`), 2 new minimal
fixtures (`/xss/reflected/form-vulnerable`;
`second-service.scanner.test`'s own standalone app) -- no new
vulnerability-specific lab logic beyond what already existed
(`sqliSimulateQuery` reused for the second host, not reimplemented).
Full `lab` suite re-verified clean under `-race`. **PASS**

### E2E
3 new e2e tests (`tests/e2e/e2e_active_xss_form_test.go`) against the
REAL built binary and the REAL, isolated lab. Full `tests/e2e` suite
re-verified clean. **PASS**

### ADVERSARIAL (task section 14)

| # | Scenario | Covered by |
|---|---|---|
| Out-of-scope query target | Reused, unchanged: Phase 3.19/3.20's own suites |
| Out-of-scope form action | `TestBuildTargets_FormCrossOriginAction_TargetsRealDestinationWithNilIP` (routing), `TestPhase3_21_FullCrawl_OutOfScopeFormAction_NeverBecomesFinding` (no finding, updated), `TestScanCmd_ActiveFormMutation_OutOfScopeAction_NeverBecomesFinding` (real binary, unchanged from Phase 3.21, re-verified) |
| Separately in-scope second host | `TestPhase3_22_FullCrawl_SeparatelyInScopeSecondHost_ReachesActiveDetection` (positive), `TestPhase3_22_FullCrawl_SecondHostNotInScope_NoFindingAgainstIt` (negative) |
| Same host different port | `TestPhase3_22_BuildTargets_SameHostDifferentPort_TreatedAsCrossOrigin`, `TestOriginOf` (Phase 3.21, re-verified) |
| Subdomain confusion | `TestPhase3_22_BuildTargets_SubdomainConfusion_TreatedAsCrossOrigin` |
| Redirect to out-of-scope host | Reused, unchanged: Phase 3.17/3.19's own `safedial` adversarial suite |
| Encoded authority | Reused, unchanged: `endpoints.originOf` uses `net/url`'s own parsing throughout (`TestOriginOf`'s userinfo-stripping case, Phase 3.21) |
| Malformed URL | `TestBuildTargets_FormMalformedActionOrigin_NoTarget` |
| Identity A/B contamination | `TestPhase3_22_IdentityAAndB_XSSForm_IndependentFindingsNoContamination`, `TestScanCmd_ActiveXSSForm_IdentityAAndB_IndependentScans_RealBinary` |
| Credential leakage | `TestScanCmd_ActiveXSSForm_AuthenticatedPOSTForm_RealBinary` (password never in report) |
| CSRF token leakage | Reused, unchanged: Phase 3.21's own `IsLikelySecurityToken` exclusion, Location-agnostic |
| Oversized mutation input | Reused, unchanged: `ExecutorConfig`/`parameters.Limits`, Location-agnostic |
| Cancellation during active detection | Reused, unchanged: `TestDetect_ContextCancelled_ReturnsPromptlyNoHang` (Phase 3.20, Location-agnostic) |
| Concurrent active detection | `TestPhase3_22_IdentityAAndB_XSSForm_IndependentFindingsNoContamination`'s own two-orchestrator pattern; reused concurrency guarantees |

All scenarios: **NO SECURITY BOUNDARY FAILURE. PASS.**

### REGRESSION

```
go build ./...                                          -> clean
go vet ./...                                             -> clean
gofmt -l .                                                -> clean (no output)
go test $(go list ./... | grep -v '/tests/e2e') -race -v  -> ok, 1439 PASS, 0 FAIL (35 packages with tests)
go test ./tests/e2e/... -v                                -> ok, 93 PASS, 0 FAIL (one intermittent failure
                                                              observed on an earlier run of a pre-existing,
                                                              Phase-3.22-unrelated test -- see design decision 4)
```

Production/lab independence re-verified: physically removed `lab/` and
`tests/`, confirmed `go build ./...`/`go vet ./...` succeed with both
absent, restored both, rebuilt again to confirm restoration. Every
pre-existing detector's own test suite re-verified passing unchanged
-- only `xssactive` (the adapter) and `internal/detection/targets.go`
(the cross-origin resolution) were touched, both additively. Explicit
regression re-verification for Phase 3.19 (`internal/detectors/xssactive`'s
own pre-existing query/JSON tests, all still passing),
Phase 3.20 (`internal/detectors/sqliactive`'s own suite, untouched,
all still passing), and Phase 3.21 (`lab/phase3_21_form_mutation_test.go`,
2 tests updated per design decisions 1-2 above, the rest unchanged and
still passing). **PASS**

### RACE

Full non-e2e suite, every package, `-race -count=1`: clean, zero races
reported. **PASS**

## Final validation (task section 16)

1. **Can query parameters reach XSS active detection?** Yes --
   unchanged since Phase 3.19.
2. **Can form parameters reach XSS active detection?** Yes -- this
   phase's own central addition, proven at unit, lab (real crawl), and
   e2e (real binary) level.
3. **Can JSON parameters reach XSS active detection?** Yes, with the
   same honest caveat as every prior phase: proven via a directly-
   persisted parameter, not a live crawl-discovered one, since the
   crawler cannot produce a live JSON request body. No e2e-binary test
   exists for this combination -- stated explicitly, not hidden.
4. **Can query parameters reach SQLi active detection?** Yes --
   unchanged since Phase 3.20.
5. **Can form parameters reach SQLi active detection?** Yes --
   unchanged since Phase 3.21.
6. **Can JSON parameters reach SQLi active detection?** Yes, same
   caveat as question 3.
7. **Do all use the canonical mutation engine?** Yes -- confirmed by
   direct inspection of both detector packages; neither builds its own
   request.
8. **Are REQUEST_INPUT and RESPONSE_FIELD still strictly separated?**
   Yes -- unchanged condition in `BuildTargets`, re-verified.
9. **Is authentication preserved?** Yes, identically across every
   Location, by construction (the session-attachment code path never
   inspects `ParameterLocation`).
10. **Is multi-identity isolation preserved?** Yes, proven at the
    label level and (reused from Phase 3.21) at the raw HTTP/cookie
    level.
11. **Is scope enforced consistently?** Yes -- and now MORE
    completely than before: a cross-origin form's real destination is
    actually scope-checked (via the same, unchanged
    `resolveAndValidate`), rather than the destination simply never
    being attempted.
12. **Are redirects scope-safe?** Yes -- unchanged `safedial`
    machinery, unaffected by this phase's changes.
13. **Is evidence complete?** Yes -- unchanged `MutationEvidence` path
    for both detectors.
14. **Are secrets protected?** Yes -- unchanged Phase 3.15 redaction,
    re-verified via a real e2e report.
15. **Are resource limits preserved?** Yes -- unchanged, already
    Location-agnostic mechanisms.
16. **Is deterministic ordering preserved?** Yes, proven directly
    across 3 repeated real crawls.
17. **Is the lab still independent?** Yes -- re-verified by physically
    removing `lab/`/`tests/`, rebuilding clean, restoring.
18. **Are any discovered input types still unable to reach active
    detection?** Yes, exactly one: path-location parameters -- because
    NOTHING discovers one live in the first place (`InferPathInputs`
    has zero callers), not because of a routing gap. header/cookie
    locations have no discovery source either, unchanged since Phase
    3.13.
19. **If yes, are those limitations explicitly documented?** Yes --
    stated plainly here and in the design doc's own section 6, with
    the exact evidence (a repository-wide grep finding zero callers)
    that led to the conclusion, not an assumption carried over from a
    prior phase.

Every answer is yes except question 18's honest "no" for path
parameters, itself fully explained by question 19 -- not hidden.

## Final report

```
PHASE 3.22 ACTIVE DETECTION COVERAGE COMPLETION

TOTAL TESTS: 1532
PASS: 1532
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

XSS QUERY: PASS
XSS FORM: PASS
XSS JSON: PASS

SQLI QUERY: PASS
SQLI FORM: PASS
SQLI JSON: PASS

CANONICAL MUTATION: PASS
TARGET ROUTING: PASS
AUTHENTICATION: PASS
MULTI-IDENTITY: PASS
SESSION ISOLATION: PASS
SCOPE ENFORCEMENT: PASS
REDIRECT SAFETY: PASS
RESPONSE COMPARISON: PASS
EVIDENCE: PASS
SECRET PROTECTION: PASS
RESOURCE LIMITS: PASS
DETERMINISM: PASS
LAB: PASS
E2E: PASS
ADVERSARIAL: PASS
REGRESSION: PASS
RACE: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 1 (pre-existing, Phase-3.22-unrelated: an
intermittent SQLITE_BUSY race in TestConcurrency_ScopeAdd_FreshDatabase_NoCorruption
when 10 CLI subprocesses race to create+migrate the same brand-new
database file -- observed once during this phase's own regression
sweep, reproduced once more in 3 isolated re-runs, confirmed NOT
caused by any Phase 3.22 code path, and NOT fixed here since a
correct fix belongs to internal/storage/sqlite's own connection/
migration bootstrap strategy, not this phase's detection-routing
scope. See design decision 4 and "Remaining limitations" below.)
PERFORMANCE ISSUES: 0

SUPPORTED INPUT TYPES:
query (GET), application/x-www-form-urlencoded (POST/non-GET form
body, including a cross-origin form action resolved against the
scan's existing scope), JSON request body (REQUEST_INPUT provenance
only, reachable via a directly-persisted parameter today, not yet a
live crawl-discovered path) -- for both sqli-active and
xss-reflected-active.

REMAINING LIMITATIONS:
1. Path-location parameters are never discovered by the live pipeline
   (internal/parameters.InferPathInputs has zero callers) and
   therefore never reach active detection -- a discovery-layer gap,
   not a routing-layer one, confirmed by evidence rather than assumed,
   and explicitly out of this phase's own "active detection coverage,
   not new discovery sources" scope.
2. header/cookie parameter locations have no discovery source at all
   (unchanged since Phase 3.13).
3. A live JSON REQUEST body still cannot be crawl-discovered (the
   crawler issues only GET) -- unchanged since Phase 3.18; JSON
   coverage for both detectors is proven via a directly-persisted
   parameter, with no e2e-binary test for this specific combination.
4. A CSRF/security-token field's real submitted value is never
   recoverable once redacted at discovery time (Phase 3.15's own
   design, unchanged) -- a safe failure mode for a strictly-validating
   application, not a silent gap.
5. (Pre-existing, unrelated to this phase's own changes)
   TestConcurrency_ScopeAdd_FreshDatabase_NoCorruption is
   intermittently flaky: 10 CLI subprocesses racing to create and
   migrate the same brand-new SQLite database file can occasionally
   hit SQLITE_BUSY despite the existing 5-second busy_timeout pragma,
   which is sufficient for ordinary write contention against an
   already-migrated database but not always sufficient for this
   specific "N processes race to create the file itself" scenario.
   Discovered incidentally during this phase's own e2e regression
   sweep; not caused by, and not fixed in, this phase (see design
   decision 4). Recommended for its own focused fix in a future phase
   (e.g., an advisory lock or WAL-mode-aware migration guard shared
   across CLI invocations).

PHASE 3.22 VERDICT: PASS
```

Per the task's final rule: no IDOR/BOLA, authorization testing, mass
assignment, CSRF detection, SSRF/path-traversal/command-injection
active detection, SSTI, XXE, deserialization, file upload
vulnerabilities, business-logic vulnerabilities, or time-based SQLi
were implemented. Stopping here -- Phase 3.23 is not started.
