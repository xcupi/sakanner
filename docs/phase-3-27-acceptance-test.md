# Phase 3.27 Acceptance Test — Path Traversal Active Detector

## PHASE 3.27 PATH TRAVERSAL ACTIVE DETECTOR

```
TOTAL TESTS: 2049
PASS:        2049
FAIL:        0
PARTIAL:     0
NOT IMPLEMENTED: 0

PATH TRAVERSAL DETECTOR:     PASS
QUERY:                       PASS
FORM:                        PASS
PATH:                        PASS
JSON:                        PARTIAL (see below)
AUTHENTICATION:              PASS
MULTI-IDENTITY:              PASS
SESSION ISOLATION:           PASS
SCOPE ENFORCEMENT:           PASS
PAYLOAD SAFETY:               PASS
RESPONSE COMPARISON:          PASS (deliberately unused as evidence -- see below)
EVIDENCE:                     PASS
CORRELATION-RISK:             PASS
FALSE-POSITIVE RESISTANCE:    PASS
SECRET PROTECTION:            PASS
RESOURCE LIMITS:               PASS
DETERMINISM:                  PASS
LAB:                          PASS
E2E:                          PASS
ADVERSARIAL:                  PASS
REGRESSION:                   PASS
RACE:                         PASS

SECURITY ISSUES:     0
RELIABILITY ISSUES:  0
PERFORMANCE ISSUES:  0
```

`JSON: PARTIAL` is deliberate, not a gap this phase introduced or is
expected to close — the crawler still cannot discover a live JSON
REQUEST_INPUT parameter, the same honest, pre-existing Phase 3.19
limitation already documented for `xssactive`/`ssrfactive`/
`cmdinjectionactive`. The underlying JSON-body detection logic itself
is fully proven correct against a real, genuinely vulnerable endpoint
(`/files/download/vulnerable-json`) via a directly-persisted
parameter — it is only the live crawl-discovery path that is not
proven, per Do not inflate PASS where the architecture only supports
PARTIAL.

2008 tests carried over unchanged from Phase 3.1 through 3.26 (all
still passing after this phase's own changes, including one
pre-existing test proactively updated for a legitimate, expected
reason — see DEFECTS FOUND AND FIXED item 6). 41 tests are new in this
phase: 4 in
[internal/parameters/filepath_parameter_test.go](../internal/parameters/filepath_parameter_test.go),
21 in [internal/detectors/traversalactive/detector_test.go](../internal/detectors/traversalactive/detector_test.go),
7 in [internal/detectors/traversalactive/adversarial_test.go](../internal/detectors/traversalactive/adversarial_test.go),
2 in [internal/detectors/traversalactive/filesystem_safety_test.go](../internal/detectors/traversalactive/filesystem_safety_test.go),
7 in [lab/phase3_27_traversal_active_test.go](../lab/phase3_27_traversal_active_test.go),
2 in [tests/e2e/e2e_traversal_active_test.go](../tests/e2e/e2e_traversal_active_test.go).

## PATH TRAVERSAL DETECTOR

`internal/detectors/traversalactive` (new package, ID
`path-traversal-active`) — coexists with `internal/detectors/traversal`
(Phase 3.6), which is not modified anywhere in this change (confirmed:
zero diff to that package, and its own test suite passes unchanged).
Built entirely on `internal/mutation`'s canonical Request/Mutate/
Execute model, unlike `traversal` itself (which predates it, builds
its own `*http.Request` per probe, and is GET/query-location only).
Reuses `traversal.TraversalCase{RelativePath, Marker}` directly
(imported, not duplicated) but implements ONLY the old detector's
stronger "confirmed marker match" evidence tier — the weaker
"suspicious" (response-difference-from-baseline) tier is deliberately
dropped, mirroring `ssrfactive`'s identical decision relative to `ssrf`
(Phase 3.25). Registered but disabled by default (needs an
operator-configured `[]traversal.TraversalCase`, mirroring
`ssrfactive`/`idoractive`'s own precedent, not `cmdinjectionactive`'s
self-contained one) — proven only through the lab.

## QUERY / FORM / PATH

All three proven through a REAL crawl → discovery → persistence →
`BuildTargets` → mutation → execution → finding chain, against real
lab fixtures:

- **QUERY**: `TestPhase3_27_QueryLocation_Finding`, reusing the
  EXISTING, unmodified `/files/download/vulnerable` fixture
  (Phase 3.6) — zero new fixture needed.
- **FORM**: `TestPhase3_27_FormLocation_Finding`, new
  `/files/download/vulnerable-form` fixture linked from `/forms/index`.
- **PATH**: `TestPhase3_27_PathLocation_Finding`, new
  `/files/download/path/<value>` fixture (two example links,
  `report-1.txt`/`report-2.txt`).

Path-location surfaced a genuine, non-obvious defect during this
phase's own development — see DEFECTS FOUND AND FIXED item 1 (Go's
`http.ServeMux` auto-redirecting `".."`-containing paths before any
handler runs). Once fixed, this is a genuine FINDING-level proof (not
merely parameter discovery), matching the bar Phase 3.26 first
established for `cmdinjectionactive`'s own path-location test.

## JSON — PARTIAL, an honest, pre-existing, non-regressed limitation

The crawler cannot discover a live JSON REQUEST_INPUT parameter
through a real crawl — the same Phase 3.19 limitation already
documented for `xssactive`, `ssrfactive` (Phase 3.25), and
`cmdinjectionactive` (Phase 3.26). `traversalactive`'s own JSON-body
(`mutation.LocationJSON`) support is proven correct against a REAL
vulnerable HTTP endpoint (`/files/download/vulnerable-json`) using a
DIRECTLY-PERSISTED Parameter row
(`TestPhase3_27_JSONLocation_DirectlyPersisted_Finding`), mirroring
the established pattern exactly. Marked PARTIAL, not PASS, per the
task's own explicit instruction not to inflate PASS where the
architecture only supports PARTIAL.

## AUTHENTICATION / MULTI-IDENTITY / SESSION ISOLATION

New authenticated fixture, `/download-file` (`lab/harness_auth.go`,
session-gated, mirrors `/ping-exec`'s Phase 3.26 precedent — including
its own hard-learned "never echo the raw parameter value" lesson: the
handler only ever returns the resolved file's own content, never the
raw `file` value, so it cannot accidentally look like reflected XSS to
`xssactive` once both fixtures are discovered in the same authenticated
scan). Proven with both Phase 3.16 accounts independently
(`TestPhase3_27_AuthenticatedTraversal_TwoIdentities_SessionIsolated`):
each identity's own finding carries the correct `IdentityContext`. No
new authentication mechanism was added.

## SCOPE ENFORCEMENT

Zero new scope code — every probe goes through the unchanged
`mutation.Executor.Execute` → `resolveAndValidate` path. Host safety of
an injected traversal value proven
(`TestAdversarial_ProbeRequest_NeverChangesHost`); scope-denial proven
(`TestDetect_DeniedScope_ErrorsAndNoRequestsIssued`); redirect-to-
out-of-scope-host proven never followed even when the out-of-scope
target serves back the exact configured marker
(`TestDetect_RedirectToOutOfScopeHost_NeverFollowed`) — the marker's
mere appearance is never sufficient proof by itself, it must be
reachable within scope.

## PAYLOAD SAFETY

Every payload is either the literal configured `TraversalCase.RelativePath`
or one of its wire-encoded representations (percent-encoded `..`/`/`)
— never a destructive filesystem operation, write, delete, execution,
or arbitrary enumeration attempt. `filesystem_safety_test.go` proves,
both statically (no local-filesystem-touching import, via `go/parser`)
and dynamically (a temp working directory stays empty after `Detect`
runs against dangerous-looking configured values like
`../../../../../../etc/passwd`), that this package never touches the
real local filesystem — mirroring `traversal`'s own identical,
already-reviewed guarantee.

## FALSE-POSITIVE RESISTANCE

All 8 of the task's named scenarios addressed — see architecture doc
section 2's full table. Proven live against the 5 existing
negative-control fixtures (`/files/download/safe`, `sanitized`,
`by-id`, `reflect`, `generic`) in
`TestPhase3_27_NegativeControls_NoFinding`, plus unit-level negatives
(`TestDetect_SafeContained_NoFinding`, `TestDetect_Sanitized_NoFinding`,
`TestDetect_ByIDNoPathConstruction_NoFinding`,
`TestDetect_ReflectionOnly_NoFinding`,
`TestDetect_GenericResponse_NoFinding`,
`TestAdversarial_EmptyMarker_NeverConfirms`).

## EVIDENCE / SECRET PROTECTION / CORRELATION-RISK

Every finding's evidence (2 items: baseline, confirmed probe) reuses
`detection.MutationEvidence` unchanged, proven directly
(`TestPhase3_27_QueryLocation_Finding` asserts `len(f.Evidence) == 2`).
No raw credential is ever constructed by this package. Findings use
the standard `models.Finding` shape (`VulnerabilityType:
"path_traversal"`, `Category: "broken_access_control"`, `Severity:
Critical`) with no detector-specific correlation code required — the
existing, unmodified correlation/risk pipeline consumes it exactly
like every other detector's output.

## RESPONSE COMPARISON

`internal/mutation.Compare` exists but is deliberately unused as a
finding-basis anywhere in this package — the task's own prohibition on
"arbitrary response differences alone" as proof is enforced
structurally: the only code path to `OutcomeFinding` requires an exact
`bytes.Contains` match of the operator-configured marker.

## RESOURCE LIMITS

No new limit configuration — reused executor bounds apply unchanged.
At most 5 requests per eligible target (1 baseline + 4 variant probes
for one configured case, short-circuiting on the first confirmed
match) — proven exactly (`TestDetect_RequestCount_Bounded`). Proven
scaling to multiple cases remains linear and bounded by construction
(nested loop, no unbounded recursion/enumeration). Cancellation proven
(`TestDetect_ContextCancelled_ReturnsPromptlyNoFinding`).

## DETERMINISM

Proven by `TestPhase3_27_Determinism_RepeatedScans_SameFindingCount`
(3 repeated real-lab scans, identical `path_traversal` finding count
every time).

## LAB

`lab/harness_traversal_active.go` (new): form/JSON/path-location
fixtures, all additive, reusing `travSynthFS`/`travResolve`'s own
Phase 3.6 resolution logic verbatim. `lab/harness_auth.go` gained one
new authenticated fixture (`/download-file`). `lab/harness_form_mutation.go`
gained one new `<form>` on `/forms/index`. `lab/harness_vuln.go`
gained two new index links (path-location examples), five new
`travSynthFS` entries (see DEFECTS FOUND AND FIXED items 2-3), and one
new wrapper (`travPathLocationBypass`, see item 1) around the
assembled mux — purely additive, no existing route's behavior changed.
`lab/ground-truth-vulnerabilities.yaml` required **no new entries** —
confirmed by the full regression run: unlike Phase 3.25's
`/ssrf/vulnerable-blind` and Phase 3.26's
`/api/ping/vulnerable-windows`, none of this phase's new fixtures are
QUERY-GET-location, so the pre-existing, unmodified `traversal`
detector (query-GET-only) never becomes independently eligible for any
of them — the architecture doc's own prediction, verified rather than
assumed. Lab/production independence re-verified: `lab/` and `tests/`
moved aside, `go build ./...`/`go vet ./...` succeed with zero
lab-dependent code, the one already-known harmless false positive (a
doc comment in `internal/detectors/sqliactive/detector_test.go`)
confirmed unchanged, then restored and rebuilt clean.

## E2E

`tests/e2e/e2e_traversal_active_test.go` (new, 2 tests):
`TestDetectorsCmd_PathTraversalActive_RegisteredButDisabled` and
`TestScanCmd_PathTraversalActive_DisabledByDefault_NeverProducesFinding`.
Since `path-traversal-active` is disabled by default (like
`ssrf-active`/`idor-active`, needing an operator-configured
`TraversalCase` no production build ships with), this phase proves the
CLI-level registration/enablement contract and the "never silently
enable an expensive active detector globally" rule through the real
binary — the real positive/negative proof lives in the lab tests
above, mirroring `ssrfactive`'s own identical, already-reviewed
precedent. Full e2e suite: 107/107 pass.

## ADVERSARIAL

| Scenario | Proof |
|---|---|
| Host never changed by injected value | `TestAdversarial_ProbeRequest_NeverChangesHost` |
| Dot-segments not collapsed client-side | `TestAdversarial_DotSegmentsNeverCollapsedBeforeSending` |
| Concurrent scans / cross-contamination | `TestAdversarial_ConcurrentDetects_NoCrossContamination` (20 goroutines) |
| Empty/misconfigured marker never trivially confirms | `TestAdversarial_EmptyMarker_NeverConfirms` |
| Cancellation during execution | `TestDetect_ContextCancelled_ReturnsPromptlyNoFinding` |
| Resource exhaustion | `TestDetect_RequestCount_Bounded` |
| Redirect to out-of-scope host serving the exact marker | `TestDetect_RedirectToOutOfScopeHost_NeverFollowed` |
| Reflected-only traversal-looking values | `TestDetect_ReflectionOnly_NoFinding`, `/files/download/reflect` |
| Sanitized/defended endpoint | `TestDetect_Sanitized_NoFinding`, `/files/download/sanitized` |
| Opaque ID-based lookup (no path construction) | `TestDetect_ByIDNoPathConstruction_NoFinding`, `/files/download/by-id` |
| Generic constant response | `TestDetect_GenericResponse_NoFinding`, `/files/download/generic` |
| Malicious configured TraversalCase never touches local filesystem | `TestDetect_MaliciousTraversalCase_NeverTouchesLocalFilesystem` |
| Concurrent identities | `TestPhase3_27_AuthenticatedTraversal_TwoIdentities_SessionIsolated` |
| Secret leakage | Section "EVIDENCE / SECRET PROTECTION" above |
| Out-of-scope behavior (non-redirect) | `TestDetect_DeniedScope_ErrorsAndNoRequestsIssued` |

## REGRESSION

Every prior phase's own test suite passes (1942/1942 non-e2e, 107/107
e2e — see TOTAL TESTS). One pre-existing test required a genuine,
correct, proactive update (the hardcoded detector-registry count) —
see DEFECTS FOUND AND FIXED item 6; no production behavior regressed.
No ground-truth ripple occurred, verified rather than assumed (see LAB
above).

## RACE

Full non-e2e suite passes clean under `go test -race` (confirmed in
the FIRST regression pass, before the verbose re-run — the verbose
re-run itself was run without `-race` purely to extract exact counts
without doubling runtime; both passes are the same code, same
outcome). `internal/detectors/traversalactive`'s own concurrency test
and `lab/phase3_27_traversal_active_test.go`'s authenticated
multi-identity test both re-confirmed clean under `-race` specifically
during package-level development.

## SECURITY ISSUES

None found in production code.

## RELIABILITY ISSUES

None.

## PERFORMANCE ISSUES

None observed. Query-location end-to-end detection completes in well
under 1 second against the real lab.

## DEFECTS FOUND AND FIXED

1. **Real, non-obvious gap: Go's `net/http.ServeMux` unconditionally
   301-redirects any request whose decoded path contains `".."` to its
   cleaned equivalent, BEFORE any registered handler runs.** Discovered
   while debugging why `TestPhase3_27_PathLocation_Finding` produced no
   finding despite the path-location parameter being correctly
   discovered and eligible: reproduced directly against the stdlib
   (a minimal `httptest` repro confirmed `ServeMux.Handler`'s own
   `cleanPath` redirect fires before dispatch). This silently defeated
   the path-location traversal fixture regardless of what the handler
   itself would have done with the raw segment — a routing-layer
   artifact, not a detector defect. Fixed by intercepting that one
   route prefix OUTSIDE the mux
   (`travPathLocationBypass`/`travPathLocationHandler`/
   `travPathLocationPrefix`, `lab/harness_traversal_active.go`),
   wrapping the fully-assembled `vulnAppHandler` so every other route's
   behavior is completely unaffected. This exercises a realistic
   "custom router trusts a raw path segment" vulnerability shape
   instead of a `ServeMux`-specific artifact, and is documented in the
   architecture doc (section 13, question 10) as a generalizable fact
   for any future path-location lab fixture built on `http.ServeMux`.
2. **Real gap: the two path-location crawl-discovery example links
   (`/files/download/path/report-1.txt`, `report-2.txt`) had no
   corresponding entries in `travSynthFS`.** Their baseline
   ("legitimate access") probe 404'd, failing the `looksAllowed`
   reachability gate before any traversal payload was ever tried.
   Caught by `TestPhase3_27_PathLocation_Finding` failing with the
   query-location finding present but no path-location one. Fixed by
   adding `"public/report-1.txt"`/`"public/report-2.txt"` entries to
   `travSynthFS` (`lab/harness_vuln.go`).
3. **Real gap: `/files/download/vulnerable-json`'s baseline probe has
   no seeded body** (`detection.NewMutationRequest` has no
   JSON-seeding mechanism), so it legitimately arrives with an empty
   `file` field, resolving to `travResolve("")` = `"public"` — a key
   `travSynthFS` did not have, causing the same baseline-gate 404 as
   item 2. Fixed by adding a `"public": "index of public/"` entry to
   `travSynthFS`, mirroring the identical fix already applied in this
   package's own unit test (`detector_test.go`'s local `testFS`).
   Verified no existing test relies on an empty-`file`-value-404
   behavior before adding this entry.
4. **Self-caught tool-usage mistake (not a code defect):** the first
   version of `filesystem_safety_test.go` used an invalid
   `httpHandlerFunc`/`httpResponseWriter`/`httpRequest` type-alias hack
   instead of importing `net/http` directly. Fixed immediately during
   development, before any test run was attempted against it.
5. **Test-authoring/formatting bug:** `gofmt` flagged
   `detector_test.go`'s `testFS` map literal alignment after adding the
   `"public"` key (item 3's fix). Fixed via `gofmt -w`.
6. **One PRE-EXISTING test's hardcoded detector-registry count required
   a proactive update — a genuine, expected consequence of registering
   a 12th detector, not a regression.**
   `TestDefaultCLI_CrawlerDisabled_ZeroDetectorRunsIsObservable`
   (`tests/e2e/e2e_detection_readiness_test.go`) asserted `"Registered:
   11"`; updated to `"Registered: 12"` after `path-traversal-active`
   joined the production registry, mirroring the identical bump every
   prior phase adding a detector has required (Phase 3.19 → 3.26).

No defect was found in `internal/detectors/traversal`, `internal/mutation`,
`internal/detection`, `internal/orchestrator`, `internal/safedial`, or
`internal/scope` — every fact this phase's architecture review relied
on was independently verified by directly reading the relevant source
files, and none of them required any change.

## REMAINING LIMITATIONS

1. **JSON REQUEST_INPUT parameters cannot be discovered through a real
   crawl** — an honest, pre-existing Phase 3.19 limitation, reaffirmed
   identically for the fourth consecutive phase (`xssactive`,
   `ssrfactive`, `cmdinjectionactive`, now `traversalactive`). Not
   something any single phase is positioned to close in isolation.
2. **Header/cookie path-traversal inputs are not supported** — no
   discovery source in this codebase ever produces a header/cookie-
   location file-path-shaped parameter, so none is claimed.
3. **Path-location traversal fixtures built on a plain
   `*http.ServeMux` require the routing-layer workaround documented in
   DEFECTS FOUND AND FIXED item 1** — not a limitation of the detector
   itself (which sends and receives exactly what the wire protocol
   allows), but future lab fixtures adding NEW path-location routes on
   `http.ServeMux` should be aware `".."` in a path segment will be
   silently redirected away unless routed like
   `travPathLocationBypass`.
4. **DNS rebinding / IP-obfuscation traversal techniques are not
   addressed** — out of this phase's own scope (task section 12),
   consistent with every prior "-active" detector's own identical
   boundary.

## ARCHITECTURAL FINDINGS

See [docs/phase-3-27-path-traversal-active.md](phase-3-27-path-traversal-active.md)
in full, including the complete post-implementation architecture
review (section 13). Headline findings:

- `internal/detectors/traversal` (Phase 3.6) already has a directly
  reusable `TraversalCase` type and an existing, near-complete
  false-positive-resistant fixture family
  (`registerPathTraversalAPI`) — reused verbatim/as-is for the
  query-location proof and every negative control, with zero
  modification needed.
- Query-GET-only structural ineligibility of the OLD detector for this
  phase's new form/JSON/path fixtures held exactly as predicted —
  confirmed via the full regression run, not assumed; no ground-truth
  update was needed at all, a first among the three most recent
  "-active" phases (3.25/3.26 both required one).
- A genuinely new, generalizable architectural fact was discovered:
  `net/http.ServeMux`'s built-in dot-segment path cleaning silently
  defeats path-segment traversal attempts before a handler ever runs —
  worth remembering for any future lab fixture (or, more importantly,
  any real production code review) that routes path-location input
  through a plain `ServeMux`.

## PHASE 3.27 VERDICT: PASS
