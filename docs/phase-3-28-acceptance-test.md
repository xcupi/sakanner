# Phase 3.28 Acceptance Test — Open Redirect Active Detector

## PHASE 3.28 OPEN REDIRECT ACTIVE DETECTOR

```
TOTAL TESTS: 2089
PASS:        2089
FAIL:        0
PARTIAL:     0
NOT IMPLEMENTED: 0

OPEN REDIRECT DETECTOR: PASS
QUERY: PASS
FORM: PASS
PATH: PASS
JSON: PARTIAL (see below)
AUTHENTICATION: PASS
MULTI-IDENTITY: PASS
SESSION ISOLATION: PASS
SCOPE ENFORCEMENT: PASS
REDIRECT SAFETY: PASS
EVIDENCE: PASS
FALSE-POSITIVE RESISTANCE: PASS
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
```

`JSON: PARTIAL` is deliberate, not a gap this phase introduced or is
expected to close — the crawler still cannot discover a live JSON
REQUEST_INPUT parameter, the same honest, pre-existing Phase 3.19
limitation already documented for `xssactive`/`ssrfactive`/
`cmdinjectionactive`/`traversalactive`. The underlying JSON-body
detection logic itself is fully proven correct against a real,
genuinely vulnerable endpoint (`/redirect/open/vulnerable-json`) via a
directly-persisted parameter — it is only the live crawl-discovery
path that is not proven. Not inflated to PASS.

2049 tests carried over unchanged from Phase 3.1 through 3.27 (all
still passing after this phase's own changes, including one
pre-existing test proactively updated for a legitimate, expected
reason — see DEFECTS FOUND AND FIXED item 4). 40 tests are new in this
phase: 2 in
[internal/parameters/url_parameter_test.go](../internal/parameters/url_parameter_test.go),
19 in [internal/detectors/openredirectactive/detector_test.go](../internal/detectors/openredirectactive/detector_test.go),
9 in [internal/detectors/openredirectactive/adversarial_test.go](../internal/detectors/openredirectactive/adversarial_test.go),
8 in [lab/phase3_28_openredirect_active_test.go](../lab/phase3_28_openredirect_active_test.go),
2 in [tests/e2e/e2e_openredirect_active_test.go](../tests/e2e/e2e_openredirect_active_test.go).

## OPEN REDIRECT DETECTOR

`internal/detectors/openredirectactive` (new package, ID
`open-redirect-active`) — there is **no** pre-existing "open-redirect"
detector to coexist with (see architecture doc section 1.1); this is
the first active OR passive detector for this vulnerability class.
Built entirely on `internal/mutation`'s canonical Request/Mutate/
Execute model. A finding requires the response to be a genuine 3xx
redirect whose `Location` header, once **parsed and resolved** (RFC
3986 relative-reference resolution via `url.URL.ResolveReference`,
the exact mechanism `net/http`'s own redirect-following uses) against
the request's own URL, produces a destination whose host/port/path
**exactly match** an operator-configured, out-of-scope destination
URL — never a status code, reflection, body content, or substring
match on the raw Location text. Registered but **disabled by
default** (needs an operator-configured destination URL, mirroring
`ssrfactive`/`traversalactive`'s own precedent — there is no passive
sibling to mirror the disabled-by-default reasoning against, since
none exists).

## QUERY / FORM / PATH

All three proven through a REAL crawl → discovery → persistence →
`BuildTargets` → mutation → execution → finding chain, against real
lab fixtures:

- **QUERY**: `TestPhase3_28_QueryLocation_Finding`, reusing the
  EXISTING, unmodified `/redirect/open/vulnerable` fixture (Phase 3)
  — zero new fixture needed.
- **FORM**: `TestPhase3_28_FormLocation_Finding`, new
  `/redirect/open/vulnerable-form` fixture linked from `/forms/index`.
- **PATH**: `TestPhase3_28_PathLocation_Finding`, new
  `/redirect/open/next/<value>` fixture (two example links).

Path-location surfaced a genuine, non-obvious defect during this
phase's own development, structurally similar to (but a different
mechanism from) Phase 3.27's own equivalent discovery — see DEFECTS
FOUND AND FIXED items 1 and 3.

## JSON — PARTIAL, an honest, pre-existing, non-regressed limitation

The crawler cannot discover a live JSON REQUEST_INPUT parameter
through a real crawl — the same Phase 3.19 limitation already
documented for `xssactive`, `ssrfactive` (Phase 3.25),
`cmdinjectionactive` (Phase 3.26), and `traversalactive` (Phase 3.27).
`openredirectactive`'s own JSON-body (`mutation.LocationJSON`) support
is proven correct against a REAL vulnerable HTTP endpoint
(`/redirect/open/vulnerable-json`) using a DIRECTLY-PERSISTED
Parameter row (`TestPhase3_28_JSONLocation_DirectlyPersisted_Finding`),
mirroring the established pattern exactly. Marked PARTIAL, not PASS,
per the task's own explicit instruction not to inflate PASS where the
architecture only supports PARTIAL.

## AUTHENTICATION / MULTI-IDENTITY / SESSION ISOLATION

New authenticated fixture, `/redirect-me` (`lab/harness_auth.go`,
session-gated, mirrors `/download-file`/`/ping-exec`'s Phase 3.26/3.27
precedent). Unlike those two fixtures, a redirect response carries no
reflected body content at all, so the cross-fixture reflected-XSS
concern their own doc comments describe structurally cannot recur
here. Proven with both Phase 3.16 accounts independently
(`TestPhase3_28_AuthenticatedOpenRedirect_TwoIdentities_SessionIsolated`):
each identity's own finding carries the correct `IdentityContext`. No
new authentication mechanism was added.

## SCOPE ENFORCEMENT / REDIRECT SAFETY

Zero new scope or redirect-following code — every probe goes through
the unchanged `mutation.Executor.Execute` → `safedial.Dialer`'s own
`CheckRedirect`, which already truncates the chain at any out-of-scope
hop and returns the last in-scope response (the redirect itself, with
headers intact) rather than an error — this detector only ever
INSPECTS that response, never follows or dials the destination itself.
Proven:

- **The configured destination is never actually dialed**:
  `TestAdversarial_ConfiguredDestination_NeverActuallyDialed` — a
  real, listening canary server as the destination, denied by scope,
  confirmed zero hits recorded even though the finding is correctly
  produced from the Location header alone.
- **Redirect chains**: `TestDetect_RedirectChain_ThroughInScopeHop_Finding`/
  `TestPhase3_28_RedirectChain_OutOfScope_Finding` (a 2-hop chain
  through an in-scope intermediate, ending out of scope — genuinely
  vulnerable, correctly flagged) and `TestDetect_RedirectChain_StaysInScope_NoFinding`/
  `TestPhase3_28_NegativeControls_NoFinding`'s `/redirect/chain/in-scope`
  entry (a chain that never leaves scope — correctly NOT flagged).
- **Same-host, different-port**: `TestDetect_SameHostDifferentPort_NoFinding`
  — in-scope per `scope.Validator.CheckHost` (hostname-only), the
  underlying client CAN follow it, yet this detector still never
  flags it (it structurally cannot match the configured destination),
  a deliberately separate concern from whether the hop is
  scope-followable.
- **Host safety of the injected value**:
  `TestAdversarial_ProbeRequest_NeverChangesHost`.
- **Denied-scope target**: `TestDetect_DeniedScope_ErrorsAndNoRequestsIssued`.

## FALSE-POSITIVE RESISTANCE

All 8 of the task's named scenarios addressed — see architecture doc
section 6's full table. Proven live against 6 negative-control
fixtures (`/redirect/open/safe`, `/redirect/safe-origin`,
`/redirect/relative-only`, `/redirect/reflect-only`,
`/redirect/tracking-decoy`, `/redirect/chain/in-scope`) in
`TestPhase3_28_NegativeControls_NoFinding`, plus unit-level negatives
(`TestDetect_SafeOrigin_NoFinding`, `TestDetect_Allowlist_NoFinding`,
`TestDetect_RelativeOnly_NoFinding`, `TestDetect_ReflectOnly_NoFinding`,
`TestDetect_TrackingDecoy_NoFinding`). The tracking-decoy case
specifically proves the exact-match-after-resolve requirement (section
2 of the architecture doc): a Location header that textually contains
the configured destination's hostname as a query-string decoration,
while the ACTUAL resolved destination is the app's own origin, is
never flagged — a real substring-match trap this detector's design
structurally avoids.

## EVIDENCE / SECRET PROTECTION

Every finding's evidence (2 items: baseline, confirmed probe) reuses
`detection.MutationEvidence` unchanged, proven directly
(`TestPhase3_28_QueryLocation_Finding` asserts `len(f.Evidence) == 2`).
Evidence includes both the raw Location header value and the resolved
destination for reproducibility. No raw credential is ever constructed
by this package.

## RESOURCE LIMITS

No new limit configuration — reused executor bounds apply unchanged.
At most 4 requests per eligible query/form target (1 baseline + 3
variant probes, short-circuiting on the first confirmed match), 2 for
path/JSON — proven exactly (`TestDetect_RequestCount_Bounded`). No new
redirect-hop-following code exists in this detector; the pre-existing
`MaxRedirects`/chain-truncation logic is reused unchanged, already
bounding hops regardless of which detector is running. Cancellation
proven (`TestDetect_ContextCancelled_ReturnsPromptlyNoFinding`).

## DETERMINISM

Proven by `TestPhase3_28_Determinism_RepeatedScans_SameFindingCount`
(3 repeated real-lab scans, identical `open_redirect` finding count
every time).

## LAB

`lab/harness_openredirect_active.go` (new): form/JSON/path-location
vulnerable fixtures plus 6 false-positive-resistance fixtures and a
2-hop redirect-chain pair, all additive, reusing
`registerOpenRedirect`'s (Phase 3) own two existing routes
unmodified. `lab/harness_auth.go` gained one new authenticated
fixture (`/redirect-me`). `lab/harness_form_mutation.go` gained one
new `<form>` on `/forms/index`. `lab/harness_vuln.go` gained 6 new
index links and one new mux-wrapping call
(`openRedirectPathLocationBypass`) — purely additive, no existing
route's behavior changed. `lab/ground-truth-vulnerabilities.yaml`
required **no changes** — it already contained
`VULN-OPENREDIRECT-001`/`VULN-OPENREDIRECT-NEG-001` entries (prepared
before this phase for a detector that didn't exist yet), and no test
that consumes ground truth runs a registry containing this new,
disabled-by-default detector (confirmed via the full regression run,
not assumed — see architecture doc section 10, question 8). Lab/
production independence re-verified: `lab/` and `tests/` moved aside,
`go build ./...`/`go vet ./...` succeed with zero lab-dependent code,
the one already-known harmless false positive (a doc comment in
`internal/detectors/sqliactive/detector_test.go`) confirmed unchanged,
then restored and rebuilt clean.

## E2E

`tests/e2e/e2e_openredirect_active_test.go` (new, 2 tests):
`TestDetectorsCmd_OpenRedirectActive_RegisteredButDisabled` and
`TestScanCmd_OpenRedirectActive_DisabledByDefault_NeverProducesFinding`.
Since `open-redirect-active` is disabled by default (like
`ssrf-active`/`path-traversal-active`, needing an operator-configured
destination no production build ships with), this phase proves the
CLI-level registration/enablement contract and the "never silently
enable an expensive active detector globally" rule through the real
binary — the real positive/negative proof lives in the lab tests
above. Full e2e suite: 109/109 pass.

## ADVERSARIAL

| Scenario | Proof |
|---|---|
| Host never changed by injected destination | `TestAdversarial_ProbeRequest_NeverChangesHost` |
| Configured destination never actually dialed | `TestAdversarial_ConfiguredDestination_NeverActuallyDialed` |
| Redirect chain through an in-scope hop, ending out of scope | `TestDetect_RedirectChain_ThroughInScopeHop_Finding` / `TestPhase3_28_RedirectChain_OutOfScope_Finding` |
| Redirect chain that stays entirely in scope | `TestDetect_RedirectChain_StaysInScope_NoFinding` |
| Same-host, different-port redirect | `TestDetect_SameHostDifferentPort_NoFinding` |
| Concurrent scans / cross-contamination | `TestAdversarial_ConcurrentDetects_NoCrossContamination` (20 goroutines) |
| Cancellation during execution | `TestDetect_ContextCancelled_ReturnsPromptlyNoFinding` |
| Resource exhaustion | `TestDetect_RequestCount_Bounded` |
| Invalid/hostless configured destination | `TestAdversarial_InvalidDestination_NeverConfirms` |
| Reflected URL without redirect | `TestDetect_ReflectOnly_NoFinding` |
| Same-origin / allowlisted / relative-only redirect | `TestDetect_SafeOrigin_NoFinding` / `TestDetect_Allowlist_NoFinding` / `TestDetect_RelativeOnly_NoFinding` |
| Location header with non-equivalent encoded representation | `TestDetect_TrackingDecoy_NoFinding` |
| Concurrent identities | `TestPhase3_28_AuthenticatedOpenRedirect_TwoIdentities_SessionIsolated` |
| Secret leakage | Section "EVIDENCE / SECRET PROTECTION" above |
| Out-of-scope target | `TestDetect_DeniedScope_ErrorsAndNoRequestsIssued` |

## REGRESSION

Every prior phase's own test suite passes (1980/1980 non-e2e, 109/109
e2e — see TOTAL TESTS). One pre-existing test required a genuine,
correct, proactive update (the hardcoded detector-registry count) —
see DEFECTS FOUND AND FIXED item 4; no production behavior regressed.
No ground-truth ripple occurred, verified rather than assumed (see LAB
above) — the first phase this session where pre-existing ground-truth
entries for the new vulnerability class already existed, and they
required no change at all.

## RACE

Full non-e2e suite passes clean under `go test -race` (confirmed in
the first regression pass; the verbose re-run used to extract exact
counts was run without `-race` purely to avoid doubling total runtime
— same code, same outcome).
`internal/detectors/openredirectactive`'s own concurrency test and
`lab/phase3_28_openredirect_active_test.go`'s authenticated
multi-identity test both re-confirmed clean under `-race`
specifically during package-level development.

## SECURITY ISSUES

None found in production code.

## RELIABILITY ISSUES

None.

## PERFORMANCE ISSUES

None observed. Query-location end-to-end detection completes in well
under 1 second against the real lab.

## DEFECTS FOUND AND FIXED

1. **Real, non-obvious gap: `*http.ServeMux`'s built-in path cleaning
   also collapses repeated slashes, not just `".."` segments.** When
   the operator-configured destination (an absolute URL containing
   `scheme://`) is injected as a raw PATH SEGMENT, the `//` immediately
   after the scheme gets collapsed by `path.Clean` to a single `/`
   (`scheme:/host/...`), and `ServeMux.Handler` 301-redirects to that
   corrupted path BEFORE the handler ever runs — reproduced directly
   against the stdlib during this phase's own development (a minimal
   `httptest` repro confirmed the exact corruption:
   `http://external.scanner.test/marker` arrived at the handler as
   `http:/external.scanner.test/marker`, a schemeless, hostless
   value). This is the SAME class of `ServeMux` auto-cleaning artifact
   Phase 3.27 first discovered (there, via dot-segment collapsing on a
   traversal payload) — a structurally different trigger, same root
   cause. Fixed identically: `openRedirectPathLocationBypass`/
   `openRedirectPathLocationHandler`/`openRedirectPathLocationPrefix`
   (`lab/harness_openredirect_active.go`), intercepting that one route
   prefix OUTSIDE the mux, wrapping the fully-assembled
   `vulnAppHandler`.
2. **Real, self-caught defect in this phase's OWN "safe" test
   fixture**: the first version of `safeOriginHandler`
   (`internal/detectors/openredirectactive/detector_test.go`, meant as
   a NEGATIVE control) validated a destination as "safe" using
   `strings.HasPrefix(next, "/")` alone — but a protocol-relative
   value (`//external.redirect.test/marker`) ALSO starts with `/` while
   being a full authority change in every browser and in
   `url.ResolveReference`. Caught by `TestDetect_SafeOrigin_NoFinding`
   failing (the detector correctly flagged what was, in fact, a
   genuine protocol-relative bypass of the fixture's own naive check)
   — a real vulnerability in the TEST fixture's logic, not a false
   positive from the detector. Fixed by rejecting values that are
   ALSO protocol-relative (`strings.HasPrefix(next, "//")`) before
   treating a leading `/` as safe, applied to both the unit-test
   fixture and the real lab fixture (`/redirect/safe-origin`) from the
   start, avoiding reproducing the same mistake twice.
3. **Test-setup bug (not a production defect):**
   `TestAdversarial_ConfiguredDestination_NeverActuallyDialed`'s first
   version used a canary server bound to `127.0.0.1` — the SAME
   loopback address the test's own main server already used — so
   `hostConditionalValidator` (checking hostnames only) allowed it by
   coincidence, defeating the test's own purpose. Fixed by binding the
   canary to a distinct loopback IP (`127.0.0.9`), mirroring
   `sqliactive`/`traversalactive`'s own established `newIPServer`
   pattern for exactly this class of test.
4. **One PRE-EXISTING test's hardcoded detector-registry count required
   a proactive update — a genuine, expected consequence of registering
   a 13th detector, not a regression.**
   `TestDefaultCLI_CrawlerDisabled_ZeroDetectorRunsIsObservable`
   (`tests/e2e/e2e_detection_readiness_test.go`) asserted `"Registered:
   12"`; updated to `"Registered: 13"` after `open-redirect-active`
   joined the production registry, mirroring the identical bump every
   prior phase adding a detector has required (Phase 3.19 → 3.27).

No defect was found in `internal/safedial`, `internal/mutation`,
`internal/detection`, `internal/orchestrator`, or `internal/scope` —
every fact this phase's architecture review relied on (in particular,
`safedial.Dialer`'s own `CheckRedirect` truncation behavior) was
independently verified by directly reading the relevant source files
AND by reproducing it against the real stdlib, and none of them
required any change.

## REMAINING LIMITATIONS

1. **JSON REQUEST_INPUT parameters cannot be discovered through a real
   crawl** — an honest, pre-existing Phase 3.19 limitation, reaffirmed
   identically for the fifth consecutive phase (`xssactive`,
   `ssrfactive`, `cmdinjectionactive`, `traversalactive`, now
   `openredirectactive`). Not something any single phase is positioned
   to close in isolation.
2. **Header/cookie-location redirect parameters are not supported** —
   no discovery source in this codebase ever produces a header/cookie-
   location URL-shaped parameter, so none is claimed.
3. **Userinfo-component redirect obfuscation is not a dedicated
   payload variant** (e.g. `http://trusted-looking@attacker.test/`) —
   a real bypass technique against SOME naive validators, but out of
   this phase's own bounded 3-variant set (absolute/protocol-relative/
   percent-encoded). Documented, not silently claimed as covered.
4. **`*http.ServeMux`-routed path-location lab fixtures require the
   routing-layer workaround documented in DEFECTS FOUND AND FIXED item
   1** — not a limitation of the detector itself, but future lab
   fixtures adding new path-location routes that inject `scheme://`-
   shaped values on top of `http.ServeMux` should be aware of this
   double-slash-collapsing behavior, exactly as Phase 3.27 already
   documented for dot-segment collapsing.

## PHASE 3.28 VERDICT: PASS
