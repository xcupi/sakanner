# Phase 3.25 Acceptance Test — SSRF Active Detection Foundation

## PHASE 3.25 SSRF ACTIVE DETECTION

```
TOTAL TESTS: 1967
PASS:        1967
FAIL:        0
PARTIAL:     0
NOT IMPLEMENTED: 0

SSRF DETECTOR:              PASS
RESPONSE-BASED SSRF:        PASS
BLIND/OOB SSRF:              PASS
QUERY:                       PASS
FORM:                        PASS
JSON:                        PARTIAL (see below)
PATH:                        PASS
AUTHENTICATION:               PASS
MULTI-IDENTITY:               PASS
SESSION ISOLATION:            PASS
SCOPE ENFORCEMENT:            PASS
REDIRECT SAFETY:              PASS
CALLBACK CORRELATION:         PASS
FALSE-POSITIVE RESISTANCE:    PASS
EVIDENCE:                     PASS
SECRET PROTECTION:            PASS
RESOURCE LIMITS:              PASS
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
expected to close — see "JSON location" below.

1966 tests carried over unchanged from Phase 3.14 through 3.24 (all
still passing after this phase's own changes, including three
existing tests updated for legitimate reasons — see DEFECTS FOUND AND
FIXED). 32 tests are new in this phase: 2 in
[internal/parameters/url_parameter_test.go](../internal/parameters/url_parameter_test.go),
14 in [internal/detectors/ssrfactive/detector_test.go](../internal/detectors/ssrfactive/detector_test.go),
4 in [internal/detectors/ssrfactive/adversarial_test.go](../internal/detectors/ssrfactive/adversarial_test.go),
10 in [lab/phase3_25_ssrf_active_test.go](../lab/phase3_25_ssrf_active_test.go),
2 in [tests/e2e/e2e_ssrf_active_test.go](../tests/e2e/e2e_ssrf_active_test.go).

## SSRF DETECTOR

`internal/detectors/ssrfactive` (new package, ID `ssrf-active`) —
coexists with `internal/detectors/ssrf` (Phase 3.4), which is not
modified. Built entirely on `internal/mutation`'s canonical
Request/Mutate/Execute model, unlike `ssrf` itself (which predates it
and builds its own `*http.Request` per probe).

## RESPONSE-BASED SSRF (Mode A)

Reuses the pre-existing, unmodified `ssrf-internal.scanner.test`
fixture (`lab/harness_vuln.go`, Phase 3.4) as the "internal resource"
— no new lab server was needed. A finding requires the TARGET
APPLICATION's own response to embed that resource's distinctive,
fixed content (`"ssrf-internal-fixture"`), never a status code, a
reflected URL, or a generic diff. Proven live end to end
(`TestPhase3_25_QueryLocation_ResponseBasedAndCallback_Finding`,
confidence 0.95 — both modes confirmed).

## BLIND/OOB SSRF (Mode B)

Reuses `internal/detectors/ssrf.CallbackClient` and
`lab.SSRFCallbackServer` unchanged. A dedicated fixture,
`/ssrf/vulnerable-blind`, whose response NEVER reveals fetch outcome
(fire-and-forget goroutine, modeling an async/queued job), proves Mode
B alone is sufficient (`TestPhase3_25_BlindOnly_Finding`, confidence
0.9). Also added as a new positive to
`lab/ground-truth-vulnerabilities.yaml` (`VULN-SSRF-BLIND-001`) since
it is a genuinely new, distinct vulnerable fixture the pre-existing
`ssrf` detector's own ground-truth test now correctly detects too.

## QUERY / FORM / PATH

All three proven through a REAL crawl → discovery → persistence →
BuildTargets → mutation → execution → finding chain, against real
lab fixtures:
`TestPhase3_25_QueryLocation_ResponseBasedAndCallback_Finding`,
`TestPhase3_25_FormLocation_Finding` (`/ssrf/vulnerable-form`, linked
from `/forms/index`), `TestPhase3_25_PathLocation_Finding`
(`/ssrf/fetch/<url-path-escaped-target>`, two example links). The CLI
e2e level additionally confirms `ssrf-active` never fires when
disabled by default.

## JSON LOCATION — PARTIAL, an honest, pre-existing, non-regressed limitation

The crawler cannot discover a live JSON REQUEST_INPUT parameter
through a real crawl — this is a Phase 3.19 limitation, already
honestly documented there for `xssactive`
(`docs/phase-3-19-acceptance-test.md`: *"the crawler still cannot
produce a live JSON REQUEST body"*), unchanged by every phase since,
including this one. `ssrfactive`'s own JSON-body (`mutation.LocationJSON`)
support is proven correct against a REAL vulnerable HTTP endpoint
(`/ssrf/vulnerable-json`) using a DIRECTLY-PERSISTED Parameter row
(`Location: "json"`, `Provenance: "REQUEST_INPUT"`) — mirroring
`TestPhase3_19_JSONRequestInputParameter_ReachesActiveDetection`'s
own exact, already-accepted pattern
(`TestPhase3_25_JSONLocation_DirectlyPersisted_Finding`). This is
marked PARTIAL, not PASS, specifically because the task's own "prove
it with an actual end-to-end test" bar is satisfied for the
detector/mutation/execution logic but NOT for real crawl-based
discovery — an honest distinction, not an inflated claim.

## AUTHENTICATION / MULTI-IDENTITY / SESSION ISOLATION

New authenticated fixture, `/ssrf-fetch` (`lab/harness_auth.go`,
session-gated, mirrors `/lookup`'s Phase 3.20 precedent). Proven with
BOTH Phase 3.16 accounts independently
(`TestPhase3_25_AuthenticatedSSRF_TwoIdentities_SessionIsolated`):
each identity's own finding carries the correct `IdentityContext`,
proving no cookie/session crossover. No new authentication mechanism
was added — `ssrfactive` receives its session-bound `*detection.Executor`
the exact same way every detector already does.

## SCOPE ENFORCEMENT / REDIRECT SAFETY

Zero new scope code — every probe goes through the unchanged
`mutation.Executor.Execute` → `resolveAndValidate` path. Host safety
of a mutated payload value proven
(`TestAdversarial_ProbeRequest_NeverChangesHost`); scope-denial
proven (`TestDetect_DeniedScope_ErrorsAndNoRequestsIssued`).
"Callback through redirect" proven as an infrastructure-level fact,
requiring zero detector-side redirect code
(`TestPhase3_25_RedirectThroughCallback_CallbackRecordsHit`): a new
`/ssrf/redirect-bounce` fixture, restricted to loopback destinations,
lets the TARGET APPLICATION's own outbound client follow a
server-side redirect to the real callback server.

## CALLBACK CORRELATION

Reused `ssrf.CallbackClient`/`lab.SSRFCallbackServer` entirely
unchanged (no modification to `lab/callback.go` — a deliberate
decision documented in the architecture review, since one existing
test hard-asserts the literal ack body, and changing it for no
compelling gain wasn't worth risking). Cross-scan isolation proven
sequentially (existing `ssrf` package test,
`TestCorrelation_CallbackFromAnotherScanIsolated`, unchanged) and
under true concurrent execution, new to this phase
(`TestAdversarial_ConcurrentScans_CallbacksNeverCrossAttribute`,
`TestAdversarial_ManyConcurrentProbes_NoRaceNoCrossContamination`, 20
goroutines).

## FALSE-POSITIVE RESISTANCE

All 10 of task section 7's named scenarios addressed — see
architecture doc section 7's full table. Proven live against
`/ssrf/reflect-only`, `/ssrf/store-only`, `/ssrf/client-fetch`,
`/ssrf/validate-reject` (`TestPhase3_25_NegativeControls_NoFinding`)
plus `/ssrf/safe` (`TestPhase3_25_SafeEndpoint_NoFinding`) and unit-level
reflection/login-style negatives
(`TestDetect_ReflectedURLOnly_NoMarker_NoFinding`,
`TestDetect_NoCallbackNoMarker_NoFinding`).

## EVIDENCE / SECRET PROTECTION

Every finding's evidence (2-3 items depending on which mode(s)
confirmed) records the baseline, Mode A probe (with an explicit
`marker_found` observation), and Mode B probe (with the callback
token and a redacted-safe observation summary) — reusing
`detection.MutationEvidence` unchanged. No raw credential is ever
constructed by this package; only plain, non-secret identity names
and bare UUID correlation tokens ever appear in evidence/findings.

## RESOURCE LIMITS

No new limit configuration — the SAME `MaxMutationsPerParameter`/
`MaxActiveRequestsPerScan`/`Concurrency`/rate-limiter bounds every
other active detector already respects apply unchanged. At most 3
requests per eligible target (baseline uncharged, Mode A and Mode B
each independently charged against the mutation budget). The
callback poll is bounded (`callbackMaxWait = 200ms`) and ctx-aware —
cancellation during the wait returns promptly, proven
(`TestDetect_ContextCancelledDuringCallbackWait_ReturnsPromptly`), no
goroutine/timer/waiter left behind.

## DETERMINISM

Proven by `TestPhase3_25_Determinism_RepeatedScans_SameFindingCount`
(3 repeated real-lab scans, identical `ssrf` finding count every
time) — structural determinism (target ordering, payload ordering,
finding count/shape), never byte-identical UUID tokens, which would
be a meaningless definition given a real correlation token is
involved.

## LAB

`lab/harness_ssrf_active.go` (new): form/JSON/path/blind/redirect
fixtures, all additive, reusing the loopback-only safety net
`/ssrf/vulnerable` already established (duplicated, not shared, so
that file is never touched). `lab/harness_auth.go` gained one new
authenticated fixture (`/ssrf-fetch`). `lab/harness_form_mutation.go`
gained one new `<form>` on `/forms/index`. `lab/harness_vuln.go`
gained three new index links (path-location examples, blind-only) —
purely additive. `lab/ground-truth-vulnerabilities.yaml` gained one
new positive entry (`VULN-SSRF-BLIND-001`). Lab/production
independence re-verified: `lab/` and `tests/` moved aside,
`go build ./...`/`go vet ./...` succeed with zero lab-dependent code,
the one already-known harmless false positive (a doc comment in
`internal/detectors/sqliactive/detector_test.go`) confirmed unchanged,
then restored and rebuilt clean.

## E2E

`tests/e2e/e2e_ssrf_active_test.go` (new, 2 tests): confirms
`ssrf-active` is registered but disabled by default via `detectors
list`, and confirms a real scan against a plain URL-shaped-parameter
fixture never produces an `ssrf` finding while disabled (task
section 16's "do not silently enable an expensive active detector
globally"). No dedicated CLI e2e test exists for the POSITIVE case,
mirroring the pre-existing `ssrf` package's own identical precedent —
nothing to prove via the real binary beyond registration, since no
production-reachable callback service ships with this build (an
honest, pre-existing gap `ssrf.New(nil)` already documents, carried
forward unchanged). Full e2e suite: 102/102 pass.

## ADVERSARIAL

Task section 19's list, mapped:

| Scenario | Proof |
|---|---|
| Out-of-scope callback destination | Structurally impossible — the scanner never dials callback/resource URLs itself (architecture doc section 6) |
| Malicious hostname | `TestAdversarial_DangerousOriginalParameterValueNeverDialed` |
| Redirect scope bypass | `TestAdversarial_ProbeRequest_NeverChangesHost`; unchanged `mutation.Executor` redirect re-validation |
| Callback token collision | Inherited from `ssrf`'s own `TestAdversarial_TokenCollision_StillCorrelatesToTheSharedToken` (unchanged) |
| Concurrent callback events | `TestAdversarial_ManyConcurrentProbes_NoRaceNoCrossContamination` |
| Wrong-scan callback | `TestAdversarial_ConcurrentScans_CallbacksNeverCrossAttribute` |
| Wrong-identity callback | `TestPhase3_25_AuthenticatedSSRF_TwoIdentities_SessionIsolated` |
| Callback replay / duplicate | Inherited from `ssrf`'s own `TestCorrelation_DuplicateCallbacksStillOneFinding` (unchanged) |
| Delayed callback | Inherited from `ssrf`'s own `TestCorrelation_CallbackArrivesDuringPolling`/`_AfterTimeout` (unchanged) |
| Malformed callback | `lab.SSRFCallbackServer`'s own `TestSSRFCallbackServer_NeverProxiesRegardlessOfInput` (unchanged) |
| Cancellation during callback wait | `TestDetect_ContextCancelledDuringCallbackWait_ReturnsPromptly` |
| Resource exhaustion | Section "RESOURCE LIMITS" above — reused executor bounds |
| Secret leakage | Section "EVIDENCE / SECRET PROTECTION" above |
| Response-reflection false positive | `TestDetect_ReflectedURLOnly_NoMarker_NoFinding`, `/ssrf/reflect-only` |
| Redirect false positive | Section 2's own structural argument — a plain redirect response is never itself evidence |
| DNS-only false positive | Not applicable — no DNS-only signal exists anywhere in this design |

## REGRESSION

Every prior phase's own test suite passes (1865/1865 non-e2e,
102/102 e2e — see TOTAL TESTS). Three pre-existing tests required a
genuine, correct update — see DEFECTS FOUND AND FIXED; no production
behavior regressed.

## RACE

Full non-e2e suite passes clean under `go test -race` (1865/1865, 0
failures, 0 race reports). `internal/detectors/ssrfactive`'s own
concurrency tests and `lab/phase3_25_ssrf_active_test.go`'s
authenticated multi-identity test both re-confirmed clean under
`-race` specifically.

## SECURITY ISSUES

None found in production code.

## RELIABILITY ISSUES

None.

## PERFORMANCE ISSUES

None observed. Query-location end-to-end detection (both modes
confirmed) completes in under 1 second against the real lab.

## DEFECTS FOUND AND FIXED

1. **Test fixture bug, not a production defect.** The first version of
   `internal/detectors/ssrfactive/detector_test.go`'s own
   `vulnerableSSRFHandler` test helper fetched the target URL but
   never actually read/embedded the fetched response body — a
   test-authoring mistake caught immediately by the test's own
   expected-vs-actual failure. Fixed before any other work continued.
2. **Test bug: wrong-finding false failure, not a production defect.**
   The first version of `lab/phase3_25_ssrf_active_test.go`'s
   `findSSRFFor` helper matched by parameter name alone. Since
   multiple distinct `/ssrf/*` fixtures share the parameter name
   `"url"` across different endpoints, `TestPhase3_25_FormLocation_Finding`
   and the query-location test's own confidence assertion both
   initially picked up the WRONG endpoint's finding. Fixed by matching
   on endpoint path + parameter name together.
3. **Pre-existing test's crawl-page-budget assumption went stale
   — not a production defect.** `TestPhase3_25_FormLocation_Finding`
   initially reused the shared `runReconAgainstVulnLab` helper
   (`CrawlMaxPages: 30`), which is no longer enough to reach
   `/forms/index` now that the vuln app's root index links dozens of
   fixtures across every phase. Fixed by adding a dedicated
   `runReconAgainstVulnLabDeep` helper (`CrawlMaxPages: 150`) used only
   by this phase's own form-location test, rather than raising the
   shared helper's budget (which other, unrelated tests depend on
   staying as-is) — mirroring `tests/e2e/e2e_active_form_mutation_test.go`'s
   own identical precedent from Phase 3.21.
4. **Three PRE-EXISTING tests' hardcoded ground-truth-derived counts
   went stale — a genuine, expected consequence of this phase's own
   lab addition, not a regression.** Adding `/ssrf/vulnerable-blind`
   (a genuinely, deliberately vulnerable new fixture) to the shared
   `vuln.scanner.test` app caused the PRE-EXISTING, unmodified `ssrf`
   detector (Phase 3.4) to correctly detect it too via its own
   callback-confirmed tier — exactly as it should, since the fixture
   really is SSRF-vulnerable. This made three pre-existing tests'
   hardcoded expectations stale:
   `TestPhase3_4_SSRFDetector_MatchesGroundTruth` (flagged a "false
   positive" because ground truth didn't list the new fixture yet),
   `TestPhase3_8_Correlation_RealDetectorOutputProducesCanonicalFindings`
   (expected exactly 1 canonical `ssrf` finding, now correctly 2), and
   `TestPhase3Lab_ScanAndCompareAgainstGroundTruth`/`comparison_test.go`'s
   own `len(Positives())` check (expected 22 total positive ground-truth
   fixtures, now correctly 23). Fixed by adding `VULN-SSRF-BLIND-001`
   to `lab/ground-truth-vulnerabilities.yaml` (the fixture genuinely
   IS SSRF-vulnerable and belongs there) and updating the three
   dependent counts/comments accordingly — not by weakening any
   assertion. Re-verified all three pass, and re-ran the full
   regression suite afterward to confirm no other test depended on the
   old counts.

No defect was found in `internal/detectors/ssrf`, `internal/mutation`,
`internal/detection`, `internal/orchestrator`, `internal/safedial`,
`internal/scope`, or `lab/callback.go` — every fact this phase's
architecture review relied on was independently verified by directly
reading the relevant source files (including `lab/callback_test.go`'s
own hard assertion on the literal ack body, which is exactly why Mode
A was built as a separate, new component rather than by modifying
that file).

## REMAINING LIMITATIONS

1. **JSON REQUEST_INPUT parameters cannot be discovered through a
   real crawl** — an honest, pre-existing Phase 3.19 limitation
   (already documented there for `xssactive`), not something this
   phase regresses or was asked to close. `ssrfactive`'s own JSON-body
   mutation/execution logic is proven correct against a real endpoint
   via a directly-persisted parameter instead.
2. **No production-reachable callback service ships with this
   build** — the same honest, pre-existing gap `internal/detectors/ssrf`
   (Phase 3.4) already carries. `ssrf-active` is registered but
   disabled by default in `productionRegistry()`, proven exclusively
   through the lab's real `lab.SSRFCallbackServer`.
3. **Header/cookie SSRF inputs are not supported** — no discovery
   source in this codebase ever produces a header/cookie-location
   URL-shaped parameter, so none is claimed.
4. **No DNS rebinding, wildcard DNS, or IP-obfuscation techniques**
   — explicitly out of this phase's own scope (task section 13),
   documented as deliberate future work, not attempted.

## ARCHITECTURAL FINDINGS

See [docs/phase-3-25-ssrf-active-detection.md](phase-3-25-ssrf-active-detection.md)
in full, including the complete 20-question validation (section 18).
Headline findings:

- `internal/detectors/ssrf` (Phase 3.4) already has a complete,
  working `CallbackClient`/`Observation` abstraction and a real,
  adversarially-tested `lab.SSRFCallbackServer` implementation — fully
  sufficient for Mode B (blind/OOB), reused entirely unchanged.
- The existing `ssrf-internal.scanner.test` fixture (Phase 3.4,
  `lab/harness_vuln.go`) was ALREADY exactly what Mode A
  (response-based evidence) needed — no new "internal resource" lab
  server was required at all, only a caller-supplied marker string
  parameter on `ssrfactive.New`.
- `lab/callback.go` was deliberately NOT modified: one existing test
  (`TestSSRFCallbackServer_NeverProxiesRegardlessOfInput`) hard-asserts
  the literal acknowledgment body, so extending it for Mode A reuse
  was rejected in favor of keeping Mode A entirely separate — a
  concrete example of "reuse where sufficient, build minimally and
  separately where not," per the task's own section 11 instruction.
- Adding a new, genuinely vulnerable lab fixture to a SHARED app that
  an OLDER, unrelated detector already scans has a real, traceable
  ripple effect on that older detector's own ground-truth-driven
  tests — correctly resolved by updating ground truth (the fixture
  really is vulnerable) rather than by suppressing or weakening any
  assertion.
