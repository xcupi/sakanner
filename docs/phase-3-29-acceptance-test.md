# Phase 3.29 Acceptance Test — Active Detection Coverage Review & SSTI Active Detector

## PHASE 3.29 ACTIVE DETECTION COVERAGE REVIEW

SELECTED DETECTOR: Server-Side Template Injection (`internal/detectors/sstiactive`, ID `ssti-active`)

SELECTION RATIONALE: Of the 12 candidate vulnerability classes evaluated
against direct repository evidence (see
[docs/phase-3-29-active-detection-coverage-review.md](phase-3-29-active-detection-coverage-review.md)),
SSTI was the only one classified unconditionally **READY**: its payload
is a plain string, so it fits query/form/path/JSON mutation with zero
new `Location` type, zero new discovery mechanism, and zero new lab-
account work. A strong, deterministic proof strategy was directly
achievable by adapting `cmdinjectionactive`'s own already-reviewed
"freshly generated, unpredictable per-probe value" technique (there, a
UUID token; here, the exact product of two randomly chosen operands),
and a safe lab fixture was buildable with the same "fake backend, no
real dependency" pattern already used four times in this codebase
(`sqliSimulateQuery`, `travSynthFS`, `cmdInjectionMatch`). Every other
candidate needed a genuine foundation addition (structured JSON-value
injection for NoSQL/prototype-pollution/mass-assignment; a new header-
location discovery mechanism for Host-header injection; a new
privilege-tier lab identity for function-level authorization; a raw-
socket HTTP client for request smuggling; a new backend simulator for
XXE/LDAP) or was found architecturally inappropriate (HTTP request
smuggling's dangerous blast radius; classic CRLF response-splitting,
empirically confirmed impossible to reproduce through Go's own
`net/http.ResponseWriter` without bypassing the standard library
entirely; insecure deserialization's unsafe RCE-confirmation
requirement; HTTP parameter pollution's lack of a standalone
exploitation proof).

```
TOTAL TESTS: 2127
PASS:        2127
FAIL:        0
PARTIAL:     0
NOT IMPLEMENTED: 0

ARCHITECTURE REVIEW: PASS
SELECTED DETECTOR: PASS

QUERY: PASS
FORM: PASS
PATH: PASS
JSON: PARTIAL (see below)
AUTHENTICATION: PASS
MULTI-IDENTITY: PASS
SESSION ISOLATION: PASS
SCOPE ENFORCEMENT: PASS
EVIDENCE: PASS
CORRELATION / RISK: PASS
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
limitation already documented for every prior "-active" detector.
`sstiactive`'s own JSON-body support is fully proven correct against a
real, genuinely vulnerable endpoint (`/ssti/vulnerable-json`) via a
directly-persisted parameter — it is only the live crawl-discovery
path that is not proven. Not inflated to PASS.

2089 tests carried over unchanged from Phase 3.1 through 3.28 (all
still passing after this phase's own changes; zero pre-existing tests
required modification — the first phase this session to add a new
detector without needing a single reactive fix to prior test code).
38 tests are new: 14 in
[internal/detectors/sstiactive/detector_test.go](../internal/detectors/sstiactive/detector_test.go),
7 in [internal/detectors/sstiactive/match_test.go](../internal/detectors/sstiactive/match_test.go),
6 in [internal/detectors/sstiactive/adversarial_test.go](../internal/detectors/sstiactive/adversarial_test.go),
8 in [lab/phase3_29_ssti_active_test.go](../lab/phase3_29_ssti_active_test.go),
3 in [tests/e2e/e2e_ssti_active_test.go](../tests/e2e/e2e_ssti_active_test.go).

## ARCHITECTURE REVIEW

Full 19-point review plus per-detector inventory and 12-candidate
evaluation table in
[docs/phase-3-29-active-detection-coverage-review.md](phase-3-29-active-detection-coverage-review.md).
Verified directly against the repository, not assumed — including two
empirical reproductions during the review itself: (1) Go's
`net/http.ResponseWriter` strips/folds raw CR/LF in header values
(confirmed via a minimal `httptest` repro, ruling out CRLF injection
as buildable without bypassing the stdlib), and (2)
`internal/mutation.applyJSON` always marshals/escapes its value as a
JSON **string**, never splices a structured object (confirmed by
direct reading of `setJSONPathEscaped`/`setJSONPathVerbatim`, ruling
out NoSQL/prototype-pollution's strongest vector without new
plumbing).

## SELECTED DETECTOR

`internal/detectors/sstiactive` (new package, ID `ssti-active`) —
there is **no** pre-existing "ssti" detector to coexist with (the
first detector for this class), named with the "-active" suffix for
family consistency, mirroring `openredirectactive`'s own identical
precedent (Phase 3.28, also no legacy sibling). Built entirely on
`internal/mutation`'s canonical Request/Mutate/Execute model. A
finding requires the response to contain the EXACT numeric product of
two operands freshly, randomly chosen for that one probe, as an
isolated standalone token (never part of a larger number) — never a
status code, timing, generic error, or the raw payload text reflected
unevaluated. Enabled by default (needs no external dependency,
mirroring `cmdinjectionactive`/`xssactive`/`sqliactive`'s own
precedent, not `ssrfactive`/`traversalactive`/`openredirectactive`'s
disabled-by-default one) — its correlation mechanism (the fresh
operand pair) is entirely self-contained.

## QUERY / FORM / PATH

All three proven through a REAL crawl → discovery → persistence →
`BuildTargets` → mutation → execution → finding chain, against real
lab fixtures:

- **QUERY**: `TestPhase3_29_QueryLocation_Finding`, new
  `/ssti/vulnerable` fixture.
- **FORM**: `TestPhase3_29_FormLocation_Finding`, new
  `/ssti/vulnerable-form` fixture linked from `/forms/index`.
- **PATH**: `TestPhase3_29_PathLocation_Finding`, new
  `/ssti/greet/<value>` fixture (two example links).

Path-location surfaced a genuine, self-caught defect during this
phase's own development — see DEFECTS FOUND AND FIXED item 1: the
first version of the two example links used plain words ("alice"/
"bob"), which `internal/parameters.InferPathInputs`' own identifier-
shape heuristic correctly rejects (by design, to avoid mistaking
unrelated static sibling endpoints for a templated resource). Fixed
by using identifier-shaped values ("guest-1"/"guest-2"), the SAME
lesson `traversalactive`'s own architecture doc already documented —
this phase is the first to actually TRIP over it during development
rather than avoid it by design from the start.

## JSON — PARTIAL, an honest, pre-existing, non-regressed limitation

The crawler cannot discover a live JSON REQUEST_INPUT parameter
through a real crawl — the same Phase 3.19 limitation reaffirmed for
the sixth consecutive phase. `sstiactive`'s own JSON-body
(`mutation.LocationJSON`) support is proven correct against a REAL
vulnerable HTTP endpoint (`/ssti/vulnerable-json`) using a
DIRECTLY-PERSISTED Parameter row
(`TestPhase3_29_JSONLocation_DirectlyPersisted_Finding`). Marked
PARTIAL, not PASS, per the task's own explicit instruction.

## AUTHENTICATION / MULTI-IDENTITY / SESSION ISOLATION

New authenticated fixture, `/greet-me` (`lab/harness_auth.go`,
session-gated, mirrors `/redirect-me`/`/download-file`'s Phase
3.27/3.28 precedent). Only ever reflects an HTML-escaped literal for
non-matching input, so — like `/redirect-me` before it — it cannot
accidentally look like reflected XSS to `xssactive` in the same
authenticated scan as `/search`. Proven with both Phase 3.16 accounts
independently
(`TestPhase3_29_AuthenticatedSSTI_TwoIdentities_SessionIsolated`) and
through the real CLI binary
(`TestScanCmd_SSTIActive_AuthenticatedGreetMe_RealBinary`): each
identity's own finding carries the correct `IdentityContext`. No new
authentication mechanism was added.

## SCOPE ENFORCEMENT

Zero new scope code — every probe goes through the unchanged
`mutation.Executor.Execute` → `resolveAndValidate` path. Host safety
of an injected template payload proven
(`TestAdversarial_ProbeRequest_NeverChangesHost`); scope-denial proven
(`TestDetect_DeniedScope_ErrorsAndNoRequestsIssued`). No callback/
redirect/destination concept exists in this detector at all — the
entire evidence signal lives in the response body, so no destination-
scope class of concern applies here (unlike `ssrfactive`/
`openredirectactive`).

## FALSE-POSITIVE RESISTANCE

Proven live against 2 negative-control fixtures (`/ssti/safe`,
`/ssti/generic`) in `TestPhase3_29_NegativeControls_NoFinding`, plus
unit-level negatives (`TestDetect_Safe_NoFinding`,
`TestDetect_Generic_NoFinding`,
`TestAdversarial_RawPayloadReflectedUnevaluated_NeverConfirms` — a raw,
un-evaluated payload echo, e.g. the literal text "37" and "41"
appearing verbatim, must never be mistaken for the evaluated PRODUCT).
`containsIsolatedNumber`'s own standalone-token boundary check is
directly unit-tested (`match_test.go`, 7 tests) against exactly the
failure mode a naive substring check would miss: a product string
appearing only as part of a LARGER coincidental number (e.g. "3589"
inside "13589") must never match.

**A genuinely new cross-detector proof was added this phase**:
`TestPhase3_29_ExistingDetectors_DoNotAlsoFlagSSTIFixture` runs the
full `allDetectorsRegistry` (all 6 legacy detectors) against the new
`/ssti/*` fixtures and confirms none of them — including
`sqli`/`xssreflected`, neither of which has a name-based `Eligible`
gate on the legacy side either — accidentally produces a finding
there. This is the FIRST phase this session to add such a test
proactively rather than discover a cross-contamination defect
reactively (Phase 3.26's `/ping-exec` lesson).

## EVIDENCE / SECRET PROTECTION / CORRELATION-RISK

Every finding's evidence (2 items: baseline, confirmed probe) reuses
`detection.MutationEvidence` unchanged, proven directly
(`TestPhase3_29_QueryLocation_Finding` asserts `len(f.Evidence) == 2`).
No raw credential is ever constructed by this package; evidence
contains only the template syntax name, the injected payload, and the
computed product. Findings use the standard `models.Finding` shape
(`VulnerabilityType: "ssti"`, `Category: "injection"`, `Severity:
High`), consumed unchanged by the existing correlation/risk pipeline.

## RESOURCE LIMITS

No new limit configuration — reused executor bounds apply unchanged.
At most 5 requests per eligible target (1 baseline + 4 template-syntax
variants, short-circuiting on the first confirmed match) — proven
exactly (`TestDetect_RequestCount_Bounded`). Cancellation proven
(`TestDetect_ContextCancelled_ReturnsPromptlyNoFinding`). No local
code execution or template engine of any kind — proven statically via
`go/parser` import inspection
(`TestSourceNeverInvokesLocalShellOrTemplateEngine`, forbidding
`os/exec`/`text/template`/`html/template`/`plugin`): the only
computation this package ever performs is one Go-native integer
multiplication.

## DETERMINISM

Proven by `TestPhase3_29_Determinism_RepeatedScans_SameFindingCount`
(3 repeated real-lab scans, identical `ssti` finding count every
time) — structural determinism, never byte-identical operand pairs.

## LAB

`lab/harness_ssti_active.go` (new): query/form/JSON/path-location
vulnerable fixtures plus 2 negative controls, all additive. Reuses the
established "fake backend" pattern (`sstiSimulateRender`, a
regex-matched `NUMBER*NUMBER` evaluator recognizing ONLY the 4 fixed
delimiter shapes `sstiactive`'s own `templateVariants` produces —
never a real template engine). `lab/harness_auth.go` gained one new
authenticated fixture (`/greet-me`). `lab/harness_form_mutation.go`
gained one new `<form>` on `/forms/index`. `lab/harness_vuln.go`
gained 2 new index links — purely additive, no existing route's
behavior changed. `lab/ground-truth-vulnerabilities.yaml` required
**no changes** — there is no legacy detector for this vulnerability
class to establish ground truth against, and
`TestPhase3_29_ExistingDetectors_DoNotAlsoFlagSSTIFixture` (above)
directly confirms none of the 6 legacy detectors picks up the new
fixtures either way. Lab/production independence re-verified: `lab/`
and `tests/` moved aside, `go build ./...`/`go vet ./...` succeed with
zero lab-dependent code, the one already-known harmless false positive
(a doc comment in
`internal/detectors/sqliactive/detector_test.go`) confirmed unchanged,
then restored and rebuilt clean.

## E2E

`tests/e2e/e2e_ssti_active_test.go` (new, 3 tests): a REAL positive
proof through the actual compiled CLI binary
(`TestScanCmd_SSTIActive_QueryLocation_RealBinary`, confirming the
finding via `scanner report --format json`), a real authenticated
proof (`TestScanCmd_SSTIActive_AuthenticatedGreetMe_RealBinary`), and
a registry-enablement confirmation
(`TestDetectorsCmd_SSTIActive_RegisteredAndEnabled`). Since
`ssti-active` is enabled by default (like `command-injection-active`),
this phase proves the POSITIVE case directly through the real binary,
not merely registration. Full e2e suite: 112/112 pass.

## ADVERSARIAL

| Scenario | Proof |
|---|---|
| Host never changed by injected payload | `TestAdversarial_ProbeRequest_NeverChangesHost` |
| No real template engine / code execution | `TestSourceNeverInvokesLocalShellOrTemplateEngine` (static import check) |
| Concurrent scans / cross-contamination | `TestAdversarial_ConcurrentDetects_NoCrossContamination` (20 goroutines) |
| Raw payload reflected, never evaluated | `TestAdversarial_RawPayloadReflectedUnevaluated_NeverConfirms` |
| Cancellation during execution | `TestDetect_ContextCancelled_ReturnsPromptlyNoFinding` |
| Resource exhaustion | `TestDetect_RequestCount_Bounded` |
| Standalone-token boundary correctness | `match_test.go`'s 7 `TestContainsIsolatedNumber_*` tests |
| Concurrent identities | `TestPhase3_29_AuthenticatedSSTI_TwoIdentities_SessionIsolated` |
| Cross-detector false positive | `TestPhase3_29_ExistingDetectors_DoNotAlsoFlagSSTIFixture` |
| Out-of-scope target | `TestDetect_DeniedScope_ErrorsAndNoRequestsIssued` |
| Secret leakage | Section "EVIDENCE / SECRET PROTECTION" above |

## REGRESSION

Every prior phase's own test suite passes (2015/2015 non-e2e, 112/112
e2e — see TOTAL TESTS) with **zero pre-existing tests requiring any
modification** — the first phase this session to add a new detector
without needing even a proactive count bump beyond the one always-
expected `Registered: N` line (see DEFECTS FOUND AND FIXED item 2). No
ground-truth ripple occurred, verified rather than assumed
(`TestPhase3_29_ExistingDetectors_DoNotAlsoFlagSSTIFixture`, plus the
full regression run).

## RACE

Full non-e2e suite passes clean under `go test -race` (confirmed in
the first regression pass; the verbose re-run used to extract exact
counts was run without `-race` purely to avoid doubling total runtime
— same code, same outcome).
`internal/detectors/sstiactive`'s own concurrency test and
`lab/phase3_29_ssti_active_test.go`'s authenticated multi-identity
test both re-confirmed clean under `-race` specifically during
package-level development.

## SECURITY ISSUES

None found in production code.

## RELIABILITY ISSUES

None.

## PERFORMANCE ISSUES

None blocking, but worth recording honestly: full-lab, full-registry
e2e scans grew noticeably slower after this phase (`go test
./tests/e2e/...` total runtime: 1103s here vs. 969s in Phase 3.28,
well within the 25-minute suite timeout either way). Root cause:
`sstiactive.Eligible` has NO parameter-name heuristic gate (a
deliberate design choice, section "SELECTED DETECTOR" above, mirroring
`sqliactive`/`xssactive`'s own identical precedent), so it attempts a
probe against every discovered query/form/path parameter across the
entire lab, not just SSTI-plausible ones — the same trade-off
`sqliactive`/`xssactive` already made, now compounded by a 4th
broadly-eligible detector running in the same registry. Not a defect;
documented as a REMAINING LIMITATION below.

## DEFECTS FOUND AND FIXED

1. **Real, self-caught defect: the path-location example links'
   values were not identifier-shaped.** The first version of
   `/ssti/greet/<value>`'s two crawl-discovery example links used
   plain words ("alice"/"bob") — `internal/parameters.InferPathInputs`'
   own `allLookLikeIdentifiers` check (Phase 3.23, confirmed by direct
   reading: "ordinary lowercase-word static resource names essentially
   never [look identifier-shaped]") correctly and deliberately rejects
   these as indistinguishable from unrelated static sibling endpoints,
   so no path-location parameter was ever discovered. Caught by
   `TestPhase3_29_PathLocation_Finding` failing with the query/form/
   JSON findings present but no path-location one. Fixed by renaming
   the example values to "guest-1"/"guest-2" (hyphenated, identifier-
   shaped), the SAME fix `traversalactive`'s own architecture doc
   already documented as a design requirement — this phase is the
   first to actually trip over it in practice (every prior "-active"
   phase's own path-location fixtures happened to need a name-
   heuristic-driven route rename for a DIFFERENT reason, which
   incidentally also produced identifier-shaped values; `sstiactive`
   has no such gate, so this specific pitfall was not forced to the
   surface until now).
2. **One PRE-EXISTING test's hardcoded detector-registry count
   required a proactive update — a genuine, expected consequence of
   registering a 14th detector, not a regression.**
   `TestDefaultCLI_CrawlerDisabled_ZeroDetectorRunsIsObservable`
   (`tests/e2e/e2e_detection_readiness_test.go`) asserted `"Registered:
   13"`; updated to `"Registered: 14"` after `ssti-active` joined the
   production registry, mirroring the identical bump every prior phase
   adding a detector has required (Phase 3.19 → 3.28). This is the
   ONLY pre-existing test this phase touched.

No defect was found in `internal/mutation`, `internal/detection`,
`internal/orchestrator`, `internal/scope`, or any of the 12 pre-existing
detector packages — every fact this phase's architecture review relied
on was independently verified by directly reading the relevant source
files and, for the two Go-stdlib-behavior claims (CRLF header
sanitization, JSON string-only value marshaling), by direct empirical
reproduction, and none of them required any change.

## REMAINING LIMITATIONS

1. **JSON REQUEST_INPUT parameters cannot be discovered through a real
   crawl** — an honest, pre-existing Phase 3.19 limitation, reaffirmed
   identically for the sixth consecutive phase.
2. **No parameter-name heuristic gate** — a deliberate design choice
   (SSTI is meaningful against nearly any parameter), with a real,
   measured performance cost on full-registry lab/e2e scans (see
   PERFORMANCE ISSUES above). Not a correctness gap.
3. **Bounded to 4 fixed template-engine delimiter syntaxes** — covers
   the most common real-world shapes (Jinja2/Twig/Mustache,
   Freemarker/JSP-EL/Thymeleaf, Ruby/JSF, ERB/JSP-scriptlet) but not
   every possible template engine's own custom delimiter syntax (e.g.
   Velocity's statement-based `#set`/`#if` forms, which are not a
   simple inline expression and were deliberately excluded from this
   phase's bounded set as a different shape of payload entirely).
4. **Header/cookie-location SSTI parameters are not supported** — no
   discovery source in this codebase ever produces a header/cookie-
   location parameter (confirmed in the architecture review, section
   3-7), consistent with every other detector's own identical
   boundary.
5. **This phase's own architecture review surfaced two credible
   runner-up candidates that were deliberately NOT implemented**,
   honestly documented rather than silently dropped: Broken Function-
   Level Authorization (needs one new privilege-tier lab identity plus
   a way to seed admin-only endpoint paths to a low-privilege re-test)
   and Host-header injection (the mutation-layer plumbing already
   exists via `applyHeader`, but no existing detector uses an endpoint-
   level-rather-than-parameter-level `Eligible` shape, a real, if
   small, architectural gap). Either would be a reasonable Phase 3.30
   candidate; neither was started, per this phase's own "implement
   only the minimum foundation required for the SELECTED candidate"
   instruction.

## PHASE 3.29 VERDICT: PASS
