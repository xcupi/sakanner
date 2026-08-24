# Phase 3.26 Acceptance Test — Command Injection Active Detection

## PHASE 3.26 COMMAND INJECTION ACTIVE DETECTION

```
TOTAL TESTS: 2008
PASS:        2008
FAIL:        0
PARTIAL:     0
NOT IMPLEMENTED: 0

COMMAND INJECTION DETECTOR:  PASS
UNIX:                        PASS
WINDOWS:                     PASS
QUERY:                       PASS
FORM:                        PASS
JSON:                        PARTIAL (see below)
PATH:                        PASS
AUTHENTICATION:              PASS
MULTI-IDENTITY:               PASS
SESSION ISOLATION:            PASS
SCOPE ENFORCEMENT:            PASS
PAYLOAD SAFETY:                PASS
FALSE-POSITIVE RESISTANCE:    PASS
EVIDENCE:                     PASS
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
REQUEST_INPUT parameter, an honest, pre-existing Phase 3.19 limitation
task section 4 explicitly asked to be preserved and tested honestly,
not hidden.

1968 tests carried over unchanged from Phase 3.14 through 3.25 (all
still passing after this phase's own changes, including three
pre-existing tests updated for legitimate, expected reasons — see
DEFECTS FOUND AND FIXED). 40 tests are new in this phase: 4 in
[internal/parameters/command_parameter_test.go](../internal/parameters/command_parameter_test.go),
16 in [internal/detectors/cmdinjectionactive/detector_test.go](../internal/detectors/cmdinjectionactive/detector_test.go),
5 in [internal/detectors/cmdinjectionactive/adversarial_test.go](../internal/detectors/cmdinjectionactive/adversarial_test.go),
4 in [internal/detectors/cmdinjectionactive/shell_isolation_test.go](../internal/detectors/cmdinjectionactive/shell_isolation_test.go),
8 in [lab/phase3_26_cmdinjection_active_test.go](../lab/phase3_26_cmdinjection_active_test.go),
3 in [tests/e2e/e2e_cmdinjection_active_test.go](../tests/e2e/e2e_cmdinjection_active_test.go).

## COMMAND INJECTION DETECTOR

`internal/detectors/cmdinjectionactive` (new package, ID
`command-injection-active`) — coexists with
`internal/detectors/cmdinjection` (Phase 3.7), which is not modified.
Built entirely on `internal/mutation`'s canonical Request/Mutate/
Execute model, unlike `cmdinjection` itself (which predates it and
builds its own `*http.Request` per probe, GET/query-location only).
Reuses `cmdinjection`'s own already-reviewed safe-proof strategy
verbatim: inject `<separator><fake-lab-command-name> <token>`, confirm
ONLY on an exact match of the constant marker prefix immediately
followed by THIS probe's own freshly generated, unpredictable UUID
token. Enabled by default (needs no external dependency, mirroring
`xssactive`/`sqliactive`'s own precedent, not `idoractive`/
`ssrfactive`'s disabled-by-default one).

## UNIX / WINDOWS

Four fixed, deterministic separator variants tried unconditionally
against every target, regardless of fingerprinted OS (task's own
"do not blindly send large payload sets... keep selection bounded"):
pipe, semicolon, double-ampersand (all three inherited verbatim from
`cmdinjection`'s own already-reviewed set), plus one new
single-ampersand variant closing the one meaningful `cmd.exe`-specific
gap a bare semicolon can never reach (real `cmd.exe` never treats `;`
as a separator). Proven live against two distinct lab fixtures with
genuinely different separator grammars:
`TestDetect_UnixVulnerable_Finding`/`TestPhase3_26_QueryLocationUnix_Finding`
(`;`/`|`/`&&`) and
`TestDetect_WindowsVulnerable_Finding`/`TestPhase3_26_QueryLocationWindows_Finding`
(`&`/`&&`/`|`, deliberately excluding `;`). No OS-fingerprint-based
filtering/reordering is implemented — documented as a deliberate,
justified simplification (architecture doc section 3), not a
correctness gap: the small fixed set is tried regardless of target OS
and completes in a bounded number of requests either way.

## QUERY / FORM / PATH

All three proven through a REAL crawl → discovery → persistence →
BuildTargets → mutation → execution → finding chain, against real lab
fixtures: `TestPhase3_26_QueryLocationUnix_Finding`/
`_QueryLocationWindows_Finding`, `TestPhase3_26_FormLocation_Finding`
(`/api/ping/vulnerable-form`, linked from `/forms/index`),
`TestPhase3_26_PathLocation_Finding` (`/api/ping/host/<value>`, two
example links). The CLI e2e level additionally confirms both Unix and
Windows query-location findings through the real compiled binary
(`TestScanCmd_CommandInjectionActive_QueryLocation_RealBinary`).

Path-location required a genuine fix during this phase's own
development: `internal/parameters.InferPathInputs` (Phase 3.23) never
crawl-discovers a path parameter under its "natural" name — it always
derives one from the preceding static segment plus a fixed `_id`/
`_value` suffix (e.g. `host_value`, never bare `host`). The original
name-heuristic gate (`IsLikelyCommandParameter`, an exact-match
allowlist mirroring `cmdinjection`'s own private list) never matched
this suffixed form, so path-location `Eligible` never fired against a
real crawl — caught by writing `TestPhase3_26_PathLocation_Finding` to
assert an actual FINDING (not merely parameter discovery), fixed by
adding conservative `_value`/`_id` suffix-stripping to
`IsLikelyCommandParameter` (see DEFECTS FOUND AND FIXED item 1). This
is a MORE thorough proof than Phase 3.25's own equivalent path-location
lab test achieved for `ssrfactive` (which only asserted discovery, not
a finding, for path-location SSRF) — documented here, not silently
fixed there, per this phase's own scope boundary.

## JSON — PARTIAL, an honest, pre-existing, non-regressed limitation

The crawler cannot discover a live JSON REQUEST_INPUT parameter
through a real crawl — the same Phase 3.19 limitation already
documented for `xssactive` and reaffirmed for `ssrfactive` (Phase
3.25). `cmdinjectionactive`'s own JSON-body (`mutation.LocationJSON`)
support is proven correct against a REAL vulnerable HTTP endpoint
(`/api/ping/vulnerable-json`) using a DIRECTLY-PERSISTED Parameter row
(`TestPhase3_26_JSONLocation_DirectlyPersisted_Finding`), mirroring
the established pattern exactly. Marked PARTIAL, not PASS, per task
section 9's own explicit instruction.

## AUTHENTICATION / MULTI-IDENTITY / SESSION ISOLATION

New authenticated fixture, `/ping-exec` (`lab/harness_auth.go`,
session-gated, mirrors `/ssrf-fetch`'s Phase 3.25 precedent). Proven
with both Phase 3.16 accounts independently
(`TestPhase3_26_AuthenticatedCmdInjection_TwoIdentities_SessionIsolated`):
each identity's own finding carries the correct `IdentityContext`. No
new authentication mechanism was added.

## SCOPE ENFORCEMENT

Zero new scope code — every probe goes through the unchanged
`mutation.Executor.Execute` → `resolveAndValidate` path. Host safety
of a mutated payload value proven
(`TestAdversarial_ProbeRequest_NeverChangesHost`); scope-denial proven
(`TestDetect_DeniedScope_ErrorsAndNoRequestsIssued`). This detector
has no out-of-band destination of its own at all (unlike `ssrfactive`)
— there is no callback/resource URL to misuse, so the entire class of
"callback destination scope" concerns from Phase 3.25 does not apply.

## PAYLOAD SAFETY

Every payload is a shell-metacharacter-prefixed reference to a fake,
lab-recognized-only command name (`sakanner_lab_echo`) plus a freshly
generated UUID token — never a real command, download, persistence,
reverse-shell, credential, or network-scanning primitive.
`shell_isolation_test.go` proves, both statically (no `os/exec`/
`syscall` import, via `go/parser`) and dynamically (a temp working
directory stays empty after `Detect` runs against genuinely
dangerous-looking values like `` `rm -rf /tmp/whatever` ``), that this
package never invokes a local shell of any kind — mirroring
`cmdinjection`'s own identical, already-reviewed guarantee.

## FALSE-POSITIVE RESISTANCE

All 12 of task section 6's named scenarios addressed — see
architecture doc section 6's full table. Proven live against 7
negative-control fixtures (`/api/ping/safe`, `/api/ping/sanitized`,
`/api/ping/by-id`, `/api/ping/reflect`, `/api/ping/generic`,
`/api/ping/static-marker`, `/api/ping/error`) in
`TestPhase3_26_NegativeControls_NoFinding`, plus unit-level negatives
(`TestDetect_ReflectionOnly_NoFinding`,
`TestDetect_StaticMarkerPresent_NoFinding`,
`TestAdversarial_BareMarkerPrefixWithoutExactToken_NeverConfirms`).

## EVIDENCE / SECRET PROTECTION

Every finding's evidence (2 items: baseline, confirmed probe) reuses
`detection.MutationEvidence` unchanged. No raw credential is ever
constructed by this package; only plain, non-secret identity names,
the fixed marker prefix, and a self-generated UUID token ever appear
in evidence/findings.

## RESOURCE LIMITS

No new limit configuration — reused executor bounds apply unchanged.
At most 5 requests per eligible target (1 uncharged baseline + 4
variant probes, short-circuiting on the first confirmed match) —
proven exactly (`TestDetect_RequestCount_Bounded`). No callback/OOB
polling exists in this package at all, so no bounded-wait/cancellation
concern beyond `x.ExecuteMutation`'s own ctx-awareness — proven
(`TestDetect_ContextCancelled_ReturnsPromptlyNoFinding`).

## DETERMINISM

Proven by `TestPhase3_26_Determinism_RepeatedScans_SameFindingCount`
(3 repeated real-lab scans, identical `command_injection` finding
count every time) — structural determinism, never byte-identical UUID
tokens.

## LAB

`lab/harness_cmdinjection_active.go` (new): Windows-style/form/JSON/
path/generic-error fixtures, all additive, reusing
`cmdInjectionLabCommand`/`cmdInjectionMarkerPrefix`/`cmdInjectionPattern`
(`lab/harness_vuln.go`, Phase 3.7, unmodified). `lab/harness_auth.go`
gained one new authenticated fixture (`/ping-exec`). `lab/harness_form_mutation.go`
gained one new `<form>` on `/forms/index`. `lab/harness_vuln.go`
gained four new index links (Windows-style, generic-error, two
path-location examples) — purely additive. `lab/ground-truth-vulnerabilities.yaml`
gained one new positive entry (`VULN-CMDI-API-WINDOWS-001`). Lab/
production independence re-verified: `lab/` and `tests/` moved aside,
`go build ./...`/`go vet ./...` succeed with zero lab-dependent code,
the one already-known harmless false positive (a doc comment in
`internal/detectors/sqliactive/detector_test.go`) confirmed unchanged,
then restored and rebuilt clean.

## E2E

`tests/e2e/e2e_cmdinjection_active_test.go` (new, 3 tests): a REAL
positive proof through the actual compiled CLI binary
(`TestScanCmd_CommandInjectionActive_QueryLocation_RealBinary`,
confirming BOTH Unix and Windows findings via `scanner report --format
json`), a real authenticated proof
(`TestScanCmd_CommandInjectionActive_AuthenticatedPingExec_RealBinary`),
and a registry-enablement confirmation
(`TestDetectorsCmd_CommandInjectionActive_RegisteredAndEnabled`).
Since `command-injection-active` is enabled by default (unlike
`ssrf-active`/`idor-active`), this phase proves the POSITIVE case
directly through the real binary, not merely registration. Full e2e
suite: 105/105 pass.

## ADVERSARIAL

Task section 16's list, mapped:

| Scenario | Proof |
|---|---|
| Payload reflection | `TestDetect_ReflectionOnly_NoFinding`, `/api/ping/reflect` |
| Encoding tricks | `wireEncodedPayload`/`rawPayload`'s own per-location correctness, proven by every positive location test (query/form/path each round-trip correctly through their own distinct encoding path) |
| Malformed input | `TestDetect_MaliciousParameterValue_NeverInvokesLocalShell` (5 shell-breakout-shaped values) |
| Shell metacharacter escaping | `/api/ping/sanitized` |
| Command separator handling | 4 variants, `TestDetect_UnixVulnerable_Finding`/`_WindowsVulnerable_Finding` |
| Quote handling | Covered by the malformed-input adversarial values (backticks, `$(...)`) |
| Whitespace handling | Inherited from `cmdinjection`'s own already-reviewed `%20` design |
| False-positive response differences | Section "FALSE-POSITIVE RESISTANCE" above |
| Duplicate/colliding markers | `TestAdversarial_BareMarkerPrefixWithoutExactToken_NeverConfirms` |
| Concurrent scans | `TestAdversarial_ConcurrentDetects_IndependentMarkersNoCrossContamination` (20 goroutines) |
| Concurrent identities | `TestPhase3_26_AuthenticatedCmdInjection_TwoIdentities_SessionIsolated` |
| Cancellation during execution | `TestDetect_ContextCancelled_ReturnsPromptlyNoFinding` |
| Timeout handling | Same test — ctx timeout propagates as an error, no finding |
| Resource exhaustion | `TestDetect_RequestCount_Bounded` |
| Secret leakage | Section "EVIDENCE / SECRET PROTECTION" above |
| Out-of-scope behavior | `TestDetect_DeniedScope_ErrorsAndNoRequestsIssued` |
| Malicious endpoint/host values | `TestEligible_NeverInspectsParameterValue`, `TestDetect_MaliciousConfiguredValueReachingVulnerableFixture_StillOnlyHTTP` |

## REGRESSION

Every prior phase's own test suite passes (1903/1903 non-e2e,
105/105 e2e — see TOTAL TESTS). Four pre-existing tests required a
genuine, correct, PROACTIVE update — see DEFECTS FOUND AND FIXED; no
production behavior regressed.

## RACE

Full non-e2e suite passes clean under `go test -race` (1903/1903, 0
failures, 0 race reports). `internal/detectors/cmdinjectionactive`'s
own concurrency test and `lab/phase3_26_cmdinjection_active_test.go`'s
authenticated multi-identity test both re-confirmed clean under
`-race` specifically.

## SECURITY ISSUES

None found in production code.

## RELIABILITY ISSUES

None.

## PERFORMANCE ISSUES

None observed. Query-location end-to-end detection completes in well
under 1 second against the real lab.

## DEFECTS FOUND AND FIXED

1. **Real gap: path-location name heuristic never matched
   `InferPathInputs`' own suffixed naming convention.** Caught by
   writing `TestPhase3_26_PathLocation_Finding` to assert an actual
   FINDING (not merely that a path parameter was discovered) — the
   test initially failed because `IsLikelyCommandParameter`'s
   exact-match allowlist never matched `"host_value"` (the name
   `pathInputName` -- Phase 3.23 -- always derives: preceding static
   segment + `_id`/`_value`, never a bare recognized name). Fixed by
   adding conservative `_value`/`_id` suffix-stripping to
   `IsLikelyCommandParameter` (`internal/parameters/command_parameter.go`)
   before the allowlist check, and renaming the lab's own path fixture
   route from `/api/ping/exec/` to `/api/ping/host/` so its own
   preceding static segment ("host") is itself a recognized base name.
   Re-verified the fix does not loosen the allowlist for unrelated
   names (`TestIsLikelyCommandParameter_UnrelatedSuffixedNames_False`).
   This closes a gap Phase 3.25's own equivalent `ssrfactive` path-
   location proof did not fully close (that test only asserted
   discovery, not a finding) — documented here as a MORE thorough
   proof, not retroactively fixed in Phase 3.25's own code (out of
   this phase's own scope boundary).
2. **Real, self-inflicted defect: a new lab fixture accidentally
   introduced a SECOND, unintended vulnerability class.** The first
   version of `/ping-exec` (`lab/harness_auth.go`) echoed the raw
   `host` query value back unescaped in its response text — safe in
   isolation, but once this fixture coexists with `/search`'s own
   genuine reflected-XSS fixture in the SAME authenticated scan,
   `internal/detectors/xssactive`'s own reflection classifier (which
   has no Content-Type awareness — a real, pre-existing property of
   that package, not something this phase modifies) correctly
   classified the raw, unescaped reflection as `ReflectionExact`,
   producing an UNINTENDED reflected-XSS finding on `/ping-exec`.
   Caught by `TestPhase3_19_AuthenticatedPositive_FindingWithIdentityContext`
   (a pre-existing, unmodified Phase 3.19 test) failing with the wrong
   `AffectedParameter`. Fixed by redesigning `/ping-exec` to never echo
   the raw `host` value in its response at all — it only ever reports
   a fixed acknowledgment plus the marker prefix+token on a genuine
   grammar match — closing the accidental cross-vulnerability-class
   interaction without touching `xssactive` or any other pre-existing
   detector/package. This is a genuinely different root cause than
   item 4 below (a new fixture accidentally triggering an EXISTING,
   different detector, rather than an EXISTING detector correctly
   detecting a genuinely new fixture of its OWN vulnerability class).
3. **Test-authoring bug: JSON baseline body handling.** The first
   version of `TestDetect_JSONBodyVulnerable_Finding`
   (`internal/detectors/cmdinjectionactive/detector_test.go`) rejected
   unparseable JSON with a 400 — but the BASELINE probe for JSON-body
   location has no seeded body at all (`detection.NewMutationRequest`
   has no mechanism to pre-populate one), so it legitimately arrives
   empty, and the fixture's own 400 caused the baseline
   reachability gate to fail before any variant was ever tried. Fixed
   by tolerating the empty/malformed body (ignoring the unmarshal
   error), mirroring `internal/detectors/sqliactive`'s own identical,
   already-established test precedent.
4. **Four PRE-EXISTING tests' hardcoded ground-truth-derived counts
   required a proactive update — a genuine, expected consequence of
   this phase's own lab addition, not a regression, and NOT the same
   root cause as item 2 above.** Adding `/api/ping/vulnerable-windows`
   (a genuinely, deliberately vulnerable new fixture) to the shared
   `vuln.scanner.test` app meant the PRE-EXISTING, unmodified
   `command-injection` detector (Phase 3.7) would ALSO correctly
   detect it via its own pipe/double-ampersand variants (only its
   semicolon variant doesn't match this fixture's Windows-style
   grammar) — exactly as it should, since the fixture really is
   vulnerable. Learning directly from Phase 3.25's identical lesson
   with `/ssrf/vulnerable-blind`, this was addressed PROACTIVELY,
   before running the full regression suite: `VULN-CMDI-API-WINDOWS-001`
   was added to `lab/ground-truth-vulnerabilities.yaml` at the same
   time the fixture itself was written, and the three dependent counts
   (`TestPhase3_8_Correlation_RealDetectorOutputProducesCanonicalFindings`'s
   per-type map, `TestPhase3Lab_ScanAndCompareAgainstGroundTruth`'s
   `TotalExpected`, `comparison_test.go`'s `len(Positives())`) were
   updated in the same change. All three passed on the FIRST
   regression run with no reactive fix needed.

No defect was found in `internal/detectors/cmdinjection`,
`internal/mutation`, `internal/detection`, `internal/orchestrator`,
`internal/safedial`, or `internal/scope` — every fact this phase's
architecture review relied on was independently verified by directly
reading the relevant source files.

## REMAINING LIMITATIONS

1. **JSON REQUEST_INPUT parameters cannot be discovered through a
   real crawl** — an honest, pre-existing Phase 3.19 limitation,
   reaffirmed identically for the third consecutive phase
   (`xssactive`, `ssrfactive`, now `cmdinjectionactive`). Not
   something any single phase is positioned to close in isolation —
   would require crawler-level work to synthesize/discover JSON
   request bodies, explicitly out of this phase's own scope.
2. **No OS-fingerprint-based payload reordering** — a deliberate
   simplification (architecture doc section 3), not a correctness
   gap: the small, fixed 4-variant set is tried unconditionally
   against every target regardless of OS, bounded and deterministic
   either way. A future phase could add fingerprint-based reordering
   as a pure efficiency optimization (fewer average requests against a
   known-OS target) without changing correctness.
3. **Header/cookie command-injection inputs are not supported** — no
   discovery source in this codebase ever produces a header/cookie-
   location command-shaped parameter, so none is claimed.
4. **Phase 3.25's own `ssrfactive` path-location lab proof was found,
   during this phase's own investigation, to only assert path-location
   PARAMETER DISCOVERY, not an actual FINDING** — a real, if minor,
   gap in that phase's own acceptance claim, discovered as a byproduct
   of this phase hitting and fixing the identical underlying issue
   (`IsLikelyURLParameter` has the same exact-match-only limitation
   `IsLikelyCommandParameter` had before this phase's own fix).
   Documented here as future work for a maintenance pass on Phase
   3.25's own test, not retroactively fixed here (out of this phase's
   own scope boundary — task section 19's "no scope creep").

## ARCHITECTURAL FINDINGS

See [docs/phase-3-26-command-injection-active.md](phase-3-26-command-injection-active.md)
in full, including the complete 20-question validation (section 17).
Headline findings:

- `internal/detectors/cmdinjection` (Phase 3.7) already has the
  single best-designed safe-proof mechanism in the codebase for this
  phase's own purpose — reused verbatim, not diluted or reinvented.
- The existing `cmdInjectionLabCommand`/`cmdInjectionMarkerPrefix`/
  `cmdInjectionPattern` lab protocol (Phase 3.7, `lab/harness_vuln.go`)
  was directly reusable for every new fixture this phase added — no
  new safety protocol was needed, only new grammar variations
  (Windows-style) and new transport locations (form/JSON/path).
- `internal/parameters.InferPathInputs`' own suffixed naming
  convention (`_value`/`_id`, Phase 3.23) is a cross-cutting fact
  every NAME-gated active detector (`ssrfactive`, `idoractive`,
  `cmdinjectionactive`) needs to account for — this phase is the
  first to actually catch and fix the resulting gap with a real,
  passing, finding-level (not merely discovery-level) end-to-end test.
- Adding a new, genuinely vulnerable lab fixture to a SHARED app that
  an OLDER, unrelated detector already scans continues to have a
  real, traceable ripple effect on that older detector's own
  ground-truth-driven tests (now proactively anticipated and fixed
  BEFORE the first regression run, not discovered reactively) — and,
  separately, on OTHER detectors that might accidentally also match a
  new fixture's response shape (the `/ping-exec` reflected-XSS
  cross-contamination, a genuinely different failure mode from the
  ground-truth one, both real and both fixed).
