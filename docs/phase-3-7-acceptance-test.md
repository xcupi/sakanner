# Phase 3.7 Acceptance Test: Command Injection Detector

Scope: `internal/detectors/cmdinjection` (the detector and its
self-generated correlation-token mechanism), the 7 new Phase 3 Test Lab
query-parameter command injection fixtures
(`lab/harness_vuln.go`'s `registerCommandInjectionAPI`), its
registration in `cmd/scanner/detectors.go`'s `productionRegistry()`
(enabled, unlike ssrf/idor/traversal -- see below), and the integration
tests proving it works end to end through the unmodified Phase 3.1
detection engine. See
[docs/phase-3-7-command-injection.md](phase-3-7-command-injection.md)
for the full architecture writeup this test verifies against.

`scanner detectors list` now shows all six real detectors:

```
ID                 STATUS    CATEGORY               NAME
xss-reflected      enabled   injection              Reflected XSS Detector
sqli               enabled   injection              SQL Injection Detector
command-injection  enabled   injection              Command Injection Detector
ssrf               disabled  ssrf                   SSRF Detector
idor               disabled  broken_access_control  IDOR / BOLA Detector
path-traversal     disabled  broken_access_control  Path Traversal Detector
```

`command-injection` is registered **enabled** by default, alongside
`xss-reflected`/`sqli` -- a deliberate departure from the
ssrf/idor/traversal pattern. Those three are disabled because each
requires operator-supplied production infrastructure this build does
not ship; `command-injection`'s correlation mechanism (a fresh,
unpredictable UUID token generated per probe) needs no external
configuration at all (`cmdinjection.New()` takes no arguments), so
there is nothing missing to justify disabling it. See "Why this
detector needs no external configuration" in
[docs/phase-3-7-command-injection.md](phase-3-7-command-injection.md).

## What was built

- `internal/detectors/cmdinjection/detector.go`: `Detector`
  implementing `detection.Detector` (Phase 3.1, unmodified) --
  `Metadata`, `Eligible` (command-like parameter-name heuristic),
  `Detect` (legitimate-access reference + up to 3 correlation-token
  probes, stopping at first confirmation), finding construction.
- `internal/detectors/cmdinjection/variants.go`: `commandVariants` --
  the fixed, 3-entry probe-variant generator (pipe raw, semicolon
  percent-encoded, double-ampersand percent-encoded), plus the shared
  `labCommand`/`markerPrefix` constants.
- `internal/detectors/cmdinjection/normalize.go`: `looksAllowed`.
- `lab/harness_vuln.go`: `registerCommandInjectionAPI` -- 7 new
  handlers (`/api/ping/vulnerable`, `/safe`, `/sanitized`, `/by-id`,
  `/reflect`, `/generic`, `/static-marker`) sharing a fake, lab-only
  command grammar (`cmdInjectionPattern`, pure Go regexp, never a real
  shell), plus 6 new crawlable links in the lab's index page. This is
  the FIRST command-injection fixture in the Phase 3 Test Lab -- no
  prior phase built one.
- `lab/ground-truth-vulnerabilities.yaml`: 8 new findings
  (`VULN-CMDI-API-001` positive, 7 negatives) -- positives 21->22,
  negatives 38->45.
- `lab/comparison_test.go`, `lab/phase3_lab_test.go`:
  updated fixture-count assertions (22 positives / 45 negatives).
- `cmd/scanner/detectors.go`: `productionRegistry()` now registers
  `cmdinjection.New()`, ENABLED (not disabled like ssrf/idor/traversal).
- Tests: 43 unit/adversarial top-level tests (47 including subtests) in
  `internal/detectors/cmdinjection`, 3 integration tests (10 including
  subtests) in `lab/phase3_7_cmdinjection_test.go`.

## Ground-truth comparison (integration, against the real lab)

`TestPhase3_7_CmdInjectionDetector_MatchesGroundTruth` runs real recon
(`orchestration.Pipeline`, crawling enabled) against the real
`vuln.scanner.test` lab, runs the real `command-injection` detector
through the real `detection.Engine`, and compares persisted findings
against every `command_injection`-typed ground-truth fixture:

| Fixture | Expected | Actual | Result |
|---|---|---|---|
| VULN-CMDI-API-001 (`/api/ping/vulnerable`) | FINDING | FINDING | true_positive |
| VULN-CMDI-API-NEG-001 (`/api/ping/safe`, allowlist) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-CMDI-API-VALIDATION-NEG-001 (`/api/ping/safe`, invalid input) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-CMDI-API-SANITIZED-NEG-001 (`/api/ping/sanitized`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-CMDI-API-BYID-NEG-001 (`/api/ping/by-id`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-CMDI-API-REFLECT-NEG-001 (`/api/ping/reflect`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-CMDI-API-GENERIC-NEG-001 (`/api/ping/generic`) | NO FINDING | NO FINDING | (correctly absent) |
| VULN-CMDI-API-STATICMARKER-NEG-001 (`/api/ping/static-marker`) | NO FINDING | NO FINDING | (correctly absent) |

```
True Positives:  1
False Positives: 0
False Negatives: 0
Duplicates:      0
```

The engine ran the detector against **all 142 targets** the recon
crawl produced from the whole lab (every vulnerability class's
fixtures, not just command injection's own), across 13 eligible
(detector, target) pairs, issuing 50 requests total -- passing on the
**first attempt** against the real lab (both bugs described below were
caught entirely by unit testing, before any lab integration ran).
`TestPhase3_7_CmdInjectionDetector_NegativeFixturesProduceNoFinding`
additionally checks each of the 7 negative fixtures individually
(table-driven, one subtest per fixture ID mapped to its exact value),
all passing.

## Issues found and fixed during this phase

Two genuine bugs were caught by this phase's own unit-test suite,
before any lab integration testing ran -- exactly the discipline the
project's established practice is designed to produce.

### 1. A malformed `fmt.Sprintf` directive silently dropped the token

The pipe variant's template was originally written as
`"|" + labCommand + "%20%s"`. `fmt.Sprintf` parses `%20` as a
width-modified format verb (width `20`, verb `%`), not literal text --
consuming the `%s` I intended for token substitution and leaving the
token as an unused "extra" argument. `TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests`'s
exact request-count assertion caught this immediately:

```
Executor.RequestCount() = 30, want exactly 20 (10 candidates x 2 requests each)
```

(the detector needed 3 requests per candidate instead of 2, because the
first, broken variant never matched anything). Root cause: a single
missing `%` -- every OTHER variant already correctly used `%%20` (a
literal `%` in Go's format string produces `%20` in the output);
the pipe variant's template was the one place this was omitted.
Confirmed with a focused reproduction
(`fmt.Sprintf("|sakanner_lab_echo%20%s", "TOKEN")` produces
`"|sakanner_lab_echo%s%!(EXTRA string=TOKEN)"`, not
`"|sakanner_lab_echo%20TOKEN"`). Fixed by escaping to `"%%20%s"`, matching
the other two variants; `TestCommandVariants_EachProducesTheLabCommandAndToken`
(added specifically to catch a stray `%!` fmt-error marker in any
future variant) now guards against a regression of this exact class.

### 2. A raw, unescaped `;` is silently split by Go's own query parser

During variant design, an initial attempt sent the semicolon separator
completely raw (matching the task's own conceptual `; command`
example). A direct reproduction against a real `net/http` server
proved this never works as intended:

```
try "host=;sakanner_lab_echo%20TOKEN1" -> RawQuery="host=;sakanner_lab_echo%20TOKEN1"  host=""
```

Go's `url.ParseQuery` treats a raw `;` as an alternate parameter
delimiter, splitting `host=` (now empty) from a second, keyless
parameter -- the intended value is discarded before the target
application ever sees it, regardless of whether the target itself
would have been vulnerable. This is a real, general transport
constraint (not specific to sakanner's lab), so the fix was to
percent-encode `;` (and, for the same reason, `&&`, since `&` is the
standard delimiter) in the actual variant set, while `|` -- confirmed
directly to survive raw -- is sent unescaped. See
[docs/phase-3-7-command-injection.md](phase-3-7-command-injection.md)
"Controlled probes" for the full before/after proof this was based on,
not assumed.

### 3. A naive static-source safety check flagged its own doc comment

`TestSourceNeverInvokesLocalShellOrExec`'s first draft did a plain
substring search for `"os/exec"` across the package's `.go` files --
which immediately flagged `detector.go`'s own package doc comment
(which explicitly states, in prose, that the package "never imports
`os/exec`"). Fixed by switching to `go/parser`, checking actual parsed
import declarations rather than raw text -- a more correct and more
robust check besides, since it cannot be defeated by the string
appearing anywhere else in the file (a log message, a different
comment) either.

None of these three issues reached the lab-integration stage; all were
caught and fixed by unit-level testing first, consistent with this
project's established discipline.

## Revert-and-verify: false-negative and false-positive directions

Per the task's "do not weaken tests to achieve PASS" instruction, both
directions were verified against the working detector.

1. **False-negative direction**: the exact-token confirmation check was
   temporarily short-circuited to never match
   (`if false && bytes.Contains(...)`). Re-running
   `TestPhase3_7_CmdInjectionDetector_MatchesGroundTruth` failed exactly
   as expected:
   ```
   0 findings created
   VULN-CMDI-API-001 | FINDING | NO FINDING | false_negative
   TruePositives = 0, want 1
   FalseNegatives = 1, want 0
   ```
2. **False-positive direction**: the check was first weakened to a bare
   `markerPrefix` (with colon) substring match -- this did **not**
   produce a false positive (the static-marker fixture deliberately
   omits the colon, a defense-in-depth design choice this correctly
   exposed). Weakening it further to a bare `"COMMAND_INJECTION_MARKER"`
   substring match (no colon, no token at all) then failed exactly as
   expected:
   ```
   2 findings created
   VULN-CMDI-API-001 | FINDING | FINDING | true_positive
   (unexpected) (actual: /api/ping/static-marker) | NO FINDING | FINDING | false_positive
   FalsePositives = 1, want 0
   ```
   Confirming the exact-token requirement is genuinely load-bearing
   against precisely the false-positive class `/api/ping/static-marker`
   exists to test (section 4.7 / section 12's "marker exists in static
   content").

Both defects were reverted; `go build ./...`, the full
`internal/detectors/cmdinjection` package suite, and
`go test ./lab/... -race -run TestPhase3_7 -v` were all re-run
and confirmed clean after restoration.

## Acceptance quality gate

| Requirement | Status |
|---|---|
| Positive command injection fixture detected | PASS (1/1, TruePositives = TotalExpected) |
| Zero false positives on negative fixtures | PASS (across all 142 real recon targets) |
| Zero duplicate findings | PASS (Phase 3.1's dedup, reused unmodified) |
| Execution proof required, never HTTP 200/reflection/status alone | PASS (see below) |
| Cross-scan / stale / duplicate marker never confirms | PASS (adversarial tests, see below) |
| Scope enforcement passes | PASS |
| Scanner shell isolation passes | PASS (see below -- static + behavioral proof) |
| Cancellation (including mid-baseline) passes | PASS |
| Timeout handling passes | PASS |
| Response-size limit passes | PASS (oversized-response test) |
| Exact-token confirmation guard proven load-bearing | PASS (found + fixed during this phase, then confirmed via revert-and-verify) |
| No critical security issues | PASS (see Security review below) |

## Command execution proof (CRITICAL, per the task)

Task section 5 forbids treating HTTP 200, response-length change,
reflected payload, shell-character presence, error text alone, or
command-looking text as proof. This detector satisfies that
exhaustively:

- `TestDetect_ReflectionOnly_NoFinding` -- reflected payload alone,
  never sufficient.
- `TestDetect_GenericResponse_NoFinding` -- HTTP 200 alone, never
  sufficient.
- `TestDetect_StaticMarkerWithoutToken_NoFinding` -- command-looking/
  marker-looking text alone, never sufficient.
- `TestDetect_ErrorResponseAlone_NoFinding` -- generic command-related
  error text alone, never sufficient.
- Every confirmation requires `COMMAND_INJECTION_MARKER:<the exact,
  freshly generated token THIS probe produced>` -- section 11's
  correlation requirement, satisfied by construction (a UUID is
  practically impossible to collide with anything the detector didn't
  itself generate moments earlier).

No case was found where the detector reported a finding based on
anything short of this exact requirement.

## Output correlation / cross-scan and stale-marker safety

`TestAdversarial_MarkerFromAnotherScanNeverConfirms` (a fixture that
always echoes a fixed, unrelated token regardless of what was sent) and
`TestAdversarial_StaleMarkerFromEarlierProbeNeverConfirmsLaterProbe`
(a fixture that echoes back the FIRST token it ever saw, simulating a
stale/cached marker) both confirm the exact-token requirement rejects
correlation to anything other than the current probe's own,
independently-generated token. Since every probe generates its own
fresh `uuid.NewString()` token and the marker format never leaks
between requests in this detector's own state (there is none --
`Detector` holds no mutable fields), cross-scan and stale-marker
confusion is structurally impossible, not merely tested-for.

## Scanner shell isolation

`internal/detectors/cmdinjection` operates ENTIRELY over HTTP --
verified two independent ways:

- **Static**: `TestSourceNeverInvokesLocalShellOrExec` parses this
  package's own non-test source files with `go/parser` and asserts
  their actual, parsed import declarations never include `"os/exec"`
  or `"syscall"` -- a mechanically-enforced guarantee that survives
  future edits, and correctly distinguishes a real import from a
  string mentioned in prose (see "Issues found and fixed" #3 above).
- **Behavioral**: `TestDetect_MaliciousParameterValue_NeverInvokesLocalShell`
  runs `Detect` from a temporary, otherwise-empty working directory
  with discovered/injected values shaped like real local shell breakout
  attempts (`; touch ...`, `$(touch ...)`, backtick command
  substitution, `&& cat /etc/passwd`) and confirms the temp directory
  has exactly 0 entries afterward.
  `TestDetect_MaliciousConfiguredValueReachingVulnerableFixture_StillOnlyHTTP`
  repeats the check for a genuinely CONFIRMED finding, proving even
  successful detection never involves anything beyond an ordinary HTTP
  request/response.

No local shell invocation of any kind occurs anywhere in this
detector's code path.

## Scope enforcement

`TestDetect_OutOfScope_ReturnsErrorWithoutDialing` (unit) and
`TestPhase3_7_CmdInjectionDetector_ScopeEnforcementStaysActiveDuringDetection`
(integration -- a real scan job whose `ScopeSnapshot` authorizes only
`vuln.scanner.test`, tested against a manufactured `Target` pointing at
the Phase 2 lab's real `scanner.test` host) both confirm zero requests
reach an out-of-scope host. No scope bypass was found; per the task's
explicit instruction, one here would have been an automatic Phase 3.7
failure.

## Adversarial testing (section 30)

Performed only against synthetic `httptest` servers -- no external
targets, no real shells, no real files, no real credentials, no real
networks, per the task's explicit constraint.

| Scenario | Test | Result |
|---|---|---|
| Command separator variants (pipe/semicolon/double-ampersand) | `TestDetect_VulnerableCommandInjection_HighConfidenceFinding`, `TestCommandVariants_*` | correctly generated and confirmed |
| Encoded variants | `TestCommandVariants_EachProducesTheLabCommandAndToken` | correctly substituted, no fmt corruption |
| Reflection-only payloads | `TestDetect_ReflectionOnly_NoFinding` | correctly silent |
| Escaped characters | `TestAdversarial_EscapedCharactersRejected` | correctly rejected by allowlist |
| Rejected input | `TestDetect_SafeAllowlist_NoFinding`, `TestDetect_400Handling_NoFinding` | correctly silent |
| Parameterized command handling | `TestAdversarial_ParameterizedCommandHandling`, `TestDetect_ByIDLookup_NoFinding` | correctly silent |
| Static marker | `TestDetect_StaticMarkerWithoutToken_NoFinding` | correctly silent; guard proven load-bearing via revert-and-verify |
| Stale marker | `TestAdversarial_StaleMarkerFromEarlierProbeNeverConfirmsLaterProbe` | correctly isolated |
| Duplicate marker | (same mechanism as stale -- exact-token requirement) | correctly isolated |
| Marker from another scan | `TestAdversarial_MarkerFromAnotherScanNeverConfirms` | correctly isolated |
| Delayed marker | `TestAdversarial_DelayedMarker_StillObservedWithinTheSameRequest` | correctly observed synchronously |
| Timeout | `TestDetect_Timeout_ReturnsError` | correct error |
| Cancellation (mid-baseline specifically) | `TestDetect_CancellationDuringBaseline` | terminates correctly, no data race |
| Oversized response | `TestDetect_OversizedResponse_TruncatedNotUnbounded` | bounded read, no crash |
| Malformed (binary) response | `TestAdversarial_MalformedResponseBody_NoCrash` | no crash |
| Out-of-scope target | `TestDetect_OutOfScope_ReturnsErrorWithoutDialing`, `TestPhase3_7_CmdInjectionDetector_ScopeEnforcementStaysActiveDuringDetection` | zero requests |
| Scanner shell isolation | `TestSourceNeverInvokesLocalShellOrExec`, `TestDetect_MaliciousParameterValue_NeverInvokesLocalShell`, `TestDetect_MaliciousConfiguredValueReachingVulnerableFixture_StillOnlyHTTP` | zero local shell invocation, static + behavioral proof |
| Unusual status codes (204/301/429/503) | `TestAdversarial_UnusualStatusCodes_NoCrashNoFalsePositive` (4 subtests) | no crash, no false positive |

## Security review (section 31)

- **Command injection in the scanner itself**: impossible by
  construction -- see "Scanner shell isolation" above; this package
  imports neither `os/exec` nor `syscall`.
- **Shell invocation / arbitrary local command execution**: none
  anywhere in this package's code path.
- **Scope bypass**: none found.
- **Request amplification**: strictly bounded at 1 + 3 requests per
  candidate maximum, with early exit on confirmation; never scales
  with the number of other candidates or resources.
- **Response memory exhaustion**: `maxBodySample` (256KB) bounds every
  read via `io.LimitReader`; confirmed directly
  (`TestDetect_OversizedResponse_TruncatedNotUnbounded`).
- **Stale execution markers**: rejected by construction (exact-token
  matching) and confirmed adversarially
  (`TestAdversarial_StaleMarkerFromEarlierProbeNeverConfirmsLaterProbe`).
- **Cross-scan marker confusion**: impossible by construction (each
  probe generates its own fresh UUID; `Detector` holds no shared
  mutable state across calls) and confirmed adversarially
  (`TestAdversarial_MarkerFromAnotherScanNeverConfirms`).
- **Unsafe logging**: evidence never stores full response bodies, raw
  command output, environment variables, or system information -- only
  a bounded fragment around the detector's own constant marker+token.
- **Credential leakage**: nothing in this detector ever requests,
  stores, or transmits a credential of any kind.
- **Race conditions**: the full suite runs under `-race` throughout
  this phase, including the concurrency test
  (`TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests`, 10
  concurrent candidates) and the cancellation test (using
  `atomic.Int32`). Zero races detected.

No new security issue was introduced; the scanner does not become a
command execution mechanism.

## Regression

Full suite, `go test -race -count=1 -v ./...`, run after every change
in this phase (including both revert-and-verify exercises) and again
as the final check:

```
TOTAL TESTS: 817 (556 top-level + 261 subtests)
PASS:        817
FAIL:        0
```

All 25 tested packages report `ok` (`cmd/scanner` and several stub
packages have no tests, by design, same as every prior phase). `gofmt
-l .`, `go build ./...`, and `go vet ./...` are all clean.
`golangci-lint` is not installed on this machine (unchanged from every
prior phase) -- `go vet` is what's available and was run. The CLI
binary was rebuilt (`go build -o bin/scanner ./cmd/scanner`) and
`scanner detectors list` confirmed to show all six registered
detectors with the correct enabled/disabled state.

- **Phase 1 regression**: unchanged packages all pass, no file under
  any of them was touched in this phase.
- **Phase 2 regression**: unchanged, all pass.
- **Phase 3 Test Lab regression**: all original fixture pairs, scope-
  enforcement scenarios, and prior authentication coverage remain
  unchanged and passing; lab changes were purely additive (7 new
  handlers, 6 new crawlable links, 8 new ground-truth entries, updated
  fixture-count assertions from 21/38 to 22/45).
  `TestPhase3Lab_ScanAndCompareAgainstGroundTruth` correctly reports
  the updated 22 expected positives for a recon-only run.
- **Phase 3.1 regression**: `internal/detection` and
  `internal/detection/detectiontest` completely unchanged; all their
  unit and integration tests pass unchanged.
- **Phase 3.2 regression**: `internal/detectors/xssreflected`
  completely unchanged; all its tests pass unchanged.
- **Phase 3.3 regression**: `internal/detectors/sqli` completely
  unchanged; all its tests pass unchanged.
- **Phase 3.4 regression**: `internal/detectors/ssrf` completely
  unchanged; all its tests pass unchanged.
- **Phase 3.5 regression**: `internal/detectors/idor` completely
  unchanged; all its tests pass unchanged.
- **Phase 3.6 regression**: `internal/detectors/traversal` completely
  unchanged; all its tests pass unchanged -- confirming all six real
  detectors coexist in the registry without interfering with each
  other's results.

## Known limitations

Documented in full in
[docs/phase-3-7-command-injection.md](phase-3-7-command-injection.md)
"Limitations": GET query parameters only, parameter-name heuristic only
(no stronger recon evidence available yet), three fixed separator
representations only (no backticks/`$()`/newlines), no MEDIUM/LOW
confidence tier (task section 12's prohibition list is exhaustive), no
blind/time-based detection (output correlation only), single-request-
cycle correlation only (no out-of-band polling). None of these caused a
missed positive or an unresolved false positive against the Phase 3
Test Lab's fixtures.

## Final report

```
PHASE 3.7 COMMAND INJECTION DETECTOR
TOTAL TESTS: 817 (556 top-level + 261 subtests)
PASS: 817
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

TRUE POSITIVES: 1
FALSE POSITIVES: 0
FALSE NEGATIVES: 0
DUPLICATES: 0

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0

PHASE 1 REGRESSION: PASS
PHASE 2 REGRESSION: PASS
PHASE 3 LAB REGRESSION: PASS
PHASE 3.1 REGRESSION: PASS
PHASE 3.2 REGRESSION: PASS
PHASE 3.3 REGRESSION: PASS
PHASE 3.4 REGRESSION: PASS
PHASE 3.5 REGRESSION: PASS
PHASE 3.6 REGRESSION: PASS

PHASE 3.7 ADVERSARIAL: PASS

PHASE 3.7 VERDICT: PASS
```

Not proceeding to Phase 3.8, not implementing another detector, not
implementing reverse shells, arbitrary command execution, real-target
command execution, real system file/credential access, network
scanning, post-exploitation, persistence, or LLM runtime functionality,
per the task's explicit instruction to stop after this report.
