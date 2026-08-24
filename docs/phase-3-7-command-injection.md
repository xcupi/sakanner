# Phase 3.7: Command Injection Detector

sakanner's sixth real vulnerability detector. Implements
`detection.Detector` (`internal/detection`, Phase 3.1) unchanged --
nothing in the framework was modified to build this; see
[docs/phase-3-1-detection-engine.md](phase-3-1-detection-engine.md)
"How to implement a new detector" for the contract this follows.

**OS command injection**: unsanitized input reaching shell command
construction, allowing arbitrary command execution on the target. This
detector proves execution occurred through a self-generated,
unpredictable per-probe correlation token -- never through status
codes, response length, reflected payloads, or generic error text
alone.

## Core security principle

The scanner must never execute arbitrary commands anywhere -- not on
the scanner host, not on production systems, not on any out-of-scope
target. Every probe this detector sends is an ordinary HTTP request;
target-controlled input (a discovered parameter value, a response
body) is treated strictly as data throughout, never as something to
interpret or execute locally. See "Scanner shell isolation" below for
how this is enforced and tested, not just asserted.

## What this detector does NOT do

Per the task's explicit scope boundary, none of the following are
implemented, attempted, or in any way exercised by this package:

- **Execute arbitrary commands** -- against the scanner's own host, a
  real target, or anywhere else. The only "command" concept in this
  entire codebase is a fixed, fake, lab-only string
  (`sakanner_lab_echo`) matched via Go regexp inside the test lab's own
  fixture code -- never a real shell invocation, anywhere.
- **Run reverse or bind shells** -- not implemented, not attempted; the
  probe payload's only effect (against a genuinely vulnerable target)
  is a single, harmless, synthetic string appearing in an HTTP
  response.
- **Access credentials, system files, or environment variables** -- the
  probe never asks for any of these, and the lab's simulated
  "execution" never reads or exposes any of them (see "Test lab
  architecture").
- **Perform post-exploitation, lateral movement, or persistence** --
  detection stops the moment evidence is gathered; no finding ever
  triggers a further, more invasive probe.
- **Execute malware or exfiltrate data** -- no capability exists in this
  package to do either.
- **Network scanning** -- this detector only ever issues requests to
  the one, already-scope-validated `Target` it was given.

## Architecture

```
internal/detectors/cmdinjection/
├── detector.go             Detector, Metadata, Eligible, Detect, finding construction
├── variants.go              commandVariants -- the small, deterministic probe-variant generator
└── normalize.go               looksAllowed

lab/harness_vuln.go   registerCommandInjectionAPI -- the query-parameter-
                             based /api/ping/* fixture family
```

## Why this detector needs no external configuration

Unlike [SSRF](phase-3-4-ssrf.md) (needs an out-of-band callback
service), [IDOR](phase-3-5-idor-bola.md) (needs operator-supplied
resource ownership), or [path traversal](phase-3-6-path-traversal.md)
(needs a known protected-resource marker), this detector's correlation
mechanism is entirely **self-contained**: it generates a fresh,
unpredictable UUID token for every single probe and injects it as an
argument to a fixed, safe, publicly-known synthetic command name
(`sakanner_lab_echo`). There is no sensitive, production-specific
knowledge an operator would ever need to supply -- the "convention"
both the detector and the lab agree on is exactly as safe and
non-secret as any other detector's hardcoded payload strings (`sqli`'s
boolean probes, `xssreflected`'s script marker). `cmdinjection.New()`
therefore takes **no arguments** and holds **no state**
(`type Detector struct{}`).

Because nothing is missing, `cmd/scanner/detectors.go`'s
`productionRegistry()` registers this detector **enabled** by default,
alongside `xssreflected` and `sqli` -- a deliberate departure from the
ssrf/idor/traversal "registered but disabled" pattern, since that
pattern exists specifically to signal missing operator infrastructure,
and there is none here to signal.

## Test lab architecture

Every handler in `lab/harness_vuln.go`'s
`registerCommandInjectionAPI` simulates "the application passed this
value to a shell command" using **pure Go regexp matching against a
fixed, deterministic, LAB-ONLY grammar** -- none of them ever call
`os/exec`, invoke a real shell, or touch a real system resource:

```go
const cmdInjectionLabCommand = "sakanner_lab_echo"       // never a real command
const cmdInjectionMarkerPrefix = "COMMAND_INJECTION_MARKER:"
var cmdInjectionPattern = regexp.MustCompile(`(?:;|\||&&)\s*sakanner_lab_echo\s+(\S+)`)
```

The vulnerable handler (`/api/ping/vulnerable`) checks whether the
`host` value matches this pattern; if it does, it appends
`COMMAND_INJECTION_MARKER:<the exact captured token>` to an otherwise
normal, synthetic "ping" response. `cmdInjectionLabCommand` is
deliberately **not** `echo` or any real shell builtin -- so nothing
about this fixture's grammar could ever be mistaken for, or
accidentally generalize to, real shell syntax against a real system.

Six negative fixtures, mirroring every prior phase's "one endpoint per
distinct false-positive shape" discipline:

| Endpoint | Behavior | Role |
|---|---|---|
| `/api/ping/vulnerable` | Naive grammar match, no containment | **Positive** |
| `/api/ping/safe` | Strict `^[a-zA-Z0-9.\-]+$` allowlist, rejects before any matching | Safe argument handling + input validation |
| `/api/ping/sanitized` | Strips `;`/`\|`/`&` from the DECODED value before matching | A different (still effective, against this detector's own probe set) strategy than the allowlist |
| `/api/ping/by-id` | `host` is only ever an opaque allowlist key (`"1"`, `"2"`), never concatenated into anything | Parameterized/safely-resolved access |
| `/api/ping/reflect` | Echoes the requested value; never attempts grammar matching | Reflection-only negative |
| `/api/ping/generic` | Fixed `{"status":"ok"}` regardless of input | Generic-200 negative |
| `/api/ping/static-marker` | Always includes the literal substring `COMMAND_INJECTION_MARKER` (no colon, no token) | Static-content negative |

## Candidate selection

```go
SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint}
SupportedMethods:     []string{http.MethodGet}
```

plus `Eligible(t)` requiring the parameter's **name** to match one of
the task's own fourteen examples: `host`, `hostname`, `ip`, `address`,
`domain`, `command`, `cmd`, `exec`, `executable`, `program`, `file`,
`path`, `target`, `query` (case-insensitive). `Eligible` inspects only
the parameter's NAME, never its value -- confirmed directly by
`TestEligible_NeverInspectsParameterValue` -- so a malicious value can
never influence candidate *selection*, only what gets sent as an
ordinary HTTP request once a candidate is already chosen by name.

**GET query parameters only**, the same documented limitation every
Phase 3.x detector carries (Phase 3.1's `detection.BuildTargets` only
extracts query strings). Per task section 14, POST/PUT/PATCH were
considered but not implemented -- extending `BuildTargets` to extract
form-body parameters would mean redesigning Phase 3.1's target-
selection model, against the project's "do not invent a separate
request engine" instruction.

## Baseline

A single **legitimate-access reference**: `t.URL`'s already-discovered
value, unchanged -- the same pattern `xssreflected`/`sqli`/`ssrf`/
`idor`/`traversal` all use for their own baselines. Not analyzable
(non-text/JSON/XML) -> `OutcomeSkipped`. Not allowed (2xx, non-empty)
-> `OutcomeNoFinding` -- nothing reachable to test further. This
reference is recorded for evidence (section 16's "BASELINE: normal
behavior") and doubles as a basic reachability gate; no separate
"not-found" reference is needed, since this detector's confirmation
signal (see "Execution verification") never depends on a body-diff
comparison the way `traversal`'s MEDIUM tier does.

## Controlled probes

`commandVariants()` returns a small, fixed, deterministic set of
exactly 3 -- matching task section 13's explicit "basic, a separator
variant, an encoded variant" and section 8's "small deterministic probe
set," never a payload dictionary:

1. **Pipe (raw)**: `|sakanner_lab_echo%20<token>`
2. **Semicolon (percent-encoded)**: `%3Bsakanner_lab_echo%20<token>`
3. **Double-ampersand (percent-encoded)**: `%26%26sakanner_lab_echo%20<token>`

### A real transport nuance, discovered and proven, not assumed

Every variant percent-encodes the space between the lab command name
and its token as `%20`. This is not a stylistic choice: a literal,
unescaped space is not valid inside an HTTP request line at all --
confirmed directly against a real `net/http` server during this
phase's own development (a raw-space request simply never reached the
handler). No representation here could ever send a literal space
regardless of injection intent, mirroring how a real attacker's browser
or HTTP client would also never transmit one.

The three separators are deliberately **not** treated uniformly. `|`
is sent completely raw; `;` and `&&` are percent-encoded. This is also
not a stylistic choice: Go's own `url.ParseQuery` treats a raw,
unescaped `;` as an **alternate parameter delimiter** (a long-standing
historical quirk of the `net/url` package, still present in this Go
version) -- confirmed directly:

```
try "host=;sakanner_lab_echo%20TOKEN1" -> RawQuery="host=;sakanner_lab_echo%20TOKEN1"  host=""
try "host=|sakanner_lab_echo%20TOKEN2" -> RawQuery="host=|sakanner_lab_echo%20TOKEN2"  host="|sakanner_lab_echo TOKEN2"
```

A raw `;` silently splits "host=" (empty) from a second, keyless
parameter, discarding the intended value entirely; `&` (the standard
delimiter) would be split identically if sent raw. Only
percent-encoding survives standard query-string transport for these
two separators. `requestURL` builds the request's `RawQuery` by hand
(never through `url.Values.Encode()`) specifically so an
already-percent-encoded representation is never re-escaped a second
time (which would turn `%3B` into `%253B` and silently defeat the
point of testing an encoded representation at all).

**A concrete bug this exact nuance caught during development**: an
early draft's pipe-variant template used a literal `%20` in its Go
source without escaping the `%` for `fmt.Sprintf` (`"%20%s"` instead of
`"%%20%s"`), so `fmt.Sprintf` consumed `%20` as an (invalid) width+verb
directive instead of producing literal text, silently dropping the
token substitution. `TestCommandVariants_EachProducesTheLabCommandAndToken`
(checking for a stray `%!` fmt-error marker in every generated variant)
and the concurrency test's exact request-count assertion both caught
this immediately, before any lab integration ran -- see
[docs/phase-3-7-acceptance-test.md](phase-3-7-acceptance-test.md)
"Issues found and fixed."

## Execution verification

A response is treated as **confirmed** if and only if it contains
`COMMAND_INJECTION_MARKER:<the EXACT token this specific probe
generated>` -- never a bare substring match on `COMMAND_INJECTION_MARKER`
alone, never a different probe's token, never a reflected copy of the
injected text itself (since the injected payload never contains the
literal words "COMMAND_INJECTION_MARKER" at all, a pure-reflection
endpoint can never accidentally produce a match). `Detect` stops at the
first confirmed variant -- no aggregation across multiple attempts is
needed the way `idor`/`traversal` require, since exactly one
confirmation is already airtight proof.

### Reflection vs. execution

`TestDetect_ReflectionOnly_NoFinding` proves this directly: an endpoint
that echoes the raw injected text verbatim (`/api/ping/reflect`) never
produces the transformed marker string, so it's naturally,
structurally distinguished from genuine execution without needing a
`stripPayload`-style fix (unlike `traversal`'s differential-comparison
design, this detector's evidence requirement makes the distinction
automatic by construction).

### Static content

`TestDetect_StaticMarkerWithoutToken_NoFinding` proves the exact-token
requirement defeats a fixture that always includes the bare substring
"COMMAND_INJECTION_MARKER" in unrelated static content
(`/api/ping/static-marker`) -- a naive substring-only check would
false-positive here; the exact prefix+token requirement does not. This
was directly confirmed via revert-and-verify (see the acceptance
report): weakening the check to a bare substring match immediately
produced a false positive against exactly this fixture.

### Error-based signals

Command-related error text (section 10: "shell syntax error", "command
not found", "invalid command", "execution error") is never, by itself,
sufficient evidence -- `TestDetect_ErrorResponseAlone_NoFinding`
confirms a fixture returning exactly this wording for every injection
attempt (with no marker) produces `OutcomeNoFinding`.

## Confidence and severity

| Signal | Severity | Confidence |
|---|---|---|
| `COMMAND_INJECTION_MARKER:<exact fresh token>` found verbatim in this probe's own response | critical | 0.95 |
| Anything else (reflected, generic, static, error text, denied) | -- | -- (`OutcomeNoFinding`) |

**No MEDIUM or LOW tier is fabricated**, a more rigorous version of the
same reasoning [IDOR](phase-3-5-idor-bola.md) applied when it omitted
a LOW tier. Task section 12's false-positive-prevention list is
exhaustive: reflected, stored, escaped, parameterized, rejected,
generic command-related text, marker in static content, cross-scan
marker, stale marker, and "execution cannot be confirmed" are *all*
explicitly named as cases that **must not** produce a finding. Every
candidate signal a weaker tier could plausibly be built from is already
claimed by one of these explicit prohibitions -- there is no remaining,
safely-reportable "weaker but still real" signal left to build a
MEDIUM tier from. Separately, the correlation mechanism itself is
airtight by construction: since the detector's own random UUID token
never appears anywhere except as its own injected payload, *any*
verbatim appearance of the full marker+token string in a probe's own
response -- 2xx or otherwise -- is unambiguous proof, with no
meaningful "confidence gradient" to express between "confirmed" and
"not confirmed." Severity reuses `pkg/models.Severity` unchanged,
matching the Phase 3 ground truth's `severity: critical` for
`VULN-CMDI-API-001`; `Metadata.DefaultSeverity` (`high`) is
deliberately lower than the confirmed tier's actual `critical`, per
task section 18's "do not automatically classify every command
injection as Critical" -- the METADATA default is a generic fallback,
never what a real confirmed finding reports.

## Evidence

Every finding's `Evidence` is one
`detection.NewRequestResponseEvidence`, structured to answer task
section 16's exact shape:

- **TARGET** / **PARAMETER** -- `t.Path`, `t.Parameter`, in
  `Observation`'s `target=`/`parameter=`.
- **BASELINE** -- implicit in `Detect`'s legitimate-access reference
  gate (recorded via the fact that a finding exists at all only after
  that reference succeeded); the confirmed probe's variant name is
  `Observation`'s `probe=`.
- **CONTROLLED PROBE** -- the variant name (e.g. "pipe (raw)"),
  `Observation`'s `probe=` and the full injected value in `Payload`.
- **EXPECTED** -- always `input_treated_as_data`
  (`Observation`'s `expected=`).
- **ACTUAL** -- always `controlled_command_execution_occurred`
  (`Observation`'s `actual=`).
- **EXECUTION PROOF** -- `Observation`'s `proof=`, the full
  `COMMAND_INJECTION_MARKER:<token>` string, plus a bounded (±80 byte)
  `ResponseFragment` centered on it.

No arbitrary command output, environment variable, or system
information is ever stored -- there is none to store, since the lab's
simulated "execution" only ever produces the fixed marker prefix plus
the detector's own token, never anything resembling real command
output.

## Finding

Uses `pkg/models.Finding` unchanged -- no new schema.
`VulnerabilityType` is `"command_injection"`; `Title`, `Severity`,
`Confidence`, `AffectedParameter`, `Description`, `Remediation`, and
`Evidence` are set by the detector; the engine's `normalizeFinding`
(Phase 3.1, unchanged) fills `ID`, `ScanID`, `DetectorID`, `Host`,
`Port`, `URL`, `Method`, `AffectedEndpoint`, `Source`, and timestamps.

## Deduplication

Reuses `internal/detection.Deduplicate` (Phase 3.1) unmodified. This
detector reports **at most one finding per (endpoint, parameter)
candidate** -- `Detect` returns immediately at the first confirmed
variant, so there is nothing to aggregate. Two separate `Detect` calls
against the identical candidate (e.g. rediscovered by a later crawl
pass) still produce logically identical findings, correctly collapsed
by Phase 3.1's existing dedup key
(`DetectorID + Host + Port + AffectedEndpoint + Method +
AffectedParameter + VulnerabilityType`) -- confirmed by
`TestDetect_IdenticalFindingsAcrossTwoRunsDeduplicate`.

## Scope enforcement

Every probe goes through `detection.Executor.Do` -- the same
scope-validated, rate-limited, timeout-bounded request path every
other detector uses; `probe`/`probeRaw` never build their own
`http.Client` or bypass scope in any way.
`TestDetect_OutOfScope_ReturnsErrorWithoutDialing` (unit) and
`TestPhase3_7_CmdInjectionDetector_ScopeEnforcementStaysActiveDuringDetection`
(integration -- a real scan job whose `ScopeSnapshot` authorizes only
`vuln.scanner.test`, tested against a manufactured `Target` pointing at
the Phase 2 lab's real `scanner.test` host) both confirm zero requests
reach an out-of-scope host. A scope bypass here would be an automatic
Phase 3.7 failure; none was found.

## Scanner shell isolation (CRITICAL, per the task)

This package's ENTIRE implementation operates over HTTP -- there is no
code path in it that constructs or runs a local shell command from any
input, trusted or otherwise. Verified two ways, not just asserted:

- **Static guarantee**: `TestSourceNeverInvokesLocalShellOrExec` parses
  this package's own non-test `.go` source files with `go/parser` and
  asserts their actual, parsed import declarations never include
  `"os/exec"` or `"syscall"` -- checked against real AST import nodes,
  not a naive substring search (a naive search would have false-
  positived on this very package's own doc comments, which *mention*
  `"os/exec"` in prose to explain that it's never imported -- caught
  and fixed during this phase's own development).
- **Behavioral guarantee**: `TestDetect_MaliciousParameterValue_NeverInvokesLocalShell`
  runs `Detect` from a temporary, otherwise-empty working directory
  with discovered parameter values shaped like real local shell
  breakout attempts (`; touch ...`, `$(touch ...)`, backtick
  substitution, `&& cat /etc/passwd`) and confirms the temp directory
  has exactly 0 entries afterward -- proof, not just an absence of an
  error, that nothing was created, read, or executed locally.
  `TestDetect_MaliciousConfiguredValueReachingVulnerableFixture_StillOnlyHTTP`
  repeats the same check for a *genuinely confirmed* finding, proving
  even successful detection never involves anything beyond building
  and sending an ordinary HTTP request and inspecting its response
  body.

Target-controlled input remains data passed to the target throughout;
this detector never interprets it as anything else.

## Request limits

- **Bounded per candidate**: 1 legitimate-access reference + up to 3
  variant probes, with an early exit as soon as one confirms. In the
  common (first-variant-confirms) case, 2 requests total.
- **No combinatorial explosion**: candidates are evaluated
  independently; nothing scales with the number of other candidates or
  resources on the target.
- **Timeout / concurrency / rate limiting**: inherited unchanged from
  the shared `detection.Executor`, identical to every other Phase 3.x
  detector.
- `TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests` runs 10
  candidates concurrently and asserts exactly `10 × 2 = 20` total
  target requests -- no request multiplication, confirmed under
  `-race`.

## Response limits

`maxBodySample` (256KB) bounds every read via `io.LimitReader`,
identical to every other Phase 3.x detector.
`TestDetect_OversizedResponse_TruncatedNotUnbounded` sends a response
4x larger than the cap and confirms the detector still completes
cleanly.

## Error handling and cancellation

- **400/403/404/429/500** -- none of these gate the exact-token check
  directly (a genuine match is airtight regardless of status code, see
  "Confidence"), but the legitimate-access reference DOES require 2xx,
  so a target that rejects its own originally-discovered value never
  proceeds to variant probing at all.
- **Malformed response body (binary/non-UTF8)** -- byte-level
  `bytes.Contains` operates without assuming valid UTF-8 structure;
  `TestAdversarial_MalformedResponseBody_NoCrash` confirms no panic.
- **Connection failure / timeout** -- `probe`/`probeRaw` propagate the
  `Executor.Do` error via `fmt.Errorf("cmdinjection: ... probe: %w", err)`;
  `Detect` returns that error rather than a Result.
- **Cancellation** -- checked implicitly at every `Executor.Do` call
  (legitimate-access reference, every variant probe);
  `TestDetect_ContextCancellation_ReturnsError` and
  `TestDetect_CancellationDuringBaseline` (using `atomic.Int32` to
  avoid a data race) confirm no further request is issued after
  cancellation.

## Limitations

- **GET query parameters only** -- see "Candidate selection."
- **Parameter-name heuristic only** -- Phase 2's recon has no
  parameter-value-shape classification, the same documented gap every
  Phase 3.x detector carries.
- **Three fixed separator representations only** -- `|` (raw), `;`
  (percent-encoded), `&&` (percent-encoded); other shell metacharacters
  (backticks, `$()`, newlines) are not tried, matching task section
  13's "do not create dozens of payloads."
- **No LOW/MEDIUM confidence tier** -- see "Confidence and severity"
  for the exhaustive-prohibition-list rationale.
- **No blind/time-based detection** -- this detector only ever proves
  execution via output correlation (the marker appearing in the HTTP
  response body); a target whose command injection has no output
  channel back into the response (fully blind, detectable only via
  timing) is out of reach. Time-based detection was considered and
  rejected: response-timing signals are inherently noisier and harder
  to bound deterministically than output correlation, and the task's
  "small deterministic probe set" instruction favors the simpler,
  airtight mechanism.
- **Single-request-cycle correlation only** -- like every out-of-band-
  free design in this project, there is no polling or delayed-callback
  mechanism (unlike `ssrf`'s bounded wait); "delayed" only ever means
  "the HTTP round trip took longer," never "arrives after the
  response" (see `TestAdversarial_DelayedMarker_StillObservedWithinTheSameRequest`).
