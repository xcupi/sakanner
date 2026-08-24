# Phase 3.26: Command Injection Active Detection

## 0. Scope discipline

This phase implements exactly one thing: an active, mutation-engine-
based OS command injection detector, across query/form/JSON/path
locations, requiring genuine execution-correlation proof (never a
response-difference/status-code/reflection heuristic). No SSTI, XXE,
deserialization, LDAP/XPath injection, template injection, RCE beyond
the safe proof mechanism, privilege escalation, credential theft,
persistence, reverse shells, data exfiltration, or internal network
scanning.

## 1. Architecture review

Traced with exact citations, not assumed.

### 1.1 The existing `internal/detectors/cmdinjection` (Phase 3.7) package

A complete, working, and ALREADY ENABLED-BY-DEFAULT detector exists.
`ID = "command-injection"` (`cmdinjection/detector.go:42`). Unlike
`ssrf`/`idor`/`traversal`, it needs no constructor-injected dependency
-- its correlation mechanism is a freshly generated, unpredictable
per-probe UUID token, entirely self-contained
(`cmdinjection/detector.go:74-79`) -- so `cmd/scanner/detectors.go`
registers it via a bare `cmdinjection.New()` and never disables it
(confirmed: `cmdinjection.ID` does not appear in
`buildProductionRegistry`'s disabled-IDs list).

**This is already the single best-designed safe-proof mechanism in
the whole codebase for this phase's own purpose** (task section 2):
inject `<separator><fake-lab-command-name> <token>`
(`cmdinjection/variants.go`), and confirm ONLY on an EXACT match of
`markerPrefix + token` (`cmdinjection/detector.go:133-134`) -- never a
bare substring, never a stale/cross-probe token, never a reflected
copy of the injected text. `shell_isolation_test.go` proves this
package never imports `os/exec` or invokes a local shell of any kind.

**Critically, like `ssrf` and the pre-Phase-3.24 `idor`, this package
does not import `internal/mutation` at all** -- `Eligible` restricts to
GET-only query-location targets (`cmdinjection/detector.go:97-103`),
and `probe`/`probeRaw`/`requestURL` build a private `*http.Request`
by hand, issued through the OLD `x.Do(ctx, t, req)` path
(`cmdinjection/detector.go:206-236`). This is the SAME architectural
gap `idor`→`idoractive` (Phase 3.24) and `ssrf`→`ssrfactive` (Phase
3.25) already closed for their own vulnerability classes -- the same
resolution applies here: a NEW, coexisting package built on the
canonical mutation engine, leaving `internal/detectors/cmdinjection`
completely untouched (its own tests, including
`shell_isolation_test.go`, remain valid and unmodified).

The old detector's own marker-correlation strategy is not a "weaker
fallback tier" the way `ssrf`'s response-diff/error-phrase tiers were
(Phase 3.25's own reason for being MORE conservative than `ssrf`) --
it is ALREADY the single, airtight, high-bar signal this phase's own
task section 1/2 demands. `cmdinjectionactive` therefore REUSES this
exact strategy (same marker prefix convention, same exact-match
requirement, same fresh-per-probe-token design), not a diluted or
alternate one.

### 1.2 The existing lab fixture (`lab/harness_vuln.go:930-1054`, unauthenticated,
`vuln.scanner.test`)

`cmdInjectionLabCommand = "sakanner_lab_echo"` (a deliberately fake
command name, never a real shell builtin) and
`cmdInjectionMarkerPrefix = "COMMAND_INJECTION_MARKER:"` are already
shared, safe, lab-only constants. `cmdInjectionPattern` is a pure Go
regexp (`(?:;|\||&&)\s*sakanner_lab_echo\s+(\S+)`) matched against the
DECODED query value -- no shell of any kind is ever invoked
(`registerCommandInjectionAPI`'s own doc comment, `harness_vuln.go:919-928`).
Seven existing routes: `/api/ping/vulnerable` (genuinely vulnerable,
Unix-style separators `;`/`|`/`&&`), `/api/ping/safe` (strict
allowlist), `/api/ping/sanitized` (metacharacter-stripping), `/api/ping/by-id`
(opaque key, no command construction), `/api/ping/reflect` (echo
only), `/api/ping/generic` (constant response), `/api/ping/static-marker`
(the bare marker substring present in unrelated static content, no
real token match possible) -- task section 6's false-positive list
items 1-3, 5, 8, 9, 11 are already covered live by these.

**Gaps this phase must fill in the lab** (task section 10): a
Windows-cmd.exe-style vulnerable fixture (a DIFFERENT separator
grammar -- real `cmd.exe` does not treat `;` as a separator at all,
unlike POSIX shells), form/JSON/path-location vulnerable fixtures, an
authenticated fixture.

### 1.3 The established "-active" detector pattern (Phase 3.19-3.25)

`cmdinjectionactive` follows the SAME shape `xssactive`/`sqliactive`/
`ssrfactive` already established: `Eligible` accepts query (GET only),
form/body/path (any method) -- mirroring `sqliactive.Eligible`'s exact
switch. Like `ssrfactive` and unlike `idoractive`, there is no
cross-identity mutation-safety concern here (only one identity/
session is ever involved), so the general "-active" convention
applies unmodified. Like `xssactive`/`sqliactive` (and unlike
`idoractive`/`ssrfactive`, which need an external dependency),
`cmdinjectionactive` needs NO constructor-injected dependency --
mirroring `cmdinjection.New()`'s own reasoning exactly -- so it is
registered ENABLED BY DEFAULT, not behind a flag or a nil-dependency
gate.

## 2. Core security requirement -- what counts as proof

Per task section 1's own explicit prohibition list, NONE of the
following, alone, is ever sufficient: status code, response-length
change, the payload appearing in the response, the literal words
"command"/"shell"/"bash"/"cmd" appearing anywhere, response timing,
or a generic error. `cmdinjectionactive` structurally cannot produce a
finding from any of these -- the ONLY code path to
`OutcomeFinding` requires `bytes.Contains(body, []byte(markerPrefix +
token))` where `token` is THIS SPECIFIC probe's own freshly generated
UUID (never reused, never predictable, never derived from anything an
attacker/observer could pre-compute) -- reusing the OLD detector's own
exact, already-reviewed logic, section 1.1.

## 3. Detection modes -- OS awareness

Per task section 3's own "the architecture should not assume the
target OS is known" and "do not blindly send large sets of Windows and
Unix payloads to every target, keep payload selection bounded and
deterministic": a single, small, FIXED set of 4 separator variants is
tried against every target, unconditionally, regardless of any
fingerprinted OS -- no `Target.Technologies`-based filtering or
reordering is implemented. This is a deliberate simplification,
justified as follows: correctness does not require OS detection at
all (a target's own shell either recognizes a given separator or it
doesn't; trying all 4 is safe, bounded, and short-circuits on the
first confirmed hit exactly like the old detector's own 3-variant loop
already does), and request volume stays small and deterministic (at
most 4 probes plus 1 baseline per eligible target) regardless of
whether OS-based reordering is added. OS-fingerprint-based REORDERING
(trying likely-correct variants first, to reduce AVERAGE request count
against a real target) is documented here as a reasonable future
optimization this phase deliberately does not build, per task
section 3's own explicit "if a reliable OS-neutral proof is not
possible, document the limitation rather than creating weak
detection" -- here a reliable OS-neutral proof IS possible (try the
small fixed set), so no weak detection was created; the omission is
purely an efficiency optimization, not a correctness gap.

The 4 variants (see section 5): 3 are the OLD detector's own,
already-reviewed set (`|` raw, `;` percent-encoded, `&&`
percent-encoded) -- all of which are valid POSIX-shell separators, and
`|`/`&&` are ALSO valid Windows `cmd.exe` separators. The 4th, new
variant adds a single `&` (percent-encoded) -- `cmd.exe`'s own
command-chaining operator, which `;` (a bare semicolon, never a
`cmd.exe` separator) cannot reach. This is why a Unix-only detector
design (`;`/`|`/`&&`) already accidentally covers MOST of Windows
`cmd.exe` too (`|`/`&&` both work there) -- the single `&` variant
closes the one meaningful gap.

## 4. Mutation locations

`Eligible` mirrors `sqliactive`/`ssrfactive`'s exact location switch
(section 1.3): query (GET only), form/body/path (any method). Query/
form/path are proven end to end through a REAL lab fixture + REAL
crawl + REAL detection run (section 10). JSON is proven correct
against a real endpoint via a DIRECTLY-PERSISTED parameter, honestly
marked PARTIAL for real-crawl discovery -- per task section 4's own
explicit instruction ("this is especially important because Phase
3.25 explicitly marked JSON as PARTIAL... preserve that limitation and
test it honestly"), the SAME pre-existing, honestly-documented Phase
3.19 gap (the crawler cannot discover a live JSON REQUEST_INPUT
parameter) applies identically here, unchanged and un-worsened by
this phase.

Header/cookie command-injection inputs are NOT claimed -- no
discovery/configuration source in this codebase ever produces a
`ParameterLocation` of `"header"`/`"cookie"` for a command-like value.

## 5. Payload safety

Deterministic, bounded, non-destructive: exactly 5 requests per
eligible target maximum (1 baseline + up to 4 variant probes,
short-circuiting on the first confirmed match) -- smaller than
`ssrfactive`'s own 3-per-target bound is not required here since
there is no separate Mode A/B split, just one correlation mechanism
tried across a small fixed variant list, mirroring the OLD detector's
own already-reviewed 3-variant loop, extended by exactly one variant
(section 3). Every payload is a shell-metacharacter-prefixed
reference to `cmdInjectionLabCommand` (a fake, lab-recognized-only
command name) plus a freshly generated UUID token -- never a real
command, never a download/persistence/reverse-shell/credential/
network-scanning primitive. No lab destination is ever a real,
arbitrary host or command.

## 6. False-positive resistance

Task section 6's 12-item list, mapped to how this design handles each:

| Case | How it's handled |
|---|---|
| 1. Reflected unchanged | Marker requires the lab's own simulated grammar match, not reflection -- proven live by `/api/ping/reflect` |
| 2. URL-decoded but never executed | Same -- `/api/ping/reflect` decodes and echoes, never grammar-matches |
| 3. Generic application error | An error response cannot contain the exact per-probe token -- structurally impossible to false-positive |
| 4. Behavior changes without execution | No code path treats "behavior changed" as evidence at all |
| 5. Shell-looking strings, never invokes a shell | Proven live by `/api/ping/static-marker` (the bare marker substring, never a real token match) |
| 6. Shell metacharacters sanitized | Proven live by `/api/ping/sanitized` |
| 7. Fixed command unrelated to input | Proven live by `/api/ping/by-id` (host is an opaque allowlist key) |
| 8. Value stored, never executed | Covered by the SAME reasoning as items 1-2; no store-only fixture is separately needed since the marker-match requirement already excludes it structurally |
| 9. Marker appears in output "accidentally" | Proven live by `/api/ping/static-marker` -- the exact ATTACK this fixture exists to defeat |
| 10. Concurrent scans, independent markers | Proven adversarially (section 16) -- each probe's own UUID token is generated fresh, never shared across concurrent `Detect` calls |
| 11. Same marker in unrelated response content | Same structural argument as item 9 -- the EXACT token, not the bare prefix, is required |
| 12. Timing changes without execution | No code path in this package ever measures or compares timing |

## 7. Authentication

Zero new authentication code. `cmdinjectionactive.Detect(ctx, t, x)`
receives `x *detection.Executor` the same way every detector does --
already bound to whichever session `orchestrator.buildDetectionExecutor`
attached for this scan. A new authenticated fixture is added to
`harness_auth.go`'s existing `authApp` (section 10.G), proving the
probe correctly carries the session's cookies. Multi-identity
isolation (section 10.H) reuses the SAME authenticated fixture with
Phase 3.16's existing two accounts -- no new identity/session
mechanism, mirroring `ssrfactive`'s own identical precedent (Phase
3.25).

## 8. Scope

Zero new scope code. Every probe goes through the identical
`x.ExecuteMutation` -> `mutation.Executor.Execute` ->
`resolveAndValidate` path every other active detector already uses.
The injected payload VALUE (a shell-metacharacter-prefixed string)
can never change the probe request's own dial target -- the request
is always addressed to `t.Host`/`t.IP`/`t.Port`, only the PARAMETER
value changes -- the identical, already-proven argument every prior
"-active" detector's own host-safety adversarial test makes, reused
here by the identical reasoning and re-proven with a dedicated test
(section 16). This detector never has an out-of-band destination of
its own (unlike `ssrfactive`) -- there is no callback/resource URL to
misuse at all, so the entire class of "callback destination scope"
concerns from Phase 3.25 does not apply here.

## 9. Evidence

`models.Finding`/`models.Evidence` reused unchanged, exactly like the
OLD detector's own finding-building code
(`detection.NewTypedRequestResponseEvidence`/
`detection.MutationEvidence`). Two evidence records per finding:
baseline (legitimate-access reference) and the confirmed probe
(request/response/marker-match observation) -- mirroring
`cmdinjection`'s own exact 2-item evidence shape. `Finding.IdentityContext`
is populated automatically by the engine's `normalizeFinding` from
`Target.IdentityContext` -- `cmdinjectionactive` never sets it
explicitly (only one identity is ever involved, unlike `idoractive`).
No raw credential is ever placed in evidence; only the marker
prefix/token (a safe, non-secret, self-generated UUID) and bounded
response fragments appear.

## 10. Lab

New file, `lab/harness_cmdinjection_active.go`, additive only --
`lab/harness_vuln.go`'s existing seven `/api/ping/*` routes are NOT
modified.

- **A. Vulnerable Unix-style (existing, reused)**: `/api/ping/vulnerable`.
- **B. Vulnerable Windows-style**: new `/api/ping/vulnerable-windows`,
  a DIFFERENT regexp (`(?:&{1,2}|\|)\s*sakanner_lab_echo\s+(\S+)` --
  recognizes `&`, `&&`, `|`, but explicitly NOT a bare `;`, modeling
  `cmd.exe`'s own real separator grammar) against the SAME safe
  `cmdInjectionLabCommand`/`cmdInjectionMarkerPrefix` protocol.
- **C. Safe/sanitized (existing, reused)**: `/api/ping/safe`,
  `/api/ping/sanitized`.
- **D. Reflection-only (existing, reused)**: `/api/ping/reflect`.
- **E. Fixed-command (existing, reused)**: `/api/ping/by-id`.
- **F. Generic-error negative control**: `/api/ping/generic` (existing,
  constant response) plus a NEW fixture returning a genuine error
  status for command-shaped input specifically, to directly exercise
  task section 6 item 3 against a non-2xx response.
- **G. Authenticated**: new `/api/ping-exec` on `auth.scanner.test`
  (`harness_auth.go`'s existing `authApp`), session-gated, mirroring
  `/ssrf-fetch`'s Phase 3.25 precedent exactly.
- **H. Multi-identity**: proven by running the SAME authenticated
  fixture under both Phase 3.16 accounts -- no new fixture needed.
- **New form/JSON/path fixtures**: `/api/ping/vulnerable-form` (POST
  form field `host`), `/api/ping/vulnerable-json` (POST JSON field
  `host`, directly-persisted-parameter proof only), `/api/ping/exec/{value}`
  (path segment) -- all reusing the SAME `cmdInjectionPattern`-style
  grammar match, factored into a small shared helper in the new file
  (not touching `harness_vuln.go`'s own existing, working handlers).

Ground truth (`lab/ground-truth-vulnerabilities.yaml`) gains a new
positive entry for `/api/ping/vulnerable-windows` -- task section 10's
own "ground truth must explicitly identify which fixtures are
vulnerable." This is REQUIRED, not optional: the pre-existing,
unmodified `cmdinjection` detector (query-GET-only) is ALSO eligible
against this new query-location fixture and its `|`/`&&` variants DO
match the Windows-style grammar too (only its `;` variant doesn't) --
exactly the same ripple effect Phase 3.25 discovered and fixed for
`/ssrf/vulnerable-blind`, addressed proactively here instead of
reactively.

## 11. Response comparison

`mutation.Compare` (Phase 3.17) is available but, per section 2's own
reasoning, is NOT used as an independent basis for a finding --
`cmdinjectionactive` has no code path that compares baseline/probe
response bodies for structural difference at all. The baseline probe
exists solely as a reachability/analyzability gate (mirroring the OLD
detector's own `isAnalyzable`/`looksAllowed` checks), never as a
differential signal.

## 12. Resource limits

No new limit configuration -- the SAME `MaxMutationsPerParameter`/
`MaxActiveRequestsPerScan`/`Concurrency`/rate-limiter bounds every
other active detector already respects apply unchanged. At most 5
requests per eligible target (section 5). No callback/OOB polling
exists in this package at all (unlike `ssrfactive`), so there is no
bounded-wait/cancellation concern beyond what `x.ExecuteMutation`'s
own ctx-awareness already provides uniformly to every detector.

## 13. Determinism

Target ordering: the SAME already-deterministic `BuildTargets` output
every detector consumes. Variant ordering: a fixed slice, never a map
iteration (mirroring the OLD detector's own `commandVariants()`
function shape exactly). Marker tokens are fresh UUIDs each run (not
byte-identical across repeated scans, mirroring `ssrfactive`'s own
identical, already-reviewed reasoning for why this does not break
determinism -- structural finding count/shape is what's guaranteed,
never a literal token value).

## 14. Multi-identity

Reuses Phase 3.16's existing identity architecture entirely unchanged
-- no second identity/session mechanism, no compare-identity concept
(unlike `idoractive`, this detector never compares two identities
against each other; each identity's own scan simply carries its own
session through to its own probes, exactly like `ssrfactive`'s own
Phase 3.25 precedent).

## 15. CLI

Zero new CLI surface. `cmdinjectionactive.New()` is registered into
the SAME `buildProductionRegistry` function `idoractive`/`ssrfactive`
already extended (`cmd/scanner/detectors.go`) -- enabled by default
alongside `command-injection` (mirroring `xssactive`/`sqliactive`'s
own precedent, not `idoractive`/`ssrfactive`'s disabled-by-default
one, since no external dependency is needed here -- section 1.3).

## 16. Adversarial testing

Explicit, real tests (not merely documented) for: payload reflection,
encoding tricks (percent-encoding round-trip through each location's
own mutation path), malformed input, shell-metacharacter handling per
separator, quote/whitespace handling (inherited from the OLD
detector's own already-reviewed variant design, section 3), duplicate/
colliding markers, concurrent scans with independent tokens,
concurrent identities, cancellation, resource bounds, secret
non-leakage, out-of-scope host rejection, and malicious parameter
values that must never change the probe's own dial target.

## 17. Architecture review questions (all 20, answered with test evidence)

Post-implementation, all 20 re-confirmed against actual code/tests:

1. **Does the detector use canonical `mutation.Request`?** Yes --
`detector.go`'s `Detect` builds every request via
`detection.NewMutationRequest`/`detection.NewTargetMutation`/
`mutation.Mutate`.
2. **Does it use `mutation.Executor`?** Yes -- every probe goes through
`x.ExecuteMutation` (`executeAndBound`); no detector-private HTTP
client exists.
3. **Does authenticated detection use the existing session?** Yes --
proven live, `TestPhase3_26_AuthenticatedCmdInjection_TwoIdentities_SessionIsolated`.
4. **Does `--identity` work without another authentication mechanism?**
Yes -- `cmdinjectionactive` never authenticates anything itself.
5. **Are query parameters supported end-to-end?** Yes --
`TestPhase3_26_QueryLocationUnix_Finding`/`_QueryLocationWindows_Finding`,
plus `TestScanCmd_CommandInjectionActive_QueryLocation_RealBinary`
through the real CLI binary.
6. **Are form parameters supported end-to-end?** Yes --
`TestPhase3_26_FormLocation_Finding` (real crawl via `/forms/index`).
7. **Are path parameters supported end-to-end?** Yes --
`TestPhase3_26_PathLocation_Finding` -- a genuine FINDING, not merely
discovery (closing a gap this phase's own investigation found in
Phase 3.25's own, slightly weaker, discovery-only path-location proof
-- see section 4's own note).
8. **Are JSON parameters genuinely reachable through the live
pipeline?** No -- the crawler cannot discover a live JSON
REQUEST_INPUT parameter (Phase 3.19's own pre-existing limitation).
9. **If JSON is not live, is it honestly marked PARTIAL?** Yes -- see
`docs/phase-3-26-acceptance-test.md`'s own JSON row; proven correct
via a directly-persisted parameter
(`TestPhase3_26_JSONLocation_DirectlyPersisted_Finding`), never
claimed as crawl-proven.
10. **Is command execution proven rather than inferred from response
difference?** Yes -- section 2's structural argument; the only
finding-producing code path requires an EXACT match of THIS probe's
own freshly generated token.
11. **Are false positives tested?** Yes -- section 6's full table,
`TestPhase3_26_NegativeControls_NoFinding` (7 negative fixtures live),
`TestAdversarial_BareMarkerPrefixWithoutExactToken_NeverConfirms`.
12. **Is execution bounded?** Yes -- `TestDetect_RequestCount_Bounded`
(exactly 5 requests: 1 baseline + 4 variants).
13. **Does cancellation work?** Yes --
`TestDetect_ContextCancelled_ReturnsPromptlyNoFinding`.
14. **Are findings identity-aware?** Yes -- `Finding.IdentityContext`
populated automatically by the engine, proven per-identity in the
authenticated multi-identity test.
15. **Are secrets protected?** Yes -- `detection.MutationEvidence`'s
existing redaction, unchanged; no raw credential is ever constructed.
16. **Does scope enforcement remain unchanged?** Yes -- zero new scope
code; `TestDetect_DeniedScope_ErrorsAndNoRequestsIssued`,
`TestAdversarial_ProbeRequest_NeverChangesHost`.
17. **Does the lab prove vulnerable and safe cases?** Yes -- sections
A-H all present and tested (Unix, Windows, safe/sanitized, reflection,
fixed-command, generic-error, authenticated, multi-identity).
18. **Does production build without `lab/` and `tests/`?**
Re-verified: both moved aside, `go build ./...`/`go vet ./...` succeed
with zero lab-dependent code.
19. **Do all previous phase regressions pass?** Yes -- 1903/1903
non-e2e, 105/105 e2e, full suite re-run after every fix.
20. **Are existing detectors unchanged?** Yes --
`internal/detectors/cmdinjection` was not modified; its own
ground-truth-driven tests needed a proactive, deliberate update
(adding `VULN-CMDI-API-WINDOWS-001`, a genuinely new positive
fixture the old detector's own `|`/`&&` variants correctly also
detect) -- addressed proactively before regression, not reactively
after a failure, learning from Phase 3.25's identical lesson with
`/ssrf/vulnerable-blind`.

## 18. What this phase intentionally does not implement

SSTI, XXE, deserialization, LDAP/XPath injection, template injection,
RCE beyond the safe marker-correlation proof, privilege escalation,
credential theft, persistence, reverse shells, data exfiltration,
internal network scanning, header/cookie-based command-injection
inputs (no discovery source produces them), OS-fingerprint-based
payload reordering (an optimization, not a correctness gap -- section
3), and any vulnerability class outside command injection.
