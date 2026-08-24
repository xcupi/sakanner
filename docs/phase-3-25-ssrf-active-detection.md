# Phase 3.25: SSRF Active Detection Foundation

## 0. Scope discipline

This phase implements exactly one thing: an active, mutation-engine-
based SSRF detector requiring genuine server-side evidence (callback
correlation or embedded-resource-content), across query/form/JSON/
path locations. No new vulnerability class beyond SSRF; no
authorization/IDOR work; no SSTI/XXE/deserialization/mass-assignment/
DNS-rebinding/cloud-metadata exploitation/internal network scanning.

## 1. Architecture review

Traced with exact citations, not assumed.

### 1.1 The existing `internal/detectors/ssrf` (Phase 3.4) package

A complete, working, but disabled-by-default detector already exists.
`ID = "ssrf"` (`ssrf/detector.go:35`). `New(cb CallbackClient) *Detector`
(`ssrf/detector.go:96`) -- a nil `cb` makes every `Detect` call return
`OutcomeSkipped`, mirroring the `idor`/`traversal` nil-dependency
precedent. Registered-but-disabled in `cmd/scanner/detectors.go`
(`ssrf.New(nil)`, disabled via `SetEnabled(ssrf.ID, false)`) because
"an out-of-band callback service... this build does not ship" -- the
SAME honest, pre-existing gap `idor` (Phase 3.5) carried before Phase
3.24, now carried forward for SSRF too.

**Critically, this package does not import `internal/mutation` at all**
-- `Eligible` restricts to GET-only query-location targets
(`ssrf/detector.go:116-122`), and `probe` builds its own
`*http.Request` via `url.Parse`/`nethttp.NewRequestWithContext`,
issued through the OLD `x.Do(ctx, t, req)` path
(`ssrf/detector.go:280-300`) rather than `x.ExecuteMutation`. This is
the exact same architectural gap `internal/detectors/idor` had before
Phase 3.24's `idoractive` -- the same resolution applies: a NEW,
coexisting package built on the canonical mutation engine, leaving
`internal/detectors/ssrf` completely untouched (its own tests,
`correlation_test.go`/`adversarial_test.go`, remain valid and
unmodified).

The existing detector's OWN weaker fallback tiers (`ssrf/detector.go:
161-184`: a "body differs after normalization" Medium/0.25 tier and a
"fetch-error-phrase present" High/0.5 tier, used only when no callback
was observed) are EXACTLY the kind of evidence this phase's own task
explicitly prohibits treating as sufficient ("response length
difference," "generic response change," "application error containing
the supplied URL" must never alone prove SSRF). `ssrfactive` is
therefore DELIBERATELY MORE conservative than `ssrf`: it never reports
a finding from response-difference or error-phrase heuristics alone --
only from genuine server-side evidence (sections 2-3 below). This is a
correctness improvement over the older package's own historical design,
not a regression -- `ssrf` itself is left unmodified, so both detectors
coexist with distinct evidentiary standards visible in their own code.

### 1.2 The existing callback/OOB infrastructure (task section 11)

`internal/detectors/ssrf.CallbackClient` (`ssrf/callback.go:32-43`) is
a minimal, already-well-designed interface:

```go
type CallbackClient interface {
    NewToken(ctx context.Context) (token, callbackURL string, err error)
    Observations(ctx context.Context, token string) ([]Observation, error)
}
```

`Observation` (`ssrf/callback.go:12-17`) carries only
`Method`/`Path`/`RemoteAddr`/`Timestamp` -- no secrets, ever.

`lab.SSRFCallbackServer` (`lab/callback.go`) implements this directly:
a real, local, non-forwarding HTTP server (`/cb/{token}` records a hit
keyed by the token embedded in the URL PATH, never a header/cookie/
query string that could be stripped or rewritten by an intermediate
proxy) with a FIXED "ok" acknowledgment body regardless of input --
proven adversarially
(`TestSSRFCallbackServer_NeverProxiesRegardlessOfInput`,
`lab/callback_test.go:19-63`, which explicitly asserts `body == "ok"`
even against proxy-shaped headers). Token isolation across many tokens
is proven against the REAL server
(`TestSSRFCallbackServer_TokenIsolationAcrossManyTokens`,
`lab/callback_test.go:101-135`), and cross-scan isolation is proven at
the detector-consumption level
(`TestCorrelation_CallbackFromAnotherScanIsolated`,
`ssrf/correlation_test.go:32-56`).

**Decision: this infrastructure is fully sufficient for Mode B (blind/
OOB) and is reused completely unchanged.** `lab/callback.go` is NOT
modified by this phase -- `TestSSRFCallbackServer_NeverProxiesRegardlessOfInput`
hard-asserts the literal ack body `"ok"` (`lab/callback_test.go:52`),
so changing that body (e.g. to embed the token, which was considered
as a way to reuse ONE server for both evidence modes) would break an
existing, passing, adversarially-meaningful Phase 3.4 test for no
compelling gain -- see section 3 for why Mode A instead gets its own,
separate, new, minimal lab component rather than touching this file.

Cross-scan/cross-token correlation works structurally, without any
scan-ID/target-ID field on the wire, because `NewToken` always returns
a freshly generated, globally-unique UUID (`lab/callback.go:78-81`,
`uuid.NewString()`) and the CALLER (the detector, inside one `Detect`
call) is the only place that ever associates a token with a specific
scan/target/mutation/identity -- this is Go closure-scoped state, not
anything transmitted over the wire, so there is nothing new to add for
"correlate scan/target/identity without exposing secrets" (task
section 11): the token itself already carries zero information beyond
random uniqueness.

### 1.3 The established "-active" detector pattern (Phase 3.19-3.24)

`ssrfactive` follows the SAME shape `xssactive`/`sqliactive`/
`idoractive` already established: `Eligible` accepts query (GET only),
form/body/path (any method) -- mirroring `sqliactive.Eligible`'s exact
switch (`sqliactive/detector.go:82-94`). Unlike `idoractive`, there is
no cross-identity mutation-safety concern here (only one identity/
session is ever involved in an SSRF probe, never a second one used
"as" the same request), so there is no reason to restrict to GET-only
the way `idoractive.Eligible` deliberately does -- the general
"-active" convention applies unmodified.

Requests are built exclusively via `detection.NewMutationRequest`/
`detection.NewTargetMutation`/`mutation.Mutate`/
`Executor.ExecuteMutation` -- identical to every detector since Phase
3.19. `mutation.Compare` is available but, per section 1.1's own
reasoning, deliberately NOT used as an independent basis for a
finding -- only for descriptive/logging purposes within evidence text,
never as a gate.

### 1.4 Existing lab SSRF fixtures (`lab/harness_vuln.go`, unauthenticated,
`vuln.scanner.test` = 127.0.0.21)

Six existing routes, wired via `registerSSRF(mux, ssrfInternalAddr)`
(`harness_vuln.go:1057`), called from `vulnAppHandler`
(`harness_vuln.go:165`), only present under `StartWithVulnerabilities`:

- `/ssrf/vulnerable` -- genuinely fetches the `url` query parameter
  server-side (`http.Client{}.Get(target)`), restricted by an inline
  lab-only safety net to loopback destinations only (`ip.IsLoopback()`),
  and embeds the fetched body verbatim in its own response
  (`"fetched %s: %s"`). **This is real, response-based evidence
  already, for query location** -- reused as-is by `ssrfactive` for
  Mode A (section 3) with zero modification.
- `/ssrf/safe` -- allowlist-checked, never actually fetches.
- `/ssrf/reflect-only`, `/ssrf/store-only`, `/ssrf/client-fetch`,
  `/ssrf/validate-reject` -- four negative-control shapes (reflected
  URL, no response change, client-side-only fetch, response differs by
  shape but no fetch attempt) -- task section 7's false-positive list
  items 1/2/4/5/8 are already covered live by these four fixtures.

`lab.SSRFCallback *SSRFCallbackServer` (`harness.go:129`,
`harness_vuln.go:95-100`) is wired only under `StartWithVulnerabilities`,
on its own fixed loopback IP (`ipSSRFCallback = "127.0.0.23"`,
`harness_vuln.go:39`) -- an established test-lab-only field this
phase's own lab tests reuse directly, exactly like
`lab/phase3_4_ssrf_test.go`'s own `ssrfRegistry` helper already does.

**Gaps this phase must fill in the lab** (task section 10): form/JSON/
path-location vulnerable fixtures (only GET-query exists today),
an authenticated SSRF fixture, a redirect-to-callback fixture, and a
Mode-A-specific "internal resource" server distinct from the callback
recorder (section 3).

## 2. Evidence principle -- what counts as proof

Per task section 2's own explicit prohibition list, NONE of the
following, alone, is ever sufficient: status code (any of 2xx/3xx/
4xx), response-length delta, response-timing delta, a reflected URL,
an error message containing the supplied URL, a generic response
change, or the SCANNER's OWN successful DNS resolution of the payload
host. `ssrfactive` structurally cannot produce a finding from any of
these alone, because neither of its two evidence modes (section 3) is
built from them at all -- there is no code path in this package that
compares response bodies/lengths/timings between baseline and probe
and treats a difference as evidence.

## 3. Detection modes

### Mode A: response-based (secondary-resource content evidence)

The detector injects a URL pointing at a NEW, minimal, lab-owned
"internal resource" HTTP server
(`lab/harness_ssrf_active.go`, new IP `127.0.0.28`) that serves a
single, fixed, distinctive marker string
(`SSRF_INTERNAL_RESOURCE_MARKER_PHASE325`, never a value a legitimate
page would coincidentally contain) for any request. If the TARGET
APPLICATION's own response (from the SAME request the probe issued)
contains this exact marker, that is genuine evidence the application
fetched and embedded that specific resource's content server-side --
not a status code, not a generic diff, not a reflected URL (the marker
is never present in the injected URL string itself, so `stripPayload`-
style reflection can never produce a false match).

No per-probe token or correlation state is needed for Mode A: the
causality is already established structurally by the request/response
pair the SAME `Detect` call already holds -- the detector knows
definitively "I asked this specific target to fetch this specific
URL, and the response to THAT SAME REQUEST contains the resource's
distinctive content." This is why Mode A needs no new stateful
server type -- a bare `http.HandlerFunc` is sufficient (see section
10).

Configured via a new, optional constructor parameter,
`internalResourceURL string`. Empty string skips Mode A gracefully
(never fatal) -- only Mode B (section below) is required for the
detector to be enabled at all, matching `ssrf.New`'s own existing
nil-`cb`-means-disabled precedent for the primary dependency.

### Mode B: blind/OOB (callback correlation)

Reused, unchanged: `ssrf.CallbackClient` (`d.callback.NewToken`/
`Observations`), the SAME interface and the SAME
`lab.SSRFCallbackServer` implementation the existing `ssrf` package
already uses (section 1.2). A bounded poll
(`callbackPollInterval`/`callbackMaxWait`, values copied from
`ssrf/detector.go:64-67` -- the exact same, already-reviewed bounds)
checks for an observation after the probe request completes. `cb ==
nil` disables the WHOLE detector (`OutcomeSkipped`), mirroring
`ssrf.New`'s own precedent exactly -- Mode B is the PRIMARY,
required-for-any-detection dependency; Mode A is an enhancement on
top of it, never a substitute (a target that can be proven via Mode A
alone, with no callback client configured at all, is not something
this phase's detector attempts to support -- consistent with keeping
exactly one required external dependency, matching every other
disabled-by-default detector's own single-prerequisite convention).

### Combining the two modes

Per eligible target: baseline probe (unmutated, via `x.ExecuteMutation`)
establishes the endpoint is analyzable at all; then, if
`internalResourceURL != ""`, a Mode A probe (mutate to
`internalResourceURL`, check the SAME response for the marker); then a
Mode B probe (mutate to a FRESH callback URL, then bounded-poll for an
observation). A finding is produced if EITHER mode confirms -- Mode A
alone, Mode B alone, or both (in which case the finding's evidence
records BOTH, at the highest resulting confidence). Neither mode alone
running is treated as "insufficient" -- task's own "at least two modes
where technically possible," not "both modes must independently
confirm."

## 4. Mutation locations

`Eligible` mirrors `sqliactive`'s exact location switch (section 1.3):
query (GET only), form/body/path (any method). Every location is
proven end to end through a REAL lab fixture + REAL crawl + REAL
detection run (section 10), never merely by constructing a synthetic
`detection.Target` and asserting `Eligible` returns true (that proof
also exists, but is not treated as sufficient alone -- task's own
"prove it with an actual end-to-end test").

Header/cookie SSRF inputs are NOT claimed -- no discovery/
configuration source in this codebase ever produces a
`ParameterLocation` of `"header"`/`"cookie"` for a URL-shaped value
(confirmed: `BuildTargets`/`internal/parameters` only ever emit
query/form/body/path REQUEST_INPUT parameters), so `Eligible` never
matches those locations and no fixture/test claims to exercise them.

## 5. Payload design

Deterministic, bounded, no combinatorics: exactly 3 requests per
eligible target (baseline, Mode A if configured, Mode B), matching
section 3's own design. The Mode A payload is a FIXED, constant URL
(`internalResourceURL`, configured once at construction, never varied
per-probe) -- genuinely deterministic across repeated scans. The Mode
B payload is a freshly generated callback URL per probe (via
`NewToken`), which is NOT byte-identical across repeated scans (a
fresh UUID every time) but IS structurally deterministic: every run
issues exactly one Mode-B probe per eligible target, in the same
target order, producing the same STRUCTURAL finding count and shape
every time (task section 15's own "finding identity, evidence
structure, risk input" bar -- never "byte-identical UUIDs," which
would be a meaningless, wrong definition of determinism for anything
built on a real correlation token). This mirrors how every existing
identity/session-aware component already reasons about determinism
(e.g. `mutation.MutationID`, session cookie VALUES are never
byte-identical across runs either -- see Phase 3.16's own
determinism tests, which check structural counts, never literal
session token values).

No lab destination is ever a real, arbitrary public host -- both the
callback server and the internal-resource server are lab-owned,
loopback-only.

## 6. Scope safety

Zero new scope code. Every probe request (to the TARGET APPLICATION)
goes through the identical `x.ExecuteMutation` -> `mutation.Executor.
Execute` -> `resolveAndValidate` path every other active detector
already uses -- an out-of-scope target application is refused exactly
as before this phase, proven by the SAME
`TestDetect_DeniedScope_ErrorsAndNoRequestsIssued` pattern every prior
"-active" detector's own test suite already establishes.

The callback/internal-resource DESTINATIONS are never dialed BY THE
SCANNER at all -- the scanner only ever sends their URLs AS PAYLOAD
VALUES in a normal, in-scope request to the target application; the
callback server's `Observations` and the Mode A marker check are both
answered via the scanner's own in-process/synchronous means (an
in-memory map lookup and a response-body substring check,
respectively), never a second outbound dial from the scanner itself.
This means the callback/resource destinations structurally can never
need to be "in scope" for the SCANNER's own dialing -- they are
scanner-owned infrastructure the target application (not the scanner)
dials, if and only if it is vulnerable. This is the same reasoning
`internal/detectors/ssrf` (Phase 3.4) itself already established and
this phase inherits unchanged.

A mutated URL VALUE can never change the dial target for the probe
request ITSELF (the request is always addressed to the target
application's own `t.Host`/`t.IP`/`t.Port` -- only the PARAMETER value
changes) -- the identical, already-proven argument every prior
"-active" detector's own host-safety adversarial test makes (e.g.
`idoractive`'s `TestAdversarial_KnownBadControl_NeverChangesHost`,
`sqliactive`'s path-segment equivalent). Reused by the identical
reasoning here, proven by a dedicated test (section 19).

## 7. False-positive resistance

Task section 7's 10-item list, mapped to how this design handles each:

| Case | How it's handled |
|---|---|
| 1. Reflected but never requested server-side | Neither mode's evidence is "value appears in response" for the INJECTED value itself -- Mode A requires the SEPARATE marker string (never equal to the injected URL); Mode B requires an actual callback HIT. A pure reflection produces neither. Proven live by `/ssrf/reflect-only`. |
| 2. Response changes but no outbound request | Same reasoning -- a response diff alone triggers neither mode. Proven live by `/ssrf/validate-reject`. |
| 3. Generic error | Same -- an error body is not the Mode A marker and produces no Mode B callback. |
| 4. Supplied URL returned without fetching | Proven live by `/ssrf/reflect-only`/`/ssrf/client-fetch`. |
| 5. Normal redirect to the scanner | The scanner's OWN probe response being a redirect is never itself evidence (section 2) -- only a genuine Mode A/B signal is. |
| 6. Callback endpoint never contacted | The default, expected outcome for every safe/negative fixture -- `Observations` returns empty, no finding. |
| 7. Callback receives unrelated traffic | Structurally impossible to attribute to the wrong token -- `Observations(token)` only ever returns hits recorded under that exact token (section 1.2's token-isolation proof). |
| 8. Same response regardless of payload | Never evaluated at all -- this design has no "does the response differ" gate. |
| 9. DNS resolution without HTTP interaction | `mutation.Executor`/`safedial` resolve the TARGET APPLICATION's own host to dial it -- this is unrelated to whether the target itself made an SSRF request; no DNS-only signal is ever treated as SSRF evidence anywhere in this package (task's own "do not assume successful DNS resolution... is proof"). |
| 10. Wrong-scan callback attribution | Section 1.2's cross-scan isolation proof (`TestCorrelation_CallbackFromAnotherScanIsolated`) plus a NEW concurrent-scan lab test (section 19). |

## 8. Authentication

Zero new authentication code. `ssrfactive.Detect(ctx, t, x)` receives
`x *detection.Executor` the same way every detector does -- already
bound to whichever session `orchestrator.buildDetectionExecutor`
attached for this scan (`--auth-profile` or `--identity`, both
unchanged since Phase 3.14/3.16). An authenticated SSRF fixture is
added to `harness_auth.go`'s existing `authApp` (section 10.E),
proving the probe correctly carries the session's cookies. No
multi-identity/compare-identity concept is needed here at all (unlike
Phase 3.24) -- SSRF probing never compares two identities' sessions
against each other; it only needs ONE already-authenticated session to
carry through unchanged, which the existing single-session
architecture already provides for free.

## 9. Identity / evidence / correlation

`models.Finding`/`models.Evidence` reused unchanged, exactly like
`ssrf`'s own existing finding-building code
(`detection.NewTypedRequestResponseEvidence`/
`detection.MutationEvidence`). `Finding.IdentityContext` is populated
automatically by the engine's `normalizeFinding` from
`Target.IdentityContext` -- `ssrfactive` never sets it explicitly
(unlike `idoractive`, which needed to override it for a SECOND
identity; SSRF only ever involves one). Evidence records: baseline
(request/response), Mode A probe (request/response/marker-found
boolean) when configured, Mode B probe (request/response/callback
token/observation summary) -- redacted via the SAME
`detection.MutationEvidence`/`evidence.IsSensitiveFieldName`
mechanism every other detector already uses; no raw credential is
ever placed in a callback token (a bare UUID) or in evidence text.

## 10. Lab

New file, `lab/harness_ssrf_active.go`, additive only -- `lab/callback.go`
and `lab/harness_vuln.go`'s existing six SSRF routes are NOT modified.

- **A. Vulnerable (response-based, existing, reused)**: `/ssrf/vulnerable`
  (query, `harness_vuln.go`, unchanged) -- Mode A's evidence source
  when pointed at the new internal-resource server.
- **New internal-resource server** (Mode A): a tiny, stateless HTTP
  server on a NEW loopback IP (`127.0.0.28`), any path, always returns
  the fixed marker `SSRF_INTERNAL_RESOURCE_MARKER_PHASE325`.
- **B. Safe (existing, reused)**: `/ssrf/safe`.
- **C. Blind SSRF**: `/ssrf/vulnerable` pointed at the callback server
  IS the blind-SSRF proof (Mode B doesn't need response content at
  all) -- no separate fixture required; a dedicated "blind-only"
  fixture (response NEVER reveals anything, e.g. always returns "202
  queued" regardless of fetch outcome, proving Mode B alone still
  confirms) is added as `/ssrf/vulnerable-blind` for an unambiguous
  Mode-B-only proof.
- **D. Negative control (existing, reused)**: `/ssrf/validate-reject`
  (and the other three negative fixtures).
- **E. Authenticated SSRF**: new `/ssrf-fetch` on `auth.scanner.test`
  (`harness_auth.go`'s existing `authApp`), session-gated, mirroring
  `/lookup`'s Phase 3.20 precedent exactly.
- **F. Multi-identity/session isolation**: proven by running the SAME
  authenticated fixture under two separate identities (Phase 3.16's
  existing `AccountAUsername`/`AccountBUsername`) and confirming each
  identity's own probe uses its own session's cookie -- no new lab
  fixture needed, reusing `harness_auth.go`'s existing two-account
  infrastructure exactly as `idoractive`'s own session-isolation
  tests already do.
- **New form/JSON/path fixtures**: `/ssrf/vulnerable-form` (POST
  form field `url`), `/ssrf/vulnerable-json` (POST JSON field
  `url`), `/ssrf/fetch/{path-escaped-target-url}` (path segment) --
  all reusing the SAME lab-safety-net logic (loopback-only
  destinations) as `/ssrf/vulnerable`, factored into one small shared
  helper `ssrfFetchWithLabSafetyNet` in the new file (not touching
  `harness_vuln.go`'s own existing, working handler).
- **Redirect-through fixture**: a tiny redirector on the
  internal-resource server's own mux, `/bounce?to=<loopback-url>`,
  restricted to loopback destinations, proving "callback through
  redirect" (task section 12) works via the TARGET APPLICATION's own
  outbound `http.Client` (which follows redirects by default) with
  zero detector-side redirect-specific code.

Ground truth is deterministic: every fixture's vulnerable/safe
behavior is a fixed, unconditional code path (no randomness, no
timing dependency beyond the already-bounded callback poll).

## 11. Callback/OOB architecture

Answered in full in section 1.2/3. Summary: `ssrf.CallbackClient` and
`lab.SSRFCallbackServer` are REUSED, unmodified, for Mode B. Mode A
gets its own new, separate, minimal lab component specifically to
avoid touching Phase 3.4's already-tested callback ack-body behavior
(the one place a shared-server design was considered and rejected --
see section 1.2's explicit reasoning). No new correlation TOKEN
concept was needed for Mode A at all (section 3).

## 12. Redirect handling

The scanner's own probe requests already re-validate scope on every
redirect hop via the existing `mutation.Executor`/`safedial` machinery
-- unchanged, proven by every prior phase's own adversarial tests
(Phase 3.17/3.19 onward) and re-confirmed here with one dedicated
`ssrfactive`-level test (section 19) rather than re-deriving the
argument from scratch. The TARGET APPLICATION's own outbound fetch
(which may itself follow a redirect server-side, entirely outside the
scanner's own network path) is proven via the redirect-through
fixture (section 10) -- the callback server correctly records the hit
regardless of how many server-side hops the target's own HTTP client
followed to get there, since `Observations` only cares about who
ultimately reached `/cb/{token}`, never how they got there.

## 13. DNS/IP handling

No DNS rebinding, wildcard DNS, or IP-obfuscation technique is
implemented in this phase (task's own explicit boundary). Payload
values are always concrete, pre-resolved loopback addresses/URLs
(the callback server's and internal-resource server's own literal
`host:port`, obtained via `Addr()`) -- never a hostname the scanner
itself would need to freshly resolve, and never a value under
attacker/operator control beyond what this phase's own lab
constructs. This avoids any new DNS-request volume, any scope-bypass
surface, and any uncontrolled network activity by construction --
documented here as the explicit, deliberate absence of that
functionality, not an oversight.

## 14. Resource limits

No new limit configuration -- `ssrfactive`'s executor is the SAME
`*detection.Executor` (with its own already-existing
`MaxMutationsPerParameter`/`MaxActiveRequestsPerScan`/`Concurrency`/
rate-limiter config) every other active detector already respects.
Per eligible target this detector issues at most 3 requests (section
5) -- 1 unmutated (uncharged against the mutation budget, `Origin ==
OriginOriginal`) and up to 2 mutated (Mode A, Mode B -- each charged
independently, exactly like every other detector's own mutation
probes). The callback poll (section 3) is bounded
(`callbackMaxWait = 200ms`, matching `ssrf`'s own already-reviewed
value) and ctx-aware, so cancellation during a poll returns
immediately via the `ctx.Done()` select branch -- no goroutine, timer,
or waiter is ever left running past `Detect`'s own return (proven by
a dedicated cancellation test, section 19).

## 15. Determinism

See section 5's own detailed reasoning. Target ordering is the SAME
already-deterministic `BuildTargets` output every detector consumes.
Payload ordering is fixed (baseline, then Mode A if configured, then
Mode B, always in that order -- never a map iteration). Finding/
evidence STRUCTURE (evidence count, evidence kinds, ordering) is
fixed regardless of the specific UUID a given run's callback tokens
happen to be.

## 16. CLI

Zero new CLI surface. `ssrfactive.New(cb, internalResourceURL)` is
registered into the SAME `buildProductionRegistry` function
`idoractive` already extended (`cmd/scanner/detectors.go`) --
mirroring `xssactive`/`sqliactive`'s own precedent of being enabled by
default alongside their non-active sibling (unlike `idoractive`, which
needed a NEW flag because it required a second identity; `ssrfactive`
needs no such flag since it uses only the scan's own existing single
session). Since NO production callback service ships with this build
(section 1.1's own honest, inherited gap), `ssrfactive` is constructed
with `New(nil, "")` in `productionRegistry()` and explicitly disabled
via `SetEnabled(ssrfactive.ID, false)`, mirroring `ssrf.New(nil)`'s
OWN existing disabled-by-default precedent exactly -- `scanner
detectors list` honestly shows it exists and why it's off. It is
proven enabled and working exclusively through the lab's real
`SSRFCallbackServer`, exactly like `ssrf` itself already is.

## 17. Evidence quality

Every finding's evidence records (section 9): original parameter
name/location, the baseline (unmutated) request/response, the Mode A
probe's request/response plus an explicit
`marker_found=true/false` observation, the Mode B probe's request/
response plus the callback token and a redacted-safe observation
summary (method/path/remote-addr/timestamp -- never a raw header/
body), and a `Reason` string explaining WHY this is genuine SSRF
evidence rather than reflection/redirect ("the callback service
observed a server-side request... " / "the response embedded the
internal resource's own distinctive marker content... "). No full
raw response body is ever stored -- only bounded fragments, matching
`detection.MutationEvidence`'s own existing convention.

## 18. Architecture review questions (all 20, answered with test evidence)

Post-implementation, all 20 re-confirmed against actual code/tests
(see `docs/phase-3-25-acceptance-test.md` for the full pass/fail
summary):

1. **Does SSRF use the canonical `mutation.Request`?** Yes --
`detector.go`'s `probe` builds every request via
`detection.NewTargetMutation`/`mutation.Mutate`, never a raw
`net/http` request.
2. **Does SSRF use the existing `mutation.Executor`?** Yes -- every
probe is issued via `x.ExecuteMutation`/`d.callback`'s own executor-
independent polling; no detector-private HTTP client exists.
3. **Does authenticated SSRF use the existing session?** Yes -- proven
live against a real session-gated fixture,
`TestPhase3_25_AuthenticatedSSRF_TwoIdentities_SessionIsolated`.
4. **Does `--identity` work without a second authentication
mechanism?** Yes -- `ssrfactive` never authenticates anything itself;
it only receives the engine-supplied, already-session-bound `x`.
5. **Are query/form/JSON/path inputs actually reachable?** Query/
form/path: yes, via real crawl (`TestPhase3_25_QueryLocation...`,
`_FormLocation...`, `_PathLocation...`). JSON: the detector/mutation
logic is proven against a real endpoint, but real CRAWL-based
discovery is a pre-existing, honestly-documented gap (see JSON
PARTIAL in the acceptance doc) -- not claimed as fully proven.
6. **Is SSRF evidence based on server-side interaction rather than
response difference alone?** Yes -- section 2's structural argument,
confirmed by `TestDetect_ReflectedURLOnly_NoMarker_NoFinding` and the
four negative-control fixtures never producing a finding.
7. **Can blind SSRF be correlated to the originating scan/target/
mutation?** Yes -- the token is generated and consumed entirely
within one `Detect` call's own closure; proven end to end
(`TestPhase3_25_BlindOnly_Finding`).
8. **Can callback events remain isolated across concurrent scans?**
Yes -- `TestAdversarial_ConcurrentScans_CallbacksNeverCrossAttribute`.
9. **Can callback evidence remain isolated across identities?** Yes --
`TestPhase3_25_AuthenticatedSSRF_TwoIdentities_SessionIsolated`.
10. **Does scope enforcement remain unchanged?** Yes -- zero new scope
code anywhere in `internal/detectors/ssrfactive`.
11. **Can redirects cause a scope bypass?** No -- unchanged
`mutation.Executor`/`safedial` redirect re-validation; proven at the
detector level by `TestAdversarial_ProbeRequest_NeverChangesHost`.
12. **Are arbitrary external callback destinations prevented?** Yes,
structurally -- the scanner never dials a callback/resource URL
itself; both are lab-owned literal loopback addresses.
13. **Are resource limits bounded?** Yes -- reused executor limits, at
most 3 requests per eligible target, bounded ctx-aware poll.
14. **Does cancellation cleanly terminate callback waits?** Yes --
`TestDetect_ContextCancelledDuringCallbackWait_ReturnsPromptly`.
15. **Are secrets redacted everywhere?** Yes -- `detection.MutationEvidence`'s
existing redaction, unchanged; no raw credential is ever constructed
by this package.
16. **Does the lab prove positive and negative SSRF cases?** Yes --
sections A-F all present and tested (query/form/JSON/path positive,
safe, blind-only, negative controls, authenticated, multi-identity).
17. **Does the production build work with `lab/` removed?**
Re-verified: `lab/`+`tests/` moved aside, `go build ./...`/`go vet ./...`
succeed with zero lab-dependent code.
18. **Are existing detectors unchanged?** Yes -- `internal/detectors/ssrf`
was not modified; three of its OWN ground-truth-driven tests needed
updating (not weakening) because this phase added a genuinely new
vulnerable lab fixture the old detector correctly also detects -- see
the acceptance doc's DEFECTS FOUND AND FIXED item 4.
19. **Are existing Phase 3.17-3.24 tests still passing?** Yes --
1865/1865 non-e2e, 102/102 e2e, full suite re-run after every fix.
20. **Is every claimed supported input type proven through the real
pipeline?** Yes for query/form/path (full crawl-to-finding); JSON is
explicitly marked PARTIAL, not claimed as fully proven, for the
reason in question 5.

## 19. What this phase intentionally does not implement

DNS rebinding, wildcard DNS, IP-obfuscation/encoding tricks beyond
what a target application's own URL parser already handles, cloud
metadata exploitation, internal network scanning, credential
harvesting, destructive payloads, header/cookie-based SSRF inputs (no
discovery source produces them), a production-ready/network-reachable
callback SERVICE (only the lab's own local server -- exactly
`ssrf`'s own pre-existing, honestly-documented gap, carried forward
unchanged), and any vulnerability class outside SSRF (IDOR/
authorization, SSTI, command injection, XXE, deserialization, mass
assignment, prototype pollution).
