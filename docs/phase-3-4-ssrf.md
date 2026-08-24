# Phase 3.4: SSRF Detector

sakanner's third real vulnerability detector. Implements
`detection.Detector` (`internal/detection`, Phase 3.1) unchanged --
nothing in the framework was modified to build this; see
[docs/phase-3-1-detection-engine.md](phase-3-1-detection-engine.md)
"How to implement a new detector" for the contract this follows, and
[docs/phase-3-3-sqli.md](phase-3-3-sqli.md) for the sibling detector
whose false-positive lesson (reflected payloads) this one applies
proactively.

**Detection only, via out-of-band callback correlation.** The only
payload this detector ever sends is a callback URL pointing at its
*own* configured `CallbackClient` -- never a real internal address,
never a cloud metadata endpoint, never anything an operator or caller
supplies.

## What this detector does NOT do

- **Internal network scanning / enumeration** -- the detector never
  probes a range of internal addresses; it injects exactly one URL (its
  own callback) and checks for exactly one thing (whether that callback
  was hit).
- **Port scanning** -- not attempted, anywhere.
- **Cloud metadata access** -- never sends a probe toward
  `169.254.169.254` or any other metadata-service-shaped address; the
  only destination ever injected is the configured callback service.
- **Credential extraction** -- a confirmed finding proves the
  *capability* exists; nothing about confirming it reads, requests, or
  stores any credential.
- **Data extraction** -- the callback service (see below) never
  forwards, proxies, or returns fetched content; it only records that a
  request arrived.
- **Network pivoting / post-exploitation** -- detection stops the
  moment a callback is observed (or isn't, within the bounded wait). No
  finding ever triggers a further, more invasive probe.

## Security principle

Every active request this detector makes to the *target* application
goes through `detection.Executor.Do` -- the same scope-validated,
rate-limited, timeout-bounded, redirect-controlled choke point
`xssreflected` and `sqli` already use. The detector never builds its
own `http.Client`, never bypasses scope, and — critically — never lets
an operator- or attacker-influenced value decide the callback
destination: `requestURL` only ever substitutes the callback URL this
detector's own `CallbackClient.NewToken` returned. See "Scope
enforcement" below for the explicit distinction this implies.

## Architecture

```
internal/detectors/ssrf/
├── detector.go     Detector, Metadata, Eligible, Detect, finding construction
├── callback.go      CallbackClient interface + Observation
└── normalize.go      normalizeBody / stripPayload / containsFetchErrorPhrase
                       (the sqli false-positive fix, applied here from the start)

lab/callback.go   SSRFCallbackServer -- the real, local, non-
                        forwarding recorder that implements
                        ssrf.CallbackClient for lab tests

cmd/scanner/detectors.go   productionRegistry() registers ssrf.New(nil),
                            then disables it -- see "Callback architecture"
```

## Callback architecture

`CallbackClient` is the interface the detector uses to obtain a fresh,
correlatable out-of-band URL and later check whether anything hit it:

```go
type CallbackClient interface {
    NewToken(ctx context.Context) (token, callbackURL string, err error)
    Observations(ctx context.Context, token string) ([]Observation, error)
}
```

In a real deployment this would be backed by an operator-configured,
network-reachable callback/collaborator service. **sakanner ships no
such infrastructure in this build** -- there is no public webhook
service, no Burp Collaborator, no interactsh client, nothing that
reaches the public Internet, by design (this project never touches
third-party infrastructure). `productionRegistry()`
(`cmd/scanner/detectors.go`) therefore registers `ssrf.New(nil)` and
immediately disables it (`r.SetEnabled(ssrf.ID, false)`) -- `scanner
detectors list` shows it exists, its `Prerequisites` field explains
why it's off, and `Detect` on a nil `CallbackClient` returns
`OutcomeSkipped` rather than panicking. This is the same "built, not
yet wired into production" pattern Phase 3.1 established for
`DetectionConfig`.

In the Phase 3 Test Lab, `lab.SSRFCallbackServer`
(`lab/callback.go`) implements `CallbackClient` directly against
a real, local HTTP server:

- One fixed lab-only loopback address (`127.0.0.23`), never a
  DNS-resolvable hostname -- the fixture applications that fetch a
  callback URL do so with their own, real `http.Client`, using the
  REAL system resolver (not sakanner's `dns.FakeResolver`, which only
  governs the scanner's own dialing) -- so the callback URL must be a
  literal IP:port a real fetch can actually reach.
- `NewToken` returns a fresh `uuid.NewString()` token embedded in the
  URL path (`http://127.0.0.23:PORT/cb/{token}`).
- The HTTP handler does exactly one thing: append an in-memory
  `Observation{Method, Path, RemoteAddr, Timestamp}` keyed by the
  token extracted from the path, then return a fixed `200 ok`. **It
  makes zero outbound network calls anywhere in its own
  implementation** -- see "Callback security" below.
- `Observations(token)` returns a copy of whatever's recorded under
  that exact token -- nothing more.

## Candidate selection

```go
SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint}
SupportedMethods:     []string{http.MethodGet}
```

plus `Eligible(t)` requiring the parameter's **name** to match one of
the task's own ten examples: `url`, `uri`, `target`, `destination`,
`redirect`, `callback`, `webhook`, `endpoint`, `image`, `resource`
(case-insensitive). This is honestly the only signal available today:
Phase 2's recon model (`internal/detection.BuildTargets`) has no
parameter-value-shape classification, the same documented gap
`xssreflected` and `sqli` both already carry. "If existing
reconnaissance data contains stronger evidence, prefer that" doesn't
currently apply -- there is no stronger evidence to prefer.

## Baseline

`baselineValue = "sakannerSSRFBASELINE"` -- deliberately **not
URL-shaped at all**, not even a lab-internal URL. This is a different
choice than `xssreflected`/`sqli`'s baselines (which use plain-but-inert
values too) specifically because a genuinely vulnerable target might
try to actually fetch *any* URL-shaped baseline value, and this
detector has no way to guarantee in advance where a real target's own
input validation would let that go. A non-URL string is harmlessly
rejected by any reasonable URL-fetching code path without ever
attempting a dial -- the baseline's only job is establishing reference
response characteristics (status, content type, body shape), never
testing fetch behavior itself.

## Probe

Exactly **two requests to the target application** per candidate
parameter:

1. **Baseline** -- `baselineValue`.
2. **Callback probe** -- the callback URL obtained from
   `CallbackClient.NewToken`.

Then, separately (never counted against the target's request budget --
see "Request limits"), a **bounded, ctx-aware poll** of
`CallbackClient.Observations` for the token: up to 20 attempts at 10ms
intervals (`callbackMaxWait = 200ms`, `callbackPollInterval = 10ms`),
returning as soon as an observation appears. The Phase 3 lab's own
fixtures perform their server-side fetch **synchronously**, inline
within the same request/response cycle the probe triggers -- so in
practice the very first poll already finds the observation
(`TestPhase3_4_SSRFDetector_MatchesGroundTruth` completes in well under
a second). The bounded loop exists anyway to correctly model a target
whose SSRF manifests asynchronously (a queued job, a webhook processor)
-- `TestCorrelation_CallbackArrivesDuringPolling` and
`TestCorrelation_CallbackArrivesAfterTimeout` exercise both the
early-return and the full-timeout paths directly.

## Callback validation

A confirmed finding requires **all** of:

1. The target application received the callback URL (the probe
   request itself always succeeds, or the detector never gets this
   far).
2. The callback service observed a request (`len(observations) > 0`).
3. That observation is scoped to *this exact probe's token* --
   `CallbackClient.Observations(token)` is the correlation boundary;
   the detector never inspects an observation's *content* beyond
   presence, trusting the client's own token-scoping contract (see
   "Callback isolation" below for why that trust is justified).

**Reflection is explicitly distinguished from a server-side request.**
An endpoint that echoes the callback URL back into its response
(`/ssrf/reflect-only`) produces **zero** callback observations, because
nothing about echoing a string makes an HTTP request -- confirmed
directly by `TestDetect_NoServerSideFetch_NoFinding` and, against the
real lab, `VULN-SSRF-REFLECT-NEG-001`.

## False-positive prevention

Every negative shape the task named maps to a distinct Phase 3 Test Lab
fixture, verified against the real lab (not assumed):

| Negative shape | Fixture | Why this detector stays silent |
|---|---|---|
| URL reflection only | `/ssrf/reflect-only` | No callback observed -- reflecting text isn't a request |
| URL stored but not fetched | `/ssrf/store-only` | No callback observed -- "saved" never triggers a fetch |
| Client-side fetch only | `/ssrf/client-fetch` | The URL sits in an `<img src>` -- only a rendering browser would ever fetch it; this test harness never does |
| URL validation rejects callback | `/ssrf/validate-reject` | The fixture requires an allowlisted partner host; the callback URL never matches, request is rejected with 400 before any fetch |
| Safe allowlist implementation | `/ssrf/safe` | Identical to `sqli`/`xssreflected`'s allowlist fixtures -- the one allowlisted destination is never the callback URL |
| Callback from unrelated traffic | (tested at the correlation level, not via a fixture -- see below) | `Observations(token)` never returns another token's recorded hit |

### The reflected-parameter false positive, applied proactively

Phase 3.3 (`sqli`) discovered, via broad adversarial testing, that
comparing baseline vs. probe response bodies directly produces false
positives on any endpoint that merely **echoes** its parameter -- the
two payload *strings* differ, with no real behavior difference
involved. `normalize.go`'s `stripPayload` (removing each body's own
injected payload -- raw, HTML-escaped, URL-encoded -- before comparing)
was built into this detector **from the start**, rather than being
rediscovered. `TestDetect_ReflectedCallbackURLDoesNotCauseFalsePositive`
and `TestAdversarial_URLEncodedEchoOfCallbackURLStillStripped` prove
this directly; against the real lab,
`TestPhase3_4_SSRFDetector_MatchesGroundTruth` ran the detector against
**all 105 targets** the recon crawl produced from the whole lab (every
vulnerability class's fixtures, not just SSRF's own) and found zero
false positives on the first attempt.

## Confidence and severity

| Signal | Severity | Confidence | Rationale |
|---|---|---|---|
| Callback observed | critical | 0.9 | Direct, correlated confirmation of a server-side request -- "HIGH" per the task's rubric |
| No callback; probe response contains fetch-error wording baseline didn't | high | 0.5 | Behavioral evidence of an attempted (but unconfirmed) fetch -- "MEDIUM: strong indication... incomplete" |
| No callback; response differs from baseline for some other reason | medium | 0.25 | Generic, weak indication -- "LOW: weak URL-fetching indication without sufficient confirmation" |
| No callback; response identical to baseline (after stripping/normalizing) | -- | -- | No finding |

Severity reuses `pkg/models.Severity` unchanged, matching the Phase 3
ground truth's `severity: critical` for `VULN-SSRF-001`. Not every SSRF
indication is reported as critical -- only a confirmed callback is;
weaker, unconfirmed evidence is reported at lower severity *and* lower
confidence, per the task's explicit "do not automatically classify
every SSRF as critical."

## Evidence

Every finding's `Evidence` is one `detection.RequestResponseEvidence`:
the probe request (with the callback URL and correlation token named
explicitly), the probe's status line, the matched parameter, the
callback URL as `Payload`, a **bounded** `ResponseFragment` (±80 bytes),
and an `Observation` field carrying `callback_token`,
`callback_observed`, and a one-line detail of the first recorded
observation (method, path, remote address, RFC3339Nano timestamp) when
one exists. No callback *request body* is ever stored (the callback
server doesn't even read one), and no fetched content is ever exposed
through evidence -- only that a request arrived.

## Finding

Uses `pkg/models.Finding` unchanged. The detector sets
`VulnerabilityType` (`ssrf`), `Title`, `Severity`, `Confidence`,
`AffectedParameter`, `Description`, `Remediation`, and `Evidence`; the
engine's `normalizeFinding` (Phase 3.1, unchanged) fills `ID`,
`ScanID`, `DetectorID`, `Host`, `Port`, `URL`, `Method`,
`AffectedEndpoint`, `Source`, and timestamps.

## Deduplication

Reuses `internal/detection.Deduplicate` (Phase 3.1) unmodified. `Detect`
always returns at most one `Finding` per call regardless of how many
observations a token accumulated (`TestCorrelation_DuplicateCallbacksStillOneFinding`
proves the detector's own single-finding-per-call behavior directly);
the standard dedup key (`DetectorID`, `Host`, `Port`,
`AffectedEndpoint`, `Method`, `AffectedParameter`, `VulnerabilityType`)
handles the case where multiple recon sources discover the same
vulnerable parameter.

## Scope enforcement

**Critical distinction, stated explicitly per the task's own framing:**

- The **vulnerable application** may perform an SSRF request to the
  controlled callback service -- that is the entire premise of
  detection, and exactly what `VULN-SSRF-001`/`/ssrf/vulnerable`
  demonstrates.
- The **scanner itself** must never actively access an out-of-scope
  destination. Every request the *detector* makes goes through
  `Executor.Do`, bound to the target's own scope-validated `Host`/`IP`
  -- the detector has no other way to reach any network address.
  `TestDetect_OutOfScope_ReturnsErrorWithoutDialing` (unit) and
  `TestPhase3_4_SSRFDetector_ScopeEnforcementStaysActiveDuringDetection`
  (integration, against the real lab with the real job `ScopeSnapshot`
  -- authorizing only `vuln.scanner.test`, refusing a manufactured
  `Target` pointing at the Phase 2 lab's `scanner.test`) both confirm
  zero requests reach an out-of-scope host.
- `TestAdversarial_DangerousOriginalParameterValueNeverDialed` proves
  the detector never uses a target's *original*, Phase-2-discovered
  parameter value (which could look like anything, including
  `file:///etc/passwd`) as a destination -- `requestURL` only ever
  substitutes the detector's own callback URL.
- Redirects are not followed by the scanner (`ExecutorConfig.MaxRedirects`
  defaults to `0`, unchanged from `sqli`) -- inherited, unmodified
  protection from the shared `safedial` layer.

A scope bypass here would be an automatic phase failure; none was
found.

## Callback isolation and correlation

Every scenario the task names is tested directly against
`CallbackClient`'s own contract (`correlation_test.go`):

- **Unrelated callback traffic**: a hit recorded under a different
  token never appears under the probe's own token
  (`TestCorrelation_UnrelatedCallbackDoesNotAffectAnotherToken`).
- **Callback from another scan**: two independent `CallbackClient`
  instances (modeling two independent scans/`Engine.Run`s) never see
  each other's observations
  (`TestCorrelation_CallbackFromAnotherScanIsolated`).
- **Stale callback from a previous scan**: an old token's recorded hit
  never matches a freshly-generated token
  (`TestCorrelation_StaleCallbackFromPreviousScanNeverMatchesNewToken`).
- **Token collision** (hypothetical -- `uuid.NewString()` makes a real
  one astronomically unlikely): even if a `CallbackClient`
  implementation ever collided two tokens, the detector still
  correctly correlates to whichever token it was given
  (`TestAdversarial_TokenCollision_StillCorrelatesToTheSharedToken`).

Against the real lab, `TestSSRFCallbackServer_TokenIsolationAcrossManyTokens`
(`lab/callback_test.go`) proves the same property end to end with
10 real tokens, hitting only every other one, and confirming
`Observations` reports exactly the right subset.

## Callback security

`lab.SSRFCallbackServer`'s handler makes **zero outbound network
calls anywhere in its implementation** -- it cannot become an open
proxy because there is no code path in it that ever calls out.
`TestSSRFCallbackServer_NeverProxiesRegardlessOfInput`
(`lab/callback_test.go`) sends a request carrying
proxy-shaped headers (`X-Forward-To`, `X-Proxy-Target` pointed at a
cloud-metadata-shaped address, a spoofed `Location`) and confirms the
response is the identical, fixed `200 ok` every other request gets --
nothing about the request's content ever changes its behavior.
`TestSSRFCallbackServer_RecordsOnlyNecessaryMetadata` confirms only
method/path/remote-addr/timestamp are ever recorded, never a request
body.

## Request limits

- **2 requests to the target per candidate** (baseline + callback
  probe) -- no conditional escalation, ever.
- **Bounded callback polling**: at most 20 poll attempts (200ms total)
  per candidate, entirely separate from the target's own request
  budget (polling talks to the local `CallbackClient`, in the lab a
  direct in-process method call, never counted against
  `Executor.RequestCount()` -- confirmed by
  `TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests`
  asserting exactly `candidates × 2`).
- **No permanent goroutines**: `waitForCallback` is a bounded loop
  inside the same `Detect` call, never a background goroutine outliving
  it -- `TestDetect_CancellationWhileWaitingForCallback` proves the
  poll loop terminates immediately (not after the full 200ms budget)
  when `ctx` is cancelled mid-wait.
- **Timeout / concurrency / rate limiting**: inherited from the shared
  `detection.Executor`, identical to `xssreflected`/`sqli` -- no
  detector-specific network controls exist or are needed.

## Performance

`TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests` runs 12
candidates concurrently against a shared `Executor` and a shared
callback server, asserting exactly `12 × 2 = 24` total target requests
-- no request multiplication, and (run under `-race`, as the whole
suite always is) no data races. `Detector` holds no mutable state of
its own beyond the injected `CallbackClient` reference.

## Limitations

- **GET query parameters only** -- see "Candidate selection."
- **Parameter-name heuristic only** -- no stronger recon-derived
  evidence (parameter-value shape, prior observed redirect behavior)
  exists yet to narrow candidates further; this is the same honestly
  documented gap `xssreflected`/`sqli` both carry.
- **No production callback infrastructure ships in this build** -- see
  "Callback architecture." The detector is fully built, tested, and
  verified against the real Phase 3 lab's own callback server; wiring
  it to a real, operator-configured collaborator service is future
  work, deliberately out of this phase's scope (no third-party
  infrastructure is ever touched by this project).
- **Digit-run-only response normalization** -- the same documented
  limitation `sqli` carries: non-digit dynamic content is not
  normalized away.
- **No redirect-chain-aware detection** -- the detector never follows
  redirects itself (by design, matching scope enforcement); a target
  whose SSRF only manifests after an internally-followed redirect the
  scanner never sees is out of reach for the same reason a stored/
  DOM-based vulnerability is out of reach for `xssreflected`.
