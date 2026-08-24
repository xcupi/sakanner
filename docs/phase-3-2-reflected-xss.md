# Phase 3.2: Reflected XSS Detector

sakanner's first real vulnerability detector. Implements
`detection.Detector` (`internal/detection`, Phase 3.1) unchanged --
nothing in the framework was modified to build this; see
[docs/phase-3-1-detection-engine.md](phase-3-1-detection-engine.md)
"How to implement a new detector" for the contract this follows, and
this document for what's specific to reflected XSS.

**Scope: reflected XSS only.** A GET query parameter whose value is
echoed back into the *same* HTML response without adequate encoding.

## What this detector does NOT detect

- **Stored XSS** — a payload that persists and is reflected on a
  *later*, separate request (e.g. `/xss/stored/vulnerable` in the Phase
  3 lab). This detector only ever looks at the response to the exact
  request it just made.
- **DOM-based XSS** — a client-side JavaScript sink (`innerHTML`,
  `document.write`, ...) that never touches the server-rendered
  response body at all. Not observable from HTTP response bodies alone,
  so out of reach for this detector's entire approach.
- **Any other injection class** — SQL injection, SSRF, path traversal,
  etc. are unrelated vulnerability classes with their own future
  detectors.
- **POST/form-body parameter reflected XSS** — see "Input selection"
  below for why.

## Architecture

```
internal/detectors/xssreflected/
└── detector.go   Detector, Metadata, Eligible, Detect, and every helper below

cmd/scanner/detectors.go   productionRegistry() registers xssreflected.New()
```

One file, no new framework surface. `Detector` is stateless (a
zero-size struct) — every piece of state a `Detect` call needs (the
`Target`, the `Executor`) is passed in, matching
`detectiontest.Mock`'s shape exactly.

## Candidate selection (input selection)

```go
SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint}
SupportedMethods:     []string{http.MethodGet}
```

plus `Eligible(t)` requiring `t.Parameter != "" && t.ParameterLocation
== "query"`. This is deliberately narrow: `internal/detection.BuildTargets`
(Phase 3.1) only ever produces a `Parameter`-bearing `Target` from a
query string already observed on a crawled URL (`internal/parameters`
remains an unimplemented Phase 1 stub — no form-field parameter surface
exists to test yet). This detector's own eligibility check doesn't
invent a parameter source Phase 2 doesn't provide; it consumes exactly
what's there. POST/form endpoints are consequently never eligible in
this phase, not because reflected XSS can't occur there, but because
there is no parameter target to test yet — documented here as an honest
gap, the same way Phase 3.1 documented `BuildTargets`' own limitation.

## Probes

At most **three** requests per candidate parameter, each with a
distinct, single-purpose payload — never a large payload dictionary:

| # | Name | Payload | Purpose |
|---|---|---|---|
| 1 | Reflection probe | `sakannerXSSPROBE` (plain alphanumeric) | Does the parameter's value appear in the response at all? No HTML metacharacters, so this alone can never reveal or corrupt HTML structure — a clean, unambiguous presence/absence check. This is also where reflection **context** is classified (see below), from this same clean response. |
| 2 | Context probe | `<sakannerXSSPROBE>"'` | Do HTML metacharacters (`<`, `>`, `"`, `'`) survive **unescaped** at the reflection point — i.e. is the reflection *dangerous*, not just present? |
| 3 | Validation probe | context-appropriate full payload (see below) | Does a complete, structurally valid executable payload — not just loose metacharacters — still reflect verbatim? The strongest evidence tier. |

The detector stops as early as possible: if probe 1 shows no
reflection, or probe 2 shows the reflection is safely encoded, no probe
3 is ever sent — "the detector should stop once sufficient evidence has
been established." Probe 3 only fires once probes 1 and 2 have already
established both reflection *and* danger.

Validation payload, by classified context:

```go
func validationPayload(ctx reflectionContext) string {
	if ctx == contextHTMLAttribute {
		return `x" onmouseover="` + reflectionMarker + `VALIDATE`
	}
	return "<script>" + reflectionMarker + "VALIDATE</script>"
}
```

Both are deterministic, non-destructive, and scoped narrowly to proving
script *would* execute (a full `<script>` element, or an event-handler
attribute) — never an attempt at persistence, data exfiltration, or any
form of post-exploitation.

## Reflection detection and encoding

Probe 1's result is a simple `bytes.Contains` check for the marker.
Probe 2's "dangerous" determination is likewise a single
`bytes.Contains(ctxBody, []byte(ctxPayload))` — the *entire* context
payload, metacharacters and all, must appear verbatim. This one check
implicitly handles every "safe transformation" the task asked about:
HTML-entity-encoding (`&lt;`, `&gt;`, `&#34;`, `&#39;`, or any other
encoded form) never produces the raw literal substring, so any of those
transformations — plus outright stripping/filtering, plus URL-encoding
(`%3C` etc.) — are all indistinguishable from "safe" by this check, and
all correctly result in no finding. There is no allow-list of "known
safe encodings" to maintain or get out of date; the bar is simply "did
the exact dangerous bytes survive."

## Context analysis

`classifyContext` looks at the HTML structure immediately **before**
the marker's position in probe 1's clean response (never probe 2's,
whose own injected metacharacters could otherwise be mistaken for
surrounding structure):

```go
lastLT := strings.LastIndex(before, "<")
lastGT := strings.LastIndex(before, ">")
insideTag := lastLT > lastGT   // an unclosed "<" after the last ">"

switch {
case insideTag && (strings.HasSuffix(before, `="`) || strings.HasSuffix(before, `='`)):
    return contextHTMLAttribute
case !insideTag:
    return contextHTMLText
default:
    return contextUnknown
}
```

- **`html_text`**: no unclosed tag precedes the marker — it's ordinary
  text content between tags (e.g. `<p>You searched for: MARKER</p>`).
- **`html_attribute`**: an unclosed tag precedes the marker, and the
  text immediately before it ends in `="` or `='` (e.g. `value="MARKER"`).
- **`unknown`**: anything else — e.g. inside an HTML comment
  (`<!-- MARKER -->`, an unclosed `<` from `<!--` with no attribute-quote
  suffix), a bare tag-name position, or the marker not found at all.
  This detector never guesses a context it can't classify this way —
  see "Confidence" below for what happens instead.

Only two contexts are reported ("Only add contexts that can be
reliably tested" — see also "Test Lab extension" below for why exactly
these two).

## Confidence

| Tier | Condition | Confidence |
|---|---|---|
| **High** | Validation probe's full payload reflects verbatim | 0.95 |
| **High** (partial) | Validation probe's marker survives but the full payload was modified/filtered | 0.6 |
| **Low** | Context probe shows danger, but context could not be classified (`unknown`) | 0.35 |
| *(none)* | Not reflected, or reflected but safely encoded/filtered | no finding |

This maps directly onto the task's own rubric: "High: strong evidence
of executable reflection" / "Medium: reflection and suspicious context
detected but validation incomplete" / "Low: reflection detected but
exploitability is uncertain." The 0.6 "partial validation" tier sits
between the two, deliberately — it is real evidence of raw
metacharacter survival (probe 2), just not a fully confirmed complete
payload (probe 3), so it is reported, not discarded, but at reduced
confidence, matching "Do not report a high-confidence vulnerability
when evidence is weak."

## Severity

Reuses `pkg/models.Severity`'s existing five-value scale, no new model.
Every finding uses `high`, matching the Phase 3 Test Lab ground truth's
`severity: high` for `VULN-XSS-REFLECTED-001` and
`VULN-XSS-REFLECTED-ATTR-001` — the rationale in both cases is
identical regardless of *where* in the page the injection lands: "can
execute arbitrary script in a victim's session, unauthenticated, no
interaction beyond a crafted link." Context (text vs. attribute)
changes exploit *mechanics*, not *impact*, so severity does not vary by
context in this implementation. Confidence, not severity, is what
varies with evidence strength (task's own example: "High severity + low
confidence is valid" — this detector's low-confidence, unknown-context
finding is exactly that case, still reported at high-severity-adjacent
`medium` given the genuine placement uncertainty, never silently
dropped).

## Evidence

Every finding's `Evidence` is one `detection.RequestResponseEvidence`
(the structured shape Phase 3.1 established), populated with: the GET
request line actually sent, the response status line, response headers
(flattened to one value per key), the specific `Parameter` and
`Payload` used, a **bounded** `ResponseFragment` (±80 bytes around the
reflection point — never the full response body), and `Observation`/
`Reason` strings explaining the classified context and why this
confidence tier was chosen. `maxBodySample` (256KB, matching
`internal/http.Prober`'s own bound) caps how much of any single
response is ever read into memory in the first place.

## Finding

Uses `pkg/models.Finding` unchanged (Phase 3.1's existing schema, no new
fields). The detector sets `VulnerabilityType`, `Title`, `Severity`,
`Confidence`, `AffectedParameter`, `Description`, `Remediation`, and
`Evidence`; the engine's `normalizeFinding` (Phase 3.1, unchanged) fills
`ID`, `ScanID`, `DetectorID`, `Host`, `Port`, `URL`, `Method`,
`AffectedEndpoint`, `Source`, and timestamps from the `Target` and
`Metadata()` — exactly the division of labor Phase 3.1 established for
every future detector.

## False-positive prevention

Every negative shape the task named is a distinct Phase 3 Test Lab
fixture, verified directly (not assumed):

| Negative shape | Fixture | Why this detector stays silent |
|---|---|---|
| Safely HTML-encoded reflection (text) | `/xss/reflected/safe` | Probe 2's raw payload never survives `html.EscapeString`-equivalent encoding |
| Safely HTML-encoded reflection (attribute) | `/xss/reflected/attribute/safe` | Same, in an attribute context |
| Non-reflected parameter | `/xss/reflected/unrelated` | Probe 1 finds no marker at all — stops after 1 request |
| Static content unrelated to the parameter | `/xss/reflected/static-decoy` | The page always contains `<script>legacyExampleWidget()</script>`-shaped text, but never the detector's own marker — probe 1 correlates its own probe, not "does `<script>` appear anywhere" |

## Controlled validation

The validation probe is the closest thing to "proof of exploitability"
this detector performs, and it is deliberately bounded: one additional
GET request with a benign, non-destructive payload (a script tag or
event-handler attribute containing only the detector's own marker
text — never a real payload that exfiltrates data, opens a shell,
modifies state, or persists anything). No cookies/sessions are
established or reused across probes, no follow-up requests are made
after a payload succeeds, and nothing about a positive result triggers
further, more aggressive probing — the detector stops the moment
sufficient evidence exists, in either direction (finding or no finding).

## Scope enforcement

Every request goes through `detection.Executor.Do` — the only
sanctioned request path Phase 3.1 established — never a
detector-private HTTP client. This detector never parses a response
body or a parameter's own value for a URL to dial; `requestURL` only
ever *replaces* `t.Parameter`'s value inside `t.URL` (already
scope-validated by the time `BuildTargets` produced `t`), and every
probe dials through `x.Do(ctx, t, req)`, bound to `t.Host`/`t.IP`.
`TestDetect_OriginalParameterValueCannotRedirectProbesElsewhere`
(unit test) proves this directly: even when a target's *original*,
Phase-2-discovered parameter value looks like a reference to an
out-of-scope host, the detector's own probes never dial anything but
the target's own `t.Host`/`t.IP`.
`TestDetect_OutOfScope_ReturnsErrorWithoutDialing` and
`TestPhase3_2_ReflectedXSSDetector_NegativeFixturesProduceNoFinding`
(lab, against the real lab with the real `ScopeSnapshot`) cover
the direct denial path. Redirect-to-out-of-scope and
crawler-never-follows-out-of-scope-link are properties of the shared
recon/executor layer (`safedial`, unchanged), already covered by
Phase 2/3's own scope tests (`TestPhase3Lab_CrawlerNeverFollowsOutOfScopeLinkFromVulnApp`,
`TestPhase3Lab_OpenRedirectToOutOfScopeIsTruncated`) — this detector
introduces no new way to reach a network address, so it inherits those
guarantees rather than needing to re-prove them independently.

## Request limits

- **Maximum 3 requests per candidate parameter** (reflection, context,
  validation — validation only if the first two establish danger).
- **Timeout**: `detection.ExecutorConfig.Timeout`, shared across every
  detector (not configurable per-detector).
- **Concurrency**: bounded by `detection.Executor`'s own semaphore,
  shared across every `(detector, target)` pair the engine runs — this
  detector holds no concurrency state of its own.
- **Cancellation**: every probe takes `ctx` through to `x.Do`; a
  cancelled context aborts the in-flight probe and the remaining probes
  in the same `Detect` call are never sent.
- **Rate limiting / total request budget**: `detection.Executor`'s
  shared `*rate.Limiter` and `MaxRequests` ceiling apply identically to
  every request this detector makes — no detector-specific rate control
  exists or is needed.

## Performance

`TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests` (unit
test) runs 20 candidates concurrently against a shared `Executor` and
asserts exactly `20 × 3 = 60` total requests — proving no request
multiplication across concurrent candidates, and (run under `-race`,
as the whole suite always is) no data races. The detector holds no
mutable state of its own (`Detector` is a zero-size struct), so there
is nothing for concurrent `Detect` calls to race on in the first place.

## Limitations

- **GET query parameters only** — see "Candidate selection" above.
- **Two reflection contexts** (`html_text`, `html_attribute`) — script
  context, URL context, and CSS context reflection are real reflected-XSS
  variants this detector does not attempt to classify or validate;
  reflection landing in one of those (or any other unrecognized
  structure) is reported at the `unknown`/low-confidence tier rather
  than misclassified.
- **No response-content-derived probing** — the detector never crawls,
  follows links found in a response, or uses response content to decide
  where to probe next; every probe targets the same, single endpoint
  URL the engine handed it.
- **No session/authentication handling** — matches Phase 3.1's own
  documented gap; every reflected-XSS fixture this detector is verified
  against is unauthenticated, consistent with
  `authentication_required: false` in ground truth for both positive
  fixtures.
