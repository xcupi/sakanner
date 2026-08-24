# Phase 3.10: Evidence & Reproducibility Engine

## Purpose

`internal/evidence` turns a Phase 3.8 `correlation.CanonicalFinding` and
a Phase 3.9 `risk.Assessment` into a `FindingPackage` a human analyst
can actually read and act on: what was tested, what was observed, why
it's a vulnerability, and how to safely reproduce it -- all sanitized,
bounded, hashed, and deterministic. It never re-detects, re-verifies,
exploits, or scores anything; it is a pure, one-way transform over data
those earlier phases already produced.

## Detector independence

Like `internal/correlation` and `internal/risk` before it, this package
contains **no vulnerability-specific logic**. It never branches on
`VulnerabilityType`, never knows what "XSS" or "SSRF" mean, and never
hardcodes a detector's field names. The one place detector-specific
data crosses in -- `DetectorFields` -- is extracted through a single
GENERIC key=value tokenizer (`parseDetectorFields`/`tokenizeKeyValue`
in `parse.go`) applied uniformly to every detector's `Observation`
string, because all six existing detectors independently converged on
the same `key=value key=value ...` convention for it. Adding a seventh
detector requires zero changes here as long as it follows that same
convention -- and if it doesn't, this package simply extracts fewer
fields, never crashes or misattributes.

## Architecture

```
correlation.CanonicalFinding  ---\
                                   >---  BuildEvidence  ---> []CanonicalEvidence
risk.Assessment                ---/            |
                                                v
                                          BuildPackage
                                                |
                                                v
                                         FindingPackage
```

- `model.go`: the canonical evidence model.
- `limits.go`: `Limits` and the shared `truncate` helper.
- `redact.go` / `redact_body.go`: secret redaction across headers,
  URLs, JSON/form/multipart bodies, and generic text.
- `binary.go`: binary response detection and safe summarization.
- `parse.go`: parsing the Phase 3.1 `RequestResponseEvidence` JSON
  contract and the generic detector-field tokenizer.
- `hash.go`: canonical serialization and SHA-256 identity/integrity.
- `summary.go`: deterministic human-readable summary/explanation text.
- `reproduction.go` / `reproduction_build.go`: the reproduction model
  and its construction from already-sanitized evidence.
- `engine.go`: `BuildEvidence` and `BuildPackage`, the two public entry
  points, plus dedup/ordering/limit enforcement.

## Canonical evidence model (task section 2)

```go
type CanonicalEvidence struct {
    EvidenceID            string
    FindingID             string
    Type                  EvidenceType
    Request               RequestEvidence
    Response              ResponseEvidence
    Baseline              *DifferentialEvidence
    Redirect              *RedirectEvidence
    Observation           string
    Verification          string
    Confidence            float64
    DetectorFields        map[string]string
    AuthenticationContext string
    Duration              time.Duration
    IntegrityHash         string
    CollectedAt           time.Time
}
```

`EvidenceID` and `IntegrityHash` are both derived from the SAME
canonical, redacted content (see "Hashing" below); `CollectedAt` and
`Duration` are excluded from that content on purpose (see
"Determinism").

## Evidence types (task section 3)

```
BASELINE  < PROBE  < OBSERVATION  < VERIFICATION  < REPRODUCTION
```

This fixed rank drives `sortCanonicalEvidence`. Every one of the six
real detectors today emits exactly one combined
`detection.RequestResponseEvidence` item per finding -- there is no
separately-persisted baseline, probe, or observation anywhere upstream.
Rather than inventing fake data to populate all five types, this
package makes an honest architectural choice:

- Every real detector's combined evidence item is classified
  **VERIFICATION** -- the type that generically and correctly
  describes "the evidence supporting this conclusion," for any
  detector, without guessing at an internal testing sequence no
  detector actually records.
- **REPRODUCTION** is always synthesized (see below) directly from
  fields already present on the VERIFICATION item -- never new
  detection logic, purely a repackaging of Method/URL/Parameter/Payload
  that were already captured.
- **BASELINE**, **PROBE**, and **OBSERVATION** are fully modeled and
  tested (`Diff`, `DifferentialEvidence`, `RedirectEvidence`) but
  unpopulated for every real finding today. This mirrors Phase 3.9's
  own precedent ("Exposure is UNKNOWN for every real finding today")
  rather than fabricating a baseline that was never actually captured.
  This is called out explicitly in every finding's `limitations[]`
  (see "Limitations" below), never silently hidden.

## Secret redaction (task sections 5-10)

One centralized blocklist per axis, checked case-insensitively, drives
every redaction path:

- `sensitiveHeaderNames` (`redact.go`): `Authorization`, `Cookie`,
  `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`, `X-Auth-Token`,
  `Api-Key`, `X-Access-Token`. Only the header VALUE is replaced with
  `<REDACTED>`; the header NAME is preserved so an analyst can still
  see that credentials were present.
- `sensitiveFieldNames` (`redact.go`): `password`, `passwd`, `secret`,
  `token`, `access_token`, `refresh_token`, `api_key`, `apikey`,
  `authorization`, `client_secret`, `session`, `private_key`. Drives
  redaction of query parameters, JSON/form body fields, multipart
  field names, and the generic free-text pattern below.

Four content-type-aware body redaction paths (`redact_body.go`):

- `application/json` -- real recursive unmarshal/redact/remarshal
  (`redactJSON`), handling nested objects and arrays.
- `application/x-www-form-urlencoded` -- real `url.ParseQuery`-based
  redaction (`redactForm`).
- `multipart/*` -- real MIME parsing via `mime`/`mime/multipart`
  (`redactMultipart`), matching each part's `Content-Disposition`
  `name=` against the blocklist and reassembling with the same
  boundary and headers.
- Anything else, or a body that fails to parse as its declared type --
  falls back to `redactText`'s generic `key=value`/`key: value` regex
  scan.

`redactURL` performs a structured, per-query-parameter pass first, then
a second `redactText` pass over the whole result -- because a
parameter's own VALUE can be a URL carrying its own embedded secret
(an SSRF target parameter whose value is
`http://internal/api?api_key=X`), which a top-level-keys-only pass
would never see.

This is explicitly a deterministic, pattern-based defense, never a
claim of perfect secret detection (task section 7) -- see "Known
trade-offs" below for the one documented gap.

## Control-character sanitization

Beyond named secrets, every non-sensitive header value is also passed
through `sanitizeControlChars`, which replaces raw CR, LF, and other C0
control bytes with visible two/four-character escapes (`\r`, `\n`,
`\xNN`). A target response containing
`X-Custom: value\r\nX-Injected: evil` can never have that reinterpreted
as a second header line by anything that later renders or re-emits
this stored evidence -- nothing is dropped, the original bytes remain
fully recoverable from the escaped text.

## Response bounding and truncation (task sections 20-21)

`Limits` (defaults: 20 evidence items/finding, 4KB request, 2KB
response excerpt, 2KB headers/metadata/reproduction) bound every
captured field. Critically, **truncation happens before sanitization**,
not after: `buildFromRawItem`/`buildResponseEvidence` call `truncate()`
first, then run redaction only on the bounded result. This means
sanitization cost always scales with the CONFIGURED LIMIT, never with
however large a response a target happened to send (see "Performance
fix" below for the bug this closes). A secret that straddles the
truncation boundary stays safe either way: a cut mid-VALUE still leaves
a recognizable key+separator+partial-value for the pattern to match; a
cut mid-KEY-NAME leaves a fragment that matches nothing and is
harmless.

## Binary response handling (task section 22)

`isBinaryContentType` (declared `Content-Type`) and `looksBinary`
(content-based: invalid UTF-8 or a NUL byte) together decide whether a
response is binary. A binary response is never stored as text --
`buildBinarySummary` computes `ContentType`, `SizeBytes`, a full
SHA-256 over the complete body, and a 16-byte hex sample prefix,
leaving `Response.Excerpt` empty. `looksBinary` deliberately scans the
FULL, untruncated fragment (a cheap linear byte scan) so truncating
first can never clip away the exact bytes that would have identified
genuinely binary content.

## Integrity hashing and evidence identity (task sections 15-18)

`canonicalHashInput` is the exact, explicit set of identity-bearing
fields (FindingID, Type, Request, Response, Baseline, Redirect,
Observation, Verification, Confidence, DetectorFields) -- deliberately
excluding `EvidenceID`/`IntegrityHash` (can't depend on themselves) and
`CollectedAt`/`Duration` (task section 26's "changed timestamp only ->
same hash"). `encoding/json.Marshal`'s guaranteed stable struct-field
order and alphabetically-sorted map keys make it a safe canonical
serializer without this package reimplementing anything. `IntegrityHash`
is the full 64-hex-character SHA-256; `EvidenceID` is its first 32
characters (128 bits) -- the same short-ID convention
`internal/correlation` and `internal/risk` already established.
Because every field is already redacted before this struct is built,
the hash itself never encodes a secret value.

## Deduplication and ordering (task sections 18-19)

`dedupeCanonicalEvidence` collapses items sharing the same `EvidenceID`
(first occurrence wins) -- since identity is derived purely from
canonical content, a resubmitted or byte-identical probe collapses
automatically, while two probes with even one different byte remain
distinct. `sortCanonicalEvidence` orders by `typeRank` then by
`EvidenceID` -- both fields excluded from timestamp/randomness, so
repeated runs against identical input always produce the identical
order.

## Reproduction (task sections 12-14, 34)

`buildReproductionInfo` derives `ReproductionInfo{Method, URL,
Parameter, SafeTestValue, ExpectedBehavior, ObservedBehavior, Level,
Notes}` from the already-sanitized VERIFICATION item -- never from raw
detector output again, and never a newly-invented payload:
`SafeTestValue` is extracted directly from the sanitized URL's own
query string via `safeTestValueFromURL`, so reproduction only ever
proves the finding using the same value the detector itself already
used. `buildReproductionEvidence` wraps the same data as one more
REPRODUCTION-typed `CanonicalEvidence` item, so it's represented both
as a typed evidence entry and as `FindingPackage.Reproduction` -- two
views of one underlying source, never two independently-derived (and
possibly inconsistent) ones.

`ReproducibilityLevel` (`reproducibilityLevelOf`) is classified from
structural facts, never optimistically:

- **LIMITED** -- no Method/URL available at all (raw evidence failed
  to parse).
- **PARTIAL** -- Parameter or SafeTestValue missing, anything was
  truncated, or the URL/SafeTestValue carries the redaction
  placeholder.
- **FULL** -- every required field present, nothing truncated, nothing
  redacted.

A finding whose reproduction depends on a value this engine itself
redacted (e.g. the vulnerable parameter is itself named `token`) can
therefore never claim FULL -- task section 34's explicit prohibition,
enforced structurally rather than by convention.

## Summary and "why vulnerable" (task section 31)

`Summarize`/`WhyVulnerable` (`summary.go`) generate short, deterministic,
template-based sentences from the finding's vulnerability type label,
parameter, path, and the VERIFICATION item's own verification/reason
text -- no LLM, no free-form generation, the same sentence every time
for the same input.

## Limitations (task section 32)

`limitationsFor` generates an honest `[]string` from structural facts,
never hiding uncertainty:

- No separate baseline request/response was persisted (true for every
  real finding today -- see "Evidence types" above).
- Response or request evidence was truncated to stay within limits (if
  applicable).
- Reproduction information is incomplete (if `Level != FULL`).

## Safe authentication context (task section 33)

`authContextOf` reports only whether SOME header name suggests
authentication was in play (`"authenticated"` or `""`) -- never the
header's own value, never a credential, never an identity.

## Known trade-offs

- `keyValuePattern`'s value character class excludes `/` and `:` on
  top of the obvious delimiters. Without that exclusion, an embedded
  URL (`http://internal/api?api_key=X`) produces a false match at
  `http:` itself, greedily consuming the entire rest of the string as
  one bogus "value" and hiding the genuinely sensitive `api_key=X` a
  few characters later (`ReplaceAllStringFunc` never re-scans inside
  an already-consumed match). Excluding `/`/`:` makes `http:` fail to
  match, so the scan continues past the URL's own scheme/host and
  finds `api_key=X` on its own. The trade-off: a secret value that
  itself legitimately contains `/` or `:` survives THIS generic
  fallback pattern uncaught -- the structured JSON/form/multipart
  parsers have no such gap, since they parse real field boundaries
  rather than scanning text.
- BASELINE/PROBE/OBSERVATION evidence types, `DifferentialEvidence`,
  and `RedirectEvidence`/`Duration` are fully implemented and tested
  but unpopulated for every real detector today (see "Evidence types").

## Scope enforcement (task section 25)

This package never dials, resolves, or fetches anything -- it has no
network import at all (enforced by a static AST check in
`security_test.go`). It only ever transforms `EvidenceItem.Content`
strings the scanner already captured during detection, so it is
structurally incapable of expanding scope.

## Security considerations (task section 36)

No `os/exec`, `syscall`, `net`, `net/http`, `text/template`, or
`html/template` import anywhere in this package (statically enforced).
HTML, shell metacharacters, and script-like payloads are stored as
inert text -- there is no code path that could execute, render, or
evaluate them. CRLF, control characters, null bytes, huge strings
(20MB+), Unicode/RTL-override sequences, malformed URLs/headers, fake
secrets amid adversarial formatting, and deeply nested JSON (2000+
levels) are all exercised without a crash.

## Performance (task section 40)

Truncation runs before sanitization (see above), so cost scales with
the configured limit, not the target's response size. 10,000 findings
build in well under a second without `-race`; scaling from 500 to
5,000 findings stays comfortably sub-quadratic.

## Concurrency (task section 41)

`BuildEvidence`/`BuildPackage` hold no package-level mutable state --
every function is a pure computation over its arguments plus a fresh
`time.Now()` per call -- so concurrent use needs no locking. Verified
under `go test -race`: 100 concurrent calls against the same finding
produce byte-identical evidence-ID sequences; concurrent calls across
distinct findings never cross-contaminate.
