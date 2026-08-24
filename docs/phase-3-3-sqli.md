# Phase 3.3: SQL Injection Detector

sakanner's second real vulnerability detector. Implements
`detection.Detector` (`internal/detection`, Phase 3.1) unchanged --
nothing in the framework was modified to build this; see
[docs/phase-3-1-detection-engine.md](phase-3-1-detection-engine.md)
"How to implement a new detector" for the contract this follows, and
[docs/phase-3-2-reflected-xss.md](phase-3-2-reflected-xss.md) for the
sibling detector this one's structure closely mirrors.

**Detection only.** Every probe payload is a read-only boolean
condition (`OR '1'='1'` / `AND '1'='2'`) or a single syntax-breaking
character (`'`) -- chosen to reveal behavior, never to change or
retrieve data.

## What this detector does NOT do

- **Data extraction** -- no probe ever attempts to read out actual
  database contents (table names, column names, row values beyond what
  the application already returns for a normal request).
- **Database/table enumeration** -- no `UNION SELECT`, no
  `information_schema` probing, nothing that maps database structure.
- **Credential dumping** -- never attempts to read user/password tables
  or any authentication-related data.
- **Destructive queries** -- no `DROP`, `DELETE`, `UPDATE`, `INSERT`,
  `ALTER`, `CREATE`, ever, anywhere in any payload this detector sends.
- **OS command execution** -- no attempt at `xp_cmdshell`,
  `LOAD_FILE`, `INTO OUTFILE`, or any database-functionality-as-RCE
  vector.
- **Post-exploitation of any kind** -- the moment sufficient evidence
  exists, the detector stops; it never chains a confirmed finding into
  a further, more invasive probe.

## Architecture

```
internal/detectors/sqli/
├── detector.go        Detector, Metadata, Eligible, Detect, finding construction
├── errorpatterns.go    dbErrorPattern table + matchDBError -- the maintainable,
│                       testable error-signature abstraction (section 16)
└── normalize.go         normalizeBody (digit-run collapsing) + stripPayload
                          (echoed-parameter false-positive fix)

cmd/scanner/detectors.go   productionRegistry() registers sqli.New()
                            alongside xssreflected.New()
```

Like `xssreflected`, `Detector` is a stateless zero-size struct -- every
piece of state a `Detect` call needs (`Target`, `Executor`) is passed
in.

## Candidate selection (target selection)

Identical eligibility shape to `xssreflected`, for the identical reason:

```go
SupportedTargetTypes: []detection.TargetKind{detection.TargetKindEndpoint}
SupportedMethods:     []string{http.MethodGet}
```

plus `Eligible(t)` requiring `t.Parameter != "" && t.ParameterLocation
== "query"`. `internal/detection.BuildTargets` (Phase 3.1) only
produces `Parameter`-bearing targets from query strings already
observed on crawled URLs -- no form-field or JSON-body parameter
surface exists in Phase 2's recon model yet, so POST/API-body
parameters are out of scope for this phase, the same honestly-documented
gap `xssreflected` already carries.

## Baseline

The first of four requests per candidate: `id=1` (a plain, syntactically
inert control value). Its purpose is twofold:

1. **Differential comparison needs something to compare against** --
   without it, "the response changed" has no reference point.
2. **False-positive prevention for the error signal** -- an endpoint
   that already shows database-error-shaped text for a completely
   benign, non-malicious request is a *generically misbehaving*
   endpoint (or one whose static content happens to mention "database
   error"), not evidence of injection. The error probe's result is only
   ever trusted when it *differs* from this baseline (see "Error-based
   detection" below).

The baseline is never itself compared for a boolean-differential
signal -- that comparison is strictly between the two controlled
boolean probes (see "Differential detection").

## Probes

Exactly **four** requests per candidate parameter, no more, each
serving one distinct purpose:

| # | Category | Payload | Purpose |
|---|---|---|---|
| 1 | Baseline | `1` | Reference point (see above) |
| 2 | Syntax/error | `'` | The smallest possible syntax-breaking input -- reveals whether unescaped input reaches SQL syntax at all, without itself altering query semantics |
| 3 | Boolean condition A (true) | `1' OR '1'='1` | A tautology: if concatenated unsanitized, always evaluates true |
| 4 | Boolean condition B (false) | `1' AND '1'='2` | A contradiction: under the same conditions, always evaluates false |

Probes 3 and 4 together are the "controlled condition A vs. condition
B" comparison. All four requests are always sent once a candidate is
eligible (no early-exit path) -- with only 4 requests total, the cost
of always gathering the full evidence picture is small, and it keeps
the confidence-tiering decision (see "Confidence" below) simple and
fully deterministic rather than depending on request order.

## Error-based detection

`errorpatterns.go`'s `dbErrorPatterns` table holds phrase lists for five
database families (MySQL/MariaDB, PostgreSQL, MSSQL, SQLite, Oracle)
plus a lower-priority `generic` fallback (cross-family wording like "sql
syntax", "database error") -- data, not scattered regexes through
`detector.go`, per the task's explicit "maintainable pattern
abstraction" requirement. `matchDBError` prefers a family-specific match
over generic, matching case-insensitively against several candidate
phrases per family rather than one exact string (see
`errorpatterns_test.go` for one test per family).

**Database error text alone is never sufficient for a finding.**
`computeSignals` correlates the error probe's result against the
baseline first: if baseline *already* shows the identical error family
for a plain, benign request, the probe's matching error carries zero
additional weight (`errorSignal := errMatched && !(baselineMatched &&
baselineFamily == errFamily)`). This is what makes the "generic
unrelated error" negative fixture (`/sqli/generic-error`, always 500
with "Database error: ..." regardless of input) correctly produce no
finding: the baseline itself already shows that exact error.

## Differential detection

`sig.booleanDiff` is `true` when the (normalized, payload-stripped --
see below) true-condition and false-condition response bodies differ.
This is the strongest single signal this detector has: a genuine
behavioral difference correlated to a controlled true/false condition
pair is direct evidence of data exposure, independent of whether any
error text ever surfaced (see `/sqli/boolean/vulnerable`, a fixture
built specifically to prove this path works with *zero* error signal
involved).

### The reflected-parameter false positive (and its fix)

A real false positive was found during Phase 3.3's own broad
integration testing (see "Adversarial testing" in
[docs/phase-3-3-acceptance-test.md](phase-3-3-acceptance-test.md)):
**any endpoint that simply echoes its parameter back** -- a
reflected-XSS-shaped page, an open redirect's Go-stdlib-generated
`<a href="...">Found</a>` body, a "page not found: X" message -- showed
a false differential, for the trivial reason that the *true* and
*false* payload strings are different strings from each other, with no
SQL logic involved anywhere.

Fixed by `stripPayload` (`normalize.go`): before comparing, each body
has its *own* probe payload removed -- raw, HTML-entity-encoded (the
exact form `html.EscapeString` produces), and URL-percent-encoded --
so an endpoint that only echoes input shows *identical* stripped bodies
regardless of which payload was sent, while a genuine SQL-driven
difference (`"results: alice, bob, admin"` vs. `"results: (none)"` --
neither of which contains the payload text at all) is completely
unaffected. `TestComputeSignals_NoFalsePositiveWhenPayloadEchoedRaw`/
`...HTMLEscaped` and `TestDetect_ReflectedParameterUnrelatedToSQL_NoFinding`
lock this in; `TestComputeSignals_GenuineDifferenceStillDetectedAfterStripping`
proves the fix doesn't mask real evidence.

## Response normalization

`normalizeBody` collapses every run of ASCII digits to a single `#`
before comparison -- timestamps, request counters, tracking IDs all
normalize identically regardless of their actual value (see
`/sqli/dynamic`, whose responses genuinely differ byte-for-byte on
every request via an incrementing counter, but whose *meaningful*
content -- `"results: (none)"` -- never changes). This deliberately does
**not** attempt to normalize non-digit dynamic content (a random string,
a rotating word) -- over-normalizing risks erasing the very behavioral
difference detection depends on; digit-run collapsing is what every
dynamic-but-safe fixture this detector is verified against actually
needs. See "Limitations" below.

## Confidence and severity

| Signals | Severity | Confidence | Rationale |
|---|---|---|---|
| Family-specific error **and** boolean differential | critical | 0.95 | Multiple independent, consistent signals -- the strongest possible evidence |
| Boolean differential alone | critical | 0.75 | A proven, controlled behavioral difference is strong evidence on its own, even with no corroborating error text |
| Family-specific error alone | high | 0.55 | A real database-family signature is a strong indication, but not confirmed by behavior |
| Generic error text only | medium | 0.3 | Weak indication -- cross-family wording alone, unconfirmed |
| Neither | -- | -- | No finding |

This maps directly onto the task's HIGH/MEDIUM/LOW confidence rubric.
Severity reuses `pkg/models.Severity` unchanged, matching the Phase 3
Test Lab ground truth's `severity: critical` for both `VULN-SQLI-001`
and `VULN-SQLI-BOOLEAN-001` -- confidence, not severity, is what carries
the evidence-strength distinction (a finding can be `critical` severity
at `0.3` confidence: the *impact* if real is still critical, the
*certainty* is what varies). No CVSS calculation is implemented, per
task scope.

## Confirmation

The strongest tier (0.95) requires the combination the task calls
"multiple supporting signals": an error signature independently
observed AND a boolean differential independently observed. Neither
signal alone reaches that tier. No exploitation (data extraction,
enumeration) is ever attempted to "confirm" a finding further -- the
detector stops at 4 requests regardless of outcome.

## Evidence

Every finding's `Evidence` is one `detection.RequestResponseEvidence`
(Phase 3.1's structured shape): the four payloads sent, each probe's
status code, the matched error family (if any) and whether a boolean
differential was observed, a **bounded** `ResponseFragment` (±80 bytes
around the matched error text or, failing that, the true-probe payload
-- never the full response), and a `Reason` string naming exactly which
signals produced this confidence tier. `maxBodySample` (256KB, matching
`xssreflected`/`internal/http.Prober`) caps every response read.

## Finding

Uses `pkg/models.Finding` unchanged. The detector sets
`VulnerabilityType` (`sql_injection`), `Title`, `Severity`,
`Confidence`, `AffectedParameter`, `Description`, `Remediation`, and
`Evidence`; the engine's `normalizeFinding` (Phase 3.1, unchanged) fills
`ID`, `ScanID`, `DetectorID`, `Host`, `Port`, `URL`, `Method`,
`AffectedEndpoint`, `Source`, and timestamps.

## False-positive prevention

Every negative shape the task named is a distinct Phase 3 Test Lab
fixture, verified directly (not assumed) via
`lab/phase3_3_sqli_test.go`:

| Negative shape | Fixture | Why this detector stays silent |
|---|---|---|
| Parameterized/safe query | `/sqli/safe` | The `id` parameter is always an opaque value lookup; true/false probes produce identical `"results: (none)"` |
| Boolean-shaped safe query | `/sqli/boolean/safe` | Same, exercising the boolean-only path specifically |
| Generic HTTP 500 / DB-sounding error unrelated to input | `/sqli/generic-error` | Baseline shows the identical error, so it carries no weight |
| Dynamic page (normal responses vary) | `/sqli/dynamic` | The only raw variance is a digit-run counter; normalization erases it |
| Reflected/echoed parameter (no database involved) | (regression coverage; see "The reflected-parameter false positive" above) | `stripPayload` removes each probe's own payload text before comparing |

## Deduplication

Reuses `internal/detection.Deduplicate` (Phase 3.1) unmodified -- no
second mechanism. `Detect` returns at most one finding per call; the
dedup key (`DetectorID`, `Host`, `Port`, `AffectedEndpoint`, `Method`,
`AffectedParameter`, `VulnerabilityType`) collapses the same vulnerable
parameter discovered via multiple recon sources (e.g. both a crawled
link and a direct crawl visit to the same URL) into one persisted
finding. `TestDetect_IdenticalFindingsAcrossTwoRunsDeduplicate` and
`TestPhase3_3_SQLiDetector_MatchesGroundTruth`'s `Duplicates == 0`
assertion (against the real lab, real crawl, real multi-source
discovery) both confirm this.

## Scope enforcement

Every request goes through `detection.Executor.Do` -- the same choke
point `xssreflected` uses, never a detector-private client. No response
body, header, or parameter value is ever parsed as a URL to dial.
`TestDetect_OutOfScope_ReturnsErrorWithoutDialing` (unit) and
`TestPhase3_3_SQLiDetector_NegativeFixturesProduceNoFinding`
(integration, against the real lab with the real `ScopeSnapshot`) cover
the direct denial path; redirect-to-out-of-scope and
crawler-never-follows-out-of-scope-link are inherited, unmodified
properties of the shared `safedial`/crawler layer.

**Redirects are not followed by default** (`ExecutorConfig.MaxRedirects`
defaults to `0`) -- this detector receives the redirect response itself
(status + `Location` header + auto-generated body), never whatever is
at the destination, which is also *why* the redirect-body-echo false
positive above was reachable at all (the auto-generated "Found" body
still echoes the `Location` value) and exactly what `stripPayload`
neutralizes.

## Request limits

- **Maximum 4 requests per candidate parameter**, always (baseline +
  error + true + false) -- no conditional early-exit, no additional
  confirmation round.
- **Timeout / concurrency / rate limiting / total request budget**: all
  inherited from the shared `detection.Executor`, identical to
  `xssreflected` -- no detector-specific controls exist or are needed.
- **Cancellation**: every probe takes `ctx` through to `x.Do`; a
  cancelled context aborts the in-flight probe and stops the remaining
  probes in the same `Detect` call from ever being sent
  (`TestDetect_CancellationDuringBaseline` proves at most the baseline
  request reaches the server).

## Performance

`TestDetect_ManyConcurrentCandidates_NoRaceNoExcessRequests` runs 15
candidates concurrently against a shared `Executor` and asserts exactly
`15 × 4 = 60` total requests -- no request multiplication across
concurrent candidates, and (run under `-race`, as the whole suite always
is) no data races. `Detector` holds no mutable state of its own.

## Limitations

- **GET query parameters only** -- see "Candidate selection."
- **Digit-run normalization only** -- genuinely non-digit dynamic
  content (a rotating word, a random-looking but non-numeric token)
  is not normalized away; a fixture built around that shape could in
  principle still produce a false positive. Digit-run collapsing is
  what every fixture this detector is verified against actually
  requires; broader normalization is a documented gap, not attempted
  here to avoid risking erasure of genuine evidence.
- **No time-based blind SQLi detection** -- this detector never measures
  response timing as a signal (the task's own baseline list mentions
  timing "where already supported"; Phase 3.1's `Executor`/`Target`
  carry no timing-measurement primitive yet, so this is an honestly
  documented absence, not an oversight).
- **No stacked-query or second-order SQLi detection** -- only the
  immediate response to each probe is examined; a payload that only
  manifests behavior on a *later*, unrelated request is out of reach
  for the same reason `xssreflected` cannot detect stored XSS.
- **Five database families** -- MySQL/MariaDB, PostgreSQL, MSSQL,
  SQLite, Oracle, plus a generic fallback. A database family not
  represented in `dbErrorPatterns` falls back to the generic tier (low
  confidence) rather than going unrecognized entirely, but its errors
  won't reach the higher-confidence family-specific tier until a
  pattern is added.
