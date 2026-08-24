# Phase 3.33: Active Detection Coverage Review & Next Detector Selection

**This is a review-only phase. No production code was modified.** Every
claim below was verified directly against the current repository
(source reads and targeted `grep`, not trust in prior phase docs) —
where a prior phase's own documentation turned out to be stale, that
is called out explicitly.

## 1. Executive Summary

sakanner currently ships **14 detector packages** (20 registered
instances counting `idor-active`'s conditional variant), split evenly
between 6 legacy/passive (heuristic, response-analysis-only) and 8
active (mutation-based, strong-evidence) detectors, covering **7
vulnerability classes**: XSS (reflected), SQL injection, command
injection, SSRF, IDOR/BOLA, path traversal, open redirect, and SSTI.
Every passive detector has an active sibling except two active-only
classes (open redirect, SSTI) that were built directly as active
detectors with no legacy predecessor.

This review found the architecture **broadly sound and genuinely
reusable** for several new candidate classes without major new
infrastructure — but it also surfaced **two confirmed, previously
undocumented foundational issues** that materially affect what should
happen next:

1. **Evidence redaction is a presentation-layer-only, in-memory
   operation that never reaches storage.** Every finding's evidence is
   persisted, unredacted, by `internal/detection.Engine.Run` the
   instant a detector reports it — before correlation, before the
   Evidence stage's redaction pass ever runs. The redacted copy that
   pass produces is architecturally incapable of being written back
   (`storage.FindingRepository` has no `Update` method at all), so
   `scanner findings show`, `scanner findings show --curl`, and
   `scanner report --format json` all read the raw, unredacted row.
   Today's concrete blast radius is narrow — one detector
   (`xss-reflected`) captures full raw response headers (including any
   `Set-Cookie`) into evidence — but the architectural guarantee itself
   does not exist for any future detector either.
2. **The mutation engine's documented "hard ceiling" on requests per
   target/scan is not actually wired into production.**
   `mutation.ExecutorConfig.MaxMutationsPerTarget`/`MaxTotalMutations`
   are never set by `cmd/scanner/scan.go` (they default to `0`, meaning
   unbounded), and there is no config surface to set them at all. This
   is currently masked by every active detector's own small, fixed
   payload lists, but the promised backstop does not fire, and a
   config-list-driven detector (like the existing, currently-disabled
   `idor`/`traversal`) would have zero enforced ceiling if enabled with
   a large list.

Both are detailed in Section 10. Per this phase's own instruction, they
are **reported, not fixed**, and shape the Section 12 recommendation:
Phase 3.34 should close the storage-time redaction gap **before or
alongside** any new detector, since every new detector added on top of
today's architecture inherits the same unredacted-persistence
guarantee gap.

Setting that aside, the review's **top recommended next detector is
CORS Misconfiguration** — see Section 11 for the full ranked list and
rationale.

## 2. Current Detector Inventory

### 2.1 Legacy / passive detectors (6) — GET + query-parameter only

| ID | Package | Evidence strategy | Enabled | Auth | Multi-identity | Lab | E2E |
|---|---|---|---|---|---|---|---|
| `xss-reflected` | `xssreflected` | 3-tier marker→context→validation-payload HTML reflection classification | Yes | implicit session | No | `lab/phase3_2_reflected_xss_test.go` | indirect (default-registry scans) |
| `sqli` | `sqli` | DB-error-family regex + payload-stripped boolean differential | Yes | implicit session | No | `lab/phase3_3_sqli_test.go` | indirect |
| `ssrf` | `ssrf` | OOB callback correlation (primary), weak response-diff fallback | **No** — nil `CallbackClient` in production | implicit session | No | `lab/phase3_4_ssrf_test.go` | indirect |
| `idor` | `idor` | Owner-baseline vs. operator-supplied cross-`AuthContext` comparison | **No** — `idor.New(nil)` | manual per-context headers, not scan session | Architecturally yes, never wired live | `lab/phase3_5_idor_test.go` | none dedicated |
| `path-traversal` | `traversal` | Operator-configured `TraversalCase{RelativePath,Marker}`, marker match (confirmed tier) or weak diff (suspicious tier) | **No** — `traversal.New(nil)` | implicit session | No | `lab/phase3_6_traversal_test.go` | none dedicated |
| `command-injection` | `cmdinjection` | Fresh-UUID marker, exact `markerPrefix+token` match only | Yes (self-contained, no external config needed) | implicit session | No | `lab/phase3_7_cmdinjection_test.go` | none dedicated |

All six are IMPLEMENTED for query-parameter GET requests only. `ssrf`,
`idor`, and `path-traversal` are **DISCOVERY-LIMITED in production
specifically because they require operator-supplied ground truth**
(a callback client, ownership map, or known traversal case) that
nothing in `cmd/scanner` currently wires up — they fail closed
(`OutcomeSkipped`) rather than guess, by design.

A real, previously-fixed false-positive class recurs across three of
these detectors' own phase docs: **the reflected-parameter false
positive** — an endpoint that merely echoes its own input produced
spurious differential signal until `sqli`/`ssrf`/`idor`/`path-traversal`
each added payload-stripping before comparison.

### 2.2 Active detectors (8) — mutation-engine-based, strong evidence

| ID | Package | Locations | Evidence strategy | Enabled | Multi-identity |
|---|---|---|---|---|---|
| `xss-reflected-active` | `xssactive` | query(GET)/form/body(JSON)/path | Context-classified reflection (`none/html_encoded/exact/attribute/javascript/json_string`); encoded reflection never a finding | Yes | No |
| `sqli-active` | `sqliactive` | query(GET)/form/body/path | Same error-family+boolean-differential idea as `sqli`, independently re-derived via `mutation.Compare` | Yes | No |
| `command-injection-active` | `cmdinjectionactive` | query(GET)/form/body/path | Same UUID-marker exact-match strategy as `cmdinjection` | Yes | No |
| `ssrf-active` | `ssrfactive` | query(GET)/form/body/path | Two independent strong modes: scanner-owned internal-resource marker in target's own response, OR OOB callback | **No** | No |
| `path-traversal-active` | `traversalactive` | query(GET)/form/body/path | Exact `Marker` match only — no weak tier at all | **No** | No |
| `open-redirect-active` | `openredirectactive` | query(GET)/form/body/path | Genuine 3xx + RFC-3986-resolved `Location` exactly matching an operator-configured out-of-scope destination | **No** | No |
| `ssti-active` | `sstiactive` | query(GET)/form/body/path | Two random primes' numeric product, isolated-token match — no parameter-name gate | Yes | No |
| `idor-active` | `idoractive` | query(GET)/form/body/path, GET-only | Baseline / cross-identity / known-bad-control 3-probe comparison, requires a genuinely second, independently-authenticated identity | Conditional on `--authz-identity` | **Yes — the only production multi-identity detector** |

None of the 8 active detectors touch HEADER or COOKIE locations —
see Section 3 for why that's a dead-code gap, not a missing feature at
the mutation-engine layer.

**Correlation/chains participation**: every persisted `models.Finding`
(from either passive or active detectors) is eligible for both
`internal/correlation`'s dedup pass and `internal/chains`' relation
analysis — participation is structural (any Finding qualifies), not
detector-specific opt-in.

**Known, currently-accepted limitations across every detector class**:
GET/query-heavy bias in the 6 legacy detectors; no stored/DOM/blind XSS;
no time-based blind SQLi; no write-path (POST/PUT/DELETE) traversal or
IDOR testing; SSRF has no production OOB infrastructure; `idor`/
`path-traversal`/`ssrf` (legacy) all require operator-supplied ground
truth not currently exposed by any CLI flag.

## 3. Input/Mutation Coverage Matrix

```
                     QUERY   FORM   JSON   PATH   HEADER   COOKIE
XSS (reflected)       ✓       ✓      ✓      ✓       ✗        ✗
SQLi                  ✓       ✓      ✓      ✓       ✗        ✗
IDOR/BOLA              ✓*      ✓*     ✓*     ✓*      ✗        ✗
SSRF                  ✓       ✓      ✓      ✓       ✗        ✗
Command Injection     ✓       ✓      ✓      ✓       ✗        ✗
Path Traversal         ✓       ✓      ✓      ✓       ✗        ✗
Open Redirect          ✓       ✓      ✓      ✓       ✗        ✗
SSTI                   ✓       ✓      ✓      ✓       ✗        ✗
```
`✓* ` = `idoractive`'s `Eligible()` does not check `ParameterLocation`
at all (unlike every other active detector), so it is mechanically
eligible across all four non-header/cookie locations, but is GET-only.

**This matrix overstates real-world JSON coverage.** `mutation.Mutate`
fully implements `LocationJSON`, and `BuildTargets`
(`internal/detection/targets.go:131`) will emit a JSON-body Target —
**but only when `Provenance == "REQUEST_INPUT"`**. The live crawl
pipeline can **never** produce that provenance for a JSON parameter:
`internal/crawler` only ever captures a JSON **response** body
(`crawler.go:63-72`, explicit doc comment: "this crawler never issues
anything but GET"), and the one production caller of JSON parsing,
`parameters.NormalizeJSONResponses`, hardcodes
`ProvenanceResponseField` (`normalize.go:142`). Every existing JSON
mutation test (`lab/phase3_19_active_detection_test.go:273-320` et al.)
proves this path by **directly persisting** a synthetic
`models.Parameter{Location:"json", Provenance:"REQUEST_INPUT"}` row via
`store.Parameters().Create`, bypassing the crawler entirely — it is a
mutation-engine capability proof, not a live-discovery capability
proof. **A directly-persisted synthetic parameter is not evidence the
live crawler supports JSON input discovery, and this review does not
treat it as such.**

**HEADER and COOKIE columns are entirely dead code from a
live-detection standpoint**, despite being fully implemented, wire-
capable, and unit-tested at the `internal/mutation` layer
(`Mutate`'s `applyHeader`/`applyCookie`, `Executor.buildHTTPRequest`
actually placing a mutated header/cookie onto the real outgoing
request). Nothing in `BuildTargets`, and no detector's `Eligible()`,
ever produces or accepts a `"header"`/`"cookie"` `ParameterLocation`.
This is the single most consequential piece of evidence for Section 4:
several strong candidate classes (CORS, Host Header Injection, CRLF/
header injection) are gated on closing this ONE specific, narrow,
already-tested gap — not on building new mutation infrastructure from
scratch.

## 4. Candidate Vulnerability Matrix

| Candidate | Classification |
|---|---|
| XXE | REQUIRES MAJOR FOUNDATION |
| NoSQL Injection (query-string operator syntax) | READY WITH SMALL FOUNDATION |
| NoSQL Injection (JSON-body operator syntax) | REQUIRES MAJOR FOUNDATION (blocked by JSON discovery gap) |
| LDAP Injection | READY WITH SMALL FOUNDATION |
| XPath Injection | READY WITH SMALL FOUNDATION (low practical value) |
| Expression Language Injection | **substantially already covered by `ssti-active`** — not a distinct candidate |
| Prototype Pollution | REQUIRES MAJOR FOUNDATION |
| HTTP Request Smuggling | REQUIRES MAJOR FOUNDATION / NOT APPROPRIATE FOR THIS ARCHITECTURE |
| CRLF / HTTP Header Injection | REQUIRES MAJOR FOUNDATION (general case); narrow reflected-header sub-case is READY WITH SMALL FOUNDATION |
| Host Header Injection | READY WITH SMALL FOUNDATION |
| Web Cache Poisoning | REQUIRES MAJOR FOUNDATION / NOT APPROPRIATE FOR THIS ARCHITECTURE |
| CORS Misconfiguration | READY WITH SMALL FOUNDATION |
| OAuth Misconfiguration | NOT APPROPRIATE FOR THIS ARCHITECTURE |
| JWT-related vulnerabilities | READY WITH SMALL FOUNDATION (conditional on JWT-based auth being configured) |
| GraphQL-specific vulnerabilities | REQUIRES MAJOR FOUNDATION |
| SSTI | **already IMPLEMENTED** (`ssti-active`, Phase 3.29) — not re-evaluated as a candidate |
| CSRF | READY WITH SMALL FOUNDATION for a heuristic-only missing-token check; strong exploit proof SHOULD REMAIN MANUAL |
| Authentication/Session weaknesses | READY |
| Authorization/BOLA/IDOR extensions (BFLA) | READY WITH SMALL FOUNDATION |
| File Upload vulnerabilities | REQUIRES MAJOR FOUNDATION |
| Deserialization | REQUIRES MAJOR FOUNDATION / NOT APPROPRIATE FOR THIS ARCHITECTURE |
| Business Logic vulnerabilities | SHOULD REMAIN MANUAL / OPERATOR-DRIVEN |
| Race-condition vulnerabilities | SHOULD REMAIN MANUAL / OPERATOR-DRIVEN |
| Information Disclosure / sensitive-data exposure | READY |
| API-specific authorization issues | Same as Authorization/BOLA/IDOR extensions — READY WITH SMALL FOUNDATION |

## 5. Readiness Classification — evidence-based criteria (A–M)

Applied to the five strongest candidates (full detail; remaining
candidates summarized in Section 4's table with reasoning inline
above).

### CORS Misconfiguration — READY WITH SMALL FOUNDATION
- **A (discover input)**: Yes — needs no parameter discovery at all,
  only one probe per already-discovered HTTP service (`recon`'s
  existing `internal/http.Prober` output).
- **B (mutation.represent)**: Yes — `mutation.LocationHeader` already
  exists and is tested (`mutate_test.go:495-541`); sending a custom
  `Origin` header is a one-line `mutation.Mutation{Location:
  LocationHeader, Parameter: "Origin", ...}`.
- **C (executor safety)**: Yes — `mutation.Executor.buildHTTPRequest`
  already sends mutated headers on the wire (`executor.go:262-292`);
  goes through the same `safedial`-validated client as every other
  detector.
- **D (identity preserved)**: Yes — same `IdentityContext` threading
  every other detector already gets for free.
- **E (scope)**: Yes — no new host is ever contacted; the probe targets
  the same in-scope service.
- **F (deterministic evidence)**: Yes — `Access-Control-Allow-Origin`
  either verbatim-reflects an attacker-chosen Origin (with
  `Access-Control-Allow-Credentials: true`) or it doesn't; no
  differential-response ambiguity.
- **G (strong proof)**: Yes — this is a structural response-header
  fact, not a heuristic.
- **H (lab fixture)**: Yes — trivial to add a `lab/harness_*.go`
  handler that reflects Origin unconditionally.
- **I (no contamination)**: Yes — a single new probe type, no overlap
  with existing detectors' evidence.
- **J (resource bound)**: Yes — one probe per HTTP service, not per
  parameter; cheapest possible new detector by request count.
- **K (evidence/risk pipeline)**: Yes — same `models.Finding`/
  `RequestResponseEvidence` path every detector already uses.
- **L (chains)**: Yes — raw `Finding`, same isolation rules apply.
- **M (Phase 3.32 inspection)**: Yes — `findings show`/`--curl`
  already handle any finding uniformly.

### Host Header Injection — READY WITH SMALL FOUNDATION
Same A–M profile as CORS (same `LocationHeader` foundation), with one
weaker point: **F/G are narrower** — the strongest deterministic proof
available is "the target reflects our injected Host value verbatim
into a sensitive response artifact" (a password-reset link body, a
`Location` header built from Host) rather than a universal structural
signal like CORS's `Access-Control-Allow-Origin`. Confidence should be
tiered accordingly (a confirmed reflection into a `Location`/absolute-
URL context is strong; a bare reflection into an HTML body is weaker
and should not alone justify a finding, mirroring `xssactive`'s own
`ReflectionHTMLEncoded`-never-a-finding precedent).

### Authentication/Session weaknesses (cookie security attributes) — READY
- **A–C**: N/A in the usual sense — this needs no new discovery or
  mutation at all. It is a **passive** analysis of the `Set-Cookie`
  header(s) already captured during every authenticated login
  (`internal/auth/formlogin.go`'s own login-response handling already
  has full access to these headers).
- **D**: Trivially yes — it operates directly on a specific identity's
  own session.
- **E**: Yes — no new request is ever sent.
- **F/G**: Fully deterministic — `Secure`/`HttpOnly`/`SameSite`
  attribute presence is a structural fact, not inferred.
- **H**: Yes — trivial to configure a lab fixture that omits `Secure`/
  `HttpOnly`.
- **I/J**: Trivial — zero additional requests, zero contamination risk.
- **K/L/M**: Same as every other detector once it becomes a
  `models.Finding`.

This is the single lowest-risk, lowest-cost, highest-determinism
candidate reviewed. Its only weakness is that it is a configuration-
hygiene check rather than an exploit-provable vulnerability class in
the same sense as the other candidates — see Section 11's scoring for
how that trades off against CORS.

### Information Disclosure / sensitive-data exposure — READY
- **A–C**: N/A — purely passive, response-content pattern matching
  against content the crawler has **already fetched** for every page.
  Zero new requests.
- **F/G**: Deterministic pattern matching (AWS-key shape, PEM private-
  key headers, stack-trace signatures, verbose framework error pages)
  — the same class of fixed-pattern matching `internal/evidence`'s own
  `redactText`/`sensitiveFieldNames` already uses elsewhere in the
  codebase, just pointed at crawl response bodies instead of evidence
  text.
- **H**: Trivial lab fixture (a page that leaks a fake AWS-shaped key
  or a stack trace).
- **I/J**: Zero additional requests — reuses already-fetched crawl
  data.
- Chain value is high (see Section 9).

### Authorization/BOLA/IDOR extension (function-level / BFLA) — READY WITH SMALL FOUNDATION
Reuses `idoractive`'s entire dual-identity/`compareExecutor` machinery
verbatim (A/B/C/D/E/K/L/M all inherited unchanged). The new work is
narrow: compare **endpoint-level** reachability (does the compare
identity get a 2xx `looksLikeSuccessfulObjectResponse` result from an
endpoint the baseline identity's role should exclusively own) rather
than **object-ID-level** comparison. F/G are as strong as `idoractive`'s
own existing proof (same `looksLikeSuccessfulObjectResponse` +
known-bad-control pattern). H requires one new lab fixture (an
admin-only endpoint reachable by a non-admin compare identity).

## 6. False-Positive / False-Negative Analysis

| Candidate | Strongest proof | Common FP pattern | Common FN pattern | Needs timing? | Needs OOB? | Needs 2nd identity? | Needs 2nd host? | Needs new request type? | Needs raw-byte HTTP? | Needs browser? | Needs stateful workflow? |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CORS Misconfiguration | Origin verbatim-reflected + credentials:true | An app that legitimately allows `*` without credentials (not a real misconfig — must check credentials flag jointly) | A CDN/proxy that strips/overwrites CORS headers before reaching the scanner | No | No | No | No | No (header mutation only) | No | No | No |
| Host Header Injection | Injected Host reflected into `Location`/absolute-URL context | Injected Host reflected into a harmless display-only context (e.g. a debug footer) — must tier confidence by sink | An app behind a fronting proxy that normalizes Host before the app ever sees it | No | No | No | No | No | No | No | No |
| Session security attributes | Missing `Secure`/`HttpOnly`/`SameSite` on the session cookie itself | Flagging a non-session cookie (analytics/tracking) as if it were the session token | A session split across multiple cookies where only the non-critical one is checked | No | No | No | No | No | No | No | No |
| Information Disclosure | Fixed-pattern match (AWS key shape, PEM header, stack trace) | A fixture/demo page intentionally containing example-looking secrets (rare but possible) | A secret in a format/shape not covered by the fixed pattern list | No | No | No | No | No | No | No | No |
| BFLA (authorization extension) | Compare identity gets a genuine, resource-varying 2xx from an endpoint the baseline role should own exclusively | An endpoint that's intentionally public/shared across roles | An endpoint that returns a generic "access denied" page with a 200 status (not caught by naive status-code checks — requires the same `looksLikeSuccessfulObjectResponse` body-shape check `idoractive` already has) | No | No | **Yes** | No | No | No | No | No |
| LDAP/NoSQLi (query-string) | Boolean-differential (always-true vs always-false filter fragment) | An endpoint that already varies its response for unrelated reasons (session-dependent content, timestamps) — requires the same payload-stripping/normalization discipline `sqli`/`sqliactive` already apply | An app using a parameterized/prepared LDAP or Mongo driver call (no injection possible, and no visible signal either) | No | No | No | No | No | No | No | No |
| XXE | External-entity marker echoed in response | N/A — requires the target to actually process attacker XML and reflect it, which is rare/absent unless discovery specifically finds an XML-consuming endpoint | Blind XXE (no in-band echo) — undetectable without OOB infrastructure this codebase doesn't have | No | **Yes, for blind case** | No | No | **Yes — XML body, no `mutation.Location` for it today** | No | No | No |
| CRLF/Header Injection (general) | Genuine response splitting observed | A value merely containing `%0d%0a`-looking text with no actual injection | Go's own `net/http` stack may normalize/reject the malformed construct before it's even observable | No | No | No | No | No | **Yes** | No | No |
| HTTP Request Smuggling | Desynced front-end/back-end response interpretation | Nearly indistinguishable from ordinary latency/connection-reuse noise without raw framing control | Nearly everything, without raw-byte control | No | No | No | Often | Yes | **Yes** | No | Often |
| Race conditions | Two synchronized requests both succeeding against a single-use resource | Ordinary eventual-consistency lag misread as a race win | Requires precise, deliberately-simultaneous firing this codebase's rate-limited/semaphore-bounded executor is not designed to provide | **Yes** | No | Sometimes | No | No | No | No | **Yes** |
| Business Logic | N/A — inherently app-specific | Every generic heuristic here is a FP pattern by definition | Everything not specifically modeled | Sometimes | No | Sometimes | Sometimes | Sometimes | No | Sometimes | **Yes** |

**Preference is deterministic, high-confidence detection over
technical possibility** — this is why CORS/Host-Header/Session-
Security/Info-Disclosure/BFLA rank above LDAP/NoSQLi (real but weaker
differential signal) and far above XXE/smuggling/race conditions/
business logic (all require infrastructure this architecture
deliberately does not have).

## 7. Manual-vs-Automated Boundary

Per this phase's own instruction, "manual" is a valid, non-failure
architectural outcome now that Phase 3.32 provides
`findings show --curl` and full evidence inspection.

**Recommended to remain manual / operator-driven:**
- **HTTP Request Smuggling** — requires raw-byte HTTP/1.1 framing
  control Go's `net/http` deliberately does not expose, and a
  successful desync can affect *other users* of a shared front-end —
  a blast radius beyond the scanner's own test traffic. NOT
  APPROPRIATE for automation in this architecture.
- **Web Cache Poisoning** — requires precise cache-key modeling and
  affects other users' cached responses; same shared-blast-radius
  concern as smuggling.
- **Business Logic vulnerabilities** — inherently app-specific; no
  generic, deterministic signature exists to automate.
- **Race-condition vulnerabilities** — requires precisely-synchronized
  concurrent request firing this codebase's executor is architected to
  *rate-limit*, not to weaponize; building that capability would be a
  major, narrowly-scoped foundation investment for a class that's also
  inherently timing-flaky (poor false-positive resistance).
- **Complex OAuth flows** — requires simulating a real browser through
  multi-hop redirect/consent flows; no such engine exists or is
  proposed.
- **Deserialization** — payload construction is language/framework-
  specific and typically destructive or OOB-dependent; poor fit for
  this architecture's "never destructive" discipline.
- **Strong CSRF exploit proof** (as opposed to a heuristic missing-
  token check) — genuinely proving a cross-site request succeeds
  requires simulating a second-origin browser context, which does not
  exist here.

For every one of these, `scanner findings show --curl` (Phase 3.32)
now gives an operator who suspects one of these classes a safe,
sanitized starting point to investigate manually — this is treated as
adequate coverage, not a gap.

## 8. Chain/Correlation Opportunities

`internal/chains` has exactly 9 `RelationType` values:
`SAME_ENDPOINT, SAME_PARAMETER, SAME_RESOURCE, SAME_IDENTITY,
SAME_SCAN, SHARED_EVIDENCE, DATA_FLOW, POTENTIAL_PRECONDITION,
POTENTIAL_IMPACT_AMPLIFIER`. Only `DATA_FLOW`, `SHARED_EVIDENCE`, and
`POTENTIAL_PRECONDITION` can produce `SUPPORTED` status; `CONFIRMED` is
never auto-assigned by this session's own established, deliberate
policy.

For each example relation, **evidence that occurring on the same host
is never sufficient** — every upgrade path below requires an actual
data-flow or precondition link between the two findings' own evidence,
not mere co-location.

| Relation | RELATED (structural only) | STRONGLY RELATED | CONFIRMED |
|---|---|---|---|
| Information disclosure → IDOR/BOLA | Both findings on the same host, same scan | The disclosed value (e.g. a leaked object ID pattern) is a `DATA_FLOW` match — the disclosed identifier literally appears as the parameter value the IDOR finding used | The IDOR finding's actual mutation used the EXACT value the disclosure finding revealed (provable byte-for-byte from evidence) — this session's policy still withholds CONFIRMED even here, since "used the same value" doesn't prove causal reliance |
| SSRF → internal information disclosure | Same host/scan | SSRF's own confirmed internal-resource marker overlaps textually with the disclosure finding's own evidence (`SHARED_EVIDENCE`) | Never — no mechanism proves the disclosure was *reached via* the SSRF request rather than independently discovered |
| SSRF → cloud metadata exposure | Same host/scan, both flagged SSRF-class | The SSRF finding's own target parameter value is the literal `169.254.169.254` metadata address (a `DATA_FLOW`-shaped match against the finding's own recorded payload) | Never automatically — would require the SSRF detector itself to have proven metadata-endpoint content in-band (currently out of scope; the existing `safedial` reserved-range deny-list actually **blocks** the scanner's own outbound requests to `169.254.169.254`, meaning this specific chain is structurally hard to produce today without an explicit scope carve-out) |
| Open redirect → OAuth misconfiguration | Same host/scan | The redirect destination the open-redirect finding proved matches a registered OAuth `redirect_uri` pattern found elsewhere (`DATA_FLOW`) | Never — no OAuth detector exists to produce the second finding at all today (see Section 4/7) |
| XSS → CSRF/account-impact | Same host/scan | The XSS finding's own endpoint is also a state-changing (POST/form) endpoint with a `SAME_ENDPOINT` CSRF-heuristic finding | Never — impact (actual account takeover) is never observed, only co-located weaknesses |
| SSTI → command execution | Same host/scan | N/A today — this codebase has no command-execution-via-SSTI detector; SSTI's own proof is numeric-only by design (never attempts code execution) | Never — would require a fundamentally different, more dangerous SSTI proof strategy this codebase deliberately does not implement |
| File upload → path traversal | Same host/scan | The uploaded filename/path (if a file-upload detector existed) matches the traversal-marker path literally (`DATA_FLOW`) | Never automatically |
| Path traversal → information disclosure | Same host/scan | `SHARED_EVIDENCE` if the traversal's own confirmed file content overlaps with a separate disclosure finding's content | Never — traversal's own finding already **is** an information disclosure; this specific pairing is more often just the SAME finding described twice, and `internal/correlation`'s dedup (not chains) is the correct layer to prevent double-counting |
| SQL injection → auth bypass/data exposure | Same host/scan | The SQLi finding's own endpoint is a login/auth endpoint (`SAME_ENDPOINT` + parameter-name heuristic) | Never — actual bypass (successful unauthenticated access) is never independently observed by any detector today |
| XXE → SSRF/local file disclosure | Same host/scan | N/A today — no XXE detector exists | N/A |

**Two currently-buildable relations stand out as immediately valuable**
once the Section 11 recommendations ship: **Information Disclosure →
almost anything** (a leaked internal endpoint/path/identifier is
exactly the `DATA_FLOW`-provable shape `internal/chains` already
looks for), and **Authentication/Session weaknesses → any authenticated
finding** (a `SAME_IDENTITY` relation between a weak-session finding
and any finding produced under that same session gives an operator a
genuinely actionable "this session's own weaknesses may compound this
other finding's impact" signal without ever overclaiming CONFIRMED).

## 9. Performance / Scale Analysis

**Current scale**: 14 detector packages, 20 registered instances, 7
enabled by default. Per-scan hard caps: crawl depth 2 / max pages 20;
`detection.max_requests_per_run` 10000; detection concurrency
(detector-pair) 5 workers; `MaxFindings` 1000 (orchestrator) / 500
(chains); chain relations capped at 2000, candidates at 100.

**Worst-case request amplification today**: bounded by
`crawler.max_pages=20` × discovered-inputs-per-endpoint (policy caps
100-200) × payload-variant-count-per-detector (small, fixed: 3-8 per
detector) × 7 enabled detectors — large but hard-capped by the crawl/
input-discovery ceiling, not by detector count.

**Identity multiplication**: currently at most ×2 in production
(`--identity` + `--authz-identity`), and only `idoractive` actually
issues the second identity's own requests — not a general multiplier
across all detectors.

**Chain-analysis cost**: `internal/chains.Correlate` is O(n²) in the
number of findings up to `MaxFindings=500`, explicitly capped
mid-loop at `MaxRelations=2000` — a real, tested, enforced bound (see
Phase 3.30/3.31's own adversarial testing). Not a concern.

**Documented e2e runtime trend**: 1252s (3.29) → 1306s (3.30) → 1315s
(3.31) → **1787s / ~30 min (3.32)**, now past the prior 25-minute CI
budget, driven by new test volume rather than detector count.

**Could the next detector create an unacceptable explosion?** Not for
any of the Section 11 top-5 candidates specifically: CORS and Host
Header Injection are **single-shot-per-service** probes (not per-
parameter), the cheapest possible new-detector shape — actually
*lower* per-scan cost than any existing per-parameter active detector.
Session-security and information-disclosure are **passive, zero-new-
request** detectors. LDAP/NoSQLi would add per-parameter cost
comparable to `sqliactive` today (already-bounded).

**The confirmed unbounded-mutation-budget gap (Section 10) is the real
scale risk**, not detector count — it means nothing currently stops a
*future* config-list-driven detector (or a misconfigured operator
supplying a large `TraversalCase`/`AuthContext` list to the currently-
disabled `traversal`/`idor` detectors) from generating unbounded
requests. **Recommend**: wire `MaxMutationsPerTarget`/
`MaxTotalMutations` from `cfg.Detection.MaxRequestsPerRun` (or a new
dedicated config value) in `cmd/scanner/scan.go`'s executor
construction, closing the gap between the documented guarantee and the
actual production wiring. Per this phase's own instruction, this is a
**recommendation, not an implementation** — see Section 12.

## 10. Security Architecture Findings

Two confirmed foundational issues were found during this review. Both
are reported here, unfixed, per the phase's explicit instruction not
to silently fix unrelated production defects during a coverage review.

### 10.1 CONFIRMED: Evidence redaction never reaches storage

- `internal/detection/engine.go:213` — `e.Store.Findings().Create(ctx,
  f)` persists every detector's raw `models.Finding` (including its
  unredacted `Evidence.Content`) as part of the DETECTION stage,
  before correlation or evidence-building ever runs.
- `storage.FindingRepository` (`internal/storage/store.go:145-150`) has
  exactly four methods — `Create, Get, ListByScanJob, Delete` — **no
  `Update`**. It is structurally impossible for any later stage to
  revise what was already persisted.
- `internal/evidence.BuildPackage` (invoked from
  `orchestrator.go:595`'s `StageEvidence`) correctly redacts headers/
  body/text via `evidence.IsSensitiveFieldName`/`RedactedPlaceholder`
  — but only into a transient, in-memory `evidence.FindingPackage`
  slice that is attached to the one-time `orchestrator.Result` printed
  live by `scan` and then discarded. It is never written back.
- Concrete, currently-exploitable instance: `xssreflected`'s own
  `firstHeaders(resp.Header)` (`detector.go:256-265`) captures the
  **entire, unfiltered** response header set — including any
  `Set-Cookie` — directly into persisted evidence, with zero redaction
  call anywhere in that code path.
- `scanner findings show <id>` (`cmd/scanner/findings.go:111-114`)
  reads and prints this raw, persisted evidence directly;
  `sanitizeForTerminal` (Phase 3.32) strips only ANSI/control bytes,
  never secrets. `scanner report --format json` marshals the same raw
  row. `scanner report --format markdown` is safe only by omission (it
  never renders evidence content at all), not by redaction.
- Active detectors (the majority of the default-enabled set) are
  narrower risk: `detection.MutationEvidence` (used by all 8) does
  correctly redact the mutated parameter's own value and never
  populates a `Headers` field — but its `ResponseFragment:
  string(resp.Body)` embeds the full response body unredacted at
  construction time, with no `redactBody`/`redactText` call in that
  path either.

**This directly narrows the scope of a claim in
`docs/phase-3-32-acceptance-test.md`** ("every credential/session
cookie... is redacted from all of the above") — that claim held for
the specific adversarial test scenarios exercised (which checked for a
known login *password* string, produced by active detectors, not for a
session-cookie token captured by `xssreflected`'s header dump). It was
not previously known to be architecturally incomplete; this review is
the first to trace the full persistence path end to end.

### 10.2 CONFIRMED: Mutation request-count ceiling not wired into production

- `mutation.ExecutorConfig.MaxMutationsPerTarget`/`MaxTotalMutations`
  are enforced only when `> 0` (`mutation/executor.go:236-254`); the
  zero-value default is silently unbounded, and
  `ExecutorConfig.applyDefaults()` does not backfill either field.
- `cmd/scanner/scan.go`'s `DetectionExecutorConfig` construction
  (`scan.go:308-315`, and `buildAuthzExecutor`'s `scan.go:451-458`)
  never sets either field. `internal/config` has no YAML/env surface
  for them at all.
- `detection.Executor.ExecuteMutation` — the sole entry point every
  active detector uses — bypasses `Do`'s own separate `MaxRequests`
  counter entirely; that counter only guards the legacy/passive
  detector path.
- Currently masked by small, fixed-constant payload lists in every
  enabled active detector. The gap becomes live risk the moment a
  config-list-driven detector (the existing, currently-disabled
  `traversal`/`idor`, or a future one) is enabled with a large
  operator-supplied list, or if a future detector's request count
  scales with any unbounded input.

### 10.3 Other items actively investigated, found NOT to be issues

Cross-identity session/cookie reuse, scope bypass via redirects,
target-controlled CLI injection (`os/exec`), shared mutable state/
races, nondeterministic map-iteration ordering, and raw-Finding
provenance attribution were all specifically searched for and found
**clean**, with file:line evidence for each (fresh cookie jars/header
maps per identity; `CheckRedirect` + independent per-hop IP
revalidation; `os/exec` used only for fixed-binary-name recon tools
with target data passed as discrete argv elements, never a shell;
mutexes/atomics correctly guard every shared counter found; every
order-sensitive list is either SQL-`ORDER BY`-backed or explicitly
re-sorted by content before use).

Two lower-severity design notes, not defects: `internal/correlation`'s
`Identity` struct has no `IdentityContext` field, which would silently
merge two different identities' findings into one `CanonicalFinding`
if a future phase ever ran two identities' crawls through the same
primary detection pipeline (currently inert — no live code path
triggers it). And `CanonicalFinding.DetectorID` reports only a single
"winning" detector when multiple independent detectors corroborate the
same identity (deliberate consolidation design, with a corroboration
count preserved in metadata) — understates provenance completeness
if read in isolation, but not incorrect.

## 11. Top-5 Recommendation

### Scoring table (0–10 per factor)

| Factor | CORS | Host Header Inj. | Session Security | Info Disclosure | BFLA (idor ext.) |
|---|---|---|---|---|---|
| 1. Realistic readiness | 9 | 8 | 10 | 10 | 8 |
| 2. Security value | 8 | 6 | 7 | 8 | 8 |
| 3. Confidence of proof | 9 | 6 | 10 | 8 | 7 |
| 4. False-positive resistance | 9 | 6 | 10 | 8 | 7 |
| 5. Coverage gap (novelty) | 9 | 8 | 9 | 9 | 6 |
| 6. Reuse of existing infra | 8 | 8 | 10 | 10 | 9 |
| 7. Auth compatibility | 8 | 8 | 10 | 8 | 9 |
| 8. Multi-identity compatibility | 5 | 5 | 6 | 5 | 10 |
| 9. Scope safety | 10 | 9 | 10 | 10 | 9 |
| 10. Lab reproducibility | 9 | 8 | 9 | 9 | 8 |
| 11. Resource cost (lower=better, scored inverted) | 10 | 10 | 10 | 10 | 7 |
| 12. Operator usefulness | 8 | 6 | 7 | 9 | 8 |
| 13. Chain participation value | 6 | 5 | 8 | 9 | 7 |
| **Total /130** | **108** | **93** | **116** | **113** | **103** |

### TOP 5 CANDIDATES

**#1 — Authentication/Session security attributes (passive cookie-flag analysis).**
Highest total score, and the single lowest-risk addition reviewed:
zero new requests, zero new mutation infrastructure, fully
deterministic, reuses `internal/auth`'s already-captured login-response
headers verbatim. Its only weakness is being a hygiene check rather
than an exploit-class detector — outweighed by every other factor.

**#2 — Information Disclosure / sensitive-data exposure (passive pattern-matching).**
Near-identical profile to #1: zero new requests, deterministic
fixed-pattern matching, reuses already-fetched crawl content. Scores
highest on chain-participation value (Section 8) since a leaked
identifier/endpoint is exactly the shape `internal/chains`' `DATA_FLOW`
relation already looks for.

**#3 — CORS Misconfiguration.**
The strongest genuinely *active* candidate: single-shot-per-service
probe (cheapest possible new active detector), deterministic structural
proof (`Access-Control-Allow-Origin` reflection + credentials flag),
needs only the ONE already-tested `mutation.LocationHeader` gap closed
in `BuildTargets`/a new detector's `Eligible()` — not new mutation-
engine work.

**#4 — Authorization/BOLA/IDOR extension (function-level / BFLA).**
Reuses `idoractive`'s entire dual-identity architecture nearly
unchanged; the highest multi-identity-compatibility score of any
candidate (it's the only class besides existing IDOR that inherently
needs two identities, which this codebase already fully supports).
Scored slightly below CORS mainly on proof confidence (endpoint-level
authorization is a shade less structurally unambiguous than object-ID
comparison) and resource cost (per-endpoint, not per-service).

**#5 — Host Header Injection.**
Shares CORS's exact foundation (`LocationHeader`) at lower additional
cost once #3 is built, but scores lower on proof confidence/FP
resistance since its strongest signal (reflection into a sensitive
sink) is narrower and more context-dependent than CORS's universal
structural check.

## 12. Recommended Phase 3.34 Scope

**Recommended primary scope**: fix Section 10.1 (storage-time
redaction gap) as the phase's first priority, then implement
**Authentication/Session security attributes** (#1) as the new
detector — pairing naturally, since the fix and the new detector both
touch session/cookie handling and the phase can prove the fix using
the very cookies the new detector inspects.

**Concretely**:
1. Close the redaction-at-storage gap: either (a) redact
   `models.Finding.Evidence` before `internal/detection.Engine.Run`
   calls `Store.Findings().Create`, or (b) add a genuinely narrow
   `FindingRepository.Update` and have the Evidence stage write its
   already-redacted `FindingPackage` back. Given this session's own
   established "introduce the minimum required schema/change rather
   than redesigning" principle, (a) is very likely the smaller,
   correct fix — redact at the same point evidence is first
   constructed, reusing the existing `evidence.IsSensitiveFieldName`/
   `RedactedPlaceholder`/`redactHeaders` primitives, never a second
   implementation.
2. Fix `xssreflected`'s specific unredacted-header capture as part of
   the same work (the one concrete, currently-exploitable instance).
3. Implement the new session-security-attributes detector: passive,
   operates on an authenticated identity's own `Set-Cookie` response,
   checks `Secure`/`HttpOnly`/`SameSite` presence, no mutation engine
   involvement.
4. Add the adversarial/lab/e2e tests this session's own discipline
   requires for both the fix and the new detector.

**Explicitly recommend against** starting directly on CORS/Host-Header
Injection in 3.34 despite their strong individual scores — they're
better sequenced *after* the redaction fix lands, since any new active
detector inherits the same storage-time redaction gap this review just
confirmed, and shipping another detector on top of an unfixed
foundational gap repeats the same risk Section 10.1 describes.

**Also recommend, as a smaller parallel task if scope allows**: wire
`MaxMutationsPerTarget`/`MaxTotalMutations` (Section 10.2) from
existing config, closing the documented-but-unenforced ceiling before
any future config-list-driven detector could exploit the gap.

## 13. Explicit Non-Goals

- No new vulnerability detector was implemented in this phase.
- No production code was modified in this phase (verified: `go build
  ./...`, `go vet ./...`, `gofmt -l .` all clean, matching the
  pre-review state exactly).
- No speculative plumbing (e.g. header/cookie `BuildTargets` support)
  was added ahead of an actual detector needing it.
- Section 10's two confirmed foundational issues were **not** fixed in
  this phase, per explicit instruction — they are reported for Phase
  3.34 to address.
- Phase 3.34 is **not** started or scoped beyond the recommendation in
  Section 12.

---

## Testing

This is a review-only phase — **no production code was changed**, so
no new PASS/FAIL counts were manufactured. `go build ./...`, `go vet
./...`, and `gofmt -l .` were re-run after the review to confirm the
repository is in the identical, unmodified state it was in at the end
of Phase 3.32 (2230 tests, 0 FAIL, per `docs/phase-3-32-acceptance-
test.md`) — all three commands passed cleanly with no diffs. No E2E or
race re-run was performed, since no code path they exercise changed;
re-running the full ~30-minute suite would not have produced different
information than Phase 3.32's own already-current results.

---

# PHASE 3.33 ACTIVE DETECTION COVERAGE REVIEW

TOTAL TESTS: 2230
PASS: 2230
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

(Unchanged from Phase 3.32 — this phase modified no production code;
build/vet/gofmt re-verified clean against the identical repository
state.)

CURRENT DETECTOR INVENTORY: PASS
INPUT/MUTATION COVERAGE REVIEW: PASS
CANDIDATE REVIEW: PASS
READINESS CLASSIFICATION: PASS
FALSE-POSITIVE ANALYSIS: PASS
CHAIN/CORRELATION REVIEW: PASS
PERFORMANCE REVIEW: PASS
SECURITY ARCHITECTURE REVIEW: PASS
MANUAL/AUTOMATED BOUNDARY: PASS

FOUNDATIONAL ISSUES: 2

TOP RECOMMENDED NEXT DETECTOR:
Authentication/Session security attributes (passive Set-Cookie
Secure/HttpOnly/SameSite analysis)

READINESS:
READY

WHY:
Zero new discovery or mutation infrastructure required — operates
entirely on session cookies already captured during existing
authenticated-login flows (`internal/auth/formlogin.go`). Fully
deterministic (attribute presence is a structural fact, not a
heuristic), zero additional requests, highest total score (116/130)
of every candidate reviewed. Recommended to ship alongside — not
instead of — a fix for the Section 10.1 storage-time redaction gap,
since that gap concerns the very session cookies this detector
inspects.

ALTERNATIVES:
1. Information Disclosure / sensitive-data exposure (passive,
   pattern-based, 113/130) — equally low-risk, highest chain-
   participation value.
2. CORS Misconfiguration (108/130) — strongest active-detector
   candidate; single-shot-per-service probe; needs only the existing,
   already-tested `mutation.LocationHeader` gap closed in
   `BuildTargets`/a new `Eligible()`.
3. Authorization/BOLA/IDOR extension — function-level/BFLA (103/130)
   — reuses `idoractive`'s dual-identity architecture nearly
   unchanged; strongest multi-identity fit of any candidate.

RECOMMENDED PHASE 3.34:
(1) Fix the confirmed storage-time evidence-redaction gap (Section
10.1): redact `models.Finding.Evidence` before
`internal/detection.Engine.Run` persists it, reusing existing
`internal/evidence` redaction primitives — never a second
implementation — and specifically fix `xssreflected`'s unredacted
`firstHeaders` capture as the one concrete exploitable instance. (2)
Implement the Authentication/Session security-attributes detector
(passive, `Secure`/`HttpOnly`/`SameSite` presence). (3) If scope
allows, wire `MaxMutationsPerTarget`/`MaxTotalMutations` from existing
config to close the Section 10.2 unbounded-request gap. Do not start
CORS/Host-Header-Injection work until the redaction fix has landed.

REMAINING LIMITATIONS:
- Header/cookie mutation remains entirely dead code from a live-
  detection standpoint (tested at the `internal/mutation` engine layer
  only) until a detector or `BuildTargets` actually uses it — CORS/
  Host-Header-Injection are the natural first consumers, deferred to
  after Phase 3.34's foundation work per the sequencing above.
- Live JSON request-body discovery remains structurally impossible
  (crawler-response-body-only limitation, unchanged since Phase 3.18);
  every existing JSON mutation test proves the mutation-engine
  capability only, via directly-persisted synthetic parameters, never
  live discovery.
- HTTP Request Smuggling, Web Cache Poisoning, Business Logic, Race
  Conditions, complex OAuth flows, and Deserialization are
  deliberately recommended to remain manual/operator-driven
  indefinitely, not merely "not yet automated" — see Section 7 for the
  architectural reasoning specific to each.
- `internal/correlation`'s `Identity` struct not including
  `IdentityContext` is a latent (currently inert) cross-identity-merge
  risk for any future phase that runs two identities' crawls through
  the same primary detection pipeline.
- SHARED_EVIDENCE chain relation's previously-documented (Phase 3.31)
  residual low-frequency false-positive risk is unchanged by this
  review.

PHASE 3.33 VERDICT: PASS

STOP HERE.

DO NOT START PHASE 3.34.
