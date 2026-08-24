# Phase 3.29: Active Detection Coverage Review & Next Detector Foundation

This document is the required PRE-implementation review. Every claim
below was verified directly against the repository during this phase
(file/line citations, or a minimal reproduction where the claim is
about Go stdlib behavior a lab fixture would depend on) — nothing here
is assumed from memory of building the codebase.

## 1. Every currently implemented active detector

"Active" = built on `internal/mutation`'s canonical Request/Mutate/
Execute model (Phase 3.17+), coexisting with an older "legacy"
detector where one exists. Confirmed via `cmd/scanner/detectors.go`'s
`buildProductionRegistry` (13 detectors total) and each package's own
`import "sakanner/internal/mutation"`:

| ID | Package | Phase | Default state |
|---|---|---|---|
| `xss-reflected-active` | `internal/detectors/xssactive` | 3.19 | enabled |
| `sqli-active` | `internal/detectors/sqliactive` | 3.20 | enabled |
| `command-injection-active` | `internal/detectors/cmdinjectionactive` | 3.26 | enabled |
| `ssrf-active` | `internal/detectors/ssrfactive` | 3.25 | disabled (needs `CallbackClient`) |
| `idor-active` | `internal/detectors/idoractive` | 3.24 | disabled unless `--authz-identity` |
| `path-traversal-active` | `internal/detectors/traversalactive` | 3.27 | disabled (needs `[]TraversalCase`) |
| `open-redirect-active` | `internal/detectors/openredirectactive` | 3.28 | disabled (needs destination URL) |

## 2. Every legacy/passive detector

Pre-`internal/mutation`, each builds its own private `*http.Request`
and issues it via `detection.Executor.Do` (the pre-Phase-3.19 path),
never `ExecuteMutation`:

| ID | Package | Default state |
|---|---|---|
| `xss-reflected` | `internal/detectors/xssreflected` | enabled |
| `sqli` | `internal/detectors/sqli` | enabled |
| `command-injection` | `internal/detectors/cmdinjection` | enabled |
| `ssrf` | `internal/detectors/ssrf` | disabled |
| `idor` | `internal/detectors/idor` | disabled |
| `path-traversal` | `internal/detectors/traversal` | disabled |

Open redirect has **no** legacy counterpart — `openredirectactive` is
the first and only detector for that class (confirmed Phase 3.28,
re-confirmed here by the same repository search: no
`internal/detectors/openredirect` package exists).

## 3-7. Parameter locations: enum, discoverability, and how far each reaches

Verified directly in `internal/mutation/mutate.go` and
`internal/parameters/model.go`:

```go
// internal/mutation/mutate.go
LocationQuery, LocationForm, LocationJSON, LocationPath, LocationHeader, LocationCookie

// internal/parameters/model.go (identical set, with an explicit note)
LocationHeader Location = "header" // an HTTP request header (not yet discovered by any source in this phase -- see doc.go)
LocationCookie Location = "cookie" // an HTTP cookie (not yet discovered by any source in this phase -- see doc.go)
```

| Location | Crawl-discoverable? | Reaches `BuildTargets`? | Reaches `internal/mutation`? | Reaches active detection? |
|---|---|---|---|---|
| query | Yes (Phase 3.13) | Yes | Yes (`applyQuery`) | Yes — proven by every "-active" detector's own query-location lab test |
| form | Yes (Phase 3.21, `/forms/index`-style discovery) | Yes | Yes (`applyForm`) | Yes — proven by every "-active" detector's own form-location lab test |
| path | Yes (Phase 3.23, `InferPathInputs`, requires ≥2 distinct example values at the same segment) | Yes | Yes (`applyPath`) | Yes — proven by every "-active" detector's own path-location lab test |
| JSON (REQUEST body) | **No** | Only via a directly-persisted test `Parameter` row, never a real crawl | Yes (`applyJSON`) | Yes, but only reachable in tests via direct persistence — every "-active" detector marks this **PARTIAL** |
| header | **No** | No | Yes (`applyHeader` exists and works) | **No** — nothing in `internal/parameters`/`internal/discovery` ever produces a header-location `Parameter`, so no `Eligible`-per-parameter detector can ever receive one through the normal pipeline |
| cookie | **No** | No | Yes (`applyCookie` exists and works) | **No** — identical gap to header |

**Root cause of the JSON gap**, confirmed by direct reading of
`internal/parameters/json.go`'s own doc comment: `ParseJSONBody`
discovers fields from a captured **response** body only —
"nothing in this codebase captures a live JSON REQUEST body, only a
RESPONSE body." This is a crawler/discovery-layer limitation, not a
mutation-layer one — `internal/mutation.applyJSON` itself works
correctly once a JSON-location `Parameter` exists by any means.

**The header/cookie gap is architecturally different from the JSON
gap**: `internal/mutation` already fully supports mutating a header or
cookie value (`applyHeader`/`applyCookie`, wired into `Mutate`'s own
switch) — the missing piece is entirely at the *discovery* layer (no
source ever creates a `Parameter{Location: "header"}` row), **not**
the mutation layer. A detector wanting to test headers (e.g. `Host`,
`X-Forwarded-Host`) would need a fundamentally different shape than
every existing detector: it would test a small, fixed set of headers
unconditionally against every discovered endpoint, rather than being
gated by `Eligible(t detection.Target)` on a *discovered* parameter —
none of the 13 existing detectors work this way.

## 8. Authentication/session support

Session-aware end to end: `mutation.SessionContext{Jar, Headers,
PinnedHost}`, attached automatically by `detection.Executor` once a
scan authenticates (`detection/executor.go:194-198`, unchanged since
Phase 3.19). Every "-active" detector inherits this for free — none
constructs its own authentication. Proven per-detector via a dedicated
authenticated lab fixture (`/lookup`, `/ssrf-fetch`, `/ping-exec`,
`/download-file`, `/redirect-me`).

## 9. Multi-identity support

`--identity`/`--authz-identity` CLI flags (Phase 3.16/3.24), each
identity's own session pinned to its own host/cookie jar, findings
carry `Finding.IdentityContext` set by the engine automatically. Every
"-active" detector's own lab test proves session isolation with two
real accounts (`AccountAUsername`/`AccountBUsername`,
`lab/harness_auth.go`) run as **independent scans**, each producing a
finding with the correct `IdentityContext`.

`idoractive` additionally has a SECOND identity concept — a
"compare-identity" executor (`idoractive.New(compareExecutor,
compareIdentity)`) used to issue a cross-identity confirmation probe.
No other detector needs this (they only ever act as one identity at a
time).

**Both lab accounts (`userA`/`userB`) are same-privilege, different-
resource-ownership** — confirmed by `lab/harness_auth.go:59-61` and
`idor.AuthContext{OwnsResourceIDs}`'s own shape (a per-resource
ownership map, not a privilege tier). No admin/elevated-privilege lab
account exists today.

## 10. Scope enforcement

Unchanged since Phase 3.1/3.17: every request — legacy `Do` or active
`ExecuteMutation` — goes through `safedial.Dialer`, which pins the
dial to the original target's own scope-validated IP and re-validates
every redirect hop's hostname before following it
(`safedial.go:71,133-157`). No detector, legacy or active, has its own
scope logic.

## 11. Redirect safety

`safedial.Dialer.NewClient`'s `CheckRedirect` callback truncates the
chain (returns `http.ErrUseLastResponse`, not an error) the moment a
hop's hostname fails scope validation — the client never dials an
out-of-scope host. `openredirectactive` (Phase 3.28) is the first
detector to make this mechanism its OWN primary evidence source
(rather than an adversarial edge case); every other detector treats it
as pure defense-in-depth.

## 12. Evidence and reproduction support

Every active detector uses `detection.MutationEvidence` /
`detection.NewRequestResponseEvidence` /
`detection.NewTypedRequestResponseEvidence` — unchanged since Phase
3.19, never a detector-specific evidence shape. Standard 2-item
pattern (baseline + confirmed probe) universal across all 7 active
detectors.

## 13. Correlation and risk integration

`internal/correlation.Engine.Ingest`/`Findings()` consumes the
standard `models.Finding` shape — no detector-specific correlation
code exists anywhere. `lab/phase3_8_correlation_test.go`'s
`allDetectorsRegistry` helper has never been updated to include any
"-active" detector across Phases 3.19-3.28 (confirmed: still only
lists the 6 original legacy detectors) — a deliberate, consistent
choice each phase has made, not a gap.

## 14. Resource limits

`detection.ExecutorConfig{Concurrency, MaxRequests,
MaxMutationsPerParameter, MaxActiveRequestsPerScan, MaxRedirects}` —
shared, unchanged since Phase 3.17/3.19. Every active detector's own
per-target request count is small and fixed (1 baseline + 1-4 variant
probes), proven by a dedicated `TestDetect_RequestCount_Bounded`-style
test in every package.

## 15. Existing lab capabilities

`lab/harness_vuln.go` (unauthenticated `vuln.scanner.test`) and
`lab/harness_auth.go` (authenticated `auth.scanner.test`, 2 accounts)
together host every fixture for all 13 detectors. A `travSynthFS`-
style "fake backend that mimics vulnerable behavior without a real
dependency" pattern is used repeatedly (`sqliSimulateQuery` for a fake
SQL backend, `travSynthFS` for a fake filesystem,
`cmdInjectionMatch`/marker-prefix for a fake shell) — proven,
reusable, and directly relevant to picking a next candidate (a
candidate that can reuse or extend this pattern needs no new
infrastructure).

## 16. Existing ground-truth capabilities

`lab/ground-truth-vulnerabilities.yaml` — a curated, hand-maintained
list of known-vulnerable/known-safe fixtures, consumed by
`lab.LoadVulnGroundTruth`/`CompareFindings`. Adding a genuinely new
vulnerable fixture to the SAME shared app has repeatedly (Phase
3.25/3.26) caused an OLDER, unrelated, still-query-GET-only legacy
detector to independently become eligible for it too, requiring a
proactive ground-truth + dependent-count update — a known, recurring
maintenance cost when a new fixture's location/shape overlaps an
existing detector's own eligibility, NOT a bug.

## 17. Existing detector-specific parameter classifiers

All in `internal/parameters/`, all following the identical shape
(exact-match, case-insensitive allowlist, name-based only, `_value`/
`_id` path-inferred-suffix tolerance in the 3 most recent):

- `IsLikelySecurityToken`
- `IsLikelyObjectIdentifier` (used by `idoractive`)
- `IsLikelyURLParameter` (used by `ssrfactive` AND `openredirectactive`
  — the first classifier this session reused across two unrelated
  detectors, rather than each building its own)
- `IsLikelyCommandParameter` (used by `cmdinjectionactive`)
- `IsLikelyFilePathParameter` (used by `traversalactive`)

`sqliactive`/`xssactive` deliberately do NOT gate on a name heuristic
at all — SQL injection and XSS are meaningful against essentially any
parameter, unlike SSRF/command-injection/traversal/redirect, which are
only meaningful against a parameter whose NAME suggests the right
kind of value.

## 18. Existing discovery gaps

1. **JSON request bodies** (section 3-7 above) — crawler captures
   response JSON, never request JSON.
2. **Headers and cookies** (section 3-7 above) — `internal/mutation`
   supports mutating them; nothing discovers them as candidate
   parameters.
3. **No admin/elevated-privilege lab identity** (section 9) — both
   existing accounts are peer-level.
4. **No OpenAPI/Swagger or other spec-driven discovery** — confirmed
   by direct search (`grep -rl "openapi\|swagger"
   internal/discovery internal/crawler` — zero matches). All discovery
   is crawl/response-body-driven.

## 19. Existing technical debt relevant to active detection

1. Six legacy detectors still build their own private `*http.Request`
   (query-GET-only, no `internal/mutation`) — each has an "-active"
   sibling now except none is being removed; explicitly out of this
   phase's scope to touch (task's own "do not modify unrelated
   detectors").
2. `lab/phase3_8_correlation_test.go`'s `allDetectorsRegistry` only
   ever exercises the 6 legacy detectors — a stable, deliberate
   scope boundary (section 13), not something this phase should
   change.
3. Every "-active" detector to date has needed a `ServeMux`-related
   lab-routing workaround (`travPathLocationBypass`,
   `openRedirectPathLocationBypass`) for its own path-location fixture
   — a recurring, now well-documented pattern (Phase 3.27/3.28), not a
   production defect.

---

## CURRENT ACTIVE DETECTOR INVENTORY (task's required per-detector detail)

| Detector | Locations | Authenticated | Multi-identity | Evidence model | Lab proof | Known limitations |
|---|---|---|---|---|---|---|
| **Reflected XSS** (`xssactive`) | query, form, path, JSON (partial) | Yes | Yes | `MutationEvidence`, reflection-context classification | Full crawl-based lab suite | JSON partial (crawl gap); no Content-Type-aware reflection classifier (a real, documented Phase 3.26 discovery — can misclassify a non-HTML reflection) |
| **SQL injection** (`sqliactive`) | query, form, path, JSON (partial) | Yes | Yes | `MutationEvidence`, boolean/error-based confirmation | Full crawl-based lab suite | JSON partial; no name-heuristic gate (broad by design) |
| **IDOR/BOLA** (`idoractive`) | query only (GET) | Yes | Yes (core purpose) | `MutationEvidence`, 3-probe (baseline/cross-identity/known-bad-control) | Full lab suite, 2 real accounts | Query-GET-only by design (mutation-safety); needs operator `AuthContext`s |
| **SSRF** (`ssrfactive`) | query, form, path, JSON (partial) | Yes | Yes | `MutationEvidence`, response-marker + blind/OOB callback | Full lab suite | JSON partial; path-location proof is discovery-only in some historical builds (documented, not retroactively fixed); needs operator `CallbackClient` |
| **Command injection** (`cmdinjectionactive`) | query, form, path, JSON (partial) | Yes | Yes | `MutationEvidence`, exact marker-token match | Full lab suite, Unix+Windows | JSON partial; self-contained, no operator config needed |
| **Path traversal** (`traversalactive`) | query, form, path, JSON (partial) | Yes | Yes | `MutationEvidence`, exact protected-marker match | Full lab suite | JSON partial; needs operator `[]TraversalCase`; path-location lab fixtures need the `ServeMux` double-slash/dot-segment workaround |
| **Open redirect** (`openredirectactive`) | query, form, path, JSON (partial) | Yes | Yes | `MutationEvidence`, resolved-Location exact-match | Full lab suite | JSON partial; needs operator destination URL; first class with no legacy sibling |

Every "-active" detector shares the IDENTICAL JSON limitation (crawler
gap, not detector-specific) and the identical query-GET/form-path-any-
method `Eligible` shape except `idoractive` (query-GET-only
everywhere, for mutation-safety reasons unique to authorization
testing).

---

## NEXT-DETECTOR CANDIDATE EVALUATION

| Candidate | Classification | Architectural reason |
|---|---|---|
| **SSTI** (Server-Side Template Injection) | **READY** | Payload is a plain string (e.g. `{{7*13}}`) — fits query/form/path/JSON string-value mutation with ZERO new `Location`/discovery work. Strong, deterministic evidence is directly achievable: inject an arithmetic expression using two FRESH random operands per probe and require the EXACT product to appear in the response — mirrors `cmdinjectionactive`'s own "freshly generated, unpredictable token" precedent exactly, just arithmetic instead of a UUID. A safe, deterministic lab fixture needs only a fake, bounded expression evaluator (mirrors `sqliSimulateQuery`'s established "fake backend, no real dependency" pattern) — never a real template engine, so no RCE risk. |
| **Authorization/access-control variant — Broken Function-Level Authorization (BFLA)** | **READY WITH SMALL FOUNDATION** | Reuses `idoractive`'s entire proof shape (cross-identity comparison, `MutationEvidence`) almost verbatim. Two concrete gaps: (1) no admin/elevated-privilege lab identity exists today (section 9) — needs one new account; (2) an admin-only endpoint is, by definition, never linked/discoverable while crawling as a low-privilege identity, so either an admin-authenticated crawl must feed candidate endpoints to a low-privilege re-test, or the endpoint list must be operator-configured — a real, if small, foundation gap this phase's own review is required to surface, not paper over. |
| **NoSQL injection** | **REQUIRES SMALL FOUNDATION** | The query-string/array-parameter vector (`?field[$ne]=1`, framework-dependent) fits existing string-value mutation. The stronger, more realistic JSON-operator vector (`{"password":{"$ne":null}}`) needs INJECTING A STRUCTURED JSON VALUE, not replacing a leaf string — confirmed by direct reading of `applyJSON`/`setJSONPathEscaped`/`setJSONPathVerbatim` (`internal/mutation/mutate.go:225-244,259+`): every path always marshals/escapes `m.Value` as a JSON **string**, never splices a raw JSON object/array. Deterministic proof (vs. boolean/timing-based blind proof, which the task explicitly disallows as sole evidence) also needs a purpose-built fake NoSQL backend, mirroring `sqliSimulateQuery`'s pattern — buildable, but real, additive work beyond payload/location plumbing. |
| **Prototype pollution** | **REQUIRES MAJOR FOUNDATION** | Needs adding NEW keys (`__proto__`, `constructor.prototype.x`) to a JSON body, not mutating an existing field — the same structural-JSON-injection gap as NoSQL injection, but WORSE: proof requires observing a SERVER-SIDE BEHAVIOR CHANGE caused by a polluted global prototype, which is highly application-specific and cannot be generalized into one bounded, reusable lab pattern the way SQLi/XSS/command-injection markers can. |
| **Mass assignment** | **REQUIRES MAJOR FOUNDATION** | Needs injecting EXTRA, unexpected fields (not in the original discovered parameter set) into a form/JSON body, PLUS a confirmation step (re-fetch the resource, check whether the injected privilege/field actually took effect) — a fundamentally different, multi-step proof shape no existing detector uses. Meaningful authenticated applicability, but the extra-field-injection primitive doesn't exist in `internal/mutation` today (mutation only ever changes an EXISTING field's value, confirmed by every `Mutation{Parameter, Value}` construction site across all 7 active detectors). |
| **XXE** (XML External Entity) | **REQUIRES MAJOR FOUNDATION** | No XML parameter location, no XML discovery, no XML-shaped lab fixture anywhere in this codebase (confirmed: `grep -rl "xml" internal/mutation internal/parameters` finds nothing content-related). Would need a new `LocationXML`-equivalent (or ad hoc raw-body construction), new discovery, and either OOB/callback proof (mirroring `ssrfactive`, buildable) or file-disclosure proof (mirroring `traversalactive`, buildable) — the PROOF strategy is reachable via existing patterns, but the INPUT PLUMBING is not, and is a genuinely large addition, not a small one. |
| **LDAP injection** | **REQUIRES MAJOR FOUNDATION** | No LDAP-backed fixture or simulated LDAP backend exists. Realistic proof is typically boolean/differential (task explicitly disallows "arbitrary response differences alone"); a deterministic marker-based proof would require a purpose-built fake LDAP-query simulator returning a KNOWN distinguishing result for a KNOWN injected filter — plausible in principle, but a new backend-simulation design from scratch, not a reuse of an existing one. |
| **Insecure deserialization** | **NOT APPROPRIATE YET** | Genuine exploitation proof is inherently format/gadget-chain-specific (Java/PHP/Python/.NET) and either requires unsafe RCE-style confirmation (explicitly prohibited: "does not introduce dangerous or destructive testing") or degrades to pure format-fingerprinting (not real active exploitation proof, closer to a passive/info-exposure check). |
| **CRLF / HTTP response-splitting via header injection** | **NOT APPROPRIATE YET** | Directly reproduced against the Go stdlib during this review: `http.ResponseWriter.Header().Set` + a raw `\r\n`-containing value never produces split headers — `net/http` folds/strips the CR/LF before writing (confirmed empirically: an injected `\r\nSet-Cookie: sess=hijacked` arrived as a single, harmless header value with the CRLF replaced by spaces, and no `Set-Cookie`/extra header was ever created). A genuinely vulnerable Go-based lab fixture would require bypassing `net/http`'s own writer entirely (raw `net.Conn` writes) — exactly the "major new protocol engine" work the task says to avoid, for a class increasingly rare in real Go/modern-framework targets specifically because of this same protection. |
| **Host-header injection** (as its own class, distinct from CRLF) | **READY WITH SMALL FOUNDATION** | `internal/mutation.applyHeader` already works correctly (confirmed, section 3-7) — the gap is purely architectural SHAPE, not plumbing: every existing detector is `Eligible`-gated on a *discovered* parameter, but Host-header testing is inherently endpoint-level (test a small fixed header set against every endpoint, not parameter-gated). This is a real, if bounded, new detector shape — smaller than XXE/NoSQLi/mass-assignment's gaps, but not zero. |
| **HTTP parameter pollution** | **NOT APPROPRIATE YET** | Not a standalone vulnerability with its own deterministic "this is exploitable" proof independent of a companion class (SQLi/XSS/auth-bypass) — it is a technique for AMPLIFYING other classes, not a vulnerability class with its own exploitation evidence. Better suited as a future payload-delivery variant on EXISTING detectors than a new detector. |
| **HTTP request smuggling** | **NOT APPROPRIATE (clear stop)** | Requires precise control of raw TCP-level HTTP framing (ambiguous Content-Length/Transfer-Encoding, chunked-encoding edge cases) entirely outside what `net/http.Client`/`Transport` exposes — would require a from-scratch raw-socket HTTP client, the single clearest "major new protocol engine" case among all candidates. Also carries genuine blast-radius risk on shared/production infrastructure (can desync a connection queue and affect OTHER users' requests) — directly conflicts with the task's own "does not introduce dangerous or destructive testing" criterion. |

### Selection

**SSTI is selected** — the only candidate that is unconditionally
**READY**: zero new `Location` types, zero new discovery mechanism,
zero new lab-account/privilege work, a proof strategy that mirrors an
already-proven, already-reviewed pattern
(`cmdinjectionactive`'s fresh-per-probe-token technique, adapted to
arithmetic), and a lab fixture buildable with the SAME "fake backend,
no real dependency" pattern already used four times in this codebase.
BFLA and Host-header injection are both credible, honestly-scoped
runners-up (documented above as "READY WITH SMALL FOUNDATION" rather
than dismissed), but each needs a genuine foundation addition this
phase's own instructions say to avoid unless it is the SELECTED
candidate's own minimum requirement — SSTI needs none.
