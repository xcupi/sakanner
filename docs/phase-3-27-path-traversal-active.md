# Phase 3.27: Path Traversal Active Detection

## 0. Scope discipline

This phase implements exactly one thing: an active, mutation-engine-
based path traversal detector, across query/form/JSON/path locations,
requiring genuine protected-resource-content proof (never a status
code/length/timing/generic-error/response-difference/reflection
heuristic). No SSTI, XXE, deserialization, LDAP/XPath injection,
arbitrary filesystem enumeration, destructive filesystem operations,
or any vulnerability class outside path traversal.

## 1. Architecture review

Traced with exact citations, not assumed.

### 1.1 The existing `internal/detectors/traversal` (Phase 3.6) package

A complete, working, but disabled-by-default detector exists.
`ID = "path-traversal"` (`traversal/detector.go:34`). Like `ssrf`/
`idor`, it needs an operator-configured dependency --
`TraversalCase{RelativePath, Marker}` (`traversal/cases.go:20-23`), a
KNOWN relative traversal path plus a KNOWN confirmation marker string
-- so `cmd/scanner/detectors.go` registers it via `traversal.New(nil)`
and disables it (confirmed: `traversal.ID` is in
`buildProductionRegistry`'s disabled-IDs list, alongside `ssrf.ID`/
`idor.ID`).

**Critically, like `ssrf`/`idor`/`cmdinjection`, this package does not
import `internal/mutation` at all** -- `Eligible` restricts to GET-only
query-location targets (`traversal/detector.go:108-114`), and `probe`/
`probeRaw`/`requestURL` build a private `*http.Request` by hand,
issued through the OLD `x.Do(ctx, t, req)` path. This is the SAME
architectural gap `idor`→`idoractive`, `ssrf`→`ssrfactive`, and
`cmdinjection`→`cmdinjectionactive` already closed for their own
vulnerability classes -- the same resolution applies here: a NEW,
coexisting package built on the canonical mutation engine, leaving
`internal/detectors/traversal` completely untouched.

**The old detector's own evidence model has TWO tiers**
(`traversal/detector.go:233-251`): "confirmed" (the configured marker
matched verbatim, Critical/0.9) and "suspicious" (the response is
merely allowed AND distinguishable from a "not found" baseline after
stripping the echoed payload, High/0.55). Task section 2's own
explicit prohibition list ("arbitrary response differences alone"
must never be sufficient) rules out reusing the "suspicious" tier for
this phase's own detector -- `traversalactive` implements ONLY the
"confirmed marker match" tier, deliberately MORE conservative than its
sibling, mirroring the exact same "drop the weaker tier" decision
`ssrfactive` made relative to `ssrf`'s own response-diff/error-phrase
fallbacks (Phase 3.25) and `cmdinjectionactive` made relative to
`cmdinjection`'s single strong tier (which it already reused verbatim,
having no weaker tier to drop). `TraversalCase` itself IS reused
directly (imported from `internal/detectors/traversal`, a pure data
struct with zero dependency on that package's own HTTP logic) --
mirroring `ssrfactive`'s own reuse of `ssrf.CallbackClient`/
`ssrf.Observation` exactly, never a duplicated parallel type.

### 1.2 Parameter-name classification

`pathLikeParameterNames` (`traversal/detector.go:63-68`, private):
`file, filename, filepath, path, file_path, document, document_path,
template, resource, download, attachment, image, directory`. Reused as
the allowlist for a NEW `parameters.IsLikelyFilePathParameter`
function (deliberately NOT named `IsLikelyPathParameter`, to avoid
confusion with `mutation.LocationPath`, an unrelated "path" concept --
this function is about parameter NAMES that suggest a
file/resource-path VALUE). Per Phase 3.26's own hard-learned lesson
(`internal/parameters.InferPathInputs`' `_value`/`_id` suffix
convention, `path.go:229-241`), this function strips those same two
suffixes before the allowlist check from the start, rather than
rediscovering the gap a third time.

### 1.3 Phase 3.23 path-parameter flow (re-confirmed, not re-derived)

crawl → `internal/parameters.InferPathInputs` (>=2 distinct values at
the same segment position, evidence-gated) → persisted
`models.Parameter{Location: "path", PathSegmentIndex: N}` →
`BuildTargets`/`endpointTargets` → `detection.Target{ParameterLocation:
"path", PathSegmentIndex: N}` → `detection.NewTargetMutation` (uses
`mutation.NewPathMutation`) → `mutation.Mutate`'s `applyPath` (Phase
3.23's own double-encoding fix: stores the value UNMODIFIED, letting
`url.URL.String()`'s own single escaping pass handle it) → `x.ExecuteMutation`.
Unchanged since Phase 3.23; re-verified by direct testing in this
phase (section 4).

### 1.4 The established "-active" detector pattern (Phase 3.19-3.26)

`traversalactive` follows the SAME shape `sqliactive`/`ssrfactive`/
`cmdinjectionactive` already established: `Eligible` accepts query (GET
only), form/body/path (any method). Unlike `idoractive`, there is no
cross-identity mutation-safety concern here. Unlike `cmdinjectionactive`
(self-contained, enabled by default), `traversalactive` NEEDS an
operator-configured `[]traversal.TraversalCase` -- mirroring
`ssrfactive`/`idoractive`'s own disabled-by-default treatment exactly,
proven only through the lab's own known cases.

## 2. Existing lab fixtures (`lab/harness_vuln.go`, unauthenticated,
`vuln.scanner.test`) -- exceptionally reusable

`registerPathTraversalAPI` (`harness_vuln.go:778-883`) already
provides a QUERY-parameter (`?file=`) family, parameter name "file"
(already in the name allowlist), covering nearly every false-positive
scenario task section "FALSE-POSITIVE RESISTANCE" names, with zero
new fixtures required for query location:

- `/files/download/vulnerable` -- `path.Clean(path.Join("public",
  file))`, no containment check -- the GENUINE vulnerability (task's
  "traversal-looking but doesn't escape" is the CORRECT negative case
  this endpoint's OWN safe sibling demonstrates, not this one).
- `/files/download/safe` -- same resolve+clean, PLUS an explicit
  containment check before use -- proves a correctly-defended
  endpoint is never flagged.
- `/files/download/sanitized` -- rejects any decoded value containing
  ".." outright -- task's "traversal-looking values that do not
  actually escape."
- `/files/download/by-id` -- an opaque allowlist key, never
  path-joined at all -- a second instance of the same "doesn't
  escape" case, via an entirely different (ID-based) mechanism.
- `/files/download/reflect` -- echoes the value, never reads a file --
  task's "reflected traversal strings" / "length changes, no file
  disclosure."
- `/files/download/generic` -- constant response regardless of input
  -- task's "generic error/response" (paired with the STATUS-based
  negative every 404-on-unknown-file response from `/vulnerable`
  itself already demonstrates -- task's "normal file-not-found
  behavior").

`travSynthFS` (`harness_vuln.go:754-758`) is the shared synthetic
"filesystem": `public/index.html`, `public/public-marker.txt`
(legitimately public -- task's "endpoints that legitimately return
static content"), and `protected/secret-marker.txt` = the literal
string `"PATH_TRAVERSAL_SECRET_MARKER"` -- the KNOWN marker this
phase's own `TraversalCase` reuses verbatim, unchanged. Ground truth
already has 8 entries for this exact family
(`VULN-TRAVERSAL-API-001`/`-NEG-001`/`-SANITIZED-NEG-001`/
`-BYID-NEG-001`/`-REFLECT-NEG-001`/`-GENERIC-NEG-001`/
`-INVALID-NEG-001`/`-PUBLICTEXT-NEG-001`).

**Gaps this phase must fill**: form/JSON/path-location vulnerable
fixtures (the `path.Clean(path.Join("public", file))` logic, reused
verbatim across each new transport location), an authenticated
fixture.

## 3. Core security requirement -- what counts as proof

Per task section 2's own explicit prohibition list, NONE of status
code, response length, timing, generic errors, arbitrary response
differences, or reflection is ever sufficient alone.
`traversalactive` structurally cannot produce a finding from any of
these -- the ONLY code path to `OutcomeFinding` requires
`bytes.Contains(body, []byte(traversalCase.Marker))` where `Marker` is
an OPERATOR-CONFIGURED, KNOWN string identifying a SPECIFIC protected
resource (reusing `traversal.TraversalCase` verbatim, section 1.1) --
never a guess, never a generic substring, never a status-code/length/
timing signal.

## 4. Mutation locations

`Eligible` mirrors `sqliactive`/`ssrfactive`/`cmdinjectionactive`'s
exact location switch: query (GET only), form/body/path (any method).
Query is proven via the EXISTING, unmodified lab fixtures (section 2).
Form/path are proven via NEW lab fixtures + a real crawl + a real
detection run (section 8). JSON is proven correct against a real
endpoint via a DIRECTLY-PERSISTED parameter, honestly marked PARTIAL
for real-crawl discovery -- the SAME pre-existing, honestly-documented
Phase 3.19 gap (the crawler cannot discover a live JSON REQUEST_INPUT
parameter), reaffirmed for the fourth consecutive "-active" detector
phase, unchanged and un-worsened by this phase.

Header/cookie path-traversal inputs are NOT claimed -- no discovery
source in this codebase ever produces a `ParameterLocation` of
`"header"`/`"cookie"` for a file-path-like value.

## 5. Canonical mutation APIs reused

`detection.NewMutationRequest`, `detection.NewTargetMutation`,
`mutation.Mutate`, `Executor.ExecuteMutation` -- identical to every
"-active" detector since Phase 3.19. Per-location encoding mirrors
`cmdinjectionactive`'s own already-reviewed split exactly (section 5
of `docs/phase-3-26-command-injection-active.md`), for the identical
reason: query/form need a PRE-ENCODED payload sent via
`mutation.EncodingVerbatim` (Go's own `url.ParseQuery` quirks around
certain characters as alternate delimiters do not apply to `.`/`/`,
but the SAME "already percent-encoded, must not be re-escaped"
principle from `traversal/variants.go`'s own established technique
applies uniformly); path/JSON need the RAW literal payload via
`mutation.EncodingEscaped`, letting their own single-pass escaping
(`url.URL.String()`'s path escaper; `json.Marshal`'s string escaper)
apply correctly without double-encoding (the exact, already-fixed
Phase 3.23 `applyPath` defect this design avoids by construction, per
`mutate.go`'s own doc comment).

A mutated traversal VALUE can never change the probe request's own
dial target (`t.Host`/`t.IP`/`t.Port` are fixed; only the PARAMETER
value changes) -- the identical, already-proven host-safety argument
every prior "-active" detector's own adversarial test makes, re-proven
here (section 12). Go's `net/http` client does not resolve/collapse
`".."` dot-segments when serializing a request (that is a browser/
proxy navigation concern, not something `url.URL.String()`/
`RequestURI()` performs on an already-absolute URL) -- confirmed by
direct testing (section 12), not assumed, since this is the one fact
this phase's own probing mechanism structurally depends on.

## 6. Authentication and multi-identity

Zero new authentication code. `traversalactive.Detect(ctx, t, x)`
receives `x *detection.Executor` the same way every detector does. A
new authenticated fixture is added to `harness_auth.go`'s existing
`authApp` (section 8), proving the probe correctly carries the
session's cookies -- designed from the start to NEVER echo the raw,
attacker-controlled parameter value anywhere in its response (learning
directly from Phase 3.26's own self-inflicted cross-detector
contamination: an authenticated fixture that echoes raw input
unescaped can accidentally also look like reflected XSS to
`xssactive`'s own Content-Type-blind reflection classifier once both
fixtures coexist in the same scan -- avoided here by construction, not
discovered the hard way a second time). Multi-identity isolation
reuses the SAME authenticated fixture with Phase 3.16's existing two
accounts -- no new identity/session mechanism.

## 7. Scope enforcement

Zero new scope code. Every probe goes through the identical
`x.ExecuteMutation` → `mutation.Executor.Execute` → `resolveAndValidate`
path every other active detector already uses. This detector has no
out-of-band destination of its own (unlike `ssrfactive`) -- there is
no callback/resource URL to misuse, so the entire class of "callback
destination scope" concerns from Phase 3.25 does not apply. Redirect
behavior is governed entirely by the unchanged `mutation.Executor`/
`safedial` redirect-following/re-validation machinery -- re-proven at
the detector level (section 12), not re-derived from scratch.

## 8. Lab

New file, `lab/harness_traversal_active.go`, additive only --
`lab/harness_vuln.go`'s existing `registerPathTraversalAPI` routes are
NOT modified.

- **1. Genuinely vulnerable (existing, reused)**: `/files/download/vulnerable`
  (query).
- **2. Safe (existing, reused)**: `/files/download/safe`.
- **3. Generic-error negative control (existing, reused)**:
  `/files/download/generic`.
- **4. Traversal-looking-but-not-vulnerable (existing, reused)**:
  `/files/download/sanitized`, `/files/download/by-id`.
- **5. Deterministic marker content (existing, reused)**:
  `travSynthFS["protected/secret-marker.txt"] =
  "PATH_TRAVERSAL_SECRET_MARKER"`.
- **6. Query/form/path coverage**: query via the existing family
  above; NEW `/files/download/vulnerable-form` (POST form field
  `file`), NEW `/files/download/vulnerable-json` (POST JSON field
  `file`, directly-persisted-parameter proof only), NEW
  `/files/download/path/<value>` (path segment) -- all reusing the
  SAME `path.Clean(path.Join("public", file))` logic, factored into a
  small shared helper (not touching `harness_vuln.go`'s own existing,
  working handlers).
- **Authenticated**: NEW `/download-file` on `auth.scanner.test`
  (`harness_auth.go`'s existing `authApp`), session-gated, mirroring
  `/ping-exec`'s Phase 3.26 precedent -- including its OWN
  "never echo the raw value" safety lesson (section 6).

Ground truth (`lab/ground-truth-vulnerabilities.yaml`) gains new
positive entries for the form/path fixtures. Unlike SSRF/command-
injection's own proactive ground-truth lessons (Phase 3.25/3.26), the
OLD `path-traversal` detector (query-GET-only) is STRUCTURALLY
ineligible for these new form/path-location fixtures (different
`ParameterLocation` entirely), so no ripple effect on its own
ground-truth-driven tests is expected here -- verified, not assumed,
by the regression run (section "REGRESSION").

## 9. Evidence

`models.Finding`/`models.Evidence` reused unchanged, exactly like the
OLD detector's own finding-building code. Two evidence records per
finding: baseline (legitimate-access reference) and the confirmed
probe (request/response/marker-match observation) -- mirroring
`cmdinjectionactive`'s own exact 2-item shape (simpler than the OLD
`traversal` detector's 3+-item shape, since the "not-found baseline"
existed there to support the now-dropped "suspicious" tier, section
1.1, and is no longer needed once that tier is gone).
`Finding.IdentityContext` is populated automatically by the engine.

## 10. Correlation / risk

Both packages remain fully generic over `models.Finding` -- unchanged
since every prior phase's own re-confirmation, not re-verified from
scratch here since neither package has been touched by any phase
since Phase 3.19's own original review.

## 11. Resource limits / determinism / concurrency

No new limit configuration -- reused executor bounds apply unchanged.
At most 2 + (cases × variants-per-case) requests per eligible target
(1 legitimate-access baseline uncharged, then one mutated probe per
variant, short-circuiting on the first confirmed marker match) --
small, bounded, deterministic, mirroring `cmdinjectionactive`'s own
exact reasoning. Variant ordering is a fixed slice, never a map
iteration. No callback/OOB polling exists in this package, so no
bounded-wait/cancellation concern beyond `x.ExecuteMutation`'s own
ctx-awareness.

## 12. What this phase intentionally does not implement

SSTI, XXE, deserialization, LDAP/XPath injection, arbitrary filesystem
enumeration, destructive filesystem operations (write/delete/modify/
execute -- this detector only ever issues GET/POST HTTP requests, never
a local filesystem call of any kind, proven statically and dynamically
exactly like `cmdinjectionactive`'s own `shell_isolation_test.go`),
header/cookie-based path-traversal inputs (no discovery source
produces them), DNS rebinding/IP-obfuscation techniques, and any
vulnerability class outside path traversal.

## 13. Architecture review questions

Re-confirmed post-implementation against the actual, tested code (not
the pre-implementation plan above).

1. **How does the existing detector work?** `internal/detectors/traversal`
(Phase 3.6) is GET/query-only, builds its own private `*http.Request`
(no `internal/mutation`), and reports two evidence tiers (confirmed
marker match + a weaker "suspicious" response-difference tier) --
confirmed unchanged by `traversal/detector.go:63-68,108-114,233-251`,
untouched by this phase (no diff to that package anywhere in this
change).
2. **What is the existing name/location classification?**
`pathLikeParameterNames` (`traversal/detector.go:63-68`), reused as
the allowlist for the new `parameters.IsLikelyFilePathParameter`
([filepath_parameter.go](../internal/parameters/filepath_parameter.go)),
with `_value`/`_id` suffix-stripping built in from the start (Phase
3.26's lesson), proven live for the path-inferred case by
`TestEligible_PathInferredSuffix_True` and
`TestPhase3_27_PathLocation_Finding` (a real `path_value`-named
parameter, genuinely detected).
3. **Does the Phase 3.23 path-parameter flow still hold?** Yes,
unmodified -- `internal/parameters/path.go` was not touched by this
phase. Re-verified end-to-end by
`TestPhase3_27_PathLocation_Finding` (real crawl of
`/files/download/path/report-1.txt` and `report-2.txt` →
`InferPathInputs` → a real finding).
4. **What canonical mutation APIs are reused?**
`detection.NewMutationRequest`/`detection.NewTargetMutation`/
`mutation.Mutate`/`x.ExecuteMutation` exclusively --
[detector.go](../internal/detectors/traversalactive/detector.go)
has no detector-private HTTP client, confirmed statically by
`TestSourceNeverTouchesLocalFilesystem` and dynamically by
`TestDetect_MaliciousTraversalCase_NeverTouchesLocalFilesystem`.
5. **Does auth/multi-identity flow work unmodified?** Yes --
`traversalactive` performs no authentication of its own; the engine's
existing session-injection and per-identity `Finding.IdentityContext`
population are untouched. Proven live by
`TestPhase3_27_AuthenticatedTraversal_TwoIdentities_SessionIsolated`
against the new `/download-file` fixture: both identities
independently produce a finding, each carrying its own
`IdentityContext`.
6. **Is scope enforcement preserved?** Yes -- every probe still goes
through the shared `scope.Validator` via `x.ExecuteMutation`, with no
detector-local override. Proven adversarially by
`TestDetect_RedirectToOutOfScopeHost_NeverFollowed` (a probe redirected
to an out-of-scope host that serves back the exact configured marker
still produces no finding) and `TestAdversarial_ProbeRequest_NeverChangesHost`.
7. **How is evidence represented?** Standard
`detection.MutationEvidence`-derived `models.Finding.Evidence`, two
items per finding (baseline + confirmed probe) -- unchanged shape from
every other "-active" detector, confirmed by `TestDetect_Vulnerable_Finding`
and the real query-location lab assertion
(`TestPhase3_27_QueryLocation_Finding`, asserting `len(f.Evidence) == 2`).
8. **Do correlation/risk consume this detector's output correctly?**
Yes -- findings use the standard `models.Finding` shape
(`VulnerabilityType: "path_traversal"`, `Category: "broken_access_control"`,
`Severity: Critical`) with no detector-specific correlation code
required; the existing correlation/risk pipeline (unmodified by this
phase) consumes it exactly like every other detector's output.
9. **Which existing lab fixtures were reusable?** All 8 of
`registerPathTraversalAPI`'s existing query-location fixtures
(`/files/download/vulnerable`, `safe`, `sanitized`, `by-id`, `reflect`,
`generic`) needed ZERO modification -- reused as-is for both the
query-location positive proof and the negative-control proof
(`TestPhase3_27_QueryLocation_Finding`,
`TestPhase3_27_NegativeControls_NoFinding`). Only form/JSON/path/
authenticated coverage needed new, additive fixtures
([harness_traversal_active.go](../lab/harness_traversal_active.go)).
10. **What architectural gaps did implementation surface that the
pre-implementation plan (sections 1-12 above) did not anticipate?**
One genuine, non-obvious gap: Go's `net/http.ServeMux` unconditionally
301-redirects any request whose decoded `r.URL.Path` contains `".."`
to its cleaned equivalent, in `ServeMux.Handler`, BEFORE any registered
handler runs -- confirmed by direct reproduction against the stdlib
during this phase's development (see
[harness_traversal_active.go](../lab/harness_traversal_active.go)'s
own `travPathLocationPrefix` doc comment). This silently defeats
PATH-location traversal for any fixture routed through a plain
`*http.ServeMux`, regardless of what the handler itself would have
done with the raw segment -- structurally unrelated to the detector's
own correctness. Resolved by intercepting that one route prefix
OUTSIDE the mux (`travPathLocationBypass`, wrapping the assembled
`vulnAppHandler`), exercising a realistic "custom router trusts a raw
path segment" shape instead of a `ServeMux`-specific artifact. This is
a real, generalizable fact worth documenting for anyone building
further path-location lab fixtures on top of `http.ServeMux`.
