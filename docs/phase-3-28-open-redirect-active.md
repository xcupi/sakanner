# Phase 3.28: Open Redirect Active Detection

## 0. Scope discipline

This phase implements exactly one thing: an active, mutation-engine-
based open-redirect detector, across query/form/JSON/path locations,
requiring genuine proof that a server-side redirect actually points at
an attacker-controlled, out-of-scope destination -- never reflection,
body-containing-the-URL, status code, a Location header merely
containing the payload as a substring, response-length difference, or
generic redirect behavior. No other vulnerability class is touched.

## 1. Architecture review

### 1.1 Is there an existing open-redirect detector to coexist with?

**No.** Unlike every prior "-active" phase this session (xss, sqli,
ssrf, cmdinjection, traversal, idor all had a pre-existing "passive"
sibling under `internal/detectors/`), there is **no**
`internal/detectors/openredirect` package anywhere in this repository
-- confirmed by an exhaustive search (`grep -rn "open_redirect\|
OpenRedirect" --include="*.go"`, `find . -iname "*redirect*"`). The
only existing open-redirect-related code is:

- `lab/harness_vuln.go`'s `registerOpenRedirect` (lines 1180-1193):
  two minimal fixtures, `/redirect/open/vulnerable` (`next` query
  param, zero validation, `http.Redirect`) and `/redirect/open/safe`
  (a 2-entry allowlist). Neither is detected by anything today.
- `lab/phase3_lab_test.go`'s `TestPhase3Lab_OpenRedirectToOutOfScopeIsTruncated`
  -- a Phase 3 lab test proving the **dialer's own** scope enforcement
  (not a detector) truncates the redirect chain at the out-of-scope
  hop. This is infrastructure this phase reuses (section 1.3), not a
  detector to coexist with.
- `lab/apps/redirect/redirect.py` -- a vestigial Python fixture,
  unreferenced by any Go code, from an earlier (pre-Phase-3) lab
  iteration; not touched by this phase.

**Consequence**: this phase's "do NOT modify the existing
open-redirect/passive detection logic unless proven necessary" clause
is vacuously satisfied -- there is nothing to coexist with or
accidentally break. This is the FIRST vulnerability class this session
gets active detection with no passive counterpart at all.

### 1.2 Parameter-name classification -- reuse, not duplicate

`internal/parameters.IsLikelyURLParameter` (Phase 3.25, built for
`ssrfactive`) already allowlists exactly the names an open-redirect
parameter uses in practice: `redirect`, `redirect_uri`, `next`,
`return_url`/`returnurl`, `destination`, `dest`, `target`, `url`,
`link`, plus `_url`/`_uri`/camelCase-`Url`/`Uri` suffixes. This is a
direct, near-perfect fit -- reused verbatim as `openredirectactive`'s
own `Eligible` gate rather than inventing a parallel
`IsLikelyRedirectParameter`. Per this session's own repeated lesson
(Phase 3.26 discovering the `_value`/`_id` path-inferred-suffix gap
for `IsLikelyCommandParameter`, Phase 3.27 building it in from the
start for `IsLikelyFilePathParameter`), `IsLikelyURLParameter` itself
still lacked that suffix tolerance (a known, documented,
never-retroactively-fixed limitation from Phase 3.26's own acceptance
report). Since THIS phase's own path-location support genuinely
depends on it, the fix is applied now, directly to the shared function
(`internal/parameters/url_parameter.go`) -- not a scope-creep
retrofit of `ssrfactive`'s own test suite (untouched), but a
necessary fix for a function this phase newly, directly depends on.

### 1.3 Scope-safe redirect infrastructure -- reuse, do not duplicate

Read directly, in full: `internal/safedial/safedial.go`,
`internal/mutation/executor.go`, `internal/detection/executor.go`.

`safedial.Dialer.NewClient`'s `CheckRedirect` callback (`safedial.go:133-157`)
already:

1. Records **every hop actually followed** into a caller-supplied
   `*[]models.RedirectHop{URL, StatusCode}` chain.
2. Re-checks scope (`Validator.CheckHost`) on **every** redirect
   target's hostname, BEFORE any dial to it is attempted.
3. On an out-of-scope hop (or exceeding `maxRedirects`), returns
   `http.ErrUseLastResponse` -- the client **never dials the
   out-of-scope host at all**, and `client.Do` returns the LAST
   in-scope response (the redirect response itself, headers intact)
   with **no error** -- proven today by
   `lab.TestPhase3Lab_OpenRedirectToOutOfScopeIsTruncated`.

`internal/mutation.Executor.Execute` (`executor.go:164,181,203-205`)
already builds its client via this exact same `safedial.Dialer` and
copies `chain` into `Response.RedirectChain`, `httpResp.Header` into
`Response.Headers`, `httpResp.StatusCode` into `Response.StatusCode`,
with `Outcome = OutcomeSuccess` -- **all unconditionally, including
when the chain was truncated at an out-of-scope hop**. This means:

- The detector needs **zero new scope code**. Every probe already goes
  through `x.ExecuteMutation`, exactly like every prior "-active"
  detector.
- The detector's evidence surface is simply: `resp.StatusCode` (a 3xx
  redirect status), `resp.Headers.Get("Location")` (the destination,
  possibly relative/protocol-relative/encoded), and (for multi-hop
  proof) `resp.RedirectChain` (the in-scope hops actually followed
  before truncation).
- **The scanner's own transport never dials the attacker-controlled
  destination at all** -- satisfying "never redirect to arbitrary
  external infrastructure" structurally, not by convention.

`MaxRedirects` is a fixed, Executor-construction-time value shared by
every detector using that Executor (`ExecutorConfig.MaxRedirects`,
`detection/executor.go:29,109-111`) -- a detector cannot override it
per-probe. This phase's own probes therefore rely on whatever the
scan's own configured value is (defaulting to a small positive number
in production, 0 in most unit tests), exactly like every other
detector; no detector-local override is introduced.

### 1.4 The established "-active" detector pattern (Phase 3.19-3.27)

`openredirectactive` follows the same `Eligible` shape as
`sqliactive`/`ssrfactive`/`cmdinjectionactive`/`traversalactive`:
query (GET only), form/body/path (any method), gated by
`IsLikelyURLParameter`. Built entirely on
`detection.NewMutationRequest`/`detection.NewTargetMutation`/
`mutation.Mutate`/`x.ExecuteMutation` -- no detector-private HTTP
client. Registered but **disabled by default**, mirroring
`ssrfactive`/`traversalactive`/`idoractive`'s own precedent: it needs
an operator-configured attacker/canary destination URL (section 3), a
value no production build ships with, proven only through the lab.

## 2. Core security requirement -- what counts as proof

None of the task's excluded signals (reflection, body containing the
URL, status code alone, Location containing the payload as a
substring, length difference, generic redirect behavior) is ever
sufficient alone. The ONLY code path to `OutcomeFinding` requires ALL
of:

1. `resp.Outcome == mutation.OutcomeSuccess` (a real HTTP response was
   received, not a scope rejection/transport error/cancellation).
2. `resp.StatusCode` is a redirect status (300-399).
3. A non-empty `Location` header is present.
4. The Location value, **properly parsed and resolved** (via
   `url.Parse` + `base.ResolveReference`, exactly matching RFC 3986
   relative-reference resolution -- handling absolute, protocol-
   relative, and relative forms correctly, the same mechanism
   `net/http`'s own redirect-following uses) against the REQUEST's own
   URL, produces a destination whose **hostname and port exactly
   match** (case-insensitive host, exact port) the operator-configured
   `DestinationURL`'s own hostname/port, **and** whose path exactly
   equals the configured destination's path.

This is never a substring/`strings.Contains` check on the raw Location
text -- it is a real URL parse-and-resolve, followed by an exact
structural comparison, which is exactly what defeats the task's
"Location header with a non-equivalent encoded representation" false-
positive scenario (section 6).

## 3. Operator-configured destination

Mirrors `traversal.TraversalCase`/`ssrf.CallbackClient`'s own
established pattern: a single operator-configured, KNOWN,
out-of-scope destination URL (`New(destinationURL string)`), never
guessed or synthesized. The lab configures it as
`http://external.scanner.test/sakanner-lab-redirect-marker` --
`external.scanner.test` is the SAME "guaranteed never in scope"
hostname already used throughout the lab for unrelated out-of-scope
proofs (Phase 3.21/3.22's form-mutation fixture, Phase 3.25/3.26/3.27's
own scope-adversarial tests), reused here rather than inventing a new
one. No per-probe unique token is needed (unlike `cmdinjectionactive`'s
freshly generated UUID) -- the configured destination is already fully
operator-specified and structurally unrelated to anything the target
app would ever legitimately redirect to, so an exact host+path match
is sufficient causation proof by construction.

## 4. Mutation locations and payload variants

Query/form get THREE wire representations of the same configured
destination, mirroring `traversalactive`/`cmdinjectionactive`'s own
established "try a small, fixed set of wire encodings" pattern:

1. **Absolute** -- the destination URL verbatim, sent through the
   normal `mutation.EncodingEscaped` path (the query/form encoder's
   own single-pass percent-encoding is correct and sufficient here;
   unlike traversal/cmdinjection, this payload contains no characters
   that need manual pre-encoding).
2. **Protocol-relative** -- the destination with its `scheme:` prefix
   stripped (`//external.scanner.test/...`), also `EncodingEscaped`.
3. **Pre-encoded** -- the destination manually percent-encoded by this
   package itself, sent via `mutation.EncodingVerbatim` (avoiding
   double-encoding, the exact same reason every prior phase's own
   "encoded" variant needed Verbatim).

Path/JSON get exactly ONE payload -- the raw, unmodified destination,
sent via `mutation.EncodingEscaped` (their own downstream single-pass
escaping, `url.URL.String()`'s path escaper / `json.Marshal`, handles
it correctly) -- mirroring `traversalactive`'s identical location
split exactly.

## 5. Lab fixture plan

The task lists 8 required fixture roles. Mapped:

| # | Role | Fixture | Notes |
|---|---|---|---|
| 1 | Genuinely vulnerable | `/redirect/open/vulnerable` (existing, query) + new `-form`/`-json`/`/path/<value>` siblings | Zero validation -- ALL 3 payload variants (absolute/protocol-relative/pre-encoded) succeed against this ONE fixture, since it performs no validation regardless of representation. This jointly satisfies roles 1, 5 ("protocol-relative fixture"), and 6 ("encoded fixture") without inventing separate bypass-specific app logic -- deliberately, per "do not introduce unrelated vulnerabilities": a SECOND fixture whose only difference is "vulnerable to protocol-relative" would just be the same vulnerability demonstrated twice. |
| 2 | Safe (same-origin validated) | new `/redirect/safe-origin` | Validates the requested destination's scheme+host match the app's own before allowing it; otherwise defaults safely. |
| 3 | Relative-only | new `/redirect/relative-only` | Strips any scheme/host component from the input, redirecting only to the resulting path -- never able to leave the origin regardless of input. |
| 4 | Same-origin (see role 2) | (covered by role 2) | |
| 5 | Protocol-relative (see role 1) | (covered by role 1's payload variant) | |
| 6 | Encoded (see role 1) | (covered by role 1's payload variant) | |
| 7 | Reflection, no redirect | new `/redirect/reflect-only` | Echoes the `next` value in the response BODY as plain text, status 200, never issues a 3xx -- proves reflection alone is never sufficient. |
| 8 | Fixed/allowlisted | `/redirect/open/safe` (existing) | Unmodified, already a 2-entry allowlist. |

Plus, for the SCOPE proof requirements specifically:

- `/redirect/chain/out-of-scope` -- redirects to an in-scope
  intermediate hop, which redirects again to the configured
  out-of-scope destination (multi-hop chain ending out of scope).
- `/redirect/chain/in-scope` -- a multi-hop chain that stays entirely
  within scope (never reaches an external destination) -- a negative
  control for "redirect chain that ultimately remains in scope".
- `/redirect/tracking-decoy` -- constructs a SAFE, same-origin
  Location header that happens to embed the raw injected payload as a
  query-string VALUE (`/dashboard?ref=<percent-encoded payload>`) --
  the literal substring "external.scanner.test" appears in the
  Location header text, but the ACTUAL destination (once resolved) is
  the app's own origin. Proves section 2's exact-match-after-resolve
  requirement, not a substring check, is what's actually enforced --
  this is the "Location header with a non-equivalent encoded
  representation" false-positive scenario.
- An authenticated fixture, `/redirect-me` (`lab/harness_auth.go`),
  session-gated, mirroring `/download-file`/`/ping-exec`'s Phase
  3.26/3.27 precedent, unconditional redirect based on `next`.

`travSynthFS`-style marker content is not needed here (open redirect's
"marker" is the destination HOST itself, not file content).

## 6. False-positive resistance -- task's 8 named scenarios

| Scenario | Fixture/mechanism |
|---|---|
| Reflected URL without redirect | `/redirect/reflect-only` |
| Normal application redirect | `/redirect/open/safe`'s own default-to-`/dashboard` behavior for an unrecognized value |
| Same-origin redirect | `/redirect/safe-origin` |
| Allowlisted redirect | `/redirect/open/safe` |
| URL encoded as data (not a real redirect target) | `/redirect/tracking-decoy` |
| Location header with non-equivalent encoded representation | `/redirect/tracking-decoy` (same fixture, same underlying mechanism) |
| Redirect chain that ultimately remains in scope | `/redirect/chain/in-scope` |
| Redirect chain that attempts to leave scope | `/redirect/chain/out-of-scope` (this one IS expected to be flagged -- it genuinely is vulnerable) |

## 7. Authentication / multi-identity / scope

No new authentication mechanism. `/redirect-me` reuses Phase 3.16's
two accounts exactly like `/download-file` (Phase 3.27); each
identity's finding must carry its own `IdentityContext`, proven live.
Scope: zero new scope code (section 1.3); the detector's own proof
requires the RESOLVED destination to structurally differ from the
target's own origin, so a same-host-different-port redirect (in-scope
per `scope.Validator.CheckHost`, which is hostname-only) is naturally
never flagged as an open-redirect finding by this detector (it doesn't
match the configured attacker destination), while still being
correctly followable by the underlying scope-safe client if the scan
configuration allows it -- these are two independent, correctly
separated concerns (scope-followability vs. this-is-the-configured-bad-destination).

## 8. Evidence / correlation / resource limits / determinism

Standard `detection.MutationEvidence`-derived `models.Finding`, 2
evidence items (baseline + confirmed probe), reproducibility
information includes the raw Location header value AND the resolved
destination -- never a credential. `VulnerabilityType:
"open_redirect"`, `Category: "broken_access_control"` (matches OWASP's
own current classification), consumed by the existing, unmodified
correlation/risk pipeline. At most 1 baseline + 3 variant probes per
eligible query/form target (1 for path/JSON), short-circuiting on
first confirmation -- same bounded-request shape as every prior
"-active" detector. No new redirect-hop-following code is introduced
by this detector; the pre-existing `MaxRedirects`/chain-truncation
logic (section 1.3) already bounds hops, reused unchanged. Determinism
proven via repeated real-lab scans producing the same finding count.

## 9. What this phase intentionally does not implement

Header/cookie-location redirect parameters (no discovery source
produces them), userinfo-component redirect obfuscation
(`http://trusted@evil.test/`) as a dedicated payload variant (a real
bypass technique, but out of this phase's own bounded 3-variant set;
documented as a remaining limitation, not silently claimed), DNS
rebinding, and any vulnerability class outside open redirect.

## 10. Architecture review questions

Re-confirmed post-implementation against the actual, tested code.

1. **Is there an existing detector to coexist with?** No -- confirmed
   by an exhaustive repo search (section 1.1); this is the first
   detector for this vulnerability class. `internal/detectors/openredirectactive`
   is entirely new, and no pre-existing file was modified to
   accommodate it except the two additive, behavior-preserving fixes
   below.
2. **What is the existing name/location classification?**
   `internal/parameters.IsLikelyURLParameter` (Phase 3.25), reused
   directly as `Eligible`'s gate -- extended with `_value`/`_id`
   suffix tolerance (section 1.2), proven live for the path-inferred
   case by `TestIsLikelyURLParameter_PathInferredSuffixes_True` and
   `TestPhase3_28_PathLocation_Finding` (a real finding, not merely
   discovery).
3. **Is scope-safe redirect infrastructure reused, not duplicated?**
   Yes -- zero new scope or redirect-following code exists anywhere in
   `openredirectactive`. Every probe goes through the unchanged
   `x.ExecuteMutation` → `safedial.Dialer`'s own `CheckRedirect`.
   Proven live: `TestAdversarial_ConfiguredDestination_NeverActuallyDialed`
   (a real, listening canary server, confirmed zero hits),
   `TestDetect_RedirectChain_ThroughInScopeHop_Finding`/
   `TestPhase3_28_RedirectChain_OutOfScope_Finding` (multi-hop chains),
   `TestDetect_SameHostDifferentPort_NoFinding` (hostname-only scope
   semantics correctly separated from destination-matching semantics).
4. **What canonical mutation APIs are reused?**
   `detection.NewMutationRequest`/`detection.NewTargetMutation`/
   `mutation.Mutate`/`x.ExecuteMutation` exclusively -- no
   detector-private HTTP client anywhere in
   [detector.go](../internal/detectors/openredirectactive/detector.go).
5. **Does auth/multi-identity flow work unmodified?** Yes -- proven
   live, `TestPhase3_28_AuthenticatedOpenRedirect_TwoIdentities_SessionIsolated`
   against the new `/redirect-me` fixture: both identities
   independently produce a finding, each carrying its own
   `IdentityContext`.
6. **Is scope enforcement preserved, with target/destination/request-
   host/redirect-target-host correctly distinguished?** Yes -- section
   1.3/7's own reasoning, proven by items 3 above plus
   `TestAdversarial_ProbeRequest_NeverChangesHost` (the scanner's own
   dial target is always the endpoint's host, regardless of injected
   destination).
7. **How is evidence represented?** Standard
   `detection.MutationEvidence`-derived `models.Finding.Evidence`, two
   items per finding (baseline + confirmed probe), including the raw
   Location header AND the resolved destination for reproducibility --
   confirmed by `TestPhase3_28_QueryLocation_Finding` asserting
   `len(f.Evidence) == 2`.
8. **Do correlation/risk consume this detector's output correctly?**
   Yes -- standard `models.Finding` shape, no detector-specific
   correlation code required; confirmed no ripple to the existing,
   unmodified correlation pipeline via the full regression run (zero
   changes needed to `lab/phase3_8_correlation_test.go`'s
   `allDetectorsRegistry`, which has never included any "-active"
   detector across Phases 3.19-3.27 either -- consistent, not a gap
   this phase introduces).
9. **Which existing lab fixtures were reusable?** Both of
   `registerOpenRedirect`'s existing fixtures
   (`/redirect/open/vulnerable`, `/redirect/open/safe`) needed ZERO
   modification -- reused as-is for the query-location positive proof
   and the allowlist negative control. Pre-existing ground-truth
   entries `VULN-OPENREDIRECT-001`/`VULN-OPENREDIRECT-NEG-001`
   (`lab/ground-truth-vulnerabilities.yaml`, present before this phase
   began, prepared for a detector that didn't exist yet) now correctly
   describe genuinely detectable/non-detectable fixtures -- confirmed
   NOT to require any test update, since no test that consumes ground
   truth actually runs a registry containing this new,
   disabled-by-default detector (section 8 below).
10. **What architectural gaps did implementation surface that the
    pre-implementation plan (sections 1-9 above) did not anticipate?**
    Two, both discovered via `*http.ServeMux`'s own path-cleaning --
    the SAME class of artifact Phase 3.27 first discovered (there, via
    dot-segment collapsing), now hit again via a DIFFERENT mechanism:
    `path.Clean` also collapses ANY run of repeated slashes, so an
    absolute URL payload's own `scheme://` gets corrupted to
    `scheme:/` when injected as a raw PATH SEGMENT, silently breaking
    the injected destination before the handler ever sees it
    correctly. Resolved with the identical technique Phase 3.27 used
    (`openRedirectPathLocationBypass`, routing that one prefix outside
    the mux). Separately, this phase's own FIRST version of a "safe,
    same-origin-validated" TEST fixture (`safeOriginHandler`) was
    itself vulnerable to a protocol-relative bypass (`//host/...`
    passes a naive `strings.HasPrefix(next, "/")` check) -- caught by
    the detector's own protocol-relative payload variant correctly
    flagging it, a real defect in test code the detector correctly
    found (see DEFECTS FOUND AND FIXED item 2 in the acceptance
    report), not a detector false positive.
