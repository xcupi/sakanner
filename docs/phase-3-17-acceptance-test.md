# Phase 3.17 Acceptance Test: Request Mutation & Attack Surface Foundation

This phase is infrastructure only. No vulnerability detector was added,
modified, or extended. `internal/detectors/idor` remains the only
authorization-adjacent detector in this codebase, unmodified. See
[docs/phase-3-17-request-mutation.md](phase-3-17-request-mutation.md)
section 0 for the full scope discipline this document assumes.

## What was built

- **`internal/mutation`** (new package, 8 source files): a canonical
  `Request`/`Response` model, deterministic `Clone`, a provenance-
  carrying `Mutate` covering query/form/JSON/path/header/cookie
  locations with escaped/verbatim encoding, a scope-safe `Executor`
  built directly on `safedial.Dialer` (the same primitive
  `internal/detection.Executor`/`internal/crawler`/
  `internal/http.Prober` already share), a detector-independent
  `Compare` primitive, and an `evidence.go` bridge producing the exact,
  pre-existing `detection.RequestResponseEvidence` shape.
- **Zero changes to any existing detector, `internal/detection`,
  `internal/orchestration`, `internal/orchestrator`, `internal/config`,
  `cmd/scanner`, storage, or migrations.** `internal/mutation` is
  additive and currently unreferenced by any other package -- verified
  directly (`grep` for `sakanner/internal/mutation` outside the package
  itself returns nothing but this phase's own lab test).
- **`lab/phase3_17_request_mutation_test.go`** (new file, 0 new lab
  fixtures): 6 tests against harness_auth.go's existing Phase 3.14-3.16
  page graph, proving the package works end to end against a real
  authenticated application with two real accounts.
- **Documentation**: `docs/phase-3-17-request-mutation.md`
  (architecture, written and reviewed BEFORE implementation began, per
  the task's own section 1 requirement), this file.

## Architecture review (task section 1)

Conducted before any code was written -- full findings in the
architecture doc's own section 1. Headline conclusions:

1. No canonical request/response model existed anywhere in this
   codebase.
2. Six existing detectors independently duplicated the same
   `requestURL`/`probe` pattern, in two flavors (escaped/verbatim) --
   this is the exact duplication generalized into `Mutate`'s
   `Encoding`.
3. Response comparison was duplicated per-detector too, with no shared
   primitive.
4. `safedial.Dialer`, `scope.Validator`, `detection.Target`, and
   `detection.RequestResponseEvidence` were all reused directly, not
   re-derived.
5. `internal/crawler`'s established discipline of never importing
   `internal/auth` (accepting a plain `Jar`/`Headers` value instead)
   was deliberately mirrored by `internal/mutation.SessionContext`.

## Design decisions worth recording

1. **A real bug found and fixed during this phase's own development,
   not merely claimed.** The first implementation of verbatim JSON
   mutation embedded the raw payload via `obj[key] =
   json.RawMessage(value)` before marshaling the whole object.
   `TestMutate_JSON_Verbatim_RawInjection` failed on its first real run
   with `json: error calling MarshalJSON for type json.RawMessage:
   invalid character ',' after top-level value` -- `encoding/json`
   validates/compacts every `RawMessage` it marshals as part of a
   larger structure, so a genuinely malformed verbatim payload (the
   exact case that mode exists for) was being REJECTED, not passed
   through. Fixed by switching verbatim JSON to the same
   string-splice technique query/form verbatim mutation already use
   (marshal the other fields safely, concatenate the raw bytes in by
   hand) -- documented in full, including the wrong first attempt, in
   the architecture doc section 4.
2. **A second self-caught mistake, this time in the test itself, not
   production code.** The first version of
   `TestAdversarial_RedirectScopeBypass_ChainTruncatedNotFollowed` used
   two plain `httptest.NewServer` instances for the "legitimate" and
   "evil" targets -- both of which default to `127.0.0.1`, differing
   only by port. Since scope decisions are host-based, this made the
   "out-of-scope redirect" test meaningless: the redirect was (legally)
   allowed, and the test failed with the evil content actually present
   in the response -- correctly catching its OWN setup bug, the exact
   same same-host-different-port mistake Phase 3.15's own development
   already made and documented once before. Fixed by adding a local
   `newIPServer` helper (mirroring `internal/auth`'s own established
   one) binding the two servers to genuinely different loopback IPs
   (`127.0.0.1`/`127.0.0.2`), after which the test correctly passed.
   Recorded here in full rather than quietly fixed, per this session's
   own established practice of not hiding a self-caught mistake.
3. **`internal/mutation` never imports `internal/auth`.** Verified
   directly (`grep`), not just asserted -- `SessionContext` is a plain
   data value a caller builds from a real `*auth.Session` via
   `JarFor`/`HeadersFor`, mirroring `internal/crawler.Options`'s
   existing, already-reviewed pattern exactly. This is what makes
   "authentication remains separate from [the request engine]" and
   "identity remains separate from authentication profile" structural
   facts about the import graph, not merely conventions to remember.
4. **No existing detector was migrated onto this foundation.** All six
   keep their own private `requestURL`/`probe` helpers, fully covered
   by their own pre-existing test suites, unchanged. A natural future
   cleanup, deliberately not attempted here -- see architecture doc
   section 14 for the full reasoning.
5. **No CLI command, no config/profile wiring, no storage migration.**
   All three were considered and explicitly declined, each with its
   own documented reasoning (architecture doc sections 11, 13, 14) --
   not simply omitted for lack of time.
6. **Response comparison's normalization is deliberately minimal**
   (digit-run collapsing only, mirroring `internal/detectors/idor`'s
   own already-reviewed technique) -- proven not to erase a genuine
   signal by `TestCompare_DigitRunNormalization_PreservesNonNumericDifferences`
   and, against the real lab,
   `TestPhase3_17_AuthenticatedRequest_IdentityAAndB_IsolatedThroughExecutor`'s
   own comparison assertion (two identities' JSON responses, which
   differ only in a numeric `user_id` AND a non-numeric username, are
   still correctly reported as structurally different).

## Test matrix results

### A. REQUEST MODEL
`NewRequestFromTarget` copies every provenance field verbatim from a
`detection.Target`, defaults an empty `Method` to GET; `URL()` builds
deterministic, sorted-by-key query strings;
`RawQueryOverride` correctly takes precedence for a verbatim mutation.
**PASS**

### B. REQUEST CLONING
`Clone()` deep-copies `Query`/`Headers`/`Cookies`/`Body`/
`RawQueryOverride`/`IP` -- proven in both directions (mutating a clone
never affects the original; mutating the original after cloning never
affects the clone), plus a zero-value `Request.Clone()` no-panic case.
**PASS**

### C. QUERY MUTATION
Escaped (`url.Values.Set`+`Encode`) and verbatim (delete+encode-rest+
concat-raw, matching traversal/cmdinjection's own established
technique) both proven, including that verbatim never double-encodes
an already-percent-encoded payload. Duplicate parameter names collapse
deterministically to one value. Encoded parameter names/values round-
trip correctly through the full encode/decode/re-encode cycle.
**PASS**

### D. FORM MUTATION
Escaped and verbatim both proven, including starting from an empty
body and preserving unrelated fields already present in the body
(critical for the lab's own CSRF-token-plus-mutated-field test,
section M below). **PASS**

### E. JSON MUTATION
Top-level-field escaped mutation (safely quoted) and verbatim mutation
(raw, unvalidated bytes spliced in -- see "Design decisions" #1 for the
real bug this caught) both proven; a non-object existing body is
rejected with a clear error; key order is deterministic across repeated
calls. **PASS**

### F. PATH MUTATION
Segment-index replacement proven; an out-of-range index is rejected
with a clear error rather than silently no-op'ing or panicking.
**PASS**

### G. AUTHENTICATION
`Executor.Execute` attaches `SessionContext.Headers`/`.Jar` only when
the request's host matches `SessionContext.PinnedHost` -- proven at the
unit level (`TestExecute_SessionHeadersAttached_HostMatch`,
`TestExecute_SessionJarAttached_HostMatch`) and end to end against the
real lab (`TestPhase3_17_MutatedFormParameter`'s successful,
CSRF-token-validated POST; `TestPhase3_17_Evidence_NoSessionSecretLeakage`
confirming the canonical `Request` never carries a session cookie
directly). **PASS**

### H. IDENTITY A
`TestPhase3_17_AuthenticatedRequest_IdentityAAndB_IsolatedThroughExecutor`
authenticates a real account through the real Phase 3.14 login flow,
executes `/api/data` through `Executor`, and confirms the response
contains ONLY that account's own `user_id`. **PASS**

### I. IDENTITY B
The same test's second half, for the second real account, confirming
the same guarantee independently. **PASS**

### J. IDENTITY ISOLATION
Structural (a fresh `*http.Client` is built per `Execute` call, no
executor-level mutable session state exists to contaminate) plus two
concurrent adversarial proofs under `-race`:
`TestAdversarial_CookieLeakageBetweenIdentities_ConcurrentExecution`
(30 iterations x 2 identities, true concurrent goroutines, every single
response checked) and
`TestAdversarial_ConcurrentIdentityExecution_TimeoutAndCancellationDoNotHang`.
Neither identity's response ever contained the other's `user_id`, in
either the unit-level or lab-level test. **PASS**

### K. SCOPE ENFORCEMENT
`Execute` re-validates `req.Host`/`req.IP` via the exact same
`scope.Validator.CheckResolved`/`safedial.Dialer.ResolveInScope`
sequence `detection.Executor.Do`/`internal/auth` already use --
proven: a denied target is never dialed
(`TestExecute_DeniedScope_NeverDials`, hit-count assertion on the
target server itself, not just an error check); a request with no
pre-resolved IP is independently resolved-and-validated
(`TestExecute_NoPreResolvedIP_*`); a stale pre-resolved IP for a denied
host is still rejected on re-validation
(`TestAdversarial_ScopeBypass_MutatedIPIgnoredIfHostDeniedOnRevalidation`);
an encoded-path-shaped bypass attempt never changes the actual dial
target (`TestAdversarial_ScopeBypass_EncodedPathNeverChangesDialTarget`);
against the real lab, a request mutated to the pre-existing
out-of-scope `external.scanner.test` host is rejected with
`RequestCount() == 0`
(`TestPhase3_17_ScopeRejection_MutatedHostNeverDialed`). **PASS**

### L. RESPONSE COMPARISON
`StructurallyDifferent` correctly reports false for identical responses
and true for a genuine status/content-type/body difference; content-
type comparison ignores charset parameters; digit-run body
normalization ignores numeric-only differences while preserving
non-numeric ones (the over-normalization guard the task explicitly
warned about); volatile headers (`Date`, `X-Request-Id`, ...) are
ignored, `Set-Cookie` is compared by cookie NAME only; `HeaderDeltas`
is sorted and accurate; repeated `Compare` calls on the same inputs are
byte-for-byte deterministic. Against the real lab: a mutated query
value the target ignores correctly produces NO structural difference
(`TestPhase3_17_MutatedQueryParameter_AndComparison_NoDifference`), and
two different identities' JSON responses correctly DO
(`TestPhase3_17_AuthenticatedRequest_IdentityAAndB_IsolatedThroughExecutor`).
**PASS**

### M. EVIDENCE
`ToEvidence` produces the exact, pre-existing
`detection.RequestResponseEvidence` shape (round-trips through
`detection.NewRequestResponseEvidence` into valid JSON); a sensitive
`Mutation.Parameter` name (e.g. `password`) redacts `Payload`; an
UNRELATED sensitive-named query parameter also already present on the
request is redacted in the rendered request line, not just the
mutated field. Against the real lab: a CSRF-token-targeting mutation's
evidence never contains the attempted value, the account's real
password never appears in the evidence request line, and the canonical
`Request` is confirmed to carry zero cookies directly (session cookies
live only in `SessionContext.Jar`, attached at the transport layer)
(`TestPhase3_17_Evidence_NoSessionSecretLeakage`). **PASS**

### N. SECRET REDACTION
Covered by category M above plus
`TestAdversarial_CredentialLeakage_SessionHeaderNeverInErrorOrResponse`
(a forced transport failure with a secret-bearing session header
attached -- the secret never appears in the returned error or
`Response.Error`). **PASS**

### O. RESOURCE LIMITS
`MaxRequestBodyBytes` rejects an oversized request body BEFORE any
network activity (hit-count assertion on the target server);
`MaxResponseBodyBytes` truncates an oversized response body to exactly
the configured limit; `MaxConcurrentRequests` is a real, observed
ceiling under concurrent load
(`TestExecute_ConcurrencyLimit_Bounded`, tracking actual peak
concurrent in-flight requests); `MaxMutationsPerTarget`/
`MaxTotalMutations` are real, enforced ceilings (both the per-target
and the cross-target total case tested independently), charged only
for `Origin == OriginMutated` requests -- an ORIGINAL/baseline request
run 10 times against a budget of 1 is never rejected
(`TestExecute_OriginalRequests_NeverChargedAgainstMutationBudget`).
`TestAdversarial_ExcessiveMutationCount_BudgetStopsFurtherRequests`
proves the budget actually stops NETWORK traffic (hit-count assertion),
not merely returns an error while still dialing. **PASS**

### P. CANCELLATION
`TestExecute_Cancellation` (a caller-cancelled context mid-request
returns promptly with `Outcome: CANCELLED`, not a hang) and
`TestAdversarial_ConcurrentIdentityExecution_TimeoutAndCancellationDoNotHang`
(5 concurrent requests under a short-timeout, soon-cancelled context,
all return within a 5s deadline). **PASS**

### Q. TIMEOUT
`TestExecute_Timeout` (a server that never responds within
`ExecutorConfig.Timeout` produces `Outcome: TIMEOUT`, correctly
distinguished from `CANCELLED` via `errors.Is(err,
context.DeadlineExceeded)` against the actual error `client.Do`
returns, not a heuristic). **PASS**

### R. CONCURRENCY
Full repository, including every Phase 3.17 addition, passes under
`-race` with zero races reported.
`TestAdversarial_ConcurrentMutationExecution_NoRace` (50 concurrent
`Mutate` calls against one shared original, race-detector clean, original
provably undisturbed afterward);
`TestAdversarial_CookieLeakageBetweenIdentities_ConcurrentExecution`;
`TestExecute_ConcurrencyLimit_Bounded`. **PASS**

### S. DETERMINISM
`Mutation.ID` is content-hash derived (SHA-256, never a counter) --
proven identical across repeated calls with identical inputs, distinct
across different values/locations, and stable across concurrent/
reordered computation from many goroutines
(`TestAdversarial_MutationOrderingNondeterminism_SameInputsSameID`).
Query/JSON serialization ordering relies on the standard library's own
sort-by-key guarantee, verified directly
(`TestRequestURL_QueryEncodingDeterministic`,
`TestMutate_JSON_Deterministic_KeyOrder`). `Compare`'s `HeaderDeltas`
is sorted; repeated `Compare` calls on identical inputs are
byte-for-byte identical (`TestCompare_Deterministic_RepeatedCallsIdentical`).
**PASS**

### T. LAB ISOLATION
No new lab fixture was added this phase -- `harness_auth.go` is
untouched. Physical `lab/`+`tests/` removal, production `go build`/
`go vet` success, `grep -rl "sakanner/lab"` outside `lab/` itself
returning nothing, restoration, and a confirming rebuild: all
re-verified this phase (see REGRESSION below). **PASS**

### U. CLI REGRESSION
No CLI command was added or changed this phase (a deliberate decision,
architecture doc section 11/14). Every existing `cmd/scanner`
subcommand's own e2e coverage re-verified unchanged (see E2E in
REGRESSION below) -- there is nothing new to regress. **PASS**

### V. FULL REGRESSION
See REGRESSION section below -- every prior phase's own suite re-run
and passing, zero corrections required to any pre-existing test.
**PASS**

### W. ADVERSARIAL SECURITY TESTS (task section 16)

| # | Scenario | Covered by |
|---|---|---|
| 1 | Out-of-scope mutated URL/host | `TestAdversarial_ScopeBypass_MutatedHostOutOfScope`, `TestPhase3_17_ScopeRejection_MutatedHostNeverDialed` |
| 2 | Out-of-scope Host header / stale IP | `TestAdversarial_ScopeBypass_MutatedIPIgnoredIfHostDeniedOnRevalidation` |
| 3 | Encoded scope bypass | `TestAdversarial_ScopeBypass_EncodedPathNeverChangesDialTarget` |
| 4 | Absolute URL injection | `TestAdversarial_ScopeBypass_MutatedHostOutOfScope` (evil absolute URL smuggled into a query VALUE never redirects the dial) |
| 5 | Redirect scope bypass | `TestAdversarial_RedirectScopeBypass_ChainTruncatedNotFollowed` (real cross-host redirect, genuinely distinct loopback IPs -- see "Design decisions" #2 for a self-caught test-setup mistake this test's first version had) |
| 6 | Credential leakage | `TestAdversarial_CredentialLeakage_SessionHeaderNeverInErrorOrResponse`, `TestPhase3_17_Evidence_NoSessionSecretLeakage` |
| 7 | Cookie leakage between identities | `TestAdversarial_CookieLeakageBetweenIdentities_ConcurrentExecution` |
| 8 | Identity A -> Identity B contamination | `TestPhase3_17_AuthenticatedRequest_IdentityAAndB_IsolatedThroughExecutor` |
| 9 | Mutation of original via aliasing | `TestAdversarial_AliasingOriginalViaMutation_BothDirections`, `TestClone_DeepIsolation_*` (both directions) |
| 10 | Mutation ordering nondeterminism | `TestAdversarial_MutationOrderingNondeterminism_SameInputsSameID` |
| 11 | Oversized request body | `TestExecute_OversizedRequestBody_RejectedBeforeNetworkActivity` |
| 12 | Oversized response | `TestExecute_OversizedResponseBody_Truncated` |
| 13 | Excessive mutation count | `TestExecute_MutationBudget_*`, `TestAdversarial_ExcessiveMutationCount_BudgetStopsFurtherRequests` |
| 14 | Cancellation during request | `TestExecute_Cancellation`, `TestAdversarial_ConcurrentIdentityExecution_TimeoutAndCancellationDoNotHang` |
| 15 | Timeout during request | `TestExecute_Timeout` |
| 16 | Concurrent identity execution | `TestAdversarial_CookieLeakageBetweenIdentities_ConcurrentExecution`, `-race`-clean |
| 17 | Concurrent mutation execution | `TestAdversarial_ConcurrentMutationExecution_NoRace`, `-race`-clean |
| 18 | Malformed URLs | `TestAdversarial_MalformedURL_ControlCharsInHost_NoCrash` |
| 19 | Malformed headers | `TestAdversarial_MalformedHeaders_CRLFInValue_NoInjection` |
| 20 | Malformed content types | `TestAdversarial_MalformedContentType_NoCrash` |
| 21 | Duplicate parameters | `TestMutate_Query_DuplicateParameterName_CollapsesToSingleValue`, `TestAdversarial_DuplicateParameters_NoCrashOrAmbiguity` |
| 22 | Encoded parameter names | `TestMutate_EncodedParameterName_RoundTrips` |
| 23 | Encoded parameter values | `TestMutate_EncodedParameterValue_RoundTrips` |

All 23 scenarios: **NO SECURITY BOUNDARY FAILURE. PASS.**

### REGRESSION

Full repository, fresh run this phase:

```
go build ./...                                          -> clean
go vet ./...                                             -> clean
gofmt -l .                                                -> clean (no output)
go test $(go list ./... | grep -v '/tests/e2e') -race     -> ok, 1245 PASS, 0 FAIL (33 packages, +1 for internal/mutation)
go test ./tests/e2e/...                                   -> ok, 76 PASS, 0 FAIL (unchanged -- no CLI surface added)
```

Production/lab independence re-verified the strongest way: physically
removed `lab/` and `tests/` from disk, confirmed `grep -rl
"sakanner/lab"` outside `lab/` itself returns nothing, rebuilt and
vetted the production scanner successfully, restored both directories,
rebuilt again to confirm restoration was complete.

No pre-existing test required correction this phase -- every one of
the 1236 tests that existed before Phase 3.17 still passes unchanged.
`internal/mutation` itself needed one internal fix during its own
development (verbatim JSON mutation, "Design decisions" #1 above),
caught by a test written for exactly that purpose failing on its first
real run -- not a pre-existing regression.

## Final report

```
PHASE 3.17 REQUEST MUTATION FOUNDATION

TOTAL TESTS: 1321
PASS: 1321
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

REQUEST MODEL: PASS
REQUEST CLONING: PASS
PARAMETER MUTATION: PASS
REQUEST EXECUTION: PASS
AUTHENTICATION: PASS
IDENTITY ISOLATION: PASS
SCOPE ENFORCEMENT: PASS
RESPONSE COMPARISON: PASS
EVIDENCE: PASS
SECRET PROTECTION: PASS
RESOURCE LIMITS: PASS
DETERMINISM: PASS
LAB: PASS
E2E: PASS
ADVERSARIAL: PASS
REGRESSION: PASS
RACE: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0
(one internal defect -- verbatim JSON mutation rejecting malformed
payloads instead of passing them through -- was found and fixed during
THIS phase's own development, caught by a test written for exactly
that purpose; not an issue remaining at delivery. See "Design
decisions" #1.)

PHASE 3.17 VERDICT: PASS
```

## Architectural notes flagged per task instruction

Per this phase's own "if a design decision is ambiguous, inspect the
existing architecture and document the ambiguity before changing
behavior" instruction: no ambiguity required a behavior change outside
this phase's own scope. Two decisions worth carrying forward
explicitly, since a future phase building on this one will want to
know them:

1. **`detection.Executor` (the existing, six-detectors-strong request
   path) still has no session/identity wiring.** This was already true
   before Phase 3.17 (noted in the architecture review, section 1
   finding 5) and remains true after it -- `internal/mutation.Executor`
   is a NEW, separate, session-aware executor; it does not retrofit
   `detection.Executor`. A future phase that wants an EXISTING detector
   to run authenticated would need to either migrate that detector onto
   `internal/mutation.Executor` or add session wiring to
   `detection.Executor` directly -- both are real, scoped decisions
   deliberately left to whichever future phase actually needs one,
   rather than guessed at here.
2. **No detector currently consumes `internal/mutation` at all.** This
   phase's own task explicitly required this (section 0's scope
   discipline) -- flagged here only so it is not mistaken for an
   oversight when Phase 3.18+ is planned.

Per the task's final rule: no new vulnerability detector, no IDOR/BOLA
logic, no XSS/SQLi/SSRF expansion, no `scanner request` CLI surface,
and no `--identity a,b` comparison semantics were implemented. Work
stops here pending a new phase instruction -- Phase 3.18 is explicitly
not started.
