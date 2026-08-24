# Phase 3.17: Request Mutation & Attack Surface Foundation

## 0. Scope discipline

This phase is infrastructure only. It does not implement, extend, or
touch any vulnerability detector. `internal/detectors/idor` already
exists as a complete, working detector (Phase 3.5) -- Phase 3.17 does
not modify it, does not build a second IDOR mechanism, and does not
give any detector new detection logic. Nothing in this document or its
implementation should be read as "IDOR/BOLA is now automated" --
identity- and session-aware request execution is a prerequisite for a
future authorization detector, not that detector itself.

## 1. Architecture review findings

Before writing any code, the existing codebase was inspected
end-to-end (`internal/http`, `internal/detection`, `internal/safedial`,
`internal/scope`, `internal/auth`, `internal/crawler`,
`internal/parameters`, `internal/evidence`, `internal/orchestration`,
`internal/orchestrator`, `internal/policy`, `internal/storage`,
`pkg/models`, `internal/findings`, `cmd/scanner`, `lab/`, and all six
existing detectors). The load-bearing findings:

1. **No canonical request/response model exists.** `internal/http` is
   probe-only (service fingerprinting, one GET). `detection.Target` is
   the closest "canonical" shape but describes a *target to probe*, not
   a request/response pair, and is never mutated (a deliberate value
   copy).
2. **Mutation is duplicated six times.** Every detector
   (`idor`/`sqli`/`ssrf`/`traversal`/`xssreflected`/`cmdinjection`) has
   its own private `requestURL`/`probe` pair. Two shapes exist: an
   *escaped* mutation (`url.Values.Set` + `Encode`, used by sqli/ssrf/
   xssreflected/idor) and a *verbatim* mutation (manual string
   concatenation so an already-percent-encoded payload reaches the
   target unescaped, used by traversal/cmdinjection, which need literal
   bytes on the wire). This is the exact duplication this phase
   generalizes -- the escaped/verbatim fork is the one real behavioral
   distinction preserved, as `Encoding`.
3. **Response comparison is duplicated per-detector too**, always ad
   hoc (sqli's `computeSignals`, ssrf's stripped-body diff, idor's
   `normalizeBody` digit-collapsing equality check). No shared,
   detector-independent "are these two responses structurally
   different" primitive exists.
4. **`safedial.Dialer`/`safedial.PinnedRoundTripper`** are already the
   one shared, reused-everywhere primitive for scope-safe dialing and
   host-pinned header/cookie attachment (used by `internal/http`,
   `internal/crawler`, `internal/detection.Executor`,
   `internal/auth.Session.NewClient`). Any new executor reuses this
   directly rather than re-deriving dial logic.
5. **`detection.Executor` has no session/identity wiring.** Detection-
   stage requests today run unauthenticated except where a detector
   manually attaches headers (IDOR's own `AuthContext`). This is a
   pre-existing gap, not something this phase is required to close in
   `detection.Executor` itself -- but the new mutation executor DOES
   need session/identity wiring, since the task requires it.
6. **`internal/crawler` deliberately never imports `internal/auth`.**
   It accepts primitive `Jar http.CookieJar` + `ExtraHeaders
   map[string]string` values; the caller
   (`internal/orchestration.Pipeline`) derives them from a real
   `*auth.Session` via `Session.JarFor`/`HeadersFor` first. This is the
   established layering discipline for "authentication remains separate
   from [a request-issuing component]" -- Phase 3.17's executor follows
   the identical pattern (see section 6).
7. **`internal/evidence`** already owns the one, reused
   secret-redaction blocklist (`sensitiveHeaderNames`,
   `sensitiveFieldNames`, `RedactedPlaceholder`,
   `IsSensitiveFieldName`) -- `internal/auth` and `internal/parameters`
   both already defer to it rather than keeping a second list. Phase
   3.17 does the same.
8. **`detection.RequestResponseEvidence`** is already the one
   structured evidence shape every detector populates, JSON-marshaled
   into `models.Evidence.Content` and parsed back out by
   `internal/evidence`. Phase 3.17's evidence bridge produces this
   exact shape rather than inventing a parallel one.
9. **No per-detector profile gating exists** -- only a single
   `Profile.DetectionEnabled` boolean (false for "recon", true for
   "web"/"deep"), which already turns the entire detection engine (and
   therefore anything a detector would call, including this new
   package) off under "recon". See section 11.
10. **All finding evidence is embedded JSON inside `findings.evidence`**
    -- no separate requests/mutations table exists anywhere in storage.
    Next migration number is `0010`, not used this phase (see section
    9 below).

Conclusion: reuse `safedial.Dialer`, `scope.Validator`,
`detection.Target` (as an input), `detection.RequestResponseEvidence`
(as an output), and `internal/evidence`'s redaction helpers directly.
Build exactly one new thing: a canonical request/response model with
clone/mutate/execute/compare operations, in a new package,
`internal/mutation`, that no existing detector is required to adopt
this phase.

## 2. Package: `internal/mutation`

```
internal/mutation/
    doc.go       package overview, explicit non-goals
    request.go   Request (canonical model), Clone, URL(), NewRequestFromTarget
    mutate.go    Location, Encoding, Mutation, Policy, Mutate()
    response.go  Response, Outcome
    executor.go  ExecutorConfig, SessionContext, Executor, Execute()
    compare.go   ComparisonResult, Compare(), normalization policy
    evidence.go  ToEvidence() bridge to detection.RequestResponseEvidence
```

`internal/mutation` imports `internal/detection` (for `Target`, as an
input type, and `RequestResponseEvidence`, as an output type),
`internal/safedial`, `internal/scope`, `internal/dns`,
`internal/evidence` (redaction helpers only), and `pkg/models`. It does
**not** import `internal/auth` -- see section 6. `internal/detection`
does not import `internal/mutation` back (no cycle); no existing
detector is modified to use this package this phase (see section 14).

## 3. Canonical request model

```go
type Origin string
const (
    OriginOriginal Origin = "ORIGINAL"
    OriginMutated  Origin = "MUTATED"
)

type Request struct {
    Method  string
    Scheme  string
    Host    string   // hostname only, no port
    Port    int
    IP      net.IP   // pre-resolved, scope-validated IP if known (from a Target); nil triggers a scope-validated resolve at Execute time
    Path    string
    Query   url.Values
    RawQueryOverride *string // set only by a verbatim query mutation; see section 4
    Headers http.Header
    Cookies []*http.Cookie
    Body    []byte
    ContentType string

    ScanJobID, HTTPServiceID, EndpointID string
    Parameter, ParameterLocation string // mirrors detection.Target's own field names/semantics exactly
    IdentityContext string

    Origin     Origin
    MutationID string // "" for ORIGINAL
}
```

`NewRequestFromTarget(t detection.Target) Request` builds the
**original** canonical request directly from a `Target` -- the "obtain
canonical request" step in the task's own future-detector diagram.
Every provenance field (`ScanJobID`/`HTTPServiceID`/`EndpointID`/
`Parameter`/`ParameterLocation`/`IdentityContext`) is copied verbatim
from the `Target`, so a future detector loses none of the context
`BuildTargets` already established.

`Request.Clone()` deep-copies `Query` (map of slices), `Headers` (same
shape), `Cookies` (slice of `*http.Cookie` -- each pointer is
dereferenced and re-allocated, not shared), `Body` (a fresh backing
array), and `RawQueryOverride` (a fresh `*string`). Nothing in a clone
aliases the original's mutable memory -- proven by
`TestClone_DeepIsolation_MutatingCloneNeverAffectsOriginal`.

`Request.URL()` builds the final `*url.URL` deterministically:
`RawQuery` comes from `RawQueryOverride` when set, otherwise
`Query.Encode()` (which Go's standard library already sorts by key).

**ORIGINAL vs. MUTATED is structural, not a convention detectors must
remember:** `NewRequestFromTarget` always sets `Origin: OriginOriginal`
and `MutationID: ""`; the only function in this package that ever
produces `Origin: OriginMutated` is `Mutate` (section 4), and `Mutate`
always clones first -- it is not possible to obtain a mutated Request
that is the same Go value as its original, and calling `Mutate` twice
from the same original produces two independent Requests, neither of
which observes the other's change (task's "Mutation A/B/C, no mutation
may alter the original or another mutation branch").

## 4. Mutation

```go
type Location string
const (
    LocationQuery  Location = "query"
    LocationForm   Location = "form"
    LocationJSON   Location = "json"
    LocationPath   Location = "path"
    LocationHeader Location = "header"
    LocationCookie Location = "cookie"
)

type Encoding string
const (
    EncodingEscaped  Encoding = "escaped"  // safe re-encode (url.Values / json.Marshal)
    EncodingVerbatim Encoding = "verbatim" // literal bytes on the wire, never re-escaped
)

type Mutation struct {
    ID        string // deterministic, content-derived -- see below
    Location  Location
    Parameter string // provenance: the parameter/field/header/cookie NAME (never absent, even for path mutations)
    Value     string
    Encoding  Encoding
    PathSegmentIndex int // meaningful only when Location == LocationPath

    SourceEndpointID, SourceParameterID, IdentityContext string
}

type Policy struct {
    AllowedHeaders []string // header names mutation may target; empty = none
    AllowedCookies []string // cookie names mutation may target; empty = none
}

func NewMutation(...) Mutation   // computes ID
func Mutate(original Request, m Mutation, policy Policy) (Request, error)
```

**Mutation ID determinism:** `NewMutation` computes `ID` as a SHA-256
hash (first 16 hex characters) over
`Location|Parameter|Encoding|SourceEndpointID|SourceParameterID|Value`.
Content-derived, not counter-derived -- the same mutation request
always gets the same ID regardless of program state, goroutine
scheduling, or call order (task's "mutation IDs" determinism
requirement), with no global counter to synchronize across concurrent
callers.

**Per-location mutation semantics:**

- **query**: escaped uses `url.Values.Set` (duplicate query keys
  collapse to the single mutated value -- documented, intentional,
  deterministic, not a bug: task's "duplicate parameters" adversarial
  case is about not crashing/behaving unpredictably, not about
  preserving every duplicate). Verbatim deletes the key from the
  decoded map, re-encodes the rest, and concatenates
  `parameter=rawvalue` back unescaped -- exactly traversal/
  cmdinjection's existing technique, generalized.
- **form**: parses the existing body as `application/
  x-www-form-urlencoded` (or starts from empty if there is none),
  applies the same escaped/verbatim logic as query, sets
  `ContentType` to `application/x-www-form-urlencoded`.
- **json**: parses the existing body as a **top-level** JSON object
  (`map[string]json.RawMessage` -- nested/array mutation is
  out of scope this phase, documented as a known limitation in section
  14). Escaped marshals the value as a safely-quoted JSON string via
  `obj[key] = json.RawMessage(json.Marshal(value))`, then
  `json.Marshal`s the whole map (which sorts keys alphabetically --
  deterministic body bytes with zero extra code). Verbatim cannot use
  the same map-embedding technique: `encoding/json` validates/compacts
  every `json.RawMessage` value it marshals as part of a larger
  structure, so a genuinely malformed or structurally-injecting
  payload (the exact case this mode exists for) would be REJECTED by
  `json.Marshal`, not passed through -- discovered by
  `TestMutate_JSON_Verbatim_RawInjection` failing on its first real
  run against a payload that broke out of the target field into a
  sibling key. Verbatim JSON therefore mirrors the query/form verbatim
  technique instead: the other fields are marshaled safely, then the
  raw, unvalidated bytes are spliced in by string concatenation before
  the closing brace, exactly as traversal/cmdinjection already splice
  a raw query value back after `Encode()`-ing everything else.
- **path**: replaces the path segment at `PathSegmentIndex` (a 0-based
  index, not a name -- there is no path templating anywhere in this
  codebase to infer which segment a discovered "path" parameter
  corresponds to, so the caller states it explicitly). `Parameter`
  still carries the human-readable name for provenance/evidence.
- **header**/**cookie**: rejected with an error unless `Parameter` is
  present (case-insensitively for headers) in `Policy.AllowedHeaders`/
  `AllowedCookies` -- task's explicit "do NOT automatically mutate
  arbitrary headers or cookies." An empty `Policy{}` (the zero value)
  permits nothing; a caller must opt in per name.

## 5. Response model

```go
type Outcome string
const (
    OutcomeSuccess        Outcome = "SUCCESS"          // a real HTTP response was received (any status code)
    OutcomeInvalidRequest Outcome = "INVALID_REQUEST"  // malformed/oversized request, caught before any network activity
    OutcomeScopeRejected  Outcome = "SCOPE_REJECTED"   // scope.Validator denied the host/IP, before any dial
    OutcomeTimeout        Outcome = "TIMEOUT"
    OutcomeCancelled      Outcome = "CANCELLED"
    OutcomeTransportError Outcome = "TRANSPORT_ERROR"  // DNS failure, connection refused, TLS error, etc.
)

type Response struct {
    Outcome     Outcome
    StatusCode  int
    Headers     http.Header
    ContentType string
    Body        []byte  // bounded by ExecutorConfig.MaxResponseBodyBytes
    BodySize    int64
    Truncated   bool
    RedirectChain []models.RedirectHop
    Duration    time.Duration
    Error       string  // human-readable, secret-free -- see section 9

    RequestOrigin   Origin
    MutationID      string
    IdentityContext string
    ScanJobID, HTTPServiceID, EndpointID string
}
```

A non-2xx status code is `OutcomeSuccess` -- a 404 or 500 is a real,
successfully-received HTTP response, not an execution failure. Only
the four other outcomes represent "the request never produced an HTTP
response to interpret." Timeout vs. cancellation is distinguished via
`errors.Is(err, context.DeadlineExceeded)` /
`errors.Is(err, context.Canceled)` against the error `client.Do`
actually returns -- reliable regardless of whether the timeout came
from the caller's own `ctx` or from `http.Client.Timeout` firing
internally (Go's client implements its own `Timeout` via an internal
context deadline, so the same check catches both cases correctly).

## 6. Executor: session/identity integration

```go
type SessionContext struct {
    Jar             http.CookieJar
    Headers         map[string]string
    PinnedHost      string
    IdentityContext string
}

type Executor struct { /* unexported */ }
func NewExecutor(validator scope.Validator, resolver dns.Resolver, cfg ExecutorConfig) *Executor
func (x *Executor) Execute(ctx context.Context, req Request, sess SessionContext) (Response, error)
func (x *Executor) RequestCount() int64
```

`Executor` never imports or references `internal/auth.Session`
directly -- `SessionContext` is a plain data value, exactly mirroring
`internal/crawler.Options`'s own `Jar`/`ExtraHeaders` fields (section
1, finding 6). A caller that has a real `*auth.Session` builds a
`SessionContext` from it:

```go
sess := mutation.SessionContext{
    Jar:             authSession.JarFor(hostname),
    Headers:         authSession.HeadersFor(hostname),
    PinnedHost:      authSession.Host,
    IdentityContext: authSession.IdentityName,
}
```

This is a one-line adapter a caller writes, not something
`internal/mutation` does itself -- so "authentication remains separate
from [the request engine]" and "identity remains separate from
authentication profile" (task's architectural constraints 2 and 3) are
enforced by this package's own import graph, not merely by convention.
`SessionContext{}` (the zero value) is a fully valid, unauthenticated
session -- `Execute` behaves identically to a plain, credential-free
request when `Jar`/`Headers` are empty, preserving Phase 1-3.16's
unauthenticated-scan behavior exactly (task's "backward compatibility
for unauthenticated scans").

Cookie/header attachment reuses `internal/auth.Session.NewClient`'s
exact pattern (`client.Jar = sess.Jar` iff the request's host matches
`sess.PinnedHost`; `client.Transport` wrapped in
`safedial.PinnedRoundTripper{Headers: sess.Headers, PinnedHost:
sess.PinnedHost}` iff headers are present) -- the SAME transport-layer
host-pinning guarantee every other authenticated code path in this
codebase already relies on, not a fourth independent implementation.

Two identities' `SessionContext` values passed to the same `Executor`
never interact: each `Execute` call builds its own `*http.Client` (via
`safedial.Dialer.NewClient`, matching `detection.Executor.Do`'s own
per-call-client pattern), attaches only that call's own `sess.Jar`, and
discards the client afterward. There is no executor-level, cross-call
mutable session state to contaminate -- proven concurrently by
`TestExecute_ConcurrentIdentities_NoJarCrossContamination` and, against
the real lab, `TestPhase3_17_IdentityAAndB_IsolatedThroughExecutor`.

## 7. Scope enforcement

`Execute` performs the exact same "never trust a single check"
sequence `detection.Executor.Do` already established, generalized for
a Request that may or may not already carry a pre-resolved IP:

- If `req.IP` is set (the normal case -- `NewRequestFromTarget` always
  sets it from the already-validated `Target.IP`), `Execute` calls
  `scope.Validator.CheckResolved(ctx, req.Host, req.IP)` again,
  immediately before dialing -- identical to
  `detection.Executor.Do:109`.
- If `req.IP` is nil (a Request built without going through a Target),
  `Execute` calls `safedial.Dialer.ResolveInScope(ctx, req.Host)` --
  the exact function `internal/auth` already uses to validate a login
  URL's host before ever dialing it -- which resolves AND validates in
  one already-reviewed call, rather than this package inventing a
  second resolve-then-check sequence.
- Either way, the actual dial then goes through
  `safedial.Dialer.NewClient`, whose own `CheckRedirect` re-validates
  scope on every redirect hop, exactly as every other stage in this
  codebase already relies on.

A mutation can change `Request.Host`, `Request.Path`, `Request.Query`,
`Request.Body`, headers, or cookies -- it can never change which IP
`Execute` actually dials without that IP re-clearing `CheckResolved`,
because `Execute` always re-derives/re-validates the dial target from
`req.Host`/`req.IP` itself, never trusting a value some earlier stage
computed. Mutating `Host` to an out-of-scope value, injecting an
absolute out-of-scope URL into what would otherwise be a relative path,
or encoding a host to evade a naive string check are all caught by
this same, centralized, IP-aware check -- there is no separate
scope-decision code in `internal/mutation` itself, satisfying "scope
logic itself must remain centralized in `internal/scope`. Do not
duplicate scope decisions." See `adversarial_test.go` for the full
`TestAdversarial_*ScopeBypass*` suite proving each listed bypass
attempt in task section 16 is actually rejected, not merely assumed
to be.

## 8. Response comparison

```go
type ComparisonResult struct {
    StatusCodeA, StatusCodeB int
    StatusCodeMatch bool
    ContentTypeA, ContentTypeB string
    ContentTypeMatch bool
    SizeA, SizeB int64
    SizeDelta int64
    SizeMatch bool
    BodyIdentical bool           // exact byte equality
    BodyNormalizedIdentical bool // equality after normalization (below)
    HeaderDeltas []string        // sorted, normalized header names that differ
    StructurallyDifferent bool   // = !StatusCodeMatch || !ContentTypeMatch || !BodyNormalizedIdentical
}
func Compare(a, b Response) ComparisonResult
```

`StructurallyDifferent` is the ONE coarse signal this package produces
-- it answers "are these responses structurally different," never
"this is an IDOR" or "this is vulnerable." Every field is a plain,
descriptive fact; nothing here assigns severity, confidence, or a
vulnerability type. A future detector interprets `ComparisonResult`
according to whatever it is specifically testing for (e.g. "two
different identities got a structurally identical 200 response for the
same resource" is IDOR-shaped evidence to an authorization detector,
but this package has no opinion about that).

**Normalization policy (deliberately minimal, per task's own "do not
over-normalize" warning):**

- **Headers**: `Date`, `Age`, `Expires`, `Etag`, `X-Request-Id`,
  `X-Correlation-Id` are ignored entirely (inherently volatile,
  timestamp/request-scoped, carry no security signal). `Set-Cookie` is
  reduced to its sorted set of cookie NAMES only (values are expected
  to differ -- session tokens, CSRF tokens -- but which cookies get set
  at all is a meaningful structural signal). Every other header is
  compared by exact value.
- **Body**: only digit-run collapsing (`[0-9]+` -> `#`) -- the same,
  already-reviewed technique `internal/detectors/idor`'s own
  `normalizeBody` uses (independently implemented here, not imported,
  since `idor`'s version is a private helper and this phase does not
  touch detector code -- see section 14). No broader token-stripping
  (UUID/hex/JWT-shaped patterns) is applied: that would risk erasing a
  genuine security signal (e.g. two identities receiving two
  DIFFERENT other users' UUIDs in an IDOR-shaped response is exactly
  the kind of difference digit-collapsing-only normalization
  preserves, while a broader UUID-stripping normalizer would hide it).
  This is a conscious, documented scope decision, not an oversight.

## 9. Evidence and secret protection

```go
func ToEvidence(req Request, resp Response, m *Mutation, observation, reason string) detection.RequestResponseEvidence
```

`m` is the `Mutation` that produced `req`, or `nil` for an ORIGINAL/
baseline request -- passed explicitly rather than reverse-engineered
from `req`'s own mutated fields, since which field of `req` carries the
applied value differs per `Location` (query/form/JSON/path/header/
cookie) and `req`'s caller already has the `Mutation` value on hand.
Produces exactly the existing `detection.RequestResponseEvidence`
shape (section 1, finding 8) -- no new evidence type, no new storage
column, no new `models.EvidenceKind`. Before building the `Request`
line, any query parameter value whose NAME matches
`internal/evidence.IsSensitiveFieldName` is replaced with
`internal/evidence.RedactedPlaceholder` -- the exact, single blocklist
every other package in this codebase already defers to (section 1,
finding 7). `Mutation.Value` itself is redacted the same way in the
`Payload` field when `Mutation.Parameter` is a sensitive name -- so a
future authentication/authorization-testing detector that mutates a
"password" or "token" field never has that value land in a Finding's
evidence.

The response body FRAGMENT embedded in evidence is not independently
re-redacted by this bridge beyond the bound already enforced by
`ExecutorConfig.MaxResponseBodyBytes` -- this matches every existing
detector's own behavior today (sqli/ssrf/xssreflected/traversal/
cmdinjection/idor all embed a raw response fragment without a second
redaction pass), and `internal/evidence.BuildEvidence`/`BuildPackage`
already perform structured, blocklist-based body redaction downstream,
at report-generation time, for every detector's evidence uniformly --
this phase does not weaken or duplicate that existing guarantee, it
relies on it exactly as every current detector already implicitly
does. `TestToEvidence_SensitiveParameterName_ValueRedacted` and
`TestToEvidence_SensitiveHeaderInQuery_RedactedInRequestLine` cover the
construction-time redaction this bridge is directly responsible for.

Never redacted-but-included by design (never present in `Request` at
all, so there is nothing to redact): a `Session`'s cookies/
Authorization header are never embedded in `Request.Headers`/
`Request.Cookies` by anything in this package -- they live only in
`SessionContext.Jar`/`SessionContext.Headers`, attached at the
transport layer by `Execute`, and are never read back out of the
`http.Client`/`http.Request` into anything this package logs or
returns. `TestExecute_SessionCredentialsNeverAppearInResponseOrError`
and the lab's own `TestPhase3_17_Evidence_NoSessionSecretLeakage` prove
this directly, not just by code inspection.

## 10. Resource limits

```go
type ExecutorConfig struct {
    Timeout               time.Duration
    MaxRedirects          int
    MaxRequestBodyBytes   int64
    MaxResponseBodyBytes  int64
    MaxConcurrentRequests int
    MaxMutationsPerTarget int // 0 = unbounded
    MaxTotalMutations     int // 0 = unbounded
    UserAgent             string
}
```

`MaxRequestBodyBytes`/`MaxResponseBodyBytes` are enforced exactly
(oversized request body rejected as `OutcomeInvalidRequest` before any
network activity; oversized response body truncated at the limit with
`Truncated: true`, never buffered past it -- `io.LimitReader(body,
limit+1)`, the same pattern `internal/http.Prober` already uses).
`MaxConcurrentRequests` is a semaphore, identical in shape to
`detection.Executor`'s own `sem chan struct{}`. `MaxMutationsPerTarget`
/`MaxTotalMutations` are atomic counters charged only for `Origin ==
OriginMutated` requests (an ORIGINAL/baseline request is not itself a
mutation and is not charged against this budget -- a detector
typically needs exactly one baseline plus N mutations, and only the N
should be bounded by a "mutation budget"), keyed by
`EndpointID+Parameter+ParameterLocation` for the per-target counter --
mirroring `detection.Executor.MaxRequests`'s existing "hard ceiling,
0 means unbounded" convention exactly. Exceeding either budget returns
`OutcomeInvalidRequest` with no network call attempted for that
specific request -- the budget check happens before the scope check,
so a caller that already ran out of budget generates zero further
scope-validator calls and zero further dials, satisfying "a future
detector must not be able to accidentally generate an infinite number
of requests" structurally, not just by convention.

## 11. Profile integration (recon / web / deep)

`internal/mutation` adds no new `policy.Profile` field and makes no
`if profile == "X"` decision anywhere in its own code. This is a
deliberate choice, not an omission: `Profile.DetectionEnabled` (false
for "recon", true for "web"/"deep") already gates the ENTIRE detection
engine -- `Orchestrator.Run` never even builds a `detection.Executor`,
let alone calls any detector, when detection is disabled (section 1,
finding 9). Since no detector in this codebase calls into
`internal/mutation` yet (section 14), there is currently no code path
under ANY profile that invokes this package during a real scan --
"disable request mutation under recon" is already true, vacuously,
without new code. Should a future detector built on this foundation
need profile-sensitive bounds (e.g. fewer mutations per target under
"web" than "deep"), `ExecutorConfig.MaxMutationsPerTarget`/
`MaxTotalMutations` are the natural knobs to wire from
`policy.Profile` at that time -- deliberately NOT pre-wired now, since
inventing specific numbers for a capability nothing yet consumes would
be exactly the kind of speculative behavior the task's own "do not
silently change the existing meaning of those profiles" / "the request
engine must not independently invent profile behavior" warns against.

## 12. Determinism

- Mutation IDs: content-hash derived (section 4), never a counter.
- Query/form serialization: `url.Values.Encode()` sorts by key
  (standard library guarantee).
- JSON serialization: `json.Marshal` on `map[string]T` sorts keys
  (standard library guarantee).
- Header application order in `Execute`'s constructed `http.Request`:
  `Request.Headers`' keys are sorted before being copied onto the
  outgoing `http.Request`, so two runs with the identical logical
  header set always produce byte-identical wire header ORDER too, not
  just an identical header SET.
- `Compare`'s `HeaderDeltas`: sorted.
- Nothing in this package iterates a Go map for any externally visible
  ordering without an explicit `sort` step first.
- `TestDeterminism_RepeatedMutateAndCompare_IdenticalResults` and the
  lab's determinism coverage prove repeated identical inputs produce
  byte-identical `Request`/`Mutation.ID`/`ComparisonResult` output.

## 13. Storage: no migration this phase

No new table, no new column, no migration `0010`. `Request`/`Response`
are transient, in-memory values, constructed, executed, and consumed
entirely within one detector call -- exactly like every existing
detector's own `probe`/`requestURL` values today, which are never
persisted as such either. The one thing that IS persisted from a
mutation-backed probe -- evidence explaining a finding -- already has
a home: `ToEvidence` (section 9) produces the exact same
`detection.RequestResponseEvidence` JSON shape every current detector
already writes into `models.Evidence.Content`, which is already wired
through storage end to end with zero schema change required. This
mirrors `models.ScanJob.AuthCrawlStats`/`Warnings`' own established
precedent (Phase 3.13/3.15: a transient, non-persisted computation
result, documented as intentionally not backed by a storage column).
Should a future phase want a queryable, cross-finding view of every
mutation attempted (not just the ones that produced a finding), that
would be new, genuinely additional scope -- a bigger step than
anything Phase 3.1-3.16 have done for evidence, deliberately deferred
rather than spent here.

## 14. What this phase intentionally does not implement

- **No detector is modified to use `internal/mutation`.** All six
  existing detectors keep their own private `requestURL`/`probe`
  helpers, unchanged, still fully covered by their own existing test
  suites. Migrating them onto this foundation is a natural, low-risk
  future cleanup, not required by this phase and not attempted here --
  it would touch six already-reviewed, fully-tested detector packages
  for a benefit (de-duplication) this phase's own task explicitly does
  not ask for, and would add regression risk against "do not break
  existing detectors" for no required gain.
- **No new vulnerability detector, no IDOR/BOLA logic, no XSS/SQLi/
  SSRF expansion, no generic payload fuzzing.**
- **No `--identity a,b` comparison semantics** (that was already
  explicitly deferred in Phase 3.16 and remains deferred).
- **No nested/array JSON mutation** -- only top-level JSON object
  fields (section 4).
- **No path templating** -- path mutation targets an explicit segment
  index, not an inferred named parameter, because no path-templating
  concept exists anywhere upstream to infer one from.
- **No CLI command.** No `scanner request`/`scanner mutate` surface is
  added -- there is no detector yet producing mutation-derived data an
  operator would want to inspect, and building an inspection command
  ahead of any real data to show would be premature surface area this
  phase's own task explicitly warns against ("avoid creating a public
  CLI contract that will later need to be broken").
- **No config/profile wiring** (section 11) -- `ExecutorConfig` is
  constructed directly by a future caller (a detector, a test), exactly
  as `detection.ExecutorConfig` already is by
  `Orchestrator.buildDetectionExecutor`; wiring it through
  `internal/config`/YAML is deferred until something actually needs an
  operator-configurable value here.
- **No storage/migration** (section 13).

## 15. How a future detector consumes this foundation

```go
// discover target
t := detection.Target{ /* from BuildTargets, as today */ }

// obtain canonical request
req := mutation.NewRequestFromTarget(t)

// clone + mutate one controlled input
m := mutation.NewMutation(mutation.LocationQuery, t.Parameter, payload,
    mutation.EncodingEscaped, t.EndpointID, "", t.IdentityContext)
mutated, err := mutation.Mutate(req, m, mutation.Policy{})

// execute through the centralized executor (reusing an existing
// *auth.Session the caller already has, or SessionContext{} for none)
sess := mutation.SessionContext{} // or derived from a real Session, see section 6
baseline, err := x.Execute(ctx, req, sess)
resp, err := x.Execute(ctx, mutated, sess)

// compare
result := mutation.Compare(baseline, resp)
if result.StructurallyDifferent {
    // the detector's OWN interpretation logic decides what this means,
    // and builds a models.Finding using mutation.ToEvidence(req, resp, &m, ...)
    // for the evidence -- none of that interpretation lives in this package
}
```

No detector built this way needs its own HTTP client, its own
cookie/session handling, its own scope check, its own timeout/
cancellation handling, its own response normalization, its own secret
redaction, or its own concurrency control -- all nine are provided by
`internal/mutation` plus the packages it already reuses
(`safedial`, `scope`, `evidence`), exactly as task section 21 asks for.
