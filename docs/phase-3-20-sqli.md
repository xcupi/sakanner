# Phase 3.20: SQL Injection Active Detector

## 0. Scope discipline

This phase adds the second active detector on Phase 3.19's foundation.
It does not implement SSRF, command injection, path traversal, IDOR/
BOLA, authorization testing, stored/DOM/blind XSS, mass assignment,
business-logic testing, database dumping, destructive SQL, OS command
execution, or automated exploitation. Every payload is read-only and
detection-oriented (a control value, a syntax-breaking quote, or a
tautology/contradiction pair) -- never `DROP`/`DELETE`/`UPDATE`/
`INSERT`/`CREATE` or anything resembling them.

## 1. Architecture review findings

Phase 3.19 already built everything this detector needs; this review
confirms exactly what to reuse, and identifies the one naming decision
that mirrors Phase 3.19's own precedent.

1. **`internal/detectors/sqli` already exists** -- a complete, working,
   fully-tested detector (Phase 3.3), query-only, GET-only, built on
   the OLD `detection.Executor.Do` + private `requestURL`/`probe`
   pattern. The task's instruction to "create internal/detectors/sqli"
   collides with this exactly the way Phase 3.19's "implement reflected
   XSS" collided with the pre-existing `xss-reflected`. The identical
   resolution applies: a NEW, clearly-differentiated package
   (`internal/detectors/sqliactive`, ID `sqli-active`) coexists with,
   and does not modify, the existing one -- its own full test suite and
   lab ground-truth mapping stay untouched. Documented here rather
   than silently overwriting working, tested code.
2. **`internal/mutation`/`internal/detection.Executor.ExecuteMutation`**
   (Phase 3.19) already provide everything section 1's "do not
   duplicate" list forbids re-deriving: HTTP execution, scope
   enforcement, session/identity attachment, request mutation
   (`mutation.Mutate`), response capture (`mutation.Response`).
   `sqliactive` uses these exactly as `xssactive` already does --
   `detection.NewMutationRequest(t)` to obtain the canonical request,
   `mutation.NewMutation`/`Mutate` to produce each probe, and
   `x.ExecuteMutation` to run it.
3. **`mutation.Compare`** (Phase 3.17) is the "existing response-
   comparison infrastructure" task section 4 requires be reused for
   boolean-differential detection -- `Compare(trueResp, falseResp)`'s
   `StructurallyDifferent`/`BodyNormalizedIdentical` fields are exactly
   the "are these two responses meaningfully different" signal a
   boolean-based SQLi probe needs. Its digit-run body normalization is
   reused as-is; a NEW, SQLi-specific pre-processing step (stripping
   each probe's own payload text, in every already-established
   raw/HTML-encoded/URL-encoded form -- see section 3) runs BEFORE
   `Compare`, so a reflected-payload false positive (task section 9's
   own required negative case) is eliminated before the comparison
   even happens, not papered over after.
4. **`detection.MutationEvidence`/`NewRequestResponseEvidence`/
   `NewTypedRequestResponseEvidence`** (Phase 3.17/3.19's relocated
   bridge) are reused unchanged -- `sqliactive` invents no second
   evidence shape.
5. **`internal/correlation`/`internal/risk`** remain fully generic over
   `models.Finding` (re-confirmed, unchanged since Phase 3.19's own
   architecture review) -- `sqliactive`'s findings need nothing
   special to flow through either.
6. **`buildDetectionExecutor`'s session threading** (Phase 3.19) already
   makes EVERY active detector's requests authenticated whenever the
   scan itself authenticated -- `sqliactive` needs no detector-specific
   authentication code at all, exactly like `xssactive`.
7. **`BuildTargets`'s JSON extension** (Phase 3.19) already surfaces
   `REQUEST_INPUT`-provenance JSON parameters with
   `ParameterLocation: "body"` -- `sqliactive`'s eligibility mirrors
   `xssactive`'s own query/body handling exactly, no further target-
   selection change is needed.
8. **Existing lab SQLi fixtures are extensive and directly reusable**:
   `/sqli/vulnerable` (error-based), `/sqli/boolean/vulnerable`
   (pure boolean-differential, no error text ever), `/sqli/safe` and
   `/sqli/boolean/safe` (parameterized negatives), `/sqli/generic-error`
   (a 500 with database-error-shaped wording that is UNCONDITIONAL,
   regardless of input -- the exact "unrelated database error" false-
   positive trap task section 9 requires), `/sqli/dynamic` (a
   response that varies for reasons unrelated to the parameter -- the
   exact "unstable application response" trap). Only two genuinely new
   fixtures are needed: a POST-form and a JSON-body vulnerable
   endpoint (section 8).
9. **`internal/detectors/sqli/errorpatterns.go`'s `dbErrorPatterns`
   table** is a clean, already-reviewed design (per-family substring
   lists, generic as a lower-confidence fallback) -- `sqliactive`
   re-derives the identical TABLE independently (not imported: no
   detector in this codebase imports another detector's package,
   preserving detector independence), rather than inventing a
   different signature set with no reason to differ.

## 2. Detection strategy

Four probes per eligible target, each executed via
`x.ExecuteMutation` -- mirroring `internal/detectors/sqli`'s own
proven design, reimplemented on the mutation engine rather than a
private client:

1. **Baseline** (`"1"`): a plain, syntactically inert control value.
   Establishes what an ordinary, non-malicious request/response looks
   like -- both the error-probe and boolean-probe signals are judged
   AGAINST this, never in isolation.
2. **Error probe** (`"'"`): the smallest possible syntax-breaking
   input. Its response is checked for a recognized database-error
   signature (`matchDBError`) -- but ONLY treated as evidence if the
   IDENTICAL signature is NOT already present in the baseline
   response (task section 9's "generic HTTP 500" / "unrelated database
   error" cases: `/sqli/generic-error` always contains
   database-error-shaped wording, including for the baseline itself,
   so the correlation step is what keeps this endpoint silent).
3. **True probe** (`"1' OR '1'='1"`): a tautology.
4. **False probe** (`"1' AND '1'='2"`): a contradiction.

Both true/false probe bodies are stripped of their OWN payload text
(raw, HTML-entity-encoded, URL-encoded forms) before being compared --
eliminating the "reflected payload" false-positive case structurally,
not by post-hoc filtering. The stripped bodies are then compared via
`mutation.Compare`; `StructurallyDifferent` (or a body-only difference
when status/content-type are already equal) is the boolean-differential
signal.

Classification (four tiers, matching `internal/detectors/sqli`'s own
already-reviewed rubric, reimplemented independently):

| Error signal | Boolean signal | Outcome |
|---|---|---|
| family-specific | yes | Critical, 0.95 -- two independent signals |
| none | yes | Critical, 0.75 -- confirmed behavioral differential alone |
| family-specific | no | High, 0.55 -- error alone, unconfirmed |
| generic only | no | Medium, 0.3 -- weak, cross-family wording only |
| none | no | No finding |

A single weak signal (a generic error alone, or a boolean difference
alone with no error) never reaches Critical -- matching task section
9's "prefer no finding over a low-confidence false positive" exactly.

## 3. Payload safety

Every payload is read-only: a bare digit, a single quote, and two
tautology/contradiction conditions built from literal, already-
established string comparisons (`'1'='1'`/`'1'='2'`) -- never a
statement that could plausibly execute `DROP`/`DELETE`/`UPDATE`/
`INSERT`/`CREATE`, never a stacked query, never an out-of-band
callback. This is unchanged from `internal/detectors/sqli`'s own
already-reviewed payload set (Phase 3.3) -- reused verbatim, not
reinvented, since a new payload set would only introduce new risk for
no benefit.

## 4. Time-based SQLi: explicitly not implemented

Per task section 3's own conditional ("if time-based SQLi is
implemented, it must have strict timing controls...") -- it is NOT
implemented this phase. Timing-based detection requires distinguishing
a deliberate database delay from ordinary network/scan-concurrency
jitter, which this architecture's shared, concurrently-used
`Executor` (bounded worker pool, shared rate limiter) cannot yet do
reliably: two probes racing against N other detectors' own in-flight
requests would see timing noise unrelated to the target's own
behavior. Documented as a known limitation (section 14), not silently
skipped.

## 5. Consumption of Phase 3.19 infrastructure -- exact call shape

```go
original := detection.NewMutationRequest(t)          // Phase 3.19 bridge, reused verbatim
loc := mutation.LocationQuery                         // or mutation.LocationJSON for t.ParameterLocation == "body"

baseline := probe(ctx, x, original, loc, t, "1")
errProbe := probe(ctx, x, original, loc, t, "'")
trueProbe := probe(ctx, x, original, loc, t, "1' OR '1'='1")
falseProbe := probe(ctx, x, original, loc, t, "1' AND '1'='2")

// probe() is THIS detector's own thin helper -- it does no HTTP of its
// own; it only calls mutation.NewMutation/Mutate/x.ExecuteMutation,
// exactly like xssactive's own Detect does inline.
```

No detector-specific HTTP client, cookie jar, or scope decision exists
anywhere in `sqliactive` -- verified by inspection (grep for
`net/http.Client`/`cookiejar`/`scope\.` inside the package returns
nothing beyond the imported types `mutation.Request`/`Response`
themselves reference).

## 6-7. Authentication / multi-identity

Identical to `xssactive`: `Executor.ExecuteMutation` is already
session-aware whenever `buildDetectionExecutor` threaded a session in
(Phase 3.19); `sqliactive` never touches a credential, a cookie jar, or
an identity string beyond reading `t.IdentityContext` to stamp it onto
its own `mutation.Mutation` values (for evidence/provenance), exactly
as `xssactive` already does. No new authentication code was written.

## 8. Lab

Two new, minimal fixtures (`lab/harness_vuln.go`, extended in place):
`/sqli/form/vulnerable` (POST form field, same error-based logic as
`/sqli/vulnerable`) and `/sqli/json/vulnerable` (JSON body field, same
logic). Both reuse the exact same `sqliFakeDB()`/naive-string-
concatenation-simulation the existing query fixtures already use --
no new "database," no new vulnerability shape, just a different input
location for the identical, already-reviewed behavior.

## 9. What this phase intentionally does not implement

- No SSRF, command injection, path traversal, IDOR/BOLA, authorization
  testing, stored/DOM/blind XSS, mass assignment, business-logic
  testing.
- No database dumping, destructive SQL, OS command execution, or
  automated exploitation of any kind.
- No time-based SQLi (section 4).
- No migration of the existing `internal/detectors/sqli` onto
  `internal/mutation` -- it keeps its own private `requestURL`/`probe`
  pair, unchanged, fully covered by its own pre-existing suite.
- No new `Metadata` fields, no new CLI surface, no new config/profile
  knobs -- `sqliactive` is registered exactly like every other
  detector, with no additional plumbing.

## 10. How this phase answers task section 18's questions

Answered in full, with the actual test that proves each, in
`docs/phase-3-20-sqli-acceptance-test.md`'s own "Final architectural
validation" section.
