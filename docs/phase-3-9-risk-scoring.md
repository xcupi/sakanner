# Phase 3.9: Risk Scoring & Prioritization Engine

**This is an internal deterministic prioritization model, not CVSS or
EPSS.** `internal/risk` consumes ONLY `internal/correlation.CanonicalFinding`
values (Phase 3.8's output) and produces a `RiskScore` (0-100), a
`Priority` band, a reproducible `ScoreBreakdown`, and a deterministic,
human-readable `Explanation` for each. No LLM, no network request, no
external service, and no randomness is involved anywhere in this
computation.

## Scoring philosophy

The risk score answers a narrower question than "how bad is this
vulnerability" (that's what `Severity` already answers, and this
package never touches it). It answers: **given this finding's
severity, how much evidence backs it, and how exposed is the affected
asset, how urgently should someone look at it first?** Two findings
with identical `Severity` can have very different risk scores; the
reverse is also true (see "Severity vs. priority" below).

## Architecture

```
internal/risk/
├── model.go              CanonicalFinding-independent types: RiskFactors,
│                          ScoreBreakdown, Assessment, AssetContext, tiers
├── weights.go               the ONE centralized weight table (task section 3)
├── score.go                   Score(), clampScore(), PriorityForScore()
├── derive.go                     DeriveFactors() -- the only place a real
│                                  CanonicalFinding's fields are read
├── explain.go                      Explain() -- deterministic sentence generation
└── engine.go                          Assess()/AssessAll()/Rank()
```

```
Detector (unchanged)
    ↓
Phase 3.8 correlation.Engine
    ↓
CanonicalFinding
    ↓  DeriveFactors(cf, ctx)
RiskFactors (Severity, Confidence, Verification, Exposure)
    ↓  Score(factors)
ScoreBreakdown (severity_base, 3 multipliers, raw_score, risk_score, priority)
    ↓  Assess(cf, ctx)
Assessment (score + breakdown + explanation + asset summary)
    ↓  Rank(assessments)
deterministically-ordered []Assessment
```

`RiskFactors` is deliberately constructible directly, independent of
any real `CanonicalFinding` -- this is what makes the full 4×3×3×4
factor matrix and the monotonicity properties (see below) testable
exhaustively, not just for whatever combinations happen to occur in
the lab.

## Inputs

Exactly one `correlation.CanonicalFinding` plus an optional
`*AssetContext` (task section 9: host, port, protocol, application,
endpoint, environment, and an explicit `Exposure` override). No raw
`models.Finding`, no detector-specific evidence parsing, and no second
read of anything Phase 3.8 already normalized.

## Severity values

Reused from `pkg/models.Severity` unchanged -- never overwritten,
never re-derived. `Assessment.Severity` is always exactly
`CanonicalFinding.Severity`.

| Severity | Base |
|---|---|
| `critical` | 90 |
| `high` | 70 |
| `medium` | 40 |
| `low` | 20 |
| `info` | 10 (a real, recognized value below `low` -- see "Unknown values") |
| *(unrecognized)* | 10 (the conservative fallback -- never assumed strongest) |

## Confidence multipliers

`CanonicalFinding.Confidence` (a continuous 0-1 float from Phase 3.8)
is bucketed into one of 3 tiers using the same 0.4/0.75 thresholds
`internal/correlation`'s own confidence-tier bucketing uses, for
consistency between how the two phases talk about confidence:

| Tier | Threshold | Multiplier |
|---|---|---|
| HIGH | ≥ 0.75 | 1.00 |
| MEDIUM | ≥ 0.40 | 0.75 |
| LOW | < 0.40 | 0.50 |

A comparison against `NaN` is always false in Go, so a `NaN`
confidence value falls through every threshold and lands on LOW
without any special-casing -- an elegant, already-safe consequence of
how the bucketing is written, confirmed directly by
`TestDeriveFactors_NaNConfidenceFallsBackToLow`.

## Verification multipliers

| Tier | Multiplier |
|---|---|
| VERIFIED | 1.00 |
| SUSPICIOUS | 0.85 |
| UNVERIFIED | 0.70 |

### Derivation: an independent axis from Confidence, not a renamed copy of it

Task section 7 requires "use existing finding evidence... do not infer
VERIFIED solely from severity," and section 19 requires the risk
engine to "remain independent from detector implementation" (never
re-parsing a detector's raw evidence). `verificationTierOf` reads only
two fields Phase 3.8 already computed:

- `CanonicalFinding.Status == correlation.StatusConfirmed` (2+
  INDEPENDENTLY-signatured pieces of evidence corroborated the same
  identity -- see
  [docs/phase-3-8-finding-correlation.md](phase-3-8-finding-correlation.md)
  "Finding status") → **VERIFIED**, unconditionally. This is the
  strongest signal available: multiple different observations agreeing,
  not just one detector run's own confidence claim.
- Otherwise, `Status == StatusNew` (exactly one distinct evidence
  signature so far): **SUSPICIOUS** if that single observation is
  itself HIGH confidence (matching every real detector's own "confirmed
  via controlled marker" tier -- task section 7's per-detector examples
  all correspond to each detector's ~0.9+ confidence case), else
  **UNVERIFIED**.

This design keeps Verification genuinely independent of Confidence
rather than a relabeled duplicate: a HIGH-confidence single observation
is SUSPICIOUS (strong, but not yet independently corroborated), while a
MEDIUM-confidence finding a SECOND, distinct piece of evidence also
corroborates is VERIFIED (individually weaker, but agreed upon by more
than one observation). `TestDeriveFactors_VerificationNeverInferredFromSeverityAlone`
confirms a CRITICAL-severity finding with weak, uncorroborated evidence
still derives UNVERIFIED.

## Exposure multipliers

| Tier | Multiplier |
|---|---|
| INTERNET_FACING | 1.00 |
| RESTRICTED | 0.75 |
| UNKNOWN | 0.70 |
| INTERNAL | 0.60 |

`UNKNOWN` (0.70) deliberately sits between `INTERNAL` (0.60) and
`RESTRICTED` (0.75) -- an asset of undetermined exposure is treated
more cautiously than a known-restricted one, but is never assumed
internet-facing (task section 8's explicit instruction).
`TestMonotonicity_UnknownExposureBetweenInternalAndRestricted` confirms
this ordering directly.

### Derivation: honestly UNKNOWN for every real finding today

This project's current recon model (Phases 1-3.8) tracks no
internet-facing/internal/restricted classification for any asset --
there is no stage that determines this yet. `exposureOf` therefore
resolves `ExposureUnknown` for every real `CanonicalFinding` unless the
caller explicitly supplies one via `AssetContext.Exposure`. This is not
a gap papered over silently: it is exactly the conservative default
task section 8 requires, and it is documented here and in "Limitations"
below rather than assumed away.

## Formula

```
raw_score = severity_base × confidence_multiplier × verification_multiplier × exposure_multiplier
risk_score = round(clamp(raw_score, 0, 100))
```

`Score(factors RiskFactors) ScoreBreakdown` is the ONLY function that
touches the weight tables in `weights.go`; every other entry point
(`Assess`, `AssessAll`) eventually calls it, so there is exactly one
place the formula is implemented (task section 3's "the exact weights
must be documented and centralized").

## Rounding

`math.Round` -- round-half-away-from-zero (4.5 → 5, 76.5 → 77) -- a
standard, deterministic Go stdlib function, never a hand-rolled
rounding rule. Confirmed directly for several half-integer cases in
`TestRounding_HalfAwayFromZero`.

## Clamping

`clampScore` handles every value `math.Round` could theoretically
receive, including values that can never arise from the documented
formula's own arithmetic (a finite product of finite positive numbers)
but that a directly-constructed adversarial `RiskFactors` call could
still produce if the tables were ever extended incorrectly:

| Input | Output |
|---|---|
| `NaN` | 0 |
| `+Inf` | 100 |
| `-Inf` | 0 |
| `> 100` | 100 |
| `< 0` | 0 |

`PriorityForScore` (exported, callable directly with any int) applies
the same defensive clamp before banding, so a caller passing `101` or
`-5` directly (task section 21's exact boundary values) never produces
an out-of-band result.

## Priority thresholds

Integer band comparison ONLY -- `PriorityForScore` rounds/clamps to an
`int` *before* any band comparison ever runs, eliminating the
floating-point boundary ambiguity task section 4 explicitly warns
against (a raw score of 89.9999999 is never left to accidentally
compare as `>= 90`; it is rounded to 90 or 89 first, deterministically,
by `math.Round`).

| Range | Priority |
|---|---|
| 90-100 | CRITICAL |
| 75-89 | HIGH |
| 50-74 | MEDIUM |
| 0-49 | LOW |

### Reachability -- a documented characteristic, not a defect

Under the documented weight table, the maximum `raw_score` any severity
level can reach (all three multipliers at their ceiling, 1.00) is
exactly its own `severity_base`: 90 for CRITICAL, 70 for HIGH, 40 for
MEDIUM, 20 for LOW. This means **HIGH severity alone can never reach
the HIGH priority band** (75-89) -- its ceiling (70) lands one point
short, in MEDIUM. Only CRITICAL severity (base 90) can reach the
CRITICAL priority band, and only by landing exactly on its floor.

This is confirmed directly by `TestFormula_ExactExample` (HIGH severity
+ perfect confidence/verification/exposure = 70, MEDIUM priority, not
HIGH) and documented here explicitly because the task's own section 5
uses an illustrative example ("Severity: HIGH, Risk score: 92, Priority:
CRITICAL. This is valid.") that is not literally reproducible from
section 3's suggested weight table taken at face value. That example is
read here as illustrating the CONCEPT that severity and priority are
independent (a fact this implementation fully upholds -- see "Severity
vs. priority" below), not as a numerical regression the suggested
weights must reproduce exactly; task section 3 itself frames the table
as "a simple baseline" a caller may adjust "if [it] remains
deterministic, explainable, bounded, and testable." This implementation
takes the suggested numbers as-is rather than inventing an adjustment
not explicitly requested, and documents the resulting reachability
characteristic honestly rather than silently.

## Ranking and tie-breaking

`Rank([]Assessment) []Assessment` sorts by task section 14's exact
8-step order, never mutating its input:

1. `RiskScore` descending
2. `Severity` descending (ordinal: info < low < medium < high < critical)
3. `Confidence` tier descending
4. `Verification` tier descending
5. `Asset.Host` ascending
6. `Asset.Path` ascending
7. `VulnerabilityType` ascending
8. `FindingID` ascending (a content hash -- see
   [docs/phase-3-8-finding-correlation.md](phase-3-8-finding-correlation.md)
   -- always available, always distinguishes two genuinely different
   findings, so this step is always sufficient to produce a total
   order)

Never `AssessedAt`, goroutine scheduling, or any random source --
`TestRank_NeverUsesRandomOrCreationTimeOrdering` confirms a
later-timestamped finding can still rank before an earlier one when the
documented keys say so, and
`TestRank_TieBreaksDeterministicallyToTheEnd` confirms two assessments
identical in every dimension except `FindingID` still order the same
way across 5 repeated calls.

## Unknown values

Task section 20's exact recommendations, implemented literally:

- Unknown/unrecognized severity → conservative base (10), never treated
  as the strongest value; `Breakdown.SeverityRecognized = false` makes
  this auditable.
- Unknown/unrecognized confidence → LOW.
- Unknown/unrecognized verification → UNVERIFIED.
- Unknown/unrecognized exposure → UNKNOWN's own multiplier (0.70).

None of these ever panic; a completely zero-value `RiskFactors{}` or an
entirely empty `correlation.CanonicalFinding{}` both produce a
well-formed, in-range `Assessment` (`TestEmptyRiskFactors_NeverPanics`,
`TestSecurity_EmptyStrings_NoCrash`).

## Monotonicity

Task section 24: if severity, confidence, verification, or exposure
increases with every other factor held equal, `risk_score` must never
decrease -- "if any of these properties fail: PHASE 3.9 FAIL."

This holds **by mathematical construction**, not by luck: `Score` is a
product of non-negative factors drawn from tables whose values are
non-decreasing in "strength" order (task section 3's own suggested
numbers already satisfy this: 20<40<70<90; 0.5<0.75<1.0 three times
over), and the product of non-decreasing positive factors is itself
non-decreasing; `math.Round` is a non-decreasing function of its input,
so rounding never introduces a monotonicity violation either. This
project's own revert-and-verify discipline confirmed the tests
genuinely enforce this: temporarily reordering the confidence table so
HIGH (0.60) scored below MEDIUM (0.75) immediately failed
`TestMonotonicity_ConfidenceIncreaseNeverDecreasesScore` with the exact
"PHASE 3.9 FAIL" message the task specifies -- see
[docs/phase-3-9-acceptance-test.md](phase-3-9-acceptance-test.md)
"Revert-and-verify."

`matrix_test.go` and `monotonicity_test.go` verify all four properties
exhaustively across the full 4×3×3×4 factor space, not just for
individual examples.

## Severity vs. priority

`Assessment.Severity` and `Assessment.Priority` are computed
independently and never made to agree by construction -- exactly task
section 1/5's requirement. A HIGH-severity, well-corroborated,
internet-facing finding can score a risk_score that lands in a
DIFFERENT priority band than what its severity alone might suggest
(section 5's core point); `Severity` itself is never downgraded,
upgraded, or overwritten anywhere in this package.
`TestAssess_PreservesOriginalSeverity` and
`TestDeriveFactors_SeverityPassedThroughUnmodified` confirm this
directly.

## No double counting

Phase 3.8 has already deduplicated findings and merged their evidence
into one `CanonicalFinding` per identity before this package ever sees
them (task section 18). This package never re-examines individual
probes or evidence items -- `DeriveFactors` reads only
`CanonicalFinding.Confidence` (already Phase 3.8's own consolidated
value) and `.Status` (already Phase 3.8's own corroboration count), so
a duplicate probe or repeated identical evidence item can never inflate
a risk score here; that guarantee was already established one layer
down, in
[docs/phase-3-8-finding-correlation.md](phase-3-8-finding-correlation.md)
"Confidence consolidation."

## Vulnerability type

No detector-specific multiplier of any kind exists anywhere in this
package (task section 17: "do NOT hard-code vulnerability-specific risk
multipliers"). `VulnerabilityType` is carried through to `Assessment`
for display and as ranking step 7 only -- it never appears on either
side of an `if` statement inside `score.go`, and `weights.go` contains
no per-type table at all.

## Security considerations

`internal/risk` is a pure, in-memory computation package -- it imports
neither `os/exec`, `syscall`, `net`, nor `net/http` (checked
mechanically via `go/parser` against real AST import declarations,
`TestSecurity_SourceNeverTouchesFilesystemNetworkShellOrLLM`), makes no
filesystem access, issues no network request, invokes no shell, and
calls no LLM. Every `CanonicalFinding` field is treated as untrusted:
tested directly against missing/invalid severity, `NaN`/`Infinity`/
negative confidence, invalid exposure and verification values, extremely
large finding sets (5000+), malformed metadata (SQL-injection-shaped and
shell-metacharacter-shaped strings -- never interpreted, only ever
compared as opaque strings), Unicode and raw control-byte content, empty
strings, and an entirely empty `CanonicalFinding{}` -- none of these
panic or produce an out-of-range score.

## Performance

`Score`/`Assess` are O(1) (a handful of map lookups and multiplications);
`AssessAll` is O(n); `Rank` is O(n log n) for the final sort. Measured
directly: 1000 findings assess+rank in ~31ms, 10000 in ~365ms, with
sub-quadratic scaling confirmed (a 10x input increase produced roughly
13x the runtime, not the ~100x a true O(n²) algorithm would show).

## Concurrency

Neither `Score`, `Assess`, `AssessAll`, nor `Rank` reads or writes any
package-level mutable state -- every one is a pure function of its
arguments, so concurrent use needs no locking to be safe. Verified
under `-race` with up to 100 concurrent goroutines calling `Score`/
`Assess` against the identical input and confirming byte-identical
results every time, plus 20 concurrent `Rank` calls against a shared
50-assessment slice confirming identical output order every time.

## Limitations

- **Exposure is UNKNOWN for every real finding today.** This project's
  recon model has no internet-facing/internal/restricted
  classification stage yet; `AssetContext` exists and is fully tested
  so a future phase (or an operator-supplied scope annotation) can
  supply real exposure data, but no current code path in sakanner does
  so automatically.
- **HIGH severity alone cannot reach the HIGH priority band** under the
  suggested weight table (see "Reachability" above) -- a documented
  mathematical consequence of taking task section 3's suggested numbers
  as-is, not a defect.
- **Not wired into the production CLI pipeline.** Like Phase 3.8,
  `cmd/scanner` does not call this package yet; it is fully built,
  tested, and ready for a future report-generation phase to consume.
- **Verification derivation is a documented heuristic**, not a formal
  guarantee. It is the most defensible mapping available from Phase
  3.8's own already-computed signals (see "Derivation" above under
  Verification multipliers), but a future phase with richer
  per-detector confirmation semantics could refine it further.
