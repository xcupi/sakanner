# Phase 3.9 Acceptance Test: Risk Scoring & Prioritization Engine

Scope: `internal/risk` (the canonical `RiskFactors`/`ScoreBreakdown`/
`Assessment` model, the centralized weight table, the scoring formula,
factor derivation from Phase 3.8 canonical findings, explanation
generation, and deterministic ranking), and
`lab/phase3_9_risk_test.go` (the integration test proving real
canonical findings from all six detectors score correctly end to end).
See [docs/phase-3-9-risk-scoring.md](phase-3-9-risk-scoring.md) for the
full architecture writeup this test verifies against.

This phase touched **no existing code** outside `internal/risk` and its
own new test files -- no detector, no `internal/correlation`, no
`pkg/models`, and no `cmd/scanner` file was modified.

## What was built

- `internal/risk/model.go`: `ConfidenceTier`, `VerificationTier`,
  `ExposureTier`, `Priority`, `RiskFactors`, `AssetContext`,
  `ScoreBreakdown`, `Assessment`, `AssetSummary` -- task section 1's
  canonical model plus every supporting type.
- `internal/risk/weights.go`: the single, centralized weight table
  (`severityBase`, `confidenceMultiplier`, `verificationMultiplier`,
  `exposureMultiplier`, priority band thresholds) -- task section 3's
  suggested numbers, taken as-is.
- `internal/risk/score.go`: `Score` (the formula), `clampScore`
  (rounding + clamping, including NaN/Infinity handling),
  `PriorityForScore` (band classification).
- `internal/risk/derive.go`: `DeriveFactors`, `confidenceTierOf`,
  `verificationTierOf`, `exposureOf` -- the only code that reads a real
  `CanonicalFinding`'s fields.
- `internal/risk/explain.go`: `Explain` -- deterministic, rule-based
  sentence generation.
- `internal/risk/engine.go`: `Assess`, `AssessAll`, `Rank` -- the
  public pipeline entry points.
- `lab/phase3_9_risk_test.go`: runs all 6 real detectors through
  the real Phase 3.1 engine, feeds the output through the real Phase
  3.8 correlation engine, then through this phase's risk engine, and
  verifies every resulting assessment.
- Tests: 78 unit/matrix/monotonicity/security/performance/concurrency
  tests in `internal/risk`, 1 integration test in `lab`.

## Real canonical findings scored end to end (task section 29)

`TestPhase3_9_Risk_RealCanonicalFindingsProduceAssessments` runs real
recon and all six real detectors through the real `detection.Engine`
against the real `vuln.scanner.test` lab, correlates the results with
the real Phase 3.8 engine, then assesses and ranks every canonical
finding:

```
Correlation: 8 raw findings -> 8 canonical findings
Top-ranked finding: 01299ce1eab650691e38979851a5a583 (command_injection, score=54, priority=MEDIUM)
```

Every one of the 8 canonical findings (covering all 6 vulnerability
types) received a risk score in `[0, 100]`, a non-empty priority, a
non-empty explanation, a matching `Breakdown.RiskScore`, and a
recognized severity -- confirmed by direct assertion, not just absence
of a crash. Repeating `AssessAll`+`Rank` against the identical
canonical set reproduced identical order, scores, and explanations.

## Acceptance table (task sections 31-32)

The 6 synthetic fixtures task section 31 requires, scored by
`TestAcceptanceMatrix_SixSyntheticFixtures`:

| Finding | Severity | Confidence | Verification | Exposure | Score | Priority | Expected | Actual | Result |
|---|---|---|---|---|---|---|---|---|---|
| 1. LOW / LOW / internal | low | LOW | UNVERIFIED | INTERNAL | 4 | LOW | 4/LOW | 4/LOW | PASS |
| 2. MEDIUM / HIGH conf / internal | medium | HIGH | SUSPICIOUS | INTERNAL | 20 | LOW | 20/LOW | 20/LOW | PASS |
| 3. HIGH / HIGH conf / internet-facing | high | HIGH | SUSPICIOUS | INTERNET_FACING | 60 | MEDIUM | 60/MEDIUM | 60/MEDIUM | PASS |
| 4. CRITICAL / HIGH conf / internet-facing | critical | HIGH | SUSPICIOUS | INTERNET_FACING | 77 | HIGH | 77/HIGH | 77/HIGH | PASS |
| 5. HIGH / LOW conf / unknown exposure | high | LOW | UNVERIFIED | UNKNOWN | 17 | LOW | 17/LOW | 17/LOW | PASS |
| 6. MEDIUM / VERIFIED / internet-facing | medium | MEDIUM | VERIFIED | INTERNET_FACING | 30 | LOW | 30/LOW | 30/LOW | PASS |

Note fixtures 3 and 4 derive `SUSPICIOUS` (not `VERIFIED`) because both
are constructed at `correlation.StatusNew` (a single, strong
observation) -- per `derive.go`'s documented rule, `VERIFIED` requires
`StatusConfirmed` (2+ independent evidence signatures), which is
exactly what fixture 6 demonstrates instead, landing at `VERIFIED`
despite weaker individual severity/confidence. This is the intended,
documented behavior (see "Verification multipliers" in
[docs/phase-3-9-risk-scoring.md](phase-3-9-risk-scoring.md)), not an
inconsistency.

## Revert-and-verify: monotonicity and boundary correctness

Per the task's "do not weaken tests to achieve PASS" instruction, both
of this phase's central correctness properties were verified by
temporarily breaking them and confirming the right tests fail for the
right reason, then reverting.

1. **Monotonicity direction**: `confidenceMultiplier[ConfidenceHigh]`
   was temporarily changed from `1.00` to `0.60` -- below
   `ConfidenceMedium`'s `0.75`, breaking the "stronger confidence never
   lowers score" invariant. Re-running
   `TestMonotonicity_ConfidenceIncreaseNeverDecreasesScore` failed
   exactly as expected, with the task's own required wording:
   ```
   PHASE 3.9 FAIL: confidence increase decreased score (severity=low confidence=HIGH verification=UNVERIFIED exposure=INTERNAL): 5 < previous 6
   ```
2. **Boundary direction**: `PriorityForScore`'s CRITICAL comparison was
   temporarily changed from `score >= priorityCriticalMin` to
   `score > priorityCriticalMin`, incorrectly excluding the boundary
   value 90 from CRITICAL. Re-running `TestPriorityBands_ExactBoundaries`
   failed exactly as expected:
   ```
   PriorityForScore(90) = HIGH, want CRITICAL
   ```

Both defects were reverted; `go build ./...`, the full `internal/risk`
package suite, and `go test ./lab/... -race -run TestPhase3_9 -v`
were all re-run and confirmed clean after restoration.

## Regression

Full suite, `go test -race -count=1 -v ./...`, run after every change
in this phase (including both revert-and-verify exercises) and again
as the final check:

```
TOTAL TESTS: 1000 (739 top-level + 261 subtests)
PASS:        1000
FAIL:        0
```

All 27 tested packages report `ok`. `gofmt -l .`, `go build ./...`, and
`go vet ./...` are all clean. `golangci-lint` is not installed on this
machine (unchanged from every prior phase). The CLI binary was rebuilt
and `scanner detectors list` confirmed unchanged (this phase touched no
`cmd/scanner` file).

- **Phase 1 regression**: unchanged, all pass.
- **Phase 2 regression**: unchanged, all pass.
- **Phase 3 Test Lab regression**: unchanged -- this phase added a new
  integration test file but modified no existing lab fixture, ground
  truth entry, or harness function.
- **Phase 3.1 regression**: `internal/detection` completely unchanged;
  all tests pass unchanged.
- **Phase 3.2 regression**: `internal/detectors/xssreflected`
  completely unchanged; all tests pass unchanged.
- **Phase 3.3 regression**: `internal/detectors/sqli` completely
  unchanged; all tests pass unchanged.
- **Phase 3.4 regression**: `internal/detectors/ssrf` completely
  unchanged; all tests pass unchanged.
- **Phase 3.5 regression**: `internal/detectors/idor` completely
  unchanged; all tests pass unchanged.
- **Phase 3.6 regression**: `internal/detectors/traversal` completely
  unchanged; all tests pass unchanged.
- **Phase 3.7 regression**: `internal/detectors/cmdinjection`
  completely unchanged; all tests pass unchanged.
- **Phase 3.8 regression**: `internal/correlation` completely
  unchanged; all tests pass unchanged -- confirming the new risk
  engine composes cleanly on top without touching the layer beneath it.

## Final report

```
TOTAL TESTS: 1000 (739 top-level + 261 subtests)
PASS: 1000
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

BOUNDARY TESTS: PASS
MATRIX TESTS: PASS
MONOTONICITY: PASS
DETERMINISTIC SCORING: PASS
DETERMINISTIC RANKING: PASS
TIE BREAKING: PASS
UNKNOWN INPUTS: PASS
ADVERSARIAL: PASS
PERFORMANCE: PASS
CONCURRENCY: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0

PHASE 1 REGRESSION: PASS
PHASE 2 REGRESSION: PASS
PHASE 3 LAB REGRESSION: PASS
PHASE 3.1 REGRESSION: PASS
PHASE 3.2 REGRESSION: PASS
PHASE 3.3 REGRESSION: PASS
PHASE 3.4 REGRESSION: PASS
PHASE 3.5 REGRESSION: PASS
PHASE 3.6 REGRESSION: PASS
PHASE 3.7 REGRESSION: PASS
PHASE 3.8 REGRESSION: PASS

PHASE 3.9 ADVERSARIAL: PASS

PHASE 3.9 VERDICT: PASS
```

Not proceeding to Phase 3.10, not implementing CVSS, EPSS, external
threat intelligence, new vulnerability detectors, exploitation,
remediation, or LLM runtime functionality, per the task's explicit
instruction to stop after this report.
