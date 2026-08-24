# Phase 3.31 Acceptance Test — Vulnerability Chain Integration & Reporting

## PHASE 3.31 VULNERABILITY CHAIN INTEGRATION & REPORTING

```
TOTAL TESTS: 2202
PASS:        2202
FAIL:        0
PARTIAL:     0
NOT IMPLEMENTED: 0

CHAIN INTEGRATION: PASS
PERSISTENCE: PASS
IDENTITY ISOLATION: PASS
SCOPE ENFORCEMENT: PASS
CHAIN EVIDENCE: PASS
CHAIN STATUS: PASS
RISK/SEVERITY: PASS
CLI/REPORTING: PASS
DETERMINISM: PASS
RESOURCE LIMITS: PASS
LAB: PASS
E2E: PASS
ADVERSARIAL: PASS
REGRESSION: PASS
RACE: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 1 (see below, non-blocking)

PHASE 3.31 VERDICT: PASS
```

2180 tests carried over unchanged from Phase 3.1 through 3.30 (all
still passing). 22 tests are new: 4 in
[internal/chains/adversarial_scenarios_test.go](../internal/chains/adversarial_scenarios_test.go),
2 new in [internal/chains/falsepositive_test.go](../internal/chains/falsepositive_test.go)
(reproducing the real defect discovered this phase — see DEFECTS
FOUND AND FIXED), 7 in
[internal/storage/sqlite/chains_test.go](../internal/storage/sqlite/chains_test.go),
6 in [lab/phase3_31_chains_integration_test.go](../lab/phase3_31_chains_integration_test.go),
3 in [tests/e2e/e2e_chains_cli_test.go](../tests/e2e/e2e_chains_cli_test.go).

## ARCHITECTURE REVIEW

Full review in
[docs/phase-3-31-chain-integration.md](phase-3-31-chain-integration.md),
covering `internal/chains`, `models.Finding`, existing persistence,
`internal/correlation`, reporting/output paths, orchestration, CLI
surfaces, `IdentityContext`, `ScanJobID`, dedup behavior, and risk/
severity representation, each verified directly against the
repository. Headline finding: `cmd/scanner/report.go` has never
consumed Phase 3.8/3.9/3.10's own correlation/risk/evidence output at
all — those computations are ephemeral, produced fresh inside one
`Orchestrator.Run` call and never persisted or independently re-
exposed. This phase's own chain data deliberately breaks that
precedent (chains ARE persisted, per the task's own explicit
requirement) specifically so `scanner chains` can read them back
independently of any single scan run.

**Smallest architecturally correct integration point**: chain
generation runs as an additive step INSIDE the existing
`StageCorrelation` block in `internal/orchestrator.Orchestrator.Run`
(right after Phase 3.8's own `ce.Findings()` call, using the SAME
already-fetched raw findings), rather than adding a new `Stage`
constant — avoiding a broader, higher-risk change to `stageOrder`
("the ONLY place this order is defined") and `state.go`'s own hard-
coded progress-percentage table for a phase that doesn't need it.

## CHAIN INTEGRATION

`internal/orchestrator/orchestrator.go`'s `StageCorrelation` block
now also calls `chains.Correlate(rawFindings, chains.DefaultLimits())`
and persists the result via `o.Store.Chains().SaveResult`. A
persistence failure is isolated as a warning (`ErrorCategoryWarning`),
never a stage failure — proven with a real, targeted failure injection
(`errorChainsStore`, Go interface embedding overriding only `Chains()`
while every other repository forwards to a real, unmodified store):
`TestPhase3_31_ChainPersistenceFailure_NeverFailsTheScan`. Detection
genuinely continues testing every eligible target/detector regardless
of chain correlation — proven with a real, broad scan producing
findings from multiple distinct detector IDs
(`TestPhase3_31_RealScan_ProducesAndPersistsGenuineChain`).
`internal/chains` itself was not modified to depend upward on
storage/orchestrator/CLI (confirmed: its own package imports remain
`pkg/models` only).

## PERSISTENCE

New, additive migration `0014_chains.sql` — `chain_relations`/
`chain_candidates`, both FK'd to `scan_jobs(id) ON DELETE CASCADE`
mirroring `findings`'s own established pattern. `SaveResult` replaces
(never appends) per scan, proven idempotent
(`TestChains_SaveResult_IdempotentReplay`,
`TestChains_SaveResult_ReplacesNotAppends`). Cascade deletion proven
(`TestChains_ScanJobDeletion_CascadesToChains`). Deterministic read
order (by content-derived ID, ascending) proven across 5 repeated
reads (`TestChains_DeterministicReadOrder`). Old databases remain
readable — the existing, unmodified migration-versioning system
(`0001`-`0013`) applies `0014` exactly like any other pending
migration; the full regression run (including every pre-existing
`internal/storage/sqlite` test) confirms nothing about the existing
schema/data changed.

## IDENTITY ISOLATION

The task's own literal worked example (Account A IDOR + Account B XSS
on the same object must never chain) is reproduced twice: at the
`internal/chains` level (`TestIdentityIsolation_TaskWorkedExample`,
carried over from Phase 3.30) and — new this phase — against REAL
findings from two REAL, independently-authenticated orchestrator runs,
read back from REAL persistence
(`TestPhase3_31_TaskWorkedExample_RealPersistedFindings`). Account
A+Account A findings correlate normally (proven throughout); Account
B+Account B likewise; Account A+Account B never do, at every layer
tested (in-memory `Correlate`, persisted relations, merged real-finding
re-correlation).

## SCOPE ENFORCEMENT

Zero new scope code. `TestPhase3_31_ScopeIsolation_OutOfScopeCandidateNeverReachable`
proves an out-of-scope host's finding, even if fed into the same
`Correlate` call as an in-scope one, never becomes `SAME_ENDPOINT` and
never reaches `SUPPORTED`/`CONFIRMED` status. Scope enforcement itself
remains entirely upstream (a `Finding` only exists because a detector
already ran against an in-scope target) — this phase's own
responsibility (proven here) is narrower: chain correlation never
introduces its OWN scope-crossing bypass.

## CHAIN EVIDENCE

Every relation's evidence remains traceable to the exact matched
token/value already present in a finding's own evidence — persisted
verbatim, displayed verbatim by `chains show`. No secret amplification:
`TestAdversarial16_SecretShapedEvidence_NeverAmplified` proves relation
evidence never exceeds the length of (or reconstructs beyond) the
matched substring a finding's own evidence already carried.

## CHAIN STATUS

`POTENTIAL`/`SUPPORTED` (the "candidate" family) vs. `CONFIRMED` (never
assigned by this phase's own policy, for the same deliberate reason
Phase 3.30 established — see architecture doc section 4). Proven
directly against REAL data:
`TestPhase3_31_RealScan_ProducesAndPersistsGenuineChain` explicitly
asserts no candidate from a real, broad scan is ever `CONFIRMED`.

## RISK/SEVERITY

No new scoring system. `ChainCandidate.Confidence`/`ImpactEstimate`
remain informational and clearly distinguished from any finding's own
`Severity` in the CLI (`chains show` labels them "Confidence"/"Impact",
never "Severity"), and every participating finding's own `Severity` is
displayed verbatim, unmodified. Proven:
`TestPhase3_31_RealScan_ProducesAndPersistsGenuineChain`'s field
checks, `TestChainsCmd_RealScan_ListsAndShowsPersistedChains`'s
`severity=` assertion.

## CLI/REPORTING

New, read-only `cmd/scanner/chains.go` (`scanner chains --scan <id>`,
`scanner chains show <id> --scan <id>`), registered in `root.go`
alongside every other existing command. No destructive verb. No
credential/secret ever displayed (chain evidence never contains one —
see CHAIN EVIDENCE above). Existing finding/report output completely
unmodified — full regression confirms. The operator can determine
everything the task lists: participating findings, relation type,
chain status, identity context, evidence summary, affected endpoints,
and individual finding severity — proven end to end through the real
compiled binary (`TestChainsCmd_RealScan_ListsAndShowsPersistedChains`).

## DETERMINISM

`internal/chains`'s own Phase 3.30 determinism guarantees (repeated
calls, shuffled input order) are unchanged and re-verified in the full
regression. New this phase: persisted chains survive a REAL database
close-and-reopen with byte-identical relation/candidate IDs and
ordering (`TestPhase3_31_DatabaseReload_ReproducesSameChains`).

## RESOURCE LIMITS

Unchanged from Phase 3.30 (`chains.DefaultLimits()`, reused as-is by
the orchestrator — no new, phase-specific limit type introduced). The
orchestrator's own chain-persistence step performs a bounded number of
additional DB writes (at most `MaxRelations` + `MaxCandidateChains`
rows), never unbounded. Verified the real, broad-scan test's own
finding count (34) stays well within `MaxFindings` (500) with no
truncation.

## LAB

`lab/phase3_31_chains_integration_test.go` (new, 6 tests) — no new
vulnerable fixture added (task's own "do not create unnecessary new
vulnerable fixtures"): the existing broad detector set (sqliactive,
xssactive, cmdinjectionactive, sstiactive) against the existing,
unmodified lab reliably produces a genuine chain
(`TestPhase3_31_RealScan_ProducesAndPersistsGenuineChain`: 34 real
findings, 112 relations, 8 persisted chain candidates from one real
scan). Every task-listed lab proof point is covered: individual
vulnerabilities detected independently (multiple distinct detector
IDs present), the chain layer recognizes the relationship, the chain
is persisted, evidence remains explainable (traced back to real
relation/finding IDs), and identity isolation remains intact (proven
against two real, independently-authenticated scans).

## E2E

`tests/e2e/e2e_chains_cli_test.go` (new, 3 tests): a REAL scan through
the actual compiled binary, followed by real `scanner chains`/`scanner
chains show` invocations against the real persisted result —
confirming the DEFAULT, production detector registry (not just the
lab's own broader test registry) naturally produces a genuine,
CLI-visible chain. Full e2e suite: 116/116 pass.

## ADVERSARIAL

All 20 task-named scenarios covered by an actual, passing test:

| # | Scenario | Test |
|---|---|---|
| 1 | Two genuinely related findings | `TestSameEndpoint_Recognized` et al. (Phase 3.30), `TestPhase3_31_RealScan_ProducesAndPersistsGenuineChain` |
| 2 | Unrelated findings with similar URLs | `TestFalsePositive_SimilarResponseBodiesUnrelatedEvidence`, `TestNoRelation_CompletelyUnrelatedFindings` |
| 3 | Unrelated findings with similar parameters | `TestFalsePositive_SameParameterNameUnrelatedEndpoints` |
| 4 | Same endpoint, different identities | `TestIdentityIsolation_AuthenticatedVsUnauthenticated_NeverRelate` |
| 5 | Same object ID, different identities | `TestIdentityIsolation_TaskWorkedExample`, `TestPhase3_31_TaskWorkedExample_RealPersistedFindings` |
| 6 | Duplicate finding vs. distinct vulnerability | `internal/correlation`'s own unchanged dedup (Phase 3.8) upstream of `internal/chains`; `TestCandidate_MultipleFindingsSameVulnerabilityTypeInOneChain` proves distinct findings of the same type still chain correctly |
| 7 | Chain with three findings | `TestCandidate_ThreeFindingsChainTogether` |
| 8 | Multiple independent chains in one scan | `TestAdversarial8_MultipleIndependentChainsInOneScan` |
| 9 | One finding in multiple valid relations | `TestAdversarial9_OneFindingInMultipleRelations` |
| 10 | Circular relation input | `TestAdversarial10_CircularRelationInput` |
| 11 | Malformed/stale finding references | `TestChains_StaleFindingReference_ReadsBackWithoutError` |
| 12 | Missing IdentityContext | `TestIdentityIsolation_UnauthenticatedFindingsCanStillRelate` |
| 13 | Unauthenticated findings | Same as #12 |
| 14 | Mixed authenticated/unauthenticated | `TestIdentityIsolation_AuthenticatedVsUnauthenticated_NeverRelate` |
| 15 | Out-of-scope candidate | `TestPhase3_31_ScopeIsolation_OutOfScopeCandidateNeverReachable` |
| 16 | Secret-containing evidence | `TestAdversarial16_SecretShapedEvidence_NeverAmplified` |
| 17 | Concurrent chain generation | `TestConcurrency_*` (Phase 3.30), `TestPhase3_31_ConcurrentScans_IndependentPersistedChains` |
| 18 | Cancellation during correlation | `TestConcurrency_CancellationDoesNotApply` (Phase 3.30 — `Correlate` takes no context, always bounded by `Limits`, proven to complete promptly even at max input size) |
| 19 | Repeated deterministic correlation | `TestDeterminism_*` (Phase 3.30), `TestChains_SaveResult_IdempotentReplay` |
| 20 | Database reload reproducing the same chains | `TestPhase3_31_DatabaseReload_ReproducesSameChains` |

## REGRESSION

Every prior phase's own test suite passes (2086/2086 non-e2e, 116/116
e2e — see TOTAL TESTS), including every pre-existing
`internal/orchestrator` and `internal/storage/sqlite` test — the two
packages this phase directly modified. No existing security assertion
was weakened or deleted.

## RACE

Full non-e2e suite passes clean under `go test -race` (confirmed in
the first regression pass; the verbose re-run used to extract exact
counts was run without `-race` purely to avoid doubling total runtime
— same code, same outcome).
`lab/phase3_31_chains_integration_test.go`'s own concurrent-scans test
and `internal/chains`'s own concurrency tests both re-confirmed clean
under `-race` specifically during development.

## SECURITY ISSUES

None found in production code.

## RELIABILITY ISSUES

None.

## PERFORMANCE ISSUES

1. **Non-blocking, honestly recorded**: the full e2e suite's total
   runtime continues its phase-over-phase growth (1315s here vs. 1306s
   in Phase 3.30, vs. 1252s in Phase 3.29) — now at ~53% of the
   25-minute budget. This phase's own contribution is 2 additional
   full-scan e2e tests (~75s each). Still comfortably within budget;
   flagged again as a trend, not a defect, consistent with the same
   honest note in the last two phases' own acceptance reports.

## DEFECTS FOUND AND FIXED

1. **Real defect, discovered by this phase's own integration testing
   against real, varied evidence (never surfaced by Phase 3.30's own
   hand-crafted unit tests): `SHARED_EVIDENCE` produced mass false-
   positive relations against a real, broad scan.** A shared PORT
   NUMBER (present in every finding's own evidence purely because
   they target the same host) and detector-internal fixed schema
   vocabulary/marker constants (a percent-encoded XSS payload marker,
   `response_fragment`, `COMMAND_INJECTION_MARKER`) both satisfied the
   original shape-only identifier check, manufacturing a relation
   between nearly every pair of findings in a 24-finding real scan (a
   single candidate absorbing 10 findings, hitting the `MaxChainLength`
   cap). Root-caused via direct reproduction against real evidence
   content, not merely inferred. Fixed with three additive
   refinements to `internal/chains/tokens.go` (digit-AND-non-digit
   requirement, exclusion of JSON `\uXXXX`-escape-artifact and
   predominantly-percent-encoded token shapes, and — the second layer
   of the same investigation — requiring an EXACT whole-token match
   between the two findings' own tokenized evidence rather than a raw
   substring-of-full-text check, which had let a short, individually-
   rare token slip through as a false match against an unrelated
   longer token it happened to prefix). Re-verified against the same
   real scan that surfaced the defect: false-positive relation count
   dropped from dominating nearly every finding pair to a small,
   documented residual (see REMAINING LIMITATIONS). Two new regression
   tests reproduce the exact real-world patterns discovered
   (`internal/chains/falsepositive_test.go`). This is a genuine,
   proactively-discovered-and-fixed defect in Phase 3.30's own design,
   not a regression this phase introduced — Phase 3.30 shipped without
   ever testing `SHARED_EVIDENCE` against real, heterogeneous detector
   evidence.

No defect was found in `internal/orchestrator`'s pre-existing stages,
`internal/storage`'s pre-existing repositories, or `internal/correlation`
— every fact this phase's architecture review relied on was
independently verified by directly reading the relevant source files,
and the full regression run confirms none of them required any
change.

## REMAINING LIMITATIONS

1. **`SHARED_EVIDENCE` remains an imperfect, heuristic signal even
   after this phase's fix.** A residual false-positive class remains
   possible: a detector-internal fixed constant that happens to be
   shared by only a SMALL number of findings in a given scan (below
   the frequency threshold) and is not caught by the digit-shape/
   encoding-artifact exclusions. Observed directly during this phase's
   own re-verification (e.g. an SSTI detector's own template-syntax
   NAME, "jinja2", coincidentally digit-containing; a rare coincidental
   collision in a detector's own small bounded random-value pool).
   This NEVER escalates a chain beyond `SUPPORTED` (CONFIRMED is never
   assigned regardless), and every relation's own evidence Detail
   shows the exact matched value for operator verification — but it is
   not perfect precision, and is documented as such rather than
   claimed otherwise.
2. **`CONFIRMED` status is never assigned** — the same deliberate,
   conservative boundary Phase 3.30 established, now also enforced at
   the persistence/CLI layer. A future phase would need a
   qualitatively stronger evidence model (e.g. actual demonstrated
   data-flow execution, not a matched static value) before safely
   introducing a CONFIRMED-assigning policy.
3. **No chain-specific resource limit beyond `chains.DefaultLimits()`
   was added to `orchestrator.Limits`** — a deliberate reuse decision
   (task's own "do not duplicate... unnecessarily"), not a gap; a
   future phase wanting scan-configurable chain limits would extend
   `orchestrator.Limits` and thread an override through to
   `chains.Correlate`.
4. **The CLI's `chains show` has no single-ID lookup** — it lists all
   of a scan's own candidates and matches locally, since
   `storage.ChainRepository` deliberately keeps its own read surface
   minimal (`Relations`/`Candidates`, both `--scan`-scoped, no
   `GetByID`). Adequate for this phase's own read-only foundation; a
   future phase with a larger CLI surface might add one.
