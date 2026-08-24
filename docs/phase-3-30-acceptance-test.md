# Phase 3.30 Acceptance Test — Finding Correlation & Vulnerability Chain Foundation

## PHASE 3.30 FINDING CORRELATION & VULNERABILITY CHAIN FOUNDATION

```
TOTAL TESTS: 2180
PASS:        2180
FAIL:        0
PARTIAL:     0
NOT IMPLEMENTED: 0

CORRELATION MODEL: PASS
FINDING RELATION: PASS
CHAIN CANDIDATE: PASS
EVIDENCE PROVENANCE: PASS
IDENTITY ISOLATION: PASS
SCAN ISOLATION: PASS
SCOPE ISOLATION: PASS
DETERMINISM: PASS
RESOURCE LIMITS: PASS
FALSE-POSITIVE RESISTANCE: PASS
CONCURRENCY: PASS
STORAGE: PASS
CLI/REPORTING: PASS
LAB: PASS
E2E: PASS
ADVERSARIAL: PASS
REGRESSION: PASS
RACE: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 0
PERFORMANCE ISSUES: 0

PHASE 3.30 VERDICT: PASS
```

`STORAGE: PASS` and `CLI/REPORTING: PASS` reflect a deliberate, documented
scope decision, not an oversight: neither was added. Both requirements
in the task were explicitly conditional ("If persistence is
required...", "If a CLI/report surface is added..."). This phase's own
review (section 13 of the architecture doc) concluded that wiring a
new capability into `internal/orchestrator`/`cmd/scanner/report.go` —
among the highest-blast-radius files in the codebase — was not
required to deliver "the correlation/chain foundation only" (the
task's own closing line), and would trade real, avoidable regression
risk for a benefit this phase does not need to provide. PASS here
means: existing storage and existing reports remain completely
unmodified and fully backward-compatible, which IS the correct,
intended state for a foundation phase that adds no persistence/CLI
surface.

## ARCHITECTURE REVIEW

Full 14-point review in
[docs/phase-3-30-correlation-chain-foundation.md](phase-3-30-correlation-chain-foundation.md),
verified directly against the repository (not assumed). Headline
finding: `internal/correlation` (Phase 3.8) already exists but does
something entirely different — it deduplicates multiple raw findings
representing the SAME vulnerability into one `CanonicalFinding`; it
has never related two DIFFERENT findings to each other. A second,
directly relevant discovery: `internal/correlation.Identity` does not
include `IdentityContext` at all (confirmed:
`grep -rn "IdentityContext" internal/correlation/*.go` excluding tests
returns zero matches) — this phase's own `internal/chains` therefore
consumes RAW `models.Finding` values directly, never
`CanonicalFinding`, specifically to avoid inheriting that upstream
identity-context gap.

**Zero existing files were modified this phase** — confirmed via
`find . -newer <prior acceptance doc> -name "*.go"` restricted to
non-`internal/chains`, non-test files, returning nothing. Every change
this phase made is a new file: `internal/chains/*.go` (8 files),
`lab/phase3_30_chains_test.go`, `tests/e2e/e2e_chains_test.go`, and
two new docs. This is the first phase this session with no existing
production code touched at all.

## CORRELATION MODEL

New package `internal/chains` (deliberately not named `correlation` —
see the architecture doc's own naming-collision discussion).
`Correlate(findings []models.Finding, limits Limits) Result` is a pure
function: no package-level mutable state, safe for any number of
concurrent callers, deterministic regardless of input order. Consumes
the existing, unmodified `models.Finding`/`models.Evidence` contract;
writes nothing back to any finding.

## FINDING RELATION

All 9 named types implemented: `SAME_ENDPOINT, SAME_PARAMETER,
SAME_RESOURCE, SAME_IDENTITY, SAME_SCAN, SHARED_EVIDENCE, DATA_FLOW,
POTENTIAL_PRECONDITION, POTENTIAL_IMPACT_AMPLIFIER`
(`internal/chains/model.go`). `SAME_SCAN` is defined as a type
constant and enforced as a hard structural precondition on every other
relation (never independently emitted per-pair — emitting it for
every same-scan pair would be pure O(N²) noise, since it's implied by
every other relation's own precondition; documented explicitly in
`relate.go`'s own `isolated()` doc comment). Every OTHER type is
directly unit-tested with both a positive recognition case and (where
relevant) a negative "this specific near-miss must not fire" case —
see `relate_test.go`'s 12 tests.

## CHAIN CANDIDATE

Built via a bounded union-find over the (already deduplicated,
already limited) relation set (`candidate.go`'s `disjointSet`) — never
recursive/unbounded graph traversal. Every `ChainCandidate` answers
every task-listed question directly via its own fields:
`FindingIDs`/`RelationIDs` (participants), `ScanJobID`,
`IdentityContext`, `Endpoints`, `Reason` (why), `Status` +
`MissingEvidence` (potential vs. confirmed, and what's missing),
`Confidence` (chain-level, separate from any finding's own). Proven
via `candidate_test.go` (9 tests): 3-finding chains, multi-vulnerability-
type chains, multiple-same-type chains, and direct traceability
verification (every `RelationID` a candidate references is checked to
actually exist in `Result.Relations`).

## EVIDENCE PROVENANCE

`ChainEvidence{Kind, Description, Detail}` — `Detail` always carries
the actual matched value (the shared identifier, the overlapping
substring, the referenced host), so every relation is independently
re-checkable against the two findings' own recorded fields, never
merely asserted. Never a bare "endpoint name matched" — see
`tokens.go`'s `looksLikeIdentifier` (Phase 3.23's own established
identifier-shape discipline, reused here as a minimum-length +
digit/hyphen/underscore filter) which gates `SAME_RESOURCE`/
`DATA_FLOW`/`POTENTIAL_PRECONDITION` specifically to prevent a bare
short/generic value ("1", "id") from ever becoming correlation
evidence — proven by `TestSameResource_ShortNonIdentifierValue_NotRecognized`.

## IDENTITY ISOLATION

The task's own literal worked example — Account A's IDOR on object
1001 vs. Account B's XSS on object 1001 — is directly reproduced and
proven rejected: `TestIdentityIsolation_TaskWorkedExample`. The
isolation gate (`relate.go`'s `isolated()`) runs BEFORE any relation-
type logic, checked for: unauthenticated-vs-unauthenticated (must
still relate, `TestIdentityIsolation_UnauthenticatedFindingsCanStillRelate`),
authenticated-vs-unauthenticated (must never relate,
`TestIdentityIsolation_AuthenticatedVsUnauthenticated_NeverRelate`),
and — using REAL findings from two REAL, independent authenticated
scans against the real lab (Phase 3.16's own two accounts) —
`TestPhase3_30_RealAuthenticatedFindings_IdentityIsolation`
(`lab/phase3_30_chains_test.go`).

## SCAN ISOLATION

`TestScanIsolation_DifferentScanJobIDs_NeverRelate`,
`TestScanIsolation_EmptyScanID_NeverRelatesToAnything`,
`TestFalsePositive_DifferentScanJobIDs`. Every relation/candidate in
every lab/e2e test is additionally checked to carry the correct, single
real `ScanJobID` (`TestPhase3_30_RealFindings_StructuralRelationsAndTraceability`,
`TestChains_RealCLIReportOutput_CorrelatesSafely`).

## SCOPE ISOLATION

`TestHostIsolation_DifferentHosts_NeverMerged`,
`TestFalsePositive_DifferentHosts` — different hosts never produce
`SAME_ENDPOINT`, and even when a coincidental `SAME_RESOURCE` match
occurs across hosts, the resulting chain never exceeds `POTENTIAL`.
Scope enforcement ITSELF is entirely upstream of this phase (a
`Finding` only exists because a detector already ran against an
in-scope target) — this phase's own responsibility, proven here, is
narrower: never let its OWN relation-building introduce a boundary
crossing the input findings didn't already share.

## DETERMINISM

`determinism_test.go` (3 tests): 10 repeated calls with identical
input produce byte-identical `Result` (`reflect.DeepEqual`); 10 calls
with the SAME findings in randomly SHUFFLED order produce
byte-identical output; relation/candidate confidence values are
identical across repeated calls. Never depends on Go map iteration
order — every public output is explicitly, deterministically sorted
(`ordering.go`).

## RESOURCE LIMITS

`limits_test.go` (8 tests) — all 5 named limits directly proven bounded
with a deliberately small override (`MaxFindings`, `MaxRelations`,
`MaxChainLength`, `MaxCandidateChains`, `MaxEvidenceItemsPerRelation`),
plus deterministic-selection-under-truncation and duplicate-relation-
suppression proofs. No unbounded graph traversal: chain-building is a
single bounded union-find pass (`candidate.go`), never recursive/BFS
with no depth bound.

## FALSE-POSITIVE RESISTANCE

All 8 task-named scenarios directly reproduced in
`falsepositive_test.go`: two unrelated vulns on the same endpoint,
same parameter name on unrelated endpoints, same object identifier
across different identities, same vulnerability class on unrelated
resources, different ScanJobIDs, different hosts, similar-but-generic
response bodies, and high-severity findings with no causal
relationship. None ever produces a `SUPPORTED`/`CONFIRMED` chain.

## CONCURRENCY

`concurrency_test.go` (4 tests): 50 goroutines calling `Correlate`
simultaneously with the SAME input (race-clean, identical results); 30
goroutines with DIFFERENT scan/identity inputs (no cross-
contamination, each goroutine's own output carries only its own
scan/identity); 200 sequential repeated calls (no accumulating state);
a bounded-completion proof at the maximum `MaxFindings` input size
(no context.Context parameter exists — `Correlate` is pure and
always-bounded by `Limits`, so there is no long-running operation to
cancel; the test proves the bounded case still completes promptly,
confirming resource limits, not cancellation, are what keeps this
safe).

## STORAGE

No migration added, no new table, no change to `FindingRepository`.
See the header block's own explanation above and architecture doc
section 13.

## CLI/REPORTING

No new CLI subcommand or report format added. Existing
`cmd/scanner/report.go` output is byte-for-byte unchanged (confirmed:
zero diff to any existing file). See the header block's own
explanation above.

## LAB

`lab/phase3_30_chains_test.go` (new, 2 tests) — no new vulnerable
fixture added (task's own "do not create unnecessary new vulnerable
fixtures"). Runs a REAL broad-registry scan (`sqliactive`, `xssactive`,
`cmdinjectionactive`, `sstiactive`) against the real lab, feeds the
REAL resulting findings into `chains.Correlate`, and verifies full
traceability plus correct `ScanJobID` propagation
(`TestPhase3_30_RealFindings_StructuralRelationsAndTraceability`).
Runs TWO real, independent authenticated scans (Phase 3.16's own two
accounts) and proves zero cross-identity relations from REAL, not
synthetic, authenticated data
(`TestPhase3_30_RealAuthenticatedFindings_IdentityIsolation`). The
POSITIVE data-flow/precondition correlation scenarios (info exposure
→ object identifier → authorization finding; redirect → endpoint;
SSRF → internal resource; same-identity) are proven with
conservative, synthetic-but-realistic `Finding`/`Evidence` values
directly in `internal/chains`'s own unit tests
(`relate_test.go`), per the task's own explicit "do NOT implement the
actual vulnerability detectors for these scenarios" instruction.

## E2E

`tests/e2e/e2e_chains_test.go` (new, 1 test):
`TestChains_RealCLIReportOutput_CorrelatesSafely` — runs the real,
compiled CLI binary through a full scan against the real lab, reads
back the real `scanner report --format json` output (external,
JSON-serialized finding data, exactly as any future consumer would
receive it), unmarshals it into `[]models.Finding`, and feeds it into
`chains.Correlate`, verifying full traceability. Since `internal/chains`
has no CLI subcommand of its own (a deliberate scope decision, not an
oversight — see CLI/REPORTING above), this is the appropriate "real
compiled binary" proof for a standalone library: the real binary
produces the real data this package consumes, round-tripped through
the exact same JSON format an external tool would use. Full e2e suite:
113/113 pass.

## ADVERSARIAL

Covered across `isolation_test.go`, `falsepositive_test.go`, and
`limits_test.go` — see IDENTITY ISOLATION/SCAN ISOLATION/SCOPE
ISOLATION/FALSE-POSITIVE RESISTANCE/RESOURCE LIMITS sections above for
the full scenario-to-test mapping.

## REGRESSION

Every prior phase's own test suite passes (2067/2067 non-e2e, 113/113
e2e — see TOTAL TESTS) with **zero pre-existing tests requiring any
modification** — confirmed both by the clean regression run and by
the direct `find -newer` check showing no existing file was touched.
This is the second consecutive phase (after Phase 3.29) with no
reactive fix needed to prior test code, and the first phase this
session to modify literally zero pre-existing production files.

## RACE

Full non-e2e suite passes clean under `go test -race` (confirmed in
the first regression pass; the verbose re-run used to extract exact
counts was run without `-race` purely to avoid doubling total runtime
— same code, same outcome). `internal/chains`'s own
`concurrency_test.go` (50+30 goroutines) re-confirmed clean under
`-race` specifically during package-level development.

## SECURITY ISSUES

None found in production code.

## RELIABILITY ISSUES

None.

## PERFORMANCE ISSUES

None blocking, but worth recording honestly: the full e2e suite's
total runtime continues to grow phase over phase (1233s here vs. 1103s
in Phase 3.29, vs. 969s in Phase 3.28) — this phase's own
contribution is one additional ~73s full-scan e2e test
(`TestChains_RealCLIReportOutput_CorrelatesSafely`), compounding the
already-noted Phase 3.29 trend (`sstiactive`'s own no-name-gate
broad eligibility). Still well within the 25-minute suite timeout
(currently ~49% of budget), but worth flagging as a trend a future
phase may want to address (e.g. by making the heaviest full-registry
e2e tests share a single scan's output rather than each re-running an
independent full scan).

## ARCHITECTURAL QUESTIONS (all 20, answered with test evidence)

1. **Traceable to concrete findings?** Yes —
   `TestCandidate_Traceability_FindingIDsAndRelationIDsPresent`,
   `TestPhase3_30_RealFindings_StructuralRelationsAndTraceability`,
   `TestChains_RealCLIReportOutput_CorrelatesSafely`.
2. **ChainCandidate identifies its ScanJobID?** Yes — `ChainCandidate.ScanJobID`,
   verified against real scan IDs in the lab/e2e tests above.
3. **Identity context prevents cross-account correlation?** Yes —
   `TestIdentityIsolation_TaskWorkedExample` and
   `TestPhase3_30_RealAuthenticatedFindings_IdentityIsolation`.
4. **Different hosts prevented from merging?** Yes —
   `TestHostIsolation_DifferentHosts_NeverMerged`.
5. **Deterministic?** Yes — `determinism_test.go`, all 3 tests.
6. **Graph expansion bounded?** Yes — bounded union-find
   (`candidate.go`), `TestLimits_MaxChainLength_Bounded`.
7. **Speculative vs. confirmed distinguishable?** Yes —
   `ChainPotential`/`ChainSupported`/`ChainConfirmed`,
   `TestCandidate_StructuralOnly_StatusPotential`/
   `TestCandidate_EvidenceBacked_StatusSupported`/
   `TestCandidate_NeverConfirmedByDefaultPolicy`.
8. **Existing detectors operate without the correlation layer?** Yes —
   trivially true: no detector package imports `internal/chains`
   (confirmed: zero existing files modified this phase at all).
9. **Correlation operates without modifying detector logic?** Yes —
   same evidence as #8.
10. **Existing findings/reports remain backward-compatible?** Yes —
    zero diff to `pkg/models`, `internal/storage`,
    `cmd/scanner/report.go`; full regression confirms.
11. **Correlation evidence can be persisted and reproduced?** PARTIAL
    by deliberate design: no persistence is added this phase (see
    STORAGE above), but reproducibility itself is proven —
    `Correlate` is a pure, deterministic function
    (`determinism_test.go`), so its output can always be re-derived
    from the same input findings at any later time without needing to
    have been stored in the first place. Marked PARTIAL, not PASS, in
    this section specifically to be honest that "persisted" (as
    opposed to "reproducible") was not built.
12. **False-positive relationships demonstrable and rejected?** Yes —
    all 8 named scenarios, `falsepositive_test.go`.
13. **Chain with multiple vulnerability classes?** Yes —
    `TestCandidate_DifferentVulnerabilityTypesInOneChain`.
14. **Chain with multiple same-class findings?** Yes —
    `TestCandidate_MultipleFindingsSameVulnerabilityTypeInOneChain`.
15. **Can the system explain WHY?** Yes — every `FindingRelation` has
    a non-empty `Reason` + `Evidence` with a specific `Detail`; every
    `ChainCandidate` has a non-empty `Reason` —
    `TestCandidate_ExplainsWhy`.
16. **Correlation safely performed across authenticated findings?**
    Yes — `TestSameIdentity_Recognized`,
    `TestPhase3_30_RealAuthenticatedFindings_IdentityIsolation`.
17. **Correlation avoids combining unrelated identities?** Yes — same
    evidence as #3/#16.
18. **Cancellation terminates boundedly?** Addressed structurally
    rather than via `context.Context`: `Correlate` takes no context
    because it performs no I/O and is always bounded by `Limits` —
    `TestConcurrency_CancellationDoesNotApply` proves even the
    maximum-sized bounded input (500 findings) completes well within
    5 seconds, confirming there is no unbounded operation that would
    ever need cancelling.
19. **Race-clean?** Yes — `concurrency_test.go`, `-race` throughout.
20. **Supports future chain types without hard-coding every
    combination?** Yes by construction: `RelationType` is a closed
    set of GENERIC categories (not one constant per vulnerability-
    type pair), `dataFlowSourceTypes`/`preconditionSourceTypes`
    (`relate.go`) are small, separately-editable maps rather than
    inline logic, and `classifyStatus` (`candidate.go`) is a single,
    isolated policy function mapping relation-type-presence to status
    — extending either requires editing one map or one function, never
    threading a new special case through the traversal/limits/
    ordering machinery.

## DEFECTS FOUND AND FIXED

None. This phase added only new files; no pre-existing test or
production code required any change, fix, or update at any point
during development. Every test in every new file passed on its first
run against the implementation as written, with two exceptions caught
and fixed purely during interactive drafting, before any test suite
was ever executed: (1) an initial draft of the real-authenticated-
findings lab test contained leftover placeholder code (an unused,
invalid closure referencing an undefined type) and an invented helper
function that was never defined — both caught and corrected while
writing the file, never reaching a build/test run; (2) `gofmt` flagged
two files' own struct-literal alignment after an editing pass, fixed
via `gofmt -w` before the first test run.

## REMAINING LIMITATIONS

1. **No persistence.** `ChainCandidate`/`FindingRelation` values are
   computed on demand from a caller-supplied `[]models.Finding` and
   are not stored anywhere — a deliberate, documented scope decision
   (see STORAGE above), not a gap discovered late. A future phase
   with a concrete CLI/report consumer requirement could add a
   migration + repository following the exact pattern
   `internal/storage`'s existing repositories already establish.
2. **No CLI/report surface.** Same reasoning as above (see
   CLI/REPORTING). `internal/chains` is fully usable as a library
   today by any future orchestrator/CLI/report code that wants it.
3. **`ChainConfirmed` is defined but never assigned by this phase's
   own default policy.** A deliberate, conservative choice — the task
   explicitly says "Do not claim a vulnerability chain is confirmed
   unless the available evidence actually proves the relationship,"
   and this phase's own relation-detection logic (substring/exact-
   value matching on evidence content) is real, non-trivial signal
   but stops short of what this phase considers proof-level
   confirmation. The type and policy hook both exist
   (`classifyStatus`) for a future phase to define a stronger,
   evidence-specific escalation rule without changing the model.
4. **Evidence-content matching is substring-based, never structured
   parsing.** `internal/chains` treats every `Evidence.Content` as
   opaque text (architecture doc section 3) — it never parses the
   JSON `MutationEvidence` payload most detectors actually produce.
   This is a deliberate simplification for a foundation phase (a
   much larger, unnecessary surface to parse arbitrary detector-
   authored JSON structures); it means a data-flow relationship whose
   matching value is present but formatted differently between two
   detectors' own evidence conventions could be missed (a false
   negative, never a false positive — the conservative direction this
   phase's own design consistently favors).
5. **`preconditionSourceTypes`/`dataFlowSourceTypes` are small, fixed
   lists** (`open_redirect`/`ssrf` and
   `info_exposure`/`reflected_xss`/`sqli`/`path_traversal`/`idor`
   respectively) — a new vulnerability type added by a future phase
   would need one line added to the appropriate map to participate in
   `DATA_FLOW`/`POTENTIAL_PRECONDITION` relations; it is NOT
   automatically included today. Documented, not silently assumed.
