# Phase 3.31: Vulnerability Chain Integration, Persistence & Reporting Foundation

## 0. Scope discipline

This phase integrates Phase 3.30's `internal/chains` into the real
scanner pipeline: persistence (a new, additive migration), the real
orchestrator (chain generation runs after Phase 3.8's existing dedup
pass), and a minimal, read-only CLI surface. No new vulnerability
detector is added or modified. No individual finding's severity is
ever changed. `internal/chains` itself is not modified to depend
upward on storage/orchestrator/CLI — the dependency runs one direction
only (storage → chains), exactly like storage already depends on the
equally standalone `pkg/models`.

## 1. Architecture review

### `internal/chains`

Unchanged in its own public contract (`Correlate(findings []models.Finding,
limits Limits) Result`, `FindingRelation`, `ChainCandidate`,
`ChainEvidence`) — see `docs/phase-3-30-correlation-chain-foundation.md`
for the full Phase 3.30 design. This phase found and fixed a REAL
defect in its own SHARED_EVIDENCE relation logic during integration
testing against real, varied detector evidence (never surfaced by
Phase 3.30's own hand-crafted unit tests) — see section "A defect
Phase 3.30's own tests never caught" below.

### `models.Finding`

Unchanged (`pkg/models/models.go:477-512`). `ScanID`/`IdentityContext`
are the two fields this phase's own isolation guarantees continue to
rely on, exactly as Phase 3.30 established.

### Existing finding persistence/storage

`internal/storage.Store`'s `FindingRepository`
(`Create/Get/ListByScanJob/Delete`), backed by
`internal/storage/sqlite`'s `findingRepo`, the `findings` table
(migration `0001`). Unchanged. `internal/storage/migrations.go`'s
embedded, versioned, sequentially-applied migration system (`0001`
through `0013` before this phase) is reused exactly as-is — this
phase adds `0014_chains.sql`, following the identical pattern.

### `internal/correlation`

Unchanged (Phase 3.8's dedup engine — see
`docs/phase-3-30-correlation-chain-foundation.md` section 5 for the
full distinction from `internal/chains`). `internal/orchestrator`
still calls it exactly as before; this phase's own new chain-
correlation step runs immediately alongside it (same stage, same raw
findings), never replacing or depending on its `CanonicalFinding`
output.

### Existing reporting/output paths

`cmd/scanner/report.go` (`reporting.Build`/`Report.JSON`/`.Markdown`)
reads raw `models.Finding` values directly from `ListByScanJob` — it
has never consumed `correlation.CanonicalFinding`, `risk.Assessment`,
or `evidence.FindingPackage` output at all (confirmed: no
"canonical_finding"/"risk_assessment" table or field exists anywhere;
those Phase 3.8/3.9/3.10 computations are ephemeral, produced fresh
inside one `Orchestrator.Run` call and never independently persisted
or re-exposed). **This phase's own chain data breaks that precedent
deliberately** — chains ARE persisted (task's own explicit
requirement) precisely so `scanner chains`/`chains show` can read them
back independently of any single `Run` call, unlike every other
Phase 3.8-3.10 computation. `report.go`/`Report`/`Findings` output is
completely unmodified by this phase.

### Scanner orchestration

`internal/orchestrator.Orchestrator.Run` — read in full. Pipeline:
`SCOPE → RECON → DISCOVERY → DETECTION → VERIFICATION → CORRELATION
(Phase 3.8 dedup) → RISK → EVIDENCE → FINALIZATION`
(`internal/orchestrator/model.go:30-49`'s `stageOrder`, "the ONLY
place this order is defined"). The `CORRELATION` stage
(`orchestrator.go:498-522` before this phase) already fetches
`rawFindings := o.Store.Findings().ListByScanJob(ctx, scanID)` before
feeding them to `correlation.NewEngine()` — **the exact same raw
finding set `internal/chains.Correlate` needs**, already in hand at
exactly the right point in the pipeline.

**Smallest architecturally correct integration point identified**:
rather than adding a brand-new `Stage` constant (which would touch the
`Stage` enum, `stageOrder`, and `state.go`'s own hard-coded progress-
percentage table — a broader, higher-risk change to a component
explicitly documented as "the ONLY place this order is defined"),
chain correlation runs as an ADDITIVE STEP inside the EXISTING
`StageCorrelation` block, immediately after `canonical :=
ce.Findings()` and before `state.CompleteStage(StageCorrelation)`.
This is semantically accurate (chain-building genuinely IS a form of
correlation) and minimizes blast radius: zero changes to the Stage
enum, stage ordering, or progress tracking; the diff to
`orchestrator.go` is one import and ~15 lines inside an existing,
already-bounded block.

**Error isolation**: a chain-persistence failure is recorded as
`ErrorCategoryWarning` (`state.AddError`), never `state.FailStage` —
mirroring the EXISTING Evidence stage's own per-item error-isolation
principle (`orchestrator.go:574-579`, one finding's evidence-build
failure never loses every other finding's result). Proven directly:
`TestPhase3_31_ChainPersistenceFailure_NeverFailsTheScan`
(`lab/phase3_31_chains_integration_test.go`), using a real store
wrapped via Go interface embedding to fail ONLY `Chains()` while every
other repository forwards to the real, unmodified store underneath.

### CLI scan/report surfaces

`cmd/scanner/findings.go` (`newFindingsCmd`/`newFindingsShowCmd`) is
the direct structural template this phase's own new
`cmd/scanner/chains.go` (`newChainsCmd`/`newChainsShowCmd`) mirrors:
a `--scan`-scoped list command plus a `show <id>` detail subcommand,
both read-only, both registered in `root.go`'s own `root.AddCommand(...)`
list. No destructive verb exists anywhere in the new command tree.

### `IdentityContext`

Preserved end to end: `models.Finding.IdentityContext` →
`chains.FindingRelation`/`ChainCandidate` (Phase 3.30, unchanged) →
`chain_candidates.identity_context` column (this phase's own new
migration) → `ChainCandidate.IdentityContext` on read-back → CLI
`chains` list's own IDENTITY column and `chains show`'s own Identity:
line. Never lost, never merged across two different non-empty values
at any layer.

### `ScanJobID`

Same end-to-end chain: `Finding.ScanID` → `chains.Correlate`'s own
isolation gate (Phase 3.30, unchanged) → `chain_relations.scan_job_id`/
`chain_candidates.scan_job_id` (both `REFERENCES scan_jobs(id) ON
DELETE CASCADE`, mirroring `findings`'s own existing FK exactly) →
`storage.ChainRepository`'s own `scanJobID`-scoped
`Relations`/`Candidates`/`SaveResult` methods → CLI's own mandatory
`--scan` flag.

### Existing deduplication behavior

Unchanged (`internal/correlation.Engine`, Phase 3.8). Not read from,
not written to, not depended upon by `internal/chains` or this
phase's own new storage/CLI code (see `internal/chains`'s own section
5 discussion in the Phase 3.30 doc for why raw findings, not
`CanonicalFinding`, are what this whole chain-correlation feature
consumes).

### Existing risk/severity representation

`pkg/models.Severity` (`info/low/medium/high/critical`,
`pkg/models/models.go:442-450`) is the ONLY severity representation in
this codebase — `internal/risk`'s own `Assessment{RiskScore,
Priority}` is a SEPARATE, ephemeral, per-`Run`-call computation (never
persisted, section "Existing reporting/output paths" above), not a
second severity scale. This phase introduces NO new scoring system
(task's own explicit prohibition) — `ChainCandidate.Confidence`/
`ImpactEstimate` (Phase 3.30, unchanged) remain informational,
descriptive fields, never a numeric score comparable to
`risk.Assessment.RiskScore`, and are never written onto or derived
INTO any individual `Finding.Severity`. See "RISK/SEVERITY" below for
the explicit decision this drove.

## 2. A defect Phase 3.30's own tests never caught

Discovered by feeding REAL, varied detector evidence (a broad,
multi-detector-type scan against the real lab) into `chains.Correlate`
for the first time — Phase 3.30's own unit tests all used hand-
crafted, single-purpose evidence strings that never exercised this
failure mode. Two related, now-fixed issues in
`SHARED_EVIDENCE`'s own token-matching logic
(`internal/chains/tokens.go`):

1. **Shape alone is not enough.** The original
   `looksLikeIdentifier`-based check (any token containing a digit,
   hyphen, or underscore) let two systemic false-positive classes
   through: (a) a shared PORT NUMBER (present in literally every
   finding's own "request" evidence field, since every finding in one
   scan targets the same host:port) and (b) detector-internal fixed
   schema vocabulary/marker constants (`response_fragment`,
   `COMMAND_INJECTION_MARKER`, a percent-encoded XSS payload marker) —
   none of these indicate a genuine relationship between two
   DIFFERENT findings, only that they were produced by the same
   detector or against the same target.
2. **Frequency alone is not enough either.** A whole-batch token-
   frequency filter (reject a token shared by more than a small,
   fixed number of findings) closed most of the gap, but a raw
   substring-of-the-whole-evidence-blob match (rather than exact
   whole-token equality) let a SHORT, individually-rare token slip
   through as a false match against a much LONGER, also-individually-
   rare token it happened to be a prefix of.

**Fixed** with three additive, well-justified refinements to
`looksLikeSharedEvidenceToken`/`substringOverlap`/`tokenFrequency`:
requiring a token to contain BOTH a digit and a non-digit character;
excluding tokens matching JSON's own `\uXXXX` HTML-escape artifact
shape and predominantly-percent-encoded tokens; and requiring an EXACT
whole-token match between the two findings' own tokenized evidence
(never a raw substring-of-full-text check). Proven via 2 new
regression tests reproducing the exact real-world patterns discovered
(`TestFalsePositive_SharedPortNumber_NeverProducesSharedEvidence`,
`TestFalsePositive_DetectorBoilerplateFieldNames_NeverProducesSharedEvidence`,
`internal/chains/falsepositive_test.go`) plus re-verification against
the same real, broad scan that originally surfaced the issue (relation
count dropped from over 100 spurious SHARED_EVIDENCE matches
dominating nearly every finding pair, to a small number of residual,
individually-verified matches — see REMAINING LIMITATIONS in the
acceptance report for the honest residual risk that remains). This is
a genuine, if imperfect, precision improvement to an inherently
heuristic signal — SHARED_EVIDENCE never escalates a chain beyond
`SUPPORTED` regardless (CONFIRMED is never assigned by this phase's
own policy either), so the worst-case consequence of any remaining
imprecision is a chain sitting at `SUPPORTED` when `POTENTIAL` would
have been more accurate, never a claim of confirmed exploitation.

## 3. Persistence schema

`internal/storage/migrations/0014_chains.sql` (additive, no existing
table altered): `chain_relations` and `chain_candidates`, both with a
`scan_job_id REFERENCES scan_jobs(id) ON DELETE CASCADE` foreign key
mirroring `findings`'s own established pattern exactly. Scalar fields
are real columns; array/nested-struct fields (`Evidence`, `FindingIDs`,
`RelationIDs`, `Endpoints`, `MissingEvidence`) are JSON TEXT columns —
the SAME established convention `findings.evidence`/`findings."references"`
already use. `storage.ChainRepository.SaveResult` DELETEs then
INSERTs (never appends) for a given `scan_job_id`, making it naturally
idempotent and safe to call more than once for the same scan — proven
by `TestChains_SaveResult_IdempotentReplay`/`_ReplacesNotAppends`
(`internal/storage/sqlite/chains_test.go`). Read methods
(`Relations`/`Candidates`) order by the content-derived `id` column
ascending — deterministic on every call, proven by
`TestChains_DeterministicReadOrder`.

## 4. Chain status

`ChainCandidate.Status` remains exactly Phase 3.30's own 3-value type
(`POTENTIAL`/`SUPPORTED`/`CONFIRMED`) — task section 4 additionally
asks for "CANDIDATE"/"CONFIRMED" to be explicitly represented; this
phase treats `POTENTIAL`/`SUPPORTED` together as the "candidate"
family (a chain has NOT been confirmed) and preserves `CONFIRMED` as
the one, single "proven" state — never introducing a fourth,
redundant status value. `CONFIRMED` continues to be defined in the
type system (reachable by future policy evolution) but is NEVER
assigned by this phase's own `Correlate`/persistence/CLI code, for the
identical, deliberate reason Phase 3.30 established: the available
evidence model (substring/exact-value matching on evidence content)
is real, non-trivial signal, but this phase's own architecture review
concludes it does not yet constitute PROOF of exploitation/impact —
see "RISK/SEVERITY" and the acceptance report's own REMAINING
LIMITATIONS for exactly what additional evidence would be needed
(e.g. an actual demonstrated data-flow execution, not just a matched
static value) before a future phase could safely introduce a
CONFIRMED-assigning policy.

## 5. Chain evidence / secret protection

`ChainEvidence.Detail` continues to carry only the exact matched
token/value already present in a finding's OWN evidence content — this
phase's persistence layer stores it verbatim (no re-derivation,
re-formatting, or expansion) and the CLI displays it verbatim. Since
`internal/chains` never reads a credential/session-cookie/authorization
header (it only ever sees whatever a detector's own, already-
redaction-governed `Evidence.Content` contains — the SAME established
evidence-redaction discipline every detector in this codebase already
follows), and never concatenates/amplifies a match beyond one
delimited token, no NEW secret exposure surface is introduced by
persistence or the CLI. Proven directly:
`TestAdversarial16_SecretShapedEvidence_NeverAmplified`
(`internal/chains/adversarial_scenarios_test.go`).

## 6. Risk / severity

No new scoring system introduced (task's own explicit prohibition).
`ChainCandidate.Confidence`/`ImpactEstimate` remain Phase 3.30's own
informational, descriptive fields — never a numeric score comparable
to `risk.Assessment.RiskScore`, and this phase's CLI output
(`chains`/`chains show`) always displays them under headers text
literally naming them "Confidence"/"Impact", never "Severity" or
"Risk Score", so an operator can never mistake a chain-level value for
an individual finding's own severity. Every individual finding's own
`Severity` is displayed VERBATIM and UNCHANGED in `chains show`'s own
"Participating findings" section (`f.Severity`, read directly from
`store.Findings().Get`, never derived or overridden) — proven by
`TestPhase3_31_RealScan_ProducesAndPersistsGenuineChain`'s own field
checks and the e2e test's own `severity=` substring assertion.
