# Phase 3.30: Finding Correlation & Vulnerability Chain Foundation

## 0. Scope discipline

This phase adds ONE new, additive, standalone library:
`internal/chains`. It consumes `[]models.Finding` (the same, unmodified
Phase 3.1 detector contract every "-active" detector already produces)
and produces `FindingRelation`/`ChainCandidate` values. It does not
implement a new vulnerability detector, does not implement exploit
chaining, does not escalate any individual finding's severity, and
does not claim a chain is confirmed beyond what the input evidence
actually supports.

## 1. The current Finding model and available fields

`pkg/models.Finding` (`pkg/models/models.go:477-512`):
`ID, ScanID, DetectorID, Target, Asset, VulnerabilityType, Title,
Description, Severity, Confidence, Host, Port, URL, Method,
AffectedEndpoint, AffectedParameter, DetectionMethod, ValidationStatus,
Evidence []Evidence, Remediation, References, Source, IdentityContext,
FirstSeen, LastSeen`. Every field a detector sets is directly readable
by this new package — no schema change needed to consume it.

## 2. Finding identity/context and ScanJobID handling

`Finding.ScanID` and `Finding.IdentityContext` are both already
present and populated by `internal/detection`'s own `normalizeFinding`
(unchanged since Phase 3.16/3.19) — copied verbatim from the
`detection.Target` a finding was detected against, never set directly
by a detector. `IdentityContext` is `""` for an unauthenticated scan.

## 3. Existing Request/Response evidence

`models.Evidence{ID, FindingID, Kind, Content, CreatedAt}`
(`pkg/models/models.go:433-439`). `Content` is a JSON-encoded string
(see `detection.MutationEvidence`) — this package treats it as opaque
text for substring-based data-flow matching, never re-parses its JSON
structure (deliberately conservative: a plain-text `strings.Contains`
check is easy to reason about and audit; parsing arbitrary
detector-authored JSON to extract structured fields would be a much
larger, unnecessary surface for this foundation phase).

## 4. Endpoint/Parameter/Target/IdentityContext/provenance

Already covered by Finding's own fields above (section 1). This
package does NOT query `internal/storage`'s `Endpoint`/`Parameter`
tables directly — it operates purely on the `Finding` values it is
handed, keeping it independent of storage/orchestrator internals
(same independence `internal/correlation`, Phase 3.8, already has).

## 5. Existing correlation/deduplication mechanisms

`internal/correlation` (Phase 3.8, `internal/correlation/*.go`, 2765
lines) already exists — but it does something **entirely different**
from what this phase builds. Read in full. It deduplicates MULTIPLE
raw `models.Finding` values that represent the SAME underlying
vulnerability (e.g. two probes that both found the same SQLi) into one
`CanonicalFinding`, keyed by `Identity{ScanID, Scheme, Host, Port,
Path, Method, Parameter, ParameterLocation, VulnerabilityType,
ResourceIdentifier}` (`internal/correlation/identity.go:19-30`). It
never relates two DIFFERENT vulnerabilities to each other — that
capability does not exist anywhere in this codebase before this
phase.

**A significant, directly relevant fact discovered during this
review**: `internal/correlation.Identity` does **not** include
`IdentityContext` (confirmed: `grep -rn "IdentityContext"
internal/correlation/*.go` excluding tests returns zero matches). This
means the Phase 3.8 engine's own `CanonicalFinding` output has no
identity-context field at all, and two findings from different
identities that happen to share the same
scan/vuln-type/host/path/method/parameter/resource would already be
silently merged upstream, before any later layer could tell them
apart.

**Design decision this fact drives**: `internal/chains` consumes RAW
`models.Finding` values directly — never `correlation.CanonicalFinding`
— specifically to avoid inheriting this upstream identity-context gap.
This phase does not modify `internal/correlation` (out of scope,
and the task's own "additive, does not modify existing detector/
correlation logic" principle applies to it too) but documents the fact
plainly rather than silently working around it.

`internal/correlation` is used in production by
`internal/orchestrator.Orchestrator.Run` (`orchestrator.go:510-513`)
and consumed by `internal/risk`/`internal/evidence`. `internal/chains`
is NOT wired into the orchestrator in this phase — see section 13.

## 6. SQLite persistence and migrations

`internal/storage/migrations.go` — an embedded, versioned,
sequentially-applied migration system (`0001`...`0013` today,
confirmed via `ls internal/storage/migrations/`), safe to re-run
(already-applied migrations skipped), refuses to run against a
database whose recorded version is NEWER than the binary knows about.
`internal/storage.Store`'s `FindingRepository`
(`Create/Get/ListByScanJob/Delete`) is the only Finding-related
persistence surface. **This phase adds no migration and no new table**
— see section 13 for why.

## 7. Existing detector registry and orchestrator lifecycle

Unchanged by this phase. `cmd/scanner/detectors.go`'s
`buildProductionRegistry` builds the 14-detector registry;
`internal/orchestrator.Orchestrator.Run` drives recon → detection →
`correlation.Engine` (dedup) → `risk.Engine` (scoring) →
`evidence.Engine` (packaging) → persisted report. `internal/chains` is
never called from this path in this phase (section 13).

## 8. How multiple findings from the same scan are represented

Every `models.Finding` produced during one scan shares the same
`ScanID` — the SAME field this phase's own scan-isolation rule keys
on. `store.Findings().ListByScanJob(ctx, scanJobID)` is the existing,
unmodified read path this phase's own lab tests reuse directly.

## 9. How findings from different identities are represented

`Finding.IdentityContext` (section 2) — the configured identity name,
or `""`. Two findings from the SAME scan but different authenticated
identities differ only in this one field; every other field (Host,
Path, VulnerabilityType, etc.) can be identical.

## 10. Scope enforcement and accidental boundary-crossing

Scope enforcement itself (`internal/scope`, `internal/safedial`) is
entirely upstream of this phase — a `Finding` only ever exists because
a detector already ran against an in-scope target. This phase's own
responsibility is narrower and different: never let ITS OWN relation-
building cross a scan, identity, or host boundary that the INPUT
findings themselves don't already share. See "IDENTITY ISOLATION" in
the correlation model below — this is the phase's own primary safety
property, tested exhaustively (`security_test.go`-equivalent, this
phase's own `internal/chains/isolation_test.go`).

## 11. Existing deterministic ordering guarantees

`internal/correlation/ordering.go` sorts `CanonicalFinding` output by
`(VulnerabilityType, Asset.Host, Asset.Port, Asset.Path, ScanID,
FindingID)` — never map iteration order. This phase's own
`internal/chains/ordering.go` follows the identical discipline: every
public output slice is explicitly sorted by content-derived keys
before being returned, never left in map/goroutine-completion order.

## 12. Existing resource limits

`internal/correlation/engine.go`'s own bounds
(`maxEvidenceGroupsPerFinding=50`, `maxEvidenceItemsPerFinding=20`,
`maxEvidenceContentBytes=4096`) are the established precedent this
phase's own `internal/chains/limits.go` mirrors in spirit (small,
named constants, deterministic eviction of the WEAKEST item when a
bound is exceeded, never random/arrival-order-dependent truncation).

## 13. Existing report/CLI output paths

`cmd/scanner/report.go` (JSON/markdown/text formats) reads
`store.Findings().ListByScanJob` and risk/evidence output — it has NO
concept of a "relation" or "chain" today. **This phase deliberately
adds no CLI/report surface and no persistence** (sections 6/13
combined decision): the task's own instructions for both are
conditional ("If persistence is required...", "If a CLI/report surface
is added..."), and the task's own closing line is explicit: "The final
deliverable should be the correlation/chain foundation only." Wiring a
new capability into `internal/orchestrator`/`cmd/scanner/report.go` --
among the highest-blast-radius files in the codebase, exercised by
hundreds of pre-existing regression tests -- for a phase whose own
title says "Foundation" would trade a real, avoidable regression risk
for a benefit (a CLI surface) the task does not actually require this
phase to deliver. `internal/chains` is built, tested, and proven
end-to-end as a fully standalone library, ready for a **future** phase
to wire into the orchestrator/CLI once it has a concrete consumer
requirement to design against.

## 14. Existing regression and E2E architecture

Unchanged and reused as-is: `go test $(go list ./... | grep -v
'/tests/e2e') -race -count=1 -timeout 20m` then `go test
./tests/e2e/... -count=1 -timeout 25m`, the lab/production
independence check (`mv lab`, `mv tests`, rebuild), and the
`testVulnLab`/`runReconAgainstVulnLab` lab helpers this phase's own
`lab/phase3_30_chains_test.go` reuses to feed REAL detector-produced
findings into `internal/chains`.

## CORRELATION MODEL

New package: **`internal/chains`** (deliberately NOT named
`correlation` — see section 5's naming-collision discussion; a name
matching an existing, semantically different package would be
actively misleading).

### Types

- **`FindingRelation`** — one pairwise, typed, evidenced relationship
  between exactly two findings.
- **`ChainCandidate`** — a set of 2+ findings, connected by one or more
  relations, with an explicit status/confidence/impact, always
  traceable back to its exact input findings and relations.
- **`ChainEvidence`** — WHY a relation was recorded: a kind, a
  human-readable description, and the specific matched detail (never
  "these are similar," always "these SHARE this specific, named
  fact").

### Relation types (9, exactly as specified)

`SAME_ENDPOINT, SAME_PARAMETER, SAME_RESOURCE, SAME_IDENTITY,
SAME_SCAN, SHARED_EVIDENCE, DATA_FLOW, POTENTIAL_PRECONDITION,
POTENTIAL_IMPACT_AMPLIFIER`.

`SAME_SCAN` and `SAME_IDENTITY` are also the two HARD PRECONDITIONS
every OTHER relation type requires before it is even attempted (see
IDENTITY ISOLATION below) — they are not just "yet another weak
signal," they gate everything else.

`SAME_PARAMETER`/`SAME_ENDPOINT` alone are purely STRUCTURAL facts —
recorded, but never by themselves enough to produce a `SUPPORTED`/
`CONFIRMED` chain (the false-positive list's "same parameter name on
unrelated endpoints" case exists specifically to prove this).

`DATA_FLOW`/`POTENTIAL_PRECONDITION` require an actual EVIDENCE-LEVEL
match: a specific, non-trivial (identifier-shaped, non-generic) token
that appears BOTH in one finding's own evidence/identifying fields and
in another finding's own identifying fields (its resource identifier,
host, or endpoint) — never a bare string-similarity heuristic.

`SHARED_EVIDENCE` fires when two findings' evidence content literally
overlaps on a specific, non-trivial substring (e.g. the same
distinctive marker/token appearing in both) — distinct from
`DATA_FLOW`, which specifically looks for one finding's evidence
containing ANOTHER finding's own identifying value (not just any
shared substring).

`POTENTIAL_IMPACT_AMPLIFIER` requires an EXISTING structural relation
(same endpoint or same resource) between two findings of different
vulnerability types, at least one HIGH/CRITICAL severity — never
merely "two findings are both severe," which the false-positive list's
"high-severity findings that have no causal relationship" case exists
to reject.

### `ChainCandidate` fields (answering every task-listed question)

`ID` (content-derived, deterministic), `ScanJobID`, `IdentityContext`
(the ONE shared identity every participating finding has — see
isolation below), `FindingIDs []string`, `RelationIDs []string`,
`Endpoints []string` (deduplicated, sorted), `Status`
(`POTENTIAL`/`SUPPORTED`/`CONFIRMED`), `Confidence float64` (a
chain-level value, entirely separate from any individual finding's own
`Confidence`), `ImpactEstimate string`, `Reason string`,
`MissingEvidence []string`.

`Status` assignment (deterministic, never a heuristic guess):
- `POTENTIAL`: the chain rests on structural relations only (`SAME_ENDPOINT`/`SAME_PARAMETER`/`SAME_IDENTITY`/`SAME_SCAN`), no evidence-level relation.
- `SUPPORTED`: at least one `DATA_FLOW`/`SHARED_EVIDENCE`/`POTENTIAL_PRECONDITION` relation backs it, but only one, or the evidence is only one-directional.
- `CONFIRMED`: never assigned in this phase's own default policy — deliberately conservative (see "Do not claim a vulnerability chain is confirmed unless the available evidence actually proves the relationship"). `CONFIRMED` is defined in the model and reachable by the type system/tests for a future stronger-evidence policy, but this phase's own `Correlate` never emits it — see REMAINING LIMITATIONS in the acceptance report for why this is an honest, deliberate boundary, not an oversight.

### IDENTITY ISOLATION (the phase's own central safety property)

A relation is **never** built between two findings unless ALL of the
following hold:
1. `a.ScanID == b.ScanID` (never empty on either side).
2. `a.IdentityContext == b.IdentityContext` (including both being
   `""` — an unauthenticated scan's own findings can still relate to
   each other, but never to an authenticated identity's findings, and
   two DIFFERENT non-empty identities never relate to each other,
   full stop).

This check runs BEFORE any relation-type-specific logic — no relation
type, however strong its evidence looks, can bypass it. The task's own
worked example (Account A's IDOR on object 1001, Account B's XSS on
object 1001) is rejected at this gate, before `SAME_RESOURCE`/
`DATA_FLOW` logic ever runs.

## Resource limits

| Limit | Default | Enforcement |
|---|---|---|
| `MaxFindings` | 500 | Input findings beyond this are dropped (deterministic: sorted by `(ScanID, Host, AffectedEndpoint, ID)`, keep first N), `Result.Truncated=true`. |
| `MaxRelations` | 2000 | Pairwise comparison stops once reached, in a fixed deterministic pair order (never map iteration). |
| `MaxChainLength` | 10 | A candidate chain never grows past 10 participating findings. |
| `MaxCandidateChains` | 100 | Chain-building stops once reached, deterministic order. |
| `MaxEvidenceItemsPerRelation` | 5 | Bounded per relation. |
| Duplicate relation suppression | n/a | A `(Type, sorted FindingA/B pair)` is never emitted twice. |

No unbounded graph traversal: chain-building is a single bounded
union-find pass over the already-capped relation set, never a
recursive/BFS traversal with no depth bound.
