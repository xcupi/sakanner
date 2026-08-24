# Phase 3.8: Finding Correlation & Deduplication Engine

`internal/correlation` is a centralized layer that receives
`pkg/models.Finding` values from every detector this project has
(reflected XSS, SQL injection, SSRF, IDOR/BOLA, path traversal,
command injection) and produces a normalized, deterministic,
non-duplicated `CanonicalFinding` set. It is entirely additive: no
existing detector, the Phase 3.1 detection engine, `pkg/models`, or
the storage layer was modified to build it. See "Detector
independence" below for why, and
[docs/phase-3-1-detection-engine.md](phase-3-1-detection-engine.md)
for the framework this sits alongside without changing.

## Architecture

```
internal/correlation/
├── model.go          CanonicalFinding, Asset, HTTPContext, Resource, Status, EvidenceItem
├── identity.go         Identity, computeIdentity, every normalization function
├── consolidate.go        severity/confidence ordering, evidenceSignature
├── engine.go               Engine, bucket, group -- Ingest/Findings, the merge logic
├── ordering.go               sortCanonicalFindings
├── group.go                    GroupByEndpoint
└── relationship.go               Relationships
```

```
Detector (unchanged)
    ↓  produces
models.Finding (unchanged, existing Phase 3.1 contract)
    ↓  Engine.Ingest(...)
computeIdentity  →  bucket keyed by Identity.FindingID()
    ↓  Engine.Findings()
consolidation (evidence merge, confidence/severity, status)
    ↓
CanonicalFinding, deterministically sorted
```

## Detector independence

The correlation engine contains **zero vulnerability-specific logic**.
It never branches on `if vulnerability_type == "xss"` or similar --
every rule in `identity.go`/`consolidate.go`/`engine.go` operates on
generic finding attributes (host, port, path, method, parameter,
vulnerability type as an opaque string, evidence content). The one
place a specific type name appears at all is `resourceIdentifier`'s
check for `"idor"` -- documented explicitly as the single, deliberate,
task-mandated exception (task section 19 requires IDOR resource
identity specifically), not a pattern the package repeats anywhere
else.

This package reads `models.Finding` fields that already exist; it adds
no field to `pkg/models`, no migration to `internal/storage`, and no
call from `internal/detection.Engine` into this package. Two
consequences follow directly:

- Every detector's own test suite (Phases 3.2-3.7) is completely
  unaffected -- confirmed by the full regression in this report.
- Wiring `internal/correlation` into the CLI's actual scan pipeline
  (having `cmd/scanner` call `Engine.Ingest`/`Findings` after a real
  scan) is deliberately left for a future phase, exactly like Phase
  3.4's SSRF callback infrastructure and Phase 3.5/3.6's operator
  configuration were left "built, tested, and ready" without being
  wired into `productionRegistry()`'s default path. Section 34's "run
  the actual lab scanners and feed their findings through the new
  correlation engine" is satisfied by
  `lab/phase3_8_correlation_test.go`, which does exactly that
  against real detector output -- proving the composition works --
  without modifying the production pipeline itself.

## Canonical finding model

```go
type CanonicalFinding struct {
    FindingID         string
    ScanID            string
    DetectorID        string
    VulnerabilityType string
    Title             string
    Asset             Asset        // Scheme, Host, Port, Path
    HTTP              HTTPContext  // Method, Parameter, Location
    Resource          Resource     // Identifier (idor only)
    Severity          models.Severity
    Confidence        float64
    Status            Status
    Evidence          []EvidenceItem
    FirstSeen, LastSeen time.Time
    Metadata          map[string]string
}
```

This is task section 1's canonical model, built by the Engine from one
or more contributing `models.Finding` values sharing an `Identity`.
Detectors never produce a `CanonicalFinding` directly.

## Identity algorithm

`Identity` (task section 2) is computed purely from fields
`models.Finding` already carries -- no schema change was needed:

```go
type Identity struct {
    ScanID, Scheme, Host string
    Port int
    Path, Method, Parameter, ParameterLocation string
    VulnerabilityType, ResourceIdentifier string
}
```

| Component | Source | Why |
|---|---|---|
| ScanID | `f.ScanID`, trimmed | Scan isolation (section 16) -- always the first key component |
| Scheme | Parsed from `f.URL` | http vs https are conservatively never merged |
| Host | `f.Host`, normalized | See "Normalization" |
| Port | `f.Port`, normalized | See "Normalization" |
| Path | `f.AffectedEndpoint` (or parsed from `f.URL`), normalized | `/api/user` vs `/api/admin` must never merge |
| Method | `f.Method`, uppercased | GET vs get is the same method |
| Parameter | `f.AffectedParameter`, trimmed | `q` vs `search` are different candidates |
| ParameterLocation | **Derived** from `f.URL` -- see below | `query:id` vs `body:id` must not collapse |
| VulnerabilityType | `f.VulnerabilityType`, lowercased | XSS + SQLi never merge |
| ResourceIdentifier | **Derived**, `idor` only -- see below | User A→Resource B ≠ User A→Resource C |

`Identity.Key()` joins every component with `\x1f` (ASCII Unit
Separator, matching `internal/detection`'s own `dedupKey` convention)
so no combination of component values can collide by concatenation
alone. `Identity.FindingID()` is `hex(sha256(Key())[:16])` -- a 32-hex-
character content hash, never a random UUID (task section 21): the
same identity, observed any number of times, in any process, produces
the identical FindingID.

### Parameter normalization

Every detector in this project today only ever produces GET,
query-string-parameter findings -- a limitation each Phase 3.x
document already carries individually. Rather than hardcode
`Location = "query"` everywhere (which would silently misrepresent a
future body/path/header/cookie-testing detector), `parameterLocation`
**derives** the location from `f.URL`: "query" if
`f.AffectedParameter` is actually present in the URL's query string
(true for every real finding today), "unspecified" otherwise. This
required no new field on `models.Finding` -- `Finding.URL` and
`Finding.AffectedParameter` already carry everything needed.
`TestNoMerge_DifferentParameterLocations` confirms this genuinely
distinguishes identity, not just in theory.

### Resource-aware identity

Task section 19 requires IDOR findings against different resources to
stay distinct ("User A → Resource B" ≠ "User A → Resource C"), while
explicitly requiring the OPPOSITE for path traversal ("do not make
every traversal payload a separate finding") and SSRF ("do not create
one finding per callback token"). `resourceIdentifier` resolves this
directly: it returns the query value of `f.AffectedParameter` **only
when `f.VulnerabilityType == "idor"`**, and `""` for every other type.
`TestComputeIdentity_ResourceAwareForIDOR` proves the IDOR case;
`TestComputeIdentity_ProbeVariantsCollapseForTraversal`,
`TestComputeIdentity_CallbackTokensCollapseForSSRF`, and
`TestComputeIdentity_CorrelationTokensCollapseForCommandInjection`
prove the opposite holds for the other three probe-token-bearing
detectors.

## Normalization

- **Host** -- lowercased, trailing DNS root-zone dot stripped
  (`example.com.` == `example.com`). Nothing beyond case and one
  trailing dot is touched; `example.com` and `evil-example.com` never
  collide.
- **Port** -- an explicit port matching its scheme's well-known default
  (443 for https, 80 for http) is treated as equivalent to no port at
  all -- task section 3's exact `https://example.com` /
  `https://example.com:443` example. In practice this equivalence is
  ALREADY structurally guaranteed in this system: every `Finding.Port`
  is the concrete, already-resolved TCP port Phase 2's HTTP probing
  actually dialed (never an "omitted, assume default" placeholder), so
  there is no real ":443 vs omitted" ambiguity left in the data by the
  time a Finding exists -- `normalizePort`/`defaultPortForScheme` exist
  as a documented, independently tested guarantee of this, not merely
  an assumption.
- **Path** -- exactly one trailing `/` is stripped from a path longer
  than `/` (`/api/search/` == `/api/search`); `/api/searchable` is
  untouched (it doesn't end in a slash-only difference) and stays
  distinct from `/api/search`; the root path `/` is never stripped to
  empty.
- **Method** -- uppercased.
- **VulnerabilityType** -- lowercased and trimmed, defensively (every
  detector already emits consistent lowercase snake_case).
- **Scheme** -- parsed from the URL, defaulting to `http` if
  unparseable (never panics -- see security_test.go).

## Evidence merging

Two findings sharing an `Identity` are merged (task section 8); their
evidence is unioned and **deduplicated** by exact `(Kind, Content)`
equality -- `TestEvidenceMerge_RepeatedEvidenceAppearsOnce` proves a
byte-for-byte repeated evidence item appears exactly once in the
canonical output, and `TestEvidenceMerge_DoesNotCreateOneFindingPerProbe`
proves 10 different probes against the same endpoint/parameter still
collapse to 1 finding with merged (not multiplied) evidence.

### Evidence limits (task section 9)

Three independent, deterministic bounds, none of them random:

- `maxEvidenceContentBytes` (4096) -- truncates any single evidence
  item's content, applied at ingest time.
- `maxEvidenceGroupsPerFinding` (50) -- bounds how many DISTINCT
  evidence *signatures* (see below) one identity retains in memory,
  regardless of how many raw findings arrive.
- `maxEvidenceItemsPerFinding` (20) -- bounds the final `Evidence[]`
  list length on the OUTPUT `CanonicalFinding`.

When either cap is exceeded, the **strongest** evidence is kept, never
a random selection: longer content (more detail) wins first, then
`Kind`, then lexical `Content` order as a final deterministic tiebreak
-- `TestEvidenceLimit_StrongestRetainedDeterministically` confirms
repeated `Findings()` calls against the same bounded-and-evicted state
produce byte-identical results.

## Confidence and severity consolidation

Task sections 10-11 require: independent evidence establishing a
higher tier may raise the canonical value, but **repeating the same
evidence must never raise it**. This is implemented as a two-level,
fully order-independent aggregation, keyed by **evidence signature**
(`evidenceSignature`: a SHA-256 hash over the sorted, deduplicated set
of every evidence item's `Kind|Content`, blind to per-record
bookkeeping like `Evidence.ID`/`CreatedAt`):

```
canonical_value = MAX over evidence groups g of ( MIN over findings sharing g's signature of value(f) )
```

- **Within** one evidence-signature group (an exact resubmission of the
  identical evidence, however many times), the **MIN** confidence/
  severity wins -- a repeat cannot claim a higher tier than the
  original observation established.
- **Across** distinct evidence-signature groups (genuinely different
  evidence), the **MAX** wins -- one strong, independent piece of
  evidence is enough to raise the canonical finding.

This two-level design is what makes the result **order-independent**
under concurrent `Ingest` calls: MIN and MAX are both commutative and
associative, so the final value never depends on arrival order (a
naive "fold sequentially and compare against whatever's already
stored" approach does NOT have this property -- see "A bug found by
this design's own order-independence test" below).

`TestConfidence_RepeatedIdenticalEvidenceOrderIndependent` submits the
identical (high, then low) confidence pair in both orders and confirms
the result is identical either way.

### A garbage-input bug found and fixed during this phase

`rankOfSeverity` returns `-1` for any severity string outside the 5
recognized values (task section 30's "conflicting severity" /
malformed-input scenario). The first draft of `minSeverity` compared
ranks directly (`if rankOfSeverity(b) < rankOfSeverity(a) { return b }`)
-- since `-1` is numerically the minimum, an **unrecognized** severity
string would win a MIN-within-group comparison against a legitimate
`critical`, silently downgrading a real finding whenever a malformed
resubmission shared its exact evidence signature.
`TestSecurity_ConflictingSeverityAcrossResubmissions_NoCrash` caught
this immediately:

```
Severity = "info", want critical
```

**Fix**: `minSeverity` now treats an unrecognized value (rank < 0) as
categorically excluded from ever winning, on either side of the
comparison -- a recognized value always beats an unrecognized one,
regardless of which argument position it's in. `maxSeverity` already
had this property naturally (a rank of `-1` can never exceed a real
rank), so only `minSeverity` needed the fix. This is exactly the kind
of "malicious or malformed finding input... must not crash... must
not [silently corrupt output]" scenario task section 30 asks for, and
the project's own established discipline (broad security testing
before declaring a phase complete) caught it before this report was
written, not after.

## Finding status

```go
const (
    StatusNew       Status = "NEW"        // exactly 1 distinct evidence signature
    StatusConfirmed Status = "CONFIRMED"  // 2+ distinct evidence signatures corroborate it
    StatusDuplicate Status = "DUPLICATE"  // per-INPUT classification only, never on output
    StatusResolved  Status = "RESOLVED"   // defined, never assigned -- see Limitations
)
```

`StatusDuplicate` never appears on an output `CanonicalFinding` --
`Engine.Ingest` returns `[]IngestResult{FindingID, Status}` alongside
its side effect, so a caller CAN inspect "was this specific raw
submission new or a repeat" without that classification ever leaking
into the merged canonical record itself (which only ever reports
NEW/CONFIRMED).

## Correlation vs. merging (relationships and groups)

Task sections 13-15 are explicit that correlation is **not**
merging -- distinct vulnerability types on the same endpoint remain
two separate `CanonicalFinding` records, always. Two read-only, derived
views expose the broader relationship without ever creating a third
"finding":

- **`GroupByEndpoint(findings)`** -- buckets findings sharing
  `(host, port, path)` into a `Group{Host, Port, Path, FindingIDs}`.
  `Group` deliberately has no severity/confidence/evidence fields at
  all -- it cannot be reported as a finding because its Go type
  doesn't carry what a finding needs.
- **`Relationships(findings)`** -- computes every pairwise
  `SameAsset`/`SameEndpoint`/`SameParameter` flag between two DISTINCT
  findings within the SAME scan (never across scans -- see "Scan
  isolation"). A `Relationship{SameEndpoint: true}` between an XSS
  finding and a SQLi finding never implies they should merge; they
  remain `FindingA != FindingB` throughout.

Both are pure functions over `[]CanonicalFinding` -- never stored by
the `Engine`, always recomputed on demand from whatever set is passed
in.

## Scan isolation

`ScanID` is the first component of `Identity.Key()`. Two findings from
different scans can share every other component exactly and will
still never produce the same `FindingID`, never merge, and (via
`Relationships`' explicit `a.ScanID != b.ScanID` skip) never even
appear related to each other. This isn't a policy layered on top --
it's structurally the first thing distinguishing any two identities.
`TestScanIsolation_IdenticalFindingTwoScansStaySeparate`,
`TestScanIsolation_EvidenceNeverCrossesScans`, and
`TestScanIsolation_RelationshipsNeverCrossScans` verify all three
consequences directly; `TestConcurrency_ConcurrentScanCompletionNoCrossScanLeak`
verifies it holds under concurrent ingestion from 20 simulated scans
at once.

## Deterministic ordering

`Engine.Findings()` always returns results sorted by: normalized host,
then port, then path, then vulnerability type, then parameter, then
`FindingID` as the final, always-sufficient tiebreak (task section 22).
`TestOrdering_DeterministicRegardlessOfIngestOrder` confirms the same
input set, ingested in two different orders, produces byte-identical
output order; `TestOrdering_StableAcrossRepeatedCalls` confirms calling
`Findings()` twice against unchanged state never reorders anything.

Genuine determinism note: `FirstSeen`/`LastSeen` naturally reflect real
wall-clock timestamps and are explicitly outside this guarantee (no
system in this project claims otherwise) -- "deterministic" here means
the SET of canonical findings, their `FindingID`s, their consolidated
Severity/Confidence/Status, their Evidence lists, and their output
ORDER, never the literal timestamp values.

## Performance characteristics

- **Ingest**: O(1) amortized per finding (a map lookup/insert keyed by
  `FindingID`, plus O(k) work inside the bucket where k =
  `maxEvidenceGroupsPerFinding`, a small fixed constant) -- never
  O(n) or worse against the number of findings already ingested.
- **Findings()**: O(b log b) where b = number of distinct identities
  (buckets), for the final sort; each bucket's own consolidation is
  O(k).
- Measured directly: 5000 distinct findings ingest in ~125ms; 10000
  duplicate submissions of the identical finding in ~180ms, collapsing
  to exactly 1 canonical finding with bounded evidence; 50000 duplicate
  submissions to one identity grow the heap by single-digit kilobytes,
  not megabytes (see `performance_test.go`).
- **Concurrency**: every mutation is serialized by one `sync.Mutex`;
  `Findings()` always recomputes consolidation from current state
  rather than maintaining incrementally-updated output, which is what
  makes the result independent of `Ingest` call order under concurrent
  use (verified under `-race` with up to 200 concurrent goroutines
  submitting to the same identity).

## Security considerations

`internal/correlation` is a pure, in-memory data-transformation
package -- it never imports `os/exec`, `syscall`, `net`, or `net/http`
(checked mechanically via `go/parser` against real AST import
declarations in `TestSecurity_SourceNeverTouchesFilesystemNetworkOrShell`,
not a naive string search), makes no filesystem access, and issues no
network request of any kind. Every function operates on Go value types
already in memory.

Tested directly against malformed/adversarial input (task section 30):
extremely long host/parameter/evidence values (up to 1MB / 50MB),
invalid UTF-8, malformed and empty URLs, null bytes, control
characters, duplicate evidence fields within one finding, conflicting
severity and confidence values across resubmissions (including the bug
described above), malformed/oversized finding IDs, a completely empty
`Finding{}`, a nil evidence slice, and 2000 findings combining several
of these at once -- none of these panic, corrupt other findings'
state, or allow malformed input to escalate a canonical finding's
severity/confidence beyond what legitimate evidence actually supports.

## Limitations

- **`StatusResolved` is defined but never assigned.** This phase has no
  re-scan/remediation-tracking capability -- there is nothing yet to
  compare a new scan's findings against to determine "this was fixed."
  The status value exists so a future phase's re-scan comparison logic
  has somewhere to report into, per task section 12's explicit
  permission ("if the current architecture does not yet support
  lifecycle management, implement only what is required for scan
  results and document the limitation").
- **Not wired into the production CLI pipeline.** `cmd/scanner` does
  not call this package. It is fully built, tested (unit, integration
  against real detector output, security, performance, concurrency),
  and ready to be wired into a future report-generation or `scanner
  findings` enhancement -- deliberately out of THIS phase's scope
  (task section 33 draws the line at "a clean interface between
  detectors and the correlation engine," not at rewiring the CLI).
- **Only query-parameter locations exist in practice.** The
  `ParameterLocation`/`HTTPContext.Location` machinery is fully built
  and tested for "query" vs "unspecified," but no detector in this
  project produces a body/path/header/cookie-located finding yet, so
  those values are never actually observed outside unit tests that
  construct them directly.
- **No cross-scan historical correlation.** Task section 16 explicitly
  forbids this for the current phase; `ScanID` isolation is total and
  by design.
