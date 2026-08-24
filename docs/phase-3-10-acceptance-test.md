# Phase 3.10 Acceptance Test: Evidence & Reproducibility Engine

Scope: `internal/evidence` (the canonical `CanonicalEvidence`/
`ReproductionInfo`/`FindingPackage` model, secret redaction, response
truncation, binary handling, integrity hashing, deduplication,
deterministic ordering, reproduction generation, summary/explanation
generation), and `lab/phase3_10_evidence_test.go` (the
integration test proving real canonical findings and risk assessments
from all six detectors produce correct evidence end to end). See
[docs/phase-3-10-evidence-reproducibility.md](phase-3-10-evidence-reproducibility.md)
for the full architecture writeup this test verifies against.

This phase touched **no existing code** outside `internal/evidence` and
its own new test files -- no detector, no `internal/correlation`, no
`internal/risk`, no `pkg/models`, and no `cmd/scanner` file was
modified.

## What was built

- `internal/evidence/model.go`: `EvidenceType`, `RequestEvidence`,
  `ResponseEvidence`, `BinarySummary`, `RedirectEvidence`,
  `CanonicalEvidence` -- task section 2's canonical model.
- `internal/evidence/limits.go`: `Limits`, `DefaultLimits`, `truncate`.
- `internal/evidence/redact.go` / `redact_body.go`: header/URL/JSON/
  form/multipart/generic-text secret redaction plus control-character
  sanitization.
- `internal/evidence/binary.go`: binary content detection and safe
  summarization.
- `internal/evidence/parse.go`: the Phase 3.1 evidence-JSON parser and
  the generic detector-field tokenizer.
- `internal/evidence/hash.go`: canonical serialization, integrity hash,
  evidence ID.
- `internal/evidence/summary.go`: deterministic summary/why-vulnerable
  text generation.
- `internal/evidence/reproduction.go` / `reproduction_build.go`:
  `DifferentialEvidence`, `Diff`, `ReproductionInfo`, `FindingPackage`,
  and their construction.
- `internal/evidence/engine.go`: `BuildEvidence`, `BuildPackage` -- the
  public pipeline entry points, plus dedup/ordering/limit enforcement.
- `lab/phase3_10_evidence_test.go`: runs all 6 real detectors
  through the real Phase 3.1 engine, the real Phase 3.8 correlation
  engine, and the real Phase 3.9 risk engine, then builds evidence for
  every resulting canonical finding.
- Tests: 105 unit/matrix/redaction/hash/reproduction/security/
  performance/concurrency tests in `internal/evidence`, 1 integration
  test in `lab`.

## Real canonical findings produce evidence end to end (task sections 42-43)

`TestPhase3_10_Evidence_RealCanonicalFindingsProduceEvidence` runs real
recon and all six real detectors through the real `detection.Engine`
against the real `vuln.scanner.test` lab, correlates the results with
the real Phase 3.8 engine, assesses them with the real Phase 3.9 risk
engine, then builds an evidence package for every canonical finding:

```
Correlation: 8 raw findings -> 8 canonical findings
Built 8 evidence packages across 6 vulnerability types
```

Every one of the 8 canonical findings (covering all 6 vulnerability
types) received: at least one evidence item with a non-empty
`EvidenceID` and `IntegrityHash`, a VERIFICATION item, a REPRODUCTION
item, a non-empty `Summary`, a non-empty `WhyVulnerable`, a non-empty
`Reproduction.Level`, and a non-empty `Limitations` list -- confirmed
by direct assertion, not just absence of a crash. Repeating
`BuildPackage` against the identical canonical set reproduced identical
evidence IDs, integrity hashes, summaries, and explanations. A direct
scan of every captured request header for `Authorization`/`Cookie`/
`Set-Cookie` confirmed none appeared unredacted in real, lab-captured
evidence (not just synthetic fixtures).

## Acceptance table -- all six vulnerability classes (task section 44)

`TestAcceptanceMatrix_AllSixVulnerabilityClasses`, run against
synthetic fixtures mirroring each real detector's actual evidence
shape:

| Finding | Evidence Type | Expected | Actual | Result |
|---|---|---|---|---|
| reflected_xss | VERIFICATION+REPRODUCTION | present | verification=true reproduction=true | PASS |
| sql_injection | VERIFICATION+REPRODUCTION | present | verification=true reproduction=true | PASS |
| ssrf | VERIFICATION+REPRODUCTION | present | verification=true reproduction=true | PASS |
| idor | VERIFICATION+REPRODUCTION | present | verification=true reproduction=true | PASS |
| path_traversal | VERIFICATION+REPRODUCTION | present | verification=true reproduction=true | PASS |
| command_injection | VERIFICATION+REPRODUCTION | present | verification=true reproduction=true | PASS |

Every fixture also produced non-empty `EvidenceID`/`IntegrityHash` on
every item, and deterministic ordering/hashing across repeated
`BuildEvidence` calls (asserted directly in the test, not just implied
by the table above).

## Issues found and fixed during this phase

Per the task's "do not weaken tests to achieve PASS" instruction, every
issue below was found by a real test failure, root-caused, fixed in the
implementation (never in the test to make it pass), and reconfirmed.

1. **Reproduction LIMITED with no explanation.** When raw evidence
   failed to parse as the Phase 3.1 JSON contract, `buildFromRawItem`'s
   fallback still produced a VERIFICATION-typed item (with empty
   Method/URL) rather than no item at all -- so `buildReproductionInfo`'s
   `verification == nil` early-return (which appends an explanatory
   note) never fired, and `Level=LIMITED` shipped with an empty
   `Notes`, violating task section 32's "never hide uncertainty."
   **Fix**: added an explicit check after classification --
   `Level == LIMITED && Method == "" && URL == ""` now appends the same
   explanatory note regardless of which code path produced the empty
   state (`reproduction_build.go`).
2. **URL-embedded secrets survived redaction.** A URL parameter whose
   VALUE was itself a URL carrying its own secret-shaped query string
   (SSRF-style: `url=http://x.test?api_key=SECRET`) leaked the embedded
   secret, because `redactURL` only inspected top-level parameter
   NAMES. **Fix**: added a second `redactText` pass over the whole URL
   after the structured per-parameter pass.
3. **Greedy regex swallowed a genuine secret.** After fix #2, the same
   secret still leaked: `keyValuePattern`'s greedy value class matched
   `"http"` as a false key (with `:` as separator) and consumed the
   ENTIRE remainder of the string as one bogus match, hiding the real
   `api_key=SECRET` a few characters later (`ReplaceAllStringFunc`
   never re-scans inside an already-consumed match). Diagnosed with an
   isolated `FindAllStringSubmatch` reproduction script. **Fix**:
   excluded `/` and `:` from the value character class, so `http:`
   fails to match at all and the scan continues past the URL's own
   scheme to find the real secret.
4. **Multipart field names never redacted.** `multipart/form-data` puts
   the field name in a `Content-Disposition` header with the value on
   a separate line -- a shape the generic text regex cannot match, so
   the assumed "falls back to text redaction" safety net did not
   actually catch it. **Fix**: implemented real MIME parsing/
   reassembly via `mime`/`mime/multipart` (`redactMultipart`) rather
   than relying on the generic fallback.
5. **Sanitize-before-truncate performance bug.** A 10MB synthetic
   response took 77.62s to process, because regex-based sanitization
   ran on the full, untruncated response/request/observation text
   BEFORE truncating to the configured limit -- sanitization cost
   scaled with whatever a target sent, not with the configured limit.
   **Fix**: reordered to truncate first, sanitize the bounded result
   second (reasoned through and confirmed safe for secrets straddling
   the cut boundary either way). Verified: the same test dropped from
   77.62s to 1.50s.
6. **CRLF passed through unredacted.** A header value containing raw
   `\r\nX-Injected: evil` was stored verbatim -- while JSON
   serialization alone makes this safe from literal header smuggling,
   task section 36 explicitly names CRLF as adversarial input this
   engine must neutralize, since raw control bytes could still be
   misused by anything that later renders or re-emits stored evidence
   as plain text (a log, a terminal, a future report writer).
   **Fix**: added `sanitizeControlChars`, applied to every captured
   header value, replacing raw CR/LF and other C0 control bytes with
   visible, information-preserving escapes (`\r`, `\n`, `\xNN`).

## Revert-and-verify

Per the task's discipline, two of this phase's central correctness
properties were verified by temporarily breaking them and confirming
the right tests fail for the right reason, then reverting.

1. **Secret redaction.** `"authorization"` was temporarily removed from
   `sensitiveHeaderNames`. Re-running the redaction/secret-leak suite
   failed exactly as expected:
   ```
   --- FAIL: TestRedactHeaders_Authorization
   --- FAIL: TestRedactHeaders_CaseInsensitive
   --- FAIL: TestSecretLeak_AuthorizationBearerNeverAppearsInEvidence
       secret "SECRET123" leaked in Request.Headers["Authorization"]: "Bearer SECRET123"
       secret "SECRET123" leaked in Response.Headers["Authorization"]: "Bearer SECRET123"
   ```
2. **Timestamp exclusion from the integrity hash.** `CollectedAt` was
   temporarily added to `canonicalHashInput` and populated in
   `finishCanonicalEvidence`. Re-running the hash/ordering/determinism
   suite failed exactly as expected, across three independent tests:
   ```
   --- FAIL: TestHash_TimestampExcludedFromCanonicalInput
       index 0: IntegrityHash differs despite only CollectedAt changing
   --- FAIL: TestOrdering_DeterministicAcrossRepeatedCalls
       index 0: order differs across repeated calls
   --- FAIL: TestConcurrency_RepeatedBuildEvidenceStaysDeterministic
       observed 100 distinct evidence-ID sequences across 100 concurrent BuildEvidence() calls, want exactly 1
   ```

Both defects were reverted; `go build ./...` and the full
`internal/evidence` package suite were re-run and confirmed byte-
identical to the pre-break versions (`diff` against a backup copy of
each file showed no difference), and clean.

## Regression

Full suite, `go test -race -count=1 -v ./...`, run after every change
in this phase (including both revert-and-verify exercises) and again
as the final check:

```
TOTAL TESTS: 1106 (845 top-level + 261 subtests)
PASS:        1106
FAIL:        0
```

All 28 tested packages report `ok`. `gofmt -l .`, `go build ./...`, and
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
  unchanged; all tests pass unchanged.
- **Phase 3.9 regression**: `internal/risk` completely unchanged; all
  tests pass unchanged -- confirming the new evidence engine composes
  cleanly on top without touching either layer beneath it.

## Final report

```
TOTAL TESTS: 1106 (845 top-level + 261 subtests)
PASS: 1106
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

EVIDENCE MODEL: PASS
BASELINE CAPTURE: PASS (modeled and tested; honestly unpopulated for every real finding today -- see Limitations)
PROBE CAPTURE: PASS (modeled and tested; honestly unpopulated for every real finding today -- see Limitations)
VERIFICATION CAPTURE: PASS
REPRODUCTION: PASS
SECRET REDACTION: PASS
EVIDENCE DEDUPLICATION: PASS
DETERMINISTIC ORDERING: PASS
INTEGRITY HASHING: PASS
LARGE RESPONSE HANDLING: PASS
BINARY RESPONSE HANDLING: PASS
SCOPE ENFORCEMENT: PASS
REPRODUCIBILITY: PASS
DETERMINISM: PASS
SECURITY: PASS
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
PHASE 3.9 REGRESSION: PASS

PHASE 3.10 ADVERSARIAL: PASS

PHASE 3.10 VERDICT: PASS
```

Not proceeding to Phase 3.11, not implementing new vulnerability
detectors, exploitation, reverse shells, arbitrary command execution,
credential harvesting, data exfiltration, remediation, or LLM runtime
functionality, per the task's explicit instruction to stop after this
report.
