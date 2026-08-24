# Phase 3.24 Acceptance Test — Authorization & IDOR/BOLA Detection Foundation

## TOTAL TESTS

1934 (1834 non-e2e + 100 e2e), run standalone (non-e2e and e2e never
run concurrently, per this repository's own established discipline).
37 tests are new in this phase: 4 in
[internal/parameters/object_identifier_test.go](../internal/parameters/object_identifier_test.go),
15 in [internal/detectors/idoractive/detector_test.go](../internal/detectors/idoractive/detector_test.go),
5 in [internal/detectors/idoractive/adversarial_test.go](../internal/detectors/idoractive/adversarial_test.go),
8 in [lab/phase3_24_authorization_test.go](../lab/phase3_24_authorization_test.go),
5 in [tests/e2e/e2e_authorization_test.go](../tests/e2e/e2e_authorization_test.go).

## PASS

1934 / 1934.

## FAIL

0.

## PARTIAL

0.

## NOT IMPLEMENTED

None of this phase's own required scope. Explicitly out of scope by
design (see architecture doc section 17): full N-identity matrices
(only one baseline+compare pair), a second discovery crawl
authenticated as the compare identity, object-ownership inference
beyond the three-probe empirical comparison, and everything in the
task's own strict-boundary exclusion list (privilege escalation,
account takeover, credential attacks, CSRF, mass assignment, SSRF,
command injection, new SQLi/XSS techniques, path traversal, business-
logic exploitation beyond authorization comparison, destructive
testing).

## SECURITY ISSUES

None found in production code. One pre-existing defect was found and
fixed in this phase's own new code during development (see DEFECTS
FOUND AND FIXED) — no defect was found in code from a prior phase.

## RELIABILITY ISSUES

None. All three probes (baseline, cross-test, known-bad control)
correctly propagate `mutation.Executor` errors (scope rejection,
timeout, transport error) as detector errors, never silently
swallowed, matching every other active detector's own established
error handling.

## PERFORMANCE ISSUES

None observed. Per eligible target, `idor-active` issues at most 3
requests (2 unmutated replays, charged against no mutation budget, and
1 mutated known-bad control, charged against the SAME per-parameter/
per-scan mutation budget every other active detector already respects
independently on its own executor) — see architecture doc section 19.
The full real-lab end-to-end test
(`TestPhase3_24_EndToEnd_HorizontalAuthorizationFailure_RealPipeline`)
completes in well under 1 second; the CLI e2e suite's authorization
tests complete in single-digit seconds each.

## DEFECTS FOUND AND FIXED

1. **Confidence-tier test used a fixture that never actually echoed
   the object value.** While writing
   `TestDetect_HorizontalAuthorizationFailure_Finding`
   (`internal/detectors/idoractive/detector_test.go`), the test
   asserted the higher (0.9) confidence tier but the synthetic
   `idorVulnerableHandler` fixture's response body never literally
   contained the requested object identifier — a test-authoring
   mistake, not a production defect (confirmed by first running the
   test and observing the actual, correct 0.75 result). Fixed by
   making the fixture echo the id, matching the real lab's own
   `/notes` fixture's behavior (`NOTE_CONTENT_MARKER_%d`).
2. **A pre-existing e2e test's hardcoded detector-registry count went
   stale.** `TestDefaultCLI_CrawlerDisabled_ZeroDetectorRunsIsObservable`
   (`tests/e2e/e2e_detection_readiness_test.go`) asserted
   `"Registered: 8"` — a literal count from when `xss-reflected-active`
   (Phase 3.19) and `sqli-active` (Phase 3.20) brought the registry to
   8 detectors. Adding `idor-active` (registered-but-disabled, exactly
   like `ssrf`/`idor`/`traversal`) legitimately brings the count to 9.
   Fixed by updating the assertion and its own explanatory comment;
   confirmed the updated test passes and no other test in the
   repository hardcodes a registry count.
3. **A goroutine-safety artifact in a new concurrency test, not a
   production defect.** The first version of
   `TestPhase3_24_ConcurrentIdentityPairs_NoCrossContamination`
   (`lab/phase3_24_authorization_test.go`) called `authenticateIdentity`
   (which uses `t.Setenv`) from inside spawned goroutines — Go's own
   `testing` package forbids `t.Setenv` from a non-test goroutine and
   `go test -race` correctly flagged it as a race. Fixed by moving
   every `*testing.T`-touching call (env vars, session/executor/
   orchestrator construction) into the main goroutine first, mirroring
   `phase3_16_multi_identity_test.go`'s own
   `TestPhase3_16_ConcurrentIdentities_AccountAAndB` structure exactly
   — only the actual `orch.Run` call (which never touches `t`) happens
   inside the spawned goroutines. Re-verified clean under `-race`.

No defect was found in `internal/detectors/idor` (Phase 3.5),
`internal/mutation`, `internal/detection`, `internal/auth`,
`internal/orchestrator`, or any other pre-existing package — every
fact this phase's architecture review relied on
(docs/phase-3-24-authorization.md section 1) was independently
verified by directly reading the relevant source files, not merely
trusting the initial exploratory summary.

## REMAINING LIMITATIONS

1. **Objects legitimately, intentionally shared between the two
   tested identities cannot be distinguished from a genuine
   authorization failure by response comparison alone.** Documented
   in depth in architecture doc section 15 and demonstrated live by
   the lab's own `/shared?share_id=` fixture
   (`TestPhase3_24_SharedObject_DocumentedLimitation`). No dynamic,
   response-comparison-only BOLA-testing tool can resolve this without
   out-of-band knowledge of the intended access-control policy — this
   is why every finding this detector produces is framed as evidence
   for human review, never an infallible verdict.
2. **Exactly one baseline+compare identity pair per scan**, not an
   N-identity matrix — a deliberate, documented scope decision (section
   6), not an oversight.
3. **Object-identifier classification is name-based only** for this
   foundation phase (`parameters.IsLikelyObjectIdentifier`) — value-
   shape or discovery-context signals are future work the architecture
   was deliberately kept swappable for (section 8), not implemented
   here.
4. **`originalParameterValue`'s echo-evidence extraction is best-
   effort** for query/path locations only; form/JSON-body locations
   fall back to an empty string, which only ever lowers a finding's
   confidence tier, never blocks detection (detector.go's own doc
   comment) — acceptable since this detector's GET-only `Eligible`
   gate makes those locations structurally unlikely to ever occur in
   practice.

## ARCHITECTURAL FINDINGS

See [docs/phase-3-24-authorization.md](phase-3-24-authorization.md) in
full. Headline findings:

- The entire pre-Phase-3.24 pipeline (`auth.Session`,
  `orchestrator.Options.AuthSession`, `mutation.SessionContext`,
  `detection.Executor`, the `Detector.Detect` interface, the CLI's
  `--identity` flag) is hard-wired to exactly one identity per scan —
  confirmed by direct source reading, not assumption.
- `internal/detectors/idor` (Phase 3.5) already solved "a detector
  needs more than one identity" via a constructor-time
  `[]AuthContext` slice — but predates `internal/mutation` and builds
  its own private HTTP requests. `idor-active`
  (`internal/detectors/idoractive`) is the SAME constructor-time-
  dependency pattern, rebuilt on the canonical mutation engine, as a
  new, coexisting package — `internal/detectors/idor` is untouched.
- `cmd/scanner/scan.go`'s own pre-existing doc comment explicitly
  anticipated this phase: *"This phase [3.16] does not implement
  automated cross-identity comparison (IDOR/BOLA detection); it
  establishes the identity/session context a future phase would need
  for that."*
- No new canonical authorization-test model was needed — every
  concept the task described (acting/baseline identity, original/test
  request-response, comparison result) already maps onto
  `detection.Target`/`mutation.Request`/`mutation.Response`/
  `mutation.Compare`/`models.Finding` (section 2).

## LAB STATUS

`lab/harness_authorization.go` (new): 5 fixtures — `/notes?note_id=`
(vulnerable), `/documents?doc_id=` (safe), `/shared?share_id=`
(documented limitation), `/ping?request_id=` (generic-response
negative control), `/archive?page=` (non-object-name negative
control) — all linked from the existing `/dashboard` authenticated
page, reusing `harness_auth.go`'s `authApp`/`requireSession`
infrastructure and Phase 3.16's own `AccountAUserID`/`AccountBUserID`
accounts unchanged. Lab/production independence re-verified: `lab/`
and `tests/` moved aside, `go build ./...`/`go vet ./...` succeed with
zero lab-dependent code, `grep -rl "sakanner/lab" | grep -v '^\./lab' |
grep -v '^\./tests'` returns only the one already-known, harmless
false positive (a doc comment in
`internal/detectors/sqliactive/detector_test.go` stating the test does
NOT import `sakanner/lab`), then restored and rebuilt clean.

## E2E STATUS

`tests/e2e/e2e_authorization_test.go` (new, 5 tests) drives the
actual, compiled CLI binary end to end:
`TestScanCmd_AuthorizationDetection_HorizontalFailure_RealBinary`
performs a real scan against the real lab with `--identity account-a
--authz-identity account-b`, parses the JSON report, and confirms an
`idor` finding for `note_id` (attributed to `account-b`) while
`doc_id` is correctly NOT flagged. Three flag-validation tests confirm
`--authz-identity` fails before any network activity when misused.
`TestScanCmd_AuthzIdentity_Omitted_IdorActiveStaysDisabled` confirms
omitting the flag leaves `idor-active` disabled, exactly as before
this phase. Full e2e suite: 100/100 pass (`-timeout 25m`, matching
Phase 3.23's own established requirement since the suite exceeds Go's
default 10-minute timeout).

## ADVERSARIAL STATUS

All 15 of the task's named false-positive scenarios are addressed —
see architecture doc section 15's full mapping table. 5 are proven
live against a real httptest server
(`internal/detectors/idoractive/detector_test.go`), 1 against the real
lab (`TestPhase3_24_SharedObject_DocumentedLimitation`, the one
honestly-documented limitation), the remainder by construction
(`Eligible`'s name-shape gate, proven by
`TestIsLikelyObjectIdentifier_Adversarial_False`). Cross-identity
credential safety proven at the HTTP layer, sequential
(`TestAdversarial_SessionIsolation_HeadersNeverCrossIdentities`) and
concurrent
(`TestAdversarial_SessionIsolation_ConcurrentScans_NeverCrossContaminate`,
20 goroutines). Host-safety of the known-bad control's sentinel value
proven (`TestAdversarial_KnownBadControl_NeverChangesHost`).

## REGRESSION STATUS

Every prior phase's own test suite passes unchanged (1834/1834
non-e2e, 100/100 e2e — see TOTAL TESTS). Explicitly re-verified for
Phase 3.14 through 3.23's own dedicated test files, all of which are
included in the totals above: authentication (3.14), authenticated
crawling (3.15), multi-identity (3.16), scan profiles (3.12, carried
forward), request mutation (3.17), active detection foundation
(3.19), active SQLi (3.20), form mutation (3.21), active-detection
coverage completion (3.22), path parameters (3.23) — none required a
code change, apart from the one pre-existing e2e assertion documented
above (DEFECTS FOUND AND FIXED item 2), which was a stale literal
count, not a behavioral regression.

## RACE STATUS

Full non-e2e suite passes clean under `go test -race` (1834/1834, 0
failures, 0 race reports). `internal/detectors/idoractive`'s own
concurrency tests
(`TestAdversarial_SessionIsolation_ConcurrentScans_NeverCrossContaminate`)
and `lab/phase3_24_authorization_test.go`'s
(`TestPhase3_24_ConcurrentIdentityPairs_NoCrossContamination`) both
pass clean under `-race` specifically.

## PROVEN IDOR/BOLA vs. POTENTIAL / NOT PROVEN

**PROVEN** (real, live, end-to-end, against a genuinely vulnerable
fixture with no ownership check at all): the `/notes?note_id=`
scenario, proven twice independently — once at the orchestrator level
(`lab/phase3_24_authorization_test.go`) and once through the actual
CLI binary (`tests/e2e/e2e_authorization_test.go`). Every finding this
phase's detector produces requires passing all four gates in section 3
of the architecture doc (baseline succeeds, cross-test succeeds,
cross-test structurally matches baseline, cross-test structurally
differs from a known-bad control) — no finding is ever produced from
status code alone, from a merely-different response, or from a merely-
identical response.

**POTENTIAL / NOT PROVEN** (a case this phase's own honest limitation
analysis flags, not a false claim of success): the `/shared?share_id=`
scenario. This detector CAN produce a finding here (the object is
real, genuinely accessible to both tested identities, and a bogus ID
correctly 404s) even though the access is, by the lab's own design,
intentional. This is not this phase inflating a finding — it is an
explicit, acknowledged boundary of what response-comparison-only IDOR
detection can and cannot resolve, documented rather than hidden (see
REMAINING LIMITATIONS item 1). No finding this detector produces
should be treated as an infallible verdict; every finding carries
full baseline/cross-test/known-bad evidence specifically so a human
reviewer can make that call.
