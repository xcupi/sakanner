# Phase 1 Acceptance Test

Independent QA pass against the Phase 1 Definition of Done, performed 2026-08-20. Every item below was actually executed (build run, test run, or manual CLI exercise) — nothing is marked PASS on inspection alone. Five real bugs were found during this pass, all fixed and covered by new regression tests; details are under the relevant item and summarized at the end.

Legend: `PASS` / `FAIL` / `PARTIAL` / `NOT IMPLEMENTED`

---

## 1. BUILD — PASS

**Test performed:** Full build of the module and the CLI binary; ran the resulting binary.
**Command used:**
```
go build ./...
go build -o bin/scanner ./cmd/scanner
./bin/scanner --help
```
**Expected result:** No compilation errors; binary runs and prints usage.
**Actual result:** Clean build, binary runs, prints the expected command tree (`target`, `scope`, `scan`, `status`, `findings`, `report`).
**Evidence:** Exit code 0 on all three commands; `--help` output lists all six subcommands plus global `--config` flag.

## 2. UNIT TESTS — PASS

**Command used:** `go test ./...`
**Expected result:** PASS.
**Actual result:** All packages pass (`ok` for every package with test files; `?` for packages with none — `cmd/scanner` and the not-yet-implemented Phase 2+ stub packages).
**Evidence:** 83 individual test cases (including subtests) across 22 `_test.go` files, ~2,839 lines of test code, all passing.

## 3. RACE DETECTION — PASS

**Command used:** `go test -race ./...`
**Expected result:** No race detector failures.
**Actual result:** Clean pass, no races reported, across all packages including the concurrency-heavy `orchestration`, `ports`, and `http` packages.

## 4. STATIC ANALYSIS — PASS (go vet) / NOT AVAILABLE (golangci-lint)

**Command used:** `go vet ./...`; `gofmt -l .`; `which golangci-lint`.
**Expected result:** No vet issues; golangci-lint results reported separately if installed.
**Actual result:** `go vet ./...` clean. `gofmt -l .` clean (no files need formatting). `golangci-lint` is not installed in this environment — not run, reported here as NOT AVAILABLE rather than assumed passing.

## 5. CLI TEST — PASS

**Test performed:** Exercised every subcommand's `--help`, and the full command sequence (target add → target list → scope add → scope list → scope remove → scan → status → findings → report in both formats), plus invalid-argument handling.
**Commands used:** `scanner --help`, `scanner target --help`, `scanner scope --help`, `scanner scan --help`, `scanner report --help`, `scanner target add`, `scanner nonexistent-command`.
**Expected result:** Help text renders correctly; commands work end-to-end; invalid usage fails gracefully with a clear message and non-zero exit code.
**Actual result:** All help text correct. Full command sequence verified manually against a local loopback target (see items 12/14/15 below for output). `target add` with 0 args: `Error: accepts 1 arg(s), received 0`, exit 1. `nonexistent-command`: `Error: unknown command "nonexistent-command" for "scanner"`, exit 1. No panics, no hangs.

## 6. TARGET VALIDATION — PASS (after fix)

**Test performed:** `scanner target add` against valid/invalid domains, IPv4/IPv6, CIDR, malformed and edge-case input.
**Command used:** `scanner target add <value>` for ~20 cases (valid domain, uppercase domain, trailing dot, overlong label, leading/trailing hyphen label, unicode/IDN, single-word host, valid/invalid IPv4, valid IPv6, valid/invalid CIDR, empty string, whitespace, malformed strings).

**FINDING (fixed):** `999.999.999.999`, `256.1.1.1`, and `192.168.001.1` (leading-zero octets) were silently accepted as valid **domain** targets. `net.ParseIP` correctly rejects these as IPs, but each dot-separated label (`999`, `256`, `001`) is independently a legal DNS label, so the parser fell through and classified them as `TargetTypeDomain` instead of rejecting them. Leading-zero IPs in particular are a known octal/decimal-ambiguity technique used to obfuscate IP addresses (a genuine SSRF/scope-bypass-adjacent concern for a security tool). **Fix:** added `looksLikeIPv4()` in [internal/target/target.go](../internal/target/target.go) — any four-dot-separated, all-numeric-label string that fails `net.ParseIP` is now rejected outright with a clear error, rather than silently reclassified as a domain.

**Actual result (post-fix):** All invalid IP-shaped strings correctly rejected. Genuinely invalid input (empty, malformed, bad hostname labels, invalid CIDR, unicode without punycode) rejected with clear errors and exit code 1; nothing panics. IPv6 targets accepted correctly. Unicode/IDN domains are rejected (not silently mishandled) — noted as a known Phase 1 limitation, not a defect: operators must supply punycode-encoded IDN domains.
**Evidence:** [internal/target/target_test.go](../internal/target/target_test.go) — 20 table-driven cases including the four new regression cases for the fixed bug; CLI-level reproduction and re-verification also performed manually.

## 7. SCOPE ENFORCEMENT — PASS (after two critical fixes)

This is the platform's core safety property, and this pass found the two most significant issues in the whole review.

**Test performed:** Exact-host rules, domain-suffix ("wildcard") rules and subdomain matching, disallowed sibling subdomains (substring-not-suffix confusion), unrelated domains, IP addresses, CIDR ranges (matching, sub-range, disjoint), and redirects to an out-of-scope host — each proven through the real pipeline (`orchestration.Pipeline.Run`) against local `httptest` targets, never live hosts.

**FINDING 1 (critical, fixed): domain-based scope rules never actually authorized anything.** `ports.Scanner` and `http.Prober` validated every dial via `Validator.CheckIP(ip)`, which only understands `cidr`/`exact_host`-as-IP rules — it has zero knowledge of `domain_suffix` rules. Since "authorize `*.example.com`" is the overwhelmingly common real-world scope rule, a scan against a domain-based target would start, resolve DNS, and then get denied on **every single port/HTTP dial**, because the resolved IP never matched any IP-level rule. This would have made the tool non-functional for the standard bug-bounty/pentest scope-authorization style. **Fix:** introduced `Validator.CheckResolved(ctx, hostname, ip)` in [internal/scope/scope.go](../internal/scope/scope.go), which (a) enforces the reserved-range deny-list on the concrete IP unconditionally — closing the DNS-rebinding gap, since a domain-suffix-authorized hostname must not be allowed to dial loopback/metadata/link-local just because the hostname matched — then (b) checks the hostname via `CheckHost` (covering `domain_suffix`/`exact_host`, and delegating to `CheckIP` for bare-IP/CIDR-string hosts), and (c) falls back to a direct IP rule only if the hostname matched *no* rule at all (an explicit deny is terminal, never overridden by a fallback IP match). `ports.Scanner.Scan` and `http.Prober`'s dial path were updated to call `CheckResolved` instead of `CheckIP`.

**FINDING 2 (fixed): CIDR-notation targets could never pass the pre-flight scope gate.** `CheckHost` had no logic for CIDR-notation strings (e.g. a `TargetTypeCIDR` target's literal value `"127.0.0.1/30"`), so the very first scope check in `orchestration.Run` denied every CIDR target outright, even with a covering CIDR rule in place — despite the *per-IP* dial-time check already working correctly for CIDR-expanded hosts. **Fix:** `CheckHost` now recognizes CIDR-notation input and matches it against `cidr`-type rules via range containment (a rule authorizes a target CIDR only if the rule's range fully covers it).

**Actual result (post-fix):** All scenarios pass through the real pipeline: exact-host, domain-suffix (with correct subdomain boundary handling — `evil-allowed.test` does NOT match a rule for `allowed.test`), unrelated-domain denial (zero DNS resolution occurs before the abort), CIDR match/sub-range/disjoint, and the redirect-to-out-of-scope-host test (the out-of-scope handler is *never invoked* — proven via a test assertion, not just a status code check).
**Evidence:** [internal/scope/scope_test.go](../internal/scope/scope_test.go) (20 cases, including 7 new `CheckResolved`/CIDR-notation cases), [internal/orchestration/scope_enforcement_test.go](../internal/orchestration/scope_enforcement_test.go) (5 full-pipeline integration tests), [internal/http/prober_test.go](../internal/http/prober_test.go) (`TestProbe_RedirectToOutOfScopeHostStopsChain`).

## 8. TIMEOUT HANDLING — PASS

**Test performed:** HTTP probing against a server that never responds (blocks forever) and one that responds far slower than the configured timeout; TCP port scanning against a closed (refused) local port.
**Command used:** Go tests using `httptest` handlers that block on an unclosed channel / `time.Sleep` far longer than `Config.Timeout`.
**Expected result:** No indefinite hang; bounded by configured timeout.
**Actual result:** Non-responsive server: `Probe` returns within ~2× the configured 300ms timeout (both https/http attempts), never approaching the test's 5s hard fail-safe. Slow server (10× the 200ms timeout): `Probe` returns an error within well under 5× the timeout. Refused TCP connections return in ~0ms (OS-level RST), far under the 3s dial timeout used in the test.
**Note:** the TCP-connect scanner only measures handshake completion, not response timing, so a "slow to respond" scenario doesn't apply at that layer by design — it's only meaningful for HTTP. A genuine network-blackhole (SYN dropped, no RST) scenario for the raw TCP layer would require firewall-level packet manipulation, which isn't practical or appropriate to construct in this sandboxed environment; the `net.Dialer{Timeout: dialTimeout}` wiring was verified by code review and the refused-connection fast-path was verified empirically.
**Evidence:** [internal/http/timeout_test.go](../internal/http/timeout_test.go), [internal/ports/ports_test.go](../internal/ports/ports_test.go) (`TestScan_RefusedConnectionsReturnQuickly`).

## 9. CANCELLATION — PASS (after two fixes)

**Test performed:** Started a scan, cancelled it mid-flight (both via Go `context.CancelFunc` in a deterministic test and via a real `SIGINT` sent to the built binary's process), and verified graceful shutdown, DB integrity, correct terminal status, and resource release.

**FINDING 1 (fixed): a cancelled scan was reported as "completed."** Individual stages (subdomain enumeration in particular) treated context cancellation the same as "this candidate just doesn't resolve" and silently swallowed it rather than propagating it as a stage error — so `orchestration.Run` never learned cancellation had occurred and reported the job as `completed` with partial/incomplete results, indistinguishable from a real success. **Fix:** `discovery.wordlistEnumerator.Enumerate` now distinguishes context cancellation from an ordinary resolution failure and propagates it; more importantly, `orchestration.Run` now checks `ctx.Err()` **authoritatively** after every stage run, regardless of whether an internal stage correctly reported the cancellation itself — closing this class of bug robustly rather than chasing every individual swallow-point. `models.ScanJobStatusCancelled` (previously defined but never actually used) is now set correctly, distinct from `Failed`.

**FINDING 2 (fixed): the final status write used the same (already-cancelled) context, risking a job stuck at "running" forever.** If the operator cancelled the scan, the request context was already `Done`; using it for the final `ScanJobs().Update` call could make persisting the terminal status itself fail as a side effect of the same cancellation, silently leaving the job's DB row at `running` indefinitely. **Fix:** the final status write (in both the normal completion path and the pre-flight `fail()` path) now uses a short-lived detached context (`context.WithTimeout(context.Background(), 5s)`), decoupled from the caller's cancellation.

**Actual result (post-fix):**
- Deterministic Go test: a scan with artificially-slowed DNS resolution (30 lookups × 80ms, concurrency 2 ≈ 1.2s uncancelled) is cancelled at 150ms; `Run` returns in well under 800ms (graceful, prompt shutdown), `job.Status == cancelled`, `FinishedAt` is set, the store remains fully usable afterward, and a fresh follow-up scan against the same store completes normally.
- Real `SIGINT` test: `scanner scan` against 4000 ports on loopback, sent `SIGINT` ~1s in. Process exits with code 1 (not killed by the raw signal — `signal.NotifyContext` caught it and translated to graceful context cancellation), logs `status=cancelled error="context canceled"`, and `scanner status` on a **fresh process** afterward correctly shows `status: cancelled` with a `finished` timestamp. A subsequent scan against the same DB file completes normally, confirming no corruption or stuck lock.
**Evidence:** [internal/orchestration/cancellation_test.go](../internal/orchestration/cancellation_test.go); manual SIGINT reproduction (documented in this session's transcript, not stored as a repo artifact since it's a live process test).

## 10. CONCURRENCY — PASS (after fix)

**Test performed:** Empirically measured the true aggregate number of in-flight dials when multiple hosts are scanned concurrently, not just inspected config wiring.

**FINDING (fixed): configured `PortWorkers` compounded across hosts instead of bounding the total.** `orchestration.scanPorts` fans out across hosts with `errgroup.SetLimit(PortWorkers)`, and — separately — `ports.Scanner.Scan` created a **fresh** `errgroup.SetLimit(concurrency)` on every call (once per host). Since `PortWorkers` was used for both, the true worst-case aggregate concurrent dials was `PortWorkers × PortWorkers` (e.g. the default of 20 → up to 400 concurrent TCP connections), not the single `PortWorkers` value an operator configuring "20 concurrent" would reasonably expect — a real violation of "respect target rate limits." **Fix:** `tcpConnectScanner` now holds a single `*semaphore.Weighted` sized at `concurrency`, created once and shared across every `Scan()` call made through that scanner instance (which orchestration already reuses across all hosts in a job) — the true aggregate in-flight dial count is now bounded by the configured value regardless of how many hosts are scanned concurrently.

**Actual result (post-fix):** A test scanning 6 hosts × 8 ports concurrently with `concurrencyLimit=4` and an artificial 15ms hold per dial-check observed a high-water mark of 6–8 concurrent in-flight dials (within the expected ceiling of `hostCount + concurrencyLimit = 10`, accounting for the legitimate, intentionally non-semaphore-gated one-time pre-flight check per host). **The same test against the pre-fix code reliably observed exactly 24** (`6 × 4`, precisely matching the predicted compounding bug) — confirming both that the bug was real and that the fix resolves it. This revert-and-verify was performed directly (temporarily reintroducing the old per-call `errgroup.SetLimit` pattern, confirming the test fails as predicted, then restoring the fix and confirming it passes again).
**Evidence:** [internal/ports/concurrency_test.go](../internal/ports/concurrency_test.go) (`TestScan_TrueAggregateConcurrencyAcrossHosts`).
**Note:** `HTTPWorkers` and `DNSWorkers` were code-reviewed for the same pattern and found *not* to have it — each is a single, non-nested `errgroup.SetLimit` with no internal per-call fan-out multiplying against it, so they were not empirically re-tested beyond the existing unit coverage.

## 11. RATE LIMITING — PASS

**Test performed:** Configured a `rate.Limiter` at 5 events/sec (burst 1) for both the port scanner and the HTTP prober, and measured wall-clock time for a batch of dials/requests against a real local listener/server, with an unlimited control run for comparison.
**Expected result:** Paced requests take measurably longer than unpaced ones, matching the configured rate.
**Actual result:** 10 port dials at 5/sec took 1.80s (theoretical: (10-1)/5 = 1.8s); the same 10 dials with no limiter took 0.01s. 6 HTTP probes at 5/sec took 1.01s (theoretical: (6-1)/5 = 1.0s).
**Evidence:** [internal/ports/ratelimit_test.go](../internal/ports/ratelimit_test.go), [internal/http/ratelimit_test.go](../internal/http/ratelimit_test.go).

## 12. DATABASE PERSISTENCE — PASS

**Test performed:** Ran a scan with one process, then queried it (`target list`, `status`, `report --format json`) from a **completely separate process invocation** against the same SQLite file (simulating "stop and restart the application," since this CLI has no long-running daemon state).
**Command used:** Sequential `./bin/scanner --config <cfg> <cmd>` invocations, each a fresh process.
**Expected result:** Data survives and is correctly retrievable after the process exits and a new one starts.
**Actual result:** Target, scope rule, scan job (with full `scope_snapshot`), and all result rows correctly retrieved by the second process. Also stress-tested with 5 concurrent scanner processes writing to the same DB file simultaneously — all 5 completed successfully and the DB remained fully readable afterward (WAL mode + `busy_timeout` pragma handling concurrent writers correctly).
**Evidence:** manual CLI reproduction (this session's transcript); the underlying mechanism is also covered by [internal/storage/sqlite/sqlite_test.go](../internal/storage/sqlite/sqlite_test.go).

## 13. DATABASE ERROR HANDLING — PASS

**Test performed:** `storage.dsn` pointing at a nonexistent directory, a directory instead of a file, and a file inside a read-only (555) directory.
**Expected result:** Graceful, clear error; no panic, no crash, no partial/corrupt state.
**Actual result:** All three: `Error: sqlite: ping: unable to open database file (14)`, exit code 1, no panic. Malformed config (duplicate YAML key, found incidentally while preparing another test) also correctly rejected with a clear parse error rather than crashing or silently using defaults.

## 14. JSON OUTPUT — PASS (after fix)

**Test performed:** Generated `scanner report --format json` and validated with an independent Python JSON parser: syntactic validity, required fields, field types, and RFC3339 timestamp parseability.

**FINDING (fixed): empty result lists serialized as `null` instead of `[]`.** Every `List`/`ListByScanJob` repository method initialized its return slice as `var out []T` (nil when zero rows), which `encoding/json` renders as the JSON literal `null` rather than `[]` — inconsistent with the field's declared array type and liable to break strict consumers that expect a consistent array shape. **Fix:** all nine `List`/`ListByScanJob` methods in [internal/storage/sqlite/repos.go](../internal/storage/sqlite/repos.go) now initialize as `out := []T{}`.

**Actual result (post-fix):** JSON syntactically valid; `job.id`, `target_ids`, `status`, `scope_snapshot`, `started_at`, `created_at` all present with correct types; `started_at`/`finished_at`/`created_at` all parse as valid RFC3339; every list-typed report field (`assets`, `hosts`, `services`, `http_services`, `technologies`, `findings`) is consistently `[]`, never `null`, even when empty.
**Evidence:** [internal/reporting/reporting_test.go](../internal/reporting/reporting_test.go) (`TestMarkdown_EmptyReportOmitsSections` extended with a JSON-shape assertion); manual `python3 -c "json.load(...)"` validation against real CLI output.

## 15. REPORTING — PASS (after security fix, see item 17)

**Test performed:** Generated both Markdown and JSON reports from a real scan against a local server (nginx-header response with a page title).
**Expected result:** Report created; contains target, scan ID, timestamps, correctly-represented results; no secrets or internal debugging info.
**Actual result:** Both formats generated correctly — Markdown includes a Summary table, Assets/Open Services/HTTP Services/Technologies sections (with `nginx` correctly fingerprinted end-to-end through the real HTTP prober), and a Findings section explaining Phase 1 has no detection yet. JSON includes the full job record with scope snapshot. Reviewed for secret/debug leakage: the `ScanJob.Config` model field (which could theoretically carry sensitive scan configuration in a future phase) is never populated in Phase 1, so nothing leaks today; no credential-handling code exists anywhere in the codebase to leak in the first place (`grep`-verified). See item 17 for the Markdown-injection fix that also applies here.
**Evidence:** manual CLI reproduction; [internal/reporting/reporting_test.go](../internal/reporting/reporting_test.go), [internal/reporting/markdown_security_test.go](../internal/reporting/markdown_security_test.go).

## 16. ERROR HANDLING — PASS

**Test performed:** DNS resolution failure (nonexistent domain, scope-allowed so it actually reaches the DNS stage), connection failure (refused ports, item 8), timeout (item 8), malformed configuration (duplicate YAML key, item 13), invalid input (item 6).
**Expected result:** No panics; clear errors; scan continues where reasonable (a single bad target in a multi-target scan shouldn't abort the whole job) or aborts cleanly where correctness demands it (scope denial).
**Actual result:** DNS failure for an allowed-but-nonexistent domain: logged as a `WARN` (`failed to resolve target ... no such host`), scan continues with zero hosts and completes with status `completed` (correct — a single unresolvable domain among what could be multiple targets shouldn't fail the whole job; this is a deliberate resilience choice, not a bug). No panics observed anywhere across the full test suite (83 tests) or the ~15 manual CLI failure-mode reproductions in this session.
**"Missing dependency":** not applicable to Phase 1 — no external tool (nmap, subfinder, etc.) is a hard dependency; all built-in implementations (TCP-connect scanner, wordlist enumerator) are pure Go.

## 17. SECURITY TESTING — PASS (2 findings, both fixed)

**Test performed:** Manual code review plus targeted greps across the codebase for each listed vulnerability class.

- **Command injection / unsafe shell execution:** `grep -rl "os/exec"` finds it used only in `tests/e2e/e2e_test.go` (building/running the test binary with fully hardcoded arguments) — **zero** shell-out surface in any production code path. No finding.
- **Path traversal / arbitrary file write:** the only file-write call in production code is `os.WriteFile(output, ...)` in `cmd/scanner/report.go`, where `output` is the `--output` flag the *operator themselves* supplies on their own command line — this is standard CLI behavior (identical trust model to `curl -o` or `wget -O`), not a privilege-boundary crossing, since the invoking user already has whatever filesystem access the process has. No finding; reviewed and not applicable.
- **Unsafe deserialization:** no `encoding/gob`, no `unsafe`, no reflection-based deserialization anywhere. All persistence uses `encoding/json` with typed Go structs. No finding.
- **SQL injection:** every query in `internal/storage/sqlite` uses parameterized `?` placeholders via `database/sql`; the only string concatenation in that package builds fixed, compile-time-constant pragma/filename strings, never scan-target or user-supplied data. No finding.
- **ReDoS:** Go's `regexp` package (used for title extraction and tech fingerprinting, both operating on untrusted scanned-target response data) is RE2-based and immune to catastrophic backtracking by construction. No finding.
- **Untrusted input handling / unsafe report generation — FINDING (fixed):** `internal/reporting/markdown.go` embedded scanned-target-controlled data (HTTP response titles, TLS certificate subject/issuer strings — the latter attacker-controllable by design, since this platform intentionally does not verify certificates in order to probe/fingerprint targets with self-signed or invalid certs) directly into Markdown table cells with no escaping. A malicious or compromised target could (a) break the table structure with an embedded `|` or newline, or (b) inject raw HTML/`<script>` that would execute if the report is later rendered as HTML by some downstream viewer (Markdown permits raw inline HTML by default). **Fix:** added `mdEscape()`, applied to every target-originated field embedded in the Markdown report (asset names/sources, HTTP titles/URLs/TLS subject, technology names/categories, finding titles/endpoints) — it neutralizes embedded pipes, flattens newlines, and HTML-escapes angle brackets/ampersands via `html.EscapeString`.
**Evidence:** [internal/reporting/markdown_security_test.go](../internal/reporting/markdown_security_test.go) — constructs a malicious title (`<script>alert('xss')</script> | broken | table\nrow`) and TLS subject, confirms no raw `<script>`/`<img` tags survive, the escaped form is present, the pipe is escaped, and the embedded newline doesn't produce a stray table row.

## 18. CLEAN ENVIRONMENT TEST — PASS

**Test performed:** Built the project with fully isolated `GOCACHE` and `GOPATH` (fresh temp directories, no reuse of the developer's existing module/build cache), simulating a fresh checkout on a new machine.
**Command used:**
```
go mod verify
GOCACHE=<fresh temp dir> GOPATH=<fresh temp dir> go build -o /tmp/clean-build-scanner ./cmd/scanner
```
**Expected result:** Builds successfully from a clean state using only `go.mod`/`go.sum`; binary runs.
**Actual result:** `go mod verify`: "all modules verified." Clean-cache build: all dependencies downloaded automatically from `go.sum`-pinned versions, build succeeded (exit 0), binary ran (`--help` succeeded). No native/cgo toolchain required (pure-Go `modernc.org/sqlite`), consistent with the "must also run natively on Ubuntu" requirement.

---

## Summary

| Total tests (automated, incl. subtests) | Passed | Failed | Partial | Not implemented |
|---|---|---|---|---|
| 83 (unit/integration) + 18 acceptance items | 83 / 83 automated; 18 / 18 acceptance items PASS | 0 | 0 | 0 (golangci-lint not available in this environment, not counted as a failure) |

**Critical requirements** (build, unit tests, race test, scope enforcement, database persistence, cancellation, input validation, security-critical error handling): **all PASS**, three of them (scope enforcement, cancellation, input validation) only after fixes described above.

**Bugs found and fixed during this pass (5 total, all with regression tests):**
1. Target parser silently accepted invalid IP-shaped strings (`999.999.999.999`, leading-zero octets) as domains — [internal/target/target.go](../internal/target/target.go).
2. **Critical:** domain-based scope rules (`domain_suffix`/`exact_host`) never actually authorized any dial — every domain-based scan would fail at the port/HTTP stage regardless of scope rules — [internal/scope/scope.go](../internal/scope/scope.go), [internal/ports/ports.go](../internal/ports/ports.go), [internal/http/prober.go](../internal/http/prober.go).
3. CIDR-notation targets could never pass the pre-flight scope check even with a covering rule — [internal/scope/scope.go](../internal/scope/scope.go).
4. Cancelled scans were reported as "completed" (cancellation silently swallowed internally), and the final status write could itself fail as a consequence of the same cancellation, leaving jobs stuck at "running" — [internal/orchestration/pipeline.go](../internal/orchestration/pipeline.go), [internal/discovery/discovery.go](../internal/discovery/discovery.go).
5. Port-scan concurrency compounded across hosts (`PortWorkers²` instead of `PortWorkers` true aggregate concurrency) — [internal/ports/ports.go](../internal/ports/ports.go).

Plus two data-quality/security hardening fixes: empty JSON list fields serializing as `null` instead of `[]`, and unescaped target-controlled content in Markdown reports (Markdown/HTML injection risk).

## PHASE 1 STATUS

**PASS**

All critical requirements pass. All findings from this review were fixed in place, covered by new regression tests, and re-verified — the full suite (`go build`, `go vet`, `gofmt -l`, `go test ./... -race`) is green, and the CLI was independently re-exercised end-to-end after each fix. Per instructions, Phase 2 is not started.
