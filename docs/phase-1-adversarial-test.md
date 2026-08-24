# Phase 1 Adversarial Test

Independent adversarial pass against the Phase 1 implementation, performed 2026-08-20 immediately after the Phase 1 acceptance test passed. The brief: assume nothing is correct, and actively try to break it. This is not a re-run of the acceptance checklist — it specifically targets attack classes and failure modes the acceptance pass didn't already cover: exotic scope-bypass encodings, redirect chains/loops, resource exhaustion, process interruption, and long-running-process resource leaks.

Two real bugs were found and fixed, both genuine and neither hypothetical:

1. **Interrupted scans left permanently stuck at `status: running`.** A `SIGKILL`, crash, or power loss during a scan left its job row unrecoverable — indistinguishable from a scan that's still genuinely in progress, forever.
2. **Goroutine/connection leak across repeated scans.** Every HTTP probe built a fresh `http.Transport` with unbounded keep-alive idle connections that were never closed, so goroutine count grew ~3 per scan with no upper bound — a slow but real resource leak in any long-running process (a daemon or a script running many scans back-to-back).

Everything else probed — including several classic SSRF/scope-bypass encodings — was already correctly defended by the Phase 1 implementation; those are documented below as verified-safe, not re-litigated as findings.

---

## Methodology

Each attack category below states what was tried, the actual mechanism (not just "I tested X"), and the result. Findings that required a fix show the root cause, the fix, and a revert-and-verify confirmation (temporarily reintroducing the bug to prove the regression test actually catches it) where practical.

## 1. Malformed targets / unexpected input

**Tried:** empty string, whitespace-only, single/multi control characters (NUL, raw bytes 0x01–0x03), embedded CR/LF (`"example.com\r\nHost: evil.com"`), unicode/IDN without punycode, overlong labels, leading/trailing hyphens, trailing dots, double dots.
**Result:** all rejected with clear errors except legitimate cases (trailing dot, incidental leading/trailing *pure* whitespace like a copy-pasted trailing newline — correctly trimmed, not a smuggling vector since nothing follows it). No panics.
**Evidence:** [internal/target/adversarial_test.go](../internal/target/adversarial_test.go) (`TestParse_ControlCharactersAndNullBytes`, `TestParse_TrimsIncidentalTrailingWhitespace`).

## 2. Extremely long input

**Tried:** domains up to 10,000,000 characters; a hostname built from 100,000 one-character labels (a different pathological shape than one huge label); a 500,000-character `--note` field.
**Result:** all rejected promptly (the 253-byte hostname-length check fires immediately) — the 10MB case completed in 0.58s with no hang. No memory blowup, no panic, no algorithmic-complexity issue (Go's `regexp` is RE2-based, immune to catastrophic backtracking, relevant here since title/fingerprint extraction runs regexes against untrusted response bodies elsewhere in the pipeline).
**Evidence:** [internal/target/adversarial_test.go](../internal/target/adversarial_test.go) (`TestParse_ExtremelyLongInput`, `TestParse_ManyLabels`).

## 3. Maliciously crafted hostnames/URLs — scope-bypass attempts (no bugs found; all verified safe)

This is the highest-value adversarial category for a security scanner, so it got the most attention. Every classic SSRF/scope-bypass encoding technique tried was already closed:

- **IPv4-mapped IPv6** (`::ffff:127.0.0.1`, `::ffff:7f00:1`, `::ffff:169.254.169.254`, fully-expanded forms): `net.ParseIP` normalizes these and `netip.Addr.Unmap()` correctly identifies the underlying loopback/link-local address, so the reserved-range deny-list catches all of them even under an explicit allow-everything (`0.0.0.0/0`, `::/0`) rule. New permanent test added: [internal/scope/scope_test.go](../internal/scope/scope_test.go) `TestReservedRanges_IPv4MappedIPv6BypassAttempt`.
- **Decimal, hex, and octal IP notation** (`2130706433`, `0x7f000001`, dotted-octal `0177.0.0.1`, `0251.0376.0251.0376`): the dotted-octal forms are caught by the same `looksLikeIPv4` fix from the Phase 1 acceptance pass (extended with explicit regression cases); the bare decimal/hex forms are accepted only as inert hostname *strings* that must then actually resolve via real DNS to do anything, and even if a (hypothetical, attacker-controlled) DNS record resolved such a name to a reserved address, `CheckResolved`'s unconditional reserved-range check on the resolved IP would still deny it — verified this defense-in-depth property holds regardless of the hostname's shape.
- **URL userinfo tricks** (`http://evil.com@allowed.example.com/` and the reverse): Go's `net/url` correctly extracts the real host per RFC 3986 in both directions — verified via CLI that the tool always operates on the actual host component, never the userinfo-looking prefix.
- **Exotic URL schemes** (`javascript:`, `data:`, `file://`, `gopher://...SET%20key%20value`): the first three are rejected outright (no `://` match, invalid hostname characters, or no host component); `gopher://127.0.0.1:6379/...` is reduced to a plain `127.0.0.1` host — sakanner never interprets the gopher-protocol-smuggling payload, it only ever does its own controlled TCP/HTTP against the extracted host, which is then correctly denied by the reserved-range check at scan time regardless of how it was originally spelled.
**Evidence:** [internal/target/target_test.go](../internal/target/target_test.go) (dotted-octal cases), [internal/scope/scope_test.go](../internal/scope/scope_test.go), manual CLI reproduction for the URL/scheme cases.

## 4. Unexpected redirects / out-of-scope redirects

**Tried:** a 3-hop redirect chain where hop 1 and hop 2 are in-scope and hop 3 is deliberately not, proving *every* hop is independently re-checked (not just the first redirect after the original request); a genuine A→B→A→B redirect loop, proving it terminates at `MaxRedirects` rather than looping until an external timeout or growing memory/request count unboundedly; malformed `Location` headers (empty, malformed URL, malformed IPv6 bracket, whitespace-only, embedded NUL byte).
**Result:** the multi-hop test confirms hop 2's handler fires exactly once and hop 3's handler never fires. The loop test produced exactly 6 requests for `MaxRedirects=5` (the correct bound: original + 5 hops), not an unbounded count. Malformed `Location` headers never panic or hang — Go's `net/http` simply doesn't follow an unparseable redirect and returns the raw response.
**Evidence:** [internal/http/adversarial_test.go](../internal/http/adversarial_test.go) (`TestProbe_MultiHopRedirect_EveryHopReChecked`, `TestProbe_RedirectLoop_BoundedByMaxRedirects`), [internal/http/malformed_redirect_test.go](../internal/http/malformed_redirect_test.go).

## 5. Invalid configuration

**Tried:** negative worker counts, negative rate limits, a string where an int is expected, an integer literal large enough to overflow `int64` (which wraps to a negative value — still correctly caught by the existing positivity check), a config file with a duplicate YAML key.
**Result:** all rejected with clear errors and exit code 1; no panic, no silent fallback to a dangerous default.

## 6. Concurrent scans / concurrent database access

**Tried:** 10 scans launched concurrently *within the same process* against the same `Store` (stressing Go-level goroutine/lock interaction, not just OS-level file locking); 5 fully separate OS processes writing to the same DB file simultaneously (re-verified after the schema change in finding #1, to confirm the new migration/reconciliation logic doesn't interfere with legitimate concurrent scans).
**Result:** all scans complete correctly within a 20s bound (no deadlock), each produces its own isolated, uncontaminated result set (verified by asserting each job has exactly the services it should, no cross-job leakage), and no job ID collisions occur under concurrent UUID generation. The 5-process test confirms the new PID-based crash-recovery check (finding #1) correctly leaves a legitimately-running concurrent scan's job untouched — it only reconciles jobs whose owning process is actually dead.
**Evidence:** [internal/orchestration/concurrent_scans_test.go](../internal/orchestration/concurrent_scans_test.go); manual 5-process CLI reproduction.

## 7. Duplicate targets / repeated scans

**Tried:** adding the identical target value twice (two distinct rows, since sakanner doesn't enforce value uniqueness) and scanning both; scanning the same target 30 times in a row sequentially, checking job-ID uniqueness and goroutine stability across the run.
**Result:** duplicates produce two independent, correctly-isolated scan jobs — no corruption. The repeated-scan test is what surfaced **finding #2** (the goroutine leak) — see below.
**Evidence:** [internal/orchestration/concurrent_scans_test.go](../internal/orchestration/concurrent_scans_test.go) (`TestRun_DuplicateTargetValue`), [internal/orchestration/repeated_scans_test.go](../internal/orchestration/repeated_scans_test.go).

## 8. Cancellation during different stages

**Tried:** cancellation during subdomain-enumeration/DNS (covered in the Phase 1 acceptance pass), and — new in this pass — cancellation specifically during **port scanning** (a CIDR target expanded to 64 hosts × 3 ports, paced by a real rate limiter so the stage takes deterministic, measurable time) and specifically during **HTTP probing** (a real server that holds the connection open for up to 3 seconds).
**Result:** both stage-specific cancellations return promptly (well under the 2-second bound in each test, against uncancelled runtimes of several seconds) and correctly report `status: cancelled` — confirming the authoritative `ctx.Err()` check added during the Phase 1 acceptance fix works uniformly across every stage, not just the one (discovery) that originally surfaced the bug.
**Evidence:** [internal/orchestration/cancellation_stages_test.go](../internal/orchestration/cancellation_stages_test.go).

## 9. Database errors / database corruption

**Tried:** (beyond the Phase 1 acceptance pass's invalid-path/read-only-directory cases) corrupting an existing valid DB file by overwriting bytes in the middle with `0xFF` garbage; pointing the DSN at a file that's plain text, not a SQLite database at all.
**Result:** both produce clear, distinct SQLite driver errors (`database disk image is malformed`, `file is not a database`) with exit code 1 — no crash, no silent misbehavior, no attempt to "repair" or misinterpret the corrupted data.

## 10. Interrupted process execution — FINDING (fixed)

**Tried:** `SIGINT` mid-scan (covered in the Phase 1 acceptance pass — confirmed still working); **`SIGKILL` mid-scan** (new: cannot be caught or handled gracefully by definition, so the question is what state is left behind and whether the *next* process can make sense of it).

**Root cause:** a `SIGKILL`'d scan's job row is left at `status: running` with no `finished_at`. Nothing in the original design distinguished "genuinely still running" from "the owning process no longer exists" — `scanner status` on that job would report `running` forever, and there was no way for an operator to know the scan was actually dead without independently checking process lists.

**Fix:** added a `pid` column to `scan_jobs` (migration `0002_scan_job_pid.sql`), populated automatically with `os.Getpid()` by the storage layer (not exposed through `models.ScanJob` — this is purely a persistence-layer concern). Every time a `Store` is opened (`sqlite.New`), a reconciliation pass (`reconcileInterruptedJobs`) finds every job still at `pending`/`running`, checks whether its recorded PID is still alive (`syscall.Kill(pid, 0)` on Unix — signal 0 performs no actual signaling, just an existence/permission check; a `!windows`/`windows` build-tag split keeps the package portable even though Ubuntu is the only supported target), and reconciles any with a dead PID to `failed` with an explanatory error. A job whose PID is still alive — including a legitimately-running concurrent scan from another process against the same DB — is left untouched.

**Known limitation, documented rather than engineered around:** PIDs can be reused by the OS. In the narrow window where a dead scanner's PID has already been recycled by an unrelated process before the next reconciliation runs, the job would be incorrectly left alone rather than reconciled. Given Phase 1's scope (a synchronous CLI, not a daemon) and typical scan durations, this is judged an acceptable residual risk rather than one worth a more elaborate mechanism (e.g. storing `(pid, process-start-time)` pairs and cross-checking `/proc`).

**Actual result (post-fix):** re-ran the exact `SIGKILL` reproduction from the Phase 1 acceptance pass — the interrupted job is correctly reconciled to `failed` with `error: interrupted: owning process (pid N) is no longer running; detected and reconciled on startup` on the very next command that opens the store. Re-verified the 5-concurrent-process scenario still works correctly (see item 6) — the fix doesn't cause false positives against genuinely concurrent scans.
**Evidence:** [internal/storage/sqlite/recovery_test.go](../internal/storage/sqlite/recovery_test.go) (`TestReconcileInterruptedJobs_DeadPIDIsReconciled`, `TestReconcileInterruptedJobs_LivePIDIsUntouched`); manual `SIGKILL` reproduction against the built binary, before and after the fix.

## 11. Data corruption — transaction atomicity under a real constraint violation

**Tried:** (beyond the Phase 1 acceptance pass's Go-level-error rollback test) a `WithTx` transaction that successfully writes two rows and then hits a **genuine SQLite-level primary-key collision** on a third insert — testing that a DB-level failure, not just an application-level `return err`, triggers a full rollback.
**Result:** neither of the two successfully-written-but-not-yet-committed rows survives the rollback; the pre-existing colliding row is untouched (not partially overwritten); the store remains fully usable immediately afterward.
**Evidence:** [internal/storage/sqlite/adversarial_test.go](../internal/storage/sqlite/adversarial_test.go).

## 12. Uncontrolled resource consumption

**Tried:** a single scan against 20,000 ports with `PortWorkers=50`, checking both wall-clock time and goroutine count before/after; goroutine-leak checks across 3 different scan outcomes (completed/denied/cancelled) and across 20 repeated cancelled scans.
**Result:** 20,000 ports scanned in 1.86s with goroutine count flat before/after (proving the Phase 1 acceptance pass's semaphore-based concurrency fix holds under real load, not just the smaller synthetic count used to originally catch that bug). The completed/denied/cancelled-outcome and repeated-cancellation goroutine tests found no leak — cancellation paths clean up correctly. The **repeated-*successful*-scan** test (item 7) is what found finding #2 (HTTP transport leak) — a leak that specifically only manifests when a real HTTP request actually succeeds and completes, which the port-scan-only and cancelled-scan tests don't exercise.
**Evidence:** [internal/orchestration/goroutine_leak_test.go](../internal/orchestration/goroutine_leak_test.go), [internal/orchestration/repeated_scans_test.go](../internal/orchestration/repeated_scans_test.go).

## 13. Goroutine/connection leak — FINDING (fixed)

**Root cause:** `internal/http/prober.go`'s `newClient` builds a brand-new `http.Transport` for every single probe attempt (each `Transport` is used for exactly one request — there's no reuse across probes). A zero-value `http.Transport`'s `IdleConnTimeout` is unbounded (`0` means "no limit", unlike `http.DefaultTransport`'s explicit 90-second value), so every successful connection was left open in that one-shot `Transport`'s idle pool — along with the background goroutine reading it — forever. Across repeated scans in a long-running process, this accumulates without bound: the adversarial test observed goroutine count grow from 4 to 94 after 30 repeated scans (~3 goroutines/connections per scan).

**Fix:** set `DisableKeepAlives: true` on the `Transport`. Since each `Transport` instance is discarded after its single request anyway, there is no reuse benefit to keep-alive pooling in the first place — disabling it is not a performance tradeoff, it's removing pointless bookkeeping that was actively leaking.

**Verification:** reverted the fix, confirmed the exact same test failure reproduces (`grew from 4 to 94`), restored the fix, confirmed it passes. This is a genuine leak that would have affected any real-world usage pattern involving more than a handful of successful HTTP probes in a single process lifetime — which is to say, almost any real scan of a domain with multiple live web services.
**Evidence:** [internal/orchestration/repeated_scans_test.go](../internal/orchestration/repeated_scans_test.go) (`TestRun_RepeatedScansOfSameTarget`); revert-and-verify performed directly against [internal/http/prober.go](../internal/http/prober.go).

## 14. Command injection / path traversal / SQL injection (no bugs found; verified safe)

- **SQL injection:** SQL metacharacter payloads (`'; DROP TABLE targets; --`, `' OR '1'='1`) injected via `--note` fields on both targets and scope rules are stored as inert literal string data — verified the `targets` table survives, subsequent inserts still work, and the payload text round-trips unchanged through `target list`. Confirms the parameterized-query design (established during the Phase 1 acceptance security review) holds under an actual attempted exploit, not just code inspection.
- **Command injection:** re-confirmed zero `os/exec` usage anywhere in production code (only in the e2e test harness, with fully hardcoded arguments).
- **Path traversal:** `--output` is operator-supplied on their own command line (same trust model as `curl -o`); not a privilege-boundary crossing. No new finding beyond the Phase 1 acceptance review.

---

## Summary of findings

| # | Category | Severity | Status |
|---|---|---|---|
| 1 | Incorrect scan state — SIGKILL'd/crashed scans stuck at "running" forever | Medium (operational/observability correctness, not a safety bypass) | **Fixed** |
| 2 | Goroutine/connection leak in HTTP prober (unbounded keep-alive pool per one-shot Transport) | Medium (resource exhaustion in long-running/repeated use) | **Fixed** |

No panics, race conditions, deadlocks, data corruption, or scope bypasses were found. Every scope-bypass technique attempted (IPv4-mapped IPv6, decimal/hex/octal IP notation, URL userinfo tricks, exotic URL schemes, multi-hop and looping redirects) was already correctly defended by the Phase 1 implementation, most of it a direct result of the fixes made during the Phase 1 acceptance pass.

Full regression suite after both fixes: **build clean, `go vet` clean, `gofmt` clean, `go test ./... -race` clean across 3 consecutive runs (no flakiness), 102 passing tests across 31 test files** (up from 83 tests / 22 files at the end of the Phase 1 acceptance pass).

## PHASE 1 STATUS

**PASS**

Both findings from this adversarial pass were genuine, fixed in place, covered by new regression tests (including revert-and-verify confirmation for both), and re-verified against the full suite plus targeted manual CLI reproduction. Per instructions, Phase 2 is not started.
