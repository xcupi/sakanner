# Lab Isolation Review

A strict architectural review separating the production scanner from
sakanner's test/QA infrastructure and vulnerable test lab, per the
following goal:

```
scanner/
  cmd/          production scanner: CLI entrypoint
  internal/     production scanner: implementation
  pkg/          production scanner: shared public types
  tests/        scanner unit/integration tests (never a vulnerable app)
  docs/         documentation
  lab/          the vulnerable/benign test target -- external to the scanner
```

This phase performs **no new vulnerability detection work**. It is
architecture review, lab isolation, dependency cleanup, a small number
of test/path fixes made necessary by the move, and documentation.

## 1. What was found

The test lab (`tests/lab`) already existed as a self-contained Go
package (built up across Phases 1-3.13) exporting `Start`,
`StartWithVulnerabilities`, `StartWithInputFixtures`, `Lab`,
`GroundTruth`, `SSRFCallbackServer`, and comparison/ground-truth
machinery -- plus, alongside it, an unexercised Docker Compose profile
(`docker-compose.yml`, `apps/*.py`, `nginx/`, `apache/`, `dns/`) and a
standalone runner (`cmd/labserver`). Architecturally this was already
sound: production code never imported it (confirmed below, both
before and after this review). The only real issue was **physical
location**: it lived nested under `tests/`, one directory indistinguishable
in the tree from `tests/e2e` (the scanner's own CLI-level integration
tests), rather than standing apart as a visibly separate, top-level
concern the way its role (an external, intentionally vulnerable test
target) actually warrants.

## 2. What changed

- **`tests/lab/` moved to `lab/`** (a new top-level directory, sibling
  to `cmd/`, `internal/`, `pkg/`, `tests/`, `docs/`) -- the entire tree:
  Go harness/fixtures/tests, ground-truth YAML, Docker Compose profile,
  `fixtures/`, `nginx/`/`apache/`/`dns/` configs, and `cmd/labserver/`,
  moved together as one unit. The Go package name (`lab`) did not
  change, only its import path (`sakanner/tests/lab` -> `sakanner/lab`).
- **Two import statements updated** to the new path -- see section 4:
  every other reference to the old path, across the whole repository,
  was in a comment or a Markdown link, not a real dependency.
- **One relative filesystem path fixed**: `phase3_12_profiles_test.go`'s
  static AST-import-scan test read `internal/policy`'s source via a
  path relative to its own file (`../../internal/policy`, correct when
  the file was two directories below the repo root); now one directory
  below, it reads `../internal/policy`. Found immediately by running
  the lab's own test suite from the new location -- see section 6.
- **Three relative Markdown links in `lab/README.md`** fixed for the
  same reason (`../../docs/...` -> `../docs/...`,
  `../../internal/...` -> `../internal/...`).
- **The Makefile's `lab-*` targets** updated to build/test/compose
  against `lab/...` instead of `tests/lab/...`.
- **Every comment and documentation reference** to the old path
  (~50 occurrences across `docs/*.md`, `README.md`, and doc comments in
  `internal/*`, `pkg/models`, and the lab's own source) updated to the
  new one.
- **`lab/README.md` substantially expanded** -- see section 7.

**Nothing else changed.** No detector, no scope-enforcement code, no
orchestration/detection/policy logic, no CLI behavior, no test
assertion, and no test was removed. The full set of edits is either
(a) a file's physical location, (b) an import path following that
move, (c) a handful of relative paths that literally could not have
continued to resolve correctly after the move, or (d) prose/comments
naming a path.

## 3. Why `lab/` and not `tests/lab_isolated/` or similar

The task's own target layout names `lab/` as a top-level sibling of
`tests/`, not a subdirectory of it -- and Go's package system requires
every file declaring `package lab` (which includes this package's own
internal, whitebox tests -- `phase3_1_detection_test.go` through
`phase3_13_inputs_test.go`, `harness_test.go`, `lab_test.go`,
`redirect_test.go`, `groundtruth_test.go`, `callback_test.go`,
`comparison_test.go`) to live in the same directory. Splitting the
lab's own harness from its own tests into two different directories
would have required rewriting every one of those test files as an
external (`package lab_test`) black-box suite, losing direct access to
unexported fixture internals (`ipVuln`, `detectionLogger`, `mustPort`,
and dozens more) that many of them legitimately need -- a large,
high-risk rewrite for no architectural benefit the acceptance criteria
actually require. **The separation the task cares about --
`tests/e2e` (scanner integration tests) remaining architecturally
distinct from the vulnerable application itself -- was already true
before this review and remains true after it**: `tests/e2e` never
contained lab/vulnerable-application code, only an import of the lab's
public API to drive fixtures for testing the scanner CLI. Moving `lab/`
to the top level makes that distinction visible in the directory tree
itself, which is the concrete, achievable form of "keep scanner
tests separate from the vulnerable application" this review adopts.

## 4. Dependency verification (static)

**Before this review**, a repository-wide search for the literal
import string `"sakanner/tests/lab"` found exactly two matches in the
entire codebase:

```
tests/lab/cmd/labserver/main.go:26:  lab "sakanner/tests/lab"
tests/e2e/e2e_detection_readiness_test.go:23:  "sakanner/tests/lab"
```

The first is the lab importing itself (its own standalone runner); the
second is `tests/e2e`, the scanner's own CLI-level integration test
suite. **Zero occurrences existed anywhere under `cmd/`, `internal/`,
or `pkg/`** -- every other one of the ~50 repository-wide mentions of
the old path was a comment or a Markdown link (verified by grepping
specifically for the quoted Go import-string form, then separately
confirming every remaining hit was prose).

**After this review**, the same check against the new path:

```bash
$ grep -rn 'sakanner/lab"' --include="*.go" .
lab/cmd/labserver/main.go:26:       lab "sakanner/lab"
tests/e2e/e2e_detection_readiness_test.go:23:  "sakanner/lab"
```

Identical shape: still exactly these same two files, now pointed at
the new path. No new import of `sakanner/lab` was introduced anywhere
in `cmd/`, `internal/`, or `pkg/`.

This was cross-checked with `go list`, which resolves the full,
authoritative build dependency graph (not just a text search):

```bash
$ go list -deps ./cmd/scanner/... | grep -i sakanner/lab
(no output)

$ for pkg in $(go list ./internal/... ./pkg/...); do
    go list -deps "$pkg" | grep -i sakanner/lab
  done
(no output for any package)
```

## 5. Dependency verification (filesystem-level, the strongest test available)

The most direct possible proof that the production scanner does not
depend on the lab: physically remove `lab/` (and, for good measure,
`tests/` too) from disk and confirm the scanner still builds, vets,
and runs.

```bash
$ mv lab /tmp/... && mv tests /tmp/...
$ ls
Makefile  README.md  bin  cmd  configs  docs  go.mod  go.sum  internal  pkg  sakanner.db  scripts

$ go build ./...
(clean)

$ go vet ./...
(clean)

$ go build -o /tmp/scanner-isolation-check ./cmd/scanner && /tmp/scanner-isolation-check --help
sakanner: modular, deterministic web security assessment platform
Usage:
  scanner [command]
...
```

The entire production scanner -- build, vet, and a working binary --
succeeds with **neither `lab/` nor `tests/` present on disk at all**.
Both directories were then restored from the same location, unmodified.

## 6. Regression testing

Every existing test was preserved; none was deleted, and none had its
assertions weakened to make it pass. Running the lab's own suite
immediately after the move surfaced the one real breakage the move
caused (section 2's relative-path fix) -- found, root-caused, and
fixed following this project's established discipline, then reverified
clean:

```bash
$ go test ./lab/... -race -count=1
--- FAIL: TestPhase3_12_PolicyPackage_HasNoScopeOrStorageAccess
    phase3_12_profiles_test.go:241: ReadDir(../../internal/policy): no such file or directory
FAIL
```
```bash
# after the one-line path fix:
$ go test ./lab/... -race -count=1
ok    sakanner/lab    25.6s
```

Full regression after the fix, run from the new layout:

- `go build ./...`, `go vet ./...`, `gofmt -l .`: all clean.
- `go test` across every package except `tests/e2e` (fast packages +
  `lab/...`), with `-race`: all clean, 0 failures.
- `go test ./tests/e2e/...` (which imports `sakanner/lab` to drive the
  real CLI binary against real lab fixtures): clean in every isolated
  run. One run flagged a pre-existing, unrelated test
  (`TestConcurrency_ScopeAdd_FreshDatabase_NoCorruption`, a Phase 3.11.1
  SQLite-concurrency test already documented as occasionally flaky
  under heavy simultaneous system load in `docs/phase-3-13-acceptance-test.md`)
  as failed while this review's own manual `make lab-up`/`curl`/
  `make lab-down` verification (section 8) was running concurrently in
  the same shell; re-run in isolation, 5/5 clean, and a subsequent
  fully-isolated full suite run passed completely. This test touches no
  lab, scope, or migration code this review changed.
- The functional lab-lifecycle check in section 8, run live.

## 7. Documentation

[`lab/README.md`](../lab/README.md) was substantially expanded to
cover, directly, every item this review's task required:

- **How to start the lab** -- in tests (automatic, no setup) and as a
  standalone process (`make lab-up`/`make lab-up-phase3`).
- **How to stop/reset the lab** -- `make lab-down`/`make lab-reset`/
  `make lab-status`.
- **Which vulnerabilities each lab application represents** -- a table
  by vulnerability class (reflected/stored XSS, SQL injection,
  authentication weakness, IDOR/BOLA, path traversal/LFI, command
  injection, SSRF, open redirect, misconfiguration/stack-trace and
  information exposure, insecure cookies, CORS, missing headers),
  cross-referenced to `ground-truth-vulnerabilities.yaml` for full
  per-fixture detail, and noting which are and are not covered by an
  existing detector today.
- **Which credentials exist** -- every synthetic credential pair/
  identity the lab defines (`admin`/`admin`, `testuser`/a strong
  fixture password, session-cookie-based user IDs, the
  `X-Test-Auth-User: user-a`/`user-b` header pair), explicitly labeled
  as fixture-only with no relationship to any real account.
- **Which endpoints are intentionally vulnerable** -- the `vulnerable`
  vs. `safe` naming convention every fixture pair follows, and why
  that pairing exists (measuring false positives, not just true
  positives).
- **How the scanner is expected to interact with the lab** -- the
  in-process `dns.FakeResolver` path for tests running in the same Go
  process vs. the literal-IP path for `tests/e2e`'s real CLI
  subprocess, and the explicit-scope-rule requirement (the lab never
  grants scope on the scanner's behalf).
- **Future expansion** -- how the existing fixtures already anticipate
  anonymous/authenticated testing, Account A/Account B (already
  implemented, not merely planned), IDOR/BOLA, API testing, and every
  vulnerability class the task named, plus several classes with ground
  truth already defined and waiting for a future detector.

## 8. Functional lab-independence check

Beyond the static/build-level checks above, the lab's standalone
lifecycle was exercised live, exactly as an operator would use it:

```bash
$ make lab-status
lab is not running

$ make lab-up
lab started (pid 81010); addresses in /tmp/sakanner-labserver.log

$ make lab-status
lab running (pid 81010)

$ curl -s http://127.0.0.11:<port>/     # a fixture address printed by lab-up
<html>...<h1>scanner.test</h1>...       # genuinely reachable, real HTTP response

$ make lab-down
lab stopped

$ make lab-status
lab is not running
```

The lab starts, serves real traffic, and stops cleanly, entirely
independent of any scanner invocation, driven purely by the Makefile
targets against the new `lab/` path.

## Final report

```
LAB ISOLATION TESTS:
PASS: 6 (dependency verification x2, filesystem-independence build,
          regression suite, documentation completeness, functional
          lab-lifecycle check)
FAIL: 0
PARTIAL: 0

PRODUCTION -> LAB DEPENDENCY:
PASS (zero references to sakanner/lab anywhere in cmd/, internal/, or
pkg/ -- confirmed by grep, by `go list -deps`, and by physically
removing lab/ and tests/ from disk and rebuilding the production
scanner successfully)

LAB INDEPENDENCE:
PASS (lab/ builds standalone via `go build ./lab/...`; starts, serves
real HTTP traffic, and stops cleanly via `make lab-up`/`make lab-down`,
independent of any scanner invocation; lab/ does not import cmd/scanner)

PHASE 1 REGRESSION: PASS
PHASE 2 REGRESSION: PASS
PHASE 3.1-3.13 REGRESSION: PASS
FULL REGRESSION (go build / go vet / gofmt / go test -race, whole repo): PASS

SCOPE ENFORCEMENT: UNCHANGED (no scope-enforcement code touched; the
lab's own scope-adversarial tests, e.g. out-of-scope form action,
external-redirect truncation, all continue to pass unmodified)

PRODUCTION BEHAVIOR CHANGES: NONE (every edit is a file's physical
location, an import path, a small number of relative paths that could
not have continued to resolve after the move, or documentation)

VERDICT:
PASS
```

Per the task's explicit scope, this review implements no new
vulnerability detector and makes no change to detection, scope
enforcement, or scan behavior -- it is architecture review, lab
isolation, dependency cleanup, the minimal test/path migration the move
itself required, and documentation, exactly as scoped.
