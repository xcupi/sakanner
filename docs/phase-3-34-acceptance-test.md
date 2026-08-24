# Phase 3.34 Acceptance Test: CLI & Operator UX Consistency Foundation

## Scope

CLI/operator UX only, per the phase instructions: no detector, mutation
heuristic, scope semantic, authentication/session semantic, or chain/
correlation semantic was changed. This report distinguishes defects
found in existing production code, stale documentation, test-authoring
notes, intentional UX decisions, and remaining limitations, and does
not inflate PASS claims.

## 1. Defects found in existing production code (fixed)

1. **`scan --help` false capability claim.** Claimed form/JSON/path
   inputs "do not yet feed any detector" — false since Phase 3.21
   (form) and Phase 3.23 (path). Fixed; see
   `docs/phase-3-34-cli-ux.md` section 2.1 for the full before/after
   and evidence trail.
2. **`findings` command description stale.** Claimed findings are
   "empty until a Phase 3.x detector is registered" — false since
   Phase 3.7. Fixed.
3. **Ten commands used Cobra's generic, unhelpful missing-argument
   error** (`scope add`, `target add`, `findings show`, `chains show`,
   `status`, `inputs`, `auth profiles show`, `identities show`,
   `profiles show`, `scan`'s target-or-`--target` check). Fixed via a
   new shared helper (`cmd/scanner/args.go`).
4. **Three commands (`findings`/`chains`/`report`) had a bare `--scan
   is required` with no `Usage:`/example.** Fixed via the same helper.
5. **`scan` had zero `Example` entries** despite being the most
   important command. Fixed.
6. **`detectors list`'s empty-registry fallback message cited a
   long-obsolete Phase 3.1 claim** (structurally unreachable today,
   but misleading if it were ever hit). Fixed.
7. **`target`'s own `--help` had no explanation that it is a legacy,
   recon-only path distinct from `scan <target>`.** Fixed.
8. **`root`'s `--help` had no overview at all** — just an alphabetized
   command list with one-line descriptions, no workflow orientation.
   Fixed.

None of these are behavioral/functional defects — all seven are
documentation-in-code (`--help` text) defects. No detection,
mutation, scope, auth, or chain code was touched to fix any of them.

## 2. Stale documentation found and fixed

- `docs/operator-guide.md`: never mentioned `report`/`detectors list`/
  `profiles list`/`show`/`tools status` in any of its 8 scenarios.
  Added an "Other useful commands" section.
- `README.md`: **materially stale** — top summary, `## Usage` example
  block, and `## Roadmap` section all still described a
  Phase-2-complete, no-vulnerability-detection build. Fixed the
  CLI-facing parts (see `docs/phase-3-34-cli-ux.md` section 10); the
  `## Architecture` section and full historical phase enumeration were
  deliberately left alone (see Section 5, Remaining limitations).
- Historical phase reports (`docs/phase-3-*.md`) were **not**
  modified, per instruction — they remain accurate snapshots of their
  own phase's state. Only `scan --help`'s own citation was redirected
  from the now-superseded `docs/phase-3-13-parameter-discovery.md`
  claim to the current `docs/phase-3-29-active-detection-coverage-review.md`.

## 3. Test-authoring notes

- The new test file `tests/e2e/e2e_cli_ux_test.go` initially used
  `exec.Command("test", "-e", path)` to check file existence in
  `TestShellCompletion_StaticEnums_NeverTouchDatabase`; replaced with
  `os.Stat` before this file was ever run, since relying on an
  external `test` binary was an unnecessary and less portable
  dependency for a Go test. No incorrect assertion ever shipped.
- No other test-authoring mistakes were found. Every new test was run
  and observed to actually exercise the real built binary (not a
  mocked command tree) before being counted as passing.

## 4. Intentional UX decisions (not defects)

- **`findings`/`chains`/`report`'s `--scan` flag vs. `inputs`/
  `status`'s `<scan-id>` positional argument inconsistency was left
  unchanged.** This predates Phase 3.34, is used throughout
  `docs/operator-guide.md`'s scripted examples, and the task's own
  Section 4 instructs to change syntax only where backward
  compatibility can be preserved without churn — converting an
  established, documented flag to a positional argument is exactly
  the kind of duplicate-interface churn Phase 3.11.1 already declined
  for the analogous `scope add` case. Documented explicitly rather
  than silently left inconsistent.
- **`scope remove`'s existing hand-written missing-argument error
  (`missingScopeRuleIDError`, Phase 3.11.1) was left as its own
  implementation**, not forced through the new generic
  `singleRequiredArg`/`missingArgError` helpers, because its three-way
  branching (by ID / by `--value` / interactively, with a distinct
  non-interactive-stdin case) doesn't fit the generic single-positional-
  argument shape, and it already meets the same UX bar the new helper
  establishes elsewhere.
- **No new CLI command was added to create/edit authentication
  profiles or identities.** This is a real, already-documented gap
  (`docs/operator-guide.md` "Known gap"); adding one would be a new
  capability, out of scope for a UX-consistency phase.
- **Detector-name/severity/status/format/location/provenance/action
  shell completion was added; profile/identity-name, scope-rule-ID,
  finding-ID, chain-ID, and scan-ID completion was deliberately NOT
  added** — the former are static, zero-I/O enums; the latter all
  require config or database access that Cobra's completion machinery
  cannot perform (established architectural limitation, Phase
  3.11.1/3.14/3.16, reconfirmed here rather than assumed).

## 5. Remaining limitations

See `docs/phase-3-34-cli-ux.md` section 13 for the full list with
rationale. Summary:

- `README.md`'s `## Architecture` section and historical phase
  enumeration are not current (out of scope for this phase).
- The `--scan` flag vs. `<scan-id>` positional inconsistency remains.
- Profile/identity/rule/finding/chain/scan-ID shell completion remains
  unimplemented (architectural limitation, not attempted).
- No CLI command exists to create/edit auth profiles or identities.
- `sakanner/tests/e2e`'s real wall-clock runtime (~29.5 minutes,
  confirmed by direct execution, Section 7 below) exceeds `go test`'s
  10-minute default per-package timeout. This is a pre-existing
  test-suite-size characteristic, not a regression this phase caused
  (see Section 7) — but it means `go test ./...` with no `-timeout`
  flag will report a false `FAIL` on `sakanner/tests/e2e` going
  forward unless run with `-timeout 40m` or larger (or the package run
  separately with its own generous timeout). This is flagged here as
  a genuine operational finding for whoever next runs this suite.

## 6. Regression verification (task section 11)

- **Existing command syntax remains compatible**: every previously-
  valid invocation of every command still works identically — the
  only observable change for a valid invocation is cosmetically richer
  `--help`/`Example` text; no flag was renamed, no positional argument
  was moved, no default value changed.
- **Scan/scope/auth/identity/detector/chain behavior unchanged**: no
  file under `internal/` was modified in this phase. `git diff`-
  equivalent confirmation: every changed file is under `cmd/scanner/`,
  `tests/e2e/`, `docs/`, or `README.md` (repo has no `.git` — verified
  by directly diffing the touched-file list against `internal/`,
  `pkg/`, `lab/` — none appear).
- **Output security intact**: `sanitizeForTerminal` and
  `Profile.Redacted()` are unchanged; new help/error/completion text
  never interpolates operator- or target-supplied data (Section 11 of
  the design doc).
- Every existing test in `tests/e2e` (24 pre-existing files) passed
  unchanged, alongside the 11 new top-level test functions in
  `e2e_cli_ux_test.go` — see Section 7.

## 7. Test execution evidence

All commands run from the repository root against the real module.

```
gofmt -l .                    # clean, no output
go vet ./...                  # clean, no output
go build ./...                # clean
```

**Full suite, sequential (`-p 1`, to avoid `sakanner/lab`'s
cross-process port-18999 coordination lock racing against a
concurrently-scheduled `sakanner/tests/e2e` test binary — see the note
below):**

```
go test ./... -p 1 -timeout 25m
```
Every package except `sakanner/tests/e2e` passed within this run;
`sakanner/tests/e2e` alone did not finish inside 25 minutes (was still
making forward progress — a new test had started 27s before the alarm
fired, not stuck). Re-run in isolation with a larger budget:

```
go test ./tests/e2e/... -timeout 50m
→ ok  	sakanner/tests/e2e	1768.285s   (~29.5 minutes, PASS)
```

**Race suite** (`internal/*`, `cmd/scanner`, `lab`, `pkg/*` —
`tests/e2e` excluded from `-race`, see rationale below):

```
go test $(go list ./... | grep -v '/tests/e2e') -race -timeout 20m
→ every package "ok", including sakanner/cmd/scanner (1.055s) and
  sakanner/lab (174.611s, race-instrumented)
```

*Why `tests/e2e` is excluded from the race run*: this phase added no
concurrency of any kind (no new goroutines — `args.go`'s new
functions are plain synchronous string formatting and Cobra
callbacks). `tests/e2e` itself drives the real `scanner` binary as a
**separate subprocess** built by `buildBinary(t)` without `-race`, so
running `go test -race` on the `tests/e2e` package would instrument
only the test-harness code, not the `cmd/scanner` logic under test —
low value for a ~30-minute-per-run cost. The actual concurrency-
sensitive code (`internal/orchestration`, `internal/storage/sqlite`,
`internal/detection`, `lab`'s own real servers) IS covered by the race
run above and passed clean, including `TestConcurrency_*`-style tests
inside those packages.

**Test counts** (top-level Go test functions, via `go test ./... -list
'.*'`, module-wide):

```
TOTAL: 1907 top-level test functions across every package
  (subtests via t.Run are not separately counted here, consistent
  with this project's own established convention — see
  docs/phase-2-acceptance-test.md's "top-level + subtests" framing)
new in this phase: 11 top-level functions in
  tests/e2e/e2e_cli_ux_test.go (several table-driven, expanding to
  21 additional subtests: 10 in TestMissingRequiredArgument_..., 3 in
  TestMissingRequiredFlag_..., 7 in TestShellCompletion_StaticEnums,
  1 in TestDetectorsListHelp_ListsRealDetectors's implicit checks)
```

Every one of the 1907 top-level tests passed in the runs above (zero
`FAIL` lines in either the full sequential run's per-package output or
the race run's output; the one `FAIL` observed during
troubleshooting — see below — was conclusively traced to test
infrastructure, not product code, and did not recur once fixed).

**Test-infrastructure incident during this phase's own verification
(not a product defect)**: an earlier verification attempt killed a
`go test ./tests/e2e/... -timeout 40m` process by sending `SIGTERM` to
its parent PID only; the compiled `e2e.test` child process (which had
already started `sakanner/lab`'s real HTTP servers, including one
bound to the fixed coordination port `127.0.0.1:18999`) survived as an
orphan and continued holding that port, causing every subsequent test
run that touched `sakanner/lab` to fail with `timed out waiting for
the cross-process lab setup lock on 127.0.0.1:18999` for up to 60s per
affected test. Identified via `ss -ltnp`/`ps aux` (found the orphaned
`e2e.test` process still listening on port 18999), fixed by killing
the orphan directly; the subsequent clean re-run showed zero lock
contention. Documented here per the task's "do not hide limitations"
instruction, even though it is self-inflicted test-tooling noise, not
a bug in `sakanner` itself — no code change resulted from it.

## 8. Final architectural review

1. **Is every major CLI command discoverable?** Yes — `scanner --help`
   now lists all 13 command groups with a workflow overview; every
   subcommand has its own `--help`.
2. **Does every required argument have useful error UX?** Yes for
   every command audited (Section 1 item 3/4); `scope remove` already
   had it (Phase 3.11.1); no command was found still using Cobra's raw
   generic message after this phase.
3. **Are examples executable?** Yes — every `Example` line uses real
   flags/subcommands/target syntax this binary accepts (verified by
   direct execution against the built binary during this phase;
   placeholder values like `<scan-id>`/`<finding-id>` follow the
   pre-existing `docs/operator-guide.md`/Phase 3.11.1 convention of
   illustrative-but-syntactically-real IDs).
4. **Is `scan --help` accurate against the current implementation?**
   Yes — verified against `cmd/scanner/detectors.go`'s
   `buildProductionRegistry` and `docs/phase-3-29-active-detection-coverage-review.md`/
   `docs/phase-3-33-active-detection-coverage-review.md` directly (Section
   1 item 1 above).
5. **Are authentication instructions accurate?** Yes — unchanged, was
   already correct (Phase 3.14), reconfirmed by direct reading of
   `auth.go` and the still-passing
   `TestOperatorWorkflow_NoRawSecretsInInspectionOrCurl`.
6. **Are identity instructions accurate?** Yes — same finding as
   authentication (Phase 3.16, unchanged).
7. **Are findings/chains workflows documented accurately?** Yes —
   `findings`/`chains` `--help` now include `Long`/`Example` text
   describing the actual workflow; `docs/operator-guide.md` Scenarios
   4-6 already covered this correctly and are now cross-referenced
   from `--help` output too.
8. **Is shell completion accurately described?** Yes — this report and
   `docs/phase-3-34-cli-ux.md` section 6 state exactly what is and is
   not completed, and why, with no overclaiming.
9. **Can help/completion execute without unintended network
   activity?** Yes — verified directly
   (`TestShellCompletion_StaticEnums_NeverTouchDatabase`,
   `TestHelpOutput_NeverReferencesLiveTargetOrCredential`); no help or
   completion path in this codebase performs a network request.
10. **Can credentials ever appear in help/error/completion output?**
    No — verified directly; no new code path in this phase touches a
    credential value, and the existing redaction mechanism
    (`Profile.Redacted()`) is unchanged and still covers every place a
    profile/identity is displayed.
11. **Are historical phase documents preserved?** Yes — zero
    `docs/phase-3-{1..33}-*.md` files were modified.
12. **Is operator documentation internally consistent?** Yes for the
    parts touched (`--help`, `docs/operator-guide.md`, `README.md`'s
    CLI-facing sections); the one known remaining inconsistency
    (`README.md`'s `## Architecture` section) is explicitly flagged,
    not hidden.
13. **Was any scanner/detector behavior changed accidentally?** No —
    confirmed by file-list review (Section 6) and by the full
    regression suite passing unchanged.
14. **Were all existing regressions preserved (i.e., no new
    regressions introduced)?** Yes — full suite (1907 top-level tests)
    and the targeted race suite both passed with zero failures
    attributable to product code.

---

PHASE 3.34 CLI & OPERATOR UX FOUNDATION

TOTAL TESTS: 1907 (top-level; +11 new top-level / +21 new subtests in this phase)
PASS: 1907
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

HELP ACCURACY: PASS
CLI CONSISTENCY: PASS (one pre-existing, deliberately preserved inconsistency documented — Section 4)
MISSING-ARGUMENT UX: PASS
AUTH UX: PASS (already correct; unchanged)
IDENTITY UX: PASS (already correct; unchanged)
COMPLETION: PASS (7 new static-enum completions added; ID/name completion remains architecturally NOT IMPLEMENTED, documented)
SECURITY: PASS
DOCUMENTATION: PASS (README.md's Architecture section remains a known, flagged gap — see Remaining limitations)
REGRESSION: PASS
RACE: PASS (scope: internal/*, cmd/scanner, lab, pkg/* — tests/e2e excluded from -race by deliberate, documented decision; no concurrency was added by this phase)

SECURITY ISSUES: 0
RELIABILITY ISSUES: 1 (sakanner/tests/e2e's real runtime exceeds go test's 10-minute default per-package timeout — pre-existing test-suite-size characteristic, not caused by this phase; see Section 5/7)
PERFORMANCE ISSUES: 0

REMAINING LIMITATIONS:
- README.md's Architecture section and full historical-phase enumeration were not brought current (out of scope for a CLI/operator-UX phase).
- findings/chains/report's --scan flag vs. inputs/status's <scan-id> positional argument inconsistency is preserved, not fixed (backward-compatibility rationale in Section 4).
- Profile/identity-name, scope-rule-ID, finding-ID, chain-ID, and scan-ID shell completion remain unimplemented (architectural: Cobra completion cannot run PersistentPreRunE, so no config/database access is possible at completion time).
- No CLI command exists to create/edit an authentication profile or identity (pre-existing, already-documented gap; out of scope — would be a new capability).
- sakanner/tests/e2e's real wall-clock runtime (~29.5 minutes) exceeds go test's default per-package timeout; must be run with an explicit -timeout 40m (or larger) going forward.

PHASE 3.34 VERDICT: PASS
