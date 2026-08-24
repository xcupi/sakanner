# Phase 1 Clean-Environment Verification

Performed 2026-08-20, immediately after the Phase 1 acceptance and adversarial passes. Goal: determine the project's real runtime/build dependencies, verify it actually builds and runs from a genuinely clean state (not just "works on the dev machine"), and fix any documentation or environment-assumption gaps found along the way.

## Starting state: no installation documentation existed

Before this pass, the repository had **no README, no INSTALL doc, and an empty `scripts/` directory** — "follow the documented installation instructions" had nothing to follow. This is itself the first and largest finding. **Fixed:** added [README.md](../README.md) covering requirements, build, test, configuration, full CLI usage, and architecture — then this entire verification pass was performed *by literally following what that README says*, so the README is verified accurate, not just written and assumed correct.

## Dependency determination

Determined by reading `go.mod`/`go.sum`, inspecting the source for cgo/syscall/platform-specific usage, and empirically testing each claim rather than assuming it:

| Dependency | How it was determined | Verified how |
|---|---|---|
| Go toolchain | `go.mod`'s `go` directive | See "go.mod version" finding below — empirically corrected via `go mod tidy`, not assumed |
| C compiler / cgo | Storage backend is `modernc.org/sqlite` (pure Go) | Built and ran with `CGO_ENABLED=0` explicitly — produced a **statically-linked** binary (`file` confirms "statically linked") |
| OS/platform | `internal/storage/sqlite/recovery_unix.go` uses `syscall.Kill` (Unix-only) behind `//go:build !windows`, with a `recovery_windows.go` no-op fallback | Read the build tags directly; this project targets Ubuntu, so this is a non-issue for the intended platform, but is now explicitly documented rather than silently discovered by a Windows user |
| Network access | Module dependencies must be downloaded from their sources at least once | Observed `go: downloading ...` for all 23 direct+indirect dependencies during the clean build |
| System packages/services | None found | No `os/exec` in production code, no reliance on external CLI tools, no database server, no other service dependency |
| Go standard library version features | Grepped for `slices`/`maps`/`cmp`/iterators (none used) and `atomic.Int64` (used once, requires only Go 1.19) | Confirmed the code itself needs nothing newer than Go 1.19; see next finding for why the declared floor was nonetheless higher |

## Finding: `go.mod` pinned an overly-specific Go version — FIXED

`go.mod` declared `go 1.26.7` — the exact patch version that happened to be installed on the original development machine (an artifact of `go mod init`, not a real requirement). This is a real undocumented environment assumption: it implies any clean environment needs *that exact or later* version, when the code itself uses nothing beyond Go 1.19 stdlib features.

**Fix, verified rather than guessed:** set the directive to a conservative `go 1.22` (Go 1.22 also happens to be where per-iteration loop variable semantics changed — relevant since the codebase wasn't audited against relying on that either way) and ran `go mod tidy`. Tooling — not guesswork — determined the *actual* floor: **`go mod tidy` auto-corrected it to `go 1.25.0`**, meaning a transitive dependency genuinely requires that version. This is now the accurate, tooling-verified minimum, a meaningful relaxation from the original `1.26.7` pin. Full build and the complete race-detected test suite were re-run afterward and are clean.

## Clean-environment procedure

A true "new machine" can't be provisioned inside this sandbox, so the closest practical approximation was used, isolating every piece of state a build/run could depend on:

1. **Fresh source tree**: `rsync`'d the project into a new `mktemp -d` directory, excluding only `bin/` (a build artifact, not source) and the local editor's `.claude/` config directory (not part of the project) — everything else, including `go.mod`/`go.sum`/`README.md` as they exist right now, came along unmodified.
2. **Isolated `GOCACHE`**, **isolated `GOPATH`** (so no pre-warmed build cache or pre-downloaded module cache from this machine's normal Go environment could mask a missing dependency), and **isolated `HOME`** (so no pre-existing `~/.config`, shell profile, or other host state could leak in).
3. Every step below ran with those three variables pointed at fresh, empty directories, in the fresh source copy — not the developer's working tree.
4. All temporary directories were removed after the run; nothing was left behind on the host, and no host-level packages, PATH entries, or configuration were modified. The only file writes were to the disposable clean-copy temp directories.

## Results

### 1. Build — PASS

```
GOCACHE=<fresh> GOPATH=<fresh> go build -o bin/scanner ./cmd/scanner
```
Downloaded all 23 dependencies from scratch (`go: downloading ...` for each), compiled cleanly, exit 0. Produced a working `bin/scanner` binary.

### 2. Test suite — PASS

```
GOCACHE=<fresh> GOPATH=<fresh> go test ./...           # exit 0, all packages ok
GOCACHE=<fresh> GOPATH=<fresh> go test ./... -race      # exit 0, all packages ok, no races
```
Includes `tests/e2e`, which itself invokes `go build` internally (via `exec.Command`) to build a fresh copy of the binary for CLI-driven testing — this nested build also succeeded correctly against the isolated caches, confirming the test suite doesn't implicitly depend on anything already being built or cached from a prior step.

### 3. Run the scanner — PASS

`./bin/scanner --help` ran correctly with an isolated `HOME`, printing the full command tree.

### 4. Verify database initialization — PASS

Before any command: no database file exists. After the *first* command (`target list`) against a config pointing at a nonexistent DB path: a `114688`-byte SQLite file is created automatically. Directly inspected with `sqlite3`/Python (bypassing the application entirely, to verify independent of the tool's own self-report):
- All 10 expected tables present: `assets, findings, hosts, http_services, scan_jobs, schema_migrations, scope_rules, services, targets, technologies`.
- `schema_migrations` shows both migrations applied in order: `(1, '0001_init.sql')`, `(2, '0002_scan_job_pid.sql')` — confirming the crash-recovery `pid` column (added during the adversarial pass) is included in a from-scratch database, not just databases upgraded from an older version.
- `PRAGMA journal_mode` reports `wal`, confirming WAL mode is active on a freshly-created database as designed.

### 5. Verify CLI functionality — PASS

Ran the full documented workflow from the README, in order, in the clean environment: `target add` (IP target, with `--note`) → `target list` → `scope add --action allow` → `scope list` → started a local `python3 -m http.server` on loopback as a scan target → `scan --target <id> --ports <port>` → `status <scan-id>` → `findings --scan <scan-id>`. Every command succeeded (exit 0) with output matching what the Phase 1 acceptance/adversarial passes established as correct behavior (1 asset, 1 host, 1 service, 1 HTTP service discovered; `status: completed`; `no findings` as expected for Phase 1).

### 6. Verify report generation — PASS

- `report --scan <id> --format markdown` (to stdout): produced a complete, correctly-formatted report — summary table, Assets/Open Services/HTTP Services sections, Findings section with the Phase-1-appropriate explanatory note.
- `report --scan <id> --format json --output report.json`: wrote a 2,051-byte file; independently parsed with Python's `json` module (not the tool's own code) to confirm it's syntactically valid JSON and that `job.status == "completed"`.

## Other environment assumptions checked and found not to be issues

- **No hardcoded filesystem paths**: grepped all production Go source for `/home`, `/usr`, `/etc`, `/var`, `/tmp/` string literals — none found. The default database path (`sakanner.db`) is a relative path resolved against the current working directory, as documented.
- **No hidden service dependencies**: no database server, no message queue, no external API — SQLite is embedded, and nothing else is required.
- **`scripts/` is intentionally empty** in Phase 1 (a placeholder for future build/dev tooling per the original architecture skeleton) — not a missing-file bug.

## Summary

| Check | Result |
|---|---|
| Documented install instructions existed | **FAIL initially → FIXED** (README.md added) |
| Dependencies fully determined | PASS — Go toolchain (now accurately pinned), pure-Go SQLite (no cgo, verified with `CGO_ENABLED=0`), network access for module download, no other system packages/services |
| Build from scratch (clean caches) | PASS |
| Test suite (clean caches, incl. `-race`) | PASS |
| Run the scanner | PASS |
| Database initialization | PASS (schema, migrations, WAL mode all correct on a from-scratch DB) |
| CLI functionality | PASS (full documented workflow exercised end-to-end) |
| Report generation | PASS (both Markdown and JSON, JSON independently validated) |
| Undocumented dependency/assumption found | Yes — the `go.mod` version pin was needlessly narrow (fixed: `1.26.7` → tooling-verified `1.25.0`) |
| Host system modified | No — only disposable `mktemp -d` directories were used and all were removed afterward |

## PHASE 1 STATUS

**PASS**

The project builds, tests, and runs correctly from a genuinely clean state using only its declared dependencies. The one real documentation/environment gap found (no install instructions; an unnecessarily narrow Go version pin) was fixed and the fix was itself verified by the same clean-environment procedure, not just asserted. Per instructions, Phase 2 is not started.
