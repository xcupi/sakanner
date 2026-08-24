# Phase 3.34: CLI & Operator UX Consistency Foundation

## Purpose

This phase makes the CLI self-documenting, consistent, and accurate for
a human operator using the CURRENT implementation. It is scoped
strictly to CLI/operator UX: **no detection heuristic, mutation
behavior, scope semantics, authentication/session semantics, or
chain/correlation semantics changed.** Every behavioral claim below
was checked against the current source (`cmd/scanner/detectors.go`'s
`buildProductionRegistry`, `internal/mutation`, `internal/parameters`,
`internal/crawler`) and, where a prior phase already reviewed the same
ground, `docs/phase-3-29-active-detection-coverage-review.md` and
`docs/phase-3-33-active-detection-coverage-review.md` — not assumed
from memory of building the codebase.

## 1. Architecture review (before any change)

`cmd/scanner` registers 13 top-level commands via `newRootCmd`
(`root.go`): `target`, `scope`, `scan`, `status`, `findings`, `chains`,
`report`, `tools`, `detectors`, `profiles`, `inputs`, `auth`,
`identities` (plus Cobra's own `completion`/`help`). Config load and
storage open happen in `PersistentPreRunE`; `SilenceUsage`/
`SilenceErrors` are already set (Phase 3.11.1) so every error prints
exactly once, to stderr, via `main.go`.

**What was already good** (Phase 3.11.1/3.14/3.16, unchanged by this
phase): `scanner scope add/list/remove` has a full `Long`, `Example`,
and a hand-written missing-argument error
(`missingScopeRuleIDError`); `scanner auth`/`scanner identities` have
thorough `Long` text explaining the config-file-only workflow and
explicitly document why profile/identity NAME completion is not
implemented (config load requires `PersistentPreRunE`, which Cobra's
`__complete` machinery never runs). These were used as the reference
standard the rest of the CLI is brought up to in this phase.

**What was stale or inconsistent** (found by diffing every `--help`
output against current source and current Phase 3.x docs — see
Section 2 for the full list): a materially false capability claim in
`scan --help`, a stale command description on `findings`, ten commands
still producing Cobra's generic `accepts 1 arg(s), received 0` instead
of the Phase 3.11.1-established clear-error pattern, three commands
(`findings`/`chains`/`report`) with a bare `--scan is required` and no
`Usage:`/example, several commands with no `Example` at all (including
`scan` itself — the single most important command), no root-level
`Long` overview, and no completion for seven finite/static flag
values that safely could have it (detector IDs, severities, chain
statuses, report formats, input locations/provenances, scope actions).

## 2. Help text accuracy (task section 1)

### 2.1 `scan --help` — the primary defect this phase fixes

The pre-3.34 `Long` text said:

> "Vulnerability DETECTION only ever runs against query-location
> inputs (a URL query parameter, or a GET form's fields, which submit
> the same way); form/JSON/path inputs are discovered and reportable
> but do not yet feed any detector — see
> docs/phase-3-13-parameter-discovery.md 'Detector compatibility.'"

This was accurate when Phase 3.13 wrote it, but **Phase 3.21 (form
mutation) and Phase 3.23 (path parameters) closed that gap**, and the
help text was never updated — confirmed directly against
`internal/mutation/mutate.go` (`applyQuery`/`applyForm`/`applyPath`/
`applyJSON` all implemented and wired into `Mutate`'s switch) and
`docs/phase-3-29-active-detection-coverage-review.md` section 3's
input/mutation coverage matrix, itself re-verified by
`docs/phase-3-33-active-detection-coverage-review.md` section 3 (a
later, independent review): every one of the 8 active detectors
mutates query, form, and path locations alike, proven per-detector by
each one's own form-location and path-location lab tests.

`scan --help` now says, accurately:

- Every enabled detector tests **query, form, and path-parameter
  inputs alike** (the pre-3.34 claim that form/path don't feed
  detectors is gone).
- **JSON request-body inputs** are supported by the mutation engine
  (`applyJSON` works, `BuildTargets` will emit a JSON target) but
  **not yet discovered by the live crawler**, which only ever captures
  a JSON RESPONSE body, never a REQUEST body — this specific
  limitation was true before 3.34 and remains true; the help text now
  says so precisely instead of lumping it in with form/path, which are
  NOT limited this way.
- **Header/cookie inputs are not yet discovered or tested at all** —
  this is new information the pre-3.34 help never mentioned; confirmed
  via `internal/parameters`/`internal/discovery` never producing a
  `header`/`cookie`-location `Parameter`, and no detector's
  `Eligible()` ever accepting one (Phase 3.33 section 3).
- Which detectors are **enabled by default** (XSS-reflected, SQLi,
  command injection, SSTI — 7 of 14 registered instances) vs.
  **registered but disabled** (SSRF, path traversal, open redirect —
  need operator configuration this build doesn't ship) vs.
  **conditional** (idor-active — needs `--authz-identity`), sourced
  directly from `buildProductionRegistry` in `cmd/scanner/detectors.go`.
- A pointer to `scanner detectors list` for the exact, current
  registry, rather than enumerating IDs that could drift out of sync
  with the registry again.

This is backed by `TestScanHelp_DoesNotClaimFormJSONPathAreUndetected`
and `TestScanHelp_DescribesDetectionCoverage`
(`tests/e2e/e2e_cli_ux_test.go`).

### 2.2 `findings` command description — stale

Root-level listing showed: `findings   List findings for a scan (empty
until a Phase 3.x detector is registered)` — false since Phase 3.7
registered real detectors (`xss-reflected`, `sqli`,
`command-injection`), over 20 phases ago. Changed to `List findings
discovered by a scan`, with a new `Long` explaining that findings
require a `web`/`deep` profile scan. Verified by
`TestFindingsShort_NotStale`.

### 2.3 `detectors list`'s empty-registry message

The (structurally unreachable today, since `buildProductionRegistry`
always registers 14 detector instances) empty-list fallback message
cited "Phase 3.1 ships the detection framework only" — stale even as a
defensive fallback. Simplified to a plain `no detectors registered`
with no version-specific claim.

### 2.4 Every other command's `--help` was audited and found accurate

`scope`, `target` (see 2.5), `auth`, `identities`, `profiles`, `tools`,
`report`, `status`, `inputs`, `findings show`, `chains`/`chains show`
all describe real, currently-implemented behavior — no other false
claims were found. Where text was correct but had zero `Example`
section (see Section 4), that's a completeness gap, not an accuracy
one.

### 2.5 `target`/`scan --target <id>` clarified as the legacy path

`target`'s own `--help` had no `Long` text at all before this phase —
an operator had no way to learn from `--help` alone that `scanner
target add` + `scanner scan --target <id>` is a **different, older,
recon-only** path than `scanner scan <target>` (the code's own
comments already call it "Original, unchanged... (Phase 1)" and
"legacy path" — `scan.go`'s `runFullScan` doc comment). Added a `Long`
to `target` explaining this explicitly, including that a normal scan
does not need `target add` at all.

## 3. CLI help structure (task section 2)

`scan --help`'s `Long` was previously one ~900-word undifferentiated
prose block. Restructured into scannable sections with the same
information density, following this file's own suggested shape:
`Two invocation forms:` / `Profiles:` / `Detection coverage:` /
`Authentication:` / `See also:`, each a short paragraph or aligned
bullet list, with a separate `Examples:` block (Cobra's own
`Example` field, rendered under its own heading). No line was forced
onto one long unwrapped string — normal terminal wrapping is used
throughout. `root.go` gained a `Long` for the first time: a 5-step
"Typical workflow" plus a command-groups summary, so `scanner --help`
alone orients a new operator instead of just listing 13 alphabetized
commands with one-line descriptions.

## 4. Missing-argument UX (task section 3)

### 4.1 The defect, confirmed by direct execution

Before this phase:

```
$ scanner scope add
error: accepts 1 arg(s), received 0
```

...and the identical Cobra-generic message for `target add`,
`findings show`, `chains show`, `status`, `inputs`, `auth profiles
show`, `identities show`, `profiles show` (all used bare
`cobra.ExactArgs(1)`), plus a distinct but equally terse defect for
the three `--scan`-flag commands:

```
$ scanner findings
error: --scan is required
```

(`findings`/`chains`/`report` never went through Cobra's arg
validator at all — `--scan` is a flag, checked manually in `RunE`.)

### 4.2 The fix

New file `cmd/scanner/args.go`:

- `singleRequiredArg(subject string, examples ...string)
  cobra.PositionalArgs` — a validator for any command taking exactly
  one required positional argument. Missing → `missingArgError`
  (below). Too many → a parallel, equally clear message (not just
  Cobra's own count mismatch).
- `missingArgError(cmd, subject, examples)` — the shared formatter:
  `"<subject> is required"`, a `Usage:` block (from `cmd.UseLine()`,
  so it can never drift from the command's own registered `Use`
  string), an optional `Examples:` block, and a `Run '<path> --help'
  for more information.` trailer.
- `requiredFlagError(cmd, subject, examples...)` — the same formatter
  for a missing required `--flag` (findings/chains/report's `--scan`).

Applied to `scope add`, `target add`, `findings show`, `chains show`,
`status`, `inputs`, `auth profiles show`, `identities show`, `profiles
show` (all via `singleRequiredArg`, replacing `cobra.ExactArgs(1)`),
`findings`/`chains`/`report` (via `requiredFlagError`, replacing the
bare `fmt.Errorf("--scan is required")`), and `scan`'s own
either/or `<target>`-or-`--target` check (via `missingArgError`
directly, since it isn't a single positional argument).

Example, after:

```
$ scanner scope add
error: a value (domain, host, IP, or CIDR) is required

Usage:
  scanner scope add <value> [flags]

Examples:
  scanner scope add example.com
  scanner scope add 203.0.113.10

Run 'scanner scope add --help' for more information.
```

Every one of the ten missing-argument cases and all three
missing-`--scan` cases is regression-tested in
`tests/e2e/e2e_cli_ux_test.go`
(`TestMissingRequiredArgument_ClearErrorAcrossCommands`,
`TestMissingRequiredFlag_ClearErrorAcrossCommands`,
`TestTooManyArgs_AlsoGetsAClearError`), driven against the real built
binary. `scope remove`'s own pre-existing, hand-written
`missingScopeRuleIDError` (Phase 3.11.1, which has its own richer
three-way branching — by ID / by `--value` / interactively) was left
as-is rather than forced through the new generic helper, since it
already met the same bar and rewriting a working, tested,
already-consistent implementation was not the smallest coherent
change.

## 5. Command consistency (task section 4)

Audited every registered command family for argument conventions,
flag naming, error message tone, capitalization, and singular/plural
naming. Positional arguments are used exactly where the task
recommends — where the argument identifies the primary object
(`scope add <value>`, `scope remove <id>`, `target add <value>`,
`status <scan-id>`, `inputs <scan-id>`, `findings show <finding-id>`,
`chains show <chain-candidate-id>`, `auth profiles show <name>`,
`identities show <name>`, `profiles show <name>`) — and flags are used
for optional behavior (`--profile`, `--auth-profile`, `--identity`,
`--exact`, `--action`, `--severity`, `--detector`, `--status`,
`--location`, `--provenance`, `--format`). No positional argument was
converted to a flag or vice versa.

**One real, deliberately preserved inconsistency, documented rather
than changed**: `findings`/`chains`/`report` gate on `--scan <id>` (a
flag), while `inputs <scan-id>`/`status <scan-id>` take the scan ID as
a positional argument. This predates Phase 3.34 (present since Phase
3.1/3.8/3.30) and is a genuine naming-convention inconsistency by the
task's own definition. It was **not** changed: `findings --scan`/
`chains --scan`/`report --scan` are documented, scripted-against
surfaces (`docs/operator-guide.md` Scenarios 4/6/7 all use `--scan`)
and the task explicitly scopes changes to cases "where backward
compatibility can be preserved" — converting an established required
flag to a positional argument (or adding a second, parallel positional
form) is exactly the kind of syntax churn the task's Section 4 warns
against ("do not create duplicate interfaces unnecessarily", echoing
`docs/phase-3-11-1-cli-ux.md`'s identical language for `scope add`).
This is called out explicitly here rather than silently left
undocumented.

## 6. Shell completion (task section 5)

**Pre-existing** (Phase 3.11.1/3.12): Cobra's built-in `completion`
command; structural subcommand/flag-name completion for the whole
command tree (zero-I/O, no `ValidArgsFunction` needed); dynamic
completion of `--profile`/`profiles show <name>` values via
`profileNameCompletion` (`policy.DefaultRegistry()` is a pure,
in-memory, zero-I/O function).

**New in this phase** — the same "static, zero-I/O enum" pattern,
extended to seven more flags that were previously plain strings with
no completion at all:

| Command | Flag | Source |
|---|---|---|
| `findings` | `--detector` | `productionRegistry().List()` (same zero-I/O function `detectors list` itself calls) |
| `findings` | `--severity` | fixed literal list (`info`/`low`/`medium`/`high`/`critical`) |
| `chains` | `--status` | fixed literal list (`POTENTIAL`/`SUPPORTED`/`CONFIRMED`) |
| `report` | `--format` | fixed literal list (`json`/`markdown`) |
| `inputs` | `--location` | fixed literal list (`query`/`path`/`form`/`json`/`header`/`cookie`) |
| `inputs` | `--provenance` | fixed literal list (`REQUEST_INPUT`/`RESPONSE_FIELD`) |
| `scope add` | `--action` | fixed literal list (`allow`/`deny`) |

New shared helpers in `args.go`: `staticChoiceCompletion(choices...)`
(a generic closed-set prefix-filter completer) and
`detectorIDCompletion` (wraps it around the live detector registry).
Both are provably zero-I/O: `detectorIDCompletion` calls
`productionRegistry()`, the exact same pure function `scanner
detectors list` calls, which touches no config, no database, no
network. `TestShellCompletion_StaticEnums_NeverTouchDatabase` proves
this directly — it points completion at a config whose database file
does not exist yet, runs `findings --detector`/`chains --status`
completion, and asserts the file still does not exist afterward (if
either completion touched storage, `sqlite.New` would have
created/migrated it as a side effect).

**Explicitly NOT completed, unchanged from Phase 3.11.1/3.14/3.16, and
why**: authentication profile names, identity names, scope rule IDs,
finding IDs, chain candidate IDs, scan IDs, and target values. Every
one of these requires either config access (profile/identity names —
Cobra's `__complete` never runs `PersistentPreRunE`, confirmed
empirically in `auth.go`'s doc comment) or database access (rule/
finding/chain/scan IDs), or is inherently free-form/sensitive (target
values, URLs). None of these were touched in this phase; the same
architectural reason applies to all of them uniformly.

## 7. Authentication UX (task section 6)

`scanner auth`'s workflow (config → `authentication.profiles` →
environment variables → `scan --auth-profile <name>`) was already
fully and clearly documented in `auth.go`'s `Long` text (Phase 3.14)
and further clarified in `docs/operator-guide.md` Scenario 2. This
phase did not change it — it was already architecturally correct and
task section 6 explicitly says "If the current configuration workflow
is already architecturally correct, keep it." Verified directly:
`auth profiles list`/`show`, `identities list`/`show` never print a
credential value — every credential-bearing field goes through
`Profile.Redacted()`/`auth.RedactedPlaceholder`, confirmed by reading
`auth.go`'s/`identities.go`'s `printSecretStatus` helper and by
`TestOperatorWorkflow_NoRawSecretsInInspectionOrCurl` (pre-existing,
still passing). The only change in this area was adding
`singleRequiredArg` to `auth profiles show <name>`/`identities show
<name>` (Section 4) and a small clarifying pointer chain in
`root.go`'s new `Long` (`config → authentication.profiles →
environment variables → scan --auth-profile <name>`, matching the
task's own suggested diagram almost verbatim).

## 8. Identity UX (task section unlabeled, folded into 6/7)

Same finding as Section 7: `identities.go`'s existing `Long` text
already explained the Identity-vs-Profile model, credential isolation,
and the `--identity`/`--authz-identity` relationship accurately
(Phase 3.16/3.24). Unchanged except for the missing-argument fix on
`identities show` (Section 4).

## 9. Operator examples (task section 7)

Added or verified `Example` blocks (every line executable against the
current binary, using the same `203.0.113.10`/`example.com`
convention `docs/operator-guide.md` already established) on: `scan`
(previously had **none** at all), `target add`/`list`, `findings`/
`findings show`, `chains`/`chains show`, `report`, `status`, `inputs`,
`auth profiles show`, `identities show`, `profiles list`/`show`,
`detectors list`, `tools status`. `scope add`/`remove`/`list` already
had `Example` blocks from Phase 3.11.1 and were left unchanged.

## 10. Documentation consistency (task section 8)

- `docs/operator-guide.md`: added an "Other useful commands" section
  (`report`, `detectors list`, `profiles list`/`show`, `tools status`)
  — these commands existed but were never mentioned anywhere in the
  guide's 8 scenarios.
- `README.md`: found **substantially stale** — frozen at a
  "Phase 2 complete; vulnerability detection not implemented yet"
  description (dated to this project's Phase 2 completion), actively
  contradicting the current build's 14 registered detectors. Updated
  the top summary paragraph, the `## Usage` example block (previously
  only showed the legacy `target add` + `scan --target <id>` path and
  said findings are "empty in Phase 1 — no detection yet"), and the
  `## Roadmap` section's false "not yet implemented" claim. **Not**
  rewritten in full — the `## Architecture` package-tree listing and
  the historical Phase 1/2 sections were left alone; see Section 13
  (Remaining limitations) for why a full README pass is out of scope
  here.
- Historical phase reports (`docs/phase-3-*-acceptance-test.md`,
  `docs/phase-3-13-parameter-discovery.md`, etc.) were **not**
  modified — per the task's explicit instruction, these remain
  historical snapshots of what was true when each phase shipped; only
  `scan --help`'s own citation was changed to point to the later,
  still-accurate `docs/phase-3-29-active-detection-coverage-review.md`
  instead of the now-superseded `docs/phase-3-13-...` claim.

## 11. Security requirements (task section 9)

- **No credentials in output**: unchanged mechanism
  (`Profile.Redacted()`), unaffected by this phase's changes; verified
  by the pre-existing `TestOperatorWorkflow_NoRawSecretsInInspectionOrCurl`
  still passing.
- **No target-controlled ANSI/control-character injection in help/
  completion**: every string this phase added to `--help`/error/
  completion output is a compile-time literal (subject names, Usage
  lines derived from `cmd.UseLine()`/`cmd.CommandPath()`, which are
  themselves static Cobra command-tree metadata, never operator input)
  — no new code path interpolates a target, finding, or other
  operator-supplied value into help/error text. `sanitizeForTerminal`
  (pre-existing, `cmd/scanner/sanitize.go`) still guards every place
  that DOES print potentially target-controlled data (finding/chain
  detail views), unchanged by this phase.
- **No shell execution of generated reproduction commands**: unchanged
  (`buildCurlReproduction`, `reproduction.go`), untouched by this
  phase.
- **No scope bypass**: no scope-checking code was touched.
- **No change to authentication/identity isolation**: no
  authentication/session code was touched; only `--help`/error text
  and `Args` validators around already-existing auth/identity
  inspection commands.
- **No unsafe shell escaping**: no shell invocation was added.
- **No accidental network activity from help/completion**: every new
  completion function (`staticChoiceCompletion`, `detectorIDCompletion`)
  is a pure, in-memory closure over a fixed list or the same zero-I/O
  `productionRegistry()` call `detectors list` already makes — proven
  by `TestShellCompletion_StaticEnums_NeverTouchDatabase` (Section 6)
  and `TestHelpOutput_NeverReferencesLiveTargetOrCredential` (asserts
  `--help` works, and works identically, pointed at a nonexistent
  config path — i.e., it does no I/O of its own).

## 12. Testing performed

- `gofmt -l .` — clean.
- `go vet ./...` — clean.
- `go build ./...` — clean.
- Full suite: see `docs/phase-3-34-acceptance-test.md` for exact
  pass/fail counts and the test-infrastructure finding around
  `sakanner/tests/e2e`'s real (not deadlocked) runtime exceeding
  `go test`'s 10-minute default per-package timeout.
- New file `tests/e2e/e2e_cli_ux_test.go` (18 test functions, several
  table-driven with multiple subtests) covers every claim in this
  document against the real built binary: help-text accuracy (no
  stale claims, required accurate claims present), missing-argument/
  missing-flag UX (exact commands listed in Section 4), the
  too-many-arguments case, all seven new completions, and the
  completion/help zero-I/O security property.
- No existing test was weakened, deleted, or had its assertions
  loosened. `grep` confirmed no existing test depended on any of the
  stale strings this phase changed (`"accepts 1 arg"`, `"--scan is
  required"` as a complete message, `"Phase 3.x detector is
  registered"`, `"Phase 3.1 ships the detection framework only"`).

## 13. Remaining limitations (not fixed in this phase, and why)

- **README.md's `## Architecture` section and historical phase
  enumeration were not brought current.** Fixing the CLI-facing
  contradictions (top summary, Usage example, Roadmap) was in scope;
  a full architectural rewrite (package-by-package description,
  enumerating all ~34 phases) is a documentation-maintenance task
  larger than "CLI/operator UX" and was deliberately left for a future
  pass rather than attempted incompletely here.
- **The `findings`/`chains`/`report` `--scan` (flag) vs. `inputs`/
  `status` `<scan-id>` (positional) inconsistency is preserved, not
  fixed** — see Section 5 for the backward-compatibility rationale.
- **Profile/identity/rule/finding/chain/scan-ID shell completion
  remains unimplemented** — architectural limitation (Cobra completion
  never runs `PersistentPreRunE`), unchanged from Phase 3.11.1/3.14/
  3.16, not attempted here (task section 5 permits documenting this
  rather than fabricating unsafe completion).
- **No CLI command exists to create/edit an authentication profile or
  identity** — a genuine, pre-existing, already-documented workflow
  gap (`docs/operator-guide.md` "Known gap"), out of scope for a
  UX-consistency phase that must not add new capabilities.
- **`sakanner/tests/e2e`'s real wall-clock runtime exceeds `go test`'s
  10-minute default per-package timeout** — see the acceptance report
  for the full investigation; this is a pre-existing test-suite-size
  characteristic (confirmed unrelated to this phase's own additions,
  which add under 2 seconds total), not a defect this phase
  introduced or was asked to fix, but it is reported here because it
  materially affects how "run the full test suite" must be executed
  going forward (`-timeout 40m` or larger, not the default).
