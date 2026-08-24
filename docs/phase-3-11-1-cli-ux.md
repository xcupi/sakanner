# Phase 3.11.1: CLI UX & Scope Management Hardening

## Purpose

This phase hardens `scanner scope` usability and fixes two real
defects discovered through actual CLI usage -- a silently-succeeding
delete of a nonexistent scope rule, and a race in database migration
startup under concurrent CLI invocations. It changes **no**
scope-matching semantics, precedence, or enforcement behavior: the
security model (default-deny, deny-overrides-allow, unmatched =
denied) is exactly as it was before this phase.

## Scope commands

### `scanner scope add <value>`

Unchanged interface: a positional `<value>` (domain, hostname, IP, or
CIDR), `--action allow|deny` (default `allow`), `--exact` (match only
the literal host, not subdomains), `--note`. Type (`exact_host`/
`domain_suffix`/`cidr`) is inferred from the value's shape, never a
separate flag -- this phase did not introduce a `--type`/`--value`
flag pair for `add`, since the existing positional-arg interface
already covers exactly the same cases and the task's own guidance was
"do not create duplicate interfaces unnecessarily."

```
scanner scope add example.com                          # allow example.com and its subdomains
scanner scope add --exact example.com                  # allow only example.com itself
scanner scope add --action deny internal.example.com   # explicitly exclude a subdomain
scanner scope add 127.0.0.1                             # allow a single IP
scanner scope add 203.0.113.0/24                        # allow a CIDR range
```

### `scanner scope list`

Unchanged columns (`ID ACTION TYPE VALUE NOTE`), unchanged full-UUID
IDs. **Deliberately not shortened**: the task permitted (but did not
require) visually shortening IDs "only if the full ID remains
available through another mechanism" and "do not make identifiers
ambiguous." Given `scope remove` now offers `--value` and interactive
selection (below) as ID-copy-free alternatives, shortening would add
representational risk (two different rules' shortened prefixes
colliding, or an operator misreading a truncated ID) for a discoverability
problem already solved a different way. An empty rule set now prints
an explicit `no scope rules configured (default-deny: no target is
authorized)` message instead of a bare, ambiguous blank table.

### `scanner scope remove`

Three ways to select which rule to remove -- task sections 2-4:

```
scanner scope remove <rule-id>       # canonical, unchanged form
scanner scope remove --value <v>     # remove by exact value match
scanner scope remove                 # interactive numbered selection
```

**By ID** (`removeScopeRuleByID` in `cmd/scanner/scope.go`): unchanged
canonical form. On a nonexistent ID, now returns a clear error and
exit code 4 (see "Exit codes") instead of the pre-3.11.1 bug where it
silently printed `removed scope rule <id>` with no actual mutation
(root cause: `internal/storage/sqlite/repos.go`'s `scopeRuleRepo.Delete`
never checked `RowsAffected` -- fixed to use the same
`checkRowsAffected` helper `scanJobRepo.Delete` already used).

**By value** (`removeScopeRuleByValue`): exact string match ONLY
against the value shown in `scope list`'s VALUE column -- never a
partial, prefix, or pattern match. Zero matches is an error (exit 4).
Exactly one match removes it. More than one match (e.g. an `allow` and
a `deny` rule sharing the same value) removes **nothing**: every
matching rule is listed with its ID, and the command exits non-zero
(exit 1 -- an ambiguous invocation is a usage error, not a "not
found") instructing the operator to supply an explicit ID instead.

**Interactive** (`removeScopeRuleInteractive`): lists every rule as
`N. <action> <type> <value>` (to stderr, so stdout stays clean for
scripts) and reads one line from stdin. An empty line, `q`, `cancel`,
or `quit` (case-insensitive) cancels with no mutation and exit 0 --
**never defaults to a destructive choice**. A non-numeric or
out-of-range entry is an error with no mutation. If stdin has **no
input available at all** (closed, `/dev/null`, or a script that piped
nothing to it -- the common non-interactive/CI case, and what an
unset `exec.Cmd.Stdin` reads as in Go), this is treated identically to
the missing-argument case below: a clear error, never a hang. Real
terminal use and non-interactive/scripted use share one code path with
no separate flag or environment-variable gate to keep synchronized --
the same input source (stdin) just behaves differently depending on
what's actually connected to it.

## Missing argument (task section 6)

```
$ scanner scope remove
error: scope rule ID is required

Usage:
  scanner scope remove <rule-id>

Examples:
  scanner scope remove <rule-id>
  scanner scope remove --value <value>
```

replaces Cobra's generic `accepts 1 arg(s), received 0` (the command
now accepts 0 or 1 positional args -- `cobra.MaximumNArgs(1)` -- with
this explicit message produced by application code, not Cobra's own
arg-count validator, whenever no id/`--value` is given and no
interactive input is available). Exit code 1.

## Duplicate rules (task section 9)

**Duplicates are allowed**, unchanged from before this phase:
`internal/storage/migrations/0001_init.sql`'s `scope_rules` table has
no uniqueness constraint beyond its `id` primary key, and `scope add`
never checks for an existing identical rule. Two rules with the exact
same value/type/action, each its own ID, coexist independently. This
is intentional, not an oversight left unfixed: it's exactly what makes
the "allow + deny on the same value" scenario possible at all (used
throughout this doc and the acceptance tests to exercise `--value`
ambiguity and precedence), and changing it would be a scope-semantics
change the task explicitly did not ask for. See
`TestScopeRuleCreate_DuplicatesAllowed` (storage-level) and
`TestScopeAdd_DuplicatesAllowed` (CLI-level).

## Remove safety (task section 10)

Removing one rule affects only that exact rule -- verified directly:
removing rule A (`allow example.com`) never removes rule B (`allow
api.example.com`); removing an `allow 127.0.0.1` rule never removes a
separate `deny 127.0.0.1` rule. Both are regression-tested at the
storage layer (`scope_rules_test.go`) and the CLI layer
(`e2e_scope_ux_test.go`).

## Help (task section 7)

`scanner scope --help`, `scope add --help`, `scope list --help`, and
`scope remove --help` each explain default-deny, allow-vs-deny,
the three rule types, and how to use that specific subcommand, with
concrete `Examples:` sections where the task asked for them.

## Shell completion (task sections 12-13)

Cobra's built-in `completion` command (bash/zsh/fish/powershell) was
already present; this phase verified it, not rebuilt it. Confirmed via
both the generated scripts themselves (`scanner completion bash|zsh|fish`,
each 200+ lines of real, non-empty shell script) and Cobra's hidden
`__complete` mechanism those scripts invoke at TAB-press time
(`scanner __complete <partial args>`), simulating real
`scanner <TAB>`, `scanner scope <TAB>`, `scanner scope add <TAB>`,
`scanner scope remove <TAB>`, `scanner scan <TAB>`, and
`scanner scan --<TAB>` -- every one returns the correct
subcommand/flag names.

**Completion is, and remains, pure static CLI metadata**: no command
in `cmd/scanner` registers a `ValidArgsFunction` or
`RegisterFlagCompletionFunc` (confirmed by grep), so Cobra's default
completion only ever enumerates command/subcommand names and flag
names from the command tree itself -- it never invokes a command's
`RunE`, never opens the database, never makes a network request, never
mutates scope, and never runs a scan. `TestShellCompletion_NeverMutatesOrScans`
confirms this directly: running `__complete` against a fresh, empty
database in every combination above leaves the scope-rule table
completely empty afterward. `scope remove <TAB>` deliberately does
NOT dynamically complete existing rule IDs (which would require
opening the database at completion time) -- the `--value`/interactive
mechanisms above already solve the "copying a UUID" discoverability
problem the task raised, and keeping completion itself simple and
side-effect-free was judged the safer choice given task section 13's
explicit "completion must be pure CLI metadata."

## Exit codes (task section 14)

Additive to the pre-existing convention (every command not listed
below still exits 1 on any error, unchanged):

| Code | Meaning | Where |
|---|---|---|
| 0 | Success | any command that completed without error |
| 1 | Invalid arguments / generic error | missing scope rule ID, ambiguous `--value`, malformed target, config/storage errors |
| 2 | Scope violation / scan failure | `scan <target>` reached `FAILED` (out-of-scope, invalid target, internal stage failure) -- unchanged from Phase 3.11 |
| 3 | Cancelled | `scan <target>` was cancelled/timed out -- unchanged from Phase 3.11 |
| 4 | Not found | `scope remove <id>`/`--value <v>` matched no rule (new in this phase) |

`cmd/scanner/exitcode.go`'s `exitCodeErr` mechanism (introduced in
Phase 3.11 for `scan`) is reused, not reinvented, for the new code 4.

## Error message quality and stdout/stderr (task sections 15-16)

Cobra's own automatic `Error: ...` print is now silenced
(`SilenceErrors: true` in `cmd/scanner/root.go`, alongside the
pre-existing `SilenceUsage: true`) -- previously every error printed
TWICE (once from Cobra, once from `main.go`'s own `"error:", err`),
which was barely noticeable for a one-line message but became a
jarring duplicated block once this phase introduced longer,
multi-line usage/example error text. Every error now prints exactly
once, to stderr, via `main.go`. Interactive prompts (the numbered rule
list, "Enter a number...") and the ambiguous-`--value` rule listing
also go to stderr -- UI chrome, not the command's actual result -- so
stdout stays predictable for scripts: a successful `scope remove`
prints only `removed scope rule <id>` to stdout; `scope list` prints
only the table.

## Real evidence integration -- unaffected

This phase touches no detection, correlation, risk, or evidence code.

## Concurrency and the migration race fix

A real, independently significant bug was found via task section 25's
required concurrency testing: several `scanner` processes starting up
concurrently against the SAME, brand-new (not-yet-migrated) database
file would race on schema migration -- each read "0 migrations
applied" via a plain, unlocked read before any of them held a write
lock, then all raced to apply migration 0001, producing "table already
exists"/"duplicate column" errors for every loser (observed: 4 of 10
concurrent `scanner scope add` invocations failed against a fresh
database). Fixed in `internal/storage/migrations.go`: the entire
read-then-apply sequence now runs inside one transaction opened with
`BEGIN IMMEDIATE` (SQLite's write lock acquired at the START of the
transaction, not deferred until the first write), so a concurrent
process's own `BEGIN IMMEDIATE` blocks (honoring the already-configured
`busy_timeout(5000)` pragma) until the first finishes, then correctly
sees the already-migrated state. This is a storage-layer reliability
fix, not a scope-semantics change -- it affects every CLI command's
startup, not scope commands specifically, since all of them call the
same `sqlite.New()`. See the acceptance report's "Issues found and
fixed" for the full root-cause writeup and revert-and-verify evidence.

## Backward compatibility (task section 27)

`scanner scope add`, `scanner scope list`, and
`scanner scope remove <rule-id>` all continue to work exactly as
before for every previously-valid invocation -- confirmed by the full
existing test suite passing unchanged, plus dedicated regression tests
for the canonical by-ID removal path. `scanner scan <target>` (Phase
3.11) is untouched by this phase.
