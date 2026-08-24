# Phase 3.32: Operator Workflow, Manual Testing & Validation Foundation

## 0. Scope discipline

No new vulnerability detector. This phase makes the EXISTING pipeline
(discovery → active detection → findings → correlation → chains →
report, all built in Phases 3.1-3.31) genuinely usable by a human
operator for authorized manual validation: finding inspection with
identity/chain context, a safe, read-only, informational curl-like
reproduction view, terminal-output hardening, and operator-facing
documentation (including an honest, executed validation against the
existing internal lab, plus correctly-written but unexecuted DVWA
instructions — see section 5).

## 1. Architecture review — answered with direct repository evidence

### Q1: Complete CLI workflow, target input → report

Traced directly through `cmd/scanner/*.go` and `internal/orchestrator`:

1. `scanner target add <value>` / `scanner scope add <host>` — operator
   defines the target and authorizes it (`cmd/scanner/target.go`,
   `scope.go`).
2. Optional authentication profile/identity configuration — via the
   YAML config file's `authentication.profiles`/`identities.identities`
   keys only. **Correction (self-caught during documentation writing):
   an earlier draft of this section claimed `scanner auth profiles
   add` exists — it does not.** Verified directly against
   `cmd/scanner/auth.go`/`identities.go`: both `scanner auth
   profiles list|show` and `scanner identities list|show` are
   READ-ONLY inspection commands only; there is no CLI command to
   create or edit either. This is a genuine, honestly-documented
   workflow gap (see `docs/operator-guide.md`'s own "Known gap"
   section), not an oversight fixed silently.
3. `scanner scan <target> [--identity <name>] [--profile web]` —
   drives `internal/orchestrator.Orchestrator.Run`: SCOPE → RECON →
   DISCOVERY → DETECTION → VERIFICATION → CORRELATION (Phase 3.8 dedup
   **and**, since Phase 3.31, chain generation + persistence) → RISK →
   EVIDENCE → FINALIZATION (`internal/orchestrator/model.go:30-49`).
4. `scanner findings --scan <id>` / `scanner findings show <id>` —
   raw, persisted findings (`cmd/scanner/findings.go`).
5. `scanner chains --scan <id>` / `scanner chains show <id> --scan <id>`
   — persisted chain candidates (Phase 3.31, `cmd/scanner/chains.go`).
6. `scanner report --scan <id> --format json|markdown` — a full report
   built from raw findings (`cmd/scanner/report.go`,
   `internal/reporting.Build`).

Every step above is a REAL, already-implemented command — none
invented for this phase.

### Q2: Which existing commands can already be used by an operator?

`target`, `scope` (`add`/`list`/`remove`), `scan`, `status`,
`findings` (+ `show`), `chains` (+ `show`, Phase 3.31), `report`,
`tools status`, `detectors list`, `profiles` (`list`/`show`),
`inputs`, `auth profiles` (+ `list`/`show`), `identities`
(+ `list`/`show`) — confirmed via `cmd/scanner/root.go`'s own
`root.AddCommand(...)` list, the single source of truth for what's
actually registered.

### Q3: What information is currently visible to the operator?

Checked directly against each command's own source, before this
phase's changes:

| Information | Visible today? | Where |
|---|---|---|
| Endpoints | Only via `report --format json` (`Report.Endpoints`) — no dedicated `endpoints` command | `internal/reporting.Report` |
| Parameters | Same — `report`'s own JSON output only | `internal/reporting.Report` |
| Requests | Embedded (redacted) inside each `Evidence.Content`'s own `Request` field | `detection.RequestResponseEvidence` |
| Responses | Embedded inside `Evidence.Content`'s own `Response`/`ResponseFragment` fields | Same |
| Findings | Yes — `findings`/`findings show` | `cmd/scanner/findings.go` |
| Evidence | Yes — `findings show`'s own "Evidence" section | Same |
| Identities | Yes — `identities list`/`show`, but **NOT surfaced on a finding itself** (`findings show` never printed `f.IdentityContext` before this phase — a real, now-fixed gap, see section 3) | `cmd/scanner/identities.go` vs. `findings.go` |
| Vulnerability chains | Yes — `chains`/`chains show` (Phase 3.31) |  `cmd/scanner/chains.go` |

### Q4: Can an operator determine, exactly, per finding?

Checked field-by-field against `findings show`'s own source
(`cmd/scanner/findings.go`, pre-Phase-3.32):

- **What URL was tested**: yes (`f.URL`).
- **What parameter was tested**: yes (`f.AffectedParameter`).
- **Which detector tested it**: yes (`f.DetectorID`).
- **Which mutation/payload was used**: PARTIALLY — present, but only
  BURIED inside `Evidence.Content`'s own raw JSON string (the
  `Payload`/`Parameter` fields of `detection.RequestResponseEvidence`),
  never surfaced as its own labeled line. A real, if minor, usability
  gap.
- **Which identity/session was used**: **NO** — `f.IdentityContext`
  exists on the model and is correctly populated by every detector,
  but `findings show` never printed it. A real, now-fixed gap.
- **What evidence caused the finding**: yes (`Evidence` section,
  though as raw JSON text, not parsed/pretty-printed).
- **Whether standalone or part of a chain**: **NO** — `chains show`
  (Phase 3.31) shows a chain's own participating findings, but there
  was no REVERSE lookup: given a finding ID, which chain(s) (if any)
  does it belong to? A real, now-fixed gap.

### A significant, related discovery: `evidence.ReproductionInfo` already exists but is completely disconnected

`internal/evidence/reproduction_build.go` (Phase 3.10) already builds
a structured `ReproductionInfo{Method, URL, Parameter, SafeTestValue,
ExpectedBehavior, ObservedBehavior, Level, Notes}` — but it operates on
`correlation.CanonicalFinding` (Phase 3.8's own dedup output), which
(per Phase 3.30/3.31's own established finding) is never persisted and
has no `IdentityContext` field at all. `cmd/scanner/report.go` never
reads `evidence.FindingPackage` either (confirmed, Phase 3.31's own
architecture review). **This means the entire Phase 3.10 reproduction-
info system has been unreachable from any CLI command since it was
built.** This phase does NOT resurrect/wire up that existing system
(doing so would require solving the SAME `CanonicalFinding` identity-
context-loss problem Phase 3.31 deliberately avoided by working from
raw findings instead) — it builds a NEW, smaller, CLI-facing
reproduction view directly from a `models.Finding`'s own ALREADY-
PERSISTED, ALREADY-REDACTED `Evidence.Content` (see section 4), while
reusing the SAME underlying redaction primitives
(`internal/evidence.IsSensitiveFieldName`/`RedactedPlaceholder`) the
Phase 3.10 system itself depends on — never a second, incompatible
redaction implementation.

### Q5: Smallest missing capabilities required for manual validation

Exactly three, all additive to `cmd/scanner/findings.go`/`chains.go`,
none requiring new storage or a new pipeline stage:

1. `IdentityContext` display on `findings show`.
2. Chain-membership lookup on `findings show` (query the existing,
   unmodified `store.Chains().Candidates(ctx, f.ScanID)` and filter
   client-side — no new storage method needed).
3. A `--curl` reproduction view on `findings show`, built directly
   from the finding's own stored, already-redacted evidence.

Plus one SECURITY hardening this review surfaced as necessary once
finding-derived text is printed more prominently to a terminal:
control-character/ANSI-escape sanitization on every finding-derived
string this phase's own commands print (see section "TERMINAL OUTPUT
SAFETY").

## 2. Manual validation workflow (task's own 7 steps, mapped to real commands)

1. **Operator defines an explicitly authorized target.**
   `scanner target add <value>`.
2. **Operator configures scope.** `scanner scope add <host>`.
3. **Operator optionally configures an identity.** Via the YAML config
   file's `authentication.profiles`/`identities.identities` keys
   (there is no CLI command to do this — see the Q1 correction above);
   `scanner auth profiles list|show` / `scanner identities list|show`
   (Phase 3.14/3.16, unmodified) let the operator inspect what's
   configured.
4. **Scanner performs discovery and active detection.**
   `scanner scan <target> [--identity <name>] [--profile web]` — the
   scanner NEVER performs destructive testing (every active detector's
   own established safety discipline: no destructive filesystem/shell
   operations, bounded payload sets, marker-based proof only — Phases
   3.19-3.29's own repeated, tested guarantee, unchanged).
5. **Scanner exposes enough evidence to manually reproduce/validate.**
   `scanner findings show <id> --curl` (this phase's own new
   capability) plus the existing Evidence section.
6. **Operator decides on further manual testing.** The generated
   curl-like command is INFORMATION ONLY — this phase's own CLI code
   never executes it (see section 4's own explicit non-execution
   guarantee, adversarially tested).
7. **Scanner records/reuses request context where appropriate.**
   Already true — every finding's own Evidence already IS the
   recorded request/response context; `--curl` is a NEW, more
   operator-readable VIEW of data the scanner already persists, not a
   new recording mechanism.

## 3. Request/finding inspection — what this phase adds

`findings show` gains (additive, nothing removed):

- An `Identity:` line (`f.IdentityContext`, or `(unauthenticated)`).
- A `Chain membership:` section, listing every chain candidate ID +
  status this finding participates in (or "not part of any chain
  candidate"), by filtering `store.Chains().Candidates(ctx,
  f.ScanID)` client-side — reusing Phase 3.31's own, unmodified
  storage method.
- A `--curl` flag producing a sanitized, informational reproduction
  command (section 4).

Every printed field (this command and `chains`/`chains show`,
retroactively hardened) is passed through a new
`sanitizeForTerminal` helper before being written to stdout — see
"TERMINAL OUTPUT SAFETY" below.

## 4. Manual reproduction support

`findings show <id> --curl` parses the finding's own most specific
`RequestResponseEvidence`-kind `Evidence.Content` (the LAST
non-baseline item, matching how every detector's own `finding()`
function already orders baseline-then-confirmed evidence) and
constructs:

```
curl -X <method> '<already-redacted URL from evidence>' [-d '<parameter>=<payload, redacted if sensitive>']
```

- **Preserves HTTP method**: yes, from the evidence's own `Request`
  field.
- **Preserves URL**: yes, verbatim from evidence (already redacted by
  `detection.MutationEvidence`'s own `redactedMutationRequestLine` —
  reused, not reimplemented).
- **Preserves relevant body** (form/JSON-location findings): the ONE
  tested parameter=payload pair the evidence itself recorded — NOT a
  full reconstruction of every other form field (a real, documented
  limitation: `detection.RequestResponseEvidence` never captured a
  full body to begin with, by the established, reviewed Phase 3.19
  design — "never embedding a raw body in the Request field").
- **Redacts secrets**: `m.Value` is ALREADY redacted at evidence-
  creation time (`MutationEvidence`) if `m.Parameter` is sensitive —
  this phase's own curl-builder does not need to (and does not)
  re-implement that check; it only ever prints what the STORED
  evidence already contains.
- **Never silently broadens scope**: the URL is copied verbatim from
  stored evidence, never re-derived, re-resolved, or pointed at a
  DIFFERENT host than what the finding itself already targeted.
- **Never automatically executed**: `--curl` only ever WRITES a string
  to stdout — no `os/exec`, no `net/http` call, anywhere in this
  phase's own new code (statically proven, see ADVERSARIAL section).
- **Shell-injection-safe**: every value is POSIX-single-quote-escaped
  (`'` → `'\''`) before being placed inside the generated command
  line, so a malicious finding/evidence value (however it got there)
  can never break out of its own quoted argument if an operator DOES
  choose to paste and run it.

## 5. DVWA / lab validation — environment-honest reporting

**This development environment has no Docker, PHP, or MySQL
available** (verified directly: `docker`, `php`, `mysql` are all
absent from `$PATH`). DVWA cannot be installed or executed in this
session. Per the task's own explicit instruction ("If a vulnerability
class cannot be demonstrated against the chosen lab, mark it honestly
as NOT DEMONSTRATED"), this phase does NOT claim DVWA was run —
instead:

1. **A correct, concrete, DVWA-specific operator runbook is written**
   (`docs/dvwa-validation.md`) — real `docker run` commands, real
   `scanner target`/`scope`/`auth profiles` invocations mapped to
   DVWA's own known login form and vulnerability pages, and an honest
   per-vulnerability-class mapping table (SQLi/reflected+stored XSS/
   command injection map cleanly to existing detectors; DVWA's own
   CSRF/file-upload/weak-session/insecure-captcha pages have NO
   corresponding detector in this codebase and are marked NOT
   DEMONSTRATED, not silently ignored). This runbook is WRITTEN,
   UNEXECUTED documentation for an operator who has Docker available
   — never claimed as tested by this session.
2. **Real, EXECUTED validation** is performed instead against
   `sakanner`'s own existing internal `lab` package — itself "a
   deliberately vulnerable lab" the task's own phrasing explicitly
   allows as an alternative to DVWA ("a controlled target such as
   DVWA or another explicitly authorized lab"). This is the SAME lab
   every prior phase's own acceptance testing has used, run through
   the COMPLETE operator workflow this phase adds (scan → findings →
   findings show --curl → chains), proving the workflow genuinely
   works end to end against a REAL, running target — not a synthetic
   unit test.

Repository buildability without any lab (DVWA or internal) is
unchanged and re-verified via the same lab/production independence
check every prior phase has run.

## TERMINAL OUTPUT SAFETY (a security hardening this review surfaced)

Every string a `models.Finding`/`chains.ChainCandidate`/
`chains.FindingRelation` carries ultimately originates from a
DETECTOR'S OWN interaction with a TARGET the operator does not fully
control (title/description text, evidence content, URLs). Before this
phase, `findings show`/`chains show`/`chains` (Phase 3.31) printed
every such field directly to stdout via `fmt.Fprintf`, with no
sanitization. A target response containing a raw ANSI escape sequence
or carriage-return-based terminal-manipulation sequence (e.g. to
overwrite a previously-printed line, or attempt to spoof a
prompt/hide following output) would be echoed VERBATIM to the
operator's own terminal. This phase adds `sanitizeForTerminal(s
string) string` (`cmd/scanner/sanitize.go`) — strips ASCII control
characters (0x00-0x1F excluding tab, 0x7F) and the ESC character
specifically (0x1B, the lead byte of every ANSI/terminal escape
sequence) — applied to every finding/chain-derived string this
phase's own commands print, including RETROACTIVELY to Phase 3.31's
own `chains`/`chains show` output (an additive hardening of existing
code, not a new command).
