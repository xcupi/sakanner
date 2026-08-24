# Phase 3.12: Scan Profiles & Detection Policy Engine

## 1. Why profiles exist

Before this phase, every scan behavior decision (crawl or not, how
deep, how many pages, whether detection runs) was a scattering of
individual `internal/config.Config` fields an operator had to
understand and set correctly together to get a coherent result. There
was no single, named, reviewable statement of "how aggressive should
this scan be" -- and no way for an operator (or a script) to say
"run reconnaissance only" versus "run a full vulnerability sweep"
without knowing which specific config keys correspond to that intent.

A **scan profile** is a fixed, named bundle of crawler, detection, and
resource settings that answers that question in one word. Selecting a
profile is a single, auditable decision (`--profile web`) instead of a
handful of easy-to-get-wrong config edits, and the profile itself is
part of the permanent scan record (`Result.Profile`), so a report can
always answer "how aggressively was this target actually examined."

Profiles are a **configuration convenience layered on top of the
existing pipeline**, not a new execution engine. They do not add scope
authority, they do not add new detectors, and "deep" does not mean
exploitation -- see section 11.

## 2. Available profiles

Three built-in profiles ship in this phase, defined in
`internal/policy/registry.go`:

| Profile | Crawler | Detection | Resource class |
|---|---|---|---|
| `recon` | disabled | disabled | low |
| `web` | enabled, depth=2, pages=20 | enabled | medium |
| `deep` | enabled, depth=4, pages=75 | enabled | high |

Run `scanner profiles list` for this table live, or
`scanner profiles show <name>` for one profile's full detail
(including its concurrency and timeout settings).

There is no runtime registration mechanism -- `internal/policy.Registry`
has no `Register` method, only `Get`/`List`/`Names` over a fixed,
package-level slice (`builtinProfiles`). A new profile can only be
added by editing that slice and shipping a new build, which is a
deliberate choice: profiles are meant to be a small, fully reviewed,
fully tested set, not an open-ended user-configurable list (see
section 12, "Profile overrides").

## 3. Default profile: `recon`

**`scanner scan <target>` with no `--profile` flag and no
`crawler.enabled: true` in config defaults to the `recon` profile** --
crawler disabled, detection disabled.

This is a deliberate choice, not an incidental one: sakanner has
always defaulted to `crawler.enabled: false` (Phase 1's own config
default). Choosing anything more active than `recon` as the implicit
default would have meant "installing profiles" silently made every
existing operator's plain `scanner scan <target>` invocation more
aggressive than it was yesterday -- exactly what the task driving this
phase explicitly forbids. `recon` is the one profile whose behavior is
identical, in terms of actual network activity, to what an operator
with a bare, unmodified config already got before this phase existed.

See section 7 for the full precedence rule this interacts with --
an operator who already has `crawler.enabled: true` in their config
and passes no `--profile` flag is NOT downgraded to `recon`; explicit
configuration continues to be honored exactly as before.

## 4. Profile behavior in detail

### `recon`

Crawling and vulnerability detection are both **structurally disabled**
for the whole scan -- `internal/orchestrator.Options.DetectionDisabled`
is set to `true`, which makes `Orchestrator.Run` skip the DETECTION
stage's Executor/Engine construction entirely (see section 10). Recon
(hosts, ports, HTTP services, technologies) runs exactly as it always
has; nothing about `recon` changes SCOPE, RECON, or DISCOVERY.

### `web`

Crawling is enabled with the same depth/page bounds this codebase's
own pre-existing `crawler.max_depth`/`crawler.max_pages` defaults
already used (2 / 20) -- `web` does not invent new numbers where
already-reviewed defaults exist. Detection runs against whatever
parameterized endpoints the crawl discovers, using the detectors
`cmd/scanner`'s `productionRegistry()` already enables by default
(`xssreflected`, `sqli`, `cmdinjection`) -- Phase 3.12 adds no new
detector types and does not change which detectors are enabled.

### `deep`

Deeper, but still explicitly bounded, crawling (depth=4, pages=75 vs
`web`'s 2/20) and more detection concurrency (10 vs 5 in-flight
detector/target pairs). **`deep` is not exploitation** and does not
run any detector `web` does not also run -- the difference is
resource depth (how much of the target's surface gets examined), not
new capability. See section 11 for the explicit safety limitations
this implies.

## 5. Resource limits

Every profile defines a finite `CrawlMaxDepth`, `CrawlMaxPages`,
`DetectionConcurrency`, `ScanTimeout`, and `StageTimeout` --
`internal/policy/registry.go`'s `builtinProfiles` literal. None of
these are ever zero/unbounded for a profile that has crawling or
detection enabled; `recon`'s own values are simply irrelevant (crawling
and detection are off), not left undefined.

| Profile | Max depth | Max pages | Detection concurrency | Scan timeout | Stage timeout |
|---|---|---|---|---|---|
| `recon` | 0 | 0 | 1 | 5m | 2m |
| `web` | 2 | 20 | 5 | 10m | 5m |
| `deep` | 4 | 75 | 10 | 20m | 10m |

`deep`'s limits are meaningfully larger than `web`'s, but still a
small, finite multiple -- not "as many as exist." Section
"DEEP PROFILE" of the acceptance report demonstrates this directly
against a 30-page test fixture: `deep` discovers more eligible targets
than `web`, but strictly fewer than the fixture actually contains.

## 6. Scope semantics

**Profiles have no access to scope at all.** `internal/policy` imports
nothing from `internal/scope`, `internal/storage`, `internal/orchestration`,
or `internal/orchestrator` -- verified structurally by
`TestPhase3_12_PolicyPackage_HasNoScopeOrStorageAccess`
(`lab/phase3_12_profiles_test.go`), an AST import scan mirroring
`internal/orchestrator`'s own `TestSecurity_SourceNeverTouchesShellOrRawSockets`.
This is not merely current behavior -- it is architecturally impossible
for a profile to expand, weaken, or bypass scope, because the package
that resolves a profile has no code path that could reach the scope
rule table even by accident.

Concretely, this means, regardless of profile:

- Scope validation happens first, exactly as it always has --
  `Orchestrator.Run`'s SCOPE stage is unmodified by this phase.
- A profile cannot expand scope, authorize a new host, or change what
  a scope rule matches.
- A redirect to an out-of-scope host is still refused, following the
  same `safedial.Dialer`/`scope.Validator` path detection and crawling
  already used -- untouched by this phase.
- A subdomain that resolves to an out-of-scope IP (the
  `admin.scanner.test` -> `ipExternal` lab fixture) is still refused
  under every profile, including `deep`
  (`TestPhase3_12_SubdomainResolvingOutOfScope_AllProfileStyles`).
- `domain_suffix` semantics are unchanged: `example.com` still only
  authorizes `example.com` and its literal subdomains, never an
  unrelated domain, under any profile.
- `TestPhase3_12_ScopeRulesNeverModified_AnyProfileStyle` confirms the
  scope_rules table is byte-for-byte identical before and after running
  every profile combination against in-scope and out-of-scope targets.

## 7. Configuration precedence

**CLI profile > explicit configuration > default profile**, resolved
once, deterministically, by `internal/policy.Resolve`
(`internal/policy/resolve.go`):

1. **`--profile <name>` given**: that profile's own crawler/detection
   settings are used unconditionally. `config.yaml`'s `crawler.*`
   section is NOT consulted for those fields once a profile is named --
   `--profile recon` with `crawler.enabled: true` in config still
   produces a fully crawler-disabled policy. The profile always wins;
   there is no partial merge and no ambiguity to resolve.
2. **No `--profile`, but `crawler.enabled: true` in config**: treated
   as "explicit configuration," reproducing this codebase's pre-3.12
   behavior exactly -- crawler enabled with the config's own
   `max_depth`/`max_pages`, detection attempted (subject to the
   pre-existing, unmodified State A/B/C eligible-targets logic). An
   operator who already relies on this is not silently downgraded by
   profiles existing.
3. **Neither given**: the `recon` default profile applies (section 3).

This is intentionally NOT a field-by-field merge (e.g. "take crawler
settings from the profile but detection settings from config") --
the task driving this phase explicitly required avoiding ambiguous,
surprising precedence, and a single named tier is unambiguous in a way
partial merging cannot be. There is no override mechanism beyond
choosing a profile (or omitting `--profile` and relying on config) --
see section 12.

An invalid `--profile` value fails before any of this: `Resolve`
returns a `*policy.UnknownProfileError` immediately, and
`cmd/scanner/scan.go`'s `runFullScan` returns it before constructing a
`Pipeline` or an `Orchestrator` at all -- no scope check, no DNS
lookup, no network activity, no scan job row created.

```
$ scanner scan example.com --profile something
error: unknown scan profile "something"
Available profiles:
  deep
  recon
  web
$ echo $?
1
```

## 8. CLI examples

```bash
scanner scan example.com                    # recon profile (default): recon only
scanner scan example.com --profile recon    # same, explicit
scanner scan example.com --profile web      # bounded crawl + detection
scanner scan example.com --profile deep     # deeper crawl + detection
scanner profiles list                       # table of all 3 profiles
scanner profiles show web                   # one profile's full detail
```

Shell completion includes profile names on both `scan --profile` and
`profiles show` (`cmd/scanner/profiles.go`'s `profileNameCompletion`)
-- the one deliberate exception to Phase 3.11.1's "no
`ValidArgsFunction`/`RegisterFlagCompletionFunc` anywhere" finding,
since profile names are `policy.DefaultRegistry`'s own fixed,
zero-I/O, in-memory list (no database access, unlike scope rule IDs,
which that phase deliberately left uncompleted for exactly that
reason).

## 9. The State A/B/C distinction (unchanged)

Phase 3.11.2 introduced 3 `DetectionState` values describing WHY
`DetectorRuns` is what it is:

- **A -- `EXECUTED`**: at least one (detector, target) pair ran.
- **B -- `NOT_RUN`**: the DETECTION stage ran, but zero targets were
  eligible.
- **C -- `FAILED`**: the DETECTION stage itself did not complete.

Phase 3.12 does not remove, rename, or change the meaning of any of
these. `web`/`deep` profiles reaching state B is fully expected and
directly tested
(`TestDefaultCLI_WebProfile_NoEligibleEndpoints_ReportsNotRun`,
`tests/e2e/e2e_detection_readiness_test.go`) -- a `web`-profile scan
against a target with nothing parameterized still reports
`COMPLETED_WITH_WARNINGS` and a `DETECTION_NOT_RUN` warning, exactly
as a pre-3.12 crawler-enabled scan would have.

## 10. Detection disabled by profile: a 4th, distinct state

The `recon` profile needed a state that Phase 3.11.2's 3 states could
not honestly represent: "detection never even attempted, by policy,"
which is a fundamentally different claim from state B ("attempted,
found nothing eligible"). Conflating the two would mean an operator
reading `NOT_RUN` on a `recon`-profile scan couldn't tell "the target
might have parameterized endpoints I never looked for" apart from "I
looked and there weren't any."

`internal/orchestrator/model.go` adds a 4th `DetectionState`:

```go
DetectionStateDisabledByProfile DetectionState = "DETECTION_DISABLED_BY_PROFILE"
```

This is reached via a new, additive `Options.DetectionDisabled bool`
field (default `false`, preserving every pre-3.12 caller's behavior
unchanged). When true, `Orchestrator.Run` skips DETECTION+VERIFICATION
entirely -- it never builds a `detection.Executor`, never constructs a
`detection.Engine`, and issues zero detection-related requests. This is
a *stronger* guarantee than "run detection with an empty registry"
(which would still cost an Executor construction and would be
misreported as state B) and is checked directly by
`TestOptions_DetectionDisabled_SkipsDetectionEntirely`
(`internal/orchestrator/policy_options_test.go`), which asserts
`RequestsIssued == 0`.

Unlike state B (a warning), disabled-by-profile records **no warning
at all** and does not push the scan to `COMPLETED_WITH_WARNINGS` --
finding zero vulnerabilities under a profile that never looks for them
is the profile working exactly as configured, not an anomaly worth
flagging.

CLI output (`scanner scan example.com --profile recon`):

```
Scan ID:  <uuid>
Target:   example.com
Profile:  recon
Status:   COMPLETED
Duration: 12ms

Detection:
  Policy enabled: false
  Reason: profile disables vulnerability detection
  Registered: 6
  Enabled: 3
  Eligible targets: 0
  Detector runs: 0
  Raw findings: 0
  Canonical findings: 0

Findings:
  (none -- vulnerability detection is disabled by the active scan profile; see Detection summary above)
```

vs. a `web`-profile scan that ran but found nothing eligible:

```
Detection:
  Policy enabled: true
  Registered: 6
  Enabled: 3
  Eligible targets: 0
  Detector runs: 0
  ...

Errors/Warnings:
  [WARNING] DETECTION: DETECTION_NOT_RUN: No vulnerability detectors were executed because no eligible detection targets were discovered.
```

The pre-existing "Enabled: N" line (Phase 3.11.2, a count of enabled
detectors in the registry) is deliberately NOT reused or repurposed
for this -- the new "Policy enabled: true/false" line answers a
different question ("did this scan's policy permit detection at all")
and sits above it to avoid the two being confused.

## 11. Safety limitations

- **Profiles do not grant authorization.** Scope rules remain the sole
  authority over what may be scanned, entirely independent of profile
  (section 6).
- **`deep` does not mean exploitation.** It runs the identical
  detector set `web` runs, with wider discovery bounds -- no
  credential attack, no brute force, no post-exploitation, no new
  vulnerability class.
- **No profile can enable a detector `cmd/scanner`'s
  `productionRegistry()` does not already enable.** `ssrf`/`idor`/
  `traversal` remain registered-but-disabled regardless of profile,
  exactly as before this phase -- profiles control whether detection
  *as a whole* runs, not which individual detectors are enabled.
- **Every profile's resource limits are finite.** There is no
  "unlimited" profile and no override mechanism to make one (section
  12).
- **Profile immutability**: once `Orchestrator.Run` starts, the
  resolved `EffectivePolicy` (translated into `Options`/`Orchestrator`
  fields by `cmd/scanner`) cannot change -- `internal/policy.Resolve`
  is a pure function called exactly once per CLI invocation, before any
  `Orchestrator` is constructed, and `EffectivePolicy` holds no
  reference back to the config it was derived from
  (`TestEffectivePolicy_HoldsNoReferenceBackToConfig`,
  `internal/policy/adversarial_test.go`). Since `cmd/scanner` is a
  one-shot process per invocation that reads its config file exactly
  once at startup (`internal/config.Load`, called from
  `PersistentPreRunE`), a config file edited on disk mid-scan cannot
  retroactively change an already-running scan's policy -- there is no
  code path that re-reads it.

## 12. Profile overrides

This build implements **no override mechanism** beyond choosing a
profile name. There is no `--crawler-depth`, no
`--detection-concurrency`, no config-file field that mutates a named
profile's own values. This is a deliberate scope decision, not an
oversight: the task driving this phase explicitly said not to
implement arbitrary profile mutation unless required, and required
that any override mechanism define exactly which fields may override
and prevent unsafe/contradictory combinations. The simplest, most
robust way to satisfy "never silently produce surprising behavior" is
to have nothing to override at all -- a resolved profile's values are
exactly its own declared values, full stop.

This also means several of the adversarial scenarios below are
vacuously safe rather than actively defended: "extreme resource
values" and "malformed profile configuration" have no way to reach the
system at all, since there is no operator-supplied numeric or
structural input anywhere in profile resolution -- only a profile
*name* (a `string`), handled by `internal/policy.Resolve` as explored
in section 13.

## 13. Test lab reuse

Every fixture type the test matrix calls for was already available in
`lab` from Phase 1-3, and Phase 3.12 deliberately reuses them
rather than adding parallel, duplicate servers:

| Required fixture | Existing lab fixture used |
|---|---|
| Recon-only target | any lab host (recon does not depend on content) |
| Benign web app | `static.scanner.test` / `scanner.test`'s own index |
| Vulnerable web app | `vuln.scanner.test` (`harness_vuln.go`) |
| Parameterized endpoint | `vuln.scanner.test`'s query-parameter endpoints |
| Redirect | `redirect.scanner.test` |
| Out-of-scope redirect | `redirect.scanner.test` -> `external.scanner.test` |
| Subdomain (in scope) | `www.scanner.test` (CNAME) |
| Out-of-scope subdomain | `admin.scanner.test` (CNAME to `ipExternal`, previously defined but never exercised by any test before this phase) |
| Slow endpoint | `slow.scanner.test` |
| Many-page crawler target | `vuln.scanner.test`, plus a purpose-built 30-page chained fixture in `tests/e2e/e2e_profiles_test.go` (`chainPageServer`) specifically to exercise the `web` vs `deep` MaxDepth difference, which none of the existing fixtures had enough linked depth to distinguish |

`admin.scanner.test` in particular was defined in `harness.go` since
an earlier phase but never referenced by any existing test -- Phase
3.12's adversarial suite is the first to actually exercise it.
