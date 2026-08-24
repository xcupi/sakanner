# Phase 3.12 Acceptance Test: Scan Profiles & Detection Policy Engine

Scope: new `internal/policy` package (Profile/EffectivePolicy model,
fixed 3-profile registry, deterministic `Resolve`), 3 small additive
fields on `internal/orchestrator` (`Options.ProfileLabel`,
`Options.DetectionDisabled`, `Options.CrawlOverride`), a 4th
`DetectionState` (`DetectionStateDisabledByProfile`), a `Profile` field
on `Result`, `cmd/scanner/scan.go` (`--profile` flag, profile
resolution wired into `runFullScan`, extended `Detection:` block),
`cmd/scanner/profiles.go` (new `scanner profiles list`/`show`
commands), `docs/phase-3-12-scan-profiles.md` (new architecture doc),
and two real bugs found and fixed in `internal/orchestrator/orchestrator.go`
while building this phase's own tests (see "Issues found and fixed").
See [docs/phase-3-12-scan-profiles.md](phase-3-12-scan-profiles.md)
for the full architecture writeup.

This phase changes **no** detector, **no** detector eligibility rule,
and **no** scope enforcement. `crawler.enabled: false` remains the
config default; the CLI's own effective default (no `--profile`, no
`crawler.enabled: true`) is now the `recon` profile, which is the
same, unmodified behavior that default already produced before this
phase (crawler off, detection never runs) -- only the REPORTED reason
changed (see State A/B/C section below), not the underlying safety
property.

## What was built

- **`internal/policy`** (new package): `Profile`/`EffectivePolicy`
  model (`model.go`), a fixed 3-profile registry with no runtime
  registration API (`registry.go`), and `Resolve(profileFlag string,
  cfg ConfigView) (EffectivePolicy, error)` implementing the exact
  "CLI profile > explicit configuration > default profile" precedence
  (`resolve.go`). Zero dependency on `internal/scope`, `internal/storage`,
  `internal/orchestration`, or `internal/orchestrator` -- verified both
  by unit test and by a structural AST import scan
  (`TestPhase3_12_PolicyPackage_HasNoScopeOrStorageAccess`).
- **`internal/orchestrator`**: `Options` gained `ProfileLabel string`,
  `DetectionDisabled bool`, and `CrawlOverride *CrawlSettings` -- all
  three default to their Go zero value, which reproduces every
  pre-Phase-3.12 caller's behavior unchanged. `CrawlOverride` is
  applied via a per-scan shallow copy of `*Orchestrator.Pipeline`
  (`scanPipeline`), never a mutation of the shared instance, so
  concurrent scans against one `Orchestrator` may safely use different
  crawl settings. `DetectionDisabled` makes `Run` skip constructing a
  `detection.Executor`/`detection.Engine` entirely, setting
  `DetectorSummary.State = DetectionStateDisabledByProfile` (a new,
  4th `DetectionState`, additive to Phase 3.11.2's existing 3) with no
  warning recorded. `Result` gained a `Profile string` field.
- **`cmd/scanner/scan.go`**: a `--profile` flag; `runFullScan` resolves
  the profile via `internal/policy.Resolve` FIRST (before constructing
  any `Pipeline`/`Orchestrator`), returning an `exitCodeErr{exitGenericError}`
  immediately on an unknown profile name; `printScanResult` gained a
  `Profile:` line and a `Policy enabled: true/false` + conditional
  `Reason:` line in the `Detection:` block, plus a 4th branch in the
  empty-findings message.
- **`cmd/scanner/profiles.go`** (new): `scanner profiles list` (a
  NAME/DESCRIPTION/CRAWLER/DETECTION/VERIFICATION/RESOURCE CLASS
  table) and `scanner profiles show <name>` (full detail). Profile
  names are completable on both `scan --profile` and `profiles show`
  (`profileNameCompletion`) -- zero-I/O, so this does not weaken Phase
  3.11.1's "completion never touches the database" finding.
- **`docs/phase-3-12-scan-profiles.md`** (new): the architecture
  writeup this report cross-references throughout.

## Issues found and fixed

Building this phase's own required tests uncovered two related, real
bugs in `internal/orchestrator/orchestrator.go` -- both **latent since
Phase 3.11**, invisible until now because every pre-3.12 caller left
`Limits.ScanTimeout`/`Limits.StageTimeout` at `0` ("no timeout"),
which this phase's profile resolution is the first thing to change by
giving the CLI real, positive values by default.

**Bug 1 -- every scan using a positive `ScanTimeout` was reported
`CANCELLED`, even ones that completed cleanly.** `Run`'s finalization
defer (registered first, so it runs LAST per Go's LIFO defer order)
computed `terminalStatus` by reading `ctx.Err()`; the ScanTimeout
context's own `defer cancel()` (registered later, so it ran FIRST) had
already marked that same `ctx` Done by the time the finalization
closure inspected it -- calling a context's cancel func always marks
it Done, indistinguishable by itself from a genuine caller-side
cancellation. First reproduced manually (`scanner scan 127.0.0.1`
against an empty scope-allowed target, `Status: CANCELLED` after 4ms)
and via `TestDefaultCLI_CrawlerDisabled_ZeroDetectorRunsIsObservable`.
**Fix**: replaced the bare `defer cancel()` with two defers registered
together -- `defer cancel()` then, immediately after, an unconditional
`defer func() { ctxDone = ctx.Err() != nil }()` -- so the capture (LIFO:
runs first) always observes `ctx`'s true state before this package's
own cleanup can touch it. `terminalStatus`/`isCancellation` were
changed to take a caller-captured `ctxDone bool` instead of a live
`context.Context`, which also keeps `go vet`'s `lostcancel` check
satisfied (the `defer cancel()` now sits in exactly the idiomatic
position it expects).

**Bug 2 -- a RECON-stage error could be misclassified as a
cancellation.** The same pattern existed at the RECON stage's own
error handling: `isCancellation(reconCtx, pipelineErr)` was called
AFTER `cancelRecon()`, so once `Limits.StageTimeout` is positive (now
the default via every profile), an ordinary RECON failure -- not a
cancellation at all -- would have its stage marked `CANCELLED` instead
of `FAILED`, purely because `cancelRecon()` had already run. **Fix**:
capture `reconCtxDone := reconCtx.Err() != nil` before calling
`cancelRecon()`, and pass that captured bool to `isCancellation`
instead.

Both fixes are pure reorderings/signature changes with no change to
what `Run` actually does over the network, to scope, or to any
detector -- confirmed by the unmodified pass of every pre-existing
Phase 3.11/3.11.1/3.11.2 test plus a new regression test,
`TestScanTimeout_PositiveButNotExceeded_DoesNotFalselyReportCancelled`.

### Revert-and-verify

`internal/orchestrator/orchestrator.go` was backed up, Bug 1's fix was
reverted to its original (broken) ordering (registering the capture
defer BEFORE `cancel()` instead of after), and
`TestScanTimeout_PositiveButNotExceeded_DoesNotFalselyReportCancelled`
was run: it failed with exactly the predicted message (`Status =
CANCELLED despite completing well within a 5-minute ScanTimeout`). The
file was then restored from backup; `diff` confirmed a byte-identical
restore; the full `internal/orchestrator` suite (including `-race`)
was re-run clean.

## Design decisions worth recording

- **`internal/orchestrator` remains completely unaware of profile
  names.** It gained 3 small, generic, profile-agnostic Options fields
  (a display label, a bool, and a settings struct) -- no `if profile ==
  "web"` anywhere in this codebase, per the task's explicit "prefer a
  centralized policy representation" instruction. All profile-name
  awareness lives in `internal/policy` and its one consumer,
  `cmd/scanner/scan.go`.
- **No override mechanism was implemented.** A resolved profile's
  values are exactly its own declared values; there is no
  `--crawler-depth`-style flag or config field that mutates a named
  profile. This is a deliberate scope decision (`docs/phase-3-12-scan-profiles.md`
  section 12), not an oversight -- it is also what makes "extreme
  resource values" and "malformed profile configuration" vacuously
  safe: there is no operator-supplied numeric or structural input
  anywhere in profile resolution, only a profile *name*.
- **Resource governance (`DetectionConcurrency`, `ScanTimeout`,
  `StageTimeout`) is resolved once per CLI invocation**, not threaded
  per-scan through a shared `Orchestrator` the way `DetectionDisabled`/
  `CrawlOverride` are -- matching how the CLI already builds a fresh
  `Orchestrator` per invocation. Per-scan behavioral fields
  (crawl on/off+depth/pages, detection on/off) ARE fully per-scan
  (`Options`-level), since the concurrency test matrix requires two
  concurrent scans on ONE shared `Orchestrator` to use different
  profiles safely (`TestOptions_ConcurrentScans_DifferentProfiles_NoCrossContamination`).
- **Test lab reuse over new fixtures**: all 10 required fixture types
  map onto existing `lab` servers (see
  `docs/phase-3-12-scan-profiles.md` section 13) except a purpose-built
  30-page chained fixture (`tests/e2e/e2e_profiles_test.go`'s
  `chainPageServer`) needed specifically to exercise `web` vs `deep`'s
  MaxDepth difference, which no existing fixture had enough linked
  depth to distinguish. `admin.scanner.test` (defined in `harness.go`
  since an earlier phase, never exercised by any prior test) is used
  for the first time by this phase's subdomain-confusion adversarial
  tests.

## Test matrix results

### PROFILE REGISTRY

Exactly 3 built-in profiles (`recon`/`web`/`deep`), no runtime
registration API, deterministic `List()` order, no duplicate names,
immutable values returned from `Get`, every profile's resource limits
bounded (`internal/policy/registry_test.go`, 11 tests).

### PROFILE RESOLUTION

Explicit `--profile` always wins over config; no-profile +
`crawler.enabled: true` reproduces pre-3.12 behavior exactly;
no-profile + no config crawler falls back to `recon`; unknown profile
name returns the exact required error text; `Resolve` is deterministic
across 50 repeated calls per profile (`internal/policy/resolve_test.go`,
7 tests).

### DEFAULT PROFILE

`recon` confirmed as `DefaultProfileName`; a bare `scanner scan
<target>` (no flags, no crawler config) resolves to `recon`, reports
`Profile:  recon`, `Policy enabled: false`, `Status: COMPLETED` (never
`COMPLETED_WITH_WARNINGS`) -- `TestDefaultCLI_CrawlerDisabled_ZeroDetectorRunsIsObservable`.

### RECON PROFILE

Crawler and detection both structurally disabled; zero detection
requests issued (`RequestsIssued == 0`); `DetectionStateDisabledByProfile`
reported; recon itself still runs and succeeds
(`TestOptions_DetectionDisabled_SkipsDetectionEntirely`, plus the CLI
test above).

### WEB PROFILE

Crawler enabled with depth=2/pages=20; real detection runs against a
real vulnerable target and finds `reflected_xss`, `sql_injection`, and
`command_injection` findings; a target with nothing parameterized
correctly reports state B (`NOT_RUN`, a warning) instead of the
profile-disabled state (`TestScanCmd_ProfileWeb_AgainstVulnLab_RealFinding`,
`TestDefaultCLI_WebProfile_NoEligibleEndpoints_ReportsNotRun`).

### DEEP PROFILE

Crawler enabled with depth=4/pages=75; detection executes against the
real vuln lab; against a 30-page fixture deeper than either profile's
own depth bound, `deep` discovers strictly more eligible targets than
`web` and strictly fewer than the fixture's total -- bounded, not
unlimited, and no new detector type
(`TestScanCmd_ProfileDeep_AgainstVulnLab_DetectionExecutes`,
`TestScanCmd_DeepProfile_CrawlsMoreThanWeb_ButBounded`).

### DETECTION POLICY

The new `DetectionStateDisabledByProfile` state is structurally
distinct from the pre-existing `NOT_RUN` (state B); no warning is
recorded for the disabled case; the existing 3-state model (A/B/C)
remains fully reachable and independently tested
(`internal/orchestrator/policy_options_test.go`, 7 tests;
`internal/orchestrator/model.go`'s `DetectionState` doc comment).

### SCOPE ENFORCEMENT

`internal/policy` has zero access to `internal/scope`/`internal/storage`
(static AST check); an out-of-scope target fails identically under
recon-, web-, and deep-style `Options`; scope rules are byte-for-byte
unchanged before/after every profile combination; a subdomain
authorized by hostname but resolving to an out-of-scope IP
(`admin.scanner.test` -> `ipExternal`) never produces a finding or
HTTP service under any profile
(`lab/phase3_12_profiles_test.go`, 4 tests, 15 subtests total).

### REDIRECT SECURITY

Unmodified by this phase: `internal/orchestrator`'s SCOPE/RECON/DETECTION
stages, `safedial.Dialer`, and `scope.Validator` are exactly as Phase
1-3.11 left them, and Phase 3.11's own pre-existing redirect tests
(`TestLab_RedirectAndStatusScenarios`, `TestLab_ExternalRedirectNeverDialsOutOfScopeHost`)
continue to pass unchanged, proving redirect-to-out-of-scope truncation
is entirely independent of anything this phase added.

### RESOURCE LIMITS

Every profile defines finite `CrawlMaxDepth`/`CrawlMaxPages`/
`DetectionConcurrency`/`ScanTimeout`/`StageTimeout`; `deep`'s values
exceed `web`'s but remain a small, explicit multiple, never
"unlimited" (`TestRegistry_DeepProfile_MoreThanWeb_ButBounded`,
`TestRegistry_EveryProfile_HasBoundedResourceLimits`).

### DETERMINISM

`Resolve` produces byte-identical `EffectivePolicy` values across 50
repeated calls per profile, for every profile including the
config-driven and default-fallback paths, using `reflect.DeepEqual`
(`TestResolve_Deterministic`). `EffectivePolicy` holds no reference
back to the `ConfigView` it was derived from
(`TestEffectivePolicy_HoldsNoReferenceBackToConfig`).

### CONCURRENCY

Two concurrent `Orchestrator.Run` calls on ONE shared instance, using
different profile-style `Options` (recon-style vs web-style), produce
fully isolated results with no cross-contamination
(`TestOptions_ConcurrentScans_DifferentProfiles_NoCrossContamination`,
passes under `-race`). `CrawlOverride` provably does not mutate the
shared `Pipeline` (`TestOptions_CrawlOverride_DoesNotMutateSharedPipeline`).

### CLI

`scanner scan --help`, `scanner profiles --help`,
`scanner profiles list`, `scanner profiles show recon|web|deep`, and
`scanner scan <target> --profile recon|web|deep` all verified manually
and via `tests/e2e/e2e_profiles_test.go` (7 tests). Invalid profile
name produces the exact required error format, exit code 1, no scan
job/target row created, and no `Scan ID:` in the output
(`TestScanCmd_InvalidProfile_CleanFailure`).

### SHELL COMPLETION

`scanner __complete scan --profile ""` and
`scanner __complete profiles show ""` both return `deep`/`recon`/`web`.
Zero-I/O (`policy.DefaultRegistry().Names()`), so this does not weaken
Phase 3.11.1's "completion never opens the database" finding --
documented explicitly as the one deliberate exception in
`cmd/scanner/profiles.go`'s `profileNameCompletion` doc comment.

### DOCUMENTATION

`docs/phase-3-12-scan-profiles.md` covers why profiles exist, all 3
profiles' behavior, the default profile and its reasoning, resource
limits, scope semantics, configuration precedence, CLI examples, the
State A/B/C distinction, the new disabled-by-profile state, safety
limitations, the (absent) override mechanism, and test lab reuse.
`docs/phase-3-11-scan-orchestrator.md` was updated with a short
cross-reference to the new 4th state.

### TEST LAB

All 10 required fixture types map onto existing `lab` fixtures
(see "Design decisions" above and `docs/phase-3-12-scan-profiles.md`
section 13) plus one new purpose-built chained fixture for the
web-vs-deep depth distinction. `admin.scanner.test` exercised by a
real test for the first time.

### ADVERSARIAL

All 14 scenarios addressed:

1. Out-of-scope target, all 3 profile styles -- PASS, no bypass.
2. Redirect to out-of-scope host -- PASS (unmodified mechanism).
3. DNS/subdomain resolving outside scope -- PASS, all 3 profile styles.
4. Subdomain confusion (`admin.scanner.test`) -- PASS.
5. Profile name injection (shell metacharacters, path traversal, null
   bytes, SQL/XSS-shaped strings, 100KB string, unicode, case
   variants) -- PASS, all cleanly rejected as `UnknownProfileError`,
   no panic, no special handling (`TestResolve_ProfileNameInjection_RejectedCleanly`,
   15 subtests).
6. Malformed profile configuration -- N/A by construction (no
   structural config input to a profile beyond its fixed name).
7. Extreme resource values -- N/A by construction (no override
   mechanism exists at all).
8. Concurrent scans, different profiles -- PASS
   (`TestOptions_ConcurrentScans_DifferentProfiles_NoCrossContamination`).
9. Configuration mutation during scan -- PASS: `EffectivePolicy` holds
   no back-reference to config; a CLI process reads its config file
   exactly once at startup, so there is no code path that could re-read
   a mid-scan edit even in principle.
10. Invalid profile + target combined -- PASS
    (`TestScanCmd_InvalidProfile_CleanFailure`).
11. Duplicate profile registration -- N/A by construction (no runtime
    registration API); guarded against a future source edit by
    `TestRegistry_NoDuplicateProfileNames`.
12. Profile attempting to enable an unauthorized target -- PASS, same
    mechanism/test as #1.
13. Profile attempting to disable scope validation -- PASS, proven
    both behaviorally and structurally (`internal/policy` cannot import
    `internal/scope`).
14. (Combined coverage of the above via the full adversarial suite.)

**Result: NO SCOPE BYPASS in any scenario.**

### SECURITY

`TestPhase3_12_PolicyPackage_HasNoScopeOrStorageAccess` (static AST
import scan, mirrors `internal/orchestrator`'s own
`TestSecurity_SourceNeverTouchesShellOrRawSockets`); no secrets in any
new log line or error message; no new network code path (recon/detection
still only ever run through the pre-existing, unmodified
`Pipeline`/`Executor`).

### PERFORMANCE

`internal/policy.Resolve` is pure, in-memory, zero-I/O computation
(a map lookup plus struct copies) -- trivially fast by construction,
confirmed by `internal/policy`'s entire test suite completing in
single-digit milliseconds. Phase 3.11's own
`TestPhase3_11_Orchestrator_Performance_FullScanCompletesQuickly`
continues to pass unmodified.

### REGRESSION

Full repository: `go build ./...`, `go vet ./...`, `gofmt -l .` all
clean. `golangci-lint` not installed in this environment (noted, not
run). Complete `go test ./...` (including `lab` and `tests/e2e`)
and a targeted `-race` pass over every concurrency-relevant package
(`internal/orchestrator`, `internal/policy`, `internal/orchestration`,
`lab`) all green.

## Final report

```
TOTAL TESTS: 1292 (1001 top-level + 291 subtests)
PASS: 1292
FAIL: 0
PARTIAL: 0
NOT IMPLEMENTED: 0

PROFILE REGISTRY: PASS
PROFILE RESOLUTION: PASS
DEFAULT PROFILE: PASS
RECON PROFILE: PASS
WEB PROFILE: PASS
DEEP PROFILE: PASS
DETECTION POLICY: PASS
SCOPE ENFORCEMENT: PASS
REDIRECT SECURITY: PASS
RESOURCE LIMITS: PASS
DETERMINISM: PASS
CONCURRENCY: PASS
CLI: PASS
SHELL COMPLETION: PASS
DOCUMENTATION: PASS
TEST LAB: PASS
ADVERSARIAL: PASS
SECURITY: PASS
PERFORMANCE: PASS
REGRESSION: PASS

SECURITY ISSUES: 0
RELIABILITY ISSUES: 2 (found and fixed -- see "Issues found and fixed")
PERFORMANCE ISSUES: 0

PHASE 3.12 ADVERSARIAL: PASS

PHASE 3.12 VERDICT: PASS
```

Not proceeding to Phase 3.13, not implementing exploitation, new
vulnerability detector types, credential attacks, brute force, or
post-exploitation, not weakening scope enforcement anywhere, not
enabling the crawler globally by default (the `recon` default keeps it
off), and not removing or altering the pre-existing State A/B/C
distinction, per the task's explicit instruction to stop after this
report.
