# Phase 3 Security Test Laboratory

**Status: this document covers only the Test Laboratory itself** —
intentionally vulnerable/safe fixture pairs, ground truth, and the
integration-test *foundation* for comparing a future detector's output
against that ground truth. **No Phase 3 vulnerability detector exists in
sakanner yet.** This document does not claim one works, because there is
nothing to claim yet — see "What this lab does and does not prove"
below.

This extends the [Phase 2 Test Laboratory](phase-2-test-lab.md), which
this document assumes as background; Phase 2's own lab, ground truth,
and tests are untouched by this work (see "Phase 1/2 regression" below).

## Why a *vulnerability* lab, and why fixture pairs

Phase 2's lab proves sakanner's recon pipeline finds real hosts,
services, redirects, and technologies correctly. Phase 3 (whenever it's
built) will need the equivalent for vulnerability detection: a local
environment with **known** vulnerabilities, of known severity, at known
endpoints — so a detector's output can be scored as true positive, false
positive, false negative, or duplicate against a ground truth, not
against its own prior output.

Every one of the 17 vulnerability classes below is implemented as a
**pair**: one endpoint that is genuinely vulnerable, and one sibling
endpoint, same shape, same synthetic data, that is not. Measuring only
true/false negatives (does the detector find the bug) is half the job;
the safe sibling exists specifically to measure false positives (does
the detector *also* fire on code that doesn't have the bug). Both halves
are equally load-bearing — see "False positive measurement" below.

## Architecture

```
lab/
├── harness.go                     Phase 2 harness (unchanged) — Start()
├── harness_vuln.go                Phase 3 fixtures — StartWithVulnerabilities()
│                                    wraps Start() and adds two more servers
├── ground-truth.yaml              Phase 2 ground truth (unchanged)
├── ground-truth-vulnerabilities.yaml   Phase 3 ground truth (new, separate file)
├── groundtruth.go                 Phase 2 loader (unchanged)
├── groundtruth_vuln.go            Phase 3 loader — VulnGroundTruth, VulnFinding, ...
├── comparison.go                  CompareFindings(): TP/FP/FN/Duplicate classification
├── comparison_test.go             proves the classifier itself is correct, using
│                                    hand-built synthetic []models.Finding data
├── phase3_lab_test.go             the lab: fixtures reachable, positives exhibit
│                                    the bug, negatives don't, SSRF isolation, scope
│                                    enforcement, determinism, and the ground-truth
│                                    comparison run against a real (currently empty)
│                                    scan result
├── cmd/labserver/                 make lab-up / lab-up-phase3 (LAB_PHASE3=1)
├── docker-compose.yml             extended with vuln + ssrf-internal services
└── apps/vulnerable/vuln_app.py    Docker-profile mirror of harness_vuln.go
```

`StartWithVulnerabilities(gt)` is a strict superset of Phase 2's
`Start(gt)` — it calls `Start` unmodified, then adds two more servers.
Nothing in `harness.go` itself changed except two new (empty-unless-
used) fields on the `Lab` struct to expose their addresses the same way
`RedirectHTTPAddr` already is. A full Phase 2 regression run confirms
this is safe (see "Phase 1/2 regression" below).

## Vulnerability fixtures

All fixtures live under one host, `vuln.scanner.test`, resolved by the
same `dns.FakeResolver` Phase 2 already uses — no real DNS, no live
network, nothing outside this process. Every finding's full detail
(endpoint, parameter, severity + rationale, expected evidence, expected
behavior) is in
[`lab/ground-truth-vulnerabilities.yaml`](../lab/ground-truth-vulnerabilities.yaml);
this table is a summary.

| # | Class | Vulnerable endpoint | Safe endpoint | Severity | Auth required |
|---|---|---|---|---|---|
| 1 | Reflected XSS | `/xss/reflected/vulnerable?q=` (+ `attribute/vulnerable?name=`, Phase 3.2) | `/xss/reflected/safe?q=` (+ `attribute/safe`, `unrelated`, `static-decoy`, Phase 3.2) | high | no |
| 2 | Stored XSS | `/xss/stored/vulnerable` (POST comment, GET to observe) | `/xss/stored/safe` | critical | no |
| 3 | SQL injection | `/sqli/vulnerable?id=` | `/sqli/safe?id=` | critical | no |
| 4 | Authentication weakness | `/auth/weak-credentials` (admin/admin) | `/auth/strong-credentials` | high | no |
| 5 | Authorization / IDOR | `/idor/vulnerable/user/{id}` | `/idor/safe/user/{id}` | high | yes |
| 6 | Path traversal | `/files/traversal/vulnerable?name=` | `/files/traversal/safe?name=` | high | no |
| 7 | Local file inclusion | `/files/lfi/vulnerable?page=` | `/files/lfi/safe?page=` | high | no |
| 8 | SSRF | `/ssrf/vulnerable?url=` | `/ssrf/safe?url=` | critical | no |
| 9 | Open redirect | `/redirect/open/vulnerable?next=` | `/redirect/open/safe?next=` | medium | no |
| 10 | Security misconfiguration (stack trace) | `/misconfig/stacktrace/vulnerable` | `/misconfig/stacktrace/safe` | medium | no |
| 11 | Sensitive information exposure | `/info/exposure/vulnerable` | `/info/exposure/safe` | high | no |
| 12 | Insecure cookie configuration | `/cookies/insecure/vulnerable` | `/cookies/insecure/safe` | medium | no |
| 13 | CORS misconfiguration | `/cors/vulnerable` | `/cors/safe` | high | no |
| 14 | Missing security headers | `/headers/missing/vulnerable` | `/headers/missing/safe` | low | no |
| 15 | Known vulnerable component | `/component/vulnerable` (jQuery 1.6.1) | `/component/safe` (jQuery 3.6.0) | medium | no |
| 16 | Exposed admin endpoint | `/admin/exposed` | `/admin/protected` (bearer token) | high | no |
| 17 | Directory listing | `/directory-listing/vulnerable/` | `/directory-listing/safe/` (403) | low | no |

Severity uses **sakanner's existing** `pkg/models.Severity` five-value
scale (info/low/medium/high/critical) — no new severity model was
invented. Each finding's `severity_rationale` in the ground-truth YAML
explains *why* that level, not just what it is.

### Why these 17 and not others

The user's requested list also mentioned "LFI (where appropriate)" —
implemented here, since a synthetic in-memory "template include"
fixture is a faithful, safe way to exercise the same detection signature
as path traversal (see fixture #7) without touching a real filesystem.
No class from the requested list was judged inappropriate for automated
detection and skipped; two findings are marked `requires_capability`
(see below) rather than omitted, since they are still valid fixtures —
just not detectable with Phase 2's current pipeline alone.

### `requires_capability`: honest gaps, not hidden ones

Two fixtures need pipeline capability Phase 2 doesn't have yet, and the
ground truth says so explicitly rather than quietly pretending they're
detectable today:

- **Stored XSS** needs *multi-step probing* (POST a payload, then a
  separate GET to observe it reflected) — Phase 2's pipeline probes
  independently, with no "do X then check Y" sequencing.
- **IDOR** needs *authenticated differential probing* (request the same
  resource as two different synthetic sessions and compare) — Phase 2
  has no session/login capability.

The known-vulnerable-component fixture is the opposite case:
`requires_capability: "none"` — it's a direct extension of Phase 2's
*already-built* JS/technology fingerprinting
(`internal/fingerprint.DefaultSignatures`'s jQuery signature), which
already extracts the exact version string (`1.6.1` vs `3.6.0`) into a
`Technology` row. A future detector only needs to compare that string
against a known-vulnerable-versions list — no new probing capability
required.

## False positive measurement

Every vulnerable endpoint's negative sibling is engineered to *look*
similar (same URL shape, same synthetic data, same response structure)
while being genuinely safe — e.g. `/sqli/safe?id=` also takes a raw
`id` parameter and queries the same three-row fixture "database," but
treats the parameter as opaque, so a tautology payload returns `(none)`
instead of every row. A detector that pattern-matches on URL shape or
parameter name alone, rather than actually confirming exploitability,
will fire a false positive here — that's the point.

`lab/comparison.go`'s `CompareFindings` classifies any actual
finding whose endpoint matches a *negative* fixture the same way it
classifies any other unexpected finding: `false_positive`.
`comparison_test.go` proves this classification path works using
synthetic finding data (`TestCompareFindings_UnexpectedFinding_IsFalsePositive`).

## Evidence: real behavior, never hard-coded

No fixture's ground truth is a hard-coded scanner finding. Every
`expected_evidence` entry names something a **real HTTP exchange**
against the fixture actually produces — a response body fragment, a
response header (or its absence), a redirect `Location` value, a status
code — verified directly against the running fixture before being
written into the YAML (see `phase3_lab_test.go`'s
`TestPhase3Lab_PositiveFixturesExhibitVulnerability` /
`TestPhase3Lab_NegativeFixturesDoNotExhibitVulnerability`, which re-run
those exact same probes as tests).

## Authentication / authorization coverage

Four scenarios, as requested, using only synthetic fixture data —
`ground-truth-vulnerabilities.yaml`'s `authentication_coverage` section
indexes which finding covers which:

- **Unauthenticated access** — `/admin/exposed` needs no credentials at all.
- **Authenticated access required and enforced** — `/admin/protected`
  correctly demands `Authorization: Bearer sakanner-lab-fixture-admin-token-000`
  (a fixture-only token, not a real secret anywhere).
- **Unauthorized access correctly denied** — `/idor/safe/user/2` with
  `Cookie: session=user1` (the wrong user's session) is correctly
  rejected with 403.
- **Horizontal authorization failure** — `/idor/vulnerable/user/2`
  ignores the session cookie entirely and returns user 2's record
  regardless of which (if any) synthetic session is presented.

All credentials involved (`admin`/`admin`, the strong-credentials pair,
the bearer token, the `session=userN` cookie scheme) are fixture-only
strings with no meaning outside this lab process.

## SSRF fixture isolation

The SSRF fixture (`/ssrf/vulnerable?url=`) is **genuinely** vulnerable:
its handler performs a real, server-side outbound HTTP fetch of
whatever URL the caller supplies, with no destination-purpose
validation — that absence *is* the vulnerability, and a real fix would
need an allowlist of legitimate destinations, not just a network-range
check.

What makes it safe to run in this repo is a **lab safety net**, layered
on top, not a fix to the vulnerability's own logic: the handler parses
the destination and refuses anything whose host isn't literally an IP
in `127.0.0.0/8` (502 otherwise). This is deliberately documented as a
safety measure specific to *running this lab*, not as an example of how
the vulnerability should be remediated — see the comment directly above
the handler in `harness_vuln.go` and the finding's `isolation_note` in
the ground-truth YAML.

The only destination the fixture can actually reach is
`ssrf-internal.scanner.test`, a second lab-only loopback server that
exists *only* to be the SSRF fixture's target — it is never a scan
`Target`, never added to any scope rule, and serves nothing else.
`TestPhase3Lab_SSRFFixtureIsolated` proves both directions: the internal
service is reachable via the SSRF fixture, and a non-loopback or
domain-name destination is refused with 502.

In the Docker Compose profile, `ssrf-internal` additionally has no
published port at all — it's reachable only from other containers on
the same compose network — as defense in depth on top of the same
application-level restriction; see the comments in `docker-compose.yml`.

## File-related fixture isolation

Path traversal and LFI fixtures (`/files/traversal/*`, `/files/lfi/*`)
never touch the real filesystem. Their "files" are Go map literals
(`SYNTH_FILES`, `SYNTH_TEMPLATES` in `harness_vuln.go` /
`vuln_app.py`) keyed by the exact strings a traversal/inclusion payload
would use (e.g. `"../../../etc/passwd"`), returning clearly
fixture-labeled synthetic content (`sakanner-lab-synthetic-fixture-file:
...`). A real target's equivalent bug would leak real file content;
this fixture proves the *detection signature* (unsanitized path-shaped
input reaching a resource lookup) without any risk of ever reading a
real file, inside or outside a container.

## Determinism

No fixture depends on wall-clock time, randomness, or an external
network/API call (the SSRF fixture only ever reaches another
lab-controlled loopback service). The one fixture with mutable state —
Stored XSS — keeps that state **closure-local** to one
`StartWithVulnerabilities` call, not a package-level global, so
concurrent or repeated lab instances never leak state into each other.
`TestPhase3Lab_Determinism` proves this two ways: the same probe against
two freshly-started labs returns byte-identical output, and a comment
POSTed to one lab instance is never visible from a second, independently
started instance.

## Scope enforcement (extends Phase 2's)

Three scenarios, on top of Phase 2's own out-of-scope host tests
(`scope_enforcement_scenarios` in the ground-truth YAML):

1. **Crawler link** — `vuln.scanner.test`'s index page links directly
   to `external.scanner.test` (Phase 2's established out-of-scope host).
   `TestPhase3Lab_CrawlerNeverFollowsOutOfScopeLinkFromVulnApp` confirms
   the crawler's existing same-origin restriction still holds from a
   vulnerable page, unchanged.
2. **HTTP redirect** — the open-redirect fixture's own natural
   exploitation path (`/redirect/open/vulnerable?next=http://external.scanner.test/`)
   *is* a redirect to an out-of-scope host.
   `TestPhase3Lab_OpenRedirectToOutOfScopeIsTruncated` confirms
   `safedial`'s existing `CheckRedirect` truncates that hop, unchanged
   from Phase 2's own redirect-to-out-of-scope behavior.
3. **SSRF parameter** — documented rather than re-tested: the SSRF
   fixture's vulnerability surface is a property of the *fixture
   application's own* server-side request, not of anything sakanner
   itself dials — sakanner's scope enforcement is unaffected either way,
   and the fixture's own 127.0.0.0/8-only safety net means even the
   fixture couldn't reach `external.scanner.test`'s real address if
   asked to, independent of sakanner entirely.

In all three cases, **no vulnerability fixture ever causes sakanner to
escape scope** — that guarantee is exactly what these tests exist to
keep proving as Phase 3 detection gets built on top of this lab.

## Ground truth and the comparison foundation

`lab/ground-truth-vulnerabilities.yaml` is the single source of
truth: originally 34 findings (17 positive + 17 negative, one pair per
vulnerability class), extended in Phase 3.2 with 4 more reflected-XSS-specific
findings (a second reflection context, plus two additional "must not be
a finding" negative shapes) for 38 total (18 positive + 20 negative) --
see that file's "Phase 3.2 additions" comment and
[docs/phase-3-2-reflected-xss.md](phase-3-2-reflected-xss.md). Plus the
3 scope-enforcement scenarios above and the authentication-coverage
index. It reuses
`pkg/models.Finding`'s existing field shape (`Type` →
`VulnerabilityType`, `Endpoint` → `AffectedEndpoint`, `Severity` →
`Severity`, ...) so a real detector's output needs no translation layer
to compare against it — no new finding-model architecture was invented
for Phase 3; `pkg/models.Finding`/`Evidence`/`Severity` already existed
from Phase 1 scaffolding, populated by nothing until a detector exists.

`lab/comparison.go`'s `CompareFindings(actual, positives,
negatives)` is that comparison, producing a `ComparisonReport` with
`TotalExpected`, `TotalActual`, `TruePositives`, `FalsePositives`,
`FalseNegatives`, `Duplicates`, and a per-finding `[]MatchResult`
flagging whether a matched true positive also got severity, endpoint,
and evidence right (not just presence/absence). Matching is by
`(VulnerabilityType, AffectedEndpoint)`; a second actual finding on the
same `(type, endpoint, parameter)` as an already-matched one is a
`Duplicate`, not a second true positive or a false positive.

`comparison_test.go` proves this classification logic is correct using
**hand-built synthetic** `[]models.Finding` data — exact match, no
match, repeated finding, severity mismatch, empty ground truth — this
was written before any real detector existed, and still passes unchanged
now that one does (Phase 3.2's reflected-XSS detector) since the
classification logic itself never needed to change.

### What this lab does and does not prove

`TestPhase3Lab_ScanAndCompareAgainstGroundTruth` runs sakanner's real
`orchestration.Pipeline` against the vulnerable lab -- recon only, it
never constructs or runs a `detection.Engine` -- retrieves whatever
`[]models.Finding` rows the (still-empty, for a recon-only run) findings
table contains, and runs `CompareFindings` against them:

```
expected: 18
actual:   0
true positives:  0
false positives: 0
false negatives: 18
duplicates:      0
```

(For what the same comparison looks like when a real detector's output
IS included, see `lab/phase3_2_reflected_xss_test.go` and
[docs/phase-3-2-acceptance-test.md](phase-3-2-acceptance-test.md).)

This is the honest, correct answer — not a placeholder and not evidence
that detection works, because it doesn't exist yet. Once a real Phase 3
detector exists and starts populating the findings table, this exact
same test, unchanged, starts reporting real numbers. That is the whole
point of building this piece now: the comparison machinery is proven
correct today, against both synthetic data (`comparison_test.go`) and a
real-but-empty scan result, so nothing about scoring a future detector's
output needs to be invented later under time pressure.

## Docker Compose profile

`vuln` and `ssrf-internal` were added to `lab/docker-compose.yml`,
mirroring `harness_vuln.go` via a Python port of the same fixture logic
(`lab/apps/vulnerable/vuln_app.py`). Same status as every other
service in that file: **documented, syntax-validated (Python
`py_compile`, `docker-compose.yml` parsed as YAML), not exercised with
`docker compose up`** — Docker is not installed on the machine this was
built on. The Go-native harness, run via `make lab-test-phase3`, is what
this document's claims were actually verified against.

## Security isolation

- Every fixture binds to a fixed loopback address (`127.0.0.21` for
  `vuln.scanner.test`, `127.0.0.22` for `ssrf-internal.scanner.test`),
  resolved only through this process's own `dns.FakeResolver` — never
  real DNS, never a real routable address, never exposed to the public
  internet.
- No real domain, no real credential, no real external system is
  referenced anywhere in the fixtures or ground truth. Every credential,
  token, cookie value, and "secret" string is a clearly fixture-labeled
  synthetic value (e.g. `sakanner-lab-fixture-admin-token-000`).
- The lab starts and stops entirely within a `go test` process or the
  `labserver` binary — no persistent state, no system-level changes, no
  root required.

## Test lab commands

```bash
make lab-test-phase3   # Phase 3 fixtures + comparison machinery only
make lab-test          # everything under lab, Phase 1+2+3 combined
make lab-up            # standalone lab, Phase 2 fixtures only (unchanged)
make lab-up-phase3     # standalone lab, Phase 2 + Phase 3 fixtures (LAB_PHASE3=1)
make lab-down          # stop whichever is running
make lab-reset         # lab-down && lab-up
make lab-status        # is a standalone lab currently running
```

`make lab-up`'s default behavior is byte-for-byte unchanged from Phase
2 — Phase 3 fixtures are opt-in via `lab-up-phase3` (or
`LAB_PHASE3=1 ./bin/labserver` directly) specifically so nothing about
Phase 2's existing, already-verified lab startup path was touched.

## Phase 1/2 regression

Every Phase 1 and Phase 2 test still passes, unchanged, after this work
— confirmed via `go test -race -count=1 ./...` covering all 19 packages
in the module (18 with tests, `cmd/scanner` has none). See the final
report for exact counts. The only change to any pre-existing file is
two new, previously-unset struct fields on `lab.Lab`
(`VulnAddr`, `SSRFInternalAddr`) and the `labserver` binary's opt-in
`LAB_PHASE3` env var — nothing in Phase 1 or Phase 2's own logic,
tests, or ground truth was modified.
