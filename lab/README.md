# sakanner Test Laboratory

An intentionally vulnerable/benign test target for sakanner's own
integration tests -- **external to the production scanner**: nothing
under `cmd/`, `internal/`, or `pkg/` imports this directory, or knows
it exists. See [docs/lab-isolation-review.md](../docs/lab-isolation-review.md)
for the full architectural review and dependency verification behind
that claim.

For the full narrative:
- Phase 2 (recon lab -- hosts, ports, HTTP, fingerprinting): [docs/phase-2-test-lab.md](../docs/phase-2-test-lab.md)
- Phase 3 (vulnerable/safe fixture pairs, ground truth, comparison machinery): [docs/phase-3-test-lab.md](../docs/phase-3-test-lab.md)
- Architectural separation from the production scanner: [docs/lab-isolation-review.md](../docs/lab-isolation-review.md)
- Phase 3.14 (authentication/session foundation): [docs/phase-3-14-authentication.md](../docs/phase-3-14-authentication.md)

## How to start the lab

**In tests (the normal case)** -- nothing to do. Every test that needs
the lab starts and stops it itself, in-process, per test run:

```go
gt, _ := lab.LoadGroundTruth()
l, _ := lab.StartWithVulnerabilities(gt) // or lab.Start(gt) for Phase 2 fixtures only
defer l.Close()
```

Each phase's own fixtures are additive supersets, called instead of the
one before when a test needs them: `Start` (Phase 2) ->
`StartWithVulnerabilities` (+ Phase 3 vulnerable/safe pairs) ->
`StartWithInputFixtures` (+ Phase 3.13 input-discovery fixtures) ->
`StartWithAuthFixtures` (+ Phase 3.14 authentication fixtures, see
below). Calling a later one always starts everything the earlier ones
do too.

No Docker, no root, no system DNS changes, nothing to clean up by hand.

**As a standalone process** (to poke at manually with `curl`, or to
point a real `scanner` CLI invocation at):

```bash
make lab-up          # Phase 2 fixtures only (hosts/ports/HTTP/fingerprinting)
make lab-up-phase3    # Phase 2 + Phase 3 (vulnerable/safe application fixtures)
```

This builds and backgrounds `lab/cmd/labserver`, prints every fixture's
resolved address, and writes its PID to `/tmp/sakanner-labserver.pid`.

## How to stop / reset the lab

```bash
make lab-down    # stop whichever standalone lab is running
make lab-reset    # lab-down && lab-up
make lab-status   # is a standalone lab currently running
```

Test-driven lab instances (`lab.Start`/`lab.StartWithVulnerabilities`
called directly from a test) need no manual stop/reset at all -- each
test's own `defer l.Close()` (or `t.Cleanup(l.Close)`) tears it down
when that test ends, regardless of pass/fail.

## Run the integration tests

```bash
make lab-test            # everything -- Phase 2 + Phase 3 combined
make lab-test-phase3     # Phase 3 fixtures + ground-truth comparison only
# or directly:
go test ./lab/... -race -v
```

## Which vulnerabilities each lab application represents

Every fixture is a **real, working implementation** of the vulnerable
(or correctly-safe) behavior -- not a hard-coded fake finding. The
single source of truth for every scenario, its expected behavior, and
which are currently detectable is
[`ground-truth-vulnerabilities.yaml`](ground-truth-vulnerabilities.yaml)
(Phase 3) and [`ground-truth.yaml`](ground-truth.yaml) (Phase 2 recon).
This table summarizes by vulnerability class; see the YAML for the full
per-fixture list (each class has one or more vulnerable/safe pairs,
`VULN-<CLASS>-*` / `VULN-<CLASS>-*-NEG-*`).

| Class | Vulnerable endpoint(s) | Covered by a detector today? |
|---|---|---|
| Reflected XSS | `/xss/reflected/vulnerable`, `/xss/reflected/attribute/vulnerable` | Yes -- `internal/detectors/xssreflected` |
| Stored XSS | `/xss/stored/*` | Not yet -- fixture only |
| SQL injection (error-based, boolean-based) | `/sqli/vulnerable`, `/sqli/boolean/vulnerable` | Yes -- `internal/detectors/sqli` |
| Authentication weakness (default/weak credentials) | `/auth/weak-credentials` | Not yet -- fixture only |
| IDOR / BOLA (path segment, query parameter, JSON API) | `/idor/vulnerable/user/{id}`, `/idor/api/resource/vulnerable?resource_id=...` | Partially -- `internal/detectors/idor` (query-parameter form only; path-segment form is intentionally undetectable today, see `ground-truth-vulnerabilities.yaml`'s `requires_capability` on `VULN-IDOR-001`) |
| Path traversal / LFI (query parameter, JSON API) | `/files/traversal/vulnerable?name=...`, `/files/lfi/vulnerable?page=...`, traversal API variants | Yes -- `internal/detectors/traversal` |
| Command injection (JSON API) | command-injection API variants (see YAML) | Yes -- `internal/detectors/cmdinjection` |
| SSRF | SSRF fixture reaching `ssrf-internal.scanner.test` | Yes -- `internal/detectors/ssrf` (needs an out-of-band callback client configured -- see `docs/phase-3-4-ssrf.md`) |
| Open redirect | open-redirect fixture | Not yet -- fixture only |
| Stack trace / misconfiguration exposure | misconfig fixture | Not yet -- fixture only |
| Information exposure | info-exposure fixture | Not yet -- fixture only |
| Insecure cookie flags | insecure-cookie fixture | Not yet -- fixture only |
| Permissive CORS | CORS fixture | Not yet -- fixture only |
| Missing security headers | missing-headers fixture | Not yet -- fixture only |

The classes with no detector yet exist precisely to support **future
expansion** without any further lab work -- see "Future expansion"
below.

## Which credentials exist

All credentials below are **synthetic, fixture-only strings with no
relationship to any real system or account** (declared as such
directly in `harness_vuln.go`'s own comments).

| Fixture | Username / identity | Secret | Purpose |
|---|---|---|---|
| `/auth/weak-credentials` | `admin` | `admin` | Deliberately weak/default credential pair |
| `/auth/strong-credentials` | `testuser` | `Xk9#mP2vQ7zL!bR4-fixture-only` | Deliberately strong credential pair (negative control) |
| `/idor/vulnerable/user/{id}`, `/idor/safe/user/{id}` | a `session` cookie shaped like `user<id>` | none (cookie presence is the only "auth") | Session-based horizontal-authorization fixture pair |
| `/idor/api/resource/*` | an `X-Test-Auth-User` header, one of `user-a` / `user-b` | none | The lab's "Account A / Account B" fixture -- see "Future expansion" |
| `auth.scanner.test` (`/login`) | `userA` | `Str0ngPass-A-fixture-only` | Phase 3.14 form-login "Account A" |
| `auth.scanner.test` (`/login`) | `userB` | `Str0ngPass-B-fixture-only` | Phase 3.14 form-login "Account B" |

All of the above are **test-only, intentionally hard-coded credentials
with no relationship to any real system or account** -- declared as
such directly in the fixture source (`harness_auth.go`) and never used
anywhere outside this lab.

## Authentication fixtures (Phase 3.14)

`auth.scanner.test` (started via `lab.StartWithAuthFixtures`) is a
small, realistic session-based login application -- a real form login
flow (including a hidden CSRF field that must round-trip unmodified),
a real server-side session store, and two endpoints gated on a genuine
session-cookie check, used to test `internal/auth`'s `FORM_LOGIN`
provider end to end.

| Path | Method | Auth required? | Purpose |
|---|---|---|---|
| `/public` | GET | No | Task's "public endpoint" -- always reachable |
| `/login` | GET | No | Serves the login form (hidden `csrf_token` field must be preserved and echoed back) |
| `/login` | POST | No (this IS the login) | Validates `username`/`password` against Account A/B; on success sets a `sakanner_session` cookie and redirects to `/account`; on failure returns 401 with **no** cookie set -- never "200 regardless of credentials" |
| `/account` | GET | Yes (`sakanner_session` cookie) | Task's "authenticated endpoint" -- 401 without a valid session; on success, its body links to `/dashboard` |
| `/dashboard` | GET | Yes (`sakanner_session` cookie) | Task's "authenticated endpoint requiring session cookie" -- reachable ONLY via the link inside `/account`'s authenticated response, never linked from the public root page. This is deliberate: it is what makes "an authenticated crawl discovers `/dashboard`, an unauthenticated one never does" an observable, directly-testable fact (see `phase3_14_auth_test.go`'s vertical-slice test) rather than merely a difference in response body content. |
| `/login-external-action` | GET | No | Adversarial fixture: a login form whose `action` points at the pre-existing, out-of-scope `external.scanner.test` host -- for "form action outside scope" testing |
| `/login-external-redirect` | GET/POST | No | Adversarial fixture: validates credentials correctly but redirects to `external.scanner.test` on success -- for "redirect outside scope" testing |

Session tokens are cryptographically random per login (a real
application's own behavior), which does **not** make the scanner's own
authentication behavior non-deterministic -- see
[docs/phase-3-14-authentication.md](../docs/phase-3-14-authentication.md)
"Determinism" for why token randomness and scanner-observable-state
determinism are different properties.

Malformed/duplicate Set-Cookie handling, oversized responses, login
timeouts, and an unreachable login server are NOT separately fixtured
in the lab -- they are covered exhaustively by `internal/auth`'s own
unit tests against local, purpose-built `httptest` servers (see
`internal/auth/formlogin_test.go`), which is a faster and equally
rigorous surface for those specific edge cases than adding more lab
fixtures would be.

`auth.scanner.test` is not currently wired into the standalone
`lab/cmd/labserver` binary (`make lab-up`) -- consistent with how Phase
3.13's `inputs.scanner.test` fixture was also left test-only rather
than added to the interactive binary; both are exercised via `go test
./lab/...`, which is this lab's primary, fully-covered test surface.

## Which endpoints are intentionally vulnerable

Every path containing `vulnerable` (e.g. `/sqli/vulnerable`,
`/idor/vulnerable/user/`, `/files/traversal/vulnerable`) is
intentionally, verifiably exploitable in the way its name describes --
this is the entire point of the fixture, not an accident. Every
corresponding `safe`/negative path (`/sqli/safe`, `/idor/safe/user/`,
`/files/traversal/safe`, and the various `*-NEG-*` ground-truth
entries) implements the CORRECT, non-vulnerable behavior for the same
operation, so a detector's false-positive rate can be measured, not
just its true-positive rate. Never point anything other than this lab
or a scanner you are authorized to test at these paths -- they exist
to be broken, safely, in a fully isolated, loopback-only environment.

## How the scanner is expected to interact with the lab

- **From a test running in the same process** (`go test ./lab/...`,
  or any `internal/*` package's own tests that construct a real
  `orchestrator.Orchestrator`/`orchestration.Pipeline` against the
  lab): pass `l.Resolver` (a `*dns.FakeResolver`) as the scanner's
  `Resolver` -- hostnames like `scanner.test`, `vuln.scanner.test`
  only resolve through this in-process fake resolver, never through
  real DNS.
- **From a real CLI subprocess** (`tests/e2e`, which builds and execs
  the actual `scanner` binary): the fake resolver is invisible to a
  separate OS process, so tests instead point the CLI directly at the
  fixture's literal loopback IP:port (e.g. `l.VulnAddr`,
  `net.SplitHostPort` to get the bare IP for `scanner scan <ip>
  --ports <port>`).
- **Scope is never implicit.** Every test adds an explicit
  `models.ScopeRule` (or, at the CLI level, runs `scanner scope add
  <host>`) before scanning a fixture -- the lab does not grant scope
  authorization on the scanner's behalf, and no fixture is reachable
  through the scanner's own default-deny model without one. This
  mirrors exactly how an operator would authorize a real target.
- **`AllowReservedRanges` must be set** for any scope validator/scan
  targeting the lab, since every fixture address is loopback
  (`127.0.0.0/8`), which sakanner's scope model treats as reserved
  (and therefore denied) by default outside test contexts.

## Future expansion

The lab already has groundwork for everything the architecture review
asked it to support going forward, without further structural change:

- **Anonymous vs. authenticated testing**: fully implemented as of
  Phase 3.14 -- `auth.scanner.test` provides a real form-login flow,
  real session cookies, and endpoints that behave differently
  authenticated vs. not (see "Authentication fixtures" above); the
  older `/auth/*` weak-credential fixtures and `/idor/api/resource/*`'s
  `X-Test-Auth-User` header remain as separate, complementary fixtures
  for their own (unrelated) vulnerability classes.
- **Account A / Account B**: already implemented two ways --
  `idorAPIResources` in `harness_vuln.go` (a synthetic two-user
  ownership map, header-identified) and, as of Phase 3.14,
  `auth.scanner.test`'s real `userA`/`userB` form-login accounts
  (session-cookie-identified) -- exactly the shapes a future Tier-S
  cross-account authorization ENGINE (explicitly out of scope for
  Phase 3.14 itself -- see docs/phase-3-14-authentication.md
  "Limitations") would need two independently-authenticated `Session`
  values for.
- **IDOR/BOLA, API testing, XSS, SQL injection, SSRF, path traversal,
  command injection**: all already have at least one vulnerable/safe
  fixture pair (see the vulnerability table above); additional
  variants follow the exact same `mux.HandleFunc(...)` +
  `ground-truth-vulnerabilities.yaml` entry pattern every existing one
  already uses.
- **Future Tier-S vulnerabilities**: `ground-truth-vulnerabilities.yaml`
  already carries several classes with no detector yet (stored XSS,
  open redirect, misconfiguration/stack-trace exposure, information
  exposure, insecure cookies, permissive CORS, missing security
  headers) -- a future detector phase can start scanning these fixtures
  on day one without touching the lab at all.

## Files

| Path | Purpose |
|---|---|
| `ground-truth.yaml` | Phase 2 single source of truth for every recon scenario -- read by both the harness and the tests. |
| `harness.go`, `groundtruth.go` | The Go-native Phase 2 lab: real local HTTP(S)/TCP servers + a `dns.FakeResolver`, verified by this repo's own test suite. |
| `harness_test.go`, `lab_test.go`, `redirect_test.go`, `groundtruth_test.go` | The Phase 2 integration tests themselves. |
| `harness_inputs.go` | Phase 3.13's parameter/input-discovery fixture app (`inputs.scanner.test`) -- query params, forms, an out-of-scope form action, malformed HTML. |
| `harness_auth.go`, `phase3_14_auth_test.go` | Phase 3.14's authentication fixture app (`auth.scanner.test`, `StartWithAuthFixtures`) -- real form login, session cookies, authenticated endpoints -- and its real-orchestrator integration tests. |
| `ground-truth-vulnerabilities.yaml` | Phase 3 single source of truth: every vulnerable/safe fixture pair, scope-enforcement scenarios, authentication coverage. |
| `harness_vuln.go`, `groundtruth_vuln.go` | The Go-native Phase 3 fixtures (`StartWithVulnerabilities`, a superset of Phase 2's `Start`) + their ground-truth loader. |
| `comparison.go`, `comparison_test.go` | Expected-vs-actual finding comparison machinery (true positive / false positive / false negative / duplicate). |
| `callback.go`, `callback_test.go` | Phase 3.4's out-of-band SSRF callback recorder, used by `internal/detectors/ssrf`'s real detector against this lab. |
| `phase3_lab_test.go`, `phase3_1_detection_test.go` .. `phase3_13_inputs_test.go` | The scanner's own integration tests: fixtures reachable, positives exhibit the bug, negatives don't, SSRF isolation, scope enforcement, determinism, ground-truth comparison against a real scan, one file per phase. |
| `cmd/labserver/` | Standalone binary for `make lab-up` (Phase 2 only) / `make lab-up-phase3` (`LAB_PHASE3=1`, adds Phase 3 fixtures). |
| `fixtures/` | Static HTML/JS content served by both the Go-native harness and the Phase 2 Docker profile. |
| `docker-compose.yml`, `nginx/`, `apache/`, `apps/`, `dns/` | Docker Compose profile -- an alternative to the Go-native harness, using real nginx/Apache/dnsmasq plus a Python mirror of the Phase 3 fixtures (`apps/vulnerable/vuln_app.py`). **Not exercised with `docker compose up` in this repo** (Docker isn't installed on the machine this was built on); see `docs/phase-2-test-lab.md` and `docs/phase-3-test-lab.md` for exactly what was and wasn't verified. |

External-tool (subfinder/httpx/naabu/dnsx/katana) fault-tolerance tests
live in [internal/orchestration/external_tool_fault_test.go](../internal/orchestration/external_tool_fault_test.go),
not here -- they're subprocess-behavior tests, not network-behavior
tests, and reuse the existing `testutil.WriteScript` fake-binary
pattern already used throughout Phase 2's own adapter tests.
