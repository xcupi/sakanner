# Phase 2 Test Laboratory

**Status: this document covers only the Test Laboratory itself** —
building it, verifying it starts and behaves as documented, and adding
the integration-test foundation that consumes it. It is **not** a Phase
2 acceptance test. No verdict on Phase 2's own correctness is made here;
see "Findings surfaced for Phase 2 QA" below for the handful of concrete
things this exercise did turn up, which the eventual Phase 2 acceptance
pass should look at.

## Why a Test Laboratory, and why two profiles

Phase 2 (recon) needs to be checked against **known ground truth**, not
against its own prior output — otherwise a regression that changes
behavior consistently would never be caught. That requires a local
environment sakanner can scan whose exact contents (hostnames, IPs,
ports, redirects, technologies, endpoints) are known in advance, is
fully under this project's control, and never touches a real
third-party host.

Two profiles exist:

1. **Go-native harness** (`lab/harness.go`) — plain
   `net/http`/`net/http/httptest` servers plus a `dns.FakeResolver`
   (already existed in `internal/dns/fake.go`, reused rather than
   duplicated), all driven directly from Go code. Needs nothing beyond
   the Go toolchain: no Docker, no root, no system DNS/hosts changes.
   **This is the profile this repository's own tests actually run, and
   the one every claim below was verified against.**
2. **Docker Compose profile** (`lab/docker-compose.yml` +
   `nginx/`, `apache/`, `apps/`, `dns/`) — real nginx, real Apache
   httpd, real dnsmasq, small Python apps for the rest. Requested
   explicitly and provided in full, but **Docker is not installed on the
   machine this was built on**, so it has not been exercised with
   `docker compose up`. See "What was and wasn't verified" below for
   exactly what partial verification was still possible without Docker
   itself.

Both profiles are built from the **same** `ground-truth.yaml` and the
**same** static fixtures (`lab/fixtures/`), so they describe one
lab, not two divergent ones.

## Architecture

```
lab/
├── ground-truth.yaml      single source of truth (hostnames, scope, IPs,
│                           expected services/endpoints/redirects/JS/tech)
├── groundtruth.go          Go structs + loader for the above
├── harness.go               Go-native lab: real HTTP(S)/TCP servers +
│                           a dns.FakeResolver, built from ground truth
├── groundtruth_test.go     ground truth parses as expected
├── harness_test.go         the harness itself starts and every service
│                           behaves as documented (no sakanner involved)
├── lab_test.go             sakanner's real orchestration.Pipeline run
│                           against the lab, asserted against ground truth
├── redirect_test.go        sakanner's real internal/safedial dialer run
│                           directly against redirect/status-code paths
├── cmd/labserver/          standalone binary for `make lab-up`
├── fixtures/               static HTML/JS shared by both profiles
├── docker-compose.yml      Docker profile (see limitations)
├── nginx/, apache/          config for the Docker profile's web servers
├── apps/                   Python apps for the Docker profile
└── dns/dnsmasq.conf         DNS zone for the Docker profile

internal/orchestration/
└── external_tool_fault_test.go   external-tool fault tolerance
                                    (malformed output / hang / non-zero
                                    exit) -- subprocess behavior, not
                                    network behavior, so it lives here
                                    rather than in the network lab
```

## DNS / hostnames

**Decision: no real DNS server for the primary (Go-native) profile.**
Every lab hostname is answered by a `dns.FakeResolver` (already existed,
reused as-is) populated from `ground-truth.yaml`. This was chosen over
both alternatives:

- **Editing `/etc/hosts`** — would modify shared system state on
  whatever machine runs the tests, which this project's own operating
  rules treat as off-limits without explicit, one-off permission; and
  it wouldn't be automatically undone if a test run is interrupted.
- **Running a real local DNS server** (dnsmasq/CoreDNS) even for the
  Go-native profile — adds a real subprocess, a real port, and real
  wire-protocol DNS parsing to every test run for no benefit: sakanner's
  `dns.Resolver` is already an interface built exactly for this
  (`internal/dns/fake.go` predates this lab), and using it keeps the
  whole test suite dependency-free and millisecond-fast.

The **Docker profile** *does* run a real DNS server (dnsmasq), since a
container-based profile has no equivalent of "just construct a Go
resolver in-process" — `lab/dns/dnsmasq.conf` is that zone, kept
in sync with `ground-truth.yaml` by hand (see the comment at its top).

Every lab hostname gets **its own distinct address**, not a shared
`127.0.0.1`:

| Hostname | Address |
|---|---|
| `scanner.test`, `www.scanner.test` (CNAME) | `127.0.0.11` |
| `api.scanner.test` | `127.0.0.12` |
| `static.scanner.test` | `127.0.0.13` |
| `redirect.scanner.test` | `127.0.0.14` |
| `js.scanner.test` | `127.0.0.15` |
| `slow.scanner.test` | `127.0.0.16` |
| `refuse.scanner.test` | `127.0.0.17` |
| `altport.scanner.test` | `127.0.0.18` |
| `ipv6.scanner.test` | `::1` (best-effort) |
| `admin.scanner.test` (CNAME), `external.scanner.test` | `203.0.113.99` |
| `another-test.local` | `203.0.113.98` |

This is deliberate, not arbitrary: **sakanner's port scanner applies the
same port list to every resolved host**. Two hostnames sharing one IP
would see each other's open ports and contaminate each other's results
(hostname A's scan would successfully connect to hostname B's port,
since it's a different port on the *same* IP, and get B's content back
under A's identity). The entire `127.0.0.0/8` range is loopback (Go's
`net.IP.IsLoopback` treats it the same as `127.0.0.1`), so
`AllowReservedRanges: true` is set for lab scans — exactly matching the
convention this codebase's other tests already use for `127.0.0.1`.

`external.scanner.test` and `another-test.local` resolve to
`203.0.113.0/24` (RFC 5737 TEST-NET-3, reserved for documentation,
guaranteed to never route to a real host) — so even a scope-enforcement
bug that let the scanner attempt a dial there would just time out
against a documentation-only network, never reach a real third party.

## Services

| Service | Hostname | What it exercises |
|---|---|---|
| "nginx" (fingerprint: `nginx/1.25.3`) | `scanner.test`, `www.scanner.test` | HTTP, web-server fingerprinting, crawling, endpoint discovery, query strings, forms, JS discovery, links to out-of-scope hosts |
| "Apache" (fingerprint: `Apache/2.4.58 (Ubuntu)`) | `api.scanner.test` | REST API, JSON endpoints, query parameters, web-server fingerprinting |
| Static site, no `Server` header | `static.scanner.test` | negative fingerprinting case |
| Redirect app | `redirect.scanner.test` | HTTP→HTTPS, multi-step, loop, redirect-to-out-of-scope, 404/403/500 |
| JavaScript app | `js.scanner.test` | JS discovery + fingerprinting (jQuery banner) |
| Slow endpoint | `slow.scanner.test` | timeout handling |
| Nothing listening | `refuse.scanner.test` | connection-refused handling |
| Non-standard port | `altport.scanner.test` | explicit-port scanning |
| IPv6 (best-effort) | `ipv6.scanner.test` | IPv6 resolution/dial |
| *(no listener at all)* | `external.scanner.test`, `admin.scanner.test`, `another-test.local` | out-of-scope references (link, redirect target, JS `src`, CNAME) that must never be dialed |

## Test scenarios (from the request) and where each is covered

| # | Scenario | Covered by |
|---|---|---|
| A | Normal HTTP | `TestLab_FullPipelineAgainstGroundTruth` (every in-scope host) |
| B | HTTPS | `TestLab_RedirectAndStatusScenarios` (real self-signed TLS via `httptest.NewTLSServer`) |
| C | HTTP → HTTPS redirect | `redirect.scanner.test` `/`, both `harness_test.go` and `redirect_test.go` |
| D | Multi-step redirect | `redirect.scanner.test` `/multi` |
| E | Redirect loop | `redirect.scanner.test` `/loop` |
| F | 404 | `redirect.scanner.test` `/missing` |
| G | 403 | `redirect.scanner.test` `/forbidden` |
| H | 500 | `redirect.scanner.test` `/error` |
| I | Query parameters | `scanner.test` `/search?...`, `api.scanner.test` `/items?...` |
| J | JavaScript discovery | `scanner.test`, `js.scanner.test` (jQuery banner, real production JS-discovery fetch+fingerprint code) |
| K | Multiple endpoints | `scanner.test`, `api.scanner.test` |
| L | Duplicate URLs | two identical-target links to `/about` on `scanner.test`, proven to dedup to one endpoint |
| M | Slow response | `slow.scanner.test` |
| N | Connection failure | `refuse.scanner.test` |
| O | Out-of-scope URL | `external.scanner.test`, `admin.scanner.test`, `another-test.local`, reached via a link, a redirect target, a `<script src>`, and a CNAME |
| P | Non-standard port | `altport.scanner.test` |
| Q | IPv4 | every service above |
| R | IPv6 | `ipv6.scanner.test` (best-effort; skips gracefully if the sandbox has no IPv6 loopback) |

## Ground truth

`lab/ground-truth.yaml` is the single source of truth: hostnames,
DNS records (A/AAAA/CNAME), scope classification (in-scope vs
out-of-scope, and *why* — see below), per-service expected technology,
endpoints, JavaScript files, and redirect/status-code behavior. Both the
harness (`groundtruth.go`'s `LoadGroundTruth`) and every test read this
one file, so they cannot silently drift apart from each other. Every
number and path in it was checked against a real run of the actual
scanner pipeline before being committed — none of it is assumed (see
"Findings surfaced for Phase 2 QA" for two cases where the first draft
was wrong and was corrected against real output rather than the other
way around).

**Query parameters, precisely:** sakanner's endpoint discovery
(`internal/endpoints`) preserves a discovered URL's full query string as
part of `Endpoint.Path` — this lab validates exactly that. Extracting
individual parameter *names* into their own model
(`pkg/models.Parameter`) is a documented future-phase feature
(`internal/parameters` is still a stub); this lab does not test a
feature that doesn't exist yet.

### Scope, and why it's not one broad rule

The lab deliberately does **not** use a single `domain_suffix` allow
rule for `*.scanner.test`, because two of the out-of-scope hostnames
(`admin.scanner.test`, `external.scanner.test`) are themselves
subdomains of `scanner.test` — a realistic scoping mistake this lab
exists to catch. Instead, scope is granted per-hostname (`exact_host`
allow), and everything else is denied purely by sakanner's fail-closed
default (**no matching rule = deny**) — not by an explicit deny rule.
This is the stronger test: it proves default-deny actually works for a
domain that superficially "looks like" an authorized subdomain, not just
that an explicit deny overrides an allow.

## How to run

```bash
make lab-test          # the integration tests (starts/stops the lab itself)
make lab-up            # standalone lab for manual poking (curl, etc.)
make lab-down          # stop it
make lab-reset         # lab-down + lab-up
```

Or without `make`:

```bash
go test ./lab/... -race -v
go run ./lab/cmd/labserver   # blocks until Ctrl+C
```

`make lab-test` / `go test ./lab/...` need nothing installed
beyond the Go toolchain already required to build sakanner itself — the
lab starts and stops automatically, per test run, in-process. There is
no persistent state to reset between runs (each `Start` call builds a
fresh set of servers and a fresh `FakeResolver`), so "reset" for this
profile is simply "run it again."

### Docker profile

```bash
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml down -v
```

**Not run in this repository** (Docker is not installed on the machine
this was built on) — see "What was and wasn't verified."

## What was and wasn't verified

**Go-native harness — fully verified, by running it:**
- Every service starts and responds (`TestLab_AllServicesStartAndRespond`).
- `refuse.scanner.test`'s port genuinely refuses connections
  (`TestLab_RefusePortRefusesConnections`).
- The slow endpoint genuinely exceeds a short client timeout
  (`TestLab_SlowEndpointExceedsShortTimeout`).
- The redirect app's every path behaves as documented, independent of
  sakanner (`TestLab_RedirectChainHTTPToHTTPS`, `TestLab_LoopIsTruncatedByClient`,
  `TestLab_StatusCodeScenarios`).
- sakanner's **real** `orchestration.Pipeline` run against the whole lab
  in one job, asserted against ground truth for assets, hosts, services,
  HTTP services, technologies, endpoints (including dedup), DNS/CNAME
  records, timeout handling, connection-refusal handling, non-standard
  ports, and out-of-scope exclusion (`TestLab_FullPipelineAgainstGroundTruth`,
  10 sub-tests).
- sakanner's **real** `internal/safedial` dialer (the same code
  `internal/http.Prober` and `internal/crawler` use) run directly
  against every redirect/status-code path, including a redirect
  *to an out-of-scope host*, proven truncated rather than followed
  (`TestLab_RedirectAndStatusScenarios`, `TestLab_ExternalRedirectNeverDialsOutOfScopeHost`).
- External-tool fault tolerance: malformed output, non-zero exit, and a
  genuinely-hanging subprocess (verified to actually take ~3s until the
  context deadline, not return early by coincidence — see the finding
  below) against the real `orchestration.Pipeline`
  (`internal/orchestration/external_tool_fault_test.go`).
- Repeated `go test ./lab/... -race -count=3` with no flakiness.
- `make lab-up` / `make lab-down` / `make lab-reset` run for real: process
  starts, is reachable over real TCP, is killed cleanly, pidfile handling
  is idempotent.

**Docker profile — NOT verified with `docker compose up`** (no Docker on
this machine). What partial verification *was* still possible, and was
done:
- `docker-compose.yml` and `ground-truth.yaml` both parse as valid YAML
  (`python3` + PyYAML).
- Every volume-mount source path in `docker-compose.yml` was confirmed
  to exist on disk.
- Every Python app (`lab/apps/*/*.py`) was byte-compiled
  (`python3 -m py_compile`) **and actually run standalone** (outside
  Docker, on an alternate unprivileged port) and exercised with `curl`
  for every documented path/status code — this caught and fixed a real
  bug (see below).
- `lab/dns/dnsmasq.conf` was run with the **real** `dnsmasq`
  binary (present on this machine, version 2.92) on an alternate port,
  and queried both with `dig` and with a Go program using
  `net.Resolver` — this caught and fixed a real bug (see below).
- `nginx/nginx.conf` and `apache/httpd.conf` were reviewed by hand but
  **not** executed (neither binary is installed here) — treat these two
  specifically as unverified until run through real nginx/Apache.

## Findings surfaced for Phase 2 QA

None of these were fixed in Phase 2 production code — per this task's
scope, this pass only builds and verifies the lab. They're recorded here
for the actual Phase 2 acceptance pass to weigh in.

1. **Cross-origin `<script src>` references are recorded as
   same-service endpoints with host information discarded.**
   `scanner.test`'s test page includes
   `<script src="http://external.scanner.test/evil.js">` (deliberately,
   to exercise "the scanner encounters an out-of-scope JS reference").
   The crawler's `Page.Scripts` field records every `<script src>`
   unconditionally regardless of origin (only the later
   fetch-and-fingerprint stage filters to same-origin before ever
   dialing — see `internal/orchestration/pipeline.go`'s
   `discoverJavaScriptTechnologies`), and `endpoints.Normalize`'s
   `pathOf()` extracts only the path component, discarding the host. Net
   effect: `/evil.js` shows up as an `Endpoint` row attached to
   `scanner.test`'s `HTTPService`, even though it was never fetched and
   `external.scanner.test` was never dialed (confirmed separately — no
   `Asset`/`Host` row for it exists after the scan). **Not a scope-safety
   bug** — confirmed no network activity reaches the out-of-scope
   host — but a data-completeness quirk in endpoint bookkeeping worth a
   look.
2. **`Prober.Probe` and the crawler's start page both only ever fetch
   `/`.** Neither takes a path argument. This is why
   `redirect.scanner.test`'s multi-step/loop/out-of-scope-redirect/
   status-code scenarios had to be tested by pointing
   `internal/safedial` directly at those sub-paths
   (`lab/redirect_test.go`) rather than through the ordinary
   pipeline/crawl flow — scanning `redirect.scanner.test` as a normal
   target only ever exercises its root path's behavior (which is itself
   the HTTP→HTTPS redirect case). This isn't a bug, just a real
   architectural constraint worth knowing about when reading or
   extending this lab's tests.
3. **(Docker profile only) dnsmasq's local `cname=` directive did not
   reliably resolve through every DNS client tested.** A live test (real
   `dnsmasq` 2.92, `--no-resolv`, run directly on this machine, queried
   with `dig` and with Go's own `net.Resolver`) found that `cname=`
   answers with *only* the CNAME record — no A record chained into the
   same response — and that Go's resolver (even with `PreferGo: true`)
   did not reliably follow it to a final address through this server.
   Fixed in `lab/dns/dnsmasq.conf` by using plain `address=`
   entries (resolving directly to the target IP) for `www.scanner.test`
   and `admin.scanner.test` instead of relying on live CNAME chasing —
   re-verified working after the fix. This is a Docker-profile-only
   concern; the Go-native harness never relied on live CNAME chasing to
   begin with (it populates `dns.FakeResolver`'s `Hosts` and `CNAMEs`
   maps independently).
4. **(Docker profile only, now fixed) the mock API app sent a duplicate,
   malformed `Server` header.** `http.server.BaseHTTPRequestHandler`
   appends `sys_version` (e.g. `Python/3.11.4`) to `server_version`
   automatically *and* the app was also sending its own explicit
   `Server` header — result, two `Server` headers, the first reading
   `Apache/2.4.58 (Ubuntu) Python/3.11.4`. Harmless for sakanner's own
   regex-based fingerprinting (still matched), but not what a real
   Apache server sends. Fixed by overriding `version_string()` in
   `lab/apps/api/api.py`; re-verified with a real local run and
   `curl -D -` showing exactly one correct header.
5. **A genuine test-authoring bug caught before it shipped:** an early
   draft of the external-tool "hang" test
   (`TestRun_SubfinderHangDoesNotHangScan`) used `sleep 30` in a fake
   binary, but the test also does `t.Setenv("PATH", ...)`, which
   *replaces* `PATH` rather than prepending to it — so `sleep` (an
   external binary) couldn't be resolved, and the fake tool exited
   immediately with "command not found" instead of actually hanging. The
   test still passed (a fast, error-free return also satisfies "does not
   hang"), which would have made it a silent false positive forever.
   Caught by checking *why* a "hang" test returned in 2ms instead of
   ~3s, not by trusting the green checkmark. Fixed by using a
   pure-POSIX-builtin busy loop (`while :; do :; done`, using only the
   `:` builtin) and adding a lower bound on elapsed time to the
   assertion, so a future regression of this exact kind would fail
   loudly instead of silently passing.

## Known limitations

- The Docker Compose profile has not been exercised with
  `docker compose up`; see "What was and wasn't verified" for exactly
  what partial verification was possible without it, and finding #3
  above for a bug that verification already caught and fixed.
- `nginx/nginx.conf` and `apache/httpd.conf` were reviewed but not
  executed against real nginx/Apache binaries.
- IPv6 coverage (`ipv6.scanner.test`) is best-effort: if the sandbox
  running the tests has no IPv6 loopback, that one host's tests skip
  rather than fail. Verified working on the machine this was built on.
- The Docker profile's `redirect-https` service is, honestly, still
  plaintext HTTP on a second published port (a documented
  simplification) — real TLS/HTTPS coverage comes from the Go-native
  harness, which does use a genuine self-signed certificate via
  `httptest.NewTLSServer`.
- Per-parameter extraction (`pkg/models.Parameter`) is not tested here
  because it does not exist yet in Phase 2 — only query-string
  preservation within `Endpoint.Path` is.
- Query-parameter/redirect/JS-discovery/endpoint-discovery scenarios are
  proven only against sakanner's **native** implementations of each
  stage; the external-tool-backed alternatives (subfinder/dnsx/naabu/
  httpx/katana) already have their own adapter-level unit tests (see
  `internal/{discovery,dns,ports,http,crawler}/*_test.go` from earlier
  Phase 2 work) plus the pipeline-level fault-tolerance tests added here
  — this lab does not additionally re-run every scenario through every
  external-tool backend, which would multiply test count without adding
  much beyond what's already covered.

## Acceptance criteria

| Criterion | Status |
|---|---|
| All required services start | PASS (Go-native harness, live-verified; Docker profile config exists, not execution-verified) |
| Health checks pass | PASS (every service responds correctly per `TestLab_AllServicesStartAndRespond`) |
| Test hostnames resolve | PASS (`dns.FakeResolver`, all 13 hostnames, live-verified) |
| HTTP works | PASS |
| HTTPS works | PASS (real self-signed TLS via `httptest.NewTLSServer`) |
| Redirect scenarios work | PASS (single-hop, multi-step, loop, out-of-scope target, all live-verified against real `safedial`) |
| API works | PASS (`api.scanner.test`, JSON endpoints with query parameters) |
| JavaScript test works | PASS (`js.scanner.test` + `scanner.test`, jQuery banner fingerprinted) |
| Non-standard port works | PASS (`altport.scanner.test`, explicit `--ports`) |
| Slow endpoint works | PASS (client timeout exceeded deterministically, scan still completes) |
| Failure scenario works | PASS (`refuse.scanner.test`, connection refused, scan still completes) |
| Out-of-scope target is reachable as a reference but is not scanned | PASS (link, redirect target, `<script src>`, and CNAME all tested; zero `Asset`/`Host` rows for any out-of-scope hostname after a real scan) |
| Ground truth exists | PASS (`lab/ground-truth.yaml`) |
| Integration tests can consume the ground truth | PASS (`groundtruth.go` loader + every test in `lab/*_test.go`) |
| Lab can be reset | PASS (`make lab-reset`, live-tested) |
| Lab can be stopped | PASS (`make lab-down`, live-tested, idempotent) |
| Documentation is complete | PASS (this document + `lab/README.md`) |

**Docker Compose profile specifically:** PARTIAL — the configuration is
complete and its DNS component plus every custom app were independently
live-verified outside Docker (and one real bug was found and fixed in
each), but the profile as a whole has not been run with
`docker compose up` since Docker is not installed on this machine. See
"What was and wasn't verified."

---

## TEST LAB STATUS: PASS

Every acceptance criterion is satisfied by the Go-native harness, which
is what this repository's own test suite (`make lab-test` /
`go test ./lab/...`) actually runs and what every claim above was
verified against. The Docker Compose profile is complete and provided as
requested, with as much independent verification as was possible without
Docker itself (and two real bugs it surfaced already fixed), but is
PARTIAL pending an actual `docker compose up` run in an environment that
has Docker.

This pass adds the Test Laboratory and its integration-test foundation
only. **Phase 2 itself has not been re-acceptance-tested here** — see
"Findings surfaced for Phase 2 QA" above for what this exercise did turn
up for that future pass to look at. Per the task's explicit instruction,
this stops here: no Phase 2 acceptance verdict, no Phase 3 work.
