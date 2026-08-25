# sakanner

A modular, deterministic, LLM-free CLI platform for authorized web security assessment (bug bounty programs, and systems you own or have explicit permission to test).

> **Authorized use only.** This tool enforces scope boundaries (`scanner scope`) before performing any network activity, and denies reserved/dangerous IP ranges (loopback, link-local, cloud metadata) by default. Only use it against systems you own or are explicitly authorized to test.

sakanner authorizes a target (`scanner scope add`), then runs a scan (`scanner scan <target> --profile web`) that performs recon (DNS, ports, HTTP/HTTPS probing, technology fingerprinting), same-origin crawling, application input discovery (query/form/path parameters), active vulnerability detection (reflected XSS, SQL injection, command injection, SSTI enabled by default; SSRF, path traversal, open redirect, and IDOR/BOLA available with additional configuration — see `scanner detectors list`), authenticated/multi-identity scanning, finding correlation into candidate vulnerability chains, and JSON/Markdown reporting. See [docs/operator-guide.md](docs/operator-guide.md) for a full walkthrough and `scanner <command> --help` for exact, current per-command behavior — this README's own [Usage](#usage) section below shows the same happy path. Historical per-phase build reports live under [docs/](docs/); see [Reports and design docs](#reports-and-design-docs) for the most relevant ones and [Roadmap](#roadmap) for current, known gaps.

## Requirements

- **Go 1.25.0 or later.** The module declares `go 1.25.0` in `go.mod` (this is the actual minimum enforced by a transitive dependency — verified with `go mod tidy`, not a guess). If your installed `go` is older, either upgrade it or let Go's toolchain manager auto-download a matching version (requires network access; this is the default behavior unless `GOTOOLCHAIN=local` is set).
- **No C compiler / cgo required.** Storage uses [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite), a pure-Go SQLite implementation. The project builds correctly with `CGO_ENABLED=0` and produces a statically-linked binary — verified as part of this project's clean-environment test (see [docs/phase-1-clean-environment-test.md](docs/phase-1-clean-environment-test.md)).
- **Linux (Ubuntu targeted).** This is the only platform actively tested. The crash-recovery mechanism in `internal/storage/sqlite` uses a Unix-specific PID-liveness check (`syscall.Kill(pid, 0)`) behind a build tag; a no-op fallback keeps the package building on Windows, but Windows is untested and unsupported.
- **Internet access** only if your installed Go toolchain doesn't already match `go.mod`'s version (see above) — building itself needs network access once to download the module dependencies listed in `go.sum` (or a pre-populated module cache / vendor directory).
- No other system packages, services, or external tools are required to build or run sakanner. Optional integrations with five external recon tools are supported (see [External tool integrations](#external-tool-integrations) below) — none of them are hard requirements; every stage they can replace has a fully-functional built-in Go implementation.

## Build

```bash
go build -o bin/scanner ./cmd/scanner
```

This produces a single self-contained binary at `bin/scanner`. There is no separate install/packaging step in Phase 1.

To verify your toolchain needs nothing beyond the Go compiler itself:

```bash
CGO_ENABLED=0 go build -o bin/scanner ./cmd/scanner
```

## Test

```bash
go test ./...            # full suite
go test ./... -race      # with the race detector (recommended; CI-equivalent)
```

The suite includes unit tests for every package, integration tests that exercise the real pipeline against local `httptest` servers, CLI-level end-to-end tests (`tests/e2e`) that build and drive the actual binary, and the Phase 2 Test Laboratory (`lab`, see below) that runs the real pipeline against a whole deterministic local environment and checks it against known ground truth. **None of the tests touch the live internet** — everything runs against loopback/`httptest`, so the suite is safe to run in any environment including CI.

A small number of DNS tests that do require live network access are excluded by default (behind a build tag) and can be run explicitly with:

```bash
go test -tags=integration ./internal/dns/...
```

## Configure

sakanner reads YAML configuration via `--config path/to/config.yaml`. Every setting can also be overridden with a `SAKANNER_`-prefixed environment variable (e.g. `storage.dsn` → `SAKANNER_STORAGE_DSN`); anything not set falls back to a built-in default. See [configs/config.yaml](configs/config.yaml) for a fully-commented example of every available setting.

If `--config` is omitted, or points to a file that doesn't exist, sakanner runs entirely on its built-in defaults (SQLite database at `sakanner.db` in the current directory, text logging, standard concurrency/rate-limit settings).

## Usage

```bash
# 1. Authorize the target in scope (REQUIRED — default-deny; nothing is
#    scanned without an explicit allow rule). A domain defaults to matching
#    itself + subdomains (domain_suffix); pass --exact to match only that
#    literal host. IPs/CIDRs are matched exactly/by range.
scanner --config config.yaml scope add example.com --action allow
scanner --config config.yaml scope list

# 2. Run a scan. "recon" (default) only discovers hosts/ports/services;
#    "web"/"deep" also crawl and run active vulnerability detection.
scanner --config config.yaml scan example.com --profile web

# 3. Inspect the results (scan ID is printed by "scan" above)
scanner --config config.yaml status <scan-id>
scanner --config config.yaml findings --scan <scan-id>
scanner --config config.yaml chains --scan <scan-id>
scanner --config config.yaml report --scan <scan-id> --format markdown
scanner --config config.yaml report --scan <scan-id> --format json --output report.json
```

See [docs/manual.md](docs/manual.md) for the full command-by-command reference (a Linux-man-page-style manual: every command's purpose, flags, defaults, exit codes, and verified examples) and [docs/operator-guide.md](docs/operator-guide.md) for authenticated/multi-identity scanning and other scenario walkthroughs. Run `scanner <command> --help` for the same reference embedded in the binary itself — `scanner scan --help`, `scanner detectors list`, and `scanner profiles list` are the most useful starting points. To check which optional external tools are installed and which backend each pluggable stage is configured to use, run `scanner tools status` (see [External tool integrations](#external-tool-integrations)).

There is also a legacy, recon-only path (`scanner target add` + `scanner scan --target <id>`) that predates the above and never runs detection — see `scanner target --help`. New usage should prefer `scanner scan <target>` directly.

## Architecture

```
cmd/scanner/        CLI entrypoint (cobra)
internal/
  config/           configuration loading (viper: YAML + env vars)
  logging/          structured logging (slog), tagged per scan job
  scope/            authorization boundary — the safety-critical package; see below
  target/           parses operator input into a typed Target
  storage/          repository interfaces; storage/sqlite is the concrete SQLite backend
  dns/              DNS resolution + record enumeration (native or dnsx)
  discovery/        subdomain enumeration (wordlist or subfinder)
  ports/            TCP port scanning (native connect scan or naabu)
  http/             HTTP/HTTPS probing, TLS/redirect capture (native or httpx)
  fingerprint/      technology/framework/CMS fingerprinting
  crawler/          same-origin web crawler + endpoint discovery (native or katana)
  endpoints/        normalizes crawl output into Endpoint records
  safedial/         shared scope-safe HTTP dialing used by http/ and crawler/
  orchestration/    legacy recon-only pipeline (the "scanner scan --target <id>" path)
  orchestrator/     the full-pipeline orchestrator "scanner scan <target>" actually
                    runs: scope, recon, crawl, detection, correlation, chains, risk,
                    evidence, in one ordered set of stages
  parameters/       discovers/classifies query, form, path, and JSON application
                    inputs from crawl output
  detection/        the detector-execution engine (registry, target-building,
                    mutation bridge, finding persistence) that every detector in
                    internal/detectors/ runs under
  detectors/        the vulnerability detectors themselves (one package per
                    detector) -- see "scanner detectors list" for the live registry
  mutation/         the request-mutation primitives (query/form/JSON/path/header/
                    cookie locations, safe execution) active detectors are built on
  correlation/      deduplicates raw findings into one canonical finding per
                    distinct vulnerability
  chains/           relates DIFFERENT findings into candidate vulnerability chains,
                    with per-scan/per-identity isolation (see docs/manual.md CHAINS)
  evidence/         builds/redacts the structured evidence attached to each finding
  risk/             risk scoring for canonical findings
  reporting/        JSON + Markdown report generation
  auth/             authentication profiles, identities, session/cookie handling
  storage/          repository interfaces; storage/sqlite is the concrete SQLite backend
  policy/           the recon/web/deep scan profiles (see "scanner profiles")
  findings/         reserved for future finding-lifecycle logic; not implemented (stub only)
  validation/       reserved for future non-destructive proof-of-vulnerability checks;
                    not implemented (stub only) -- detectors implement their own proof
                    strategies directly today (see internal/detectors/)
pkg/
  models/           shared data types (Target, ScanJob, Finding, ...)
  plugins/          shared external-tool plumbing: detection, the
                    auto|native|<tool> backend contract, JSON-lines
                    subprocess runner (see External tool integrations)
  utilities/        small shared helpers
tests/e2e/          full CLI-driven end-to-end tests
lab/                the local test laboratory (see below)
docs/               design notes, the full manual (docs/manual.md), and test reports
configs/            example configuration
```

**Scope enforcement is the platform's core safety property.** `internal/scope.Validator` is the single authority for whether any given host/IP may be touched, and every module that opens a network connection (`internal/ports`, `internal/http`) re-validates immediately before every single dial — not just once at the start of a scan. This defends against DNS rebinding (a domain-suffix-authorized hostname resolving to a reserved address mid-scan) and out-of-scope redirects (every hop of an HTTP redirect chain is independently re-checked). See the package doc comment in [internal/scope/scope.go](internal/scope/scope.go) for the full design rationale.

## External tool integrations

Five pipeline stages can each delegate to a matching tool from the [ProjectDiscovery](https://github.com/projectdiscovery) recon toolchain instead of sakanner's built-in Go implementation:

| Stage              | Built-in           | External tool | Config key      |
|---------------------|--------------------|----------------|------------------|
| Subdomain discovery | wordlist bruteforce | `subfinder`    | `tools.subfinder` |
| DNS record enumeration | `net.Resolver`   | `dnsx`         | `tools.dnsx`      |
| Port scanning        | TCP connect scan   | `naabu`        | `tools.naabu`     |
| HTTP probing          | native prober      | `httpx`        | `tools.httpx`     |
| Crawling              | native crawler     | `katana`       | `tools.katana`    |

Each key accepts `native` (always use the built-in implementation), `auto` (use the tool if it's found on `PATH`, otherwise fall back to native — **the default**, so an install with none of these tools present behaves identically to a build without this feature at all), or the tool's own name to require it explicitly (sakanner fails fast with an install hint if it's then missing, rather than silently falling back). Run `scanner tools status` to see what's currently detected on `PATH` and which backend each stage is configured to use.

None of these tools are required. Every one of them is optional, `go install`-able independently, and detected at run time — see [configs/config.yaml](configs/config.yaml) for the full commented reference.

**Trust boundary.** `subfinder` and `dnsx` only enumerate names; sakanner still resolves and scope-validates every result the normal way before ever dialing it, so using them changes nothing about the platform's safety guarantees. `naabu`, `httpx`, and `katana`, by contrast, open their own sockets from their own process when selected — sakanner's per-dial scope re-validation (`internal/scope`, `internal/safedial`) cannot reach into another process's `connect()` calls. sakanner still hands each of these the most restrictive input its interface allows (naabu is only ever pointed at a literal IP sakanner already resolved and approved, for example), but this is a real reduction in assurance versus the native path, and a `WARN`-level log line is emitted every time one of these three is actually selected. See the package doc comment in [pkg/plugins/plugins.go](pkg/plugins/plugins.go) for the full rationale.

## Phase 2 Test Laboratory

A deterministic, local-only environment for testing Phase 2's recon capabilities (DNS/subdomain discovery, HTTP/HTTPS probing, TLS/redirect capture, fingerprinting, crawling, endpoint discovery, scope enforcement, timeout/failure handling) against known ground truth — never against real third-party hosts, and never by comparing the scanner's output against itself.

```bash
make lab-test   # run the integration tests
make lab-up     # start a standalone lab for manual poking; make lab-down to stop
```

See [lab/README.md](lab/README.md) for a quick start and [docs/phase-2-test-lab.md](docs/phase-2-test-lab.md) for the full architecture, every scenario, ground truth, and known limitations.

## Reports and design docs

- [docs/phase-1-acceptance-test.md](docs/phase-1-acceptance-test.md) — full Definition-of-Done acceptance test (build/test/race/CLI/scope-enforcement/persistence/cancellation/concurrency/security review), with findings and fixes.
- [docs/phase-1-adversarial-test.md](docs/phase-1-adversarial-test.md) — adversarial break-it pass (scope-bypass encodings, redirect loops, resource exhaustion, process interruption), with findings and fixes.
- [docs/phase-1-clean-environment-test.md](docs/phase-1-clean-environment-test.md) — clean-environment build/install verification.
- [docs/phase-2-test-lab.md](docs/phase-2-test-lab.md) — Phase 2 Test Laboratory: architecture, scenarios, ground truth, and verification status.
- [docs/operator-guide.md](docs/operator-guide.md) — operator-facing workflow guide: unauthenticated/authenticated/multi-identity scanning, viewing findings/chains, safe manual reproduction.
- [docs/phase-3-33-active-detection-coverage-review.md](docs/phase-3-33-active-detection-coverage-review.md) — current, evidence-based inventory of every detector, what it covers, and known limitations.
- [docs/phase-3-34-cli-ux.md](docs/phase-3-34-cli-ux.md) — this phase's CLI/operator UX audit and changes.
- [docs/phase-3-36-auth-discovery.md](docs/phase-3-36-auth-discovery.md) — automatic login-form discovery (`form_login_auto`, `scanner auth discover`): design, safety analysis, and real DVWA validation.
- The remaining `docs/phase-3-*.md` files are historical per-phase build/acceptance reports, most recent last by number.

## Roadmap

Phases 1–2 built target/scope management, recon (DNS, ports, HTTP/HTTPS probing, fingerprinting, crawling, endpoint discovery) and the five optional external-tool integrations. Phase 3 (ongoing, see `docs/phase-3-*.md`) added application input discovery (query/form/path parameters), active vulnerability detection (XSS, SQLi, command injection, SSTI, SSRF, path traversal, open redirect, IDOR/BOLA — see `scanner detectors list` for what's enabled by default in this build), authenticated and multi-identity scanning, finding correlation into candidate chains, risk scoring, and evidence collection.

Known, current gaps (see [docs/phase-3-33-active-detection-coverage-review.md](docs/phase-3-33-active-detection-coverage-review.md) for the full, evidence-based review): JSON request-body inputs are supported by the mutation engine but not yet discovered by the live crawler; header/cookie-location inputs are not yet discovered or tested at all; there is no CLI command to create/edit an authentication profile or identity (config-file only — see [docs/operator-guide.md](docs/operator-guide.md) "Known gap").
