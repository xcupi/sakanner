# SAKANNER(1)

## NAME

sakanner — modular, deterministic, LLM-free CLI for authorized web security assessment

## SYNOPSIS

```
scanner [--config <path>] <command> [subcommand] [arguments] [flags]
```

## DESCRIPTION

sakanner authorizes a target, scans it, and lets you inspect exactly
what was found and why — every step through an explicit, scriptable
CLI command, never a hidden action. It performs recon (DNS, ports,
HTTP/HTTPS probing, technology fingerprinting), same-origin crawling,
application input discovery (query/form/path parameters), active
vulnerability detection, authenticated and multi-identity scanning,
finding correlation into candidate vulnerability chains, and
JSON/Markdown reporting.

sakanner is **default-deny**: no request is ever made against a target
that doesn't match an explicit `scanner scope add` rule, regardless of
which command or profile is used.

Typical workflow:

```
scanner scope add <target>      # authorize (required, default-deny)
scanner scan <target>           # run a scan
scanner findings --scan <id>    # inspect what was found
scanner chains --scan <id>      # inspect related-finding chains
scanner report --scan <id>      # export everything as one document
```

Every command is read-only except `target add`, `scope add`/`remove`,
and `scan` itself. Nothing else mutates persistent state or performs
network activity. Run `scanner <command> --help` for any command's
full detail and examples — that text is authoritative and always
matches the binary you're actually running; this manual is the
narrative companion to it, not a replacement.

This manual describes the CLI as currently implemented. It is not
organized by development phase, and it does not describe capabilities
that don't exist yet — see [TROUBLESHOOTING](#troubleshooting) and
each section's own "Known limitations" for honest gaps.

## COMMANDS

### scanner scope

Manage the scope rules that authorize (or explicitly exclude) targets.

```
scanner scope add <value> [--action allow|deny] [--exact] [--note <text>]
scanner scope list
scanner scope remove [<rule-id>] [--value <v>]
```

- **Purpose**: the single authorization boundary. No active request
  (port scan, HTTP probe, detection) is ever made against a target
  without a matching `allow` rule.
- **State**: `add`/`remove` mutate persistent state (the scope-rules
  table). `list` is read-only. None of the three perform network
  activity themselves.
- **Rule types** (inferred from the value, or `--exact`): `exact_host`
  (one literal host/IP), `domain_suffix` (a domain and all its
  subdomains — the default for a bare domain), `cidr` (an IP range).
- **Precedence**: a `deny` rule always overrides a matching `allow`
  rule for the same target, regardless of add order. An unmatched
  target is denied by default — there is no way to scan something
  with no matching allow rule.
- **Duplicates**: adding an identical rule twice is allowed; each gets
  its own ID and independent lifecycle.

Verified example:

```
$ scanner --config config.yaml scope add 127.0.0.21
added scope rule: allow exact_host 127.0.0.21 id=ba294676-b704-410f-8feb-c0339b56bb9d

$ scanner --config config.yaml scope list
ID                                    ACTION  TYPE        VALUE       NOTE
ba294676-b704-410f-8feb-c0339b56bb9d  allow   exact_host  127.0.0.21
```

`scope remove` accepts a rule ID, `--value <exact-match>`, or (with no
argument and an interactive terminal) a numbered prompt. It fails
cleanly rather than hanging if run non-interactively with neither.

Missing-argument error (verified):

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

### scanner target

Manage registered targets for the **legacy, recon-only** scan path.

```
scanner target add <value> [--note <text>]
scanner target list
```

A normal, full-pipeline scan does **not** need this command — pass the
host/domain/IP directly to `scanner scan`. `target add` +
`scanner scan --target <id>` is a separate, older path that performs
discovery only (hosts, ports, HTTP services, technologies) — no
crawling, detection, correlation, risk scoring, or evidence
collection, and `--profile` has no effect on it. It exists for
backward compatibility.

Verified example:

```
$ scanner --config config.yaml target add 127.0.0.21 --note "manual example"
added target 127.0.0.21 (ip) id=69324465-a9fe-4a90-b3c1-d78b96a23e33

$ scanner --config config.yaml target list
ID                                    VALUE       TYPE  NOTE            CREATED
69324465-a9fe-4a90-b3c1-d78b96a23e33  127.0.0.21  ip    manual example  2026-08-24T23:29:58Z
```

An `allow` scope rule is still required before either path may touch
anything.

### scanner scan

Run a scan. This is the only command that performs network activity
and the only one (besides `target add`/`scope add`/`remove`) that
mutates persistent state — it creates a scan job and everything
discovered under it.

```
scanner scan <target> [--profile recon|web|deep] [--ports <list>]
               [--timeout <duration>]
               [--auth-profile <name> | --identity <name> [--authz-identity <name>]]

scanner scan --target <id> [--target <id> ...] [--ports <list>]   # legacy, recon-only
```

- **`--profile`**: `recon` (default) is discovery-only — crawler and
  detection both disabled. `web` adds bounded crawling (depth 2, 20
  pages) and vulnerability detection. `deep` widens both bounds
  (depth 4, 75 pages) without changing which detectors run. An
  explicit `--profile` always overrides both the `recon` default and a
  `crawler.enabled: true` config setting. **Verified behavioral
  nuance**: if `--profile` is omitted but the config file sets
  `crawler.enabled: true`, the scan resolves to the `web` profile, not
  `recon` — the scan's own printed output says
  `Profile: web (config-driven, no --profile given)` in that case, so
  you can always see which profile actually ran.
- **`--ports`**: comma-separated, overrides the config default.
- **Authentication**: entirely opt-in (omit all three flags to scan
  unauthenticated). `--auth-profile` and `--identity` are mutually
  exclusive. `--authz-identity` requires `--identity` and enables
  horizontal-authorization (IDOR/BOLA) testing by authenticating a
  SECOND, fully independent identity — see [AUTHENTICATION](#authentication)
  and [IDENTITIES](#identities). An invalid profile/identity or a
  failed login fails the command immediately (exit code 5), before any
  scan job is created.
- **Detection coverage**: every enabled detector tests query, form,
  and path-parameter inputs alike. JSON request-body inputs are
  supported by the mutation engine but not yet discovered by the live
  crawler (which only ever observes JSON in a *response* body).
  Header/cookie inputs are not yet discovered or tested at all. Run
  `scanner detectors list` for the exact, current registry — this
  manual deliberately does not enumerate detector IDs, since the
  registry itself is the single source of truth.

Verified example — a `web`-profile scan against a local lab target
(trimmed; the real command produced 22 canonical findings):

```
$ scanner --config config.yaml scan 127.0.0.21 --ports 41613 --profile web
Scan ID:  2a4adf4c-f19d-4790-b2c8-e200aef10d92
Target:   127.0.0.21
Profile:  web
Status:   COMPLETED_WITH_WARNINGS
Duration: 1m11.356s

Crawl:
  Public URLs:             20
  Authenticated URLs:      0
  Authenticated Endpoints: 0

Inputs:
  Discovered: 86
  Unique endpoints with inputs: 77

Detection:
  Policy enabled: true
  Registered: 14
  Enabled: 7
  Eligible targets: 395
  Detector runs: 395
  Raw findings: 28
  Canonical findings: 22
  Requests issued: 1207

Findings:
CRITICAL:
  ID                                TYPE               URL                                            PARAMETER  SEVERITY  CONFIDENCE  RISK  PRIORITY
  ddc361d410ba668c1f59ad7e8aa53338  command_injection  http://127.0.0.21:41613/api/ping/vulnerable    host       critical  95%         63    MEDIUM
  ...
Summary: 22 total (critical=17 high=3 medium=2 low=0 info=0)
```

`COMPLETED_WITH_WARNINGS` here means the scan finished and produced
real findings, but one detector hit a non-fatal error on two specific
requests (visible in the printed `Errors/Warnings:` block) — the scan
continues testing every other eligible input regardless; a single
detector/request error never aborts the run. **Note the finding IDs
shown here are content-derived, deduplicated (canonical) IDs from this
one console printout — see [FINDINGS](#findings) for why they differ
from the raw IDs `scanner findings` itself lists.**

Authenticated and multi-identity invocation (syntax verified against
`--help`; illustrative — not executed against a live auth target in
this manual's own verification pass):

```
scanner scan example.com --profile web --auth-profile lab-login
scanner scan example.com --profile web --identity account-a
scanner scan example.com --profile web --identity account-a --authz-identity account-b
```

Out-of-scope target (verified — the scan job is created but fails
immediately, exit code 2):

```
$ scanner --config config.yaml scan 203.0.113.55
Scan ID:  01f921a8-26c5-42fc-bbb6-77bfcce474ba
Status:   FAILED
Errors/Warnings:
  [FATAL] SCOPE: orchestrator: target "203.0.113.55" is out of scope: no matching rule (default deny)
error: orchestrator: target "203.0.113.55" is out of scope: no matching rule (default deny)
```

### scanner status

Show one scan job's status and result counts.

```
scanner status <scan-id>
```

Read-only. Verified example:

```
$ scanner --config config.yaml status 2a4adf4c-f19d-4790-b2c8-e200aef10d92
id: 2a4adf4c-f19d-4790-b2c8-e200aef10d92
status: completed
started: 2026-08-24T23:23:17Z
finished: 2026-08-24T23:23:17Z
assets: 1
hosts: 1
dns_records: 0
services: 1
http_services: 1
technologies: 0
endpoints: 115
findings: 28
```

Note `findings: 28` here is the **raw** (pre-deduplication) count —
see [FINDINGS](#findings).

### scanner findings

List the vulnerabilities a scan's detectors found.

```
scanner findings --scan <scan-id> [--severity <level>] [--detector <id>]
scanner findings show <finding-id> [--curl]
```

Only meaningful for a scan run with detection enabled (`--profile web`
or `deep`) — a `recon`-profile scan never produces findings.

**IMPORTANT — two different ID spaces.** `scanner findings` lists
**raw, persisted** findings, each with its own storage-assigned ID.
This is a larger, non-deduplicated set (e.g. 28 raw findings for a
scan whose console summary showed 22). The scan command's own live
console printout, and `scanner report`, instead show **canonical**
(deduplicated, content-hashed) finding IDs from `internal/correlation`.
**Always use an ID returned by `scanner findings` itself when calling
`scanner findings show <finding-id>`** — an ID copied from the scan's
own console output or from `report` will not be found.

Verified example:

```
$ scanner --config config.yaml findings --scan 2a4adf4c-f19d-4790-b2c8-e200aef10d92 --severity high
ID                                    SEVERITY  DETECTOR     TITLE                                     ENDPOINT           STATUS
cc794d80-09fb-44fb-92e8-b32df2d2067a  high      ssti-active  Server-Side Template Injection (Active)  /ssti/greet/guest-1  unvalidated

$ scanner --config config.yaml findings show c044954a-fda2-4e50-b5aa-cc9b3c73b486
ID:          c044954a-fda2-4e50-b5aa-cc9b3c73b486
Detector:    ssti-active
Type:        ssti
Severity:    high
Confidence:  90%
URL:         http://127.0.0.21:41613/ssti/vulnerable?name=guest
Parameter:   name
Identity:    (unauthenticated)
Description: The "name" parameter on /ssti/vulnerable evaluates a jinja2/twig/mustache-style
             template expression ({{11*17}}) server-side, confirmed by the exact arithmetic
             result (187) appearing in the response.
Evidence (2):
  [1] kind=baseline           ...
  [2] kind=request_response   ...
Chain membership (1):
  - a85db0e7a7e76fda65090bd73f7ee0af (SUPPORTED)
```

`--curl` prints a sanitized, informational reproduction command instead
of the full detail view — see [ACTIVE SCANNING](#active-scanning)
"Manual reproduction" below.

### scanner chains

List candidate vulnerability chains — sakanner's own evidence that two
or more findings from the same scan are related.

```
scanner chains --scan <scan-id> [--status POTENTIAL|SUPPORTED|CONFIRMED]
scanner chains show <chain-candidate-id> --scan <scan-id>
```

Read-only. Status is `POTENTIAL` (structural relation only, e.g. same
endpoint), `SUPPORTED` (at least one evidence-level relation, e.g.
shared evidence content or a data-flow link), or `CONFIRMED` (never
assigned automatically by current policy — sakanner does not claim a
chain is confirmed beyond what evidence actually proves).

Verified example:

```
$ scanner --config config.yaml chains --scan 94e448fa-a50c-4270-b15e-ee18db01e3d5
ID                                STATUS     IDENTITY           FINDINGS  CONFIDENCE  REASON
154cb80fdd06f7e2298862b675273777  SUPPORTED  (unauthenticated)  9         70%         connected via: POTENTIAL_IMPACT_AMPLIFIER, SAME_ENDPOINT, SAME_PARAMETER, SAME_RESOURCE, SHARED_EVIDENCE

$ scanner --config config.yaml chains show 154cb80fdd06f7e2298862b675273777 --scan 94e448fa-a50c-4270-b15e-ee18db01e3d5
ID:               154cb80fdd06f7e2298862b675273777
Status:            SUPPORTED
Confidence:        70%
Endpoints:         [127.0.0.21:41613/api/ping/reflect 127.0.0.21:41613/api/ping/sanitized ...]
Participating findings (9): ...
Relations (N):
  [...] SHARED_EVIDENCE: <id-a> <-> <id-b> (confidence 50%)
      reason: both findings' own evidence content shares a specific, non-trivial value
```

### scanner report

Generate a full report for one scan job: assets, hosts, DNS records,
services, HTTP services, technologies, endpoints, inputs, and findings
— everything `status`/`findings` show piecemeal, assembled into one
document. **Vulnerability chains are not included** — use
`scanner chains --scan <scan-id>` separately for those.

```
scanner report --scan <scan-id> [--format json|markdown] [--output <path>]
```

`--format` defaults to `markdown`. `--output` writes to a file instead
of stdout.

Verified example (Markdown, trimmed):

```
$ scanner --config config.yaml report --scan 94e448fa-a50c-4270-b15e-ee18db01e3d5 --format markdown
# Scan Report: 94e448fa-a50c-4270-b15e-ee18db01e3d5

- **Status:** completed
- **Targets:** 71afb5e9-9483-41b8-90cc-f5d02ac8dfdc

## Summary

| Assets | Hosts | ... | Endpoints | Inputs | Findings |
|---|---|---|---|---|---|
| 1 | 1 | ... | 115 | 86 | 28 |
```

### scanner inputs

List discovered application inputs (query/form/path/JSON parameters)
for one scan job.

```
scanner inputs <scan-id> [--location <loc>] [--provenance <p>]
```

Values are already redacted at discovery time when a field's name
looks sensitive. `--location` filters to `query`, `path`, `form`,
`json`, `header`, or `cookie` (header/cookie are recognized values but
never actually populated — see [ACTIVE SCANNING](#active-scanning)).
`--provenance` filters to `REQUEST_INPUT` (an input actually observed
being accepted by the application — a query string, a rendered form)
or `RESPONSE_FIELD` (a field only ever observed in a response body,
which proves nothing about whether the application accepts it back).

Verified example:

```
$ scanner --config config.yaml inputs 94e448fa-a50c-4270-b15e-ee18db01e3d5 --location form
ID                                    ENDPOINT ID   METHOD  NAME     LOCATION  CLASSIFICATION  PROVENANCE     API    IDENTITY  VALUE
d1c304c5-e124-4758-ab97-128a12608b6b  af1ddf3b-...  POST    comment  form      FORM_FIELD      REQUEST_INPUT  false  -
```

### scanner detectors

Inspect the vulnerability detection framework's registry.

```
scanner detectors list
```

Read-only. Verified example (this build's actual current registry):

```
$ scanner --config config.yaml detectors list
ID                        STATUS    CATEGORY               NAME
xss-reflected             enabled   injection              Reflected XSS Detector
xss-reflected-active      enabled   injection              Reflected XSS Detector (Active)
sqli                      enabled   injection              SQL Injection Detector
sqli-active               enabled   injection              SQL Injection Detector (Active)
command-injection         enabled   injection              Command Injection Detector
command-injection-active  enabled   injection              Command Injection Detector (Active)
ssrf                      disabled  ssrf                   SSRF Detector
ssrf-active               disabled  ssrf                   SSRF Detector (Active)
idor                      disabled  broken_access_control  IDOR / BOLA Detector
path-traversal            disabled  broken_access_control  Path Traversal Detector
path-traversal-active     disabled  broken_access_control  Path Traversal Detector (Active)
open-redirect-active      disabled  broken_access_control  Open Redirect Detector (Active)
ssti-active               enabled   injection              Server-Side Template Injection Detector (Active)
idor-active               disabled  broken_access_control  Authorization / IDOR-BOLA Detector (Active)
```

`disabled` detectors are registered but will not run: some need
operator-supplied configuration this build ships no default for (e.g.
an out-of-band callback for `ssrf-active`); `idor-active` is disabled
unless the scan is run with `--authz-identity`. This table is always
the authoritative, current answer — it is generated from the live
registry, never hand-maintained.

### scanner profiles

Inspect sakanner's built-in scan profiles.

```
scanner profiles list
scanner profiles show <name>
```

Read-only. A profile is a named, fixed bundle of crawler/detection/
resource settings, selected with `scanner scan <target> --profile
<name>`. **Profiles never grant authorization** — scope rules remain
the sole authority over what may actually be scanned, independent of
which profile is active.

Verified example:

```
$ scanner --config config.yaml profiles list
NAME             DESCRIPTION                                CRAWLER                       DETECTION  VERIFICATION  RESOURCE CLASS
recon (default)  Reconnaissance only...                      disabled                      disabled   disabled      low
web              Recon plus bounded crawling and detection.  enabled (depth=2, pages=20)   enabled    enabled       medium
deep             Recon plus deeper, still-bounded crawling.  enabled (depth=4, pages=75)   enabled    enabled       high

$ scanner --config config.yaml profiles show web
Name:        web
Crawler:
  Enabled:   true
  Max depth: 2
  Max pages: 20
Resource limits:
  Detection concurrency: 5
  Scan timeout:          10m0s
```

### scanner auth

Inspect configured authentication profiles.

```
scanner auth profiles list
scanner auth profiles show <name>
```

Read-only. There is **no CLI command to create or edit an
authentication profile** — see [AUTHENTICATION](#authentication).
`scanner auth discover` (below) previews/exercises automatic
discovery but never writes a profile into your config file for you.
Verified example with none configured:

```
$ scanner --config config.yaml auth profiles list
no authentication profiles configured -- see "authentication.profiles" in your config file
```

### scanner auth discover

Preview — or, with credentials, actually perform — automatic
login-form discovery against a target, without first writing a
`form_login_auto` profile into config.

```
scanner auth discover <start-url> [--username-env <var>] [--password-env <var>]
```

- **State**: never mutates persistent state — no scan job is created,
  nothing is written to storage.
- **Network activity**: yes — fetches at most 3 pages looking for a
  login form (see [AUTHENTICATION](#authentication) "How discovery
  works"), and, only if both `--username-env`/`--password-env` are
  given, submits exactly one login attempt.
- With **neither** `--username-env` nor `--password-env`: preview
  only — no credential is ever read, no form is ever submitted.
- With **both**: also authenticates for real using the discovered
  form, exactly as `scan --identity <name>` would for a
  `form_login_auto` profile pointed at the same `start_url`.
- An `allow` scope rule for the target is still required.

Verified examples (real login form, real local lab target):

```
$ scanner --config config.yaml auth discover http://203.0.113.10/
Discovering a login form starting from http://203.0.113.10/ (preview only -- no credentials submitted)...
Login form discovered:
  Login URL:      http://203.0.113.10/login
  Method:         POST
  Username field: username
  Password field: password

$ scanner --config config.yaml auth discover http://203.0.113.10/ --username-env SAKANNER_USER --password-env SAKANNER_PASS
Discovering a login form and authenticating, starting from http://203.0.113.10/...
Authentication succeeded.
Discovered login URL: http://203.0.113.10/login
Session cookies established: 1
```

### scanner identities

Inspect configured multi-identity accounts.

```
scanner identities list
scanner identities show <name>
```

Read-only. See [IDENTITIES](#identities). Verified example with none
configured:

```
$ scanner --config config.yaml identities list
no identities configured -- see "identities" in your config file
```

### scanner tools

Inspect optional external recon tool integrations (subfinder, dnsx,
naabu, httpx, katana).

```
scanner tools status
```

Read-only (checks `PATH`, performs no network activity). None of these
tools are required — every stage they can replace has a fully
functional built-in Go implementation.

Verified example (no external tools installed in this environment):

```
$ scanner --config config.yaml tools status
subfinder  backend=auto       detected=not found
           install via: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
...
```

## GLOBAL OPTIONS

```
--config <path>   path to config file (YAML)
-h, --help        help for the current command
```

`--config` is the only global/persistent flag. If omitted, or it
points to a file that doesn't exist, sakanner runs entirely on its
built-in defaults (SQLite database at `sakanner.db` in the current
directory, text logging, standard concurrency/rate-limit settings).

## CONFIGURATION

sakanner reads YAML configuration via `--config path/to/config.yaml`.
Every setting can also be overridden with a `SAKANNER_`-prefixed
environment variable (e.g. `storage.dsn` → `SAKANNER_STORAGE_DSN`).
See [configs/config.yaml](../configs/config.yaml) for a fully-commented
example of every available setting, including crawler bounds,
concurrency/rate limits, DNS/port/HTTP timeouts, and the optional
external-tool backend selection (`tools.<name>: auto|native|<tool>`).

## AUTHENTICATION

An authentication **profile** describes how to establish an
authenticated session — form-based login, **automatic** form-based
login discovery, a pre-obtained session cookie, a bearer/API token, or
a custom header — configured under `authentication.profiles` in your
config file. Credentials themselves are never stored in
configuration: each profile *references* an environment variable that
must be set before the profile can be used.

### form_login: explicit configuration

Give the exact login URL and field names if you already know them:

```yaml
authentication:
  profiles:
    - name: lab-login
      type: form_login
      login_url: "http://203.0.113.10/login"
      username_env: SAKANNER_USER
      password_env: SAKANNER_PASS
```

```bash
export SAKANNER_USER=myuser
export SAKANNER_PASS=mypassword
scanner scan 203.0.113.10 --profile web --auth-profile lab-login
```

### form_login_auto: automatic login-form discovery

For a conventional username/password HTML form, you don't need to
know the exact login URL or field names at all — give a `start_url`
(any reachable same-origin page on the app; the site's own root works
for most applications) and credentials, and sakanner discovers the
real login page/form/field names itself at authenticate time:

```yaml
authentication:
  profiles:
    - name: lab-login-auto
      type: form_login_auto
      start_url: "http://203.0.113.10/"
      username_env: SAKANNER_USER
      password_env: SAKANNER_PASS
```

```bash
scanner scan 203.0.113.10 --profile web --auth-profile lab-login-auto
```

**Preview discovery before configuring anything**, or without
credentials at all:

```
$ scanner auth discover http://203.0.113.10/
Discovering a login form starting from http://203.0.113.10/ (preview only -- no credentials submitted)...
Login form discovered:
  Login URL:      http://203.0.113.10/login.php
  Method:         POST
  Username field: username
  Password field: password
```

Add `--username-env`/`--password-env` to also attempt a real login and
confirm it succeeds:

```bash
export SAKANNER_USER=myuser
export SAKANNER_PASS=mypassword
scanner auth discover http://203.0.113.10/ --username-env SAKANNER_USER --password-env SAKANNER_PASS
```

**How discovery works** (deterministic and bounded, never a guess):
fetches the start page (following ordinary redirects); if it has a
password-type `<input>`, that's the form. If not, it follows up to 2
more same-origin links whose text/URL looks login-related ("log in",
"sign in", ...), stopping at the first password-bearing form found.
The username field is chosen by scoring every other text-like field on
that form — `autocomplete="username"`/`"email"` and `type="email"`
score highest, then a name/id/label containing "user"/"email"/"login"/
"account", falling back to the first plausible text field if nothing
else distinguishes one. Hidden fields (CSRF tokens, etc.) are always
preserved unmodified. At most 3 pages are ever fetched, and exactly
one login is ever attempted — never a retry, never a different guess,
never account enumeration or credential spraying.

**Explicit `form_login` is not going away** — automatic discovery is
an additional option, not a replacement. If a target's login form
doesn't fit the "conventional HTML form" shape (JavaScript-rendered,
multi-step, OAuth/SSO, CAPTCHA, MFA), discovery will fail cleanly and
`form_login`'s explicit configuration remains the fallback.

- `--auth-profile <name>` and `--identity <name>` are **mutually
  exclusive** — use a profile directly, or an identity that references
  one (see [IDENTITIES](#identities)).
- Authentication is a strict pre-flight step: an invalid profile or a
  failed login fails the command immediately (exit code 5), before any
  scan job is created — no partial/unauthenticated scan job is ever
  left behind by a failed login.
- When authentication succeeds and crawling is enabled, the crawler
  carries the session's cookies/headers to every same-origin request
  for that session's own host.
- **Authentication never expands scope.** Every request, authenticated
  or not, passes the identical scope check.
- `scanner auth profiles list`/`show <name>` never print a credential
  value — every credential-bearing field is redacted.

**Known limitation**: there is no CLI command to create or edit an
authentication profile — this is config-file-only today.

## IDENTITIES

An **Identity** (e.g. `account-a`) is a security principal that
authenticates using a named authentication profile. Two identities may
reference the SAME profile (sharing its login mechanism) while
authenticating with completely independent credentials, by each
overriding the profile's own credential environment variables.

```yaml
identities:
  identities:
    - name: account-a
      auth_profile: lab-login
      username_env: SAKANNER_A_USER
      password_env: SAKANNER_A_PASS
    - name: account-b
      auth_profile: lab-login
      username_env: SAKANNER_B_USER
      password_env: SAKANNER_B_PASS
```

```bash
scanner scan 203.0.113.10 --profile web --identity account-a
scanner scan 203.0.113.10 --profile web --identity account-a --authz-identity account-b
```

`--identity` authenticates before scanning as that identity.
`--authz-identity` authenticates a SECOND, fully independent identity
(separate cookie jar, separate credentials) and enables horizontal-
authorization (IDOR/BOLA) testing against `--identity`'s baseline —
this is the only way `idor-active` runs. The two identities' sessions
are never mixed: each has its own client, cookie jar, and credentials.

Every finding records its own `IdentityContext` — which identity (if
any) produced it — visible via `findings show`'s `Identity:` line.
Chain correlation (`scanner chains`) never merges findings across
different identities or different scans; identity isolation is a hard
precondition checked before any relation is considered.

## SCOPE

sakanner is **default-deny**. See [scanner scope](#scanner-scope)
above for the command reference; this section covers the underlying
model:

- **No matching rule → denied.** There is no way to scan something
  with no matching `allow` rule.
- **Deny always wins** over a matching `allow` rule for the same
  target, regardless of which was added first.
- **Rule types**: `exact_host` (one literal host/IP), `domain_suffix`
  (a domain and every subdomain — inferred by default for a bare
  domain), `cidr` (an IP range).
- **Reserved/dangerous ranges are denied by default** regardless of
  scope rules (loopback, link-local, cloud metadata, multicast,
  unspecified) — `scope.allow_reserved_ranges: true` in config is
  required to override this, and should only be set for local lab
  validation, never a real engagement.
- **Active-request enforcement**: scope is re-checked immediately
  before every single outbound dial — not just once at scan start.
  This defends against DNS rebinding (a domain-suffix-authorized
  hostname resolving to a reserved address mid-scan).
- **Redirects**: every hop of an HTTP redirect chain is independently
  re-validated. A redirect to an out-of-scope host truncates the
  chain — it is never followed.
- **Cross-origin requests**: the crawler only follows same-origin
  links by default; any cross-origin URL it does encounter still goes
  through the same scope check as everything else.
- **Authentication never expands scope** — an authenticated session's
  cookies/headers are only ever attached to same-origin requests for
  that session's own host, and every request still passes the
  identical scope check regardless of authentication state.

Active scanning must remain within authorized scope at all times; none
of the above can be bypassed by profile choice, authentication, or
redirect behavior.

## SCAN PROFILES

See [scanner profiles](#scanner-profiles) above for the command
reference. Three built-in profiles: `recon` (default, discovery only),
`web` (bounded crawling + detection), `deep` (wider bounds, same
detectors as `web` — not exploitation). Profiles are a bundle of
resource/behavior settings only; they never grant authorization.

## ACTIVE SCANNING

Detection only runs under `--profile web`/`deep`, and only against
endpoints/parameters the crawler actually discovered. Run
`scanner detectors list` for the exact, current, authoritative
registry (see [scanner detectors](#scanner-detectors) above) — this
manual does not enumerate detector IDs, since new ones are added over
time.

**What's actually covered today** (verified against
`docs/phase-3-33-active-detection-coverage-review.md`, itself a
direct-repository-evidence review, not assumed from memory):

- Query, form, and path-parameter inputs are tested alike by every
  enabled detector.
- JSON request-body inputs are supported by the mutation engine, but
  **not yet discovered by the live crawler** — it only ever observes
  JSON in a response body, never constructs one from a live crawl.
- Header and cookie inputs are **not yet discovered or tested at
  all** — this is a real, current gap, not an oversight in this
  manual.
- Detectors never perform destructive actions. Command-injection
  detectors never invoke a local shell themselves; path-traversal
  detectors never read the local filesystem; every proof strategy is
  evidence-based (an exact marker, a computed numeric result, a
  structural response fact), never a guess from a status code or
  response-length difference alone.

**Manual reproduction** — `scanner findings show <finding-id> --curl`
prints a sanitized, shell-safe `curl` command reconstructing the exact
request that produced a finding's evidence. This is **information
only**: sakanner never executes it. Every value is already redacted at
evidence-creation time if it looks sensitive.

```
$ scanner findings show <finding-id> --curl
curl -X 'GET' 'http://127.0.0.21:41613/ssti/vulnerable?name=%7B%7B11%2A17%7D%7D'
# this command is INFORMATION ONLY -- sakanner never executes it; run it
# yourself only if you understand and are authorized to do so
```

## FINDINGS

See [scanner findings](#scanner-findings) above for the command
reference and the important note about raw vs. canonical finding IDs.
A finding's full detail (`findings show`) includes: detector, type,
severity, confidence, URL/endpoint, method, parameter, identity
context, evidence, and chain membership. All secret-shaped values are
redacted through sakanner's one redaction mechanism — never a second,
separate implementation.

## CHAINS

See [scanner chains](#scanner-chains) above for the command reference.
A chain candidate records why sakanner believes two or more findings
from the *same scan and same identity* are related — never merely
because they occurred on the same host. Status never escalates to
`CONFIRMED` automatically; `chains show` always states what additional
evidence would be needed to raise it further.

## REPORTING

See [scanner report](#scanner-report) above. `report` assembles
recon/crawl/input/finding data into one JSON or Markdown document.
Chains are intentionally **not** included — use `scanner chains`
separately if you need chain data alongside a report.

## LAB / LOCAL VALIDATION

Three distinct validation environments, in increasing order of realism
— and increasing setup cost:

**A. The repository's own local lab** (preferred first environment —
fully scripted, deterministic, no external dependencies):

```bash
make lab-up-phase3   # starts a local lab server with vulnerable fixtures
make lab-down        # stops it
make lab-test        # runs the lab's own automated test suite
```

`lab-up`/`lab-up-phase3` print the exact host:port addresses to target
— they use a fake DNS resolver internal to the test suite, so point the
CLI at the printed **IP:port** directly (not the printed `.scanner.test`
hostnames, which only resolve inside the test process itself):

```bash
scanner --config config.yaml scope add 127.0.0.21
scanner --config config.yaml scan 127.0.0.21 --ports 41613 --profile web
```

See [lab/README.md](../lab/README.md) and
[docs/phase-2-test-lab.md](phase-2-test-lab.md) for the full lab
architecture and every fixture scenario.

**B. Intentionally vulnerable training applications, such as DVWA.**
Real, third-party, deliberately vulnerable software — useful as a
second, independent validation target. **This has NOT been executed
as part of building sakanner** (the development environment used to
build this project has no Docker/PHP/MySQL available) — see
[docs/dvwa-validation.md](dvwa-validation.md) for a correct, concrete,
but honestly-unexecuted setup runbook, including a per-vulnerability-
class honesty table (which of DVWA's own pages a current detector can
plausibly exercise, and which classes — stored XSS, CSRF, file upload
— have no corresponding detector at all).

**C. Authorized external targets** — a bug-bounty program scope or a
system you own. Same workflow as A/B, pointed at a real domain, after
confirming your own authorization independently of sakanner.

After any lab scan, inspect results with the normal commands:
`scanner findings --scan <id>`, `scanner findings show <id>`,
`scanner chains --scan <id>`, `scanner report --scan <id>`.

## SAFETY

- **Default-deny scope**, re-checked before every dial, including
  every redirect hop (see [SCOPE](#scope)).
- **Reserved/dangerous IP ranges denied by default** (loopback,
  link-local, cloud metadata, multicast).
- **No destructive testing.** No detector modifies target state,
  invokes a local shell, or reads the local filesystem as part of its
  own proof strategy.
- **`findings show --curl` never executes anything** — it only ever
  prints a string. Verified by this manual's own author via direct
  source inspection: the file that builds this command imports neither
  `net/http` nor `os/exec`.
- **Secrets are never printed** by `auth profiles`/`identities`
  inspection commands, or by `findings show`/`--curl` for values
  already redacted at evidence-creation time.
- **Authentication never expands scope** — see [SCOPE](#scope).

## EXIT STATUS

| Code | Meaning |
|---|---|
| 0 | Success (a completed scan, or any other command that finished without error) |
| 1 | Invalid arguments / a generic, otherwise-uncategorized error |
| 2 | Scope violation or scan failure (the scan reached a terminal FAILED status) |
| 3 | Cancelled (operator interrupt, e.g. Ctrl-C, or a configured timeout elapsed) |
| 4 | Not found (e.g. `scope remove <id>` found no matching rule) |
| 5 | Authentication failed (invalid/misconfigured profile or identity, or a failed login — no scan job is created for this case) |

All five non-zero codes were verified directly against the current
binary while writing this manual (out-of-scope target → 2; invalid
`--auth-profile` → 5; `scope remove` of a nonexistent ID → 4).

## EXAMPLES

```bash
# General help
scanner --help
scanner scan --help

# Scope
scanner scope add example.com
scanner scope add --exact example.com
scanner scope add --action deny internal.example.com
scanner scope list
scanner scope remove <rule-id>

# Inspect configuration (all read-only)
scanner auth profiles list
scanner identities list
scanner profiles list
scanner profiles show web
scanner detectors list
scanner tools status

# Scanning
scanner scan example.com --profile recon
scanner scan example.com --profile web
scanner scan example.com --profile deep
scanner scan example.com --profile web --auth-profile lab-login
scanner scan example.com --profile web --identity account-a
scanner scan example.com --profile web --identity account-a --authz-identity account-b

# Inspecting results
scanner status <scan-id>
scanner inputs <scan-id>
scanner inputs <scan-id> --location form
scanner findings --scan <scan-id>
scanner findings --scan <scan-id> --severity high
scanner findings show <finding-id>
scanner findings show <finding-id> --curl
scanner chains --scan <scan-id>
scanner chains show <chain-candidate-id> --scan <scan-id>
scanner report --scan <scan-id> --format markdown
scanner report --scan <scan-id> --format json --output report.json

# Local lab
make lab-up-phase3
scanner scope add 127.0.0.21
scanner scan 127.0.0.21 --ports <printed-port> --profile web
make lab-down
```

## TROUBLESHOOTING

**"target is out of scope"** — add an `allow` scope rule for the exact
host/domain/CIDR you're targeting first: `scanner scope add <value>`.
Remember a `deny` rule always wins, and a bare domain only covers its
own subdomains unless you used `--exact`.

**A finding ID from the scan's own console output isn't found by
`findings show`** — that ID is a canonical (deduplicated) ID; use the
raw ID `scanner findings --scan <id>` itself returns instead. See
[FINDINGS](#findings).

**`--identity`/`--auth-profile` says invalid or login failed (exit 5)**
— check `scanner auth profiles list`/`scanner identities list` for the
exact configured name, and confirm the referenced environment
variables are actually set in your shell.

**A scan finishes as `COMPLETED_WITH_WARNINGS`** — this is not a
failure. Check the printed `Errors/Warnings:` block: it lists which
specific detector/request pairs hit a non-fatal error. Every other
eligible input is still tested; findings from unaffected
detectors/targets are unaffected.

**No findings at all** — confirm the scan used `--profile web` or
`deep` (a `recon`-profile scan never runs detection), and check
`scanner detectors list` for which detectors are actually enabled in
this build.

**Shell completion doesn't suggest a profile/identity/finding/scan ID**
— by design. Completion runs before sakanner's own config/database
access is available (Cobra's completion machinery never runs the
config-loading step), so anything requiring config or database access
cannot be completed. Static, finite-value flags (`--severity`,
`--format`, `--status`, `--location`, `--provenance`, `--action`, and
`--detector`, sourced from the same zero-I/O registry `detectors list`
itself uses) are completed.

**Building fails without network access** — the Go toolchain may need
to download a matching version or module dependencies once; see the
top-level [README.md](../README.md) "Requirements" section.

## SEE ALSO

- [README.md](../README.md) — project introduction, build/test/quick
  start.
- [docs/operator-guide.md](operator-guide.md) — scenario-based
  walkthroughs (unauthenticated/authenticated/multi-identity scanning,
  viewing findings/chains, safe manual reproduction).
- [docs/dvwa-validation.md](dvwa-validation.md) — DVWA-specific
  validation runbook (written, not executed in this environment — see
  [LAB / LOCAL VALIDATION](#lab--local-validation)).
- [docs/phase-3-33-active-detection-coverage-review.md](phase-3-33-active-detection-coverage-review.md)
  — current, evidence-based inventory of every detector and its known
  limitations.
- `scanner <command> --help` — the authoritative, always-current
  per-command reference embedded in the binary itself.
