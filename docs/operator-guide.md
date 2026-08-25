# sakanner Operator Guide

This guide is for a human security operator running sakanner against an
**authorized** target — a bug-bounty scope, a system you own, or a
controlled lab such as DVWA (see `docs/dvwa-validation.md`). Every
command below is a real, existing `scanner` subcommand — nothing here
is aspirational or invented; where a workflow step has no corresponding
command yet, this document says so explicitly instead of fabricating one.

sakanner never autonomously performs destructive testing and never
executes anything on your behalf beyond the scan itself — findings
inspection and reproduction commands are strictly read-only (see
`docs/phase-3-32-operator-workflow.md`).

## The 7-step manual validation workflow

1. **Define the authorized target.** `scanner scope add <host>` (below).
2. **Configure scope.** Same command — scope IS the authorization
   record; nothing scans without an explicit scope entry.
3. **Optionally configure an identity.** Edit the config YAML's
   `authentication.profiles`/`identities.identities` (no CLI command
   creates these — see Scenario 2 below).
4. **Run the scan.** `scanner scan <target> [--profile ...] [--identity ...]`.
   Discovery and active detection both happen inside this one command.
5. **Inspect the evidence.** `scanner findings --scan <id>`,
   `scanner findings show <finding-id>`, `scanner chains --scan <id>`.
6. **Decide whether to manually validate further.** Use
   `scanner findings show <finding-id> --curl` to get a sanitized,
   copy-pasteable reproduction command — YOU run it, sakanner never does.
7. **Reuse the recorded request context** as needed for your own manual
   follow-up; sakanner does not re-issue requests on your behalf.

---

## Scenario 1: Unauthenticated scan

```bash
scanner --config config.yaml scope add 203.0.113.10
scanner --config config.yaml scan 203.0.113.10 --profile web
```

`--profile` is one of `recon` (default), `web`, or `deep`. `web` enables
the active detectors; `recon` is discovery-only.

## Scenario 2: Authenticated scan

There is no CLI command to create an auth profile or identity — both
are defined in your YAML config file, referencing environment variables
for credentials (credentials are never written directly into the YAML):

```yaml
storage:
  dsn: sakanner.db
scope:
  allow_reserved_ranges: true
authentication:
  profiles:
    - name: lab-login
      type: form_login
      login_url: "http://203.0.113.10/login"
      username_env: SAKANNER_USER
      password_env: SAKANNER_PASS
identities:
  identities:
    - name: operator
      auth_profile: lab-login
      username_env: SAKANNER_USER
      password_env: SAKANNER_PASS
```

```bash
export SAKANNER_USER=myuser
export SAKANNER_PASS=mypassword
scanner --config config.yaml scope add 203.0.113.10
scanner --config config.yaml scan 203.0.113.10 --profile web --identity operator
```

Inspect what's configured (read-only) at any time:

```bash
scanner --config config.yaml auth profiles list
scanner --config config.yaml identities list
```

**Don't know the exact login URL or field names?** Use
`type: form_login_auto` with a `start_url` (any page on the app, e.g.
its root) instead of `login_url`/`username_field`/`password_field` —
sakanner discovers the real login form itself:

```yaml
authentication:
  profiles:
    - name: lab-login
      type: form_login_auto
      start_url: "http://203.0.113.10/"
      username_env: SAKANNER_USER
      password_env: SAKANNER_PASS
```

Preview what discovery would find before configuring anything, with
no credentials required:

```bash
scanner --config config.yaml auth discover http://203.0.113.10/
```

See `docs/manual.md`'s AUTHENTICATION section for exactly how
discovery works and its limitations.

## Scenario 3: Multi-identity scan

Define two identities sharing one login profile:

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

Two ways to use them:

**Independent scans, one identity each** (broadest coverage per identity):

```bash
scanner --config config.yaml scan 203.0.113.10 --profile web --identity account-a
scanner --config config.yaml scan 203.0.113.10 --profile web --identity account-b
```

**One scan, two identities** (enables horizontal-authorization / IDOR
testing — `account-a` is the baseline, `account-b` is the compare identity):

```bash
scanner --config config.yaml scan 203.0.113.10 --profile web --identity account-a --authz-identity account-b
```

`--identity` and `--auth-profile` are mutually exclusive; `--authz-identity`
requires `--identity`.

## Scenario 4: Viewing findings

```bash
scanner --config config.yaml findings --scan <scan-id>
scanner --config config.yaml findings --scan <scan-id> --severity high
scanner --config config.yaml findings --scan <scan-id> --detector sqli-active
```

`--scan` is required. Get `<scan-id>` from the `scan` command's own
output, or from `scanner status <scan-id>`.

## Scenario 5: Inspecting a finding

```bash
scanner --config config.yaml findings show <finding-id>
```

This prints, per finding: finding ID, scan ID, detector, vulnerability
type, severity, URL/endpoint, HTTP method, parameter and parameter
location, identity context, evidence, and chain membership (which chain
candidates, if any, this finding participates in). All secrets
(passwords, tokens, session cookies, API keys) are redacted using
sakanner's existing redaction mechanism — never a second implementation.

## Scenario 6: Viewing chains

A "chain" is sakanner's own evidence that two or more findings are
related (see `docs/phase-3-30-correlation-chain-foundation.md` and
`docs/phase-3-31-chain-integration.md`). Chain status is `POTENTIAL`,
`SUPPORTED`, or `CONFIRMED`.

```bash
scanner --config config.yaml chains --scan <scan-id>
scanner --config config.yaml chains --scan <scan-id> --status SUPPORTED
scanner --config config.yaml chains show <chain-candidate-id> --scan <scan-id>
```

`chains show` prints the chain's status, impact, reasoning, affected
endpoints, every participating finding (with its own severity/endpoint/
parameter), and every relation between findings (with an explainable
reason and evidence detail) — never raw secrets, never a credential.

## Scenario 7: Manually reproducing a finding safely

```bash
scanner --config config.yaml findings show <finding-id> --curl
```

This prints a sanitized, shell-safe `curl` command reconstructing the
exact request that produced the finding's evidence — method, URL,
relevant headers, relevant body, with any sensitive value already
redacted at evidence-creation time. **This command is information
only.** sakanner never executes it. Copy it, review it, and run it
yourself if you choose to validate further manually.

```bash
$ scanner --config config.yaml findings show f_a1b2c3 --curl
curl -X 'GET' 'http://203.0.113.10/search?q=%27%20OR%20%271%27%3D%271' \
  -H 'User-Agent: sakanner/1.0'

# NOTE: this command is provided for manual reproduction only.
# sakanner does not execute it. Review it before running it yourself.
```

## Scenario 8: Running against a controlled lab target

See `docs/dvwa-validation.md` for a full DVWA-specific runbook. In
short, the workflow is identical to Scenarios 1–7 above, pointed at
your lab's own host/port:

```bash
scanner --config config.yaml scope add localhost
scanner --config config.yaml scan localhost --ports 4280 --profile web --identity dvwa-admin
scanner --config config.yaml findings --scan <scan-id>
```

## Other useful commands

```bash
# A full report (JSON or Markdown) instead of separate findings/chains calls
scanner --config config.yaml report --scan <scan-id> --format markdown
scanner --config config.yaml report --scan <scan-id> --format json --output report.json

# What detectors this build has registered, and which are enabled by default
scanner --config config.yaml detectors list

# Every built-in scan profile's exact settings (crawler/detection/resource limits)
scanner --config config.yaml profiles list
scanner --config config.yaml profiles show web

# Which optional external recon tools (subfinder/dnsx/naabu/httpx/katana) are
# installed and which backend each pluggable stage is configured to use
scanner --config config.yaml tools status
```

---

## Reading exit codes

`scanner` uses distinct exit codes so a wrapper script can distinguish
failure modes: `0` success, `1` generic error, `2` scan failed, `3` scan
cancelled, `4` not found, `5` authentication failed (bad `--auth-profile`
/`--identity`, or `--authz-identity` without `--identity`).

## Known gap

There is currently no CLI command to create or edit an auth profile or
identity — this is a genuine workflow gap, not an oversight in this
guide. Operators must hand-edit the YAML config file for Scenarios 2
and 3. `scanner auth` and `scanner identities` are read-only inspection
commands only.
