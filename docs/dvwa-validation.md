# Validating sakanner Against DVWA

DVWA (Damn Vulnerable Web Application) is a real, third-party,
deliberately vulnerable PHP application, distributed for security
training and testing. It is **not** part of this repository and is
**never** a build or test dependency — `go build ./...` and every
existing test suite succeed with no knowledge of DVWA's existence.

**Honesty note**: this runbook is written, concrete, and correct, but
**it has not been executed in this development environment** — Docker,
PHP, and MySQL are all unavailable here (verified directly: `docker`,
`php`, `mysql` are all absent from `$PATH` in this session). Per this
phase's own explicit instruction not to claim a detector works against
DVWA "merely because a synthetic unit test passes," this document does
not claim DVWA validation was performed. It documents exactly how an
operator WITH Docker available would do it, and honestly maps which of
sakanner's 14 detectors DVWA's own known vulnerability pages can
plausibly exercise versus which cannot (see the coverage table below).
Real, EXECUTED validation for this phase was instead performed against
sakanner's own internal `lab` package — see
`docs/phase-3-32-acceptance-test.md`'s own LAB VALIDATION section.

## 1. Start DVWA (operator-run, requires Docker)

```bash
docker run --rm -it -p 4280:80 vulnerables/web-dvwa
```

This exposes DVWA at `http://localhost:4280/`. On first load, visit
`http://localhost:4280/setup.php` and click "Create / Reset Database."
Default credentials are `admin` / `password`.

DVWA also has a "Security Level" setting (Impossible / High / Medium /
Low) reachable at `/security.php` after login — set it to **Low** for
the most detector-friendly, unfiltered surface. Scanning DVWA at
Impossible/High is expected to find little to nothing (that is DVWA's
own intended behavior, not a sakanner defect).

## 2. Authorize the target

```bash
scanner target add localhost
scanner scope add localhost
```

## 3. Configure a DVWA authentication profile

DVWA's login is a plain HTML form at `/login.php` with fields
`username`, `password`, `Login` (submit), and a `user_token` CSRF
field sakanner's own existing form-reconstruction/authenticated-
crawling machinery (Phase 3.14/3.15) already handles generically — no
DVWA-specific code exists or is needed in sakanner itself. Credentials
are always supplied via environment-variable references, never
written directly into the YAML.

**Simplest: automatic discovery (Phase 3.36)** — no need to know the
exact login URL or field names; a `start_url` anywhere on the app is
enough:

```yaml
# config.yaml
storage:
  dsn: sakanner.db
scope:
  allow_reserved_ranges: true
authentication:
  profiles:
    - name: dvwa
      type: form_login_auto
      start_url: "http://localhost:4280/DVWA/"
      username_env: DVWA_USERNAME
      password_env: DVWA_PASSWORD
identities:
  identities:
    - name: dvwa-admin
      auth_profile: dvwa
      username_env: DVWA_USERNAME
      password_env: DVWA_PASSWORD
```

Preview what discovery finds first, with no credentials needed:

```bash
scanner --config config.yaml auth discover http://localhost:4280/DVWA/
```

**Or explicit configuration**, if you already know the exact login
URL and field names:

```yaml
authentication:
  profiles:
    - name: dvwa
      type: form_login
      login_url: "http://localhost:4280/DVWA/login.php"
      username_field: username
      password_field: password
      username_env: DVWA_USERNAME
      password_env: DVWA_PASSWORD
identities:
  identities:
    - name: dvwa-admin
      auth_profile: dvwa
      username_env: DVWA_USERNAME
      password_env: DVWA_PASSWORD
```

Either way:

```bash
export DVWA_USERNAME=admin
export DVWA_PASSWORD=password
scanner --config config.yaml scope add localhost
scanner --config config.yaml scan localhost --ports 4280 --profile web --identity dvwa-admin
```

## 4. Coverage mapping — honest, per-vulnerability-class

| DVWA page | Vulnerability class | sakanner detector | Expected result |
|---|---|---|---|
| `vulnerabilities/sqli/` | SQL injection | `sqli`, `sqliactive` | Plausible match — DVWA's own `id` GET parameter is a textbook boolean/error-based SQLi target this detector class is designed for. |
| `vulnerabilities/xss_r/` | Reflected XSS | `xssreflected`, `xssactive` | Plausible match — a classic unescaped `name` GET parameter reflection. |
| `vulnerabilities/xss_s/` | Stored XSS | — | **NOT DEMONSTRATED**: no stored-XSS detector exists in this codebase (every XSS detector here proves REFLECTED injection only, within one request/response pair — see `docs/phase-3-19-active-detection.md`). |
| `vulnerabilities/exec/` | Command injection | `cmdinjection`, `cmdinjectionactive` | Plausible match — DVWA's own `ip` field is a direct shell-command-building target. |
| `vulnerabilities/fi/` | File inclusion (local/remote) | `traversal`, `traversalactive` | Plausible PARTIAL match — sakanner's own path-traversal detectors prove PATH TRAVERSAL (reading an unauthorized file via `../` sequences) specifically, via a KNOWN marker file; DVWA's own LFI page may or may not expose a file this detector's own marker-based proof strategy can recognize without operator-side configuration of a known-readable target file — the marker-matching in this codebase is deliberately conservative (see `docs/phase-3-27-path-traversal-active.md`) and requires knowing what to look for, not a generic "any file read succeeded" heuristic. |
| `vulnerabilities/csrf/` | CSRF | — | **NOT DEMONSTRATED**: no CSRF-specific detector exists in this codebase. |
| `vulnerabilities/upload/` | Unrestricted file upload | — | **NOT DEMONSTRATED**: no file-upload detector exists; sakanner's own detectors never perform file uploads at all (out of scope for every phase to date). |
| `vulnerabilities/captcha/` | Insecure CAPTCHA | — | **NOT DEMONSTRATED**: no relevant detector. |
| `vulnerabilities/weak_id/` | Weak session/token generation | — | **NOT DEMONSTRATED**: no relevant detector. |
| SSRF/SSTI/open-redirect pages | — | `ssrfactive`, `sstiactive`, `openredirectactive` | DVWA's own standard page set (as of the commonly-distributed `vulnerables/web-dvwa` image) does not include a dedicated SSRF, SSTI, or open-redirect page — **NOT APPLICABLE**, not a gap in sakanner. |

Every row above is a documented EXPECTATION, not an executed result —
an operator running this workflow with real Docker access should
independently confirm each row via `scanner findings --scan <id>` and
`scanner findings show <id> --curl` (Phase 3.32's own new inspection
commands, see `docs/operator-guide.md`).

## 5. Inspecting results

```bash
scanner findings --scan <scan-id>
scanner findings show <finding-id>
scanner findings show <finding-id> --curl
scanner chains --scan <scan-id>
```

Every credential/session cookie sakanner uses to authenticate against
DVWA is redacted from all of the above — see
`docs/phase-3-32-operator-workflow.md`'s own SECRET SAFETY discussion
and `docs/operator-guide.md`'s worked examples.
