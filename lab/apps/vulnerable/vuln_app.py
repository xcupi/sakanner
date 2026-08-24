#!/usr/bin/env python3
"""sakanner lab -- Phase 3 vulnerable/safe fixture app (Docker Compose
profile only).

Mirrors the Go-native harness's vulnAppHandler (see ../../harness_vuln.go)
so both profiles present the same fixture behavior. As with the rest of
this Docker profile, this file has NOT been execution-verified with
Docker itself (not installed on the machine this was authored on) -- it
was syntax-checked (py_compile) and reviewed against the Go
implementation it mirrors. The Go-native harness is what
tests/lab/phase3_lab_test.go actually runs and verifies.

Every "vulnerable" handler here is genuinely vulnerable, deliberately,
for a controlled local fixture -- see docs/phase-3-test-lab.md before
assuming any of this is a template for real code.
"""
import html
import json
import re
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

FAKE_DB = [("1", "alice"), ("2", "bob"), ("3", "admin")]
SYNTH_FILES = {
    "readme.txt": "sakanner lab fixture: hello from the traversal fixture",
    "../../../etc/passwd": "sakanner-lab-synthetic-fixture-file:not-a-real-passwd-file:0:0::/fixture:/bin/fixture",
}
SAFE_FILES = {"readme.txt": "sakanner lab fixture: hello from the safe traversal fixture", "about.txt": "about this fixture"}
SYNTH_TEMPLATES = {"home": "welcome home", "../../../etc/passwd": "sakanner-lab-synthetic-fixture-file:not-a-real-passwd-file"}
SAFE_TEMPLATES = {"home": "welcome home", "about": "about us"}

# Closure-local-equivalent: module state reset each process start, one
# process per container/test run -- matches harness_vuln.go's per-Lab
# isolation (see that file's comment on why this must never be a
# cross-run-persistent global in the Go harness; the same reasoning
# applies here, one process per lab instance).
_stored = {"vulnerable": "(no comment submitted yet)", "safe": "(no comment submitted yet)"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, status, body, content_type="text/html", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode() if isinstance(body, str) else body)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query)
        qval = lambda k, d="": q.get(k, [d])[0]

        if path == "/":
            self._send(200, "<html><body><h1>Phase 3 fixtures</h1></body></html>")

        elif path == "/xss/reflected/vulnerable":
            self._send(200, f"<html><body><p>You searched for: {qval('q')}</p></body></html>")
        elif path == "/xss/reflected/safe":
            self._send(200, f"<html><body><p>You searched for: {html.escape(qval('q'))}</p></body></html>")

        elif path == "/xss/stored/vulnerable":
            self._send(200, f"<html><body><div id=comment>{_stored['vulnerable']}</div></body></html>")
        elif path == "/xss/stored/safe":
            self._send(200, f"<html><body><div id=comment>{html.escape(_stored['safe'])}</div></body></html>")

        elif path == "/sqli/vulnerable":
            id_ = qval("id")
            if "'" in id_:
                if "' or '1'='1" in id_.lower():
                    self._send(200, "results: " + ", ".join(n for _, n in FAKE_DB))
                else:
                    self._send(500, f"SQL syntax error near '{id_}' (simulated)")
            else:
                row = next((n for i, n in FAKE_DB if i == id_), None)
                self._send(200, f"results: {row or '(none)'}")
        elif path == "/sqli/safe":
            id_ = qval("id")
            row = next((n for i, n in FAKE_DB if i == id_), None)
            self._send(200, f"results: {row or '(none)'}")

        elif path == "/auth/weak-credentials":
            if qval("username") == "admin" and qval("password") == "admin":
                self._send(200, "login successful: welcome admin")
            else:
                self._send(401, "login failed")
        elif path == "/auth/strong-credentials":
            if qval("username") == "testuser" and qval("password") == "Xk9#mP2vQ7zL!bR4-fixture-only":
                self._send(200, "login successful")
            else:
                self._send(401, "login failed")

        elif path.startswith("/idor/vulnerable/user/"):
            uid = path.rsplit("/", 1)[-1]
            self._send(200, json.dumps({"id": uid, "email": f"user{uid}@fixture.test"}), "application/json")
        elif path.startswith("/idor/safe/user/"):
            uid = path.rsplit("/", 1)[-1]
            cookie = self.headers.get("Cookie", "")
            m = re.search(r"session=user(\w+)", cookie)
            if not m or m.group(1) != uid:
                self._send(403, json.dumps({"error": "forbidden"}), "application/json")
            else:
                self._send(200, json.dumps({"id": uid, "email": f"user{uid}@fixture.test"}), "application/json")

        elif path == "/files/traversal/vulnerable":
            content = SYNTH_FILES.get(qval("name"))
            self._send(200, content) if content else self._send(404, "not found")
        elif path == "/files/traversal/safe":
            content = SAFE_FILES.get(qval("name"))
            self._send(200, content) if content else self._send(404, "not found")

        elif path == "/files/lfi/vulnerable":
            tmpl = SYNTH_TEMPLATES.get(qval("page"))
            self._send(200, f"<html><body>{tmpl or 'page not found: ' + html.escape(qval('page'))}</body></html>")
        elif path == "/files/lfi/safe":
            tmpl = SAFE_TEMPLATES.get(qval("page"))
            self._send(200, f"<html><body>{tmpl}</body></html>") if tmpl else self._send(404, "not found")

        elif path == "/ssrf/vulnerable":
            target = qval("url")
            host = urlparse(target).hostname or ""
            if not (host == "127.0.0.1" or host.startswith("127.")):
                self._send(502, "fixture safety net: only 127.0.0.0/8 destinations are permitted from this lab fixture")
            else:
                try:
                    with urllib.request.urlopen(target, timeout=3) as resp:
                        body = resp.read(65536).decode(errors="replace")
                    self._send(200, f"fetched {target}: {body}")
                except Exception as e:
                    self._send(502, f"fetch failed: {e}")
        elif path == "/ssrf/safe":
            if qval("url") != "https://status.fixture.test/health":
                self._send(400, "destination not in allowlist")
            else:
                self._send(200, "ok (allowlisted destination only)")

        elif path == "/redirect/open/vulnerable":
            self._redirect(qval("next"))
        elif path == "/redirect/open/safe":
            next_ = qval("next")
            self._redirect(next_ if next_ in ("/dashboard", "/profile") else "/dashboard")

        elif path == "/misconfig/stacktrace/vulnerable":
            self._send(500, "Traceback (most recent call last):\n  File \"app.py\", line 42\nsakanner.lab.fixture.SyntheticDatabaseError\nSECRET_KEY=sakanner-lab-fixture-not-a-real-secret-000111222")
        elif path == "/misconfig/stacktrace/safe":
            self._send(500, "An unexpected error occurred. Please try again later.")

        elif path == "/info/exposure/vulnerable":
            self._send(200, "<html><!-- TODO: remove before prod. api_key=sk_test_SAKANNER_LAB_FIXTURE_0000000000 --><body>Welcome</body></html>")
        elif path == "/info/exposure/safe":
            self._send(200, "<html><body>Welcome</body></html>")

        elif path == "/cookies/insecure/vulnerable":
            self._send(200, "session set", headers={"Set-Cookie": "session=synthetic-fixture-session-token-000; Path=/"})
        elif path == "/cookies/insecure/safe":
            self._send(200, "session set", headers={"Set-Cookie": "session=synthetic-fixture-session-token-001; Path=/; HttpOnly; Secure; SameSite=Strict"})

        elif path == "/cors/vulnerable":
            origin = self.headers.get("Origin", "*")
            self._send(200, json.dumps({"data": "sensitive-fixture-data"}), "application/json",
                       headers={"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"})
        elif path == "/cors/safe":
            self._send(200, json.dumps({"data": "sensitive-fixture-data"}), "application/json",
                       headers={"Access-Control-Allow-Origin": "https://scanner.test"})

        elif path == "/headers/missing/vulnerable":
            self._send(200, "<html><body>no security headers here</body></html>")
        elif path == "/headers/missing/safe":
            self._send(200, "<html><body>fully configured</body></html>", headers={
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                "Referrer-Policy": "no-referrer",
            })

        elif path == "/component/vulnerable":
            self._send(200, '<html><head><script src="/component/old-jquery.js"></script></head><body>legacy page</body></html>')
        elif path == "/component/old-jquery.js":
            self._send(200, "/*! jQuery v1.6.1 jquery.com | jquery.org/license */", "application/javascript")
        elif path == "/component/safe":
            self._send(200, '<html><head><script src="/component/current-jquery.js"></script></head><body>current page</body></html>')
        elif path == "/component/current-jquery.js":
            self._send(200, "/*! jQuery JavaScript Library v3.6.0 */", "application/javascript")

        elif path == "/admin/exposed":
            self._send(200, "<html><body><h1>Admin Panel</h1><p>Synthetic fixture admin panel, no authentication required.</p></body></html>")
        elif path == "/admin/protected":
            if self.headers.get("Authorization") != "Bearer sakanner-lab-fixture-admin-token-000":
                self._send(401, "unauthorized")
            else:
                self._send(200, "<html><body><h1>Admin Panel</h1></body></html>")

        elif path == "/directory-listing/vulnerable/":
            self._send(200, '<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><ul><li><a href="config.bak">config.bak</a></li></ul></body></html>')
        elif path == "/directory-listing/safe/":
            self._send(403, "403 Forbidden")

        else:
            self._send(404, "not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        form = parse_qs(body)
        comment = form.get("comment", [""])[0]
        if self.path == "/xss/stored/vulnerable":
            _stored["vulnerable"] = comment
            self._send(200, "submitted")
        elif self.path == "/xss/stored/safe":
            _stored["safe"] = comment
            self._send(200, "submitted")
        else:
            self._send(404, "not found")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
