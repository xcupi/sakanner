#!/usr/bin/env python3
"""sakanner lab -- REST API app (Docker Compose profile only).

Standard-library only, no dependencies, so the container just needs a
plain python:3-alpine image with this file mounted in. Mirrors the
Go-native harness's api.scanner.test handler (see ../../harness.go's
apiHandler) so both profiles present identical behavior.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.58 (Ubuntu)"

    def version_string(self):
        # BaseHTTPRequestHandler's default appends sys_version (e.g.
        # "Python/3.11.4") to server_version, which would send a
        # doubled-up/incorrect-looking Server header -- override so this
        # sends exactly the string a real Apache would.
        return self.server_version

    def _send(self, status, body, content_type="text/html"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, open("/fixtures/api-index.html", "rb").read())
        elif path == "/items":
            self._send(200, json.dumps({"items": ["book-1", "book-2"]}), "application/json")
        elif path == "/users/42":
            self._send(200, json.dumps({"id": 42}), "application/json")
        else:
            self._send(404, "not found")

    def log_message(self, fmt, *args):
        pass  # quiet -- this is a test fixture, not a service to monitor


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
