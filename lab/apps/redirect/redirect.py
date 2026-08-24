#!/usr/bin/env python3
"""sakanner lab -- redirect/status-code app (Docker Compose profile only).

Mirrors the Go-native harness's redirect.scanner.test handlers (see
../../harness.go's redirectHTTPHandler/redirectSecureHandler) so both
profiles present identical behavior. HTTPS_PORT is read from the
environment so the http->https redirect's Location header names the
right published port (see docker-compose.yml).
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HTTPS_PORT = os.environ.get("LAB_REDIRECT_HTTPS_PORT", "8444")


class Handler(BaseHTTPRequestHandler):
    def _redirect(self, status, location):
        self.send_response(status)
        self.send_header("Location", location)
        self.end_headers()

    def _plain(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = self.path
        if path == "/":
            self._redirect(301, f"https://redirect.scanner.test:{HTTPS_PORT}/secure")
        elif path == "/multi":
            self._redirect(302, "/multi/2")
        elif path == "/multi/2":
            self._redirect(302, "/multi/done")
        elif path == "/multi/done":
            self._plain(200, "done")
        elif path == "/loop":
            self._redirect(302, "/loop")
        elif path == "/external-redirect":
            self._redirect(302, "http://external.scanner.test/")
        elif path == "/missing":
            self._plain(404, "not found")
        elif path == "/forbidden":
            self._plain(403, "forbidden")
        elif path == "/error":
            self._plain(500, "internal error")
        elif path in ("/secure", ""):
            self._plain(200, "secure page")
        else:
            self._plain(404, "not found")

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
