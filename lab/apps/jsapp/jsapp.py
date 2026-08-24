#!/usr/bin/env python3
"""sakanner lab -- JavaScript-discovery app (Docker Compose profile only).

Mirrors the Go-native harness's js.scanner.test handler (see
../../harness.go's jsAppHandler). Serves fixtures/js-index.html and
fixtures/app.js directly.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def _file(self, path, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        with open(path, "rb") as f:
            self.wfile.write(f.read())

    def do_GET(self):
        if self.path == "/":
            self._file("/fixtures/js-index.html", "text/html")
        elif self.path == "/app.js":
            self._file("/fixtures/app.js", "application/javascript")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
