#!/usr/bin/env python3
"""sakanner lab -- slow-response app (Docker Compose profile only).

Mirrors the Go-native harness's slow.scanner.test handler: sleeps for
SlowResponseDelay-equivalent (3s) before responding, so a scan configured
with a shorter HTTP timeout must not hang.
"""
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DELAY_SECONDS = 3


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(DELAY_SECONDS)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"generic lab page content")

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
