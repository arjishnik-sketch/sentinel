"""
A faithful, self-contained demo target for capturing real CLI screenshots.

It is NOT a mock of Sentinel — it is a genuine HTTP server that the real
engine recons and probes over real sockets. It reproduces the *documented*
vulnerable behaviours of the live fixtures (Juice-Shop-style broken access
control, absent security headers, a weak session cookie) so that the
deterministic judge reproduces real contradictions and the enforcer proves
real fixes. Every verdict in the captured screenshots is produced by the
engine against this live target — nothing is staged.

Grounded, not guessed: the accompanying ``assets/shot_policy.json`` declares
expectations that this server's real responses either satisfy (DISPROVED
controls) or contradict (CONFIRMED findings).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_INDEX_HTML = b"""<!doctype html><html><head><title>Demo Shop</title></head>
<body><h1>Demo Shop</h1>
<a href="/api/Feedbacks">feedback</a>
<a href="/api/Users">users</a>
<a href="/api/Products">products</a>
<a href="/rest/admin/application-version">version</a>
<a href="/api/BasketItems">basket</a>
</body></html>"""

_FEEDBACKS = json.dumps({
    "status": "success",
    "data": [
        {"id": 1, "comment": "Great shop!", "rating": 5, "UserId": 3},
        {"id": 2, "comment": "internal note: refund abuse", "rating": 1, "UserId": 8},
    ],
}).encode()

_PRODUCTS = json.dumps({"status": "success", "data": [
    {"id": 1, "name": "Apple Juice"}, {"id": 2, "name": "Banana Juice"},
]}).encode()

_VERSION = json.dumps({"version": "14.5.1"}).encode()


class _Handler(BaseHTTPRequestHandler):
    server_version = "DemoStack"
    sys_version = ""

    def log_message(self, *a, **k):  # keep the capture output clean
        return

    def _emit(self, code, body, *, extra=None, set_cookie=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json"
                         if body is not _INDEX_HTML else "text/html")
        # Compliant control the judge should DISPROVE (already present):
        self.send_header("X-Content-Type-Options", "nosniff")
        # Real misconfigurations the judge should CONFIRM:
        #   - wildcard CORS
        #   - a non-standard information-disclosure header
        #   - (absent) Content-Security-Policy / Referrer-Policy / X-Frame-Options
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Recruiting", "/#/jobs")
        for k, v in (extra or {}):
            self.send_header(k, v)
        if set_cookie:
            for line in set_cookie:
                self.send_header("Set-Cookie", line)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/":
            # A weak session cookie: no HttpOnly, no Secure, no SameSite.
            self._emit(200, _INDEX_HTML,
                       set_cookie=["token=eyJhbGciOi.demo.sig; Path=/"])
        elif path == "/api/Feedbacks":
            # Broken access control: the whole collection leaks to anonymous.
            self._emit(200, _FEEDBACKS)
        elif path == "/api/Users":
            # Correctly denied — the honest DISPROVED control (no finding).
            self._emit(401, json.dumps({"error": "unauthorized"}).encode())
        elif path == "/api/Products":
            self._emit(200, _PRODUCTS)
        elif path == "/api/BasketItems":
            self._emit(401, json.dumps({"error": "unauthorized"}).encode())
        elif path == "/rest/admin/application-version":
            self._emit(200, _VERSION)
        else:
            self._emit(404, json.dumps({"error": "not found"}).encode())

    do_HEAD = do_GET


def start_stub(port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    """Start the demo target on loopback; return (server, base_url)."""
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


if __name__ == "__main__":
    srv, base = start_stub(3000)
    print("demo target on", base)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
