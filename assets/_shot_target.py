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
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

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


# --- A genuinely SQL-injectable backend --------------------------------------
# NOT a mock: a real in-memory SQLite DB. The search endpoint below concatenates
# the `q` parameter straight into a grouped `WHERE ((name LIKE …) OR (…))` query
# (interpolated TWICE, exactly like the documented Juice-Shop shape), so the
# engine's boolean payloads genuinely toggle real SQL. Nothing pattern-matches
# "1=1" — the differential emerges from SQLite actually evaluating the injected
# boolean, and malformed paren depths raise a real error (500) that the judge
# honestly collapses rather than counting. The `/api/Products?name=` endpoint
# uses a BOUND parameter (no concatenation), so it is the compliant control that
# DISPROVES. Both are driven by the same rows, so the contrast is real.
_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB_LOCK = threading.Lock()
_DB.execute(
    "CREATE TABLE products (id INTEGER, name TEXT, description TEXT, deletedAt TEXT)"
)
_DB.executemany(
    "INSERT INTO products VALUES (?, ?, ?, ?)",
    [
        (1, "Apple Juice", "Freshly pressed apple juice", None),
        (2, "Banana Juice", "Creamy banana juice", None),
        (3, "Carrot Juice", "Organic carrot juice", None),
        (4, "Lemon Juice", "Sour lemon juice", None),
        (5, "Melon Juice", "Sweet melon juice", None),
    ],
)
_DB.commit()


def _search_products_injectable(q: str) -> list[tuple]:
    # VULNERABLE ON PURPOSE: q is string-interpolated twice into a grouped WHERE.
    sql = (
        "SELECT id, name FROM products WHERE "
        "((name LIKE '%" + q + "%' OR description LIKE '%" + q + "%') "
        "AND deletedAt IS NULL) ORDER BY id"
    )
    with _DB_LOCK:
        return _DB.execute(sql).fetchall()


def _filter_products_bound(name: str) -> list[tuple]:
    # SAFE: a bound parameter — the compliant control that collapses to DISPROVED.
    with _DB_LOCK:
        return _DB.execute(
            "SELECT id, name FROM products WHERE name = ? ORDER BY id", (name,)
        ).fetchall()


def _rows_to_body(rows: list[tuple]) -> bytes:
    return json.dumps(
        {"status": "success", "data": [{"id": r[0], "name": r[1]} for r in rows]}
    ).encode()


def _bearer_user(headers) -> str | None:
    """The user a `Bearer <user>-token` names, or None when unauthenticated.

    The demo target's broken authorization model: presenting ANY bearer token
    lets you reach ANY user's profile and the admin dashboard (no ownership /
    role check) — the real flaw the privilege-escalation judge reproduces. The
    `/orders` endpoint DOES check ownership, so it is the compliant control.
    """
    raw = headers.get("Authorization", "")
    if raw.startswith("Bearer ") and raw[7:].endswith("-token"):
        return raw[7:][: -len("-token")]
    return None


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
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        segments = [s for s in path.split("/") if s]
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
            # INJECTION COMPLIANT CONTROL: a BOUND `name` filter — no
            # concatenation, so every boolean pair collapses → DISPROVED.
            name = (query.get("name") or [""])[0]
            self._emit(200, _rows_to_body(_filter_products_bound(name)))
        elif path == "/rest/products/search":
            # INJECTION FINDING: `q` is concatenated into the SQL (see helper).
            # Real SQLite evaluates the injected boolean; malformed depths 500.
            q = (query.get("q") or [""])[0]
            try:
                rows = _search_products_injectable(q)
            except sqlite3.Error:
                self._emit(500, json.dumps({"error": "query failed"}).encode())
            else:
                self._emit(200, _rows_to_body(rows))
        elif len(segments) == 4 and segments[0] == "api" and \
                segments[1] == "users" and segments[3] == "profile":
            # PRIVESC (horizontal): NO ownership check — any bearer token reaches
            # any user's profile → CONFIRMED. Anonymous is denied (401).
            self._emit(200 if _bearer_user(self.headers) else 401,
                       json.dumps({"user": segments[2],
                                   "email": f"{segments[2]}@demo.shop"}).encode())
        elif len(segments) == 4 and segments[0] == "api" and \
                segments[1] == "users" and segments[3] == "orders":
            # PRIVESC COMPLIANT CONTROL: this endpoint DOES check ownership, so a
            # cross-tenant breach is denied (403) → DISPROVED, no finding.
            who = _bearer_user(self.headers)
            if who is None:
                self._emit(401, json.dumps({"error": "unauthorized"}).encode())
            elif who == segments[2]:
                self._emit(200, json.dumps({"user": segments[2],
                                            "orders": [{"id": 1001}]}).encode())
            else:
                self._emit(403, json.dumps({"error": "forbidden"}).encode())
        elif path == "/api/admin/dashboard":
            # PRIVESC (vertical): NO role check — any bearer token reaches the
            # admin function → CONFIRMED. Anonymous is denied (401).
            self._emit(200 if _bearer_user(self.headers) else 401,
                       json.dumps({"dashboard": "admin", "users": 5}).encode())
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
