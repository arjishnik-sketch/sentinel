"""End-to-end proof that Sentinel independently logs in, captures the genuine
session-cookie JWT, forges an ``alg=none`` token that escalates ``sub`` to the
declared admin identity, and CONFIRMS the broken-authentication bypass — with NO
external driver script.

This stands a LOCAL, faithful reproduction of the PortSwigger lab "JWT
authentication bypass via flawed signature verification" (creds wiener:peter):

  * ``GET  /login``      → a classic server-rendered username/password form
  * ``POST /login``      → on valid creds, ``Set-Cookie: session=<genuine JWT>``
                            (payload ``sub=wiener``) — the app authenticates via
                            the ``session`` cookie, exactly like the lab
  * ``GET  /my-account`` → 200 for any live session (the session-alive control a
                            VERTICAL forgery needs, since the genuine user is
                            denied at the admin route)
  * ``GET  /admin``      → the FLAW: it reads ``sub`` from the cookie JWT WITHOUT
                            verifying the signature. Anonymous → 401 (baseline
                            denied); ``sub == "administrator"`` → 200 (breach
                            granted); any other genuine user → 403.

The whole chain runs through the REAL capability code: the real headless HTTP
form-login (:mod:`app.security_graph.session.form_login`, via a scoped
``requests.Session``) captures the cookie, and the real broken_auth prove-chain
(:func:`run_broken_auth_investigation`, urllib executor) drives the live
three-probe differential against the stub. Only the matrix loader is stubbed to
return the parsed policy in-process. The captured token's VALUE never appears in
a note. Nothing here decides the verdict — the pure judge disposes it.
"""

import base64
import hashlib
import hmac
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from app.autonomous import authmatrix as AM
from app.autonomous import orchestrator as O
from app.autonomous.steer import OperatorDirective
from app.security_graph.broken_auth import parse_broken_auth_policy
from app.security_graph.privesc.privesc_policy import PrivEscPolicy


# ---- mint the genuine session JWT (sub=wiener) ------------------------------
# The stub never verifies the signature, so any real JWS shape serves; we sign
# HS256 under a throwaway secret purely to produce a valid 3-part token.

def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _mint_jwt(sub: str) -> str:
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iss": "portswigger", "exp": 4102444800, "sub": sub}
    hseg, pseg = _b64url(header), _b64url(payload)
    sig = hmac.new(b"stub-signing-key", f"{hseg}.{pseg}".encode("ascii"),
                   hashlib.sha256).digest()
    sseg = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    return f"{hseg}.{pseg}.{sseg}"


GENUINE_JWT = _mint_jwt("wiener")

_LOGIN_HTML = (
    "<html><body>"
    '<form action="/login" method="POST">'
    '<input type="text" name="username">'
    '<input type="password" name="password">'
    '<button type="submit">Log in</button>'
    "</form></body></html>"
).encode("utf-8")


def _sub_from_cookie(cookie_header: str):
    """Read ``sub`` from the ``session`` cookie's JWT payload WITHOUT verifying the
    signature — the exact flaw this lab embodies."""
    token = None
    for part in (cookie_header or "").split(";"):
        key, _, value = part.strip().partition("=")
        if key == "session":
            token = value.strip()
    if not token:
        return None
    segments = token.split(".")
    if len(segments) < 2:
        return None
    try:
        pad = "=" * (-len(segments[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(segments[1] + pad))
    except Exception:  # noqa: BLE001 — an undecodable cookie is simply no session
        return None
    return payload.get("sub")


class _FlawedJwtLab(BaseHTTPRequestHandler):
    def log_message(self, *args, **kwargs):
        return

    def _send(self, code: int, body: bytes = b"{}", cookie: str | None = None):
        self.send_response(code)
        ctype = "text/html" if body[:1] == b"<" else "application/json"
        self.send_header("Content-Type", ctype)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/login":
            self._send(200, _LOGIN_HTML)
        elif path == "/my-account":
            # control: any live (decodable) session reaches its own account
            self._send(200 if _sub_from_cookie(self.headers.get("Cookie")) else 401)
        elif path == "/admin":
            sub = _sub_from_cookie(self.headers.get("Cookie"))
            if sub is None:
                self._send(401)             # anonymous baseline → denied
            elif sub == "administrator":
                self._send(200)             # flaw: sub honoured, signature ignored
            else:
                self._send(403)             # a genuine non-admin is refused
        else:
            self._send(404)

    def do_POST(self):
        if urlsplit(self.path).path != "/login":
            self._send(404)
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        fields = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode("utf-8")))
        if fields.get("username") == "wiener" and fields.get("password") == "peter":
            self._send(200, b"welcome", cookie=f"session={GENUINE_JWT}; Path=/")
        else:
            self._send(401)


def _matrix_policy():
    """The operator's cookie-session forgery matrix: forge an alg=none token that
    escalates sub to administrator and prove /admin accepts it."""
    return parse_broken_auth_policy(
        {
            "broken_auth_matrix": {
                "token_location": {"kind": "cookie", "name": "session"},
                "principal": {
                    "name": "wiener",
                    "role": "user",
                    "control": {"method": "GET", "path": "/my-account"},
                },
                "checks": [
                    {
                        "forgery": "alg_none",
                        "route": {"method": "GET", "path": "/admin"},
                        "forge_claims": {"sub": "administrator"},
                        "severity": "HIGH",
                    }
                ],
            }
        }
    )


def test_sentinel_independently_logs_in_and_confirms_jwt_alg_none_bypass():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FlawedJwtLab)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        policy = _matrix_policy()

        # ONLY credentials + a login URL + the matrix — no token handed in. Sentinel
        # must log in itself and capture the session-cookie JWT via the REAL client.
        directive = OperatorDirective(
            credentials=("wiener", "peter"),
            login_url=f"{base}/login",
            matrix_path="/matrix.json",  # truthy path; loader is stubbed in-process
        )
        ctx = AM.resolve_auth_context(
            directive, env={}, target=base,
            load_broken_auth=lambda _p: policy,
            load_privesc=lambda _p: PrivEscPolicy(),
        )

        # A genuine token was captured live and the class is now active...
        assert ctx.token is not None
        assert ctx.has_broken_auth
        # ...but its VALUE never leaks into an operator-visible note.
        joined = " ".join(ctx.notes)
        assert GENUINE_JWT not in joined
        assert "peter" not in joined            # the password never surfaces
        assert "token captured" in joined

        # The pure judge disposes the live three-probe differential → CONFIRMED.
        verdicts = AM.run_auth_matrix(base, ctx)
        broken_auth = [v for v in verdicts
                       if v.hypothesis.technique == "broken_auth"]
        assert len(broken_auth) == 1
        assert broken_auth[0].status == O.VERDICT_CONFIRMED
    finally:
        server.shutdown()
        server.server_close()
