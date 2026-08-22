"""
Enforcement shield — the live half of PATCH + PROVE.

Given a provider-agnostic :class:`AccessControlRule` derived from a
*confirmed* authorization contradiction, this module stands a real reverse
proxy up on loopback in front of the engagement target. The proxy denies
exactly the request the rule forbids (403) and forwards everything else
unchanged to the fixed upstream. Re-probing the same authorization
property THROUGH this proxy is what lets the deterministic judge PROVE the
fix live — no source code required.

Nothing here invents authorization semantics. The decision is a pure
function of the rule and the request's own headers; the proxy only ever
forwards to the one upstream it was constructed with (SSRF-safe by
construction), lives on an ephemeral loopback port, and is scoped to the
lifetime of a single verification.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .model import AccessControlRule


# Presence of any of these request headers marks a *non-anonymous* caller:
# bearer/basic auth, a session cookie, or the two most common custom token
# headers. General across stacks — nothing target-specific.
_AUTH_INDICATOR_HEADERS = frozenset(
    {"authorization", "cookie", "x-access-token", "x-api-key"}
)

# Hop-by-hop headers a proxy must never forward verbatim.
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)

def _lower_keys(headers) -> dict[str, str]:
    """Normalise any header mapping/pair-iterable to lowercase-keyed dict."""
    if headers is None:
        return {}
    items = headers.items() if hasattr(headers, "items") else headers
    return {str(name).lower(): str(value) for name, value in items}


def _request_is_anonymous(lowered: dict[str, str]) -> bool:
    """True when the request presents no recognised principal credential."""
    return not any(name in lowered for name in _AUTH_INDICATOR_HEADERS)


def _rule_matches_principal(
    rule: AccessControlRule,
    lowered: dict[str, str],
) -> bool:
    if rule.principal_kind == "anonymous":
        # The anonymous deny rule targets only the credential-less caller.
        # A request bearing credentials is a *different* principal.
        return _request_is_anonymous(lowered)

    if rule.principal_headers:
        # A specific principal is recognised only by its exact identifying
        # headers (case-insensitive name, exact value).
        for name, value in rule.principal_headers:
            if lowered.get(str(name).lower()) != str(value):
                return False
        return True

    # A named principal we cannot fingerprint from the request alone:
    # enforce on the route itself (best-effort; documented).
    return True


def evaluate_request(rules, method, path, headers) -> str:
    """
    Pure access decision for one request against the derived rules.

    Returns ``"deny"`` if any rule forbids this request, else
    ``"forward"``. Matching is exact on method and path; principal
    identity is decided by the request's own headers. No HTTP status is
    interpreted here — this is enforcement, not observation.
    """
    method_norm = (method or "").strip().upper()
    path_norm = path or ""
    lowered = _lower_keys(headers)

    for rule in rules:
        if rule.decision != "deny":
            continue
        if rule.method.strip().upper() != method_norm:
            continue
        if rule.path != path_norm:
            continue
        if _rule_matches_principal(rule, lowered):
            return "deny"

    return "forward"

class _EnforcementServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, *, rules, upstream_base):
        super().__init__(address, handler)
        self.rules = tuple(rules)
        parsed = urlsplit(upstream_base)
        self.upstream_scheme = (parsed.scheme or "http").lower()
        self.upstream_netloc = parsed.netloc
        self.upstream_base = f"{self.upstream_scheme}://{self.upstream_netloc}"


def _json_response(handler, code: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.wfile.write(body)


class _EnforcementHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 with explicit Content-Length + Connection: close on every
    # response keeps the tiny proxy correct without keep-alive bookkeeping.
    protocol_version = "HTTP/1.1"

    def log_message(self, *args, **kwargs):  # keep the CLI output clean
        return

    def _handle(self):
        server = self.server
        split = urlsplit(self.path)
        decision = evaluate_request(
            server.rules,
            self.command,
            split.path,
            self.headers,
        )
        if decision == "deny":
            _json_response(
                self,
                403,
                {"error": "Forbidden", "by": "sentinel-remediation"},
            )
            return
        self._forward(server)

    def _read_body(self):
        length = self.headers.get("Content-Length")
        if length is None:
            return None
        try:
            count = int(length)
        except (TypeError, ValueError):
            return None
        return self.rfile.read(count) if count > 0 else None

    def _forward(self, server):
        # self.path preserves the exact path + query; the host is fixed to
        # the single upstream this enforcer was constructed with.
        upstream_url = server.upstream_base + self.path
        body = self._read_body()

        forwarded = {}
        for name, value in self.headers.items():
            lname = name.lower()
            if lname in _HOP_BY_HOP or lname == "host":
                continue
            forwarded[name] = value
        forwarded["Host"] = server.upstream_netloc

        request = Request(
            upstream_url,
            data=body,
            headers=forwarded,
            method=self.command,
        )

        try:
            with urlopen(request, timeout=10) as response:
                status = response.status
                resp_headers = list(response.headers.items())
                resp_body = response.read()
        except HTTPError as exc:
            status = exc.code
            resp_headers = list(exc.headers.items())
            resp_body = exc.read()
        except (URLError, OSError) as exc:
            _json_response(
                self,
                502,
                {
                    "error": "Bad Gateway",
                    "detail": str(exc),
                    "by": "sentinel-remediation",
                },
            )
            return

        self.send_response(status)
        for name, value in resp_headers:
            lname = name.lower()
            if lname in _HOP_BY_HOP or lname == "content-length":
                continue
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(resp_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(resp_body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle

class RemediationEnforcer:
    """
    A live, provider-agnostic enforcement shield.

    Wraps a threaded HTTP reverse proxy bound to an ephemeral loopback
    port. It denies exactly what the supplied rule(s) forbid and forwards
    every other request to the fixed ``upstream_base``. Use as a context
    manager so the listener is always torn down::

        with RemediationEnforcer(rule, upstream_base) as shield:
            probe(shield.base_url + path)

    The proxy is unauthenticated but reachable only on 127.0.0.1 via a
    random port, exists solely for the duration of one verification, and
    can never reach any host other than the engagement target.
    """

    def __init__(self, rules, upstream_base: str):
        if isinstance(rules, AccessControlRule):
            rules = (rules,)
        self._server = _EnforcementServer(
            ("127.0.0.1", 0),
            _EnforcementHandler,
            rules=rules,
            upstream_base=upstream_base,
        )
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> "RemediationEnforcer":
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                name="sentinel-remediation-enforcer",
                daemon=True,
            )
            self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "RemediationEnforcer":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.stop()
        return False
