"""Scope-guarded HTTP prober for the autonomous loop.

Mirrors the security_graph executor's safety contract exactly: every request is
refused BEFORE a socket opens unless the scheme is http/https, the method is
allowed, and (when an allowlist is set) the host is in scope. The `_opener` seam
makes it fully testable offline. Returns plain facts (status/headers/cookies/
body) — it never decides whether a response means anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
_MAX_BODY = 262144  # 256 KiB, same bound as the graph executor


class ScopeError(ValueError):
    """Raised (pre-socket) when a request violates scope/scheme/method."""


@dataclass
class Probe:
    method: str
    url: str
    status: "int | None"
    headers: dict = field(default_factory=dict)
    set_cookie: tuple = ()
    body_text: str = ""
    error: str = ""


def enforce_scope(url, allowed_hosts):
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ScopeError(f"refusing non-HTTP scheme: {scheme or 'none'}")
    if allowed_hosts is None:
        return
    host = (parsed.netloc or "").lower()
    if host not in allowed_hosts:
        raise ScopeError(f"refusing out-of-scope host: {host or 'none'}")


def _set_cookies(headers):
    get_all = getattr(headers, "get_all", None)
    return tuple(get_all("Set-Cookie") or ()) if get_all else ()


def _body(raw):
    return raw[:_MAX_BODY].decode("utf-8", "replace") if raw else ""


class HttpProber:
    def __init__(self, allowed_hosts=None, *, timeout=15, opener=None):
        self.allowed_hosts = (
            {h.lower() for h in allowed_hosts} if allowed_hosts is not None else None
        )
        self.timeout = timeout
        self._opener = opener or (lambda req, timeout: urlopen(req, timeout=timeout))

    def request(self, method, url, *, headers=None, body=None) -> Probe:
        method = method.upper()
        if method not in _ALLOWED_METHODS:
            raise ScopeError(f"refusing method: {method}")
        enforce_scope(url, self.allowed_hosts)  # pre-socket guard

        data = body.encode("utf-8") if isinstance(body, str) else body
        req = Request(url, data=data, headers=headers or {}, method=method)
        try:
            with self._opener(req, timeout=self.timeout) as resp:
                return Probe(
                    method, url, resp.status,
                    dict(resp.headers.items()), _set_cookies(resp.headers),
                    _body(resp.read()),
                )
        except HTTPError as exc:
            return Probe(
                method, url, exc.code,
                dict(exc.headers.items()), _set_cookies(exc.headers),
                _body(exc.read()),
            )
        except URLError as exc:
            return Probe(method, url, None, {}, (), "", error=str(exc.reason))
