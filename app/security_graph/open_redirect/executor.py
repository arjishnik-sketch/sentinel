"""
Live probe for the open-redirect class — a NO-FOLLOW HTTP executor.

This is the one class whose executor cannot reuse the base executor verbatim.
An open redirect is proven by the response ``Location`` header, and
``urllib.request.urlopen`` FOLLOWS 3xx redirects transparently by default — so
the ``Location`` would be consumed and the followed page returned instead. Worse,
following an *off-origin* redirect payload would make Sentinel actually contact
the attacker host — precisely what we must never do.

So this executor overrides the base's :meth:`_urlopen` seam with an opener whose
redirect handler refuses to follow: a 3xx surfaces as an ``HTTPError``, which the
base executor's existing ``except HTTPError`` branch captures — recording the
status code and the full response headers, ``Location`` included — WITHOUT ever
opening a connection to the redirect target. The payload host
(``sentinel-<nonce>.example``) is unroutable (RFC 2606) and, thanks to no-follow,
is never contacted regardless.

Like its parent it records HTTP facts only and never decides whether a response
represents an open redirect; the deterministic judge does that from the
observed ``Location`` host. The same optional host allowlist bounds every request
to the engagement scope (the request URL is always on the target — only the
parameter *value* names the nonce host, and it is never fetched).
"""

from __future__ import annotations

from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..execution.http import HttpAuthorizationExecutor


class _NoFollowRedirectHandler(HTTPRedirectHandler):
    """A redirect handler that never follows — it surfaces the 3xx as an error.

    Returning ``None`` from ``redirect_request`` tells urllib not to build a
    follow-up request, so the 3xx response is raised as an ``HTTPError`` (whose
    headers carry ``Location``) instead of being transparently followed.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class OpenRedirectProbeExecutor(HttpAuthorizationExecutor):
    """Execute one explicitly specified HTTP open-redirect probe (no-follow)."""

    kind = "open_redirect_check"

    def __init__(self, allowed_hosts=None) -> None:
        super().__init__(allowed_hosts=allowed_hosts)
        # A private opener with redirect-following disabled. Reused across probes;
        # it holds no per-request state.
        self._opener = build_opener(_NoFollowRedirectHandler)

    def _urlopen(self, request: Request, *, timeout: float):
        return self._opener.open(request, timeout=timeout)
