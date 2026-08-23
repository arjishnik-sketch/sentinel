"""
Live probe for the insecure-cookie class.

This reuses :class:`HttpAuthorizationExecutor` verbatim — that executor
already records every raw ``Set-Cookie`` response header as an HTTP fact (it
does not interpret it), which is exactly what a cookie-security judge needs.
The only difference is the experiment `kind` it answers to, so the autonomous
engine dispatches cookie probes to this executor and authorization/header
probes to their own, with no shared interpretation.

Like its parent it records HTTP facts only and never decides whether a cookie
configuration is a vulnerability; the deterministic judge does that. The same
optional host allowlist bounds every request to the engagement scope.
"""

from __future__ import annotations

from ..execution.http import HttpAuthorizationExecutor


class CookieProbeExecutor(HttpAuthorizationExecutor):
    """Execute one explicitly specified HTTP cookie-security probe."""

    kind = "cookie_check"
