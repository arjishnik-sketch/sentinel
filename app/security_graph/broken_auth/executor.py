"""
Live probe for the broken-authentication class.

This reuses :class:`HttpAuthorizationExecutor` verbatim — that executor already
records the raw HTTP facts a token-validation differential needs (status code,
headers, body length) without interpreting them. The only difference is the
experiment `kind` it answers to, so the autonomous engine dispatches
broken-auth probes here and every other class's probes to their own executors,
with no shared interpretation.

Like its parent it records HTTP facts only and never decides whether a response
represents a broken-auth flaw; the deterministic judge does that from the
three-probe control/breach/baseline differential. The same optional host
allowlist bounds every request to the engagement scope.
"""

from __future__ import annotations

from ..execution.http import HttpAuthorizationExecutor


class BrokenAuthProbeExecutor(HttpAuthorizationExecutor):
    """Execute one explicitly specified HTTP broken-authentication probe."""

    kind = "broken_auth_check"
