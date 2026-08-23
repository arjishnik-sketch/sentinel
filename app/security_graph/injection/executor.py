"""
Live probe for the injection class.

This reuses :class:`HttpAuthorizationExecutor` verbatim — that executor already
records the raw HTTP facts a boolean differential needs (status code and
response body length) without interpreting them. The only difference is the
experiment `kind` it answers to, so the autonomous engine dispatches injection
probes here and authorization/header/cookie/privesc probes to their own
executors, with no shared interpretation.

Like its parent it records HTTP facts only and never decides whether a response
represents an injection; the deterministic judge does that from the
baseline/TRUE/FALSE differential. The same optional host allowlist bounds every
request to the engagement scope.
"""

from __future__ import annotations

from ..execution.http import HttpAuthorizationExecutor


class InjectionProbeExecutor(HttpAuthorizationExecutor):
    """Execute one explicitly specified HTTP injection probe."""

    kind = "injection_check"
