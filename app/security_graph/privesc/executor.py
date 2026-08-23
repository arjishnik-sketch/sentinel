"""
Live probe for the privilege-escalation class.

This reuses :class:`HttpAuthorizationExecutor` verbatim — that executor already
records the raw HTTP facts a privilege differential needs (status code, headers,
body length) without interpreting them. The only difference is the experiment
`kind` it answers to, so the autonomous engine dispatches privilege-escalation
probes here and authorization/header/cookie probes to their own executors, with
no shared interpretation.

Like its parent it records HTTP facts only and never decides whether a response
represents an escalation; the deterministic judge does that from the three-probe
control/breach/baseline differential. The same optional host allowlist bounds
every request to the engagement scope.
"""

from __future__ import annotations

from ..execution.http import HttpAuthorizationExecutor


class PrivEscProbeExecutor(HttpAuthorizationExecutor):
    """Execute one explicitly specified HTTP privilege-escalation probe."""

    kind = "privilege_escalation_check"
