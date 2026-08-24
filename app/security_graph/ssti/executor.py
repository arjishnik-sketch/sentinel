"""
Live probe for the SSTI (server-side template injection) class.

This reuses :class:`HttpAuthorizationExecutor` verbatim — that executor already
records the raw HTTP facts an arithmetic-evaluation differential needs: the
status code and, since the shared body-capture addition, a bounded prefix of the
response body text (``response_body_text``). The only difference is the
experiment `kind` it answers to, so the autonomous engine dispatches SSTI probes
here and authorization/header/cookie/privesc/injection probes to their own
executors, with no shared interpretation.

Like its parent it records HTTP facts only and never decides whether a response
represents template evaluation; the deterministic judge does that from the
control/payload body differential. The same optional host allowlist bounds every
request to the engagement scope.
"""

from __future__ import annotations

from ..execution.http import HttpAuthorizationExecutor


class SSTIProbeExecutor(HttpAuthorizationExecutor):
    """Execute one explicitly specified HTTP SSTI probe."""

    kind = "template_injection_check"
