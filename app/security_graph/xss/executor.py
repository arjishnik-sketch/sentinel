"""
Live probe for the reflected-XSS class.

This reuses :class:`HttpAuthorizationExecutor` verbatim — that executor already
records the raw HTTP facts a reflection differential needs: the status code and,
since the shared body-capture addition, a bounded prefix of the response body
text (``response_body_text``). The only difference is the experiment `kind` it
answers to, so the autonomous engine dispatches XSS probes here and
authorization/header/cookie/privesc/injection/SSTI probes to their own
executors, with no shared interpretation.

Like its parent it records HTTP facts only and never decides whether a response
reflects un-escaped markup; the deterministic judge does that from the
control/payload body differential. The same optional host allowlist bounds every
request to the engagement scope.
"""

from __future__ import annotations

from ..execution.http import HttpAuthorizationExecutor


class XSSProbeExecutor(HttpAuthorizationExecutor):
    """Execute one explicitly specified HTTP reflected-XSS probe."""

    kind = "xss_check"
