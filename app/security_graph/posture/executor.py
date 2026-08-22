"""
Live probe for the security-header posture class.

This reuses :class:`HttpAuthorizationExecutor` verbatim — that executor
already records the full response header dict as an HTTP fact (it does not
interpret it), which is exactly what a header-posture judge needs. The only
difference is the experiment `kind` it answers to, so the autonomous engine
dispatches header probes to this executor and authorization probes to the
base one, with no shared interpretation.

Like its parent it records HTTP facts only and never decides whether a
header configuration is a vulnerability; the deterministic judge does that.
The same optional host allowlist bounds every request to the engagement
scope.
"""

from __future__ import annotations

from ..execution.http import HttpAuthorizationExecutor


class SecurityHeaderExecutor(HttpAuthorizationExecutor):
    """Execute one explicitly specified HTTP security-header probe."""

    kind = "security_header_check"
