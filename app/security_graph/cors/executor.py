"""
Live probe for the CORS class.

This reuses :class:`HttpAuthorizationExecutor` verbatim — that executor already
SENDS the request headers it is given (so the payload probe's ``Origin`` header
is delivered) and RECORDS the full response header dict as an HTTP fact (so the
``Access-Control-Allow-Origin`` / ``Access-Control-Allow-Credentials`` the judge
reads are captured). It does not interpret them. The only difference from the
base executor is the experiment ``kind`` it answers to, so the autonomous engine
dispatches CORS probes here and authorization probes to the base one, with no
shared interpretation.

Unlike the open-redirect executor there is NO no-follow override: CORS is decided
by response headers, not a ``Location`` we must refrain from following, and the
nonce origin is only ever ECHOED in a response header — never a destination
Sentinel is asked to fetch. The same optional host allowlist bounds every request
to the engagement scope.
"""

from __future__ import annotations

from ..execution.http import HttpAuthorizationExecutor


class CorsProbeExecutor(HttpAuthorizationExecutor):
    """Execute one explicitly specified HTTP CORS probe."""

    kind = "cors_check"
