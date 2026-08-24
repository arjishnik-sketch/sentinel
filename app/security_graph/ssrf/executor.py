"""
Live probe for the SSRF (server-side request forgery) class.

This reuses :class:`HttpAuthorizationExecutor` verbatim — the SSRF signal is
NOT in the target's response to us (a bare status code is never the verdict);
it is the out-of-band callback recorded by Sentinel's own loopback collaborator
(see :mod:`.collaborator`). The executor's only job is to *deliver* the probe
request (with the injected fetch URL) to the target and record the HTTP fact of
having done so; the RUNNER then reads the collaborator's hit record and writes it
as separate ``ssrf_callback`` evidence for the pure judge.

Like its parent it records HTTP facts only and never decides whether the target
made a server-side fetch; the deterministic judge does that from the callback
evidence. The same optional host allowlist bounds every request to the
engagement scope — so the *probe request itself* only ever reaches the target we
were asked to investigate.
"""

from __future__ import annotations

from ..execution.http import HttpAuthorizationExecutor


class SsrfProbeExecutor(HttpAuthorizationExecutor):
    """Execute one explicitly specified SSRF fetch-surface probe."""

    kind = "ssrf_check"
