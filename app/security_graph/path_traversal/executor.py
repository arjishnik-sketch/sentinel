"""
Live probe for the path-traversal / LFI class.

This reuses :class:`HttpAuthorizationExecutor` verbatim — that executor already
records the raw HTTP facts a canary differential needs: the status code and,
since the shared body-capture addition, a bounded prefix of the response body
text (``response_body_text``, up to 256 KiB — far more than enough to carry an
OS-file invariant, which sits at the very start of ``/etc/passwd`` and
``win.ini``). The only difference is the experiment `kind` it answers to, so the
autonomous engine dispatches path-traversal probes here and every other class to
its own executor, with no shared interpretation.

Like its parent it records HTTP facts only and never decides whether a response
leaked an OS file; the deterministic judge does that from the control/payload
body differential (an OS-file invariant regex present under a traversal payload
and absent from the benign control). The same optional host allowlist bounds
every request to the engagement scope.
"""

from __future__ import annotations

from ..execution.http import HttpAuthorizationExecutor


class PathTraversalProbeExecutor(HttpAuthorizationExecutor):
    """Execute one explicitly specified HTTP path-traversal probe."""

    kind = "path_traversal_check"
