"""
The Sentinel out-of-band (OOB) collaborator — the novel, SSRF-safe half of the
server-side request-forgery proof.

An SSRF is proven not by what the target returns to *us*, but by whether the
target can be coerced into making a request *of its own* to a location we
control. This module stands up that location: a tiny HTTP listener bound to an
ephemeral **loopback** port that records every request path it receives.

Soundness + safety are one and the same design here:

  * The listener binds ``127.0.0.1:0`` only — it is Sentinel's OWN loopback
    server, never a public endpoint. The probe injects EXACTLY this loopback
    URL (carrying a random nonce) into the target's fetch parameter. Sentinel
    therefore only ever asks the target to fetch Sentinel's own collaborator;
    it never points the target at ``169.254.169.254``, an RFC-1918 range, or any
    third-party host. The blast radius is a single loopback round-trip.
  * A request arriving at ``/<nonce>`` can ONLY have been produced by something
    fetching the URL we injected — the nonce is random and appears nowhere else.
    So a recorded hit on our nonce is unforgeable proof of a server-side fetch of
    an attacker-controlled URL. A bare target status code is never the verdict.
  * The collaborator makes no outbound request of any kind, performs no DNS, and
    forwards nothing. It only ever *receives* and records. It is the inbound
    analogue of :class:`RemediationEnforcer` (same loopback / ephemeral-port /
    context-manager shape), and just as SSRF-safe by construction.

The recorded hits are read by the RUNNER (which then writes them into graph
evidence); the PURE judge reads only that evidence, never this server. Nothing
here decides a vulnerability — it only records a fact.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _nonce_of(path: str) -> str:
    """
    Extract the leading path segment (the nonce) from a request path.

    ``/abc123/anything?x=1`` -> ``abc123``. Robust to missing/empty paths.
    """

    raw = (path or "").split("?", 1)[0].split("#", 1)[0]
    segments = [segment for segment in raw.split("/") if segment]
    return segments[0] if segments else ""


@dataclass(frozen=True)
class CollaboratorHit:
    """A single recorded inbound request. Pure data — never a verdict."""

    nonce: str
    path: str
    source_ip: str
    timestamp: float


class _CollaboratorHandler(BaseHTTPRequestHandler):
    """
    Records the request, then answers a trivial 200 so the target's
    server-side fetch *succeeds* (a failed fetch could mask a real SSRF).
    """

    # Silence the stdlib per-request stderr logging.
    def log_message(self, *args, **kwargs):  # noqa: D401,N802
        return

    def _record_and_ack(self) -> None:
        self.server.record_request(  # type: ignore[attr-defined]
            path=self.path,
            source_ip=self.client_address[0],
        )
        body = b"sentinel-collaborator\n"
        self.send_response_only(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # Any verb a fetching target might use is treated identically.
    do_GET = _record_and_ack
    do_POST = _record_and_ack
    do_HEAD = _record_and_ack
    do_PUT = _record_and_ack
    do_OPTIONS = _record_and_ack


class _CollaboratorServer(ThreadingHTTPServer):
    """Loopback HTTP server that records every inbound request it receives."""

    daemon_threads = True
    # Fail fast on a dead fetch rather than hanging a probe thread.
    timeout = 5

    def __init__(self, server_address, handler_cls):
        super().__init__(server_address, handler_cls)
        self._lock = threading.Lock()
        self._hits: list[CollaboratorHit] = []

    def record_request(self, *, path: str, source_ip: str) -> None:
        hit = CollaboratorHit(
            nonce=_nonce_of(path),
            path=path,
            source_ip=source_ip,
            timestamp=time.time(),
        )
        with self._lock:
            self._hits.append(hit)

    def hits_for(self, nonce: str) -> tuple[CollaboratorHit, ...]:
        key = (nonce or "").strip()
        with self._lock:
            return tuple(hit for hit in self._hits if hit.nonce == key)


class SentinelCollaborator:
    """
    Sentinel's own out-of-band listener — the location an SSRF-vulnerable
    target is coerced into fetching.

    Lifecycle mirrors :class:`RemediationEnforcer`: bind ``127.0.0.1:0``
    (ephemeral loopback), serve on a daemon thread, and expose a context
    manager. It never dials out; it only records what dials *in*.
    """

    def __init__(self, *, host: str = "127.0.0.1"):
        self._host = host
        self._server: _CollaboratorServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "SentinelCollaborator":
        if self._server is not None:
            return self
        self._server = _CollaboratorServer(
            (self._host, 0),
            _CollaboratorHandler,
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="sentinel-collaborator",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def __enter__(self) -> "SentinelCollaborator":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- addressing --------------------------------------------------------

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("collaborator is not running")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def callback_url(self, nonce: str) -> str:
        """The exact loopback URL to inject for ``nonce``."""

        return f"{self.base_url}/{nonce}"

    # -- observation (read by the RUNNER, never by the pure judge) ---------

    def was_hit(self, nonce: str) -> bool:
        if self._server is None:
            return False
        return bool(self._server.hits_for(nonce))

    def hits(self, nonce: str) -> tuple[CollaboratorHit, ...]:
        if self._server is None:
            return ()
        return self._server.hits_for(nonce)

    def wait_for_hit(
        self,
        nonce: str,
        *,
        timeout: float = 1.5,
        interval: float = 0.02,
    ) -> bool:
        """
        Poll for a hit on ``nonce`` up to ``timeout`` seconds.

        A server-side fetch may land microseconds after the target's own
        response returns to us, so the payload snapshot polls briefly rather
        than reading once.
        """

        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if self.was_hit(nonce):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(interval)
