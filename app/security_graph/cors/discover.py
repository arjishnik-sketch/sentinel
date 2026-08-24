"""
Zero-oracle CORS discovery — synthesize a CORS matrix from live recon.

This is what lets the CORS class join Sentinel's *discoverer* story: point it at
a URL and it derives the cross-origin surfaces to probe from what reconnaissance
actually observed, rather than from a hand-typed ``cors_matrix``.

Why this is honest (the epistemic contract is fully preserved). Like SSTI and
open redirect, CORS's ground truth is *internal*: the two-probe origin
differential (an attacker ``Origin`` header naming an unforgeable nonce origin
plus a no-Origin control anchor) is self-anchoring — a surface is CONFIRMED only
when the backend provably reflects our nonce origin (or ``*``) in
``Access-Control-Allow-Origin`` AND allows credentials AND the control proves the
reflection is origin-driven. So the operator never needed to supply *intent* for
this class, only *where to look*. This module supplies "where to look" from
observed surface instead of a file:

  * every distinct request path reconnaissance actually saw on the live target
    (ranked so credential-bearing / API / auth surfaces win a bounded budget,
    since those are where a credentialed cross-origin read leaks data), plus
  * the site root as a always-present baseline surface.

Neither source makes a security claim. Each synthesized check is exactly the same
OPEN question the operator matrix poses. The SAME pure :func:`judge_cors` decides
the outcome by re-probing the live target. A surface that does not reflect our
attacker Origin (or reflects it without credentials, or emits a static header)
collapses to DISPROVED; nothing here can manufacture a verdict.

The result is a plain :class:`CorsPolicy` — identical in type to a parsed
operator matrix — so it flows through the existing seed → probe → judge → prove
chain with not a line of change downstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ..graph import SecurityGraph
from .cors_policy import CorsCheck, CorsPolicy
# Path substrings that suggest an endpoint returns credential-scoped or
# otherwise sensitive data — the surfaces where a credentialed cross-origin read
# is most damaging, so they win a bounded probe budget first. Generic web/auth/API
# vocabulary, never a single application's routes.
_SENSITIVE_SURFACE_HINTS = (
    "api",
    "account",
    "profile",
    "user",
    "users",
    "me",
    "admin",
    "session",
    "token",
    "auth",
    "login",
    "logout",
    "oauth",
    "sso",
    "data",
    "private",
    "secure",
    "order",
    "orders",
    "cart",
    "basket",
    "wallet",
    "balance",
    "payment",
    "billing",
    "invoice",
    "email",
    "message",
    "messages",
    "settings",
    "config",
    "graphql",
    "rest",
    "v1",
    "v2",
)

# Static assets never carry a credentialed CORS surface worth a probe; skip them.
_ASSET_SUFFIXES = (
    ".js",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".webm",
    ".mp3",
    ".pdf",
    ".zip",
    ".html",
    ".htm",
    ".txt",
    ".xml",
)


@dataclass(frozen=True)
class _Candidate:
    """One synthesized cross-origin-surface candidate, with its provenance."""

    method: str
    path: str
    source: str  # "observed_surface" | "generic_root"


def _path_of(url: str) -> str:
    split = urlsplit(url if "://" in url else f"http://{url}")
    return split.path or "/"


def _looks_static(path: str) -> bool:
    return path.lower().endswith(_ASSET_SUFFIXES)


def _is_sensitive_surface(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in _SENSITIVE_SURFACE_HINTS)
def _observed_candidates(graph: SecurityGraph) -> list[_Candidate]:
    """
    Candidates drawn from distinct request paths reconnaissance actually observed.

    Two observed sources are merged, both GET-only (exactly what recon can see
    non-destructively): ``recon_parameter`` observation URLs and discovered
    endpoint URLs. Paths are ranked so credential-bearing / API / auth surfaces
    win a bounded probe budget first; any other observed path is still probed
    (self-anchoring → it simply collapses to DISPROVED if it does not reflect our
    attacker Origin with credentials). The path is read off the live target,
    never invented.
    """
    ranked: list[tuple[bool, int, _Candidate]] = []
    seen: set[str] = set()

    def _consider(url: str) -> None:
        if not isinstance(url, str) or not url.strip():
            return
        path = _path_of(url)
        if not path or _looks_static(path):
            return
        if path in seen:
            return
        seen.add(path)
        ranked.append(
            (
                not _is_sensitive_surface(path),  # sensitive surfaces first
                len(ranked),                       # stable insertion order
                _Candidate(method="GET", path=path, source="observed_surface"),
            )
        )

    for observation in graph.observations.values():
        if observation.kind != "recon_parameter":
            continue
        data = observation.data if isinstance(observation.data, dict) else {}
        _consider(data.get("url"))

    for endpoint in graph.endpoints.values():
        if (endpoint.method or "GET").upper() != "GET":
            continue
        _consider(endpoint.url)

    ranked.sort(key=lambda item: (item[0], item[1]))
    return [candidate for _a, _b, candidate in ranked]


@dataclass(frozen=True)
class CorsDiscovery:
    """A synthesized CORS policy plus a human-readable provenance summary."""

    policy: CorsPolicy
    observed_count: int
    generic_count: int
    total_candidates: int  # before the max_checks cap

    @property
    def note(self) -> str:
        return (
            f"{len(self.policy.checks)} cross-origin surface(s) synthesized from "
            f"live recon — {self.observed_count} observed path(s), "
            f"{self.generic_count} baseline root surface(s)"
            + (
                f" (capped from {self.total_candidates})"
                if self.total_candidates > len(self.policy.checks)
                else ""
            )
        )
def synthesize_cors_policy(
    graph: SecurityGraph,
    *,
    max_checks: int = 24,
    include_generic: bool = True,
) -> CorsDiscovery:
    """
    Build a :class:`CorsPolicy` from the recon surface already in ``graph``.

    Pure and target-agnostic: it reads only observed recon (discovered GET
    endpoints and parameter-observation URLs), plus the site root as an
    always-present baseline surface, and returns a policy of the same type a
    parsed operator matrix produces. The prove-chain downstream is unchanged; the
    pure judge decides every synthesized check, so no verdict can be
    manufactured. ``max_checks`` bounds live request volume.
    """
    observed = _observed_candidates(graph)
    seen_paths = {c.path for c in observed}

    generic: list[_Candidate] = []
    if include_generic and "/" not in seen_paths:
        generic.append(_Candidate(method="GET", path="/", source="generic_root"))

    ranked = observed + generic
    total = len(ranked)
    selected = ranked[: max(0, max_checks)]

    checks = tuple(
        CorsCheck(
            method=c.method,
            path=c.path,
            severity="MEDIUM",
            rationale=(
                "Surface discovered from live reconnaissance "
                f"({c.source.replace('_', ' ')}); probed for an origin-reflecting, "
                "credentialed CORS policy by the two-probe origin differential."
            ),
        )
        for c in selected
    )

    return CorsDiscovery(
        policy=CorsPolicy(checks=checks),
        observed_count=sum(1 for c in selected if c.source == "observed_surface"),
        generic_count=sum(1 for c in selected if c.source == "generic_root"),
        total_candidates=total,
    )



