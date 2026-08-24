"""
Zero-oracle SSRF discovery — synthesize an SSRF matrix from live recon.

This is what lets the SSRF class join Sentinel's *discoverer* story: point it at a
URL and it derives the server-side-fetch parameters to probe from what
reconnaissance actually observed, rather than from a hand-typed ``ssrf_matrix``.

Why this is honest (the epistemic contract is fully preserved). Like open-redirect,
SSRF's ground truth is *internal*: the out-of-band callback differential (a payload
pointing at Sentinel's OWN loopback collaborator on an unforgeable nonce, plus a
never-injected control nonce) is self-anchoring — a parameter is CONFIRMED only
when the backend provably makes a server-side request that reaches our collaborator
on our nonce, while the control nonce stays un-hit. So the operator never needed to
supply *intent* for this class, only *where to look*. This module supplies "where
to look" from observed surface instead of a file:

  * every query parameter reconnaissance actually saw on the live target
    (ranked so conventional fetch-URL names win a bounded budget), and
  * a small, fixed, target-AGNOSTIC list of conventional fetch-URL parameters
    attached to endpoints that look like fetchers (proxy / fetch / webhook /
    image / import / preview / avatar …), so a fetch parameter that never appears
    pre-populated in a crawled link can still be discovered.

Neither source makes a security claim. Each synthesized check is exactly the same
OPEN question the operator matrix poses. The SAME pure :func:`judge_ssrf` decides
the outcome by re-probing the live target. A parameter that is not fetched
server-side (or is blocked) collapses to DISPROVED; nothing here can manufacture a
verdict. The injected URL is always Sentinel's own loopback collaborator.

The result is a plain :class:`SsrfPolicy` — identical in type to a parsed operator
matrix — so it flows through the existing seed → probe → judge → prove chain with
not a line of change downstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from ..graph import SecurityGraph
from .ssrf_policy import SsrfCheck, SsrfPolicy


# A small, fixed, target-agnostic set of conventional fetch-URL parameter names —
# fields whose value a server commonly turns into a server-side request. Ordered
# by how commonly they back a server-side fetch.
_FETCH_PARAM_NAMES = (
    "url",
    "uri",
    "link",
    "src",
    "source",
    "dest",
    "destination",
    "target",
    "fetch",
    "fetchurl",
    "feed",
    "callback",
    "webhook",
    "proxy",
    "remote",
    "image",
    "imageurl",
    "img",
    "avatar",
    "load",
    "resource",
    "endpoint",
    "host",
    "u",
)

_FETCH_PARAM_SET = frozenset(_FETCH_PARAM_NAMES)


# Path substrings that suggest an endpoint performs a server-side fetch — the
# surfaces where a fetch-URL parameter is most likely to live. Generic web
# vocabulary, never a single application's routes.
_FETCH_SURFACE_HINTS = (
    "fetch",
    "proxy",
    "webhook",
    "image",
    "img",
    "avatar",
    "upload",
    "import",
    "preview",
    "pdf",
    "render",
    "thumbnail",
    "screenshot",
    "media",
    "attachment",
    "document",
    "feed",
    "rss",
    "oembed",
    "sso",
    "oauth",
    "callback",
    "gateway",
    "remote",
    "load",
)

# Static assets never fetch on a parameter; skip them outright.
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
    ".zip",
    ".txt",
)


@dataclass(frozen=True)
class _Candidate:
    """One synthesized fetch-surface candidate, with its provenance."""

    method: str
    path: str
    param: str
    location: str
    source: str  # "observed_parameter" | "generic_on_fetch_surface"


def _path_of(url: str) -> str:
    split = urlsplit(url if "://" in url else f"http://{url}")
    return split.path or "/"


def _looks_static(path: str) -> bool:
    return path.lower().endswith(_ASSET_SUFFIXES)


def _is_fetch_surface(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in _FETCH_SURFACE_HINTS)


def _looks_fetch_param(param: str) -> bool:
    lowered = param.strip().lower()
    return lowered in _FETCH_PARAM_SET or any(
        name in lowered for name in ("url", "uri", "src", "fetch", "link", "host")
    )


def _observed_candidates(graph: SecurityGraph) -> list[_Candidate]:
    """
    Candidates drawn from query parameters reconnaissance actually observed.

    Two observed sources are merged, both GET-only (exactly what recon can see
    non-destructively): ``recon_parameter`` observations, and query parameters
    embedded in any discovered endpoint URL. Candidates are ranked so
    conventional fetch-URL names — and any parameter on a fetcher-ish surface —
    win a bounded probe budget first; a plain observed parameter is still probed
    (self-anchoring → it simply collapses to DISPROVED if it is not fetched
    server-side). The parameter name is read off the live target, never invented.
    """
    ranked: list[tuple[bool, bool, int, _Candidate]] = []
    seen: set[tuple[str, str, str]] = set()

    def _consider(param: str, url: str) -> None:
        param = param.strip()
        if not param:
            return
        path = _path_of(url)
        if not path or _looks_static(path):
            return
        key = ("GET", path, param)
        if key in seen:
            return
        seen.add(key)
        ranked.append(
            (
                not _looks_fetch_param(param),      # fetch-named params first
                not _is_fetch_surface(path),        # then fetcher-ish surfaces
                len(ranked),                         # stable insertion order
                _Candidate(
                    method="GET",
                    path=path,
                    param=param,
                    location="query",
                    source="observed_parameter",
                ),
            )
        )

    for observation in graph.observations.values():
        if observation.kind != "recon_parameter":
            continue
        data = observation.data if isinstance(observation.data, dict) else {}
        parameter = data.get("parameter")
        url = data.get("url")
        if isinstance(parameter, str) and isinstance(url, str) and url.strip():
            _consider(parameter, url)

    for endpoint in graph.endpoints.values():
        if (endpoint.method or "GET").upper() != "GET":
            continue
        url = endpoint.url
        if not isinstance(url, str) or "?" not in url:
            continue
        for param, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            _consider(param, url)

    ranked.sort(key=lambda item: (item[0], item[1], item[2]))
    return [candidate for _a, _b, _c, candidate in ranked]


def _generic_candidates(
    graph: SecurityGraph,
    *,
    already: set[tuple[str, str, str]],
) -> list[_Candidate]:
    """
    Candidates from a fixed generic fetch-parameter list on fetch-surface
    endpoints, ranked BREADTH-FIRST so a bounded budget is spent where a fetch
    parameter is most likely to live rather than exhausted on a single endpoint
    (the highest-signal parameter across every surface before any secondary
    parameter anywhere).
    """
    paths: dict[str, bool] = {}
    for endpoint in graph.endpoints.values():
        if (endpoint.method or "GET").upper() != "GET":
            continue
        path = _path_of(endpoint.url)
        if not path or _looks_static(path):
            continue
        paths[path] = paths.get(path, False) or _is_fetch_surface(path)

    candidates: list[tuple[bool, int, str, str]] = []
    for path, is_surface in paths.items():
        for rank, param in enumerate(_FETCH_PARAM_NAMES):
            key = ("GET", path, param)
            if key in already:
                continue
            candidates.append((not is_surface, rank, path, param))

    candidates.sort(key=lambda c: (c[0], c[1], c[2]))

    out: list[_Candidate] = []
    for _not_surface, _rank, path, param in candidates:
        key = ("GET", path, param)
        if key in already:
            continue
        already.add(key)
        out.append(
            _Candidate(
                method="GET",
                path=path,
                param=param,
                location="query",
                source="generic_on_fetch_surface",
            )
        )
    return out


@dataclass(frozen=True)
class SsrfDiscovery:
    """A synthesized SSRF policy plus a human-readable provenance summary."""

    policy: SsrfPolicy
    observed_count: int
    generic_count: int
    total_candidates: int  # before the max_checks cap

    @property
    def note(self) -> str:
        return (
            f"{len(self.policy.checks)} fetch-surface probe(s) synthesized from "
            f"live recon — {self.observed_count} from observed parameter(s), "
            f"{self.generic_count} generic fetch parameter(s) on fetch surfaces"
            + (
                f" (capped from {self.total_candidates})"
                if self.total_candidates > len(self.policy.checks)
                else ""
            )
        )


def synthesize_ssrf_policy(
    graph: SecurityGraph,
    *,
    max_checks: int = 24,
    include_generic: bool = True,
) -> SsrfDiscovery:
    """
    Build an :class:`SsrfPolicy` from the recon surface already in ``graph``.

    Pure and target-agnostic: it reads only observed recon (parameters and
    discovered GET endpoints) and a fixed generic fetch-parameter list, and
    returns a policy of the same type a parsed operator matrix produces. The
    prove-chain downstream is unchanged; the pure judge decides every synthesized
    check via the out-of-band callback differential, so no verdict can be
    manufactured. ``max_checks`` bounds live request volume.
    """
    observed = _observed_candidates(graph)

    already: set[tuple[str, str, str]] = {
        (c.method, c.path, c.param) for c in observed
    }
    generic = (
        _generic_candidates(graph, already=already) if include_generic else []
    )

    ranked = observed + generic
    total = len(ranked)
    selected = ranked[: max(0, max_checks)]

    checks = tuple(
        SsrfCheck(
            method=c.method,
            path=c.path,
            param=c.param,
            location=c.location,
            severity="HIGH",
            rationale=(
                "Parameter discovered from live reconnaissance "
                f"({c.source.replace('_', ' ')}); probed for a coercible "
                "server-side fetch by the out-of-band callback differential."
            ),
        )
        for c in selected
    )

    return SsrfDiscovery(
        policy=SsrfPolicy(checks=checks),
        observed_count=sum(
            1 for c in selected if c.source == "observed_parameter"
        ),
        generic_count=sum(
            1 for c in selected if c.source == "generic_on_fetch_surface"
        ),
        total_candidates=total,
    )
