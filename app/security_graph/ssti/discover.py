"""
Zero-oracle SSTI discovery — synthesize an SSTI matrix from live recon.

This is what lets the SSTI class join Sentinel's *discoverer* story: point it at
a URL and it derives the parameters to probe from what reconnaissance actually
observed, rather than from a hand-typed ``ssti_matrix``.

Why this is honest (the epistemic contract is fully preserved). Like injection,
SSTI's ground truth is *internal*: the arithmetic-evaluation differential (a
literal ``a*b`` control plus template-wrapped payloads) is self-anchoring — a
parameter is CONFIRMED only when the backend provably renders the *computed
product* while the literal vanishes and the control proved mere reflection. So
the operator never needed to supply *intent* for this class, only *where to
look*. This module supplies "where to look" from observed surface instead of a
file:

  * every query parameter reconnaissance actually saw on the live target, and
  * a small, fixed, target-AGNOSTIC list of conventional reflective parameters
    attached to endpoints that look like reflective surfaces (search / profile /
    comment / render …), so a parameter that never appears pre-populated in a
    crawled link — the common case for an SPA/JSON API — can still be discovered.

Neither source makes a security claim. Each synthesized check is exactly the
same OPEN question the operator matrix poses. The SAME pure
:func:`judge_template_injection` decides the outcome by re-probing the live
target. A parameter that is only reflected (never evaluated) collapses to
DISPROVED; a parameter that does not reflect at all collapses to DISPROVED too;
nothing here can manufacture a verdict.

The result is a plain :class:`SSTIPolicy` — identical in type to a parsed
operator matrix — so it flows through the existing seed → probe → judge → prove
chain with not a line of change downstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from ..graph import SecurityGraph
from .ssti_policy import SSTICheck, SSTIPolicy


# A small, fixed, target-agnostic set of conventional reflective-parameter
# names — fields whose value a server commonly echoes into a rendered page or
# template, where an SSTI sink is most likely to live. Ordered by how commonly
# they back a reflected/templated value.
_GENERIC_REFLECTIVE_PARAMS = (
    "q",
    "query",
    "search",
    "name",
    "message",
    "comment",
    "title",
    "subject",
    "text",
    "content",
    "template",
    "input",
)


# Path substrings that suggest an endpoint reflects/renders user input — the
# surfaces where a conventional parameter is worth probing. Generic web/API
# vocabulary, never a single application's routes.
_REFLECTIVE_SURFACE_HINTS = (
    "search",
    "find",
    "query",
    "render",
    "template",
    "preview",
    "profile",
    "comment",
    "feedback",
    "review",
    "message",
    "product",
    "user",
    "page",
    "rest",
    "api",
)

# Static assets never render a template; skip them outright.
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
    """One synthesized SSTI-surface candidate, with its provenance."""

    method: str
    path: str
    param: str
    location: str
    source: str  # "observed_parameter" | "generic_on_reflective_surface"


def _path_of(url: str) -> str:
    split = urlsplit(url if "://" in url else f"http://{url}")
    return split.path or "/"


def _looks_static(path: str) -> bool:
    return path.lower().endswith(_ASSET_SUFFIXES)


def _is_reflective_surface(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in _REFLECTIVE_SURFACE_HINTS)


def _observed_candidates(graph: SecurityGraph) -> list[_Candidate]:
    """
    Candidates drawn from query parameters reconnaissance actually observed.

    Two observed sources are merged, both GET-only (exactly what recon can see
    non-destructively): ``recon_parameter`` observations, and query parameters
    embedded in any discovered endpoint URL (notably the API routes recon mines
    out of the application's own JavaScript). The parameter name is read off the
    live target, never invented.
    """
    out: list[_Candidate] = []
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
        out.append(
            _Candidate(
                method="GET",
                path=path,
                param=param,
                location="query",
                source="observed_parameter",
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

    return out


def _generic_candidates(
    graph: SecurityGraph,
    *,
    already: set[tuple[str, str, str]],
) -> list[_Candidate]:
    """
    Candidates from a fixed generic parameter list on reflective-surface
    endpoints, ranked BREADTH-FIRST so a bounded budget is spent where a
    reflective parameter is most likely to live rather than exhausted on a
    single endpoint (the highest-signal parameter across every surface before
    any secondary parameter anywhere).
    """
    paths: dict[str, bool] = {}
    for endpoint in graph.endpoints.values():
        if (endpoint.method or "GET").upper() != "GET":
            continue
        path = _path_of(endpoint.url)
        if not path or _looks_static(path):
            continue
        paths[path] = paths.get(path, False) or _is_reflective_surface(path)

    candidates: list[tuple[bool, int, str, str]] = []
    for path, is_surface in paths.items():
        for rank, param in enumerate(_GENERIC_REFLECTIVE_PARAMS):
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
                source="generic_on_reflective_surface",
            )
        )
    return out


@dataclass(frozen=True)
class SSTIDiscovery:
    """A synthesized SSTI policy plus a human-readable provenance summary."""

    policy: SSTIPolicy
    observed_count: int
    generic_count: int
    total_candidates: int  # before the max_checks cap

    @property
    def note(self) -> str:
        return (
            f"{len(self.policy.checks)} SSTI-surface probe(s) synthesized from "
            f"live recon — {self.observed_count} from observed parameter(s), "
            f"{self.generic_count} generic parameter(s) on reflective surfaces"
            + (
                f" (capped from {self.total_candidates})"
                if self.total_candidates > len(self.policy.checks)
                else ""
            )
        )


def synthesize_ssti_policy(
    graph: SecurityGraph,
    *,
    max_checks: int = 24,
    include_generic: bool = True,
) -> SSTIDiscovery:
    """
    Build an :class:`SSTIPolicy` from the recon surface already in ``graph``.

    Pure and target-agnostic: it reads only observed recon (parameters and
    discovered GET endpoints) and a fixed generic parameter list, and returns a
    policy of the same type a parsed operator matrix produces. The prove-chain
    downstream is unchanged; the pure judge decides every synthesized check, so
    no verdict can be manufactured. ``max_checks`` bounds live request volume.
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
        SSTICheck(
            method=c.method,
            path=c.path,
            param=c.param,
            location=c.location,
            severity="HIGH",
            rationale=(
                "Parameter discovered from live reconnaissance "
                f"({c.source.replace('_', ' ')}); probed for server-side "
                "template injection by the arithmetic-evaluation differential."
            ),
        )
        for c in selected
    )

    return SSTIDiscovery(
        policy=SSTIPolicy(checks=checks),
        observed_count=sum(
            1 for c in selected if c.source == "observed_parameter"
        ),
        generic_count=sum(
            1 for c in selected if c.source == "generic_on_reflective_surface"
        ),
        total_candidates=total,
    )
