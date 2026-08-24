"""
Zero-oracle path-traversal discovery — synthesize a traversal matrix from live
recon.

This is what lets the path-traversal class join Sentinel's *discoverer* story:
point it at a URL and it derives the parameters to probe from what
reconnaissance actually observed, rather than from a hand-typed
``path_traversal_matrix``.

Why this is honest (the epistemic contract is fully preserved). Like SSTI and
XSS, the path-traversal ground truth is *internal*: the OS-canary differential (a
benign traversal-free control filename plus fixed directory-escape payloads) is
self-anchoring — a parameter is CONFIRMED only when a payload provably leaks an
OS-file invariant (``root:x:0:0:`` / a ``[fonts]`` win.ini section) that is ABSENT
from the control. So the operator never needed to supply *intent* for this class,
only *where to look*. This module supplies "where to look" from observed surface
instead of a file:

  * every query parameter reconnaissance actually saw on the live target, and
  * a small, fixed, target-AGNOSTIC list of conventional FILE parameters attached
    to endpoints that look like file surfaces (download / view / render /
    template …), so a parameter that never appears pre-populated in a crawled
    link — the common case for an SPA/JSON API — can still be discovered.

Neither source makes a security claim. Each synthesized check is exactly the same
OPEN question the operator matrix poses. The SAME pure
:func:`judge_path_traversal` decides the outcome by re-probing the live target. A
parameter that canonicalises its input, confines it to a safe root, or is not a
file sink collapses to DISPROVED; nothing here can manufacture a verdict.

The result is a plain :class:`TraversalPolicy` — identical in type to a parsed
operator matrix — so it flows through the existing seed → probe → judge → prove
chain with not a line of change downstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from ..graph import SecurityGraph
from .traversal_policy import TraversalCheck, TraversalPolicy

# A small, fixed, target-agnostic set of conventional FILE-parameter names —
# fields whose value a server commonly resolves to a filesystem path, where a
# path-traversal / LFI sink is most likely to live. Ordered by how commonly they
# back a file read.
_GENERIC_FILE_PARAMS = (
    "file",
    "path",
    "filename",
    "filepath",
    "page",
    "template",
    "doc",
    "document",
    "download",
    "include",
    "view",
    "load",
    "read",
    "src",
    "dir",
    "name",
)


# Path substrings that suggest an endpoint resolves user input to a file — the
# surfaces where a conventional file parameter is worth probing. Generic web/API
# vocabulary, never a single application's routes.
_FILE_SURFACE_HINTS = (
    "download",
    "file",
    "files",
    "view",
    "read",
    "render",
    "template",
    "page",
    "doc",
    "attachment",
    "static",
    "media",
    "image",
    "img",
    "include",
    "content",
    "export",
    "report",
    "asset",
    "fetch",
    "load",
)

# Static assets are not themselves file-parameter sinks; skip such endpoint paths.
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
)
@dataclass(frozen=True)
class _Candidate:
    """One synthesized path-traversal-surface candidate, with its provenance."""

    method: str
    path: str
    param: str
    location: str
    source: str  # "observed_parameter" | "generic_on_file_surface"


def _path_of(url: str) -> str:
    split = urlsplit(url if "://" in url else f"http://{url}")
    return split.path or "/"


def _looks_static(path: str) -> bool:
    return path.lower().endswith(_ASSET_SUFFIXES)


def _is_file_surface(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in _FILE_SURFACE_HINTS)


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
    Candidates from a fixed generic FILE-parameter list on file-surface
    endpoints, ranked BREADTH-FIRST so a bounded budget is spent where a file
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
        paths[path] = paths.get(path, False) or _is_file_surface(path)

    candidates: list[tuple[bool, int, str, str]] = []
    for path, is_surface in paths.items():
        for rank, param in enumerate(_GENERIC_FILE_PARAMS):
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
                source="generic_on_file_surface",
            )
        )
    return out


@dataclass(frozen=True)
class PathTraversalDiscovery:
    """A synthesized path-traversal policy plus a human-readable provenance summary."""

    policy: TraversalPolicy
    observed_count: int
    generic_count: int
    total_candidates: int  # before the max_checks cap

    @property
    def note(self) -> str:
        return (
            f"{len(self.policy.checks)} path-traversal-surface probe(s) synthesized "
            f"from live recon — {self.observed_count} from observed parameter(s), "
            f"{self.generic_count} generic file parameter(s) on file surfaces"
            + (
                f" (capped from {self.total_candidates})"
                if self.total_candidates > len(self.policy.checks)
                else ""
            )
        )
def synthesize_path_traversal_policy(
    graph: SecurityGraph,
    *,
    max_checks: int = 24,
    include_generic: bool = True,
) -> PathTraversalDiscovery:
    """
    Build a :class:`TraversalPolicy` from the recon surface already in ``graph``.

    Pure and target-agnostic: it reads only observed recon (parameters and
    discovered GET endpoints) and a fixed generic file-parameter list, and
    returns a policy of the same type a parsed operator matrix produces. The
    prove-chain downstream is unchanged; the pure judge decides every synthesized
    check, so no verdict can be manufactured. ``max_checks`` bounds live request
    volume.
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
        TraversalCheck(
            method=c.method,
            path=c.path,
            param=c.param,
            location=c.location,
            severity="HIGH",
            rationale=(
                "Parameter discovered from live reconnaissance "
                f"({c.source.replace('_', ' ')}); probed for path traversal / LFI "
                "by the OS-canary differential."
            ),
        )
        for c in selected
    )

    return PathTraversalDiscovery(
        policy=TraversalPolicy(checks=checks),
        observed_count=sum(
            1 for c in selected if c.source == "observed_parameter"
        ),
        generic_count=sum(
            1 for c in selected if c.source == "generic_on_file_surface"
        ),
        total_candidates=total,
    )
