"""
Zero-oracle open-redirect discovery — synthesize a redirect matrix from live recon.

This is what lets the open-redirect class join Sentinel's *discoverer* story:
point it at a URL and it derives the redirect-destination parameters to probe
from what reconnaissance actually observed, rather than from a hand-typed
``open_redirect_matrix``.

Why this is honest (the epistemic contract is fully preserved). Like SSTI,
open-redirect's ground truth is *internal*: the two-probe host differential (an
off-origin payload on an unforgeable nonce host plus a same-origin control
anchor) is self-anchoring — a parameter is CONFIRMED only when the backend
provably emits a ``Location`` header carrying our nonce host while the anchor
proves the endpoint legitimately redirects on-origin. So the operator never
needed to supply *intent* for this class, only *where to look*. This module
supplies "where to look" from observed surface instead of a file:

  * every query parameter reconnaissance actually saw on the live target
    (ranked so conventional redirect-destination names win a bounded budget), and
  * a small, fixed, target-AGNOSTIC list of conventional redirect-destination
    parameters attached to endpoints that look like redirectors (login / logout /
    sso / oauth / redirect / continue …), so a redirect parameter that never
    appears pre-populated in a crawled link can still be discovered.

Neither source makes a security claim. Each synthesized check is exactly the
same OPEN question the operator matrix poses. The SAME pure
:func:`judge_open_redirect` decides the outcome by re-probing the live target. A
parameter that is ignored, sanitized, or forced on-origin collapses to DISPROVED;
nothing here can manufacture a verdict.

The result is a plain :class:`OpenRedirectPolicy` — identical in type to a parsed
operator matrix — so it flows through the existing seed → probe → judge → prove
chain with not a line of change downstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from ..graph import SecurityGraph
from .open_redirect_policy import OpenRedirectCheck, OpenRedirectPolicy


# A small, fixed, target-agnostic set of conventional redirect-destination
# parameter names — fields whose value a server commonly turns into a ``Location``
# redirect. Ordered by how commonly they back a redirect target.
_REDIRECT_PARAM_NAMES = (
    "url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "redirecturl",
    "return",
    "returnurl",
    "return_url",
    "returnto",
    "return_to",
    "next",
    "goto",
    "dest",
    "destination",
    "continue",
    "to",
    "target",
    "rurl",
    "forward",
    "callback",
    "out",
    "link",
    "u",
)

_REDIRECT_PARAM_SET = frozenset(_REDIRECT_PARAM_NAMES)


# Path substrings that suggest an endpoint performs a redirect — the surfaces
# where a redirect-destination parameter is most likely to live. Generic web/auth
# vocabulary, never a single application's routes.
_REDIRECT_SURFACE_HINTS = (
    "redirect",
    "login",
    "logout",
    "signin",
    "sign-in",
    "signout",
    "sign-out",
    "auth",
    "sso",
    "oauth",
    "callback",
    "return",
    "continue",
    "goto",
    "exit",
    "out",
    "away",
    "link",
    "forward",
)

# Static assets never redirect on a parameter; skip them outright.
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
    """One synthesized redirect-surface candidate, with its provenance."""

    method: str
    path: str
    param: str
    location: str
    source: str  # "observed_parameter" | "generic_on_redirect_surface"


def _path_of(url: str) -> str:
    split = urlsplit(url if "://" in url else f"http://{url}")
    return split.path or "/"


def _looks_static(path: str) -> bool:
    return path.lower().endswith(_ASSET_SUFFIXES)


def _is_redirect_surface(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in _REDIRECT_SURFACE_HINTS)


def _looks_redirect_param(param: str) -> bool:
    lowered = param.strip().lower()
    return lowered in _REDIRECT_PARAM_SET or any(
        name in lowered for name in ("redirect", "return", "url", "goto", "next")
    )


def _observed_candidates(graph: SecurityGraph) -> list[_Candidate]:
    """
    Candidates drawn from query parameters reconnaissance actually observed.

    Two observed sources are merged, both GET-only (exactly what recon can see
    non-destructively): ``recon_parameter`` observations, and query parameters
    embedded in any discovered endpoint URL. Candidates are ranked so
    conventional redirect-destination names — and any parameter on a redirect-ish
    surface — win a bounded probe budget first; a plain observed parameter is
    still probed (self-anchoring → it simply collapses to DISPROVED if it is not
    a redirector). The parameter name is read off the live target, never invented.
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
                not _looks_redirect_param(param),   # redirect-named params first
                not _is_redirect_surface(path),     # then redirect-ish surfaces
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
    Candidates from a fixed generic redirect-parameter list on redirect-surface
    endpoints, ranked BREADTH-FIRST so a bounded budget is spent where a redirect
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
        paths[path] = paths.get(path, False) or _is_redirect_surface(path)

    candidates: list[tuple[bool, int, str, str]] = []
    for path, is_surface in paths.items():
        for rank, param in enumerate(_REDIRECT_PARAM_NAMES):
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
                source="generic_on_redirect_surface",
            )
        )
    return out


@dataclass(frozen=True)
class OpenRedirectDiscovery:
    """A synthesized open-redirect policy plus a human-readable provenance summary."""

    policy: OpenRedirectPolicy
    observed_count: int
    generic_count: int
    total_candidates: int  # before the max_checks cap

    @property
    def note(self) -> str:
        return (
            f"{len(self.policy.checks)} redirect-surface probe(s) synthesized from "
            f"live recon — {self.observed_count} from observed parameter(s), "
            f"{self.generic_count} generic redirect parameter(s) on redirect "
            "surfaces"
            + (
                f" (capped from {self.total_candidates})"
                if self.total_candidates > len(self.policy.checks)
                else ""
            )
        )


def synthesize_open_redirect_policy(
    graph: SecurityGraph,
    *,
    max_checks: int = 24,
    include_generic: bool = True,
) -> OpenRedirectDiscovery:
    """
    Build an :class:`OpenRedirectPolicy` from the recon surface already in ``graph``.

    Pure and target-agnostic: it reads only observed recon (parameters and
    discovered GET endpoints) and a fixed generic redirect-parameter list, and
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
        OpenRedirectCheck(
            method=c.method,
            path=c.path,
            param=c.param,
            location=c.location,
            severity="MEDIUM",
            rationale=(
                "Parameter discovered from live reconnaissance "
                f"({c.source.replace('_', ' ')}); probed for an attacker-"
                "controlled redirect by the two-probe host differential."
            ),
        )
        for c in selected
    )

    return OpenRedirectDiscovery(
        policy=OpenRedirectPolicy(checks=checks),
        observed_count=sum(
            1 for c in selected if c.source == "observed_parameter"
        ),
        generic_count=sum(
            1 for c in selected if c.source == "generic_on_redirect_surface"
        ),
        total_candidates=total,
    )
