"""
Zero-oracle injection discovery — synthesize an injection matrix from live recon.

This is what turns Sentinel from a *verifier* of an operator-declared injectable
surface into a *discoverer*: point it at a URL, and it derives the parameters to
probe from what reconnaissance actually observed, rather than from a hand-typed
``injection_matrix``.

Why this is honest (the epistemic contract is fully preserved). The injection
class is the one class whose ground truth is *internal*: the three-way boolean
differential (a benign baseline plus length-matched TRUE/FALSE payload pairs) is
self-anchoring — a parameter is CONFIRMED injectable ONLY when the backend
provably tracks the injected boolean while one arm still reproduces the
legitimate baseline. So the operator never needed to supply *intent* for this
class, only *where to look*. This module supplies "where to look" from observed
surface instead of a file:

  * every query parameter reconnaissance actually saw on the live target (with
    its observed benign value as the baseline anchor — real data, never
    invented), and
  * a small, fixed, target-AGNOSTIC list of conventional query parameters
    attached to endpoints that look like query surfaces (``/rest``, ``/api``,
    ``search`` …), so an injectable parameter that never appears pre-populated
    in a crawled link — the common case for an SPA/JSON API — can still be
    discovered.

Neither source makes a security claim. Each synthesized check is exactly the
same kind of OPEN question the operator matrix poses: a parameter that MUST NOT
alter the backend query. The SAME pure :func:`judge_injection` decides the
outcome by re-probing the live target. A parameter that does not influence a SQL
boolean collapses (TRUE == FALSE) → DISPROVED → no finding. A baseline that does
not return a legitimate response → INCONCLUSIVE → no finding. Nothing here can
manufacture a verdict; the engine holds no target-specific knowledge — the target
host, routes, and parameters are all discovered live.

The result is a plain :class:`InjectionPolicy` — identical in type to a parsed
operator matrix — so it flows through the existing seed → probe → judge → prove
chain with not a line of change downstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from ..graph import SecurityGraph
from .injection_policy import InjectionCheck, InjectionPolicy


# A benign, target-agnostic probe value. It is deliberately an ordinary
# alphanumeric token: on a search/query surface it returns a legitimate
# (typically empty-result) 2xx response, which is exactly the stable anchor the
# boolean differential measures against. It carries no SQL metacharacters, so
# the baseline probe itself is inert.
_BENIGN_TOKEN = "sentinel"


# A small, fixed, target-agnostic set of conventional query-parameter names.
# These are generic web/API conventions (not specific to any one application),
# tried against endpoints that look like query surfaces so a parameter that
# never appears pre-populated in a crawled link can still be surfaced for the
# judge. Ordered by how commonly they back a searchable/injectable query.
_GENERIC_QUERY_PARAMS = (
    "q",
    "query",
    "search",
    "term",
    "keyword",
    "name",
    "id",
    "category",
    "filter",
    "sort",
    "order",
    "username",
    "email",
)


# Path substrings that suggest an endpoint backs a database-driven query — the
# surfaces where a conventional parameter is worth probing. Generic API/CRUD
# vocabulary, never a single application's routes.
_QUERY_SURFACE_HINTS = (
    "search",
    "find",
    "query",
    "lookup",
    "list",
    "filter",
    "product",
    "user",
    "account",
    "order",
    "item",
    "article",
    "post",
    "rest",
    "api",
    "graphql",
)

# Static assets never back a query; skip them outright.
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
    """One synthesized injectable-surface candidate, with its provenance."""

    method: str
    path: str
    param: str
    baseline_value: str
    location: str
    source: str  # "observed_parameter" | "generic_on_query_surface"


def _path_of(url: str) -> str:
    """The path component of a discovered URL (no scheme/host/query/fragment)."""
    split = urlsplit(url if "://" in url else f"http://{url}")
    return split.path or "/"


def _looks_static(path: str) -> bool:
    return path.lower().endswith(_ASSET_SUFFIXES)


def _is_query_surface(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in _QUERY_SURFACE_HINTS)


def _observed_candidates(graph: SecurityGraph) -> list[_Candidate]:
    """
    Candidates drawn from query parameters reconnaissance actually observed.

    Highest-signal source: the parameter is real (it appears on the live
    surface), and its observed value — when the app served one — is a genuine
    benign anchor for the differential. Two observed sources are merged, both
    GET-only (exactly what recon can see non-destructively):

      * ``recon_parameter`` observations (a parameter seen pre-populated in a
        crawled link), and
      * query parameters embedded in any discovered endpoint URL — notably the
        API routes recon mines out of the application's own JavaScript
        (``/rest/products/search?q=…``). This is what lets discovery reach an
        SPA's real query surface, which never appears as a crawlable ``?p=``
        link.

    In both cases the parameter name is read off the live target, never
    invented; a missing value falls back to the inert benign token.
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
        # Recover the observed benign value for this parameter, if any, so the
        # differential is anchored to a value the application really served.
        observed_value = ""
        for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if key == param and value:
                observed_value = value
                break
        key = ("GET", path, param)
        if key in seen:
            return
        seen.add(key)
        out.append(
            _Candidate(
                method="GET",
                path=path,
                param=param,
                baseline_value=observed_value or _BENIGN_TOKEN,
                location="query",
                source="observed_parameter",
            )
        )

    # 1) Parameters seen pre-populated in a crawled link.
    for observation in graph.observations.values():
        if observation.kind != "recon_parameter":
            continue
        data = observation.data if isinstance(observation.data, dict) else {}
        parameter = data.get("parameter")
        url = data.get("url")
        if isinstance(parameter, str) and isinstance(url, str) and url.strip():
            _consider(parameter, url)

    # 2) Parameters embedded in the query string of any discovered GET endpoint
    #    (e.g. API routes mined from the app's JavaScript).
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
    Candidates from a fixed generic parameter list on query-surface endpoints.

    This is what lets discovery reach an injectable parameter that never appears
    pre-populated in a crawled link (an SPA / JSON API). The parameter names are
    generic web conventions — no target knowledge — and the pure judge still
    decides every one: a route that ignores the parameter collapses to
    DISPROVED.

    Ordering is BREADTH-FIRST so a bounded ``max_checks`` budget is spent where
    an injectable parameter is most likely to live rather than exhausted on a
    single endpoint. Candidates are ranked by (1) query surfaces before other
    endpoints, then (2) the more common parameter first, then (3) path — so the
    single highest-signal parameter (``q``) is tried across EVERY query surface
    before any secondary parameter is tried anywhere. Without this, 13 generic
    parameters on the first endpoint alphabetically would consume the whole
    budget and the real injectable surface would never be probed.
    """
    # De-duplicate discovered GET endpoints by path, preferring query surfaces.
    paths: dict[str, bool] = {}
    for endpoint in graph.endpoints.values():
        if (endpoint.method or "GET").upper() != "GET":
            continue
        path = _path_of(endpoint.url)
        if not path or _looks_static(path):
            continue
        paths[path] = paths.get(path, False) or _is_query_surface(path)

    # Enumerate every (path, param) pair, then rank breadth-first: query
    # surfaces first, then by parameter commonality, then by path.
    candidates: list[tuple[bool, int, str, str]] = []
    for path, is_surface in paths.items():
        for rank, param in enumerate(_GENERIC_QUERY_PARAMS):
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
                baseline_value=_BENIGN_TOKEN,
                location="query",
                source="generic_on_query_surface",
            )
        )
    return out


@dataclass(frozen=True)
class InjectionDiscovery:
    """A synthesized injection policy plus a human-readable provenance summary."""

    policy: InjectionPolicy
    observed_count: int
    generic_count: int
    total_candidates: int  # before the max_checks cap

    @property
    def note(self) -> str:
        return (
            f"{len(self.policy.checks)} injectable-surface probe(s) synthesized "
            f"from live recon — {self.observed_count} from observed parameter(s), "
            f"{self.generic_count} generic parameter(s) on query surfaces"
            + (
                f" (capped from {self.total_candidates})"
                if self.total_candidates > len(self.policy.checks)
                else ""
            )
        )


def synthesize_injection_policy(
    graph: SecurityGraph,
    *,
    max_checks: int = 24,
    include_generic: bool = True,
) -> InjectionDiscovery:
    """
    Build an :class:`InjectionPolicy` from the recon surface already in ``graph``.

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

    # Observed parameters (with real anchors) take priority over generic guesses.
    ranked = observed + generic
    total = len(ranked)
    selected = ranked[: max(0, max_checks)]

    checks = tuple(
        InjectionCheck(
            method=c.method,
            path=c.path,
            param=c.param,
            baseline_value=c.baseline_value,
            location=c.location,
            severity="HIGH",
            rationale=(
                "Parameter discovered from live reconnaissance "
                f"({c.source.replace('_', ' ')}); probed for SQL injection by "
                "the boolean differential."
            ),
        )
        for c in selected
    )

    return InjectionDiscovery(
        policy=InjectionPolicy(checks=checks),
        observed_count=sum(
            1 for c in selected if c.source == "observed_parameter"
        ),
        generic_count=sum(
            1 for c in selected if c.source == "generic_on_query_surface"
        ),
        total_candidates=total,
    )
