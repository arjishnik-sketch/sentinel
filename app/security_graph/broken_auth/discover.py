"""
Zero-oracle broken-authentication discovery — synthesize a JWT-forgery matrix.

The honestly-labelled *hybrid* member of Sentinel's discoverer story. Unlike the
URL-only classes, broken-auth needs ONE live input the operator cannot skip: a
genuine bearer token to forge FROM, captured from an authenticated session (never
read from a file). Given that live principal, this module supplies the other
half — *where to look* — from reconnaissance instead of a hand-typed matrix:

  * every route reconnaissance actually observed (its own method), skipping
    static assets and ranking API / account / admin-ish surfaces first so a
    bounded probe budget lands on the routes most likely to be token-guarded, and
  * for each route, the forgery strategies whose forgery is *derivable* from the
    captured token with NO operator material — ``alg_none`` and ``unsigned``
    (both guard-provable). Signed-forgery strategies (``hs256_confusion`` /
    ``weak_secret``) are synthesized ONLY when the caller supplies the material
    they need (a public key / a candidate dictionary), because a forgery that
    cannot be derived would seed no probe anyway.

Why this is honest (the epistemic contract is fully preserved). A synthesized
check makes no security claim; it poses exactly the same OPEN question an
operator matrix poses. The SAME pure :func:`judge_broken_auth` decides every one
via the live three-probe differential — control (genuine token MUST succeed),
breach (forged token), anonymous baseline (MUST be denied). A route that is not
token-authenticated fails the control probe and collapses to INCONCLUSIVE; a
route that correctly rejects the forgery collapses to DISPROVED. Over-generating
candidate routes is therefore safe: the control + baseline probes self-anchor
every one, and nothing here can manufacture a verdict.

The result is a plain :class:`BrokenAuthPolicy` — identical in type to a parsed
operator matrix — so it flows through the existing seed → probe → judge → prove
chain with not a line of change downstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from ..graph import SecurityGraph
from .broken_auth_policy import BrokenAuthCheck, BrokenAuthPolicy, BrokenAuthPrincipal
from .forge import decode_jwt, strip_bearer

# Path substrings that suggest a route is token-guarded — the surfaces where a
# broken-auth flaw most matters. Generic web/API vocabulary, never one app.
_PROTECTED_SURFACE_HINTS = (
    "api",
    "admin",
    "account",
    "profile",
    "user",
    "me",
    "dashboard",
    "settings",
    "token",
    "auth",
    "session",
    "order",
    "cart",
    "wallet",
    "payment",
    "billing",
    "private",
    "secure",
    "internal",
    "manage",
    "config",
)

# Static assets are never token-guarded application routes; skip them outright.
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
    ".html",
    ".htm",
)

# Forgeries derivable from any JWT with NO operator material — always synthesized.
_MATERIAL_FREE_FORGERIES = ("alg_none", "unsigned")


@dataclass(frozen=True)
class _Route:
    """One synthesized candidate route, with its provenance."""

    method: str
    path: str
    is_protected_surface: bool


def _path_of(url: str) -> str:
    split = urlsplit(url if "://" in url else f"http://{url}")
    return split.path or "/"


def _looks_static(path: str) -> bool:
    return path.lower().endswith(_ASSET_SUFFIXES)


def _is_protected_surface(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in _PROTECTED_SURFACE_HINTS)


def _genuine_token(headers) -> str:
    """The bare genuine token from a principal's Authorization header, if any."""
    for name, value in headers:
        if str(name).lower() == "authorization":
            return strip_bearer(value)
    return ""


def _candidate_routes(graph: SecurityGraph) -> list[_Route]:
    """
    Candidate routes drawn from every endpoint reconnaissance observed.

    Ranked so token-guarded-looking surfaces (api / account / admin …) win a
    bounded budget first; a plain route is still probed (self-anchoring — the
    control probe collapses it to INCONCLUSIVE if it is not token-authenticated).
    The route is read off the live target, never invented.
    """
    seen: set[tuple[str, str]] = set()
    ranked: list[tuple[bool, int, _Route]] = []
    for endpoint in graph.endpoints.values():
        method = (endpoint.method or "GET").upper()
        path = _path_of(endpoint.url)
        if not path or _looks_static(path):
            continue
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        protected = _is_protected_surface(path)
        ranked.append(
            (not protected, len(ranked), _Route(method, path, protected))
        )
    ranked.sort(key=lambda item: (item[0], item[1]))
    return [route for _protected, _order, route in ranked]


@dataclass(frozen=True)
class BrokenAuthDiscovery:
    """A synthesized broken-auth policy plus a human-readable provenance summary."""

    policy: BrokenAuthPolicy
    route_count: int
    forgery_strategies: tuple[str, ...]
    token_is_jwt: bool
    total_candidates: int  # route × forgery pairs before the max_checks cap

    @property
    def note(self) -> str:
        if not self.token_is_jwt:
            return (
                "no broken-auth probes synthesized — the captured session token is "
                "not a JWT, so no forgery is derivable (nothing is claimed)"
            )
        return (
            f"{len(self.policy.checks)} token-forgery probe(s) synthesized from "
            f"live recon — {self.route_count} route(s) × forgeries "
            f"{list(self.forgery_strategies)}"
            + (
                f" (capped from {self.total_candidates})"
                if self.total_candidates > len(self.policy.checks)
                else ""
            )
        )


def synthesize_broken_auth_policy(
    graph: SecurityGraph,
    *,
    principal: BrokenAuthPrincipal,
    public_key: str = "",
    secret_candidates: tuple[str, ...] = (),
    max_checks: int = 24,
) -> BrokenAuthDiscovery:
    """
    Build a :class:`BrokenAuthPolicy` from the live `principal` and the recon
    surface already in ``graph``.

    Pure and target-agnostic: it reads only the captured token (to confirm a
    forgery is even derivable) and the observed endpoints (where to look), and
    returns a policy of the same type a parsed operator matrix produces. Only
    forgeries derivable with NO operator material (``alg_none`` / ``unsigned``)
    are synthesized by default; a signed-forgery strategy is added only when the
    material it needs is supplied. ``max_checks`` bounds live request volume. The
    prove-chain downstream is unchanged; the pure judge decides every synthesized
    check, so no verdict can be manufactured.
    """
    token = _genuine_token(principal.headers)
    token_is_jwt = bool(token) and decode_jwt(token) is not None
    if not token_is_jwt:
        return BrokenAuthDiscovery(
            policy=BrokenAuthPolicy(principal=principal, checks=()),
            route_count=0,
            forgery_strategies=(),
            token_is_jwt=False,
            total_candidates=0,
        )

    forgeries = list(_MATERIAL_FREE_FORGERIES)
    if public_key.strip():
        forgeries.append("hs256_confusion")
    if secret_candidates:
        forgeries.append("weak_secret")

    routes = _candidate_routes(graph)
    total = len(routes) * len(forgeries)

    # Breadth-first over routes so the bounded budget spreads across surfaces —
    # the highest-signal forgery on every route before any secondary forgery.
    checks: list[BrokenAuthCheck] = []
    for forgery in forgeries:
        for route in routes:
            if len(checks) >= max(0, max_checks):
                break
            needs_key = forgery == "hs256_confusion"
            needs_dict = forgery == "weak_secret"
            checks.append(
                BrokenAuthCheck(
                    forgery=forgery,
                    method=route.method,
                    path=route.path,
                    severity="HIGH",
                    public_key=public_key if needs_key else "",
                    secret_candidates=secret_candidates if needs_dict else (),
                    rationale=(
                        f"Route discovered from live reconnaissance; probed for a "
                        f"token-validation flaw ({forgery}) by the three-probe "
                        "control/breach/baseline differential."
                    ),
                )
            )

    return BrokenAuthDiscovery(
        policy=BrokenAuthPolicy(principal=principal, checks=tuple(checks)),
        route_count=len({(c.method, c.path) for c in checks}),
        forgery_strategies=tuple(forgeries),
        token_is_jwt=True,
        total_candidates=total,
    )


