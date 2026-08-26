"""Stage 2 SELECT ENDPOINTS — rank (and optionally prune) the attack surface by
injectability, so limited proof budget is spent on the endpoints most likely to
carry a vulnerability first.

CONTRACT: this stage is pure DATA. It never opens a socket and never confirms
anything. It REORDERS the Surface's endpoints (best-first) and — only when an
explicit budget is set — PRUNES the tail. With no budget (the default) coverage
is IDENTICAL to the unranked surface: the stage only changes the ORDER in which
hypotheses are posed, so that a ``max_hyps`` cap keeps the most promising probes.
Pruning is opt-in and honest — the selection always records the full ranking and
exactly what a budget dropped, so nothing is silently lost.

The score is a transparent sum of injectability signals — observed parameter
count, an id-in-path shape, high-value parameter names (search / id / redirect /
file / template), an auth-adjacent path, and an API-shaped path. Every point is
explained in ``EndpointScore.reasons`` so the ranking is auditable, never a black
box. The endpoint itself is never mutated; a high rank only says WHERE to look
first, and the pure judges still dispose downstream.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from .hypotheses import _REDIRECT_PARAMS

# High-value parameter-name buckets. Membership is by exact lower-cased name; a
# param may match more than one bucket (each adds its own point + reason). These
# are generic web conventions, never one application's routes.
_ID_PARAMS = frozenset({
    "id", "uid", "pid", "gid", "oid", "userid", "user_id", "account",
    "account_id", "order", "order_id", "docid", "item", "item_id", "num",
})
_SEARCH_PARAMS = frozenset({
    "q", "query", "search", "s", "term", "keyword", "filter", "find",
})
_FILE_PARAMS = frozenset({
    "file", "filename", "path", "page", "dir", "folder", "template", "tpl",
    "include", "load", "download", "doc", "view", "name",
})

# Path substrings that mark an auth surface or an API route. Auth-adjacent paths
# concentrate credential-field SQLi / broken-auth surface; API routes concentrate
# JSON-body injectable inputs. Both rank above a static page.
_AUTH_URL_WORDS = ("login", "signin", "sign-in", "authenticate", "session",
                   "auth", "token", "oauth", "sso")
_API_PATH_HINTS = ("/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql")

# Per-signal weights. Kept small and legible; the ORDER they induce is what
# matters, not the absolute magnitudes.
_W_PARAM = 2          # per observed param (capped)
_W_PARAM_CAP = 5      # never let raw param count alone dominate
_W_PATH_ID = 4        # id-in-path — the canonical path-segment injection surface
_W_REDIRECT = 3       # redirect-shaped param (open-redirect / SSRF vector)
_W_ID = 2
_W_SEARCH = 2
_W_FILE = 2
_W_AUTH_PATH = 3
_W_API_PATH = 1


@dataclass(frozen=True)
class EndpointScore:
    endpoint: object          # surface.Endpoint
    score: int
    reasons: tuple = ()


@dataclass(frozen=True)
class EndpointSelection:
    """The ranked surface. ``scored`` is EVERY endpoint, best-first. ``budget`` is
    the optional keep-count; ``None`` (or ≤0) means rank-only (no pruning)."""

    scored: tuple = ()
    budget: "int | None" = None

    @property
    def _limit(self):
        return self.budget if (self.budget is not None and self.budget > 0) else None

    @property
    def kept(self):
        return self.scored if self._limit is None else self.scored[: self._limit]

    @property
    def dropped(self):
        return () if self._limit is None else self.scored[self._limit :]

    @property
    def endpoints(self):
        return tuple(s.endpoint for s in self.kept)

    @property
    def pruned(self) -> bool:
        return bool(self.dropped)

    @property
    def total(self) -> int:
        return len(self.scored)


def _score_endpoint(ep) -> EndpointScore:
    """Sum the injectability signals for one endpoint into a transparent score."""
    reasons, score = [], 0
    params = tuple(getattr(ep, "params", ()) or ())
    location = getattr(ep, "location", "query")
    path = urlsplit(getattr(ep, "url", "")).path.lower()

    if location == "path":
        score += _W_PATH_ID
        reasons.append("id-in-path segment (path-segment injection surface)")

    if params:
        score += _W_PARAM * min(len(params), _W_PARAM_CAP)
        reasons.append(f"{len(params)} observed param(s)")

    for p in params:
        low = (p or "").lower()
        if low in _REDIRECT_PARAMS:
            score += _W_REDIRECT
            reasons.append(f"redirect-shaped param '{p}'")
        if low in _ID_PARAMS:
            score += _W_ID
            reasons.append(f"id-like param '{p}'")
        if low in _SEARCH_PARAMS:
            score += _W_SEARCH
            reasons.append(f"search param '{p}'")
        if low in _FILE_PARAMS:
            score += _W_FILE
            reasons.append(f"file/path param '{p}'")

    if any(w in path for w in _AUTH_URL_WORDS):
        score += _W_AUTH_PATH
        reasons.append("auth-adjacent path")
    if any(h in path for h in _API_PATH_HINTS):
        score += _W_API_PATH
        reasons.append("api-shaped path")

    return EndpointScore(endpoint=ep, score=score, reasons=tuple(reasons))


def select_endpoints(surface, *, budget=None) -> EndpointSelection:
    """Rank a surface's endpoints by injectability (always) and prune to ``budget``
    (only when a positive budget is given). Pure + deterministic: ties break on
    (url, method, location), so the same surface always yields the same ranking."""
    scored = [_score_endpoint(ep) for ep in (getattr(surface, "endpoints", ()) or ())]
    scored.sort(key=lambda s: (
        -s.score,
        getattr(s.endpoint, "url", ""),
        getattr(s.endpoint, "method", ""),
        getattr(s.endpoint, "location", ""),
    ))
    return EndpointSelection(scored=tuple(scored), budget=budget)
