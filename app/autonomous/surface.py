"""Normalized attack surface — the hand-off shape between DISCOVER and
HYPOTHESIZE. Decouples the autonomous loop from recon_engine internals so either
side can change independently.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs


_SPA_TECH = ("react", "next", "nuxt", "vue", "angular", "svelte", "ember")

# A trailing path segment that looks like a resource identifier — the shape of a
# REST id-in-path surface (``/api/users/1``, ``/rest/products/42``,
# ``/items/<uuid>``). Kept deliberately tight (pure numeric id, a UUID, or a
# 24-hex ObjectId) so ordinary word segments like ``/products/search`` are never
# mistaken for an injectable id. This is the discovery half of path-segment SQLi:
# recon sees a concrete id, and we pose the question "does that segment reach the
# query?" — the pure judge still decides.
_ID_SEGMENT = re.compile(
    r"^(?:\d+"
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|[0-9a-fA-F]{24})$"
)


@dataclass(frozen=True)
class Endpoint:
    url: str
    method: str = "GET"
    params: tuple = ()        # observed parameter names
    location: str = "query"   # query | body | path


@dataclass
class Surface:
    target: str
    endpoints: tuple = ()     # tuple[Endpoint]
    techs: tuple = ()
    params: tuple = ()        # all distinct param names across the surface
    logins: tuple = ()
    apis: tuple = ()
    has_login: bool = False
    has_graphql: bool = False
    has_swagger: bool = False
    has_uploads: bool = False
    is_spa: bool = False

    @property
    def host(self) -> str:
        return urlparse(self.target if "://" in self.target else "http://" + self.target).netloc.lower()

    @classmethod
    def from_recon(cls, recon: dict, findings: dict) -> "Surface":
        target = recon.get("target", "")
        crawl = recon.get("crawl", []) or []
        techs = tuple(sorted({t.lower() for t in _techs_from_recon(recon)}))

        endpoints = []
        seen_path_ids: set[str] = set()
        for url in crawl:
            if not isinstance(url, str):
                continue
            names = tuple(sorted(parse_qs(urlparse(url).query).keys()))
            endpoints.append(Endpoint(url=url, method="GET", params=names, location="query"))
            # A concrete trailing resource id (…/users/1) is an injectable path
            # surface distinct from the query string. Emit a second endpoint with
            # location="path"; the last non-empty segment is the hole the engine
            # fills, so the concrete URL doubles as its own template.
            path_ep = _path_id_endpoint(url)
            if path_ep is not None and path_ep.url not in seen_path_ids:
                seen_path_ids.add(path_ep.url)
                endpoints.append(path_ep)

        js_count = len(findings.get("javascript", []) or [])
        is_spa = (
            any(s in " ".join(techs) for s in _SPA_TECH)
            or (js_count >= 3 and js_count >= max(1, len(crawl)) * 0.5)
        )

        return cls(
            target=target,
            endpoints=tuple(endpoints),
            techs=techs,
            params=tuple(findings.get("parameters", []) or []),
            logins=tuple(findings.get("logins", []) or []),
            apis=tuple(findings.get("apis", []) or []),
            has_login=bool(findings.get("logins")),
            has_graphql=bool(findings.get("graphql")),
            has_swagger=bool(findings.get("swagger")),
            has_uploads=bool(findings.get("uploads")),
            is_spa=is_spa,
        )


def _techs_from_recon(recon: dict):
    for row in recon.get("alive", []) or []:
        if isinstance(row, dict):
            for t in row.get("tech", []) or ():
                yield t


def _path_id_endpoint(url: str) -> "Endpoint | None":
    """A path-segment injectable endpoint when `url`'s LAST path segment looks
    like a resource id, else None.

    The param name is the resource segment just before the id (``…/users/1`` →
    ``users``), falling back to ``id`` — cosmetic only, since the engine fills the
    last non-empty segment regardless. The URL is kept concrete: recon already
    proved this exact path returns a legitimate response, so it anchors the
    differential's benign baseline."""
    try:
        segs = [s for s in urlparse(url).path.split("/") if s]
    except (ValueError, AttributeError):
        return None
    if not segs or not _ID_SEGMENT.match(segs[-1]):
        return None
    param = segs[-2] if len(segs) >= 2 else "id"
    return Endpoint(url=url, method="GET", params=(param,), location="path")
