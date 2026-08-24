"""Normalized attack surface — the hand-off shape between DISCOVER and
HYPOTHESIZE. Decouples the autonomous loop from recon_engine internals so either
side can change independently.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs


_SPA_TECH = ("react", "next", "nuxt", "vue", "angular", "svelte", "ember")


@dataclass(frozen=True)
class Endpoint:
    url: str
    method: str = "GET"
    params: tuple = ()        # observed parameter names
    location: str = "query"   # query | body


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
        for url in crawl:
            if not isinstance(url, str):
                continue
            names = tuple(sorted(parse_qs(urlparse(url).query).keys()))
            endpoints.append(Endpoint(url=url, method="GET", params=names, location="query"))

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
