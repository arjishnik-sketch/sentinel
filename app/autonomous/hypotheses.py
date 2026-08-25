"""Hypothesis generation: qwen proposes, deterministic rules guarantee a floor.

A Hypothesis is a PROPOSAL to test one technique at one place. It is never a
finding. Downstream, provable techniques are routed to a pure differential
judge; the rest are recorded as clearly-labelled LEADs, never conflated with a
CONFIRMED result.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

from .llm import ask_json

# technique -> how it is adjudicated. "differential" techniques have a pure
# judge that proves them with a differential; "lead" techniques are surfaced as
# evidence-backed leads only (honest tier, never labelled CONFIRMED).
TECHNIQUE_ROUTING = {
    "sql_injection": "differential",
    "xss": "differential",
    "open_redirect": "differential",
    "path_traversal": "differential",
    "ssti": "differential",
    "cors": "differential",
    "ssrf": "differential",
    "broken_auth": "differential",
    "idor": "differential",
    "privilege_escalation": "differential",
    "graphql_introspection": "lead",
    "mass_assignment": "lead",
    "excessive_data_exposure": "lead",
    "nosql_injection": "lead",
    "jwt_weakness": "lead",
}
KNOWN_TECHNIQUES = frozenset(TECHNIQUE_ROUTING)

_REDIRECT_PARAMS = {
    "url", "next", "redirect", "redirect_uri", "redirecturl", "return",
    "returnurl", "return_to", "dest", "destination", "continue", "goto",
    "target", "u", "r", "link",
}


@dataclass(frozen=True)
class Hypothesis:
    technique: str
    url: str
    method: str = "GET"
    param: "str | None" = None
    location: str = "query"
    rationale: str = ""
    severity: str = "MEDIUM"
    source: str = "rule"      # rule | llm
    skill: "str | None" = None

    @property
    def key(self):
        return (self.technique, self.url, self.param, self.location)

    @property
    def provable(self) -> bool:
        return TECHNIQUE_ROUTING.get(self.technique) == "differential"


def rule_based_hypotheses(surface):
    """Deterministic floor: injectable params -> SQLi/XSS/traversal; redirect-shaped
    params -> open_redirect; a trailing resource id in the path -> path-segment SQLi.
    Guarantees the loop works with the LLM entirely off."""
    out = []
    for ep in surface.endpoints:
        # A trailing resource id in the URL path (…/users/1) is a SQLi surface in
        # its own right. Only sql_injection is posed here: the id-in-path shape is
        # the canonical path-segment injection, and the other classes have no
        # path placement, so proposing them would be dishonest breadth.
        if getattr(ep, "location", "query") == "path":
            for p in ep.params:
                out.append(Hypothesis(
                    "sql_injection", ep.url, ep.method, p, "path",
                    f"resource id in path segment '{p}'", "HIGH", "rule"))
            continue
        for p in ep.params:
            for tech, sev in (("sql_injection", "HIGH"), ("xss", "MEDIUM"), ("path_traversal", "HIGH")):
                out.append(Hypothesis(tech, ep.url, ep.method, p, "query", f"observed param '{p}'", sev, "rule"))
            if p.lower() in _REDIRECT_PARAMS:
                out.append(Hypothesis("open_redirect", ep.url, ep.method, p, "query", f"redirect-shaped param '{p}'", "MEDIUM", "rule"))
    if surface.has_login:
        for login in surface.logins:
            out.append(Hypothesis("broken_auth", login, "POST", None, "body", "login surface present", "HIGH", "rule"))
    return out


def build_prompt(surface, skill_cards=()):
    system = (
        "You are a web application pentest planner. Propose concrete, TESTABLE "
        "vulnerability hypotheses using ONLY the observed surface below. Never "
        "invent endpoints. Output STRICT JSON: {\"hypotheses\": [ {technique, url, "
        "method, param, location, severity, rationale, skill} ]}. `technique` MUST "
        "be one of: " + ", ".join(sorted(KNOWN_TECHNIQUES)) + ". `url` MUST be one "
        "of the observed endpoints or the target. `location` in query|body|path|header. "
        "`severity` in LOW|MEDIUM|HIGH|CRITICAL. Keep rationale under 15 words."
    )
    payload = {
        "target": surface.target,
        "techs": list(surface.techs),
        "is_spa": surface.is_spa,
        "has_login": surface.has_login,
        "has_graphql": surface.has_graphql,
        "endpoints": [
            {"url": e.url, "method": e.method, "params": list(e.params)}
            for e in surface.endpoints[:40]
        ],
        "skill_hints": [
            {"name": getattr(c, "name", ""), "description": getattr(c, "description", "")}
            for c in skill_cards[:12]
        ],
    }
    return system, json.dumps(payload)


def parse_hypotheses(data, surface, source="llm"):
    items = data.get("hypotheses") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    host = surface.host
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        tech = str(it.get("technique", "")).strip().lower()
        if tech not in KNOWN_TECHNIQUES:
            continue
        url = str(it.get("url") or surface.target).strip()
        from urllib.parse import urlparse
        if "://" in url and urlparse(url).netloc.lower() != host:
            continue  # scope: never propose off-target
        param = it.get("param")
        param = str(param) if param not in (None, "", "null") else None
        out.append(
            Hypothesis(
                technique=tech,
                url=url,
                method=str(it.get("method", "GET")).upper(),
                param=param,
                location=str(it.get("location", "query")).lower(),
                rationale=str(it.get("rationale", ""))[:120],
                severity=str(it.get("severity", "MEDIUM")).upper(),
                source=source,
                skill=(str(it["skill"]) if it.get("skill") else None),
            )
        )
    return out


def propose(surface, skill_cards=(), *, use_llm=True, transport=None, max_hyps=64):
    """Merge deterministic rules (floor) with LLM proposals (breadth). Deduped."""
    merged = {}
    for h in rule_based_hypotheses(surface):
        merged.setdefault(h.key, h)
    if use_llm:
        system, user = build_prompt(surface, skill_cards)
        res = ask_json(system, user, transport=transport, num_predict=768)
        if res.ok and res.data is not None:
            for h in parse_hypotheses(res.data, surface, source="llm"):
                merged.setdefault(h.key, h)
    return list(merged.values())[:max_hyps]
