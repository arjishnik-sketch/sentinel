"""Hypothesis generation: qwen proposes, deterministic rules guarantee a floor.

A Hypothesis is a PROPOSAL to test one technique at one place. It is never a
finding. Downstream, provable techniques are routed to a pure differential
judge; the rest are recorded as clearly-labelled LEADs, never conflated with a
CONFIRMED result.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import urlsplit

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

# Conventional credential field names an auth endpoint interpolates into its
# identity lookup. We do not know which one a given target uses, so both are
# posed; the pure judge DISPROVES the field that is not actually there.
_CREDENTIAL_FIELDS = ("email", "username")

# Path substrings that mark an auth endpoint as a JSON API (body_json) rather
# than a classic urlencoded form POST (body_form). Kept generic — REST/versioned
# API conventions, never one application's routes.
_JSON_PATH_HINTS = ("/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql")

# URL words that mark an endpoint as an auth surface. A login endpoint mined out
# of the app's JavaScript lands in `apis` (not `logins`), so we also scan there —
# `logins` alone would miss the SPA/JSON auth route, the common real-world case.
_AUTH_URL_WORDS = ("login", "signin", "authenticate", "session")

# A login legitimately answers a bad credential with 401/403 and a good one with
# 200 — all three are well-formed application responses, so any of them anchors
# the differential. A 500 is NOT here: it is the SQL-error signal the quote-parity
# arm keys on (odd-quote breaks the literal → off anchor; even-quote restores it).
# Without this, the pure judge's anchor gate defaults to 2xx only and a 401-baseline
# login returns INCONCLUSIVE — no honest measurement possible.
_LOGIN_SUCCESS_STATUSES = (200, 401, 403)


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
    # Anchor set for surfaces whose legitimate baseline is not 2xx (a login
    # answers a bad credential with 401/403). None → the judge's default 2xx.
    success_statuses: "tuple | None" = None

    @property
    def key(self):
        return (self.technique, self.url, self.param, self.location)

    @property
    def shape(self):
        """Full probe identity for retry de-duplication — everything the judge's
        anchor gate and probe builder actually see. Two hypotheses with the same
        :attr:`key` but different ``success_statuses`` are DIFFERENT probes (the
        anchor set changes what the differential can measure), so they must not
        collapse: a login that is both wrong-shape AND non-2xx-baseline is only
        reached by trying the anchored variant of an already-toggled shape."""
        return (self.technique, self.url, self.method, self.param,
                self.location, self.success_statuses)

    @property
    def provable(self) -> bool:
        return TECHNIQUE_ROUTING.get(self.technique) == "differential"


def _login_targets(surface) -> list:
    """Auth endpoints to probe for credential-field SQLi, in stable order.

    Union of the surfaces recon labelled logins and any discovered ``apis`` route
    whose path carries an auth word — so an SPA/JSON login mined from JavaScript
    (which lands in ``apis``, not ``logins``) is still reached. De-duped, order
    preserved (logins first)."""
    out = []
    seen = set()
    for url in surface.logins:
        if isinstance(url, str) and url and url not in seen:
            seen.add(url)
            out.append(url)
    for url in getattr(surface, "apis", ()) or ():
        if not isinstance(url, str) or not url or url in seen:
            continue
        if any(w in urlsplit(url).path.lower() for w in _AUTH_URL_WORDS):
            seen.add(url)
            out.append(url)
    return out


def _login_body_location(login_url, surface) -> str:
    """JSON body for an API/SPA auth endpoint, urlencoded form otherwise."""
    path = urlsplit(login_url).path.lower()
    if surface.is_spa or surface.has_graphql or any(h in path for h in _JSON_PATH_HINTS):
        return "body_json"
    return "body_form"


def rule_based_hypotheses(surface):
    """Deterministic floor: injectable params -> SQLi/XSS/traversal; redirect-shaped
    params -> open_redirect; a trailing resource id in the path -> path-segment SQLi;
    an auth endpoint -> credential-field (auth-bypass) SQLi + a broken_auth lead.
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

    # Auth endpoints: pose credential-field SQL injection (the classic auth-bypass
    # surface — an identifier interpolated into the identity lookup). Recon has no
    # body-parameter discovery, so the realistic signal is the login itself; the
    # content-type adapts to the target's shape (JSON API vs form POST) and
    # success_statuses carries the login's real legitimate baseline so the pure
    # judge has an anchor. The broken_auth LEAD (needs a login/identity matrix)
    # stays an honest lead beside it.
    for login in _login_targets(surface):
        loc = _login_body_location(login, surface)
        for field in _CREDENTIAL_FIELDS:
            out.append(Hypothesis(
                "sql_injection", login, "POST", field, loc,
                f"credential field '{field}' on auth endpoint (auth-bypass SQLi)",
                "HIGH", "rule", success_statuses=_LOGIN_SUCCESS_STATUSES))
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
