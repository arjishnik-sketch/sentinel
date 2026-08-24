"""
Operator-supplied SSRF oracle (the fetch-surface declaration).

Pure DATA, exactly like :mod:`app.security_graph.open_redirect.open_redirect_policy`.
It is deliberately **target-agnostic**: the engine holds no knowledge of any
particular site, route, or parameter. Everything specific to a target — which
endpoint takes which "fetch this URL for me" parameter — arrives here as declared
ground truth (typed by an operator, or synthesized from live recon). Point
Sentinel at a different stack and only this data changes; not a line of engine.

An operator declares a set of *checks*, each naming one request parameter that
feeds a server-side fetch:

    GET  /proxy      ?url=…      (query)
    POST /image      {"src": …}  (body_json)

The declared parameter makes no security claim on its own. It only poses a
question the deterministic judge answers with an **out-of-band callback
differential** on the live target. Sentinel stands up its OWN loopback
collaborator (see :mod:`.collaborator`) and injects a URL pointing back at it,
carrying a random nonce. SSRF is CONFIRMED only when the collaborator records a
hit on that exact nonce — proof the target made a server-side request of a URL we
controlled — while a never-injected control nonce stays un-hit (the anchor that
rules out a spurious/forged record). A bare status code is never the verdict; the
nonce makes the callback unforgeable and non-coincidental.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import random
import string
from typing import Any


# Where a declared parameter lives in the request. Each maps to one unambiguous
# way of injecting the fetch URL — no target-specific body semantics assumed.
_LOCATIONS = frozenset({"query", "body_form", "body_json"})

_ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


@dataclass(frozen=True)
class SsrfCheck:
    """
    One declared server-side-fetch probe.

    `param` in `location` is filled at probe time with Sentinel's own loopback
    collaborator URL (carrying a fresh nonce) for the payload probe, and with the
    target's own same-origin origin for the control anchor. `method`/`path` name
    the endpoint. No nonce is stored here: the collaborator base + per-probe
    nonces are runtime concerns, so the pure judge reads the recorded callback
    hit out of graph evidence rather than out of this declaration.
    """

    method: str
    path: str
    param: str
    location: str = "query"
    severity: str = "HIGH"
    rationale: str = ""


@dataclass(frozen=True)
class SsrfPolicy:
    checks: tuple[SsrfCheck, ...] = ()


def make_nonce(rng: random.Random | None = None) -> str:
    """
    A short random token that makes the out-of-band callback unforgeable.

    The nonce appears ONLY in the payload parameter value (as the first path
    segment of the collaborator URL), so if the collaborator records a request
    for it, that request can only have come from the target fetching our input —
    the definition of an SSRF. Kept lowercase-alphanumeric so it is a valid path
    segment (and DNS label, harmless either way).
    """
    picker = rng or random
    alphabet = string.ascii_lowercase + string.digits
    return "".join(picker.choice(alphabet) for _ in range(12))


def _as_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"ssrf matrix: '{field_name}' must be a non-empty string."
        )
    return value.strip()


def _parse_check(payload: Any) -> SsrfCheck:
    if not isinstance(payload, dict):
        raise ValueError("ssrf matrix: each check must be an object.")

    method = _as_str(payload.get("method", "GET"), "checks[].method").upper()
    path = _as_str(payload.get("path"), "checks[].path")
    param = _as_str(payload.get("param"), "checks[].param")

    location = payload.get("location", "query")
    location = _as_str(location, "checks[].location").lower()
    if location not in _LOCATIONS:
        raise ValueError(
            "ssrf matrix: 'location' must be one of "
            f"{sorted(_LOCATIONS)}, got {location!r}."
        )

    severity = payload.get("severity", "HIGH")
    severity = _as_str(severity, "checks[].severity").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError(
            "ssrf matrix: 'severity' must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}, got {severity!r}."
        )

    rationale = payload.get("rationale", "")
    if rationale and not isinstance(rationale, str):
        raise ValueError("ssrf matrix: 'rationale' must be a string.")

    return SsrfCheck(
        method=method,
        path=path,
        param=param,
        location=location,
        severity=severity,
        rationale=rationale.strip() if isinstance(rationale, str) else "",
    )


def parse_ssrf_policy(payload: Any) -> SsrfPolicy:
    """
    Validate and normalise a decoded SSRF matrix.

    Accepts either a dedicated document ``{"ssrf_matrix": {...}}`` or a combined
    access-policy document that also carries an ``ssrf_matrix`` section — so a
    single operator file drives every vulnerability class. Returns an empty
    policy (no checks) when no matrix is declared, which the caller treats as
    "ssrf pass not requested".
    """
    if not isinstance(payload, dict):
        raise ValueError("ssrf matrix: top level must be a JSON object.")

    matrix = payload.get("ssrf_matrix", payload)
    if not isinstance(matrix, dict):
        raise ValueError("ssrf matrix: 'ssrf_matrix' must be an object.")

    checks_raw = matrix.get("checks", [])
    if not isinstance(checks_raw, (list, tuple)):
        raise ValueError("ssrf matrix: 'checks' must be a list.")
    checks = tuple(_parse_check(item) for item in checks_raw)

    return SsrfPolicy(checks=checks)


def load_ssrf_policy(path: str | Path) -> SsrfPolicy:
    """Load and validate an SSRF matrix JSON file from disk."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_ssrf_policy(json.loads(text))
