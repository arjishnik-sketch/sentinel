"""
Operator-supplied open-redirect oracle (the redirect-surface declaration).

Pure DATA, exactly like :mod:`app.security_graph.ssti.ssti_policy`. It is
deliberately **target-agnostic**: the engine holds no knowledge of any
particular site, route, or parameter. Everything specific to a target — which
endpoint takes which redirect-destination parameter — arrives here as declared
ground truth (typed by an operator, or synthesized from live recon). Point
Sentinel at a different stack and only this data changes; not a line of engine.

An operator declares a set of *checks*, each naming one request parameter that
feeds a redirect destination:

    GET  /redirect   ?to=…       (query)
    GET  /login      ?returnUrl=… (query)

The declared parameter makes no security claim on its own. It only poses a
question the deterministic judge answers with a **two-probe host differential**
on the live target: an *off-origin payload* probe sets the parameter to a URL on
a random, unroutable nonce host (``https://sentinel-<nonce>.example/``) and a
same-origin *control* anchor sets it to the target's own origin. Open-redirect is
CONFIRMED only when the response ``Location`` header of the payload probe resolves
to the *nonce host* — a host that could ONLY have come from our parameter value,
so the redirect is provably attacker-controlled — while the control anchor proves
the endpoint legitimately redirects on-origin. A bare status code is never the
verdict; the nonce makes the differential unforgeable and non-coincidental.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import random
import string
from typing import Any


# Where a declared parameter lives in the request. Each maps to one unambiguous
# way of injecting the destination — no target-specific body semantics assumed.
_LOCATIONS = frozenset({"query", "body_form", "body_json"})

_ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

# RFC 2606 reserves `.example` for documentation/testing — it is guaranteed
# never to resolve, so the off-origin payload host is unroutable by construction.
# Combined with the no-follow probe executor, Sentinel never actually contacts
# it: the redirect is OBSERVED via the Location header, never followed.
_NONCE_TLD = "example"


@dataclass(frozen=True)
class OpenRedirectCheck:
    """
    One declared redirect-surface probe.

    `param` in `location` is filled with an off-origin URL on a random nonce
    host for the payload probe, and with the target's own same-origin origin for
    the control anchor. `method`/`path` name the endpoint. No benign value is
    needed — the nonce host is generated at seed time and recorded in the graph,
    so the pure judge can read it back and check the observed ``Location``.
    """

    method: str
    path: str
    param: str
    location: str = "query"
    severity: str = "MEDIUM"
    rationale: str = ""


@dataclass(frozen=True)
class OpenRedirectPolicy:
    checks: tuple[OpenRedirectCheck, ...] = ()


def make_nonce(rng: random.Random | None = None) -> str:
    """
    A short random token that makes the off-origin redirect host unforgeable.

    The nonce appears ONLY in the payload parameter value, so if the server's
    ``Location`` header carries a host built from it, the redirect destination
    can only have come from our input — the definition of an open redirect. Kept
    lowercase-alphanumeric so it is a valid DNS label.
    """
    picker = rng or random
    alphabet = string.ascii_lowercase + string.digits
    return "".join(picker.choice(alphabet) for _ in range(12))


def nonce_host(nonce: str) -> str:
    """The unroutable off-origin host for a nonce (``sentinel-<nonce>.example``)."""
    return f"sentinel-{nonce}.{_NONCE_TLD}"


def payload_url(nonce: str) -> str:
    """The off-origin payload destination for a nonce."""
    return f"https://{nonce_host(nonce)}/"


def _as_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"open-redirect matrix: '{field_name}' must be a non-empty string."
        )
    return value.strip()


def _parse_check(payload: Any) -> OpenRedirectCheck:
    if not isinstance(payload, dict):
        raise ValueError("open-redirect matrix: each check must be an object.")

    method = _as_str(payload.get("method", "GET"), "checks[].method").upper()
    path = _as_str(payload.get("path"), "checks[].path")
    param = _as_str(payload.get("param"), "checks[].param")

    location = payload.get("location", "query")
    location = _as_str(location, "checks[].location").lower()
    if location not in _LOCATIONS:
        raise ValueError(
            "open-redirect matrix: 'location' must be one of "
            f"{sorted(_LOCATIONS)}, got {location!r}."
        )

    severity = payload.get("severity", "MEDIUM")
    severity = _as_str(severity, "checks[].severity").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError(
            "open-redirect matrix: 'severity' must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}, got {severity!r}."
        )

    rationale = payload.get("rationale", "")
    if rationale and not isinstance(rationale, str):
        raise ValueError("open-redirect matrix: 'rationale' must be a string.")

    return OpenRedirectCheck(
        method=method,
        path=path,
        param=param,
        location=location,
        severity=severity,
        rationale=rationale.strip() if isinstance(rationale, str) else "",
    )


def parse_open_redirect_policy(payload: Any) -> OpenRedirectPolicy:
    """
    Validate and normalise a decoded open-redirect matrix.

    Accepts either a dedicated document ``{"open_redirect_matrix": {...}}`` or a
    combined access-policy document that also carries an ``open_redirect_matrix``
    section — so a single operator file drives every vulnerability class. Returns
    an empty policy (no checks) when no matrix is declared, which the caller
    treats as "open-redirect pass not requested".
    """
    if not isinstance(payload, dict):
        raise ValueError("open-redirect matrix: top level must be a JSON object.")

    matrix = payload.get("open_redirect_matrix", payload)
    if not isinstance(matrix, dict):
        raise ValueError(
            "open-redirect matrix: 'open_redirect_matrix' must be an object."
        )

    checks_raw = matrix.get("checks", [])
    if not isinstance(checks_raw, (list, tuple)):
        raise ValueError("open-redirect matrix: 'checks' must be a list.")
    checks = tuple(_parse_check(item) for item in checks_raw)

    return OpenRedirectPolicy(checks=checks)


def load_open_redirect_policy(path: str | Path) -> OpenRedirectPolicy:
    """Load and validate an open-redirect matrix JSON file from disk."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_open_redirect_policy(json.loads(text))
