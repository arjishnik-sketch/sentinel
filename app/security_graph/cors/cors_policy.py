"""
Operator-supplied CORS oracle (the cross-origin-surface declaration).

Pure DATA, exactly like :mod:`app.security_graph.open_redirect.open_redirect_policy`.
It is deliberately **target-agnostic**: the engine holds no knowledge of any
particular site or route. Everything specific to a target — which endpoint must
not trust an arbitrary cross-origin caller — arrives here as declared ground
truth (typed by an operator, or synthesized from live recon). Point Sentinel at
a different stack and only this data changes; not a line of engine.

An operator declares a set of *checks*, each naming one request surface whose
cross-origin access-control response MUST be safe:

    GET  /api/account
    GET  /profile

The declared surface makes no security claim on its own. It only poses a
question the deterministic judge answers with a **two-probe origin differential**
on the live target: a *payload* probe sends an ``Origin`` request header naming a
random, unroutable nonce origin (``https://sentinel-<nonce>.example``) and a
*control* anchor sends the SAME request with NO ``Origin`` header. A CORS
misconfiguration is CONFIRMED only when the payload response reflects that exact
attacker origin (or ``*``) in ``Access-Control-Allow-Origin`` AND sets
``Access-Control-Allow-Credentials: true`` — a credentialed cross-origin read the
victim's browser would honour — while the control anchor proves the reflection is
*origin-driven* rather than a static header. A bare reflected origin is never the
verdict; the nonce makes the differential unforgeable, and the credentials flag is
what makes it exploitable. The attacker origin is only ever ECHOED back by the
server — Sentinel never contacts it (it is unroutable by RFC 2606).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import random
import string
from typing import Any


_ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

# RFC 2606 reserves `.example` for documentation/testing — it is guaranteed
# never to resolve, so the nonce origin is unroutable by construction. The CORS
# probe only ever sends it as an ``Origin`` request header and reads it back from
# ``Access-Control-Allow-Origin``; Sentinel never opens a connection to it.
_NONCE_TLD = "example"


@dataclass(frozen=True)
class CorsCheck:
    """
    One declared cross-origin-surface probe.

    `method`/`path` name the endpoint. No benign value is needed — the nonce
    origin is generated at seed time and recorded in the graph, so the pure judge
    can read it back and check the observed ``Access-Control-Allow-Origin``. CORS
    is decided by the ``Origin`` *request header*, so — unlike open redirect —
    there is no injectable parameter or location: the payload probe adds the
    header, the control probe omits it.
    """

    method: str
    path: str
    severity: str = "MEDIUM"
    rationale: str = ""


@dataclass(frozen=True)
class CorsPolicy:
    checks: tuple[CorsCheck, ...] = ()


def make_nonce(rng: random.Random | None = None) -> str:
    """
    A short random token that makes the reflected origin unforgeable.

    The nonce appears ONLY in the payload ``Origin`` request header, so if the
    server's ``Access-Control-Allow-Origin`` carries an origin built from it, the
    reflection can only have come from our input — the definition of an
    origin-reflecting CORS policy. Kept lowercase-alphanumeric so it is a valid
    DNS label.
    """
    picker = rng or random
    alphabet = string.ascii_lowercase + string.digits
    return "".join(picker.choice(alphabet) for _ in range(12))


def nonce_host(nonce: str) -> str:
    """The unroutable nonce host for a nonce (``sentinel-<nonce>.example``)."""
    return f"sentinel-{nonce}.{_NONCE_TLD}"


def nonce_origin(nonce: str) -> str:
    """The attacker ``Origin`` header value for a nonce (NO trailing slash).

    An HTTP ``Origin`` is scheme+host[+port] only — it never carries a path — so
    this deliberately omits the trailing ``/`` that :func:`payload_url` uses for
    open redirect.
    """
    return f"https://{nonce_host(nonce)}"


def _as_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"cors matrix: '{field_name}' must be a non-empty string."
        )
    return value.strip()


def _parse_check(payload: Any) -> CorsCheck:
    if not isinstance(payload, dict):
        raise ValueError("cors matrix: each check must be an object.")

    method = _as_str(payload.get("method", "GET"), "checks[].method").upper()
    path = _as_str(payload.get("path"), "checks[].path")

    severity = payload.get("severity", "MEDIUM")
    severity = _as_str(severity, "checks[].severity").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError(
            "cors matrix: 'severity' must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}, got {severity!r}."
        )

    rationale = payload.get("rationale", "")
    if rationale and not isinstance(rationale, str):
        raise ValueError("cors matrix: 'rationale' must be a string.")

    return CorsCheck(
        method=method,
        path=path,
        severity=severity,
        rationale=rationale.strip() if isinstance(rationale, str) else "",
    )


def parse_cors_policy(payload: Any) -> CorsPolicy:
    """
    Validate and normalise a decoded CORS matrix.

    Accepts either a dedicated document ``{"cors_matrix": {...}}`` or a combined
    access-policy document that also carries a ``cors_matrix`` section — so a
    single operator file drives every vulnerability class. Returns an empty
    policy (no checks) when no matrix is declared, which the caller treats as
    "cors pass not requested".
    """
    if not isinstance(payload, dict):
        raise ValueError("cors matrix: top level must be a JSON object.")

    matrix = payload.get("cors_matrix", payload)
    if not isinstance(matrix, dict):
        raise ValueError("cors matrix: 'cors_matrix' must be an object.")

    checks_raw = matrix.get("checks", [])
    if not isinstance(checks_raw, (list, tuple)):
        raise ValueError("cors matrix: 'checks' must be a list.")
    checks = tuple(_parse_check(item) for item in checks_raw)

    return CorsPolicy(checks=checks)


def load_cors_policy(path: str | Path) -> CorsPolicy:
    """Load and validate a CORS matrix JSON file from disk."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_cors_policy(json.loads(text))
