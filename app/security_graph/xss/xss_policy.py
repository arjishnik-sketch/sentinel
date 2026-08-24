"""
Operator-supplied reflected-XSS oracle (the reflection-surface declaration).

Pure DATA, exactly like :mod:`app.security_graph.ssti.ssti_policy`. It is
deliberately **target-agnostic**: the engine holds no knowledge of any
particular site, route, or parameter. Everything specific to a target — which
endpoint reflects which parameter — arrives here as declared ground truth (typed
by an operator, or synthesized from live recon). Point Sentinel at a different
stack and only this data changes; not a line of engine.

An operator declares a set of *checks*, each naming one request parameter to
probe for reflected cross-site scripting:

    GET  /search    ?q=…       (query)
    POST /comment   body=…     (urlencoded body)
    POST /api/echo  {"msg": …} (JSON body)

The declared parameter makes no security claim on its own. It only poses a
question the deterministic judge answers with a **reflection differential** on
the live target: a *control* probe carries a benign random alphanumeric marker
(no HTML-significant characters) and MUST merely be reflected; a set of *payload*
probes wrap that same marker in active HTML/JS breakout shapes (``<script>``,
``<svg onload=>``, ``<img onerror=>``, ``<body onload=>``). Reflected XSS is
CONFIRMED only when a payload response contains the raw, UN-escaped markup
verbatim (with our marker inside it) AND the control proved the app reflects the
bare marker — so the HTML-significant characters provably survived output
encoding. A single status code is never itself the verdict; a value the app
HTML-escapes can never manufacture one, because the escaped form
(``&lt;script&gt;``) is not a verbatim substring of the raw payload.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import random
import string
from typing import Any


# Where a declared parameter lives in the request. Each maps to one unambiguous
# way of injecting the payload — no target-specific body semantics are assumed.
_LOCATIONS = frozenset({"query", "body_form", "body_json"})

_ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


@dataclass(frozen=True)
class XSSCheck:
    """
    One declared reflected-XSS-surface probe.

    `param` in `location` is filled with a benign random marker for the control
    probe, and with that same marker wrapped in active-markup breakout shapes for
    the payload probes. `method`/`path` name the endpoint. No benign value is
    needed — the marker is generated at seed time and recorded in the graph, so
    the pure judge can read it back.
    """

    method: str
    path: str
    param: str
    location: str = "query"
    severity: str = "HIGH"
    rationale: str = ""


@dataclass(frozen=True)
class XSSPolicy:
    checks: tuple[XSSCheck, ...] = ()


# The active-markup breakout shapes probed for each check. Each entry is
# (label, template): the SAME benign marker is wrapped in a different HTML/JS
# breakout so whichever reflection context backs the sink is exercised. Every
# shape is ALSO a member of the enforcer's ``xss`` request-guard signature family
# (a ``<tag`` and/or an ``on…=`` handler), so the exact shapes the judge keys on
# are the ones the virtual patch blocks — which is what lets the fix be PROVEN.
# The judge is shape-agnostic — it only asks whether *some* payload's raw markup
# survived verbatim (un-escaped) while carrying our marker — so this list can
# grow freely.
_XSS_PAYLOAD_SHAPES: tuple[tuple[str, str], ...] = (
    ("script_tag", "<script>{m}</script>"),      # <script>…</script>
    ("svg_onload", "<svg onload={m}>"),           # <svg onload=…>
    ("img_onerror", "<img src=x onerror={m}>"),   # <img … onerror=…>
    ("body_onload", "<body onload={m}>"),         # <body onload=…>
)


def marker_payloads(marker: str) -> tuple[tuple[str, str], ...]:
    """
    Build the ``(label, value)`` breakout payloads for one benign marker.

    Each value wraps the SAME ``marker`` in a different active-markup shape. If
    the sink reflects any of them UN-escaped, the raw markup (with the marker
    inside) survives verbatim in the response; if it HTML-escapes or drops the
    input, the raw ``<tag>`` never appears — which is exactly what the judge keys
    on. The marker inside guarantees a verbatim match is attributable to OUR
    injection, not to markup that was already on the page.
    """
    return tuple(
        (label, template.format(m=marker))
        for label, template in _XSS_PAYLOAD_SHAPES
    )


def make_marker(rng: random.Random | None = None) -> str:
    """
    Pick a distinctive benign reflection marker.

    A short lowercase-alphanumeric nonce (``s`` + 12 random chars): it carries NO
    HTML-significant character, so HTML/URL output-encoding leaves it untouched
    and it therefore reflects verbatim whenever the parameter reaches the
    response body (anchoring the differential) — yet it is astronomically
    unlikely to appear on a page by coincidence, so raw markup carrying it can
    only be our injection. ``rng`` is accepted only so tests can pin the marker
    deterministically; production uses fresh entropy.
    """
    picker = rng or random
    alphabet = string.ascii_lowercase + string.digits
    body = "".join(picker.choice(alphabet) for _ in range(12))
    return f"s{body}"


def _as_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"xss matrix: '{field_name}' must be a non-empty string."
        )
    return value.strip()


def _parse_check(payload: Any) -> XSSCheck:
    if not isinstance(payload, dict):
        raise ValueError("xss matrix: each check must be an object.")

    method = _as_str(payload.get("method", "GET"), "checks[].method").upper()
    path = _as_str(payload.get("path"), "checks[].path")
    param = _as_str(payload.get("param"), "checks[].param")

    location = payload.get("location", "query")
    location = _as_str(location, "checks[].location").lower()
    if location not in _LOCATIONS:
        raise ValueError(
            "xss matrix: 'location' must be one of "
            f"{sorted(_LOCATIONS)}, got {location!r}."
        )

    severity = payload.get("severity", "HIGH")
    severity = _as_str(severity, "checks[].severity").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError(
            "xss matrix: 'severity' must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}, got {severity!r}."
        )

    rationale = payload.get("rationale", "")
    if rationale and not isinstance(rationale, str):
        raise ValueError("xss matrix: 'rationale' must be a string.")

    return XSSCheck(
        method=method,
        path=path,
        param=param,
        location=location,
        severity=severity,
        rationale=rationale.strip() if isinstance(rationale, str) else "",
    )


def parse_xss_policy(payload: Any) -> XSSPolicy:
    """
    Validate and normalise a decoded reflected-XSS matrix.

    Accepts either a dedicated document ``{"xss_matrix": {...}}`` or a combined
    access-policy document that also carries an ``xss_matrix`` section — so a
    single operator file drives every vulnerability class. Returns an empty
    policy (no checks) when no matrix is declared, which the caller treats as
    "xss pass not requested".
    """
    if not isinstance(payload, dict):
        raise ValueError("xss matrix: top level must be a JSON object.")

    matrix = payload.get("xss_matrix", payload)
    if not isinstance(matrix, dict):
        raise ValueError("xss matrix: 'xss_matrix' must be an object.")

    checks_raw = matrix.get("checks", [])
    if not isinstance(checks_raw, (list, tuple)):
        raise ValueError("xss matrix: 'checks' must be a list.")
    checks = tuple(_parse_check(item) for item in checks_raw)

    return XSSPolicy(checks=checks)


def load_xss_policy(path: str | Path) -> XSSPolicy:
    """Load and validate a reflected-XSS matrix JSON file from disk."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_xss_policy(json.loads(text))
