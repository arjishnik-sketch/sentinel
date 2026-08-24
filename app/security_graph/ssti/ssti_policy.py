"""
Operator-supplied SSTI oracle (the template-injection-surface declaration).

Pure DATA, exactly like :mod:`app.security_graph.injection.injection_policy`. It
is deliberately **target-agnostic**: the engine holds no knowledge of any
particular site, route, or parameter. Everything specific to a target — which
endpoint reflects which parameter — arrives here as declared ground truth (typed
by an operator, or synthesized from live recon). Point Sentinel at a different
stack and only this data changes; not a line of engine.

An operator declares a set of *checks*, each naming one request parameter to
probe for server-side template injection:

    GET  /rest/products/search  ?q=…       (query)
    POST /profile               name=…     (urlencoded body)
    POST /api/render            {"tpl": …} (JSON body)

The declared parameter makes no security claim on its own. It only poses a
question the deterministic judge answers with an **arithmetic-evaluation
differential** on the live target: a *control* probe carries the literal
expression ``a*b`` (no template delimiters) and MUST merely be reflected; a set
of *payload* probes wrap that same ``a*b`` in the common template delimiters
(``{{…}}``, ``${…}``, ``#{…}``, ``<%= … %>``). SSTI is CONFIRMED only when a
payload response contains the *computed product* ``a*b`` while the literal
expression is gone AND the control proved the app merely reflects (so the
product can only have come from the backend evaluating the template). A single
status code is never itself the verdict; a reflected payload can never
manufacture one, because the reflected form still contains the literal.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import random
from typing import Any


# Where a declared parameter lives in the request. Each maps to one unambiguous
# way of injecting the payload — no target-specific body semantics are assumed.
_LOCATIONS = frozenset({"query", "body_form", "body_json"})

_ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


@dataclass(frozen=True)
class SSTICheck:
    """
    One declared template-injection-surface probe.

    `param` in `location` is filled with the literal expression ``a*b`` for the
    control probe, and with that same expression wrapped in template delimiters
    for the payload probes. `method`/`path` name the endpoint. No benign value
    is needed — the operand pair (and thus the expected product) is generated at
    seed time and recorded in the graph, so the pure judge can read it back.
    """

    method: str
    path: str
    param: str
    location: str = "query"
    severity: str = "HIGH"
    rationale: str = ""


@dataclass(frozen=True)
class SSTIPolicy:
    checks: tuple[SSTICheck, ...] = ()


# The template-expression syntaxes probed for each check. Each entry is
# (label, opener, closer): the SAME arithmetic expression ``a*b`` is wrapped in
# every common server-side template delimiter, so whichever engine backs the
# sink is exercised without the engine assuming any one framework. The judge is
# syntax-agnostic — it only asks whether *some* payload made the product appear
# while the literal expression vanished — so this list can grow freely.
_TEMPLATE_SYNTAXES: tuple[tuple[str, str, str], ...] = (
    ("jinja_twig", "{{", "}}"),      # Jinja2 / Twig / Nunjucks / Liquid
    ("dollar_el", "${", "}"),        # FreeMarker / JSP-EL / Thymeleaf / JS tpl
    ("hash_el", "#{", "}"),          # Ruby ERB-ish / JSF / Thymeleaf inline
    ("erb", "<%= ", " %>"),          # ERB / EJS
)


def template_payloads(literal_expr: str) -> tuple[tuple[str, str], ...]:
    """
    Build the ``(label, value)`` template payloads for one literal expression.

    Each value wraps the SAME ``literal_expr`` (e.g. ``1009*9973``) in a
    different template delimiter. If the sink evaluates any of them the computed
    product replaces the expression; if it merely reflects, the literal survives
    verbatim inside the delimiters — which is exactly what the judge keys on.
    """
    return tuple(
        (label, f"{opener}{literal_expr}{closer}")
        for label, opener, closer in _TEMPLATE_SYNTAXES
    )


def make_operands(rng: random.Random | None = None) -> tuple[int, int]:
    """
    Pick two operands whose product is a distinctive multi-digit number.

    Deliberately random 4-digit operands: the product is a 7–8 digit integer
    that is astronomically unlikely to appear coincidentally in a page, and the
    control probe additionally proves it is absent under mere reflection — so a
    product appearing under a template delimiter can only be an evaluation.
    """
    picker = rng or random
    a = picker.randint(1000, 9999)
    b = picker.randint(1000, 9999)
    return a, b


def _as_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"ssti matrix: '{field_name}' must be a non-empty string."
        )
    return value.strip()


def _parse_check(payload: Any) -> SSTICheck:
    if not isinstance(payload, dict):
        raise ValueError("ssti matrix: each check must be an object.")

    method = _as_str(payload.get("method", "GET"), "checks[].method").upper()
    path = _as_str(payload.get("path"), "checks[].path")
    param = _as_str(payload.get("param"), "checks[].param")

    location = payload.get("location", "query")
    location = _as_str(location, "checks[].location").lower()
    if location not in _LOCATIONS:
        raise ValueError(
            "ssti matrix: 'location' must be one of "
            f"{sorted(_LOCATIONS)}, got {location!r}."
        )

    severity = payload.get("severity", "HIGH")
    severity = _as_str(severity, "checks[].severity").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError(
            "ssti matrix: 'severity' must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}, got {severity!r}."
        )

    rationale = payload.get("rationale", "")
    if rationale and not isinstance(rationale, str):
        raise ValueError("ssti matrix: 'rationale' must be a string.")

    return SSTICheck(
        method=method,
        path=path,
        param=param,
        location=location,
        severity=severity,
        rationale=rationale.strip() if isinstance(rationale, str) else "",
    )


def parse_ssti_policy(payload: Any) -> SSTIPolicy:
    """
    Validate and normalise a decoded SSTI matrix.

    Accepts either a dedicated document ``{"ssti_matrix": {...}}`` or a combined
    access-policy document that also carries an ``ssti_matrix`` section — so a
    single operator file drives every vulnerability class. Returns an empty
    policy (no checks) when no matrix is declared, which the caller treats as
    "ssti pass not requested".
    """
    if not isinstance(payload, dict):
        raise ValueError("ssti matrix: top level must be a JSON object.")

    matrix = payload.get("ssti_matrix", payload)
    if not isinstance(matrix, dict):
        raise ValueError("ssti matrix: 'ssti_matrix' must be an object.")

    checks_raw = matrix.get("checks", [])
    if not isinstance(checks_raw, (list, tuple)):
        raise ValueError("ssti matrix: 'checks' must be a list.")
    checks = tuple(_parse_check(item) for item in checks_raw)

    return SSTIPolicy(checks=checks)


def load_ssti_policy(path: str | Path) -> SSTIPolicy:
    """Load and validate an SSTI matrix JSON file from disk."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_ssti_policy(json.loads(text))
