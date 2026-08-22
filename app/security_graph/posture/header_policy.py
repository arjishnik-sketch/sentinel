"""
Operator-supplied header-posture oracle.

Pure DATA, exactly like :mod:`app.security_graph.policy.access_policy`. It
lets an operator declare, per route, the browser-level protections the
endpoint MUST ship:

    "GET / MUST present Content-Security-Policy"
    "GET / MUST NOT set Access-Control-Allow-Origin to '*'"
    "GET / MUST NOT expose X-Powered-By"

The declared expectation is grounded in a standard security-headers audit
(CSP / HSTS / X-Frame-Options / X-Content-Type-Options / Referrer-Policy /
Permissions-Policy, non-wildcard CORS, and information-disclosure headers).
It makes no security claim on its own — it only poses a question the
deterministic judge answers by freshly re-probing the live target.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


# The four deterministic checks a single expectation can express. Each maps
# to one unambiguous comparison the pure judge performs against the observed
# response header — no scoring, no heuristics.
_REQUIREMENTS = frozenset(
    {"must_present", "must_absent", "must_equal", "must_not_equal"}
)

# Requirements that compare against a concrete value; the others are pure
# presence/absence checks and ignore `value`.
_VALUE_REQUIREMENTS = frozenset({"must_equal", "must_not_equal"})

_ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


@dataclass(frozen=True)
class HeaderExpectation:
    """
    One declared expectation about a single response header on a route.

    `requirement` is the operator's ground truth, not an observation:

      must_present    -> the header MUST appear in the response
      must_absent     -> the header MUST NOT appear (e.g. X-Powered-By)
      must_equal      -> the header MUST equal `value` (case-insensitive)
      must_not_equal  -> the header MUST NOT equal `value` (e.g. CORS '*')
    """

    header: str
    requirement: str
    value: str | None = None
    severity: str = "MEDIUM"
    rationale: str = ""


@dataclass(frozen=True)
class HeaderRule:
    """All declared header expectations for one route (method + path)."""

    method: str
    path: str
    expectations: tuple[HeaderExpectation, ...] = ()
    resource: str = ""


@dataclass(frozen=True)
class HeaderPolicy:
    rules: tuple[HeaderRule, ...] = ()


def _as_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"header policy: '{field}' must be a non-empty string."
        )
    return value.strip()


def _parse_expectation(payload: Any) -> HeaderExpectation:
    if not isinstance(payload, dict):
        raise ValueError(
            "header policy: each expectation must be an object."
        )

    header = _as_str(payload.get("header"), "expectations[].header")

    requirement = _as_str(
        payload.get("requirement"), "expectations[].requirement"
    ).lower()
    if requirement not in _REQUIREMENTS:
        raise ValueError(
            "header policy: 'requirement' must be one of "
            f"{sorted(_REQUIREMENTS)}, got {requirement!r}."
        )

    value = payload.get("value")
    if requirement in _VALUE_REQUIREMENTS:
        value = _as_str(value, "expectations[].value")
    elif value is not None:
        # A value on a presence/absence check is meaningless; reject it so
        # the declaration stays unambiguous.
        raise ValueError(
            f"header policy: '{requirement}' does not take a 'value'."
        )

    severity = payload.get("severity", "MEDIUM")
    severity = _as_str(severity, "expectations[].severity").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError(
            "header policy: 'severity' must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}, got {severity!r}."
        )

    rationale = payload.get("rationale", "")
    if rationale and not isinstance(rationale, str):
        raise ValueError("header policy: 'rationale' must be a string.")

    return HeaderExpectation(
        header=header,
        requirement=requirement,
        value=value,
        severity=severity,
        rationale=rationale.strip() if isinstance(rationale, str) else "",
    )


def _parse_rule(payload: Any) -> HeaderRule:
    if not isinstance(payload, dict):
        raise ValueError("header policy: each rule must be an object.")

    method = _as_str(payload.get("method", "GET"), "header_rules[].method").upper()
    path = _as_str(payload.get("path"), "header_rules[].path")

    resource = payload.get("resource")
    resource = _as_str(resource, "header_rules[].resource") if resource else path

    expectations_raw = payload.get("expectations")
    if not isinstance(expectations_raw, (list, tuple)) or not expectations_raw:
        raise ValueError(
            "header policy: each rule needs a non-empty 'expectations' list."
        )
    expectations = tuple(_parse_expectation(item) for item in expectations_raw)

    return HeaderRule(
        method=method,
        path=path,
        expectations=expectations,
        resource=resource,
    )


def parse_header_policy(payload: Any) -> HeaderPolicy:
    """
    Validate and normalise a decoded header-posture document.

    Accepts either a dedicated document ``{"header_rules": [...]}`` or a
    combined access-policy document that also carries a ``header_rules``
    section — so a single operator file can drive both vulnerability
    classes. Returns an empty policy (no rules) when no header rules are
    declared, which the caller treats as "posture pass not requested".
    """

    if not isinstance(payload, dict):
        raise ValueError("header policy: top level must be a JSON object.")

    rules_raw = payload.get("header_rules", [])
    if not isinstance(rules_raw, (list, tuple)):
        raise ValueError("header policy: 'header_rules' must be a list.")

    rules = tuple(_parse_rule(item) for item in rules_raw)
    return HeaderPolicy(rules=rules)


def load_header_policy(path: str | Path) -> HeaderPolicy:
    """Load and validate a header-posture JSON file from disk."""

    text = Path(path).read_text(encoding="utf-8")
    return parse_header_policy(json.loads(text))
