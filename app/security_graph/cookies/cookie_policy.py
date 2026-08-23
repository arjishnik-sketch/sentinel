"""
Operator-supplied cookie-security oracle.

Pure DATA, exactly like :mod:`app.security_graph.posture.header_policy`. It
lets an operator declare, per route, the security attributes a ``Set-Cookie``
the endpoint issues MUST (or MUST NOT) carry:

    "GET /rest/user/login   the 'token' cookie MUST be HttpOnly"
    "GET /                  every Set-Cookie MUST be Secure"
    "POST /login            the 'session' cookie MUST set SameSite=Strict"
    "GET /                  no cookie may set SameSite=None"

Weak session cookies (missing ``HttpOnly``/``Secure`` or a permissive
``SameSite``) are the classic pivot for session theft and CSRF — the
ingredients a real attacker chains with a broken-access-control finding.

The declared expectation makes no security claim on its own. It only poses a
question the deterministic judge answers by freshly re-probing the live target
and parsing the ``Set-Cookie`` it *actually* observes. An expectation is only
meaningful against a cookie the target genuinely sets; a route that issues no
matching cookie yields DISPROVED and no finding (the honest differential).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


# The four deterministic checks a single expectation can express. Each maps
# to one unambiguous comparison the pure judge performs against the observed
# Set-Cookie attributes — no scoring, no heuristics.
_CHECKS = frozenset(
    {
        "must_have_flag",
        "must_not_have_flag",
        "samesite_must_equal",
        "samesite_must_not_equal",
    }
)

# Checks that assert presence/absence of a valueless attribute flag.
_FLAG_CHECKS = frozenset({"must_have_flag", "must_not_have_flag"})
# Checks that compare the SameSite value.
_SAMESITE_CHECKS = frozenset({"samesite_must_equal", "samesite_must_not_equal"})

# The only two valueless cookie attribute flags a check may target.
_ALLOWED_FLAGS = {"httponly": "HttpOnly", "secure": "Secure"}
# Canonical SameSite values (case-insensitive on the wire).
_ALLOWED_SAMESITE = {"strict": "Strict", "lax": "Lax", "none": "None"}

_ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


@dataclass(frozen=True)
class CookieExpectation:
    """
    One declared expectation about a single ``Set-Cookie`` on a route.

    `check` is the operator's ground truth, not an observation:

      must_have_flag        -> the cookie MUST carry `flag` (HttpOnly/Secure)
      must_not_have_flag    -> the cookie MUST NOT carry `flag`
      samesite_must_equal   -> the cookie's SameSite MUST equal `value`
      samesite_must_not_equal -> SameSite MUST NOT equal `value` (e.g. None)

    `cookie_name` empty means "every Set-Cookie the route issues".
    """

    cookie_name: str
    check: str
    flag: str | None = None
    value: str | None = None
    severity: str = "MEDIUM"
    rationale: str = ""


@dataclass(frozen=True)
class CookieRule:
    """All declared cookie expectations for one route (method + path)."""

    method: str
    path: str
    expectations: tuple[CookieExpectation, ...] = ()
    resource: str = ""


@dataclass(frozen=True)
class CookiePolicy:
    rules: tuple[CookieRule, ...] = ()


def _as_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"cookie policy: '{field}' must be a non-empty string."
        )
    return value.strip()


def _parse_expectation(payload: Any) -> CookieExpectation:
    if not isinstance(payload, dict):
        raise ValueError("cookie policy: each expectation must be an object.")

    # cookie_name may be empty ("" / omitted) to mean "every Set-Cookie".
    cookie_name_raw = payload.get("cookie_name", "")
    if cookie_name_raw is None:
        cookie_name_raw = ""
    if not isinstance(cookie_name_raw, str):
        raise ValueError("cookie policy: 'cookie_name' must be a string.")
    cookie_name = cookie_name_raw.strip()

    check = _as_str(payload.get("check"), "expectations[].check").lower()
    if check not in _CHECKS:
        raise ValueError(
            "cookie policy: 'check' must be one of "
            f"{sorted(_CHECKS)}, got {check!r}."
        )

    flag: str | None = None
    value: str | None = None

    if check in _FLAG_CHECKS:
        flag_raw = _as_str(payload.get("flag"), "expectations[].flag").lower()
        if flag_raw not in _ALLOWED_FLAGS:
            raise ValueError(
                "cookie policy: 'flag' must be one of "
                f"{sorted(_ALLOWED_FLAGS.values())}, got {payload.get('flag')!r}."
            )
        flag = _ALLOWED_FLAGS[flag_raw]
        if payload.get("value") is not None:
            raise ValueError(
                f"cookie policy: '{check}' does not take a 'value'."
            )
    else:  # SameSite comparison
        value_raw = _as_str(payload.get("value"), "expectations[].value").lower()
        if value_raw not in _ALLOWED_SAMESITE:
            raise ValueError(
                "cookie policy: SameSite 'value' must be one of "
                f"{sorted(_ALLOWED_SAMESITE.values())}, got {payload.get('value')!r}."
            )
        value = _ALLOWED_SAMESITE[value_raw]
        if payload.get("flag") is not None:
            raise ValueError(
                f"cookie policy: '{check}' does not take a 'flag'."
            )

    severity = payload.get("severity", "MEDIUM")
    severity = _as_str(severity, "expectations[].severity").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError(
            "cookie policy: 'severity' must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}, got {severity!r}."
        )

    rationale = payload.get("rationale", "")
    if rationale and not isinstance(rationale, str):
        raise ValueError("cookie policy: 'rationale' must be a string.")

    return CookieExpectation(
        cookie_name=cookie_name,
        check=check,
        flag=flag,
        value=value,
        severity=severity,
        rationale=rationale.strip() if isinstance(rationale, str) else "",
    )


def _parse_rule(payload: Any) -> CookieRule:
    if not isinstance(payload, dict):
        raise ValueError("cookie policy: each rule must be an object.")

    method = _as_str(payload.get("method", "GET"), "cookie_rules[].method").upper()
    path = _as_str(payload.get("path"), "cookie_rules[].path")

    resource = payload.get("resource")
    resource = _as_str(resource, "cookie_rules[].resource") if resource else path

    expectations_raw = payload.get("expectations")
    if not isinstance(expectations_raw, (list, tuple)) or not expectations_raw:
        raise ValueError(
            "cookie policy: each rule needs a non-empty 'expectations' list."
        )
    expectations = tuple(_parse_expectation(item) for item in expectations_raw)

    return CookieRule(
        method=method,
        path=path,
        expectations=expectations,
        resource=resource,
    )


def parse_cookie_policy(payload: Any) -> CookiePolicy:
    """
    Validate and normalise a decoded cookie-security document.

    Accepts either a dedicated document ``{"cookie_rules": [...]}`` or a
    combined access-policy document that also carries a ``cookie_rules``
    section — so a single operator file drives all three vulnerability
    classes. Returns an empty policy (no rules) when no cookie rules are
    declared, which the caller treats as "cookie pass not requested".
    """

    if not isinstance(payload, dict):
        raise ValueError("cookie policy: top level must be a JSON object.")

    rules_raw = payload.get("cookie_rules", [])
    if not isinstance(rules_raw, (list, tuple)):
        raise ValueError("cookie policy: 'cookie_rules' must be a list.")

    rules = tuple(_parse_rule(item) for item in rules_raw)
    return CookiePolicy(rules=rules)


def load_cookie_policy(path: str | Path) -> CookiePolicy:
    """Load and validate a cookie-security JSON file from disk."""

    text = Path(path).read_text(encoding="utf-8")
    return parse_cookie_policy(json.loads(text))
