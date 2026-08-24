"""
Operator-supplied injection oracle (the injectable-surface declaration).

Pure DATA, exactly like :mod:`app.security_graph.privesc.privesc_policy` and
:mod:`app.security_graph.posture.header_policy`. It is deliberately
**target-agnostic**: the engine holds no knowledge of any particular site,
route, or parameter. Everything specific to a target — which endpoint takes
which parameter, and a benign value that yields a legitimate response — arrives
here as declared ground truth (typed by an operator, or imported from a spec).
Point Sentinel at a different stack and only this data changes; not a line of
engine.

An operator declares a set of *checks*, each naming one request parameter to
probe for SQL injection:

    GET  /rest/products/search  ?q=apple       (query)
    POST /rest/user/login       email=...      (urlencoded body)
    POST /api/search            {"term": ...}  (JSON body)

The declared parameter makes no security claim on its own. It only poses a
question the deterministic judge answers with a **three-way boolean
differential** on the live target: a *baseline* probe (the benign value), a
*TRUE* probe (the benign value + a boolean-tautology payload), and a *FALSE*
probe (the benign value + a boolean-contradiction payload). Each TRUE/FALSE pair
is length-matched to the character, so the ONLY difference between the two
requests is ``1`` vs ``2`` — any change in the response therefore comes from the
backend evaluating the injected boolean, not from the payload being reflected.
Injection is CONFIRMED only when a length-matched pair makes the response track
the injected boolean while one arm still reproduces the legitimate baseline; a
single error or status code is never itself the verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


# Where a declared parameter lives in the request. Each maps to one unambiguous
# way of injecting the payload — no target-specific body semantics are assumed.
_LOCATIONS = frozenset({"query", "body_form", "body_json"})

_ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

# Default "legitimate response" statuses: any 2xx. The differential (one arm
# must reproduce the benign baseline) is what makes a 2xx meaningful; this is
# never a bare-status verdict.
_DEFAULT_SUCCESS_STATUSES = tuple(range(200, 300))


@dataclass(frozen=True)
class InjectionCheck:
    """
    One declared injectable-surface probe.

    `param` in `location` is filled with the benign `baseline_value` for the
    baseline probe, and with ``baseline_value + <boolean payload>`` for the
    TRUE/FALSE probes. `method`/`path` name the endpoint.
    """

    method: str
    path: str
    param: str
    baseline_value: str
    location: str = "query"
    severity: str = "HIGH"
    rationale: str = ""


@dataclass(frozen=True)
class InjectionPolicy:
    checks: tuple[InjectionCheck, ...] = ()
    success_statuses: tuple[int, ...] = _DEFAULT_SUCCESS_STATUSES


# A ladder of boolean-injection payload pairs covering the common SQL string /
# numeric / parenthesised contexts. Each entry is (true_suffix, false_suffix)
# and the two are ALWAYS equal length (they differ only by the final digit), so
# a reflected payload contributes identical bytes to both the TRUE and FALSE
# responses and cannot by itself create a TRUE/FALSE difference. If ANY pair
# exhibits the differential, the parameter is injectable — this keeps the class
# target-agnostic without assuming a specific quoting/context.
#
# Two families are represented. The *open-context* pairs (no comment) suit a
# parameter interpolated with no trailing SQL. The *comment-terminated* pairs
# (``-- -``) break out of a quoted string, close 0/1/2 grouping parens, and then
# comment away everything the backend appended — the common shape of a grouped
# ``WHERE ((col LIKE '%<p>%' ...) AND ...)`` query where the parameter is even
# interpolated twice. This is why the ladder stays honest on real stacks:
# whichever paren depth keeps the injected query valid is the one that toggles
# the boolean; the wrong depths raise a backend error that collapses (TRUE==
# FALSE) rather than manufacturing a verdict.
_BOOLEAN_PAIR_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("' OR '1'='1", "' OR '1'='2"),
    ("' AND '1'='1", "' AND '1'='2"),
    ('" OR "1"="1', '" OR "1"="2'),
    ('" AND "1"="1', '" AND "1"="2'),
    ("') OR ('1'='1", "') OR ('1'='2"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("')) OR (('1'='1", "')) OR (('1'='2"),
    ("')) AND (('1'='1", "')) AND (('1'='2"),
    (" OR 1=1-- -", " OR 1=2-- -"),
    (" AND 1=1-- -", " AND 1=2-- -"),
    ("' OR 1=1-- -", "' OR 1=2-- -"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ("') OR 1=1-- -", "') OR 1=2-- -"),
    ("') AND 1=1-- -", "') AND 1=2-- -"),
    ("')) OR 1=1-- -", "')) OR 1=2-- -"),
    ("')) AND 1=1-- -", "')) AND 1=2-- -"),
)


def boolean_payload_pairs(baseline_value: str) -> tuple[tuple[str, str], str]:
    """
    Build the length-matched (TRUE, FALSE) payload pairs for a baseline value.

    Returns ``(pairs, baseline_value)`` where each pair is
    ``(baseline_value + true_suffix, baseline_value + false_suffix)``. Because
    every suffix pair is equal length, ``len(true) == len(false)`` for all
    pairs — the invariant the judge relies on.
    """
    pairs = tuple(
        (baseline_value + true_suffix, baseline_value + false_suffix)
        for true_suffix, false_suffix in _BOOLEAN_PAIR_SUFFIXES
    )
    return pairs, baseline_value


# Quote-parity (error-based) suffixes for the SQL string-literal context. Each
# entry is (odd_suffix, even_suffix): the odd suffix appends an UNBALANCED number
# of quotes (breaks the literal → the backend errors, leaving the success anchor)
# and the even suffix appends a BALANCED number (keeps the literal well-formed →
# the response returns to the anchor). "Odd breaks / even restores" is a
# backend-origin signal — a reflected value cannot change the STATUS by quote
# parity, and a generic quote-rejecting filter fails it (it rejects both arms).
# Two rungs (1↔2 and 3↔4 quotes) guard against a route that errors on a single
# appended character for an unrelated reason. This is the common real-world SQLi
# that a single-injection-point boolean payload misses (e.g. a parameter that is
# interpolated into the query more than once).
_QUOTE_PARITY_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("'", "''"),
    ("'''", "''''"),
)


def quote_parity_payloads(baseline_value: str) -> tuple[tuple[str, str], ...]:
    """
    Build the (odd_quote, even_quote) value pairs for the error-based arm.

    Returns a tuple of ``(baseline_value + odd_suffix, baseline_value +
    even_suffix)`` pairs. The odd arm appends an UNBALANCED number of quotes
    (breaks a SQL string literal → off the success anchor); the even arm appends
    a BALANCED number (restores the literal → back on the anchor). Unlike the
    boolean ladder this needs no length-matching: the arms are judged against the
    success anchor by STATUS parity, not against each other by length.
    """
    return tuple(
        (baseline_value + odd, baseline_value + even)
        for odd, even in _QUOTE_PARITY_SUFFIXES
    )


def _as_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"injection matrix: '{field_name}' must be a non-empty string."
        )
    return value.strip()


def _parse_check(payload: Any) -> InjectionCheck:
    if not isinstance(payload, dict):
        raise ValueError("injection matrix: each check must be an object.")

    method = _as_str(payload.get("method", "GET"), "checks[].method").upper()
    path = _as_str(payload.get("path"), "checks[].path")
    param = _as_str(payload.get("param"), "checks[].param")

    location = payload.get("location", "query")
    location = _as_str(location, "checks[].location").lower()
    if location not in _LOCATIONS:
        raise ValueError(
            "injection matrix: 'location' must be one of "
            f"{sorted(_LOCATIONS)}, got {location!r}."
        )

    # A benign value that yields a legitimate response is required — the
    # differential is anchored to it, never invented.
    baseline_value = payload.get("baseline_value", "")
    if not isinstance(baseline_value, str) or not baseline_value:
        raise ValueError(
            "injection matrix: each check needs a non-empty 'baseline_value' "
            "(a benign value that returns a legitimate response)."
        )

    severity = payload.get("severity", "HIGH")
    severity = _as_str(severity, "checks[].severity").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError(
            "injection matrix: 'severity' must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}, got {severity!r}."
        )

    rationale = payload.get("rationale", "")
    if rationale and not isinstance(rationale, str):
        raise ValueError("injection matrix: 'rationale' must be a string.")

    return InjectionCheck(
        method=method,
        path=path,
        param=param,
        baseline_value=baseline_value,
        location=location,
        severity=severity,
        rationale=rationale.strip() if isinstance(rationale, str) else "",
    )


def _parse_success_statuses(payload: Any) -> tuple[int, ...]:
    if payload is None:
        return _DEFAULT_SUCCESS_STATUSES
    if not isinstance(payload, (list, tuple)) or not payload:
        raise ValueError(
            "injection matrix: 'success_statuses' must be a non-empty list of "
            "integer HTTP status codes."
        )
    out: list[int] = []
    for item in payload:
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValueError(
                "injection matrix: each success status must be an integer."
            )
        out.append(item)
    return tuple(out)


def parse_injection_policy(payload: Any) -> InjectionPolicy:
    """
    Validate and normalise a decoded injection matrix.

    Accepts either a dedicated document ``{"injection_matrix": {...}}`` or a
    combined access-policy document that also carries an ``injection_matrix``
    section — so a single operator file drives every vulnerability class.
    Returns an empty policy (no checks) when no matrix is declared, which the
    caller treats as "injection pass not requested".
    """
    if not isinstance(payload, dict):
        raise ValueError("injection matrix: top level must be a JSON object.")

    matrix = payload.get("injection_matrix", payload)
    if not isinstance(matrix, dict):
        raise ValueError("injection matrix: 'injection_matrix' must be an object.")

    checks_raw = matrix.get("checks", [])
    if not isinstance(checks_raw, (list, tuple)):
        raise ValueError("injection matrix: 'checks' must be a list.")
    checks = tuple(_parse_check(item) for item in checks_raw)

    if not checks:
        return InjectionPolicy(
            checks=(), success_statuses=_DEFAULT_SUCCESS_STATUSES
        )

    success_statuses = _parse_success_statuses(matrix.get("success_statuses"))

    return InjectionPolicy(checks=checks, success_statuses=success_statuses)


def load_injection_policy(path: str | Path) -> InjectionPolicy:
    """Load and validate an injection matrix JSON file from disk."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_injection_policy(json.loads(text))
