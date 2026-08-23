"""
Operator-supplied privilege-escalation oracle (the "login matrix").

Pure DATA, exactly like :mod:`app.security_graph.cookies.cookie_policy` and
:mod:`app.security_graph.posture.header_policy`. It is deliberately
**target-agnostic**: the engine holds no knowledge of any particular site,
route, or account. Everything specific to a target — which accounts exist, what
each account may legitimately reach, and which object/function crosses a
privilege boundary — arrives here as declared ground truth (typed by an
operator, or captured live by the Login Tester's multi-account matrix). Point
Sentinel at a different stack and only this data changes; not a line of engine.

An operator declares a set of *principals* (accounts, each with its session
headers and one endpoint it legitimately owns — its **control**) and a set of
*checks*, each asserting a privilege boundary an attacker principal MUST NOT
cross:

    horizontal:  alice MUST NOT read GET /rest/basket/2   (bob's object — IDOR/BOLA)
    vertical:    alice MUST NOT reach GET /rest/admin/users (an admin-only function)

The declared boundary makes no security claim on its own. It only poses a
question the deterministic judge answers with a **three-probe differential** on
the live target: a *control* probe (the attacker reaching its OWN object — which
MUST succeed, proving the captured session is genuinely alive), a *breach* probe
(the attacker reaching the forbidden object/function), and an anonymous
*baseline* probe (the SAME breach request replayed with NO session). Escalation
is CONFIRMED only when the control succeeds, the breach is granted, AND the
anonymous baseline is denied — the control rules out a dead session and the
anonymous negative control rules out a public route / an app that 200s
everything, so a bare status code is never itself the verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


# The two privilege-boundary directions a check can assert. Each maps to one
# unambiguous differential the pure judge performs — no scoring, no heuristics.
_CHECK_TYPES = frozenset({"horizontal", "vertical"})

_ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

# Default "granted" statuses: any 2xx. The differential (control must also be
# 2xx) is what makes a 2xx breach meaningful; this is not a bare-status verdict.
_DEFAULT_SUCCESS_STATUSES = tuple(range(200, 300))


@dataclass(frozen=True)
class PrivEscPrincipal:
    """
    One account in the login matrix.

    `headers` are the identifying session headers a probe replays to act AS
    this principal (a bearer token, a session cookie — whatever the captured
    session carries). `control_method` + `control_path` name one endpoint this
    principal legitimately owns/reaches; a 2xx there proves the session is live
    (the confound-eliminating baseline every check reuses).
    """

    name: str
    headers: tuple[tuple[str, str], ...] = ()
    control_method: str = "GET"
    control_path: str = ""
    role: str = "user"


@dataclass(frozen=True)
class PrivEscCheck:
    """
    One declared privilege boundary an attacker principal MUST NOT cross.

      type == "horizontal"  -> `attacker` MUST NOT reach `victim`'s object
      type == "vertical"    -> `attacker` MUST NOT reach an elevated function

    `breach_method` + `breach_path` name the forbidden object/function. For a
    horizontal check `victim` names the owning principal (labelling only — the
    judge never needs the victim's session, only the attacker's).
    """

    type: str
    attacker: str
    breach_method: str
    breach_path: str
    victim: str = ""
    severity: str = "HIGH"
    rationale: str = ""


@dataclass(frozen=True)
class PrivEscPolicy:
    principals: tuple[PrivEscPrincipal, ...] = ()
    checks: tuple[PrivEscCheck, ...] = ()
    success_statuses: tuple[int, ...] = _DEFAULT_SUCCESS_STATUSES


def _as_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"privesc matrix: '{field_name}' must be a non-empty string."
        )
    return value.strip()


def _parse_headers(payload: Any, field_name: str) -> tuple[tuple[str, str], ...]:
    """Accept ``[["Name","Value"], ...]`` or ``{"Name": "Value", ...}``."""
    if payload is None:
        return ()
    pairs: list[tuple[str, str]] = []
    if isinstance(payload, dict):
        items = payload.items()
    elif isinstance(payload, (list, tuple)):
        items = []
        for entry in payload:
            if (
                not isinstance(entry, (list, tuple))
                or len(entry) != 2
            ):
                raise ValueError(
                    f"privesc matrix: each '{field_name}' entry must be a "
                    "[name, value] pair."
                )
            items.append((entry[0], entry[1]))
    else:
        raise ValueError(
            f"privesc matrix: '{field_name}' must be an object or a list of "
            "[name, value] pairs."
        )
    for name, value in items:
        pairs.append((_as_str(name, f"{field_name}[].name"), str(value)))
    return tuple(pairs)


def _parse_principal(payload: Any) -> PrivEscPrincipal:
    if not isinstance(payload, dict):
        raise ValueError("privesc matrix: each principal must be an object.")

    name = _as_str(payload.get("name"), "principals[].name")
    headers = _parse_headers(payload.get("headers"), "principals[].headers")

    control = payload.get("control")
    if not isinstance(control, dict):
        raise ValueError(
            f"privesc matrix: principal '{name}' needs a 'control' object "
            "naming an endpoint it legitimately reaches (its liveness baseline)."
        )
    control_method = _as_str(
        control.get("method", "GET"), "principals[].control.method"
    ).upper()
    control_path = _as_str(control.get("path"), "principals[].control.path")

    role = payload.get("role", "user")
    role = _as_str(role, "principals[].role") if role else "user"

    return PrivEscPrincipal(
        name=name,
        headers=headers,
        control_method=control_method,
        control_path=control_path,
        role=role,
    )


def _parse_check(payload: Any) -> PrivEscCheck:
    if not isinstance(payload, dict):
        raise ValueError("privesc matrix: each check must be an object.")

    check_type = _as_str(payload.get("type"), "checks[].type").lower()
    if check_type not in _CHECK_TYPES:
        raise ValueError(
            "privesc matrix: 'type' must be one of "
            f"{sorted(_CHECK_TYPES)}, got {check_type!r}."
        )

    attacker = _as_str(payload.get("attacker"), "checks[].attacker")

    breach = payload.get("breach")
    if not isinstance(breach, dict):
        raise ValueError(
            "privesc matrix: each check needs a 'breach' object naming the "
            "forbidden object/function (method + path)."
        )
    breach_method = _as_str(
        breach.get("method", "GET"), "checks[].breach.method"
    ).upper()
    breach_path = _as_str(breach.get("path"), "checks[].breach.path")

    victim_raw = payload.get("victim", "")
    victim = victim_raw.strip() if isinstance(victim_raw, str) else ""
    if check_type == "horizontal" and not victim:
        raise ValueError(
            "privesc matrix: a horizontal check must name the 'victim' "
            "principal whose object is being reached."
        )

    severity = payload.get("severity", "HIGH")
    severity = _as_str(severity, "checks[].severity").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError(
            "privesc matrix: 'severity' must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}, got {severity!r}."
        )

    rationale = payload.get("rationale", "")
    if rationale and not isinstance(rationale, str):
        raise ValueError("privesc matrix: 'rationale' must be a string.")

    return PrivEscCheck(
        type=check_type,
        attacker=attacker,
        breach_method=breach_method,
        breach_path=breach_path,
        victim=victim,
        severity=severity,
        rationale=rationale.strip() if isinstance(rationale, str) else "",
    )


def _parse_success_statuses(payload: Any) -> tuple[int, ...]:
    if payload is None:
        return _DEFAULT_SUCCESS_STATUSES
    if not isinstance(payload, (list, tuple)) or not payload:
        raise ValueError(
            "privesc matrix: 'success_statuses' must be a non-empty list of "
            "integer HTTP status codes."
        )
    out: list[int] = []
    for item in payload:
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValueError(
                "privesc matrix: each success status must be an integer."
            )
        out.append(item)
    return tuple(out)


def parse_privesc_policy(payload: Any) -> PrivEscPolicy:
    """
    Validate and normalise a decoded privilege-escalation matrix.

    Accepts either a dedicated document ``{"privesc_matrix": {...}}`` or a
    combined access-policy document that also carries a ``privesc_matrix``
    section — so a single operator file drives every vulnerability class.
    Returns an empty policy (no checks) when no matrix is declared, which the
    caller treats as "privilege-escalation pass not requested".

    Cross-references are validated: every check's attacker (and a horizontal
    check's victim) must be a declared principal.
    """
    if not isinstance(payload, dict):
        raise ValueError("privesc matrix: top level must be a JSON object.")

    matrix = payload.get("privesc_matrix", payload)
    if not isinstance(matrix, dict):
        raise ValueError("privesc matrix: 'privesc_matrix' must be an object.")

    principals_raw = matrix.get("principals", [])
    if not isinstance(principals_raw, (list, tuple)):
        raise ValueError("privesc matrix: 'principals' must be a list.")
    principals = tuple(_parse_principal(item) for item in principals_raw)

    checks_raw = matrix.get("checks", [])
    if not isinstance(checks_raw, (list, tuple)):
        raise ValueError("privesc matrix: 'checks' must be a list.")
    checks = tuple(_parse_check(item) for item in checks_raw)

    # An empty matrix is legal — it simply means "no privesc pass requested".
    if not checks:
        return PrivEscPolicy(principals=principals, checks=(), success_statuses=_DEFAULT_SUCCESS_STATUSES)

    known = {principal.name for principal in principals}
    for check in checks:
        if check.attacker not in known:
            raise ValueError(
                f"privesc matrix: check attacker '{check.attacker}' is not a "
                "declared principal."
            )
        if check.type == "horizontal" and check.victim not in known:
            raise ValueError(
                f"privesc matrix: horizontal check victim '{check.victim}' is "
                "not a declared principal."
            )

    success_statuses = _parse_success_statuses(matrix.get("success_statuses"))

    return PrivEscPolicy(
        principals=principals,
        checks=checks,
        success_statuses=success_statuses,
    )


def load_privesc_policy(path: str | Path) -> PrivEscPolicy:
    """Load and validate a privilege-escalation matrix JSON file from disk."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_privesc_policy(json.loads(text))

