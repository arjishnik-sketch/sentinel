"""
Operator-supplied access-policy oracle.

This module models an *external ground truth* about who is allowed to do
what — the kind of thing that lives in a design document, an API spec, or
an authorization matrix. It is deliberately pure DATA: it contains no
target-specific engine logic and makes no security claim on its own.

Its only job is to let an operator declare expectations such as:

    "the anonymous principal must be DENIED read access to /api/Feedbacks"

Sentinel then routes that declared expectation into the existing
prove-chain as an OPEN `authorization_policy_violation` hypothesis (see
`seed.py`). The deterministic judge still decides the outcome by freshly
re-probing the live target — a finding is only produced when observed
behaviour *contradicts* the declared policy. The oracle can never
manufacture a finding; it can only pose a question the judge answers.
"""

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


_ALLOWED_DECISIONS = frozenset({"allow", "deny"})

# Names an operator commonly uses for the unauthenticated caller. Purely a
# cosmetic default for the principal's `kind`; it never affects policy.
_ANON_NAMES = frozenset({
    "anonymous",
    "anon",
    "public",
    "unauthenticated",
    "guest",
})


@dataclass(frozen=True)
class PolicyPrincipal:
    """A named caller identity referenced by one or more policy rules."""

    name: str
    kind: str = "user"
    roles: tuple[str, ...] = ()
    # Request headers this principal presents (e.g. an auth token). The
    # anonymous principal has none. Reused verbatim on the fresh probe.
    headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class PolicyRule:
    """
    One declared authorization expectation.

    `decision` is the operator's ground truth ("allow" | "deny"). It is
    NOT an observation and NOT a finding — it is the policy the live
    target will be measured against.
    """

    principal: str
    method: str
    path: str
    action: str
    decision: str
    resource: str = ""
    expected_statuses: tuple[int, ...] = ()


@dataclass(frozen=True)
class AccessPolicy:
    principals: tuple[PolicyPrincipal, ...] = ()
    rules: tuple[PolicyRule, ...] = ()

    def principal(self, name: str) -> PolicyPrincipal:
        """Resolve a principal by name, synthesising a sane default."""
        for candidate in self.principals:
            if candidate.name == name:
                return candidate

        kind = "anonymous" if name.lower() in _ANON_NAMES else "user"
        return PolicyPrincipal(name=name, kind=kind)


def _as_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"access policy: '{field}' must be a non-empty string."
        )
    return value.strip()


def _as_statuses(value: Any, field: str) -> tuple[int, ...]:
    if value is None:
        return ()

    if isinstance(value, int):
        value = [value]

    if not isinstance(value, (list, tuple)):
        raise ValueError(
            f"access policy: '{field}' must be a list of HTTP status ints."
        )

    statuses = []
    for item in value:
        if not isinstance(item, int) or not (100 <= item <= 599):
            raise ValueError(
                f"access policy: '{field}' contains a non-HTTP status: "
                f"{item!r}"
            )
        statuses.append(item)

    return tuple(statuses)


def _default_statuses(decision: str) -> tuple[int, ...]:
    # Conservative protocol expectations, used only as informational
    # metadata on the probe. They never drive the allow/deny verdict —
    # the judge derives that from the live response (2xx allow, 401/403
    # deny) versus the declared policy.
    return (401, 403) if decision == "deny" else (200,)


def _parse_principal(payload: Any) -> PolicyPrincipal:
    if not isinstance(payload, dict):
        raise ValueError("access policy: each principal must be an object.")

    name = _as_str(payload.get("name"), "principals[].name")

    roles_raw = payload.get("roles", [])
    if not isinstance(roles_raw, (list, tuple)):
        raise ValueError("access policy: 'roles' must be a list.")
    roles = tuple(_as_str(role, "principals[].roles[]") for role in roles_raw)

    headers_raw = payload.get("headers", {})
    if not isinstance(headers_raw, dict):
        raise ValueError("access policy: 'headers' must be an object.")
    headers = tuple(
        (str(key), str(val))
        for key, val in sorted(headers_raw.items())
    )

    kind = payload.get("kind")
    if kind is None:
        kind = "anonymous" if name.lower() in _ANON_NAMES else "user"
    else:
        kind = _as_str(kind, "principals[].kind")

    return PolicyPrincipal(
        name=name,
        kind=kind,
        roles=roles,
        headers=headers,
    )


def _parse_rule(payload: Any) -> PolicyRule:
    if not isinstance(payload, dict):
        raise ValueError("access policy: each rule must be an object.")

    decision = _as_str(payload.get("decision"), "rules[].decision").lower()
    if decision not in _ALLOWED_DECISIONS:
        raise ValueError(
            "access policy: 'decision' must be 'allow' or 'deny', got "
            f"{decision!r}."
        )

    path = _as_str(payload.get("path"), "rules[].path")

    resource = payload.get("resource")
    resource = _as_str(resource, "rules[].resource") if resource else path

    expected = payload.get("expected_statuses")
    statuses = (
        _as_statuses(expected, "rules[].expected_statuses")
        if expected is not None
        else _default_statuses(decision)
    )

    return PolicyRule(
        principal=_as_str(payload.get("principal"), "rules[].principal"),
        method=_as_str(payload.get("method"), "rules[].method").upper(),
        path=path,
        action=_as_str(payload.get("action"), "rules[].action"),
        decision=decision,
        resource=resource,
        expected_statuses=statuses,
    )


def parse_access_policy(payload: Any) -> AccessPolicy:
    """Validate and normalise a decoded access-policy document."""

    if not isinstance(payload, dict):
        raise ValueError("access policy: top level must be a JSON object.")

    principals_raw = payload.get("principals", [])
    if not isinstance(principals_raw, (list, tuple)):
        raise ValueError("access policy: 'principals' must be a list.")
    principals = tuple(_parse_principal(item) for item in principals_raw)

    rules_raw = payload.get("rules")
    if not isinstance(rules_raw, (list, tuple)) or not rules_raw:
        raise ValueError("access policy: 'rules' must be a non-empty list.")
    rules = tuple(_parse_rule(item) for item in rules_raw)

    return AccessPolicy(principals=principals, rules=rules)


def load_access_policy(path: str | Path) -> AccessPolicy:
    """Load and validate an access-policy JSON file from disk."""

    text = Path(path).read_text(encoding="utf-8")
    return parse_access_policy(json.loads(text))
