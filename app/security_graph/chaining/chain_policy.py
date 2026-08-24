"""
Operator-supplied chaining targets (the downstream BOLA probes a proven chain
composes into). Pure DATA, exactly like
:mod:`app.security_graph.privesc.privesc_policy` — the engine holds no knowledge
of any particular site, route, or account. Everything target-specific arrives
here as declared ground truth: WHERE the leaked identifier belongs downstream
(``breach.path_template``, carrying the placeholder), and the captured attacker
session used to prove the second link is genuinely reachable
(``attacker_headers`` + ``control``, the liveness anchor). Point Sentinel at a
different stack and only this data changes; not a line of engine.

Chaining is the honestly-labeled hybrid exception to the URL-only discover
story: the FIRST link (the SQL injection) is discovered live from a URL alone,
but the SECOND link needs a genuine authenticated session to prove the object
boundary is crossed. That session is the operator's ground truth — never
synthesised, never guessed — so it is declared here, exactly like the
privilege-escalation login matrix. The composer still owns ZERO verdict logic:
it reuses the privilege-escalation class's unchanged pure judge, and emits an
edge only when the decoy wall holds (see
:func:`app.security_graph.chaining.compose.compose_chains`).
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from .compose import BolaChainTarget
from .consume import DEFAULT_PLACEHOLDER

_ALLOWED_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


@dataclass(frozen=True)
class ChainPolicy:
    """
    A validated set of downstream chain targets plus the source class the
    leaked artifacts are drawn from (``injection`` for the first shipped chain).

    An empty ``targets`` means "no chaining pass requested" — the capstone stays
    silent rather than manufacturing an edge.
    """

    targets: tuple[BolaChainTarget, ...] = ()
    source_kind: str = "injection"


def _as_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"chain targets: '{field_name}' must be a non-empty string."
        )
    return value.strip()


def _parse_headers(payload: Any, field_name: str) -> tuple[tuple[str, str], ...]:
    """Accept ``[["Name","Value"], ...]`` or ``{"Name": "Value", ...}``."""
    if payload is None:
        return ()
    pairs: list[tuple[str, str]] = []
    if isinstance(payload, dict):
        items = list(payload.items())
    elif isinstance(payload, (list, tuple)):
        items = []
        for entry in payload:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise ValueError(
                    f"chain targets: each '{field_name}' entry must be a "
                    "[name, value] pair."
                )
            items.append((entry[0], entry[1]))
    else:
        raise ValueError(
            f"chain targets: '{field_name}' must be an object or a list of "
            "[name, value] pairs."
        )
    for name, value in items:
        pairs.append((_as_str(name, f"{field_name}[].name"), str(value)))
    return tuple(pairs)


def _parse_target(payload: Any) -> BolaChainTarget:
    if not isinstance(payload, dict):
        raise ValueError("chain targets: each target must be an object.")

    breach = payload.get("breach")
    if not isinstance(breach, dict):
        raise ValueError(
            "chain targets: each target needs a 'breach' object naming the "
            "downstream object route (method + path_template)."
        )
    breach_method = _as_str(
        breach.get("method", "GET"), "targets[].breach.method"
    ).upper()
    breach_path_template = _as_str(
        breach.get("path_template", breach.get("path")),
        "targets[].breach.path_template",
    )

    placeholder = payload.get("placeholder", DEFAULT_PLACEHOLDER)
    placeholder = _as_str(placeholder, "targets[].placeholder")
    if placeholder not in breach_path_template:
        raise ValueError(
            f"chain targets: breach path_template "
            f"'{breach_path_template}' must contain the placeholder "
            f"'{placeholder}' the leaked id is substituted into."
        )

    attacker_headers = _parse_headers(
        payload.get("attacker_headers"), "targets[].attacker_headers"
    )

    control = payload.get("control")
    if not isinstance(control, dict):
        raise ValueError(
            "chain targets: each target needs a 'control' object naming a "
            "route the captured attacker session legitimately reaches (its "
            "liveness anchor)."
        )
    control_method = _as_str(
        control.get("method", "GET"), "targets[].control.method"
    ).upper()
    control_path = _as_str(control.get("path"), "targets[].control.path")

    victim_raw = payload.get("victim", "victim")
    victim = victim_raw.strip() if isinstance(victim_raw, str) else ""
    if not victim:
        victim = "victim"

    severity = payload.get("severity", "HIGH")
    severity = _as_str(severity, "targets[].severity").upper()
    if severity not in _ALLOWED_SEVERITIES:
        raise ValueError(
            "chain targets: 'severity' must be one of "
            f"{sorted(_ALLOWED_SEVERITIES)}, got {severity!r}."
        )

    artifact_kind = payload.get("artifact_kind", "leaked_object_id")
    artifact_kind = _as_str(artifact_kind, "targets[].artifact_kind")

    return BolaChainTarget(
        breach_path_template=breach_path_template,
        attacker_headers=attacker_headers,
        control_path=control_path,
        control_method=control_method,
        breach_method=breach_method,
        victim=victim,
        severity=severity,
        placeholder=placeholder,
        artifact_kind=artifact_kind,
    )


def parse_chain_targets(payload: Any) -> ChainPolicy:
    """
    Validate and normalise a decoded chaining-targets document.

    Accepts either a dedicated document ``{"chain_targets": {...}}`` or a
    combined access-policy document that also carries a ``chain_targets``
    section — so a single operator file drives every class, chaining included.
    Returns an empty policy (no targets) when none are declared, which the
    caller treats as "chaining pass not requested".
    """
    if not isinstance(payload, dict):
        raise ValueError("chain targets: top level must be a JSON object.")

    section = payload.get("chain_targets", payload)
    if not isinstance(section, dict):
        raise ValueError("chain targets: 'chain_targets' must be an object.")

    source_kind = section.get("source_kind", "injection")
    source_kind = _as_str(source_kind, "source_kind")

    targets_raw = section.get("targets", [])
    if not isinstance(targets_raw, (list, tuple)):
        raise ValueError("chain targets: 'targets' must be a list.")
    targets = tuple(_parse_target(item) for item in targets_raw)

    return ChainPolicy(targets=targets, source_kind=source_kind)


def load_chain_targets(path: str | Path) -> ChainPolicy:
    """Load and validate a chaining-targets JSON file from disk."""
    text = Path(path).read_text(encoding="utf-8")
    return parse_chain_targets(json.loads(text))
