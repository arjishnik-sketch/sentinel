"""
Seed the operator-declared login matrix into the security graph.

Mirror of :mod:`app.security_graph.cookies.seed`, for the
`privilege_escalation` class. For each declared privilege-boundary check the
seeder materialises exactly the durable state the prove-chain needs:

  * a per-attacker Principal (carrying the account's session headers), a
    per-breach Resource, an Action and an Endpoint node,
  * one explicit `requires_no_privilege_escalation` relationship carrying the
    whole differential the judge reads (attacker headers, the control URL that
    proves the session is alive, the forbidden breach URL, the "granted" status
    set, and the boundary type/labels),
  * a synthetic *declaration* Evidence record (mode is NOT "http", so it can
    never be mistaken for a live observation),
  * a non-executable *declaration* Experiment carrying the breach probe
    template, and
  * an OPEN `privilege_escalation` Hypothesis.

It never observes the target and never manufactures a finding — it only routes
a declared boundary into the prove-chain. The deterministic judge decides the
outcome by freshly re-probing the live target twice (control + breach) and
comparing the observed differential.

The seeder is entirely target-agnostic: every host/route/account detail comes
from the operator matrix (or the Login Tester's captured sessions), so the same
code drives any target.
"""

from __future__ import annotations

import json

from ..graph import SecurityGraph
from ..models import (
    Action,
    Endpoint,
    Evidence,
    Experiment,
    Hypothesis,
    HypothesisIdentity,
    HttpRequestSpec,
    Principal,
    Relationship,
    Resource,
)
from .privesc_policy import PrivEscCheck, PrivEscPolicy, PrivEscPrincipal


def _join_url(target_base: str, path: str) -> str:
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _aspect(check: PrivEscCheck) -> str:
    """Stable identity aspect for one check (unique per boundary tested)."""
    counterparty = check.victim if check.type == "horizontal" else "elevated"
    return (
        f"{check.type}:{check.attacker}->{counterparty}:"
        f"{check.breach_method}:{check.breach_path}"
    )


def privesc_target(check: PrivEscCheck) -> str:
    """Stable relationship target node for one check."""
    return f"privesc:{_aspect(check)}"


def _claim(check: PrivEscCheck) -> str:
    if check.type == "horizontal":
        boundary = (
            f"reads {check.victim}'s object at "
            f"{check.breach_method} {check.breach_path} (horizontal / BOLA)"
        )
    else:
        boundary = (
            f"reaches the elevated function "
            f"{check.breach_method} {check.breach_path} (vertical)"
        )
    return (
        f"Privilege escalation: '{check.attacker}' {boundary}, "
        f"crossing a declared privilege boundary"
    )


def seed_privesc_policy(
    graph: SecurityGraph,
    policy: PrivEscPolicy,
    *,
    target_base: str,
) -> tuple[str, ...]:
    """
    Seed each declared privilege-boundary check as an OPEN
    `privilege_escalation` hypothesis.

    Returns the ids of the hypotheses seeded (skipping any check whose semantic
    identity is already represented in the graph).
    """

    seeded: list[str] = []

    by_name: dict[str, PrivEscPrincipal] = {
        principal.name: principal for principal in policy.principals
    }
    success_statuses = list(policy.success_statuses)

    for check in policy.checks:
        attacker = by_name.get(check.attacker)
        if attacker is None:
            # parse_privesc_policy already validates this; defensive only.
            continue

        aspect = _aspect(check)
        target_node = privesc_target(check)

        breach_url = _join_url(target_base, check.breach_path)
        control_url = _join_url(target_base, attacker.control_path)

        principal_id = f"principal:privesc:{attacker.name}"
        resource_id = (
            f"resource:privesc:{check.breach_method}:{check.breach_path}"
        )
        endpoint_id = f"endpoint:{breach_url}"

        identity = HypothesisIdentity(
            kind="privilege_escalation",
            principal_id=principal_id,
            resource_id=resource_id,
            action=aspect,
        )

        # Idempotent: never seed the same semantic boundary twice.
        if graph.find_equivalent_hypothesis(identity) is not None:
            continue

        graph.add_principal(
            Principal(
                id=principal_id,
                name=attacker.name,
                kind="user",
                roles=(attacker.role,) if attacker.role else (),
            )
        )
        graph.add_resource(
            Resource(
                id=resource_id,
                type="privesc_boundary_resource",
                name=f"{check.breach_method} {check.breach_path}",
            )
        )
        graph.add_endpoint(
            Endpoint(id=endpoint_id, method=check.breach_method, url=breach_url)
        )
        graph.add_action(Action(name=aspect))

        attacker_headers_json = json.dumps([list(pair) for pair in attacker.headers])
        success_json = json.dumps(success_statuses)

        # --- the explicit privilege-boundary edge the judge reads ----------
        graph.add_relationship(
            Relationship(
                source=resource_id,
                relation="requires_no_privilege_escalation",
                target=target_node,
                metadata=(
                    ("type", check.type),
                    ("attacker", check.attacker),
                    ("victim", check.victim),
                    ("attacker_headers", attacker_headers_json),
                    ("control_method", attacker.control_method),
                    ("control_url", control_url),
                    ("breach_method", check.breach_method),
                    ("breach_url", breach_url),
                    ("breach_path", check.breach_path),
                    ("success_statuses", success_json),
                    ("severity", check.severity),
                    ("source", "privesc_matrix_oracle"),
                ),
            )
        )

        # --- synthetic provenance evidence (mode NOT "http") --------------
        evidence_id = f"evidence:privesc-declaration:{aspect}:{endpoint_id}"
        graph.add_evidence(
            Evidence(
                id=evidence_id,
                source="privesc_matrix_oracle",
                data={
                    "mode": "privesc_matrix_declaration",
                    "type": check.type,
                    "attacker": check.attacker,
                    "victim": check.victim,
                    "control_method": attacker.control_method,
                    "control_url": control_url,
                    "breach_method": check.breach_method,
                    "breach_url": breach_url,
                },
                confidence=1.0,
            )
        )

        hypothesis_id = f"hyp:privilege-escalation:{aspect}:{endpoint_id}"

        # --- declaration experiment (provenance only, never executed) -----
        graph.add_experiment(
            Experiment(
                id=f"exp:privesc-seed:{aspect}:{endpoint_id}",
                hypothesis_id=f"decl:{hypothesis_id}",
                kind="privilege_escalation_declaration",
                description=(
                    f"Operator privilege-boundary declaration: '{check.attacker}'"
                    f" MUST NOT reach {check.breach_method} {check.breach_path}"
                    f" ({check.type})."
                ),
                status="DECLARED",
                evidence_ids=(evidence_id,),
                request=HttpRequestSpec(
                    method=check.breach_method,
                    url=breach_url,
                    headers=attacker.headers,
                    body=None,
                    principal_id=principal_id,
                    resource_id=resource_id,
                    action=aspect,
                ),
                capability_id="privilege_escalation.privesc_seed",
                action="declare_privilege_boundary",
            )
        )

        # --- the OPEN hypothesis that drives the prove-chain --------------
        graph.add_hypothesis(
            Hypothesis(
                id=hypothesis_id,
                kind="privilege_escalation",
                claim=_claim(check),
                confidence=0.90,
                evidence_ids=(evidence_id,),
                identity=identity,
                source_ids=(evidence_id,),
                status="OPEN",
            )
        )

        seeded.append(hypothesis_id)

    return tuple(seeded)
