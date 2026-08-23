"""
Seed the operator-declared injection matrix into the security graph.

Mirror of :mod:`app.security_graph.privesc.seed`, for the `injection` class.
For each declared injectable-surface check the seeder materialises exactly the
durable state the prove-chain needs:

  * a shared ``principal:any-client`` Principal, a per-parameter Resource, an
    Action and an Endpoint node,
  * one explicit ``requires_no_injection`` relationship carrying the whole
    injection point the judge/runner read (method, path, param, location, the
    benign baseline value, the "legitimate" status set, and severity),
  * a synthetic *declaration* Evidence record (mode is NOT "http", so it can
    never be mistaken for a live observation),
  * a non-executable *declaration* Experiment carrying the baseline probe
    template, and
  * an OPEN `injection` Hypothesis.

It never observes the target and never manufactures a finding — it only routes
a declared injectable surface into the prove-chain. The deterministic judge
decides the outcome by freshly re-probing the live target with the three-way
boolean differential and comparing the observed responses.

The seeder is entirely target-agnostic: every host/route/parameter detail comes
from the operator matrix (or a spec import), so the same code drives any target.
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
from .injection_policy import InjectionCheck, InjectionPolicy


_ANY_CLIENT = "principal:any-client"


def _join_url(target_base: str, path: str) -> str:
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _aspect(check: InjectionCheck) -> str:
    """Stable identity aspect for one check (unique per injectable surface)."""
    return f"{check.location}:{check.param}:{check.method}:{check.path}"


def injection_target(check: InjectionCheck) -> str:
    """Stable relationship target node for one check."""
    return f"injection:{_aspect(check)}"


def _claim(check: InjectionCheck) -> str:
    return (
        f"SQL injection: the '{check.param}' parameter of "
        f"{check.method} {check.path} ({check.location}) alters the backend "
        "query — a boolean payload toggles the response"
    )


def seed_injection_policy(
    graph: SecurityGraph,
    policy: InjectionPolicy,
    *,
    target_base: str,
) -> tuple[str, ...]:
    """
    Seed each declared injectable-surface check as an OPEN `injection`
    hypothesis.

    Returns the ids of the hypotheses seeded (skipping any check whose semantic
    identity is already represented in the graph).
    """

    seeded: list[str] = []
    success_statuses = list(policy.success_statuses)

    graph.add_principal(
        Principal(id=_ANY_CLIENT, name="any client", kind="client", roles=())
    )

    for check in policy.checks:
        aspect = _aspect(check)
        target_node = injection_target(check)

        endpoint_url = _join_url(target_base, check.path)

        resource_id = f"resource:injection:{check.method}:{check.path}:{check.param}"
        endpoint_id = f"endpoint:{endpoint_url}"

        identity = HypothesisIdentity(
            kind="injection",
            principal_id=_ANY_CLIENT,
            resource_id=resource_id,
            action=aspect,
        )

        # Idempotent: never seed the same semantic surface twice.
        if graph.find_equivalent_hypothesis(identity) is not None:
            continue

        graph.add_resource(
            Resource(
                id=resource_id,
                type="injection_surface_resource",
                name=f"{check.method} {check.path} [{check.param}]",
            )
        )
        graph.add_endpoint(
            Endpoint(id=endpoint_id, method=check.method, url=endpoint_url)
        )
        graph.add_action(Action(name=aspect))

        success_json = json.dumps(success_statuses)

        # --- the explicit injectable-surface edge the judge/runner read ------
        graph.add_relationship(
            Relationship(
                source=resource_id,
                relation="requires_no_injection",
                target=target_node,
                metadata=(
                    ("method", check.method),
                    ("path", check.path),
                    ("endpoint_url", endpoint_url),
                    ("param", check.param),
                    ("location", check.location),
                    ("baseline_value", check.baseline_value),
                    ("success_statuses", success_json),
                    ("severity", check.severity),
                    ("source", "injection_matrix_oracle"),
                ),
            )
        )

        # --- synthetic provenance evidence (mode NOT "http") --------------
        evidence_id = f"evidence:injection-declaration:{aspect}:{endpoint_id}"
        graph.add_evidence(
            Evidence(
                id=evidence_id,
                source="injection_matrix_oracle",
                data={
                    "mode": "injection_matrix_declaration",
                    "method": check.method,
                    "path": check.path,
                    "param": check.param,
                    "location": check.location,
                    "baseline_value": check.baseline_value,
                },
                confidence=1.0,
            )
        )

        hypothesis_id = f"hyp:injection:{aspect}:{endpoint_id}"

        # --- declaration experiment (provenance only, never executed) -----
        graph.add_experiment(
            Experiment(
                id=f"exp:injection-seed:{aspect}:{endpoint_id}",
                hypothesis_id=f"decl:{hypothesis_id}",
                kind="injection_declaration",
                description=(
                    f"Operator injectable-surface declaration: probe the "
                    f"'{check.param}' parameter of {check.method} {check.path} "
                    f"({check.location}) for SQL injection."
                ),
                status="DECLARED",
                evidence_ids=(evidence_id,),
                request=HttpRequestSpec(
                    method=check.method,
                    url=endpoint_url,
                    headers=(),
                    body=None,
                    principal_id=_ANY_CLIENT,
                    resource_id=resource_id,
                    action=aspect,
                ),
                capability_id="injection.injection_seed",
                action="declare_injectable_surface",
            )
        )

        # --- the OPEN hypothesis that drives the prove-chain --------------
        graph.add_hypothesis(
            Hypothesis(
                id=hypothesis_id,
                kind="injection",
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
