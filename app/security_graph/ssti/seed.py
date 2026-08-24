"""
Seed the operator-declared SSTI matrix into the security graph.

Mirror of :mod:`app.security_graph.injection.seed`, for the `template_injection`
class. For each declared surface the seeder materialises exactly the durable
state the prove-chain needs:

  * a shared ``principal:any-client`` Principal, a per-parameter Resource, an
    Action and an Endpoint node,
  * one explicit ``requires_no_template_injection`` relationship carrying the
    surface the judge/runner read (method, path, param, location) PLUS the
    per-hypothesis arithmetic operands generated here — ``operand_a``,
    ``operand_b``, the literal expression ``a*b`` and its computed ``product`` —
    so the pure judge can read back the exact value that proves evaluation,
  * a synthetic *declaration* Evidence record (mode is NOT "http", so it can
    never be mistaken for a live observation),
  * a non-executable *declaration* Experiment carrying the control probe
    template, and
  * an OPEN `template_injection` Hypothesis.

It never observes the target and never manufactures a finding — it only routes a
declared surface into the prove-chain. The deterministic judge decides the
outcome by freshly re-probing the live target with the arithmetic-evaluation
differential and comparing the observed response bodies.

The operands are generated once, at seed time, and recorded in the graph — the
same role a benign baseline value plays for the boolean-injection class. Because
they are DATA in the relationship, the remediation verifier (which copies
relationships onto a scratch graph) re-probes with the identical operands, so
the before/after differential is measured against the same expected product.
"""

from __future__ import annotations

import random

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
from .ssti_policy import SSTICheck, SSTIPolicy, make_operands


_ANY_CLIENT = "principal:any-client"


def _join_url(target_base: str, path: str) -> str:
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _aspect(check: SSTICheck) -> str:
    """Stable identity aspect for one check (unique per injectable surface)."""
    return f"{check.location}:{check.param}:{check.method}:{check.path}"


def ssti_target(check: SSTICheck) -> str:
    """Stable relationship target node for one check."""
    return f"template_injection:{_aspect(check)}"


def _claim(check: SSTICheck) -> str:
    return (
        f"Server-side template injection: the '{check.param}' parameter of "
        f"{check.method} {check.path} ({check.location}) is evaluated by a "
        "template engine — an arithmetic expression is computed server-side"
    )


def seed_ssti_policy(
    graph: SecurityGraph,
    policy: SSTIPolicy,
    *,
    target_base: str,
    rng: random.Random | None = None,
) -> tuple[str, ...]:
    """
    Seed each declared SSTI-surface check as an OPEN `template_injection`
    hypothesis.

    Returns the ids of the hypotheses seeded (skipping any check whose semantic
    identity is already represented in the graph). ``rng`` is accepted only so
    tests can pin the operands deterministically; production uses fresh entropy.
    """

    seeded: list[str] = []

    graph.add_principal(
        Principal(id=_ANY_CLIENT, name="any client", kind="client", roles=())
    )

    for check in policy.checks:
        aspect = _aspect(check)
        target_node = ssti_target(check)

        endpoint_url = _join_url(target_base, check.path)

        resource_id = (
            f"resource:ssti:{check.method}:{check.path}:{check.param}"
        )
        endpoint_id = f"endpoint:{endpoint_url}"

        identity = HypothesisIdentity(
            kind="template_injection",
            principal_id=_ANY_CLIENT,
            resource_id=resource_id,
            action=aspect,
        )

        # Idempotent: never seed the same semantic surface twice.
        if graph.find_equivalent_hypothesis(identity) is not None:
            continue

        # Generate the arithmetic probe operands ONCE and record them. The judge
        # reads the product back from the graph; it never re-derives it.
        operand_a, operand_b = make_operands(rng)
        literal_expr = f"{operand_a}*{operand_b}"
        product = str(operand_a * operand_b)

        graph.add_resource(
            Resource(
                id=resource_id,
                type="ssti_surface_resource",
                name=f"{check.method} {check.path} [{check.param}]",
            )
        )
        graph.add_endpoint(
            Endpoint(id=endpoint_id, method=check.method, url=endpoint_url)
        )
        graph.add_action(Action(name=aspect))

        # --- the explicit template-injection-surface edge the judge/runner read
        graph.add_relationship(
            Relationship(
                source=resource_id,
                relation="requires_no_template_injection",
                target=target_node,
                metadata=(
                    ("method", check.method),
                    ("path", check.path),
                    ("endpoint_url", endpoint_url),
                    ("param", check.param),
                    ("location", check.location),
                    ("operand_a", str(operand_a)),
                    ("operand_b", str(operand_b)),
                    ("literal_expr", literal_expr),
                    ("product", product),
                    ("severity", check.severity),
                    ("source", "ssti_matrix_oracle"),
                ),
            )
        )

        # --- synthetic provenance evidence (mode NOT "http") --------------
        evidence_id = f"evidence:ssti-declaration:{aspect}:{endpoint_id}"
        graph.add_evidence(
            Evidence(
                id=evidence_id,
                source="ssti_matrix_oracle",
                data={
                    "mode": "ssti_matrix_declaration",
                    "method": check.method,
                    "path": check.path,
                    "param": check.param,
                    "location": check.location,
                    "literal_expr": literal_expr,
                    "product": product,
                },
                confidence=1.0,
            )
        )

        hypothesis_id = f"hyp:ssti:{aspect}:{endpoint_id}"

        # --- declaration experiment (provenance only, never executed) -----
        graph.add_experiment(
            Experiment(
                id=f"exp:ssti-seed:{aspect}:{endpoint_id}",
                hypothesis_id=f"decl:{hypothesis_id}",
                kind="template_injection_declaration",
                description=(
                    f"Operator SSTI-surface declaration: probe the "
                    f"'{check.param}' parameter of {check.method} {check.path} "
                    f"({check.location}) for server-side template evaluation."
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
                capability_id="ssti.ssti_seed",
                action="declare_ssti_surface",
            )
        )

        # --- the OPEN hypothesis that drives the prove-chain --------------
        graph.add_hypothesis(
            Hypothesis(
                id=hypothesis_id,
                kind="template_injection",
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
