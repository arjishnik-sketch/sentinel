"""
Seed operator-declared header posture into the security graph.

Mirror of :mod:`app.security_graph.policy.seed`, for the
`security_misconfiguration` class. For each declared header expectation the
seeder materialises exactly the durable state the prove-chain needs:

  * a shared `any-client` Principal, a per-route Resource, an Action and an
    Endpoint node,
  * one explicit `requires_header_posture` relationship carrying the
    expectation (this is the posture the judge reads),
  * a synthetic *declaration* Evidence record (mode is NOT "http", so it can
    never be mistaken for a live observation),
  * a non-executable *declaration* Experiment carrying the probe request
    template, and
  * an OPEN `security_misconfiguration` Hypothesis.

It never observes the target and never manufactures a finding — it only
routes a suspicion into the prove-chain. The deterministic judge decides the
outcome by freshly re-probing the live target.
"""

from __future__ import annotations

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
from .header_policy import HeaderPolicy


# The posture axis is about what every (even unauthenticated) client receives,
# so all header expectations share one synthetic principal.
_ANY_CLIENT_ID = "principal:any-client"


def _join_url(target_base: str, path: str) -> str:
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def posture_target(header: str, requirement: str) -> str:
    """Stable relationship target / identity aspect for one expectation."""
    return f"posture:{header.lower()}:{requirement}"


def _claim(method: str, path: str, expectation) -> str:
    header = expectation.header
    requirement = expectation.requirement
    if requirement == "must_present":
        detail = f"omits the {header} response header"
    elif requirement == "must_absent":
        detail = f"exposes the {header} response header"
    elif requirement == "must_equal":
        detail = f"does not set {header} to '{expectation.value}'"
    else:  # must_not_equal
        detail = f"sets {header} to the insecure value '{expectation.value}'"
    return (
        f"Security misconfiguration: {method} {path} {detail}, "
        f"violating declared header posture"
    )


def seed_header_policy(
    graph: SecurityGraph,
    policy: HeaderPolicy,
    *,
    target_base: str,
) -> tuple[str, ...]:
    """
    Seed each declared header expectation as an OPEN
    `security_misconfiguration` hypothesis.

    Returns the ids of the hypotheses seeded (skipping any expectation whose
    semantic identity is already represented in the graph).
    """

    seeded: list[str] = []

    # One shared principal for the whole posture axis.
    graph.add_principal(
        Principal(
            id=_ANY_CLIENT_ID,
            name="any-client",
            kind="any",
            roles=(),
        )
    )

    for rule in policy.rules:
        url = _join_url(target_base, rule.path)
        endpoint_id = f"endpoint:{url}"
        resource_label = rule.resource or rule.path
        resource_id = f"resource:header-posture:{resource_label}"

        graph.add_endpoint(
            Endpoint(id=endpoint_id, method=rule.method, url=url)
        )
        graph.add_resource(
            Resource(
                id=resource_id,
                type="header_posture_resource",
                name=resource_label,
            )
        )

        for expectation in rule.expectations:
            aspect = f"{expectation.header.lower()}:{expectation.requirement}"
            target_node = posture_target(
                expectation.header, expectation.requirement
            )

            identity = HypothesisIdentity(
                kind="security_misconfiguration",
                principal_id=_ANY_CLIENT_ID,
                resource_id=resource_id,
                action=aspect,
            )

            # Idempotent: never seed the same semantic claim twice.
            if graph.find_equivalent_hypothesis(identity) is not None:
                continue

            graph.add_action(Action(name=aspect))

            # --- the explicit posture edge the judge reads ---------------
            graph.add_relationship(
                Relationship(
                    source=resource_id,
                    relation="requires_header_posture",
                    target=target_node,
                    metadata=(
                        ("header", expectation.header),
                        ("requirement", expectation.requirement),
                        ("expected_value", expectation.value or ""),
                        ("severity", expectation.severity),
                        ("method", rule.method),
                        ("path", rule.path),
                        ("source", "header_policy_oracle"),
                    ),
                )
            )

            # --- synthetic provenance evidence (mode NOT "http") ---------
            evidence_id = (
                f"evidence:header-declaration:{rule.method}:"
                f"{aspect}:{endpoint_id}"
            )
            graph.add_evidence(
                Evidence(
                    id=evidence_id,
                    source="header_policy_oracle",
                    data={
                        "mode": "header_policy_declaration",
                        "method": rule.method,
                        "path": rule.path,
                        "header": expectation.header,
                        "requirement": expectation.requirement,
                        "expected_value": expectation.value or "",
                        "url": url,
                    },
                    confidence=1.0,
                )
            )

            hypothesis_id = (
                f"hyp:security-misconfig:{rule.method}:{aspect}:{endpoint_id}"
            )

            # --- declaration experiment (provenance only, never executed)-
            graph.add_experiment(
                Experiment(
                    id=(
                        f"exp:header-seed:{rule.method}:{aspect}:{endpoint_id}"
                    ),
                    hypothesis_id=f"decl:{hypothesis_id}",
                    kind="security_header_declaration",
                    description=(
                        f"Operator header-posture declaration: {rule.method} "
                        f"{rule.path} {expectation.requirement} "
                        f"{expectation.header}."
                    ),
                    status="DECLARED",
                    evidence_ids=(evidence_id,),
                    request=HttpRequestSpec(
                        method=rule.method,
                        url=url,
                        headers=(),
                        body=None,
                        principal_id=_ANY_CLIENT_ID,
                        resource_id=resource_id,
                        action=aspect,
                    ),
                    capability_id="security_misconfiguration.header_seed",
                    action="declare_header_posture",
                )
            )

            # --- the OPEN hypothesis that drives the prove-chain ---------
            graph.add_hypothesis(
                Hypothesis(
                    id=hypothesis_id,
                    kind="security_misconfiguration",
                    claim=_claim(rule.method, rule.path, expectation),
                    confidence=0.90,
                    evidence_ids=(evidence_id,),
                    identity=identity,
                    source_ids=(evidence_id,),
                    status="OPEN",
                )
            )

            seeded.append(hypothesis_id)

    return tuple(seeded)
