"""
Seed the operator-declared path-traversal matrix into the security graph.

Mirror of :mod:`app.security_graph.xss.seed`, for the `path_traversal` class.
For each declared surface the seeder materialises exactly the durable state the
prove-chain needs:

  * a shared ``principal:any-client`` Principal, a per-parameter Resource, an
    Action and an Endpoint node,
  * one explicit ``requires_no_path_traversal`` relationship carrying the surface
    the judge/runner read (method, path, param, location) PLUS the fixed benign
    control filename the control probe sends (``CONTROL_VALUE`` — a
    traversal-free, non-OS name that can never leak a system file) — so the pure
    judge can read back the exact control that anchors the OS-canary differential
    by invariant ABSENCE,
  * a synthetic *declaration* Evidence record (mode is NOT "http", so it can
    never be mistaken for a live observation),
  * a non-executable *declaration* Experiment carrying the control probe
    template, and
  * an OPEN `path_traversal` Hypothesis.

It never observes the target and never manufactures a finding — it only routes a
declared surface into the prove-chain. The deterministic judge decides the
outcome by freshly re-probing the live target with the OS-canary differential
and comparing the observed response bodies against the fixed canary invariants.

Unlike XSS, the control value is a FIXED module constant, not per-hypothesis
entropy: the payload ladder and the OS-file invariants are fixed canaries too, so
the remediation verifier reconstructs the identical differential without any
per-hypothesis state.
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
from .traversal_policy import CONTROL_VALUE, TraversalCheck, TraversalPolicy

_ANY_CLIENT = "principal:any-client"


def _join_url(target_base: str, path: str) -> str:
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _aspect(check: TraversalCheck) -> str:
    """Stable identity aspect for one check (unique per file surface)."""
    return f"{check.location}:{check.param}:{check.method}:{check.path}"


def traversal_target(check: TraversalCheck) -> str:
    """Stable relationship target node for one check."""
    return f"traversal:{_aspect(check)}"


def _claim(check: TraversalCheck) -> str:
    return (
        f"Path traversal / LFI: the '{check.param}' parameter of "
        f"{check.method} {check.path} ({check.location}) reads a file OUTSIDE the "
        "intended directory — a directory-escape payload leaks an OS system file "
        "into the response"
    )


def seed_path_traversal_policy(
    graph: SecurityGraph,
    policy: TraversalPolicy,
    *,
    target_base: str,
) -> tuple[str, ...]:
    """
    Seed each declared path-traversal-surface check as an OPEN
    `path_traversal` hypothesis.

    Returns the ids of the hypotheses seeded (skipping any check whose semantic
    identity is already represented in the graph).
    """

    seeded: list[str] = []

    graph.add_principal(
        Principal(id=_ANY_CLIENT, name="any client", kind="client", roles=())
    )
    for check in policy.checks:
        aspect = _aspect(check)
        target_node = traversal_target(check)

        endpoint_url = _join_url(target_base, check.path)

        resource_id = (
            f"resource:traversal:{check.method}:{check.path}:{check.param}"
        )
        endpoint_id = f"endpoint:{endpoint_url}"

        identity = HypothesisIdentity(
            kind="path_traversal",
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
                type="path_traversal_surface_resource",
                name=f"{check.method} {check.path} [{check.param}]",
            )
        )
        graph.add_endpoint(
            Endpoint(id=endpoint_id, method=check.method, url=endpoint_url)
        )
        graph.add_action(Action(name=aspect))

        # --- the explicit path-traversal-surface edge the judge/runner read
        graph.add_relationship(
            Relationship(
                source=resource_id,
                relation="requires_no_path_traversal",
                target=target_node,
                metadata=(
                    ("method", check.method),
                    ("path", check.path),
                    ("endpoint_url", endpoint_url),
                    ("param", check.param),
                    ("location", check.location),
                    ("control", CONTROL_VALUE),
                    ("severity", check.severity),
                    ("source", "path_traversal_matrix_oracle"),
                ),
            )
        )
        # --- synthetic provenance evidence (mode NOT "http") --------------
        evidence_id = f"evidence:traversal-declaration:{aspect}:{endpoint_id}"
        graph.add_evidence(
            Evidence(
                id=evidence_id,
                source="path_traversal_matrix_oracle",
                data={
                    "mode": "path_traversal_matrix_declaration",
                    "method": check.method,
                    "path": check.path,
                    "param": check.param,
                    "location": check.location,
                    "control": CONTROL_VALUE,
                },
                confidence=1.0,
            )
        )

        hypothesis_id = f"hyp:traversal:{aspect}:{endpoint_id}"

        # --- declaration experiment (provenance only, never executed) -----
        graph.add_experiment(
            Experiment(
                id=f"exp:traversal-seed:{aspect}:{endpoint_id}",
                hypothesis_id=f"decl:{hypothesis_id}",
                kind="path_traversal_declaration",
                description=(
                    f"Operator path-traversal-surface declaration: probe the "
                    f"'{check.param}' parameter of {check.method} {check.path} "
                    f"({check.location}) for directory-escape file reads."
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
                capability_id="path_traversal.traversal_seed",
                action="declare_path_traversal_surface",
            )
        )

        # --- the OPEN hypothesis that drives the prove-chain --------------
        graph.add_hypothesis(
            Hypothesis(
                id=hypothesis_id,
                kind="path_traversal",
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
