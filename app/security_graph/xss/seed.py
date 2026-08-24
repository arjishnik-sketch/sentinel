"""
Seed the operator-declared reflected-XSS matrix into the security graph.

Mirror of :mod:`app.security_graph.ssti.seed`, for the `xss` class. For each
declared surface the seeder materialises exactly the durable state the
prove-chain needs:

  * a shared ``principal:any-client`` Principal, a per-parameter Resource, an
    Action and an Endpoint node,
  * one explicit ``requires_no_reflected_xss`` relationship carrying the surface
    the judge/runner read (method, path, param, location) PLUS the per-hypothesis
    benign reflection *marker* generated here — a random alphanumeric nonce the
    control probe sends bare and every payload wraps in active markup — so the
    pure judge can read back the exact marker that anchors the differential,
  * a synthetic *declaration* Evidence record (mode is NOT "http", so it can
    never be mistaken for a live observation),
  * a non-executable *declaration* Experiment carrying the control probe
    template, and
  * an OPEN `xss` Hypothesis.

It never observes the target and never manufactures a finding — it only routes a
declared surface into the prove-chain. The deterministic judge decides the
outcome by freshly re-probing the live target with the reflection differential
and comparing the observed response bodies.

The marker is generated once, at seed time, and recorded in the graph — the same
role the arithmetic operands play for SSTI. Because it is DATA in the
relationship, the remediation verifier (which copies relationships onto a scratch
graph) re-probes with the identical marker, so the before/after differential is
measured against the same expected reflection.
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
from .xss_policy import XSSCheck, XSSPolicy, make_marker


_ANY_CLIENT = "principal:any-client"


def _join_url(target_base: str, path: str) -> str:
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _aspect(check: XSSCheck) -> str:
    """Stable identity aspect for one check (unique per reflective surface)."""
    return f"{check.location}:{check.param}:{check.method}:{check.path}"


def xss_target(check: XSSCheck) -> str:
    """Stable relationship target node for one check."""
    return f"xss:{_aspect(check)}"


def _claim(check: XSSCheck) -> str:
    return (
        f"Reflected cross-site scripting: the '{check.param}' parameter of "
        f"{check.method} {check.path} ({check.location}) is reflected into the "
        "response with its HTML markup UN-escaped — attacker markup executes in "
        "the victim's browser"
    )


def seed_xss_policy(
    graph: SecurityGraph,
    policy: XSSPolicy,
    *,
    target_base: str,
    rng: random.Random | None = None,
) -> tuple[str, ...]:
    """
    Seed each declared reflected-XSS-surface check as an OPEN `xss` hypothesis.

    Returns the ids of the hypotheses seeded (skipping any check whose semantic
    identity is already represented in the graph). ``rng`` is accepted only so
    tests can pin the marker deterministically; production uses fresh entropy.
    """

    seeded: list[str] = []

    graph.add_principal(
        Principal(id=_ANY_CLIENT, name="any client", kind="client", roles=())
    )

    for check in policy.checks:
        aspect = _aspect(check)
        target_node = xss_target(check)

        endpoint_url = _join_url(target_base, check.path)

        resource_id = (
            f"resource:xss:{check.method}:{check.path}:{check.param}"
        )
        endpoint_id = f"endpoint:{endpoint_url}"

        identity = HypothesisIdentity(
            kind="xss",
            principal_id=_ANY_CLIENT,
            resource_id=resource_id,
            action=aspect,
        )

        # Idempotent: never seed the same semantic surface twice.
        if graph.find_equivalent_hypothesis(identity) is not None:
            continue

        # Generate the benign reflection marker ONCE and record it. The judge
        # reads it back from the graph; it never re-derives it.
        marker = make_marker(rng)

        graph.add_resource(
            Resource(
                id=resource_id,
                type="xss_surface_resource",
                name=f"{check.method} {check.path} [{check.param}]",
            )
        )
        graph.add_endpoint(
            Endpoint(id=endpoint_id, method=check.method, url=endpoint_url)
        )
        graph.add_action(Action(name=aspect))

        # --- the explicit reflected-XSS-surface edge the judge/runner read
        graph.add_relationship(
            Relationship(
                source=resource_id,
                relation="requires_no_reflected_xss",
                target=target_node,
                metadata=(
                    ("method", check.method),
                    ("path", check.path),
                    ("endpoint_url", endpoint_url),
                    ("param", check.param),
                    ("location", check.location),
                    ("marker", marker),
                    ("severity", check.severity),
                    ("source", "xss_matrix_oracle"),
                ),
            )
        )

        # --- synthetic provenance evidence (mode NOT "http") --------------
        evidence_id = f"evidence:xss-declaration:{aspect}:{endpoint_id}"
        graph.add_evidence(
            Evidence(
                id=evidence_id,
                source="xss_matrix_oracle",
                data={
                    "mode": "xss_matrix_declaration",
                    "method": check.method,
                    "path": check.path,
                    "param": check.param,
                    "location": check.location,
                    "marker": marker,
                },
                confidence=1.0,
            )
        )

        hypothesis_id = f"hyp:xss:{aspect}:{endpoint_id}"

        # --- declaration experiment (provenance only, never executed) -----
        graph.add_experiment(
            Experiment(
                id=f"exp:xss-seed:{aspect}:{endpoint_id}",
                hypothesis_id=f"decl:{hypothesis_id}",
                kind="xss_declaration",
                description=(
                    f"Operator reflected-XSS-surface declaration: probe the "
                    f"'{check.param}' parameter of {check.method} {check.path} "
                    f"({check.location}) for un-escaped reflected markup."
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
                capability_id="xss.xss_seed",
                action="declare_xss_surface",
            )
        )

        # --- the OPEN hypothesis that drives the prove-chain --------------
        graph.add_hypothesis(
            Hypothesis(
                id=hypothesis_id,
                kind="xss",
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
