"""
Seed the operator-declared CORS matrix into the security graph.

Mirror of :mod:`app.security_graph.open_redirect.seed`, for the `cors_misconfig`
class. For each declared surface the seeder materialises exactly the durable
state the prove-chain needs:

  * a shared ``principal:any-client`` Principal, a per-surface Resource, an
    Action and an Endpoint node,
  * one explicit ``requires_safe_cors`` relationship carrying the surface the
    judge/runner read (method, path, endpoint_url) PLUS the per-hypothesis probe
    operand generated here — a random ``nonce`` and the unroutable
    ``nonce_origin`` the payload probe sends as its ``Origin`` header — so the
    pure judge can read back the exact origin that proves an origin-reflecting
    CORS policy,
  * a synthetic *declaration* Evidence record (mode is NOT "http", so it can
    never be mistaken for a live observation),
  * a non-executable *declaration* Experiment, and
  * an OPEN `cors_misconfig` Hypothesis.

It never observes the target and never manufactures a finding — it only routes a
declared surface into the prove-chain. The deterministic judge decides the
outcome by freshly re-probing the live target and comparing the observed
``Access-Control-Allow-Origin`` to the seeded nonce origin.

The nonce is generated once, at seed time, and recorded in the graph. Because it
is DATA in the relationship, the remediation verifier (which copies relationships
onto a scratch graph) re-probes with the identical nonce, so the before/after
differential is measured against the same unforgeable origin.
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
from .cors_policy import (
    CorsCheck,
    CorsPolicy,
    make_nonce,
    nonce_host,
    nonce_origin,
)


_ANY_CLIENT = "principal:any-client"


def _join_url(target_base: str, path: str) -> str:
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _aspect(check: CorsCheck) -> str:
    """Stable identity aspect for one check (unique per cross-origin surface)."""
    return f"{check.method}:{check.path}"


def cors_target(check: CorsCheck) -> str:
    """Stable relationship target node for one check."""
    return f"cors:{_aspect(check)}"


def _claim(check: CorsCheck) -> str:
    return (
        f"CORS misconfiguration: {check.method} {check.path} reflects an "
        "arbitrary attacker Origin in Access-Control-Allow-Origin and allows "
        "credentials, permitting a credentialed cross-origin read"
    )
# __APPEND2__


def seed_cors_policy(
    graph: SecurityGraph,
    policy: CorsPolicy,
    *,
    target_base: str,
    rng: random.Random | None = None,
) -> tuple[str, ...]:
    """
    Seed each declared cross-origin-surface check as an OPEN `cors_misconfig`
    hypothesis.

    Returns the ids of the hypotheses seeded (skipping any check whose semantic
    identity is already represented in the graph). ``rng`` is accepted only so
    tests can pin the nonce deterministically; production uses fresh entropy.
    """

    seeded: list[str] = []

    graph.add_principal(
        Principal(id=_ANY_CLIENT, name="any client", kind="client", roles=())
    )

    for check in policy.checks:
        aspect = _aspect(check)
        target_node = cors_target(check)

        endpoint_url = _join_url(target_base, check.path)

        resource_id = f"resource:cors-posture:{check.method}:{check.path}"
        endpoint_id = f"endpoint:{endpoint_url}"

        identity = HypothesisIdentity(
            kind="cors_misconfig",
            principal_id=_ANY_CLIENT,
            resource_id=resource_id,
            action=aspect,
        )

        # Idempotent: never seed the same semantic surface twice.
        if graph.find_equivalent_hypothesis(identity) is not None:
            continue

        # Generate the unforgeable probe nonce ONCE and record it. The judge reads
        # the nonce origin back from the graph; it never re-derives it.
        nonce = make_nonce(rng)
        host = nonce_host(nonce)
        origin = nonce_origin(nonce)
# __APPEND3__

        graph.add_resource(
            Resource(
                id=resource_id,
                type="cors_posture_resource",
                name=f"{check.method} {check.path} [cors]",
            )
        )
        graph.add_endpoint(
            Endpoint(id=endpoint_id, method=check.method, url=endpoint_url)
        )
        graph.add_action(Action(name=aspect))

        # --- the explicit cross-origin-surface edge the judge/runner read ----
        graph.add_relationship(
            Relationship(
                source=resource_id,
                relation="requires_safe_cors",
                target=target_node,
                metadata=(
                    ("method", check.method),
                    ("path", check.path),
                    ("endpoint_url", endpoint_url),
                    ("nonce", nonce),
                    ("nonce_host", host),
                    ("nonce_origin", origin),
                    ("severity", check.severity),
                    ("source", "cors_matrix_oracle"),
                ),
            )
        )

        # --- synthetic provenance evidence (mode NOT "http") -----------------
        evidence_id = f"evidence:cors-declaration:{aspect}:{endpoint_id}"
        graph.add_evidence(
            Evidence(
                id=evidence_id,
                source="cors_matrix_oracle",
                data={
                    "mode": "cors_matrix_declaration",
                    "method": check.method,
                    "path": check.path,
                    "nonce_host": host,
                    "nonce_origin": origin,
                },
                confidence=1.0,
            )
        )

        hypothesis_id = f"hyp:cors:{aspect}:{endpoint_id}"
# __APPEND4__

        # --- declaration experiment (provenance only, never executed) --------
        graph.add_experiment(
            Experiment(
                id=f"exp:cors-seed:{aspect}:{endpoint_id}",
                hypothesis_id=f"decl:{hypothesis_id}",
                kind="cors_declaration",
                description=(
                    f"Operator cross-origin-surface declaration: probe "
                    f"{check.method} {check.path} for an origin-reflecting, "
                    "credentialed CORS policy."
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
                capability_id="cors.cors_seed",
                action="declare_cors_surface",
            )
        )

        # --- the OPEN hypothesis that drives the prove-chain -----------------
        graph.add_hypothesis(
            Hypothesis(
                id=hypothesis_id,
                kind="cors_misconfig",
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




