"""
Seed the operator-declared SSRF matrix into the security graph.

Mirror of :mod:`app.security_graph.open_redirect.seed`, for the `ssrf` class.
For each declared fetch-surface the seeder materialises exactly the durable state
the prove-chain needs:

  * a shared ``principal:any-client`` Principal, a per-parameter Resource, an
    Action and an Endpoint node,
  * one explicit ``requires_no_ssrf`` relationship carrying the surface the
    judge/runner read (method, path, param, location, severity),
  * a synthetic *declaration* Evidence record (mode is NOT "http", so it can
    never be mistaken for a live observation),
  * a non-executable *declaration* Experiment, and
  * an OPEN `ssrf` Hypothesis.

Unlike the open-redirect seed, NO probe operand is generated here. SSRF is proven
by an out-of-band callback to Sentinel's OWN loopback collaborator, whose base
URL and per-probe nonces are *runtime* objects — a fresh nonce is minted for every
probe (including a fresh one for the after-remediation re-probe, so a stateful
collaborator cannot leak a stale hit across the differential). The seed therefore
records only the durable SURFACE; the runner injects the collaborator URL + nonce
at probe time and writes the recorded hit as ``ssrf_callback`` evidence the pure
judge reads back.

It never observes the target and never manufactures a finding — it only routes a
declared surface into the prove-chain.
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
from .ssrf_policy import SsrfCheck, SsrfPolicy


_ANY_CLIENT = "principal:any-client"


def _join_url(target_base: str, path: str) -> str:
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _aspect(check: SsrfCheck) -> str:
    """Stable identity aspect for one check (unique per fetch surface)."""
    return f"{check.location}:{check.param}:{check.method}:{check.path}"


def ssrf_target(check: SsrfCheck) -> str:
    """Stable relationship target node for one check."""
    return f"ssrf:{_aspect(check)}"


def _claim(check: SsrfCheck) -> str:
    return (
        f"SSRF: the '{check.param}' parameter of "
        f"{check.method} {check.path} ({check.location}) is fetched server-side "
        "and can be coerced into requesting an attacker-chosen URL"
    )


# __APPEND__


def seed_ssrf_policy(
    graph: SecurityGraph,
    policy: SsrfPolicy,
    *,
    target_base: str,
    rng: random.Random | None = None,
) -> tuple[str, ...]:
    """
    Seed each declared fetch-surface check as an OPEN `ssrf` hypothesis.

    Returns the ids of the hypotheses seeded (skipping any check whose semantic
    identity is already represented in the graph). ``rng`` is accepted only for
    signature parity with the sibling seeders; SSRF mints its nonces at probe
    time, so the seed uses no randomness.
    """

    seeded: list[str] = []

    graph.add_principal(
        Principal(id=_ANY_CLIENT, name="any client", kind="client", roles=())
    )

    for check in policy.checks:
        aspect = _aspect(check)
        target_node = ssrf_target(check)

        endpoint_url = _join_url(target_base, check.path)

        resource_id = f"resource:ssrf:{check.method}:{check.path}:{check.param}"
        endpoint_id = f"endpoint:{endpoint_url}"

        identity = HypothesisIdentity(
            kind="ssrf",
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
                type="ssrf_surface_resource",
                name=f"{check.method} {check.path} [{check.param}]",
            )
        )
        graph.add_endpoint(
            Endpoint(id=endpoint_id, method=check.method, url=endpoint_url)
        )
        graph.add_action(Action(name=aspect))

        # --- the explicit fetch-surface edge the judge/runner read -----------
        graph.add_relationship(
            Relationship(
                source=resource_id,
                relation="requires_no_ssrf",
                target=target_node,
                metadata=(
                    ("method", check.method),
                    ("path", check.path),
                    ("endpoint_url", endpoint_url),
                    ("param", check.param),
                    ("location", check.location),
                    ("severity", check.severity),
                    ("source", "ssrf_matrix_oracle"),
                ),
            )
        )

        # --- synthetic provenance evidence (mode NOT "http") -----------------
        evidence_id = f"evidence:ssrf-declaration:{aspect}:{endpoint_id}"
        graph.add_evidence(
            Evidence(
                id=evidence_id,
                source="ssrf_matrix_oracle",
                data={
                    "mode": "ssrf_matrix_declaration",
                    "method": check.method,
                    "path": check.path,
                    "param": check.param,
                    "location": check.location,
                },
                confidence=1.0,
            )
        )

        hypothesis_id = f"hyp:ssrf:{aspect}:{endpoint_id}"

        # --- declaration experiment (provenance only, never executed) --------
        graph.add_experiment(
            Experiment(
                id=f"exp:ssrf-seed:{aspect}:{endpoint_id}",
                hypothesis_id=f"decl:{hypothesis_id}",
                kind="ssrf_declaration",
                description=(
                    f"Operator SSRF-surface declaration: probe the "
                    f"'{check.param}' parameter of {check.method} {check.path} "
                    f"({check.location}) for a coercible server-side fetch."
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
                capability_id="ssrf.ssrf_seed",
                action="declare_ssrf_surface",
            )
        )

        # --- the OPEN hypothesis that drives the prove-chain -----------------
        graph.add_hypothesis(
            Hypothesis(
                id=hypothesis_id,
                kind="ssrf",
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
