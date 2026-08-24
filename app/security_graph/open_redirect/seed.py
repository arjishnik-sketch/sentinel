"""
Seed the operator-declared open-redirect matrix into the security graph.

Mirror of :mod:`app.security_graph.ssti.seed`, for the `open_redirect` class.
For each declared surface the seeder materialises exactly the durable state the
prove-chain needs:

  * a shared ``principal:any-client`` Principal, a per-parameter Resource, an
    Action and an Endpoint node,
  * one explicit ``requires_no_open_redirect`` relationship carrying the surface
    the judge/runner read (method, path, param, location) PLUS the per-hypothesis
    probe operands generated here — a random ``nonce``, the unroutable
    ``nonce_host`` / ``payload_url`` the off-origin probe uses, and the
    same-origin ``control_url`` the anchor uses — so the pure judge can read back
    the exact host that proves an attacker-controlled redirect,
  * a synthetic *declaration* Evidence record (mode is NOT "http", so it can
    never be mistaken for a live observation),
  * a non-executable *declaration* Experiment, and
  * an OPEN `open_redirect` Hypothesis.

It never observes the target and never manufactures a finding — it only routes a
declared surface into the prove-chain. The deterministic judge decides the
outcome by freshly re-probing the live target and comparing the observed
``Location`` header host to the seeded nonce host.

The nonce is generated once, at seed time, and recorded in the graph — the same
role the arithmetic operands play for SSTI. Because it is DATA in the
relationship, the remediation verifier (which copies relationships onto a scratch
graph) re-probes with the identical nonce, so the before/after differential is
measured against the same unforgeable host.
"""

from __future__ import annotations

import random
from urllib.parse import urlsplit

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
from .open_redirect_policy import (
    OpenRedirectCheck,
    OpenRedirectPolicy,
    make_nonce,
    nonce_host,
    payload_url,
)


_ANY_CLIENT = "principal:any-client"


def _join_url(target_base: str, path: str) -> str:
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _same_origin_control(endpoint_url: str) -> str:
    """The target's own origin as a same-origin redirect destination (anchor).

    Absolute and on-origin, so an absolute-URL-accepting redirector honours it
    and a safe same-origin allowlist still permits it — the legitimate baseline
    the differential's anchor must reproduce.
    """
    split = urlsplit(endpoint_url)
    scheme = split.scheme or "http"
    return f"{scheme}://{split.netloc}/"


def _aspect(check: OpenRedirectCheck) -> str:
    """Stable identity aspect for one check (unique per redirect surface)."""
    return f"{check.location}:{check.param}:{check.method}:{check.path}"


def open_redirect_target(check: OpenRedirectCheck) -> str:
    """Stable relationship target node for one check."""
    return f"open_redirect:{_aspect(check)}"


def _claim(check: OpenRedirectCheck) -> str:
    return (
        f"Open redirect: the '{check.param}' parameter of "
        f"{check.method} {check.path} ({check.location}) controls the redirect "
        "destination and can send a victim to an attacker-chosen off-origin host"
    )


def seed_open_redirect_policy(
    graph: SecurityGraph,
    policy: OpenRedirectPolicy,
    *,
    target_base: str,
    rng: random.Random | None = None,
) -> tuple[str, ...]:
    """
    Seed each declared redirect-surface check as an OPEN `open_redirect`
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
        target_node = open_redirect_target(check)

        endpoint_url = _join_url(target_base, check.path)

        resource_id = (
            f"resource:open-redirect:{check.method}:{check.path}:{check.param}"
        )
        endpoint_id = f"endpoint:{endpoint_url}"

        identity = HypothesisIdentity(
            kind="open_redirect",
            principal_id=_ANY_CLIENT,
            resource_id=resource_id,
            action=aspect,
        )

        # Idempotent: never seed the same semantic surface twice.
        if graph.find_equivalent_hypothesis(identity) is not None:
            continue

        # Generate the unforgeable probe nonce ONCE and record it. The judge reads
        # the nonce host back from the graph; it never re-derives it.
        nonce = make_nonce(rng)
        host = nonce_host(nonce)
        payload = payload_url(nonce)
        control = _same_origin_control(endpoint_url)

        graph.add_resource(
            Resource(
                id=resource_id,
                type="open_redirect_surface_resource",
                name=f"{check.method} {check.path} [{check.param}]",
            )
        )
        graph.add_endpoint(
            Endpoint(id=endpoint_id, method=check.method, url=endpoint_url)
        )
        graph.add_action(Action(name=aspect))

        # --- the explicit redirect-surface edge the judge/runner read --------
        graph.add_relationship(
            Relationship(
                source=resource_id,
                relation="requires_no_open_redirect",
                target=target_node,
                metadata=(
                    ("method", check.method),
                    ("path", check.path),
                    ("endpoint_url", endpoint_url),
                    ("param", check.param),
                    ("location", check.location),
                    ("nonce", nonce),
                    ("nonce_host", host),
                    ("payload_url", payload),
                    ("control_url", control),
                    ("severity", check.severity),
                    ("source", "open_redirect_matrix_oracle"),
                ),
            )
        )

        # --- synthetic provenance evidence (mode NOT "http") -----------------
        evidence_id = f"evidence:open-redirect-declaration:{aspect}:{endpoint_id}"
        graph.add_evidence(
            Evidence(
                id=evidence_id,
                source="open_redirect_matrix_oracle",
                data={
                    "mode": "open_redirect_matrix_declaration",
                    "method": check.method,
                    "path": check.path,
                    "param": check.param,
                    "location": check.location,
                    "nonce_host": host,
                    "payload_url": payload,
                    "control_url": control,
                },
                confidence=1.0,
            )
        )

        hypothesis_id = f"hyp:open-redirect:{aspect}:{endpoint_id}"

        # --- declaration experiment (provenance only, never executed) --------
        graph.add_experiment(
            Experiment(
                id=f"exp:open-redirect-seed:{aspect}:{endpoint_id}",
                hypothesis_id=f"decl:{hypothesis_id}",
                kind="open_redirect_declaration",
                description=(
                    f"Operator open-redirect-surface declaration: probe the "
                    f"'{check.param}' parameter of {check.method} {check.path} "
                    f"({check.location}) for an attacker-controlled redirect."
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
                capability_id="open_redirect.open_redirect_seed",
                action="declare_open_redirect_surface",
            )
        )

        # --- the OPEN hypothesis that drives the prove-chain -----------------
        graph.add_hypothesis(
            Hypothesis(
                id=hypothesis_id,
                kind="open_redirect",
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
