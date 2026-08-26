"""
Seed the operator-declared broken-authentication matrix into the graph.

Mirror of :mod:`app.security_graph.privesc.seed`. For each declared check the
seeder derives a FORGED token from the principal's genuine (live-captured) token
and materialises exactly the durable state the prove-chain needs:

  * a Principal, a per-route Resource, an Action and an Endpoint node,
  * one explicit ``requires_authentic_token`` relationship carrying the whole
    differential the judge reads (the genuine-token control headers, the
    forged-token breach headers, the protected route, the "accepted" status set,
    the forgery strategy, and whether a shape-guard can prove the fix),
  * a synthetic *declaration* Evidence record (mode is NOT "http", so it can
    never be mistaken for a live observation),
  * a non-executable *declaration* Experiment, and
  * an OPEN ``broken_auth`` Hypothesis.

To isolate the token as the SOLE authenticator, the control/breach probes carry
only an ``Authorization: Bearer`` header — never the session cookie — so a route
authenticated by cookie (not token) simply fails the control probe and the judge
returns INCONCLUSIVE rather than a false positive. A check whose forgery cannot
be derived (a non-JWT token, missing material, or an uncrackable strong secret)
is skipped: no probe is possible, so nothing is seeded and nothing is claimed.

It never observes the target and never manufactures a finding — it only routes a
declared boundary into the prove-chain. The seeder is entirely target-agnostic.
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
from .broken_auth_policy import BrokenAuthCheck, BrokenAuthPolicy, TokenLocation
from .forge import derive_forgery, strip_bearer

def _join_url(target_base: str, path: str) -> str:
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _aspect(check: BrokenAuthCheck) -> str:
    """Stable identity aspect for one check (unique per forgery+route)."""
    return f"{check.forgery}:{check.method}:{check.path}"


def broken_auth_target(check: BrokenAuthCheck) -> str:
    """Stable relationship target node for one check."""
    return f"broken_auth:{_aspect(check)}"


def _genuine_token(headers, location: TokenLocation | None = None) -> str:
    """The bare genuine token from a principal's declared location (default the
    ``Authorization: Bearer`` header). A cookie-located token (``session=<jwt>``)
    is read from the ``Cookie`` header instead — the same place the probes ride."""
    if location is not None:
        return location.extract(tuple(headers))
    for name, value in headers:
        if str(name).lower() == "authorization":
            return strip_bearer(value)
    return ""


def _claim(check: BrokenAuthCheck) -> str:
    return (
        f"Broken authentication: a forged token ({check.forgery}) is accepted at "
        f"{check.method} {check.path} where an unauthenticated caller is denied — "
        "the server does not authentically verify the token signature"
    )


def seed_broken_auth_policy(
    graph: SecurityGraph,
    policy: BrokenAuthPolicy,
    *,
    target_base: str,
) -> tuple[str, ...]:
    """
    Seed each declared check with a derivable forgery as an OPEN ``broken_auth``
    hypothesis. Returns the ids of the hypotheses seeded (skipping checks whose
    forgery cannot be derived or whose identity is already represented).
    """
    seeded: list[str] = []

    principal = policy.principal
    if principal is None:
        return ()
    location = policy.token_location
    genuine = _genuine_token(principal.headers, location)
    if not genuine:
        return ()

    success_statuses = list(policy.success_statuses)

    # The session-alive control route the genuine token legitimately owns. For a
    # VERTICAL forgery the genuine token is denied at the breach route, so the
    # control must prove the session is live against a route the principal really
    # reaches. Absent a declared control, it falls back to the breach route
    # itself (same-privilege tampering — the historical behaviour).
    control = principal.control

    for check in policy.checks:
        forge_result = derive_forgery(
            genuine,
            check.forgery,
            public_key=check.public_key,
            secret_candidates=check.secret_candidates,
            claims=check.forge_claims,
        )
        if forge_result.token is None:
            # No probe is possible without a forged token — skip, never claim.
            continue

        aspect = _aspect(check)
        target_node = broken_auth_target(check)
        breach_url = _join_url(target_base, check.path)

        principal_id = f"principal:broken_auth:{principal.name}"
        resource_id = f"resource:broken_auth:{check.method}:{check.path}"
        endpoint_id = f"endpoint:{breach_url}"

        identity = HypothesisIdentity(
            kind="broken_auth",
            principal_id=principal_id,
            resource_id=resource_id,
            action=aspect,
        )
        if graph.find_equivalent_hypothesis(identity) is not None:
            continue

        graph.add_principal(
            Principal(
                id=principal_id,
                name=principal.name,
                kind="user",
                roles=(principal.role,) if principal.role else (),
            )
        )
        graph.add_resource(
            Resource(
                id=resource_id,
                type="broken_auth_protected_route",
                name=f"{check.method} {check.path}",
            )
        )
        graph.add_endpoint(
            Endpoint(id=endpoint_id, method=check.method, url=breach_url)
        )
        graph.add_action(Action(name=aspect))

        # The token is the SOLE authenticator on both probes, carried in the
        # app's real location (Authorization header by default, or a Cookie for
        # cookie-session apps). The genuine token rides the CONTROL route (a
        # route the principal owns → session-alive), the forged token rides the
        # BREACH route. A route the token cannot reach fails the control probe
        # and the judge returns INCONCLUSIVE rather than a false positive.
        control_method = control.method if control is not None else check.method
        control_path = control.path if control is not None else check.path
        control_url = _join_url(target_base, control_path)

        control_headers = (location.header_for(genuine),)
        breach_headers = (location.header_for(forge_result.token),)
        control_json = json.dumps([list(pair) for pair in control_headers])
        breach_json = json.dumps([list(pair) for pair in breach_headers])
        success_json = json.dumps(success_statuses)

        # --- the explicit token-authentication edge the judge reads --------
        graph.add_relationship(
            Relationship(
                source=resource_id,
                relation="requires_authentic_token",
                target=target_node,
                metadata=(
                    ("forgery", check.forgery),
                    ("guard_provable", "true" if forge_result.guard_provable else "false"),
                    ("control_headers", control_json),
                    ("breach_headers", breach_json),
                    ("control_method", control_method),
                    ("control_url", control_url),
                    ("control_path", control_path),
                    ("breach_method", check.method),
                    ("breach_url", breach_url),
                    ("breach_path", check.path),
                    ("success_statuses", success_json),
                    ("severity", check.severity),
                    ("source", "broken_auth_matrix_oracle"),
                ),
            )
        )

        # --- synthetic provenance evidence (mode NOT "http") --------------
        evidence_id = f"evidence:broken-auth-declaration:{aspect}:{endpoint_id}"
        graph.add_evidence(
            Evidence(
                id=evidence_id,
                source="broken_auth_matrix_oracle",
                data={
                    "mode": "broken_auth_matrix_declaration",
                    "forgery": check.forgery,
                    "guard_provable": forge_result.guard_provable,
                    "breach_method": check.method,
                    "breach_url": breach_url,
                    "note": forge_result.note,
                },
                confidence=1.0,
            )
        )

        hypothesis_id = f"hyp:broken-auth:{aspect}:{endpoint_id}"

        # --- declaration experiment (provenance only, never executed) -----
        graph.add_experiment(
            Experiment(
                id=f"exp:broken-auth-seed:{aspect}:{endpoint_id}",
                hypothesis_id=f"decl:{hypothesis_id}",
                kind="broken_auth_declaration",
                description=(
                    f"Operator token-authentication declaration: {check.method} "
                    f"{check.path} MUST reject a forged token ({check.forgery})."
                ),
                status="DECLARED",
                evidence_ids=(evidence_id,),
                request=HttpRequestSpec(
                    method=check.method,
                    url=breach_url,
                    headers=breach_headers,
                    body=None,
                    principal_id=principal_id,
                    resource_id=resource_id,
                    action=aspect,
                ),
                capability_id="broken_auth.broken_auth_seed",
                action="declare_token_authentication_boundary",
            )
        )

        # --- the OPEN hypothesis that drives the prove-chain --------------
        graph.add_hypothesis(
            Hypothesis(
                id=hypothesis_id,
                kind="broken_auth",
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


