"""
Seed operator-declared cookie posture into the security graph.

Mirror of :mod:`app.security_graph.posture.seed`, for the `insecure_cookie`
class. For each declared cookie expectation the seeder materialises exactly
the durable state the prove-chain needs:

  * a shared `any-client` Principal, a per-route Resource, an Action and an
    Endpoint node,
  * one explicit `requires_cookie_posture` relationship carrying the
    expectation (this is the posture the judge reads),
  * a synthetic *declaration* Evidence record (mode is NOT "http", so it can
    never be mistaken for a live observation),
  * a non-executable *declaration* Experiment carrying the probe request
    template, and
  * an OPEN `insecure_cookie` Hypothesis.

It never observes the target and never manufactures a finding — it only routes
a suspicion into the prove-chain. The deterministic judge decides the outcome
by freshly re-probing the live target and parsing the ``Set-Cookie`` it emits.
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
from .cookie_policy import CookiePolicy


# Cookie security is about what every client that hits this route receives,
# so all cookie expectations share one synthetic principal.
_ANY_CLIENT_ID = "principal:any-client"


def _join_url(target_base: str, path: str) -> str:
    if "://" in path:
        return path
    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _aspect(expectation) -> str:
    """Stable identity aspect for one expectation."""
    name = (expectation.cookie_name or "").lower() or "*"
    token = (expectation.flag or expectation.value or "").lower()
    return f"{name}:{expectation.check}:{token}"


def cookie_target(expectation) -> str:
    """Stable relationship target for one expectation."""
    return f"cookie:{_aspect(expectation)}"


def _claim(method: str, path: str, expectation) -> str:
    label = expectation.cookie_name or "session"
    check = expectation.check
    if check == "must_have_flag":
        detail = f"omits the {expectation.flag} attribute on the '{label}' cookie"
    elif check == "must_not_have_flag":
        detail = f"sets the {expectation.flag} attribute on the '{label}' cookie"
    elif check == "samesite_must_equal":
        detail = (
            f"does not set SameSite={expectation.value} on the '{label}' cookie"
        )
    else:  # samesite_must_not_equal
        detail = (
            f"sets the insecure SameSite={expectation.value} on the "
            f"'{label}' cookie"
        )
    return (
        f"Insecure cookie: {method} {path} {detail}, "
        f"violating declared cookie posture"
    )


def seed_cookie_policy(
    graph: SecurityGraph,
    policy: CookiePolicy,
    *,
    target_base: str,
) -> tuple[str, ...]:
    """
    Seed each declared cookie expectation as an OPEN `insecure_cookie`
    hypothesis.

    Returns the ids of the hypotheses seeded (skipping any expectation whose
    semantic identity is already represented in the graph).
    """

    seeded: list[str] = []

    # One shared principal for the whole cookie axis.
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
        resource_id = f"resource:cookie-posture:{resource_label}"

        graph.add_endpoint(
            Endpoint(id=endpoint_id, method=rule.method, url=url)
        )
        graph.add_resource(
            Resource(
                id=resource_id,
                type="cookie_posture_resource",
                name=resource_label,
            )
        )

        for expectation in rule.expectations:
            aspect = _aspect(expectation)
            target_node = cookie_target(expectation)

            identity = HypothesisIdentity(
                kind="insecure_cookie",
                principal_id=_ANY_CLIENT_ID,
                resource_id=resource_id,
                action=aspect,
            )

            # Idempotent: never seed the same semantic claim twice.
            if graph.find_equivalent_hypothesis(identity) is not None:
                continue

            graph.add_action(Action(name=aspect))

            # --- the explicit cookie posture edge the judge reads ---------
            graph.add_relationship(
                Relationship(
                    source=resource_id,
                    relation="requires_cookie_posture",
                    target=target_node,
                    metadata=(
                        ("cookie_name", expectation.cookie_name),
                        ("check", expectation.check),
                        ("flag", expectation.flag or ""),
                        ("value", expectation.value or ""),
                        ("severity", expectation.severity),
                        ("method", rule.method),
                        ("path", rule.path),
                        ("source", "cookie_policy_oracle"),
                    ),
                )
            )

            # --- synthetic provenance evidence (mode NOT "http") ---------
            evidence_id = (
                f"evidence:cookie-declaration:{rule.method}:"
                f"{aspect}:{endpoint_id}"
            )
            graph.add_evidence(
                Evidence(
                    id=evidence_id,
                    source="cookie_policy_oracle",
                    data={
                        "mode": "cookie_policy_declaration",
                        "method": rule.method,
                        "path": rule.path,
                        "cookie_name": expectation.cookie_name,
                        "check": expectation.check,
                        "flag": expectation.flag or "",
                        "value": expectation.value or "",
                        "url": url,
                    },
                    confidence=1.0,
                )
            )

            hypothesis_id = (
                f"hyp:insecure-cookie:{rule.method}:{aspect}:{endpoint_id}"
            )

            # --- declaration experiment (provenance only, never executed)-
            graph.add_experiment(
                Experiment(
                    id=f"exp:cookie-seed:{rule.method}:{aspect}:{endpoint_id}",
                    hypothesis_id=f"decl:{hypothesis_id}",
                    kind="cookie_declaration",
                    description=(
                        f"Operator cookie-posture declaration: {rule.method} "
                        f"{rule.path} {expectation.check} "
                        f"{expectation.flag or expectation.value} on "
                        f"'{expectation.cookie_name or '*'}'."
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
                    capability_id="insecure_cookie.cookie_seed",
                    action="declare_cookie_posture",
                )
            )

            # --- the OPEN hypothesis that drives the prove-chain ---------
            graph.add_hypothesis(
                Hypothesis(
                    id=hypothesis_id,
                    kind="insecure_cookie",
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
