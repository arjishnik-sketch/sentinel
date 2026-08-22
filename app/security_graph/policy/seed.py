"""
Seed operator-declared access policy into the security graph.

This is the bridge that closes Sentinel's *bootstrap gap*: nothing in the
autonomous flow otherwise seeds a principal, an explicit allow/deny policy
edge, and a matching `authorization_policy_violation` hypothesis, so the
deterministic judge never fired.

For each declared rule the seeder materialises exactly the durable state
the existing prove-chain requires and nothing more:

  * a Principal / Resource / Action / Endpoint node,
  * one explicit `can_access` / `cannot_access` relationship carrying the
    action and expected protocol statuses (this is the policy the judge
    reads),
  * a synthetic *policy-declaration* Evidence record (mode is NOT "http",
    so it can never be mistaken for an authorization observation),
  * a non-executable *declaration* Experiment that carries the request
    template (method / url / headers) the validation planner reuses, and
  * an OPEN `authorization_policy_violation` Hypothesis.

What this does NOT do — by design:

  * It never observes the target, never sets an authorization outcome,
    and never creates an AuthorizationObservation. The fresh observation
    is produced only when the live probe runs inside a research cycle.
  * It never manufactures a finding. Seeding merely *routes a suspicion*
    into the prove-chain. The deterministic judge decides the outcome by
    freshly re-probing the live target: a finding materialises only when
    observed behaviour contradicts the declared policy. If the target
    honours the policy, the judge returns DISPROVED and nothing is
    produced.

The declaration Experiment is attributed to a distinct `decl:` id (not the
hypothesis id) and carries a non-COMPLETED status, so it is never counted
as a research attempt against the hypothesis — the first real research
cycle sees a pristine frontier.
"""

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
from .access_policy import AccessPolicy


def _endpoint_id(url: str) -> str:
    # Matches recon/ingest.py so a policy endpoint aligns with any the
    # crawler also discovered, and so the decision board can recover the
    # probed URL from the hypothesis id.
    return f"endpoint:{url}"


def _join_url(target_base: str, path: str) -> str:
    """Resolve a policy `path` against the engagement target base.

    An absolute URL is used as-is (the pre-connection scope guard still
    refuses anything off the engagement host). A bare path is joined onto
    the target so declared rules stay in-scope by construction.
    """

    if "://" in path:
        return path

    base = target_base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path

    return base + path


def seed_access_policy(
    graph: SecurityGraph,
    policy: AccessPolicy,
    *,
    target_base: str,
) -> tuple[str, ...]:
    """
    Seed each declared policy rule as an OPEN policy-violation hypothesis.

    Returns the ids of the hypotheses seeded (skipping any rule whose
    semantic identity is already represented in the graph).
    """

    seeded: list[str] = []

    for rule in policy.rules:
        principal = policy.principal(rule.principal)

        principal_id = f"principal:{principal.name}"
        url = _join_url(target_base, rule.path)
        endpoint_id = _endpoint_id(url)
        resource_label = rule.resource or rule.path
        resource_id = f"resource:{resource_label}"
        action = rule.action
        deny = rule.decision == "deny"
        relation = "cannot_access" if deny else "can_access"

        identity = HypothesisIdentity(
            kind="authorization_policy_violation",
            principal_id=principal_id,
            resource_id=resource_id,
            action=action,
        )

        # Idempotent: never seed the same semantic claim twice.
        if graph.find_equivalent_hypothesis(identity) is not None:
            continue

        # --- surface nodes --------------------------------------------
        graph.add_principal(
            Principal(
                id=principal_id,
                name=principal.name,
                kind=principal.kind,
                roles=principal.roles,
            )
        )
        graph.add_resource(
            Resource(
                id=resource_id,
                type="policy_resource",
                name=resource_label,
            )
        )
        graph.add_action(Action(name=action))
        graph.add_endpoint(
            Endpoint(
                id=endpoint_id,
                method=rule.method,
                url=url,
            )
        )

        # --- the explicit policy edge the judge reads -----------------
        graph.add_relationship(
            Relationship(
                source=principal_id,
                relation=relation,
                target=resource_id,
                metadata=(
                    ("actions", (action,)),
                    ("expected_statuses", tuple(rule.expected_statuses)),
                    ("source", "access_policy_oracle"),
                ),
            )
        )

        # --- synthetic provenance evidence ----------------------------
        # mode is deliberately NOT "http" and carries no "allowed" key,
        # so no code path can ever derive an authorization observation
        # from it. It exists only to anchor the hypothesis to its
        # originating (declaration) experiment.
        evidence_id = (
            f"evidence:policy-declaration:{principal.name}:"
            f"{rule.method}:{action}:{endpoint_id}"
        )
        graph.add_evidence(
            Evidence(
                id=evidence_id,
                source="access_policy_oracle",
                data={
                    "mode": "policy_declaration",
                    "principal": principal.name,
                    "method": rule.method,
                    "path": rule.path,
                    "action": action,
                    "decision": rule.decision,
                    "url": url,
                },
                confidence=1.0,
            )
        )

        hypothesis_id = (
            f"hyp:policy-violation:{principal.name}:"
            f"{rule.method}:{action}:{endpoint_id}"
        )

        # --- declaration experiment (provenance only, never executed) -
        # Distinct hypothesis id (`decl:`) + non-COMPLETED status keep it
        # from counting as a research attempt on the hypothesis, so the
        # first validation cycle sees an untouched frontier. The planner
        # finds it purely by shared evidence, not by hypothesis id.
        graph.add_experiment(
            Experiment(
                id=(
                    f"exp:policy-seed:{principal.name}:"
                    f"{rule.method}:{action}:{endpoint_id}"
                ),
                hypothesis_id=f"decl:{hypothesis_id}",
                kind="authorization_policy_declaration",
                description=(
                    f"Operator policy declaration: {principal.name} "
                    f"{relation} {action} {resource_label}."
                ),
                status="DECLARED",
                evidence_ids=(evidence_id,),
                request=HttpRequestSpec(
                    method=rule.method,
                    url=url,
                    headers=principal.headers,
                    body=None,
                    principal_id=principal_id,
                    resource_id=resource_id,
                    action=action,
                ),
                capability_id="authorization.policy_seed",
                action="declare_policy",
            )
        )

        # --- the OPEN hypothesis that drives the prove-chain ----------
        if deny:
            claim = (
                f"Broken access control: {principal.name} can {action} "
                f"{resource_label} despite an explicit deny policy"
            )
        else:
            claim = (
                f"Authorization regression: {principal.name} is denied "
                f"{action} on {resource_label} despite an explicit "
                f"allow policy"
            )

        graph.add_hypothesis(
            Hypothesis(
                id=hypothesis_id,
                kind="authorization_policy_violation",
                claim=claim,
                confidence=0.90,
                evidence_ids=(evidence_id,),
                identity=identity,
                source_ids=(evidence_id,),
                status="OPEN",
            )
        )

        seeded.append(hypothesis_id)

    return tuple(seeded)
