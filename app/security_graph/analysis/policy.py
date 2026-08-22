from dataclasses import dataclass

from ..graph import SecurityGraph
from ..models import AuthorizationObservation
from ..policy.authorization import authorization_policy


@dataclass(frozen=True)
class AuthorizationPolicyContradiction:
    observation_id: str
    principal_id: str
    resource_id: str
    action: str
    expected: bool
    observed: bool
    evidence_ids: tuple[str, ...] = ()


def find_authorization_policy_contradictions(
    graph: SecurityGraph,
) -> list[AuthorizationPolicyContradiction]:
    contradictions: list[AuthorizationPolicyContradiction] = []

    observations = sorted(
        graph.authorization_observations.values(),
        key=lambda item: item.id,
    )

    for observation in observations:
        policy = authorization_policy(
            graph,
            principal_id=observation.principal_id,
            resource_id=observation.resource_id,
            action=observation.action,
        )

        if policy is None:
            continue

        authorization_contradiction = (
            observation.allowed is not None
            and policy.allowed != observation.allowed
        )

        protocol_contradiction = (
            bool(policy.expected_statuses)
            and observation.status_code is not None
            and observation.status_code
            not in policy.expected_statuses
        )

        if not authorization_contradiction and not protocol_contradiction:
            continue

        contradictions.append(
            AuthorizationPolicyContradiction(
                observation_id=observation.id,
                principal_id=observation.principal_id,
                resource_id=observation.resource_id,
                action=observation.action,
                expected=policy.allowed,
                observed=observation.allowed,
                evidence_ids=observation.evidence_ids,
            )
        )

    return contradictions
