from dataclasses import dataclass

from ..graph import SecurityGraph


@dataclass(frozen=True)
class AuthorizationPolicy:
    allowed: bool
    expected_statuses: tuple[int, ...] = ()


def _action_matches(relationship, action: str) -> bool:
    metadata = dict(relationship.metadata)

    return metadata.get("action") == action


def authorization_expectation(
    graph: SecurityGraph,
    *,
    principal_id: str,
    resource_id: str,
    action: str,
) -> bool | None:
    """
    Return an authorization expectation only from explicit graph policy.

    True  -> explicit can_access relationship exists.
    False -> explicit cannot_access relationship exists.
    None  -> insufficient or contradictory policy evidence.

    Policy relationships must explicitly identify the action through
    relationship metadata. No role, name, proximity, or HTTP behavior
    is inferred here.
    """
    if not principal_id.strip():
        raise ValueError("principal_id cannot be empty.")

    if not resource_id.strip():
        raise ValueError("resource_id cannot be empty.")

    if not action.strip():
        raise ValueError("action cannot be empty.")

    allow = False
    deny = False

    for relationship in graph.relationships:
        if relationship.source != principal_id:
            continue

        if relationship.target != resource_id:
            continue

        if not _action_matches(relationship, action):
            continue

        if relationship.relation == "can_access":
            allow = True

        elif relationship.relation == "cannot_access":
            deny = True

    if allow and deny:
        return None

    if allow:
        return True

    if deny:
        return False

    return None


def authorization_policy(
    graph: SecurityGraph,
    *,
    principal_id: str,
    resource_id: str,
    action: str,
) -> AuthorizationPolicy | None:
    """
    Return explicit authorization policy for one principal/resource/action.

    The authorization outcome comes from the relationship type.
    HTTP status expectations are optional metadata and are never inferred.

    Returns None when policy is absent or contradictory.
    """
    if not principal_id.strip():
        raise ValueError("principal_id cannot be empty.")

    if not resource_id.strip():
        raise ValueError("resource_id cannot be empty.")

    if not action.strip():
        raise ValueError("action cannot be empty.")

    allow_policy = []
    deny_policy = []

    for relationship in graph.relationships:
        if relationship.source != principal_id:
            continue

        if relationship.target != resource_id:
            continue

        if not _action_matches(relationship, action):
            continue

        metadata = dict(relationship.metadata)

        raw_statuses = metadata.get("expected_statuses", ())

        if isinstance(raw_statuses, int):
            statuses = (raw_statuses,)
        elif isinstance(raw_statuses, (tuple, list)):
            statuses = tuple(
                value
                for value in raw_statuses
                if isinstance(value, int)
                and 100 <= value <= 599
            )
        else:
            statuses = ()

        policy = AuthorizationPolicy(
            allowed=relationship.relation == "can_access",
            expected_statuses=statuses,
        )

        if relationship.relation == "can_access":
            allow_policy.append(policy)

        elif relationship.relation == "cannot_access":
            deny_policy.append(policy)

    if allow_policy and deny_policy:
        return None

    policies = allow_policy or deny_policy

    if not policies:
        return None

    # Multiple identical policy relationships are harmless.
    # Conflicting protocol expectations are not.
    status_sets = {
        policy.expected_statuses
        for policy in policies
    }

    if len(status_sets) > 1:
        return None

    return policies[0]
