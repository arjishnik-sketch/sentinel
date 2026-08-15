from ..models import AuthorizationObservation, Evidence


def authorization_decision_from_evidence(
    evidence: Evidence,
) -> bool | None:
    """
    Interpret an HTTP authorization result only when the experiment
    explicitly supplied expected authorization statuses.

    Returns:
      True  -> response matched an explicitly allowed status.
      False -> response matched an explicitly denied status.
      None  -> no defensible authorization conclusion.
    """
    data = evidence.data

    if data.get("mode") != "http":
        return None

    status_code = data.get("status_code")

    if not isinstance(status_code, int):
        return None

    expected_statuses = data.get("expected_statuses")

    if not isinstance(expected_statuses, (tuple, list)):
        return None

    if not expected_statuses:
        return None

    if status_code not in expected_statuses:
        return None

    expected_outcome = data.get("expected_outcome")

    if expected_outcome == "allow":
        return True

    if expected_outcome == "deny":
        return False

    return None


def authorization_observation_from_evidence(
    evidence: Evidence,
) -> AuthorizationObservation | None:
    """
    Convert explicitly observed authorization evidence into
    an AuthorizationObservation.

    Evidence must explicitly contain:
      principal_id
      resource_id
      action
      allowed

    Dry-run evidence and incomplete evidence are ignored.
    """

    data = evidence.data

    if data.get("mode") == "dry_run":
        return None

    principal_id = data.get("principal_id")
    resource_id = data.get("resource_id")
    action = data.get("action")

    if not isinstance(principal_id, str):
        return None

    if not isinstance(resource_id, str):
        return None

    if not isinstance(action, str):
        return None

    if data.get("mode") == "http":
        allowed = authorization_decision_from_evidence(evidence)

        if allowed is None:
            return None

    else:
        if "allowed" not in data:
            return None

        allowed = data["allowed"]

        if not isinstance(allowed, bool):
            return None

    if not isinstance(principal_id, str):
        return None

    if not isinstance(resource_id, str):
        return None

    if not isinstance(action, str):
        return None

    if not isinstance(allowed, bool):
        return None

    status_code = data.get("status_code")

    if status_code is not None and not isinstance(
        status_code,
        int,
    ):
        return None

    return AuthorizationObservation(
        id=f"authobs:{evidence.id}",
        principal_id=principal_id,
        resource_id=resource_id,
        action=action,
        allowed=allowed,
        status_code=status_code,
        endpoint_id=data.get("endpoint_id"),
        evidence_ids=(evidence.id,),
    )
