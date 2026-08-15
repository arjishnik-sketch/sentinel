from ..models import AuthorizationObservation, Evidence


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

    required = (
        "principal_id",
        "resource_id",
        "action",
        "allowed",
    )

    if any(key not in data for key in required):
        return None

    principal_id = data["principal_id"]
    resource_id = data["resource_id"]
    action = data["action"]
    allowed = data["allowed"]

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
