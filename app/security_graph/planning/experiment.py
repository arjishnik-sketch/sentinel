from ..models import Experiment, Hypothesis


def plan_authorization_recheck(
    hypothesis: Hypothesis,
    *,
    resource_id: str,
    action: str,
    principal_id: str,
) -> Experiment:
    if hypothesis.kind != "authorization_differential":
        raise ValueError(
            "Authorization recheck requires an "
            "authorization_differential hypothesis."
        )

    if hypothesis.status != "OPEN":
        raise ValueError(
            "Only OPEN hypotheses can be planned."
        )

    if not resource_id.strip():
        raise ValueError("resource_id cannot be empty.")

    if not action.strip():
        raise ValueError("action cannot be empty.")

    if not principal_id.strip():
        raise ValueError("principal_id cannot be empty.")

    return Experiment(
        id=(
            f"exp:auth-recheck:"
            f"{resource_id}:"
            f"{action}:"
            f"{principal_id}"
        ),
        hypothesis_id=hypothesis.id,
        kind="authorization_recheck",
        description=(
            f"Verify {action} access to {resource_id} "
            f"using principal {principal_id}."
        ),
        status="PLANNED",
    )
