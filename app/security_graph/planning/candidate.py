from ..models import Experiment, Hypothesis


def plan_authorization_candidate(
    hypothesis: Hypothesis,
    *,
    principal_id: str,
) -> Experiment:
    if hypothesis.kind != "authorization_candidate":
        raise ValueError(
            "Candidate planner requires an "
            "authorization_candidate hypothesis."
        )

    if hypothesis.status != "OPEN":
        raise ValueError(
            "Only OPEN hypotheses can be investigated."
        )

    if not principal_id.strip():
        raise ValueError(
            "principal_id cannot be empty."
        )

    return Experiment(
        id=(
            f"exp:auth-candidate:"
            f"{hypothesis.id}:"
            f"{principal_id}"
        ),
        hypothesis_id=hypothesis.id,
        kind="authorization_candidate_check",
        description=(
            "Collect authorization behavior for the "
            f"candidate hypothesis using principal "
            f"{principal_id}."
        ),
        status="PLANNED",
    )
