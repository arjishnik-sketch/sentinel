from ..graph import SecurityGraph
from ..models import Experiment, HttpRequestSpec, Hypothesis
from ..policy.authorization import authorization_policy


def _find_originating_experiment(
    graph: SecurityGraph,
    evidence_ids: tuple[str, ...],
) -> Experiment | None:
    """Find the experiment that produced the hypothesis evidence."""

    wanted = set(evidence_ids)

    if not wanted:
        return None

    candidates = []

    for experiment in graph.experiments.values():
        if wanted.intersection(experiment.evidence_ids):
            candidates.append(experiment)

    if not candidates:
        return None

    # Deterministic selection. A hypothesis should normally point
    # to one originating experiment, but ambiguity must not become
    # an invented provenance relationship.
    candidates.sort(key=lambda item: item.id)

    if len(candidates) > 1:
        first_ids = set(candidates[0].evidence_ids)
        if not wanted.intersection(first_ids):
            return None

    return candidates[0]


def plan_authorization_policy_validation(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> Experiment | None:
    """
    Create a fresh HTTP validation experiment for a policy-violation
    hypothesis using only durable request provenance.

    No URL, identity, credentials, method, body, or expected behavior
    is inferred.
    """

    if hypothesis.kind != "authorization_policy_violation":
        raise ValueError(
            "Validation planner requires an "
            "authorization_policy_violation hypothesis."
        )

    if hypothesis.status != "OPEN":
        raise ValueError(
            "Only OPEN hypotheses can be validated."
        )

    originating = _find_originating_experiment(
        graph,
        hypothesis.evidence_ids,
    )

    if originating is None:
        return None

    request = originating.request

    if request is None:
        return None

    if (
        request.principal_id is None
        or request.resource_id is None
        or request.action is None
    ):
        return None

    policy = authorization_policy(
        graph,
        principal_id=request.principal_id,
        resource_id=request.resource_id,
        action=request.action,
    )

    if policy is None:
        return None

    validation_request = HttpRequestSpec(
        method=request.method,
        url=request.url,
        headers=request.headers,
        body=request.body,
        timeout=request.timeout,
        principal_id=request.principal_id,
        resource_id=request.resource_id,
        action=request.action,
        expected_statuses=policy.expected_statuses,
        expected_outcome=(
            "allow"
            if policy.allowed
            else "deny"
        ),
    )

    return Experiment(
        id=f"exp:validation:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="authorization_http_check",
        description=(
            "Fresh validation of policy contradiction for "
            f"{request.action} access to "
            f"{request.resource_id} using "
            f"{request.principal_id}."
        ),
        status="PLANNED",
        request=validation_request,
    )
