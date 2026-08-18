from ..graph import SecurityGraph
from ..models import Experiment, HttpRequestSpec, Hypothesis


def plan_authorization_candidate(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> Experiment | None:
    """
    Plan a bounded HTTP request from durable endpoint provenance.

    The planner may recover only facts explicitly represented by the
    canonical endpoint referenced by the hypothesis.

    No URL, method, principal, credentials, or authorization outcome
    is inferred.
    """

    if hypothesis.kind != "authorization_candidate":
        raise ValueError(
            "Candidate planner requires an "
            "authorization_candidate hypothesis."
        )

    if hypothesis.status != "OPEN":
        raise ValueError(
            "Only OPEN hypotheses can be investigated."
        )

    if not hypothesis.source_ids:
        return None

    endpoints = [
        graph.endpoints.get(source_id)
        for source_id in hypothesis.source_ids
    ]

    endpoints = [
        endpoint
        for endpoint in endpoints
        if endpoint is not None
    ]

    if len(endpoints) != 1:
        return None

    endpoint = endpoints[0]

    method = endpoint.method.strip().upper()
    url = endpoint.url.strip()

    if not method or not url:
        return None

    request = HttpRequestSpec(
        method=method,
        url=url,
    )

    return Experiment(
        id=f"exp:auth-candidate:{hypothesis.id}",
        hypothesis_id=hypothesis.id,
        kind="authorization_http_check",
        description=(
            "Bounded HTTP authorization probe for "
            f"endpoint {endpoint.id}."
        ),
        status="PLANNED",
        request=request,
    )
