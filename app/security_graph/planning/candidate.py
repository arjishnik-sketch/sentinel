from ..graph import SecurityGraph
from ..models import Experiment, HttpRequestSpec, Hypothesis


def resolve_authorization_target(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> tuple[str, str, str] | None:
    """
    Resolve an authorization target only from explicit semantic
    provenance already represented in the graph.

    Resolution order:

    1. Existing HypothesisIdentity.
    2. Explicit semantic fields carried by hypothesis evidence.

    This resolver deliberately does NOT infer:
      - resource from URL
      - action from HTTP method
      - principal from names/roles
      - authorization outcome from HTTP status

    An incomplete semantic tuple is unresolved.
    """

    identity = hypothesis.identity

    if identity is not None:
        if (
            isinstance(identity.principal_id, str)
            and identity.principal_id.strip()
            and isinstance(identity.resource_id, str)
            and identity.resource_id.strip()
            and isinstance(identity.action, str)
            and identity.action.strip()
        ):
            return (
                identity.principal_id.strip(),
                identity.resource_id.strip(),
                identity.action.strip(),
            )

    semantic_keys = (
        "principal_id",
        "resource_id",
        "action",
    )

    candidates: list[tuple[str, str, str]] = []

    for evidence_id in hypothesis.evidence_ids:
        evidence = graph.evidence.get(evidence_id)

        if evidence is None:
            continue

        data = evidence.data

        if not isinstance(data, dict):
            continue

        values = []

        valid = True

        for key in semantic_keys:
            value = data.get(key)

            if not isinstance(value, str) or not value.strip():
                valid = False
                break

            values.append(value.strip())

        if valid:
            candidates.append(
                (
                    values[0],
                    values[1],
                    values[2],
                )
            )

    unique = tuple(dict.fromkeys(candidates))

    if len(unique) != 1:
        return None

    return unique[0]


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

    # B690R30R4_ENDPOINT_ONLY_CANDIDATE
    # Endpoint candidates are observation-level experiments.
    # No principal, resource, action, credential, or authorization
    # expectation is inferred from the endpoint itself.
    request = HttpRequestSpec(
        method=method,
        url=url,
        principal_id=None,
        resource_id=None,
        action=None,
    )

    existing_attempts = graph.experiments_for(
        hypothesis_id=hypothesis.id,
    )

    attempt_number = len(existing_attempts) + 1

    return Experiment(
        id=(
            f"exp:auth-candidate:{hypothesis.id}:"
            f"attempt:{attempt_number}"
        ),
        hypothesis_id=hypothesis.id,
        kind="authorization_http_check",
        description=(
            "Bounded HTTP authorization probe for "
            f"endpoint {endpoint.id}."
        ),
        status="PLANNED",
        request=request,
        capability_id="authorization.candidate_check",
        action="test_authorization_candidate",
    )
