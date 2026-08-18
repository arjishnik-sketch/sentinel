from ..graph import SecurityGraph
from ..models import Hypothesis


_IDENTIFIER_NAMES = {
    "id",
    "uid",
    "user_id",
    "userid",
    "account_id",
    "accountid",
    "order_id",
    "orderid",
    "object_id",
    "objectid",
    "tenant_id",
    "tenantid",
}


def generate_parameter_hypotheses(
    graph: SecurityGraph,
) -> list[Hypothesis]:
    hypotheses: list[Hypothesis] = []

    for observation in graph.observations.values():
        if observation.kind != "recon_parameter":
            continue

        parameter = observation.data.get("parameter")

        if not isinstance(parameter, str):
            continue

        normalized = parameter.strip().lower()

        if normalized not in _IDENTIFIER_NAMES:
            continue

        endpoint_id = observation.subject

        hypothesis_id = (
            f"hyp:parameter-auth:"
            f"{endpoint_id}:"
            f"{normalized}"
        )

        # Existing hypothesis already represents this
        # exact attack-surface observation.
        if hypothesis_id in graph.hypotheses:
            continue

        claim = (
            f"Endpoint {endpoint_id} accepts parameter "
            f"'{parameter}', which may reference a security-"
            "sensitive object. Authorization behavior should "
            "be verified before treating this as a vulnerability."
        )

        hypothesis = Hypothesis(
            id=hypothesis_id,
            kind="authorization_candidate",
            claim=claim,
            confidence=0.45,
            evidence_ids=(observation.id,),
            source_ids=(endpoint_id,),
        )

        graph.add_hypothesis(hypothesis)
        hypotheses.append(hypothesis)

    return hypotheses

def generate_api_hypotheses(
    graph: SecurityGraph,
) -> list[Hypothesis]:
    """
    Generate conservative authorization hypotheses from
    explicitly discovered API endpoints.

    Discovery of an API endpoint is not evidence of a
    vulnerability. It is only a justified reason to investigate
    authorization behavior.

    The originating recon observation is retained as evidence.
    """

    hypotheses: list[Hypothesis] = []

    for observation in graph.observations.values():
        if observation.kind != "recon_api":
            continue

        url = None

        if isinstance(observation.data, dict):
            candidate = observation.data.get("url")

            if isinstance(candidate, str):
                url = candidate.strip()

        if not url:
            continue

        endpoint_id = observation.subject

        hypothesis_id = (
            f"hyp:api-auth:"
            f"{endpoint_id}"
        )

        if hypothesis_id in graph.hypotheses:
            continue

        claim = (
            f"API endpoint {endpoint_id} is reachable and "
            "may expose security-sensitive operations. "
            "Authorization behavior should be investigated "
            "before treating the endpoint as a vulnerability."
        )

        hypothesis = Hypothesis(
            id=hypothesis_id,
            kind="authorization_candidate",
            claim=claim,
            confidence=0.45,
            evidence_ids=(observation.id,),
            source_ids=(endpoint_id,),
        )

        graph.add_hypothesis(hypothesis)
        hypotheses.append(hypothesis)

    return hypotheses
