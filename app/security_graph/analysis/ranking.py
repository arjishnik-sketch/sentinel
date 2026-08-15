from ..graph import SecurityGraph
from ..models import Hypothesis, HypothesisScore


_IDENTIFIER_BONUS = {
    "id": 0.25,
    "uid": 0.25,
    "user_id": 0.30,
    "userid": 0.30,
    "account_id": 0.30,
    "accountid": 0.30,
    "order_id": 0.30,
    "orderid": 0.30,
    "object_id": 0.30,
    "objectid": 0.30,
    "tenant_id": 0.35,
    "tenantid": 0.35,
}


def score_hypothesis(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> HypothesisScore:
    score = hypothesis.confidence
    reasons: list[str] = []

    if hypothesis.status != "OPEN":
        return HypothesisScore(
            hypothesis_id=hypothesis.id,
            score=0.0,
            reasons=("hypothesis is not open",),
        )

    if hypothesis.kind == "authorization_candidate":
        score += 0.15
        reasons.append("authorization candidate")

    parameter = None

    for evidence_id in hypothesis.evidence_ids:
        observation = graph.observations.get(evidence_id)

        if observation is None:
            continue

        if observation.kind != "recon_parameter":
            continue

        value = observation.data.get("parameter")

        if isinstance(value, str):
            parameter = value.strip().lower()

    if parameter in _IDENTIFIER_BONUS:
        bonus = _IDENTIFIER_BONUS[parameter]
        score += bonus
        reasons.append(
            f"identifier parameter: {parameter}"
        )

    evidence_count = len(hypothesis.evidence_ids)

    if evidence_count >= 2:
        score += 0.10
        reasons.append("multiple supporting evidence items")
    elif evidence_count == 1:
        reasons.append("single supporting evidence item")

    # Keep the ranking bounded and interpretable.
    score = min(score, 1.0)

    return HypothesisScore(
        hypothesis_id=hypothesis.id,
        score=score,
        reasons=tuple(reasons),
    )


def rank_hypotheses(
    graph: SecurityGraph,
) -> list[HypothesisScore]:
    scores = [
        score_hypothesis(graph, hypothesis)
        for hypothesis in graph.hypotheses.values()
    ]

    return sorted(
        scores,
        key=lambda item: (
            -item.score,
            item.hypothesis_id,
        ),
    )
