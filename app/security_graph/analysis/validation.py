from ..models import HypothesisIdentity
from ..validation_core import judge_authorization_validation


def apply_validation_judgment(
    graph,
    judgment,
) -> None:
    """
    Apply a validation judgment to its source hypothesis.

    VALIDATED:
        The hypothesis is confirmed and closed.

    DISPROVED:
        The hypothesis is disproved and closed.

    INCONCLUSIVE:
        The hypothesis remains open.

    No other judgment status is accepted.
    """
    hypothesis = graph.hypotheses.get(judgment.hypothesis_id)

    if hypothesis is None:
        raise ValueError(
            f"Hypothesis not found: {judgment.hypothesis_id}"
        )

    if judgment.status not in {
        "VALIDATED",
        "DISPROVED",
        "INCONCLUSIVE",
    }:
        raise ValueError(
            f"Unsupported validation judgment status: "
            f"{judgment.status}"
        )

    if judgment.status == "VALIDATED":
        status = "CONFIRMED"
    elif judgment.status == "DISPROVED":
        status = "DISPROVED"
    else:
        status = "OPEN"

    evidence_ids = tuple(
        dict.fromkeys(
            hypothesis.evidence_ids
            + judgment.evidence_ids
        )
    )

    identity = hypothesis.identity

    if identity is None:
        experiment = graph.experiments.get(
            judgment.experiment_id
        )

        request = (
            experiment.request
            if experiment is not None
            else None
        )

        if (
            hypothesis.kind == "authorization_policy_violation"
            and request is not None
            and request.principal_id is not None
            and request.resource_id is not None
            and request.action is not None
        ):
            identity = HypothesisIdentity(
                kind=hypothesis.kind,
                principal_id=request.principal_id,
                resource_id=request.resource_id,
                action=request.action,
            )

    graph.add_hypothesis(
        type(hypothesis)(
            id=hypothesis.id,
            kind=hypothesis.kind,
            claim=hypothesis.claim,
            confidence=hypothesis.confidence,
            evidence_ids=evidence_ids,
            source_ids=hypothesis.source_ids,
            status=status,
            identity=identity,
        )
    )
