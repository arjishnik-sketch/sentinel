from ..graph import SecurityGraph
from ..models import (
    Hypothesis,
    HypothesisIdentity,
    ValidationJudgment,
)
from ..policy.authorization import authorization_policy


def judge_authorization_validation(
    graph: SecurityGraph,
    *,
    hypothesis: Hypothesis,
    experiment_id: str,
) -> ValidationJudgment:
    """
    Deterministically judge a fresh authorization validation.

    The judgment uses only:
      - explicit graph policy
      - a fresh authorization observation
      - durable evidence provenance

    No HTTP status is interpreted directly here.
    """

    experiment = graph.experiments.get(experiment_id)

    if experiment is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=experiment_id,
            status="INCONCLUSIVE",
            reason="validation experiment not found",
        )

    observations = [
        observation
        for observation in graph.authorization_observations.values()
        if observation.evidence_ids
        and set(observation.evidence_ids).intersection(
            experiment.evidence_ids
        )
    ]

    if len(observations) != 1:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=experiment_id,
            status="INCONCLUSIVE",
            reason=(
                "validation requires exactly one "
                "fresh authorization observation"
            ),
        )

    observation = observations[0]

    policy = authorization_policy(
        graph,
        principal_id=observation.principal_id,
        resource_id=observation.resource_id,
        action=observation.action,
    )

    if policy is None:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=experiment_id,
            status="INCONCLUSIVE",
            reason="explicit authorization policy unavailable",
            observed=observation.allowed,
            evidence_ids=observation.evidence_ids,
        )

    if policy.allowed == observation.allowed:
        return ValidationJudgment(
            hypothesis_id=hypothesis.id,
            experiment_id=experiment_id,
            status="DISPROVED",
            reason=(
                "fresh authorization behavior matches "
                "explicit policy"
            ),
            expected=policy.allowed,
            observed=observation.allowed,
            evidence_ids=observation.evidence_ids,
        )

    return ValidationJudgment(
        hypothesis_id=hypothesis.id,
        experiment_id=experiment_id,
        status="VALIDATED",
        reason=(
            "fresh authorization behavior contradicts "
            "explicit policy"
        ),
        expected=policy.allowed,
        observed=observation.allowed,
        evidence_ids=observation.evidence_ids,
    )


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
