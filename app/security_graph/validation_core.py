from .graph import SecurityGraph
from .models import (
    Hypothesis,
    ValidationJudgment,
)
from .policy.authorization import authorization_policy


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
            contradiction_kind="authorization",
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
            contradiction_kind="authorization",
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
        contradiction_kind="authorization",
        expected=policy.allowed,
        observed=observation.allowed,
        evidence_ids=observation.evidence_ids,
    )


