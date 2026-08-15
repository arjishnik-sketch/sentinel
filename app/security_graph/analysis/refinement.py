from ..graph import SecurityGraph
from ..models import Hypothesis
from .authorization import find_authorization_differentials


def refine_authorization_candidates(
    graph: SecurityGraph,
) -> list[Hypothesis]:
    observations = list(
        graph.authorization_observations.values()
    )

    differentials = find_authorization_differentials(
        observations
    )

    hypotheses: list[Hypothesis] = []

    for differential in differentials:
        hypothesis_id = (
            f"hyp:diff:"
            f"{differential.resource_id}:"
            f"{differential.action}"
        )

        if hypothesis_id in graph.hypotheses:
            continue

        evidence_ids = tuple(
            observation.id
            for observation in observations
            if (
                observation.resource_id
                == differential.resource_id
                and observation.action
                == differential.action
            )
        )

        hypothesis = Hypothesis(
            id=hypothesis_id,
            kind="authorization_differential",
            claim=(
                "Authorization behavior differs between "
                "principals for "
                f"{differential.action} access to "
                f"{differential.resource_id}."
            ),
            confidence=0.75,
            evidence_ids=evidence_ids,
        )

        graph.add_hypothesis(hypothesis)
        hypotheses.append(hypothesis)

    return hypotheses
