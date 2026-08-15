from ..analysis import authorization_observation_from_evidence
from ..graph import SecurityGraph
from ..models import AuthorizationObservation, ExecutionResult


def ingest_execution_observations(
    graph: SecurityGraph,
    result: ExecutionResult,
) -> list[AuthorizationObservation]:
    """
    Convert execution evidence into explicit graph observations.

    Raw evidence is persisted first so every generated observation
    retains a resolvable provenance chain.
    """

    observations: list[AuthorizationObservation] = []

    for evidence in result.evidence:
        # Preserve the raw execution evidence in the graph.
        if evidence.id not in graph.evidence:
            graph.add_evidence(evidence)

        observation = authorization_observation_from_evidence(
            evidence
        )

        if observation is None:
            continue

        if observation.id in graph.authorization_observations:
            continue

        graph.add_authorization_observation(
            observation
        )

        observations.append(observation)

    return observations
