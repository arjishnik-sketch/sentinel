from ..analysis import (
    authorization_observation_from_evidence,
    authorization_validation_decision_from_evidence,
)
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

        experiment = graph.experiments.get(
            result.experiment_id
        )

        if (
            experiment is not None
            and experiment.kind == "authorization_http_check"
            and experiment.request is not None
            and experiment.request.expected_outcome is not None
        ):
            allowed = (
                authorization_validation_decision_from_evidence(
                    evidence
                )
            )

            if allowed is None:
                continue

            request = experiment.request

            if (
                request.principal_id is None
                or request.resource_id is None
                or request.action is None
            ):
                continue

            data = evidence.data

            observation = AuthorizationObservation(
                id=f"authobs:{evidence.id}",
                principal_id=request.principal_id,
                resource_id=request.resource_id,
                action=request.action,
                allowed=allowed,
                status_code=data.get("status_code"),
                endpoint_id=data.get("endpoint_id"),
                evidence_ids=(evidence.id,),
            )

        else:
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
