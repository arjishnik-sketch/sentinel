from dataclasses import replace

from ..graph import SecurityGraph
from ..models import ExecutionResult
from ..execution import ExecutorRegistry


def execute_next_authorization_candidate(
    graph: SecurityGraph,
    executors: ExecutorRegistry,
) -> ExecutionResult | None:
    """
    Execute the next PLANNED authorization candidate.

    This function only executes experiments already present in
    the graph. It does not create experiments or invent evidence.
    """

    planned = [
        experiment
        for experiment in graph.experiments.values()
        if (
            experiment.kind == "authorization_candidate_check"
            and experiment.status == "PLANNED"
        )
    ]

    if not planned:
        return None

    experiment = sorted(
        planned,
        key=lambda item: item.id,
    )[0]

    if not executors.supports(experiment.kind):
        raise ValueError(
            f"No executor available for experiment kind: "
            f"{experiment.kind}"
        )

    executor = executors.get(experiment.kind)

    result = executor.execute(experiment)

    if result.experiment_id != experiment.id:
        raise ValueError(
            "Executor returned a result for a different experiment."
        )

    for evidence in result.evidence:
        graph.add_evidence(evidence)

    completed = replace(
        experiment,
        status=result.status,
        evidence_ids=tuple(
            evidence.id
            for evidence in result.evidence
        ),
    )

    graph.add_experiment(completed)

    return result
