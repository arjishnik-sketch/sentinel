from ..analysis import (
    apply_validation_judgment,
    choose_research_decision,
    materialize_confirmed_findings,
)
from ..capabilities import DEFAULT_RESEARCH_CAPABILITIES
from ..execution import ExecutorRegistry
from ..graph import SecurityGraph
from ..models import (
    ExecutionResult,
    Experiment,
    Hypothesis,
    InvestigationCycleResult,
)
from ..analysis.refinement_pressure import (
    evaluate_refinement_pressure,
)


def _execute_experiment(
    graph: SecurityGraph,
    executors: ExecutorRegistry,
    experiment: Experiment,
) -> ExecutionResult:
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

    completed = Experiment(
        id=experiment.id,
        hypothesis_id=experiment.hypothesis_id,
        kind=experiment.kind,
        description=experiment.description,
        status=result.status,
        evidence_ids=tuple(
            evidence.id
            for evidence in result.evidence
        ),
        request=experiment.request,
    )

    graph.add_experiment(completed)

    return result


def run_investigation_cycle(
    graph: SecurityGraph,
    executors: ExecutorRegistry,
) -> InvestigationCycleResult | None:
    """
    Run exactly one bounded investigation cycle.

    Select -> plan -> verify executor -> execute ->
    persist evidence -> ingest observations.

    Reasoning/refinement remains a separate stage.
    """

    research_decision = choose_research_decision(
        graph,
    )

    if research_decision is None:
        return None

    hypothesis = graph.hypotheses.get(
        research_decision.hypothesis_id
    )

    if hypothesis is None:
        raise ValueError(
            "Research decision references a missing hypothesis: "
            f"{research_decision.hypothesis_id}"
        )

    if not DEFAULT_RESEARCH_CAPABILITIES.supports(
        research_decision.capability_id
    ):
        raise ValueError(
            "Research decision selected an unavailable capability: "
            f"{research_decision.capability_id}"
        )

    capability = DEFAULT_RESEARCH_CAPABILITIES.get(
        research_decision.capability_id
    )

    experiment = capability.plan(
        graph,
        hypothesis,
    )

    if experiment is None:
        return None

    existing = graph.experiments.get(experiment.id)

    if existing is not None:
        if existing.status == "COMPLETED":
            return None

        experiment = existing

    if experiment.id not in graph.experiments:
        graph.add_experiment(experiment)
    else:
        experiment = graph.experiments[experiment.id]

    execution = _execute_experiment(
        graph,
        executors,
        experiment,
    )

    observations = capability.observe(
        graph,
        execution,
    )

    observation_ids = tuple(
        observation.id
        for observation in observations
    )

    capability = DEFAULT_RESEARCH_CAPABILITIES.get(
        research_decision.capability_id
    )

    judgment = capability.judge(
        graph,
        hypothesis,
        experiment,
    )

    if judgment is not None:
        graph.add_validation_judgment(judgment)
        apply_validation_judgment(graph, judgment)

    hypotheses_before = set(graph.hypotheses)

    refinement_pressure = evaluate_refinement_pressure(
        graph,
        hypothesis,
    )

    if refinement_pressure.required:
        refined_hypotheses = capability.refine(
            graph,
            hypothesis,
            observations,
        )
    else:
        refined_hypotheses = ()

    new_hypothesis_ids = tuple(
        sorted(
            set(graph.hypotheses) - hypotheses_before
        )
    )

    finding_materialization = (
        materialize_confirmed_findings(graph)
    )

    return InvestigationCycleResult(
        hypothesis_id=hypothesis.id,
        experiment_id=experiment.id,
        execution=execution,
        research_decision=research_decision,
        judgment=judgment,
        observation_ids=observation_ids,
        new_hypothesis_ids=new_hypothesis_ids,
        finding_materialization=finding_materialization,
    )
