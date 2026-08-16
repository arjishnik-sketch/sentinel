from ..analysis import (
    apply_validation_judgment,
    choose_research_decision,
    judge_authorization_validation,
    materialize_confirmed_findings,
    refine_authorization_candidates,
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
from ..planning import (
    plan_authorization_candidate,
    plan_authorization_recheck,
    plan_authorization_policy_validation,
)
from ..policy import select_principal
from .observations import ingest_execution_observations


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

    experiment = DEFAULT_RESEARCH_CAPABILITIES.plan(
        graph,
        hypothesis,
        research_decision.capability_id,
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

    observations = ingest_execution_observations(
        graph,
        execution,
    )

    observation_ids = tuple(
        observation.id
        for observation in observations
    )

    judgment = None

    if experiment.kind == "authorization_http_check":
        judgment = judge_authorization_validation(
            graph,
            hypothesis=hypothesis,
            experiment_id=experiment.id,
        )
        graph.add_validation_judgment(judgment)
        apply_validation_judgment(graph, judgment)

    hypotheses_before = set(graph.hypotheses)

    refine_authorization_candidates(graph)

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
