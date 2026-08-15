from dataclasses import replace

from ..execution import ExecutorRegistry
from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis
from ..planning import plan_authorization_recheck


class InvestigationOrchestrator:
    def __init__(
        self,
        graph: SecurityGraph,
        executors: ExecutorRegistry,
    ):
        self.graph = graph
        self.executors = executors

    def run_authorization_recheck(
        self,
        hypothesis: Hypothesis,
        *,
        resource_id: str,
        action: str,
        principal_id: str,
    ) -> Experiment:
        if hypothesis.id not in self.graph.hypotheses:
            raise ValueError(
                f"Hypothesis is not present in graph: {hypothesis.id}"
            )

        experiment = plan_authorization_recheck(
            hypothesis,
            resource_id=resource_id,
            action=action,
            principal_id=principal_id,
        )

        if not self.executors.supports(experiment.kind):
            raise ValueError(
                f"No executor available for experiment kind: "
                f"{experiment.kind}"
            )

        executor = self.executors.get(experiment.kind)

        self.graph.add_experiment(experiment)

        result = executor.execute(experiment)

        if result.experiment_id != experiment.id:
            raise ValueError(
                "Executor returned a result for a different experiment."
            )

        for evidence in result.evidence:
            self.graph.add_evidence(evidence)

        evidence_ids = tuple(
            evidence.id
            for evidence in result.evidence
        )

        completed = replace(
            experiment,
            status=result.status,
            evidence_ids=evidence_ids,
        )

        self.graph.add_experiment(completed)

        return completed
