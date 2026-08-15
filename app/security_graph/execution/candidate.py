from ..models import Evidence, ExecutionResult, Experiment
from .base import ExperimentExecutor


class DryRunAuthorizationCandidateExecutor(ExperimentExecutor):
    kind = "authorization_candidate_check"

    def execute(
        self,
        experiment: Experiment,
    ) -> ExecutionResult:
        if experiment.kind != self.kind:
            raise ValueError(
                f"Unsupported experiment kind: {experiment.kind}"
            )

        evidence = Evidence(
            id=f"dryrun:{experiment.id}",
            source="dry_run",
            data={
                "executor": self.kind,
                "mode": "dry_run",
                "experiment_id": experiment.id,
                "description": experiment.description,
                "authorization_observed": False,
            },
            confidence=1.0,
        )

        return ExecutionResult(
            experiment_id=experiment.id,
            status="COMPLETED",
            evidence=(evidence,),
            metadata=(
                ("mode", "dry_run"),
                ("executor", self.kind),
                ("authorization_observed", "false"),
            ),
        )
