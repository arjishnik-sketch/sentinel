from ..models import Evidence, ExecutionResult, Experiment
from .base import ExperimentExecutor


class DryRunAuthorizationExecutor(ExperimentExecutor):
    kind = "authorization_recheck"

    def execute(self, experiment: Experiment) -> ExecutionResult:
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
            ),
        )
