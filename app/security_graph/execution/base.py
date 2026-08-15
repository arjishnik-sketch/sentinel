from abc import ABC, abstractmethod

from ..models import ExecutionResult, Experiment


class ExperimentExecutor(ABC):
    kind: str

    @abstractmethod
    def execute(self, experiment: Experiment) -> ExecutionResult:
        """
        Execute a bounded experiment.

        Returns a structured execution result containing
        any evidence produced by the execution.
        """
        raise NotImplementedError
