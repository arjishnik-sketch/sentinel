from abc import ABC, abstractmethod

from ..models import Experiment


class ExperimentExecutor(ABC):
    kind: str

    @abstractmethod
    def execute(self, experiment: Experiment) -> list[str]:
        """
        Execute a bounded experiment.

        Returns IDs of evidence produced by the execution.
        """
        raise NotImplementedError
