from .base import ExperimentExecutor


class ExecutorRegistry:
    def __init__(self):
        self._executors: dict[str, ExperimentExecutor] = {}

    def register(self, executor: ExperimentExecutor) -> None:
        if not executor.kind.strip():
            raise ValueError(
                "Executor kind cannot be empty."
            )

        if executor.kind in self._executors:
            raise ValueError(
                f"Executor already registered: {executor.kind}"
            )

        self._executors[executor.kind] = executor

    def get(self, kind: str) -> ExperimentExecutor:
        try:
            return self._executors[kind]
        except KeyError:
            raise KeyError(
                f"No executor registered for experiment kind: {kind}"
            )

    def supports(self, kind: str) -> bool:
        return kind in self._executors

    def kinds(self) -> tuple[str, ...]:
        return tuple(sorted(self._executors))
