from dataclasses import dataclass

from ...recon_engine import ReconEngine
from ..execution import ExecutorRegistry
from ..execution.http import HttpAuthorizationExecutor
from ..graph import SecurityGraph
from ..analysis.attack_surface import generate_api_hypotheses
from ..recon import ingest_recon
from .cycle import run_investigation_cycle


@dataclass(frozen=True)
class TargetResearchResult:
    target: str
    recon: dict
    graph: SecurityGraph
    cycles: tuple
    stopped_reason: str


class TargetResearchPipeline:
    """
    Bridge the existing real-target reconnaissance system into
    the security-graph research loop.

    Recon remains responsible for discovering the target surface.
    The security graph remains responsible for representing evidence
    and driving justified research.

    This class does not invent hypotheses or credentials.
    """

    def __init__(
        self,
        *,
        recon_engine: ReconEngine | None = None,
        executors: ExecutorRegistry | None = None,
    ):
        self.recon_engine = (
            recon_engine
            if recon_engine is not None
            else ReconEngine()
        )

        self.executors = (
            executors
            if executors is not None
            else self._default_executors()
        )

    @staticmethod
    def _default_executors() -> ExecutorRegistry:
        registry = ExecutorRegistry()

        registry.register(
            HttpAuthorizationExecutor()
        )

        return registry

    def run(
        self,
        target: str,
        *,
        max_cycles: int = 10,
    ) -> TargetResearchResult:
        if not target or not target.strip():
            raise ValueError(
                "target cannot be empty."
            )

        if max_cycles < 0:
            raise ValueError(
                "max_cycles cannot be negative."
            )

        normalized_target = (
            self.recon_engine.normalize(target)
        )

        recon = (
            self.recon_engine.run_pipeline(
                normalized_target
            )
        )

        findings = (
            self.recon_engine.extract(
                recon
            )
        )

        graph = SecurityGraph()

        ingest_recon(
            graph,
            recon,
            findings,
        )

        generate_api_hypotheses(
            graph,
        )

        cycles = []

        for _ in range(max_cycles):
            result = run_investigation_cycle(
                graph,
                self.executors,
            )

            if result is None:
                return TargetResearchResult(
                    target=normalized_target,
                    recon=recon,
                    graph=graph,
                    cycles=tuple(cycles),
                    stopped_reason="frontier_exhausted",
                )

            cycles.append(result)

        return TargetResearchResult(
            target=normalized_target,
            recon=recon,
            graph=graph,
            cycles=tuple(cycles),
            stopped_reason="cycle_limit",
        )
