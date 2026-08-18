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


@dataclass(frozen=True)
class TargetResearchOutcome:
    """
    Read-only projection of the current research frontier
    across all hypotheses belonging to a target graph.

    This model does not mutate the graph and does not make
    security or vulnerability claims.
    """

    target: str
    phase: str
    hypothesis_count: int
    active_hypotheses: int
    exhausted_hypotheses: int
    resolved_hypotheses: int
    productive_actions_remaining: bool
    reasons: tuple[str, ...] = ()


def evaluate_target_research_outcome(
    result: TargetResearchResult,
) -> TargetResearchOutcome:
    """
    Aggregate per-hypothesis research outcomes into a
    deterministic target-level research state.

    Lifecycle state remains owned by each hypothesis.
    Frontier exhaustion is not interpreted as security.
    """

    from ..analysis.decision import (
        evaluate_research_outcome,
    )

    hypotheses = tuple(
        sorted(
            result.graph.hypotheses.values(),
            key=lambda item: item.id,
        )
    )

    outcomes = tuple(
        evaluate_research_outcome(
            result.graph,
            hypothesis,
        )
        for hypothesis in hypotheses
    )

    resolved = sum(
        1
        for outcome in outcomes
        if outcome.resolved
    )

    exhausted = sum(
        1
        for outcome in outcomes
        if (
            not outcome.resolved
            and outcome.frontier_status == "EXHAUSTED"
        )
    )

    active = sum(
        1
        for outcome in outcomes
        if (
            not outcome.resolved
            and outcome.frontier_status == "ACTIVE"
        )
    )

    productive = any(
        outcome.productive_actions_remaining
        for outcome in outcomes
    )

    if productive:
        phase = "ACTIVE"
        reasons = (
            "at least one hypothesis has productive research remaining",
        )
    elif resolved == len(hypotheses) and hypotheses:
        phase = "RESOLVED"
        reasons = (
            "all represented hypotheses are lifecycle-resolved",
        )
    elif hypotheses and exhausted == len(hypotheses):
        phase = "EXHAUSTED"
        reasons = (
            "all represented hypotheses have exhausted productive research",
            "hypotheses remain epistemically distinct from a security verdict",
        )
    elif not hypotheses:
        phase = "EMPTY"
        reasons = (
            "target graph contains no hypotheses",
        )
    else:
        phase = "MIXED"
        reasons = (
            "target contains a mixture of resolved and unresolved research paths",
        )

    return TargetResearchOutcome(
        target=result.target,
        phase=phase,
        hypothesis_count=len(hypotheses),
        active_hypotheses=active,
        exhausted_hypotheses=exhausted,
        resolved_hypotheses=resolved,
        productive_actions_remaining=productive,
        reasons=reasons,
    )


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
