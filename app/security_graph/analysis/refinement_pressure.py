from dataclasses import dataclass

from ..graph import SecurityGraph
from ..models import Hypothesis
from .hypothesis_evolution import (
    HypothesisEvolution,
    evaluate_hypothesis_evolution,
)
from .hypothesis_state import (
    HypothesisState,
    build_hypothesis_state,
)


@dataclass(frozen=True)
class RefinementPressure:
    """
    Domain-independent projection describing whether the current
    hypothesis has an unresolved knowledge gap worth investigating.

    This is a projection only. It does not create hypotheses,
    mutate the graph, or select a research capability.
    """

    hypothesis_id: str
    level: str
    required: bool
    uncertainty: float
    reasons: tuple[str, ...] = ()


def evaluate_refinement_pressure(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> RefinementPressure:
    """
    Determine whether current research leaves enough unresolved
    uncertainty to justify further investigation.
    """

    state: HypothesisState = build_hypothesis_state(
        graph,
        hypothesis,
    )

    evolution: HypothesisEvolution = (
        evaluate_hypothesis_evolution(
            graph,
            hypothesis,
        )
    )

    if evolution.resolved:
        return RefinementPressure(
            hypothesis_id=hypothesis.id,
            level="NO_PRESSURE",
            required=False,
            uncertainty=state.residual_uncertainty,
            reasons=(
                "hypothesis lifecycle is already resolved",
                "no further refinement is required",
            ),
        )

    if state.judgment_count == 0:
        return RefinementPressure(
            hypothesis_id=hypothesis.id,
            level="LOW",
            required=False,
            uncertainty=state.residual_uncertainty,
            reasons=(
                "hypothesis has not yet been researched",
                "initial research should occur before refinement",
            ),
        )

    if (
        state.supporting_judgments > 0
        and state.contradicting_judgments > 0
    ):
        return RefinementPressure(
            hypothesis_id=hypothesis.id,
            level="HIGH",
            required=True,
            uncertainty=state.residual_uncertainty,
            reasons=(
                "supporting and contradicting evidence conflict",
                "current evidence cannot resolve the hypothesis",
                "additional research should discriminate between competing explanations",
            ),
        )

    if state.inconclusive_judgments > 0:
        return RefinementPressure(
            hypothesis_id=hypothesis.id,
            level="MEDIUM",
            required=True,
            uncertainty=state.residual_uncertainty,
            reasons=(
                "prior research was inconclusive",
                "residual uncertainty remains",
                "additional research may reduce unresolved uncertainty",
            ),
        )

    return RefinementPressure(
        hypothesis_id=hypothesis.id,
        level="NO_PRESSURE",
        required=False,
        uncertainty=state.residual_uncertainty,
        reasons=(
            "current evidence does not indicate an unresolved refinement gap",
        ),
    )
