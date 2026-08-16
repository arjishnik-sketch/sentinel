from dataclasses import dataclass

from ..graph import SecurityGraph
from ..models import Hypothesis
from .hypothesis_state import (
    HypothesisState,
    build_hypothesis_state,
)


@dataclass(frozen=True)
class HypothesisEvolution:
    """
    Domain-independent description of how research has affected
    the current hypothesis.

    This is a projection only. It does not mutate graph state or
    change the hypothesis lifecycle.
    """

    hypothesis_id: str
    phase: str
    direction: str
    resolved: bool
    changed: bool
    reasons: tuple[str, ...] = ()


def evaluate_hypothesis_evolution(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> HypothesisEvolution:
    """
    Derive the current epistemic evolution of a hypothesis.

    Lifecycle status remains owned by the existing validation
    transition machinery.
    """

    state: HypothesisState = build_hypothesis_state(
        graph,
        hypothesis,
    )

    if state.current_status == "CONFIRMED":
        return HypothesisEvolution(
            hypothesis_id=hypothesis.id,
            phase="RESOLVED",
            direction="CONFIRMED",
            resolved=True,
            changed=True,
            reasons=(
                "hypothesis lifecycle is confirmed",
                "research produced sufficient supporting resolution",
            ),
        )

    if state.current_status == "DISPROVED":
        return HypothesisEvolution(
            hypothesis_id=hypothesis.id,
            phase="RESOLVED",
            direction="DISPROVED",
            resolved=True,
            changed=True,
            reasons=(
                "hypothesis lifecycle is disproved",
                "research produced sufficient contradicting resolution",
            ),
        )

    if state.judgment_count == 0:
        return HypothesisEvolution(
            hypothesis_id=hypothesis.id,
            phase="UNTESTED",
            direction="UNCHANGED",
            resolved=False,
            changed=False,
            reasons=(
                "no validation judgments exist",
                "no epistemic change has been established",
            ),
        )

    if (
        state.contradicting_judgments > 0
        and state.supporting_judgments == 0
        and state.inconclusive_judgments == 0
    ):
        return HypothesisEvolution(
            hypothesis_id=hypothesis.id,
            phase="CONTRADICTED",
            direction="WEAKENED",
            resolved=False,
            changed=True,
            reasons=(
                "contradicting evidence exists",
                "no supporting evidence offsets the contradiction",
            ),
        )

    if (
        state.supporting_judgments > 0
        and state.contradicting_judgments == 0
        and state.inconclusive_judgments == 0
    ):
        return HypothesisEvolution(
            hypothesis_id=hypothesis.id,
            phase="SUPPORTED",
            direction="STRENGTHENED",
            resolved=False,
            changed=True,
            reasons=(
                "supporting evidence exists",
                "no contradicting evidence offsets the support",
            ),
        )

    return HypothesisEvolution(
        hypothesis_id=hypothesis.id,
        phase="UNRESOLVED",
        direction="UNCERTAIN",
        resolved=False,
        changed=True,
        reasons=(
            "research produced mixed or inconclusive evidence",
            "hypothesis remains unresolved",
        ),
    )
