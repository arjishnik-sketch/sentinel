from dataclasses import dataclass

from ..graph import SecurityGraph
from ..models import Hypothesis
from .research_state import build_research_state


@dataclass(frozen=True)
class HypothesisState:
    """
    Domain-independent epistemic projection for one hypothesis.

    This is derived entirely from the SecurityGraph and the existing
    ResearchState projection. It is not a second source of truth.
    """

    hypothesis_id: str

    attempts: int
    completed_attempts: int

    judgment_count: int
    supporting_judgments: int
    contradicting_judgments: int
    inconclusive_judgments: int

    evidence_count: int

    support_ratio: float
    contradiction_ratio: float

    resolution: float
    residual_uncertainty: float

    current_status: str

    @property
    def has_prior_research(self) -> bool:
        return self.attempts > 0

    @property
    def is_resolved(self) -> bool:
        return self.current_status in {
            "CONFIRMED",
            "DISPROVED",
        }


def build_hypothesis_state(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> HypothesisState:
    """
    Build the current epistemic state for a hypothesis.

    This function derives its state from existing graph data.
    It does not mutate the hypothesis or graph.
    """

    research_state = build_research_state(
        graph,
        hypothesis,
    )

    judgment_count = research_state.judgment_count

    if judgment_count == 0:
        support_ratio = 0.0
        contradiction_ratio = 0.0
    else:
        support_ratio = (
            research_state.supporting_judgments
            / judgment_count
        )

        contradiction_ratio = (
            research_state.contradicting_judgments
            / judgment_count
        )

    if judgment_count == 0:
        resolution = 0.0

    elif (
        research_state.supporting_judgments > 0
        and research_state.contradicting_judgments > 0
    ):
        resolution = 0.0

    elif research_state.inconclusive_judgments:
        resolution = (
            (
                research_state.supporting_judgments
                + research_state.contradicting_judgments
            )
            / judgment_count
        )

    else:
        resolution = 1.0

    residual_uncertainty = max(
        0.0,
        min(
            1.0,
            1.0 - resolution,
        ),
    )

    return HypothesisState(
        hypothesis_id=hypothesis.id,
        attempts=research_state.attempts,
        completed_attempts=(
            research_state.completed_attempts
        ),
        judgment_count=judgment_count,
        supporting_judgments=(
            research_state.supporting_judgments
        ),
        contradicting_judgments=(
            research_state.contradicting_judgments
        ),
        inconclusive_judgments=(
            research_state.inconclusive_judgments
        ),
        evidence_count=research_state.evidence_count,
        support_ratio=support_ratio,
        contradiction_ratio=contradiction_ratio,
        resolution=resolution,
        residual_uncertainty=residual_uncertainty,
        current_status=research_state.current_status,
    )
