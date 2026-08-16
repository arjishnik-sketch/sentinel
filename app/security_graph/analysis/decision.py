from ..capabilities import DEFAULT_RESEARCH_CAPABILITIES
from ..graph import SecurityGraph
from ..models import (
    ResearchCandidate,
    ResearchDecision,
)
from .ranking import score_hypothesis


def generate_research_candidates(
    graph: SecurityGraph,
) -> list[ResearchCandidate]:
    """
    Generate candidates by asking every registered capability
    whether it is applicable.

    The decision engine intentionally contains no knowledge of
    individual hypothesis kinds or concrete security tools.
    """

    candidates: list[ResearchCandidate] = []

    for hypothesis in graph.hypotheses.values():
        if hypothesis.status != "OPEN":
            continue

        hypothesis_score = score_hypothesis(
            graph,
            hypothesis,
        )

        if hypothesis_score.score <= 0:
            continue

        for capability in DEFAULT_RESEARCH_CAPABILITIES.all():
            applicable, reasons = (
                capability.check_applicability(
                    graph,
                    hypothesis,
                )
            )

            if not applicable:
                continue

            candidates.append(
                ResearchCandidate(
                    id=(
                        f"candidate:{capability.id}:"
                        f"{hypothesis.id}"
                    ),
                    hypothesis_id=hypothesis.id,
                    action=capability.action,
                    capability_id=capability.id,
                    score=hypothesis_score.score,
                    rationale=tuple(
                        hypothesis_score.reasons
                        + reasons
                    ),
                )
            )

    return sorted(
        candidates,
        key=lambda item: (
            -item.score,
            item.id,
        ),
    )


def choose_research_decision(
    graph: SecurityGraph,
) -> ResearchDecision | None:
    """
    Choose the highest-value currently applicable capability.

    Selection is deterministic and records rejected alternatives.
    """

    candidates = generate_research_candidates(graph)

    if not candidates:
        return None

    selected = candidates[0]

    return ResearchDecision(
        candidate_id=selected.id,
        hypothesis_id=selected.hypothesis_id,
        action=selected.action,
        capability_id=selected.capability_id,
        score=selected.score,
        rationale=selected.rationale,
        rejected_candidate_ids=tuple(
            candidate.id
            for candidate in candidates[1:]
        ),
    )
