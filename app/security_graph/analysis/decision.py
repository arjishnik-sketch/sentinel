from ..graph import SecurityGraph
from ..models import (
    ResearchCandidate,
    ResearchDecision,
)
from .ranking import score_hypothesis
from .refinement_pressure import (
    evaluate_refinement_pressure,
)


def score_research_frontier(
    base_value: float,
    refinement_level: str,
) -> float:
    """
    Combine capability value with domain-independent refinement
    urgency.

    Capability evaluation remains the source of research value.
    Refinement pressure contributes bounded urgency only.

    The decision engine does not interpret hypothesis kinds,
    evidence semantics, or security-domain concepts.
    """

    pressure_bonus = {
        "NO_PRESSURE": 0.00,
        "LOW": 0.00,
        "MEDIUM": 0.10,
        "HIGH": 0.20,
    }.get(
        refinement_level,
        0.00,
    )

    return min(
        1.0,
        max(
            0.0,
            base_value + pressure_bonus,
        ),
    )


def generate_research_candidates(
    graph: SecurityGraph,
) -> list[ResearchCandidate]:
    """
    Generate candidates by asking every registered capability
    whether it is applicable.

    The decision engine intentionally contains no knowledge of
    individual hypothesis kinds or concrete security tools.
    """

    from ..capabilities import DEFAULT_RESEARCH_CAPABILITIES

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

            evaluation = capability.evaluate(
                graph,
                hypothesis,
            )

            refinement_pressure = (
                evaluate_refinement_pressure(
                    graph,
                    hypothesis,
                )
            )

            frontier_score = score_research_frontier(
                evaluation.value,
                refinement_pressure.level,
            )

            candidates.append(
                ResearchCandidate(
                    id=(
                        f"candidate:{capability.id}:"
                        f"{hypothesis.id}"
                    ),
                    hypothesis_id=hypothesis.id,
                    action=capability.action,
                    capability_id=capability.id,
                    score=frontier_score,
                    rationale=tuple(
                        hypothesis_score.reasons
                        + reasons
                        + evaluation.reasons
                        + refinement_pressure.reasons
                    ),
                    evaluation=evaluation,
                    refinement_level=(
                        refinement_pressure.level
                    ),
                    refinement_required=(
                        refinement_pressure.required
                    ),
                    refinement_uncertainty=(
                        refinement_pressure.uncertainty
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

    # A technically applicable action may still have no
    # remaining research value. Keep zero-value candidates
    # visible in the frontier, but never turn them into
    # executable research decisions.
    if selected.score <= 0.0:
        return None

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
