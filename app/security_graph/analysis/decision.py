from ..graph import SecurityGraph
from ..models import (
    Hypothesis,
    ResearchCandidate,
    ResearchDecision,
)
from .ranking import score_hypothesis


def generate_research_candidates(
    graph: SecurityGraph,
) -> list[ResearchCandidate]:
    """
    Generate bounded research candidates from unresolved hypotheses.

    This first implementation intentionally maps only capabilities that
    the current security-graph planning layer can execute safely.

    Candidate generation does not execute anything and does not invent
    request details.
    """

    candidates: list[ResearchCandidate] = []

    for hypothesis in graph.hypotheses.values():
        if hypothesis.status != "OPEN":
            continue

        score = score_hypothesis(
            graph,
            hypothesis,
        )

        if score.score <= 0:
            continue

        rationale = list(score.reasons)

        if hypothesis.kind == "authorization_policy_violation":
            candidates.append(
                ResearchCandidate(
                    id=f"candidate:validate:{hypothesis.id}",
                    hypothesis_id=hypothesis.id,
                    action="validate_hypothesis",
                    capability_id="authorization.policy_validation",
                    score=min(score.score + 0.05, 1.0),
                    rationale=tuple(
                        rationale
                        + [
                            "explicit policy contradiction can be "
                            "validated with a fresh authorization check"
                        ]
                    ),
                )
            )
            continue

        if hypothesis.kind == "authorization_differential":
            candidates.append(
                ResearchCandidate(
                    id=f"candidate:recheck:{hypothesis.id}",
                    hypothesis_id=hypothesis.id,
                    action="recheck_authorization",
                    capability_id="authorization.policy_validation",
                    score=score.score,
                    rationale=tuple(
                        rationale
                        + [
                            "authorization differential has a "
                            "dedicated recheck capability"
                        ]
                    ),
                )
            )
            continue

        if hypothesis.kind == "authorization_candidate":
            candidates.append(
                ResearchCandidate(
                    id=f"candidate:check:{hypothesis.id}",
                    hypothesis_id=hypothesis.id,
                    action="test_authorization_candidate",
                    capability_id="authorization.policy_validation",
                    score=score.score,
                    rationale=tuple(
                        rationale
                        + [
                            "authorization candidate has an "
                            "HTTP validation capability"
                        ]
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
    Choose the highest-value currently executable research candidate.

    Selection is deterministic. No execution occurs here.
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
