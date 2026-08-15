from ..graph import SecurityGraph
from ..models import Hypothesis
from .ranking import rank_hypotheses


def select_next_hypothesis(
    graph: SecurityGraph,
) -> Hypothesis | None:
    ranked = rank_hypotheses(graph)

    for item in ranked:
        hypothesis = graph.hypotheses[item.hypothesis_id]

        if hypothesis.status != "OPEN":
            continue

        if item.score <= 0:
            continue

        return hypothesis

    return None
