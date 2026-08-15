from ..analysis import select_next_hypothesis
from ..graph import SecurityGraph
from ..models import Experiment
from ..planning import plan_authorization_candidate
from ..policy import select_principal


def plan_next_authorization_candidate(
    graph: SecurityGraph,
) -> Experiment | None:
    """
    Select the highest-value OPEN authorization candidate and
    create a bounded experiment for an existing principal.

    This function plans only.
    It does not execute anything.
    """

    hypothesis = select_next_hypothesis(graph)

    if hypothesis is None:
        return None

    if hypothesis.kind != "authorization_candidate":
        return None

    principal = select_principal(graph)

    if principal is None:
        return None

    experiment = plan_authorization_candidate(
        hypothesis,
        principal_id=principal.id,
    )

    graph.add_experiment(experiment)

    return experiment
