from ..analysis import select_next_hypothesis
from ..execution import ExecutorRegistry
from ..graph import SecurityGraph
from ..models import Experiment, Hypothesis
from ..planning import (
    plan_authorization_candidate,
    plan_authorization_recheck,
)
from ..policy import select_principal


def _plan_hypothesis(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> Experiment | None:
    principal = select_principal(graph)

    if principal is None:
        return None

    if hypothesis.kind == "authorization_candidate":
        return plan_authorization_candidate(
            hypothesis,
            principal_id=principal.id,
        )

    if hypothesis.kind == "authorization_differential":
        # Differential hypotheses currently encode their target
        # in the hypothesis claim/source structure. For this first
        # cycle implementation, only plan when the resource/action
        # can be recovered safely from the hypothesis ID.
        prefix = "hyp:diff:"

        if not hypothesis.id.startswith(prefix):
            return None

        remainder = hypothesis.id[len(prefix):]

        if ":" not in remainder:
            return None

        resource_id, action = remainder.rsplit(":", 1)

        if not resource_id or not action:
            return None

        return plan_authorization_recheck(
            hypothesis,
            resource_id=resource_id,
            action=action,
            principal_id=principal.id,
        )

    return None


def run_investigation_cycle(
    graph: SecurityGraph,
    executors: ExecutorRegistry,
) -> Experiment | None:
    """
    Run one bounded investigation planning cycle.

    This stage selects one actionable hypothesis and plans
    exactly one supported experiment.

    Execution is deliberately not performed yet.
    """

    hypothesis = select_next_hypothesis(graph)

    if hypothesis is None:
        return None

    experiment = _plan_hypothesis(
        graph,
        hypothesis,
    )

    if experiment is None:
        return None

    if experiment.id in graph.experiments:
        return graph.experiments[experiment.id]

    graph.add_experiment(experiment)

    return experiment
