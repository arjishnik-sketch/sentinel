from dataclasses import dataclass
from typing import Callable

from .graph import SecurityGraph
from .models import (
    Experiment,
    Hypothesis,
    ResearchCandidate,
    ResearchEvaluation,
    ValidationJudgment,
)
from .planning import (
    plan_authorization_candidate,
    plan_authorization_policy_validation,
    plan_authorization_recheck,
)
from .policy import select_principal
from .validation_core import judge_authorization_validation


Planner = Callable[
    [SecurityGraph, Hypothesis],
    Experiment | None,
]

Applicability = Callable[
    [SecurityGraph, Hypothesis],
    tuple[bool, tuple[str, ...]],
]


Evaluation = Callable[
    [SecurityGraph, Hypothesis],
    "ResearchEvaluation",
]


Judge = Callable[
    [SecurityGraph, Hypothesis, Experiment],
    ValidationJudgment | None,
]


@dataclass(frozen=True)
class ResearchCapability:
    """
    A self-describing research capability.

    The decision engine knows only that capabilities can answer:

        "Can I perform this action for this hypothesis?"

    The capability itself owns:
      - applicability
      - rationale
      - planning
      - executor binding
    """

    id: str
    action: str
    executor_kind: str
    applicable: Applicability
    evaluate_fn: Evaluation
    planner: Planner
    judge_fn: Judge | None = None

    def check_applicability(
        self,
        graph: SecurityGraph,
        hypothesis: Hypothesis,
    ) -> tuple[bool, tuple[str, ...]]:
        return self.applicable(
            graph,
            hypothesis,
        )

    def evaluate(
        self,
        graph: SecurityGraph,
        hypothesis: Hypothesis,
    ) -> ResearchEvaluation:
        return self.evaluate_fn(
            graph,
            hypothesis,
        )

    def plan(
        self,
        graph: SecurityGraph,
        hypothesis: Hypothesis,
    ) -> Experiment | None:
        return self.planner(
            graph,
            hypothesis,
        )

    def judge(
        self,
        graph: SecurityGraph,
        hypothesis: Hypothesis,
        experiment: Experiment,
    ) -> ValidationJudgment | None:
        if self.judge_fn is None:
            return None

        return self.judge_fn(
            graph,
            hypothesis,
            experiment,
        )


def _judge_policy_validation(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
    experiment: Experiment,
) -> ValidationJudgment:
    return judge_authorization_validation(
        graph,
        hypothesis=hypothesis,
        experiment_id=experiment.id,
    )


# ============================================================
# Default research valuation
# ============================================================

def _default_research_evaluation(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> ResearchEvaluation:
    """
    Conservative baseline valuation.

    Capabilities may override this with domain-specific reasoning.
    The decision engine itself never needs to know the domain.
    """

    evidence_count = len(hypothesis.evidence_ids)

    information_gain = (
        0.80
        if evidence_count == 0
        else 0.65
        if evidence_count == 1
        else 0.45
    )

    cost = 0.10
    risk = 0.05

    value = max(
        0.0,
        min(
            1.0,
            information_gain
            - (0.35 * cost)
            - (0.50 * risk),
        ),
    )

    return ResearchEvaluation(
        information_gain=information_gain,
        cost=cost,
        risk=risk,
        value=value,
        reasons=(
            "fresh execution can reduce unresolved uncertainty",
            "bounded capability cost",
            "low baseline operational risk",
        ),
    )


# ============================================================
# Authorization capability applicability
# ============================================================


def _policy_validation_applicable(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> tuple[bool, tuple[str, ...]]:
    if hypothesis.kind != "authorization_policy_violation":
        return (
            False,
            (
                "hypothesis is not an authorization "
                "policy-violation hypothesis",
            ),
        )

    if hypothesis.status != "OPEN":
        return (
            False,
            ("hypothesis is not open",),
        )

    if not hypothesis.evidence_ids:
        return (
            False,
            ("hypothesis has no originating evidence",),
        )

    return (
        True,
        (
            "hypothesis represents an explicit authorization "
            "policy contradiction",
            "fresh validation can test whether the contradiction "
            "reproduces",
        ),
    )


def _authorization_candidate_applicable(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> tuple[bool, tuple[str, ...]]:
    if hypothesis.kind != "authorization_candidate":
        return (
            False,
            (
                "hypothesis is not an authorization candidate",
            ),
        )

    if hypothesis.status != "OPEN":
        return (
            False,
            ("hypothesis is not open",),
        )

    principal = select_principal(graph)

    if principal is None:
        return (
            False,
            ("no selectable principal is available",),
        )

    return (
        True,
        (
            "hypothesis represents an authorization candidate",
            f"principal {principal.id} is available for testing",
        ),
    )


def _differential_recheck_applicable(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> tuple[bool, tuple[str, ...]]:
    if hypothesis.kind != "authorization_differential":
        return (
            False,
            (
                "hypothesis is not an authorization differential",
            ),
        )

    if hypothesis.status != "OPEN":
        return (
            False,
            ("hypothesis is not open",),
        )

    prefix = "hyp:diff:"

    if not hypothesis.id.startswith(prefix):
        return (
            False,
            ("differential hypothesis ID lacks canonical "
             "resource/action encoding",),
        )

    remainder = hypothesis.id[len(prefix):]

    if ":" not in remainder:
        return (
            False,
            ("differential hypothesis lacks an action component",),
        )

    resource_id, action = remainder.rsplit(":", 1)

    if not resource_id or not action:
        return (
            False,
            ("differential hypothesis contains an empty "
             "resource or action",),
        )

    principal = select_principal(graph)

    if principal is None:
        return (
            False,
            ("no selectable principal is available",),
        )

    return (
        True,
        (
            "hypothesis represents an authorization differential",
            f"resource {resource_id} and action {action} "
            "are recoverable from canonical hypothesis identity",
            f"principal {principal.id} is available for recheck",
        ),
    )


# ============================================================
# Authorization capability planners
# ============================================================


def _plan_policy_validation(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> Experiment | None:
    return plan_authorization_policy_validation(
        graph,
        hypothesis,
    )


def _plan_authorization_candidate(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> Experiment | None:
    principal = select_principal(graph)

    if principal is None:
        return None

    return plan_authorization_candidate(
        hypothesis,
        principal_id=principal.id,
    )


def _plan_authorization_recheck(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> Experiment | None:
    principal = select_principal(graph)

    if principal is None:
        return None

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


# ============================================================
# Registry
# ============================================================


class ResearchCapabilityRegistry:
    """
    Registry of concrete research capabilities.

    The decision engine can enumerate this registry without knowing
    anything about individual hypothesis kinds.
    """

    def __init__(self):
        self._capabilities: dict[str, ResearchCapability] = {}

    def register(
        self,
        capability: ResearchCapability,
    ) -> None:
        if not capability.id.strip():
            raise ValueError(
                "Capability ID cannot be empty."
            )

        if not capability.action.strip():
            raise ValueError(
                "Capability action cannot be empty."
            )

        if not capability.executor_kind.strip():
            raise ValueError(
                "Capability executor kind cannot be empty."
            )

        if capability.id in self._capabilities:
            raise ValueError(
                f"Capability already registered: {capability.id}"
            )

        self._capabilities[capability.id] = capability

    def get(
        self,
        capability_id: str,
    ) -> ResearchCapability:
        try:
            return self._capabilities[capability_id]
        except KeyError:
            raise KeyError(
                f"No research capability registered: "
                f"{capability_id}"
            )

    def supports(
        self,
        capability_id: str,
    ) -> bool:
        return capability_id in self._capabilities

    def all(self) -> tuple[ResearchCapability, ...]:
        return tuple(
            self._capabilities[key]
            for key in sorted(self._capabilities)
        )

    def ids(self) -> tuple[str, ...]:
        return tuple(
            capability.id
            for capability in self.all()
        )

    def plan(
        self,
        graph: SecurityGraph,
        hypothesis: Hypothesis,
        capability_id: str,
    ) -> Experiment | None:
        capability = self.get(capability_id)

        return capability.plan(
            graph,
            hypothesis,
        )


DEFAULT_RESEARCH_CAPABILITIES = (
    ResearchCapabilityRegistry()
)

DEFAULT_RESEARCH_CAPABILITIES.register(
    ResearchCapability(
        id="authorization.candidate_check",
        action="test_authorization_candidate",
        executor_kind="authorization_candidate_check",
        applicable=_authorization_candidate_applicable,
        evaluate_fn=_default_research_evaluation,
        planner=_plan_authorization_candidate,
    )
)

DEFAULT_RESEARCH_CAPABILITIES.register(
    ResearchCapability(
        id="authorization.differential_recheck",
        action="recheck_authorization",
        executor_kind="authorization_recheck",
        applicable=_differential_recheck_applicable,
        evaluate_fn=_default_research_evaluation,
        planner=_plan_authorization_recheck,
    )
)

DEFAULT_RESEARCH_CAPABILITIES.register(
    ResearchCapability(
        id="authorization.policy_validation",
        action="validate_hypothesis",
        executor_kind="authorization_http_check",
        applicable=_policy_validation_applicable,
        evaluate_fn=_default_research_evaluation,
        planner=_plan_policy_validation,
        judge_fn=_judge_policy_validation,
    )
)
