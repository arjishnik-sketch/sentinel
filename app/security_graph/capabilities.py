from dataclasses import dataclass
from typing import Callable

from .graph import SecurityGraph
from .models import (
    ExecutionResult,
    Experiment,
    Hypothesis,
    AuthorizationObservation,
    Observation,
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
from .analysis.observations import (
    authorization_observation_from_evidence,
    authorization_validation_decision_from_evidence,
)
from .analysis.refinement import refine_authorization_candidates


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


Observe = Callable[
    [SecurityGraph, "ExecutionResult"],
    tuple["Observation", ...],
]

Judge = Callable[
    [SecurityGraph, Hypothesis, Experiment],
    ValidationJudgment | None,
]

Refine = Callable[
    [SecurityGraph, Hypothesis, tuple["Observation", ...]],
    tuple[Hypothesis, ...],
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
    observe_fn: Observe | None = None
    judge_fn: Judge | None = None
    refine_fn: Refine | None = None

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

    def observe(
        self,
        graph: SecurityGraph,
        result: "ExecutionResult",
    ) -> tuple["Observation", ...]:
        if self.observe_fn is None:
            return ()

        return self.observe_fn(
            graph,
            result,
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

    def refine(
        self,
        graph: SecurityGraph,
        hypothesis: Hypothesis,
        observations: tuple["Observation", ...],
    ) -> tuple[Hypothesis, ...]:
        if self.refine_fn is None:
            return ()

        return self.refine_fn(
            graph,
            hypothesis,
            observations,
        )


def _observe_authorization(
    graph: SecurityGraph,
    result: ExecutionResult,
) -> tuple[Observation, ...]:
    """
    Convert execution evidence into graph observations.

    This preserves the existing authorization observation semantics,
    including the special HTTP validation path, but makes the
    capability the owner of post-execution interpretation.
    """

    observations: list[Observation] = []

    experiment = graph.experiments.get(
        result.experiment_id
    )

    for evidence in result.evidence:
        if evidence.id not in graph.evidence:
            graph.add_evidence(evidence)

        observation = None

        if (
            experiment is not None
            and experiment.kind == "authorization_http_check"
            and experiment.request is not None
            and experiment.request.expected_outcome is not None
        ):
            allowed = (
                authorization_validation_decision_from_evidence(
                    evidence
                )
            )

            if allowed is None:
                continue

            request = experiment.request

            if (
                request.principal_id is None
                or request.resource_id is None
                or request.action is None
            ):
                continue

            data = evidence.data

            observation = AuthorizationObservation(
                id=f"authobs:{evidence.id}",
                principal_id=request.principal_id,
                resource_id=request.resource_id,
                action=request.action,
                allowed=allowed,
                status_code=data.get("status_code"),
                endpoint_id=data.get("endpoint_id"),
                evidence_ids=(evidence.id,),
            )
        else:
            observation = authorization_observation_from_evidence(
                evidence
            )

        if observation is None:
            continue

        if observation.id in graph.authorization_observations:
            continue

        graph.add_authorization_observation(
            observation
        )
        observations.append(observation)

    return tuple(observations)


def _refine_authorization(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
    observations: tuple[Observation, ...],
) -> tuple[Hypothesis, ...]:
    """
    Preserve the existing authorization refinement behavior behind
    the capability boundary.

    The legacy refiner is currently graph-global, so the capability
    adapter deliberately passes the graph through unchanged.
    """

    return tuple(
        refine_authorization_candidates(graph)
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
# Capability-owned research valuation
# ============================================================

def _research_evaluation(
    *,
    information_gain: float,
    cost: float,
    risk: float,
    reasons: tuple[str, ...],
) -> ResearchEvaluation:
    """
    Convert capability-owned research characteristics into a
    deterministic bounded research value.

    The decision engine does not know this formula or the domain.
    Capabilities own the characteristics of their research action.
    """

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
        reasons=reasons,
    )


def _evaluate_candidate_check(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> ResearchEvaluation:
    return _research_evaluation(
        information_gain=0.60,
        cost=0.20,
        risk=0.05,
        reasons=(
            "candidate check can establish whether an "
            "authorization candidate is reproducible",
            "bounded HTTP validation cost",
            "low baseline operational risk",
        ),
    )


def _evaluate_differential_recheck(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> ResearchEvaluation:
    return _research_evaluation(
        information_gain=0.72,
        cost=0.20,
        risk=0.05,
        reasons=(
            "differential recheck can distinguish authorization "
            "behavior across principals or contexts",
            "moderate validation cost",
            "low baseline operational risk",
        ),
    )


def _evaluate_policy_validation(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> ResearchEvaluation:
    return _research_evaluation(
        information_gain=0.88,
        cost=0.10,
        risk=0.05,
        reasons=(
            "fresh validation directly tests an explicit policy "
            "contradiction",
            "high expected uncertainty reduction",
            "low bounded validation cost",
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
        evaluate_fn=_evaluate_candidate_check,
        planner=_plan_authorization_candidate,
        observe_fn=_observe_authorization,
        refine_fn=_refine_authorization,
    )
)

DEFAULT_RESEARCH_CAPABILITIES.register(
    ResearchCapability(
        id="authorization.differential_recheck",
        action="recheck_authorization",
        executor_kind="authorization_recheck",
        applicable=_differential_recheck_applicable,
        evaluate_fn=_evaluate_differential_recheck,
        planner=_plan_authorization_recheck,
        observe_fn=_observe_authorization,
        refine_fn=_refine_authorization,
    )
)

DEFAULT_RESEARCH_CAPABILITIES.register(
    ResearchCapability(
        id="authorization.policy_validation",
        action="validate_hypothesis",
        executor_kind="authorization_http_check",
        applicable=_policy_validation_applicable,
        evaluate_fn=_evaluate_policy_validation,
        planner=_plan_policy_validation,
        observe_fn=_observe_authorization,
        judge_fn=_judge_policy_validation,
        refine_fn=_refine_authorization,
    )
)
