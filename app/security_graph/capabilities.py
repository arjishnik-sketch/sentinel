from dataclasses import dataclass
from typing import Callable

from .graph import SecurityGraph
from .models import Experiment, Hypothesis
from .planning import (
    plan_authorization_candidate,
    plan_authorization_policy_validation,
    plan_authorization_recheck,
)
from .policy import select_principal


Planner = Callable[
    [SecurityGraph, Hypothesis],
    Experiment | None,
]


@dataclass(frozen=True)
class ResearchCapability:
    """
    A capability Sentinel can deliberately invoke.

    The decision layer selects a capability by ID.
    The capability owns the concrete planning and executor contract.
    """

    id: str
    action: str
    executor_kind: str
    planner: Planner

    def plan(
        self,
        graph: SecurityGraph,
        hypothesis: Hypothesis,
    ) -> Experiment | None:
        return self.planner(graph, hypothesis)


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


class ResearchCapabilityRegistry:
    """
    Registry of concrete research capabilities.

    The controller does not need to know how a capability is planned.
    """

    def __init__(self):
        self._capabilities: dict[str, ResearchCapability] = {}

        self.register(
            ResearchCapability(
                id="authorization.policy_validation",
                action="validate_hypothesis",
                executor_kind="authorization_http_check",
                planner=_plan_policy_validation,
            )
        )

        self.register(
            ResearchCapability(
                id="authorization.candidate_check",
                action="test_authorization_candidate",
                executor_kind="authorization_candidate_check",
                planner=_plan_authorization_candidate,
            )
        )

        self.register(
            ResearchCapability(
                id="authorization.differential_recheck",
                action="recheck_authorization",
                executor_kind="authorization_recheck",
                planner=_plan_authorization_recheck,
            )
        )

    def register(
        self,
        capability: ResearchCapability,
    ) -> None:
        if not capability.id.strip():
            raise ValueError(
                "Capability ID cannot be empty."
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

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._capabilities))

    def plan(
        self,
        graph: SecurityGraph,
        hypothesis: Hypothesis,
        capability_id: str,
    ) -> Experiment | None:
        capability = self.get(capability_id)

        if capability.action == "":
            raise ValueError(
                f"Capability has no action: {capability.id}"
            )

        return capability.plan(
            graph,
            hypothesis,
        )


DEFAULT_RESEARCH_CAPABILITIES = ResearchCapabilityRegistry()
