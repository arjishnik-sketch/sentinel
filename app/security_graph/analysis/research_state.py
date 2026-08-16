from dataclasses import dataclass

from ..graph import SecurityGraph
from ..models import Hypothesis


@dataclass(frozen=True)
class ResearchState:
    """
    Domain-independent epistemic projection for one hypothesis.

    This is derived entirely from the SecurityGraph. It is not a
    second source of truth and must not contain capability-specific
    interpretation.
    """

    hypothesis_id: str

    attempts: int
    completed_attempts: int

    observation_count: int
    judgment_count: int

    supporting_judgments: int
    contradicting_judgments: int
    inconclusive_judgments: int

    evidence_count: int

    has_finding: bool
    current_status: str

    @property
    def has_prior_research(self) -> bool:
        return self.attempts > 0

    @property
    def unresolved(self) -> bool:
        return self.current_status == "OPEN"


def build_research_state(
    graph: SecurityGraph,
    hypothesis: Hypothesis,
) -> ResearchState:
    """
    Build the current research state for a hypothesis.

    No security-domain semantics are interpreted here.
    """

    experiments = graph.experiments_for(
        hypothesis_id=hypothesis.id,
    )

    completed_attempts = sum(
        1
        for experiment in experiments
        if experiment.status == "COMPLETED"
    )

    hypothesis_evidence = set(
        hypothesis.evidence_ids
    )

    observations = [
        observation
        for observation in graph.observations.values()
        if observation.id in hypothesis_evidence
    ]

    authorization_observations = [
        observation
        for observation in graph.authorization_observations.values()
        if observation.evidence_ids
        and hypothesis_evidence.intersection(
            observation.evidence_ids
        )
    ]

    observation_count = (
        len(observations)
        + len(authorization_observations)
    )

    judgments = [
        judgment
        for judgment in graph.validation_judgments.values()
        if judgment.hypothesis_id == hypothesis.id
    ]

    supporting = sum(
        1
        for judgment in judgments
        if judgment.status in {
            "VALIDATED",
            "CONFIRMED",
        }
    )

    contradicting = sum(
        1
        for judgment in judgments
        if judgment.status in {
            "REJECTED",
            "DISPROVED",
        }
    )

    inconclusive = sum(
        1
        for judgment in judgments
        if judgment.status == "INCONCLUSIVE"
    )

    has_finding = any(
        finding.hypothesis_id == hypothesis.id
        for finding in graph.findings.values()
    )

    return ResearchState(
        hypothesis_id=hypothesis.id,
        attempts=len(experiments),
        completed_attempts=completed_attempts,
        observation_count=observation_count,
        judgment_count=len(judgments),
        supporting_judgments=supporting,
        contradicting_judgments=contradicting,
        inconclusive_judgments=inconclusive,
        evidence_count=len(hypothesis.evidence_ids),
        has_finding=has_finding,
        current_status=hypothesis.status,
    )
