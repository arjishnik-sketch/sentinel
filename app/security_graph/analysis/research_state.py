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

    @property
    def research_depth(self) -> int:
        """
        Number of completed research attempts contributing to the
        current hypothesis state.
        """

        return self.completed_attempts

    @property
    def judgment_resolution(self) -> float:
        """
        Structural measure of how consistently prior judgments resolve.

        1.0 means all recorded judgments point in the same direction.
        0.0 means there is an even split between opposing judgments.

        Inconclusive judgments reduce resolution.
        """

        if self.judgment_count == 0:
            return 0.0

        decisive = (
            self.supporting_judgments
            + self.contradicting_judgments
        )

        if decisive == 0:
            return 0.0

        agreement = abs(
            self.supporting_judgments
            - self.contradicting_judgments
        ) / decisive

        decisive_ratio = (
            decisive / self.judgment_count
        )

        return max(
            0.0,
            min(
                1.0,
                agreement * decisive_ratio,
            ),
        )

    @property
    def residual_uncertainty(self) -> float:
        """
        Deterministic structural uncertainty signal.

        This is not a probability of truth. It represents how much
        unresolved research signal remains in the current graph state.
        """

        if self.judgment_count == 0:
            return 1.0

        resolution = self.judgment_resolution

        uncertainty = (
            1.0 - resolution
        )

        if self.inconclusive_judgments:
            uncertainty = max(
                uncertainty,
                self.inconclusive_judgments
                / self.judgment_count,
            )

        return max(
            0.0,
            min(
                1.0,
                uncertainty,
            ),
        )


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

    hypothesis_experiment_ids = {
        experiment.id
        for experiment in experiments
    }

    observations = []

    for observation in graph.observations.values():
        if observation.id in hypothesis_evidence:
            observations.append(observation)
            continue

        data = observation.data

        if not isinstance(data, dict):
            continue

        evidence_id = data.get("evidence_id")

        if (
            isinstance(evidence_id, str)
            and evidence_id in hypothesis_evidence
        ):
            observations.append(observation)
            continue

        experiment_id = data.get("experiment_id")

        if (
            isinstance(experiment_id, str)
            and experiment_id in hypothesis_experiment_ids
        ):
            observations.append(observation)

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
