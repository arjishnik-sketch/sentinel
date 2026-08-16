from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Principal:
    id: str
    name: str = ""
    kind: str = "user"
    roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class Resource:
    id: str
    type: str
    name: str = ""


@dataclass(frozen=True)
class Action:
    name: str


@dataclass(frozen=True)
class Endpoint:
    id: str
    method: str
    url: str


@dataclass(frozen=True)
class Session:
    id: str
    principal_id: str | None = None


@dataclass(frozen=True)
class Relationship:
    source: str
    relation: str
    target: str
    metadata: tuple[tuple[str, Any], ...] = ()


@dataclass(frozen=True)
class Evidence:
    id: str
    source: str
    data: Any
    confidence: float = 1.0


@dataclass(frozen=True)
class Observation:
    id: str
    kind: str
    subject: str
    data: Any = None
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthorizationObservation:
    id: str
    principal_id: str
    resource_id: str
    action: str
    allowed: bool
    status_code: int | None = None
    endpoint_id: str | None = None
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class HypothesisIdentity:
    """
    Canonical semantic identity for a security hypothesis.

    This is deliberately separate from the hypothesis ID so that
    independently generated hypotheses can be recognized as the
    same underlying security claim.
    """
    kind: str
    principal_id: str | None = None
    resource_id: str | None = None
    action: str | None = None


@dataclass(frozen=True)
class SecurityFinding:
    """
    Durable security finding derived from a validated hypothesis.

    A finding is a reporting-level security claim, not a raw
    observation. It must retain the hypothesis and evidence
    provenance that justify the claim.
    """
    id: str
    hypothesis_id: str
    kind: str
    title: str
    claim: str
    severity: str
    confidence: float
    identity: HypothesisIdentity | None = None
    evidence_ids: tuple[str, ...] = ()
    status: str = "OPEN"


@dataclass(frozen=True)
class FindingMaterialization:
    """
    Result of materializing confirmed hypotheses into findings.

    Created findings are new security claims.
    Updated findings gained new or stronger evidence/state.
    Unchanged findings were already fully represented.
    """
    created: tuple[SecurityFinding, ...] = ()
    updated: tuple[SecurityFinding, ...] = ()
    unchanged: tuple[SecurityFinding, ...] = ()


@dataclass(frozen=True)
class Hypothesis:
    id: str
    kind: str
    claim: str
    confidence: float
    evidence_ids: tuple[str, ...] = ()
    identity: HypothesisIdentity | None = None
    source_ids: tuple[str, ...] = ()
    status: str = "OPEN"


@dataclass(frozen=True)
class HttpRequestSpec:
    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    body: str | None = None
    timeout: float = 10.0
    principal_id: str | None = None
    resource_id: str | None = None
    action: str | None = None
    expected_statuses: tuple[int, ...] = ()
    expected_outcome: str | None = None


@dataclass(frozen=True)
class Experiment:
    id: str
    hypothesis_id: str
    kind: str
    description: str
    status: str = "PLANNED"
    evidence_ids: tuple[str, ...] = ()
    request: HttpRequestSpec | None = None


@dataclass(frozen=True)
class ExecutionResult:
    experiment_id: str
    status: str
    evidence: tuple[Evidence, ...] = ()
    metadata: tuple[tuple[str, Any], ...] = ()


@dataclass(frozen=True)
class WorkflowPlan:
    id: str
    workflow: str
    priority: str
    interesting: tuple[str, ...] = ()
    tests: tuple[str, ...] = ()


@dataclass(frozen=True)
class HypothesisScore:
    hypothesis_id: str
    score: float
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResearchEvaluation:
    """
    Capability-specific evaluation of a possible research action.

    Values are bounded in [0.0, 1.0].

    information_gain:
        Expected reduction in uncertainty produced by the action.

    cost:
        Expected computational, network, time, or operational cost.

    risk:
        Expected operational or target-side risk.

    value:
        Final decision value used by the research controller.
    """
    information_gain: float
    cost: float
    risk: float
    value: float
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResearchCandidate:
    """
    A possible next research action derived from current graph state.

    The candidate describes WHAT Sentinel wants to accomplish.
    Concrete execution details belong to the capability layer.
    """
    id: str
    hypothesis_id: str
    action: str
    capability_id: str
    score: float = 0.0
    rationale: tuple[str, ...] = ()
    evaluation: ResearchEvaluation | None = None


@dataclass(frozen=True)
class ResearchDecision:
    """
    The controller's explicit choice of the next research action.

    This records what Sentinel chose and why without coupling the
    reasoning layer directly to a concrete executor implementation.
    """
    candidate_id: str
    hypothesis_id: str
    action: str
    capability_id: str
    score: float
    rationale: tuple[str, ...] = ()
    rejected_candidate_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ValidationJudgment:
    hypothesis_id: str
    experiment_id: str
    status: str
    reason: str
    contradiction_kind: str = "authorization"
    expected: bool | None = None
    observed: bool | None = None
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class InvestigationCycleResult:
    hypothesis_id: str
    experiment_id: str
    execution: ExecutionResult
    research_decision: ResearchDecision | None = None
    judgment: ValidationJudgment | None = None
    observation_ids: tuple[str, ...] = ()
    new_hypothesis_ids: tuple[str, ...] = ()
    finding_materialization: FindingMaterialization | None = None
