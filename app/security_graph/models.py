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
class Hypothesis:
    id: str
    kind: str
    claim: str
    confidence: float
    evidence_ids: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()
    status: str = "OPEN"


@dataclass(frozen=True)
class Experiment:
    id: str
    hypothesis_id: str
    kind: str
    description: str
    status: str = "PLANNED"
    evidence_ids: tuple[str, ...] = ()


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
