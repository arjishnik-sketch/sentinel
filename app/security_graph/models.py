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
