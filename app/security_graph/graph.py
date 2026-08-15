from dataclasses import dataclass, field

from .models import (
    Action,
    Endpoint,
    Evidence,
    Observation,
    Principal,
    Relationship,
    Resource,
    Session,
)


@dataclass
class SecurityGraph:
    principals: dict[str, Principal] = field(default_factory=dict)
    resources: dict[str, Resource] = field(default_factory=dict)
    actions: dict[str, Action] = field(default_factory=dict)
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    sessions: dict[str, Session] = field(default_factory=dict)
    relationships: set[Relationship] = field(default_factory=set)
    evidence: dict[str, Evidence] = field(default_factory=dict)
    observations: dict[str, Observation] = field(default_factory=dict)

    def add_principal(self, principal: Principal) -> None:
        self.principals[principal.id] = principal

    def add_resource(self, resource: Resource) -> None:
        self.resources[resource.id] = resource

    def add_action(self, action: Action) -> None:
        self.actions[action.name] = action

    def add_endpoint(self, endpoint: Endpoint) -> None:
        self.endpoints[endpoint.id] = endpoint

    def add_session(self, session: Session) -> None:
        self.sessions[session.id] = session

    def add_relationship(self, relationship: Relationship) -> None:
        self.relationships.add(relationship)

    def add_evidence(self, evidence: Evidence) -> None:
        self.evidence[evidence.id] = evidence

    def add_observation(self, observation: Observation) -> None:
        self.observations[observation.id] = observation

    def summary(self) -> dict[str, int]:
        return {
            "principals": len(self.principals),
            "resources": len(self.resources),
            "actions": len(self.actions),
            "endpoints": len(self.endpoints),
            "sessions": len(self.sessions),
            "relationships": len(self.relationships),
            "evidence": len(self.evidence),
            "observations": len(self.observations),
        }
