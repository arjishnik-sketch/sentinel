from dataclasses import dataclass, field

from .models import (
    Action,
    AuthorizationObservation,
    Endpoint,
    Experiment,
    Evidence,
    Hypothesis,
    HypothesisIdentity,
    Observation,
    Principal,
    Relationship,
    Resource,
    Session,
    WorkflowPlan,
    ValidationJudgment,
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
    authorization_observations: dict[str, AuthorizationObservation] = field(default_factory=dict)
    hypotheses: dict[str, Hypothesis] = field(default_factory=dict)
    experiments: dict[str, Experiment] = field(default_factory=dict)
    validation_judgments: dict[str, ValidationJudgment] = field(default_factory=dict)
    workflow_plans: dict[str, WorkflowPlan] = field(default_factory=dict)

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


    def relationships_for(self, node_id: str) -> list[Relationship]:
        return [
            relationship
            for relationship in self.relationships
            if relationship.source == node_id
            or relationship.target == node_id
        ]

    def relationships_from(self, node_id: str) -> list[Relationship]:
        return [
            relationship
            for relationship in self.relationships
            if relationship.source == node_id
        ]

    def relationships_to(self, node_id: str) -> list[Relationship]:
        return [
            relationship
            for relationship in self.relationships
            if relationship.target == node_id
        ]

    def principals_for(self, resource_id: str) -> list[Principal]:
        principal_ids = {
            relationship.source
            for relationship in self.relationships
            if relationship.target == resource_id
            and relationship.source in self.principals
        }

        return [
            self.principals[principal_id]
            for principal_id in sorted(principal_ids)
        ]

    def resources_for(self, principal_id: str) -> list[Resource]:
        resource_ids = {
            relationship.target
            for relationship in self.relationships
            if relationship.source == principal_id
            and relationship.target in self.resources
        }

        return [
            self.resources[resource_id]
            for resource_id in sorted(resource_ids)
        ]

    def observations_for(self, subject: str) -> list[Observation]:
        return [
            observation
            for observation in self.observations.values()
            if observation.subject == subject
        ]


    def add_authorization_observation(
        self,
        observation: AuthorizationObservation,
    ) -> None:
        self.authorization_observations[observation.id] = observation

    def authorization_observations_for(
        self,
        resource_id: str | None = None,
        principal_id: str | None = None,
        action: str | None = None,
    ) -> list[AuthorizationObservation]:
        results = self.authorization_observations.values()

        if resource_id is not None:
            results = [
                item for item in results
                if item.resource_id == resource_id
            ]

        if principal_id is not None:
            results = [
                item for item in results
                if item.principal_id == principal_id
            ]

        if action is not None:
            results = [
                item for item in results
                if item.action == action
            ]

        return list(results)


    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        self.hypotheses[hypothesis.id] = hypothesis

    def find_equivalent_hypothesis(
        self,
        identity: HypothesisIdentity,
    ) -> Hypothesis | None:
        """
        Find an existing hypothesis with the same canonical
        semantic identity.

        Hypothesis IDs are intentionally ignored here because
        independently generated hypotheses may use different IDs
        while representing the same security claim.
        """
        for hypothesis in self.hypotheses.values():
            if hypothesis.identity == identity:
                return hypothesis

        return None


    def hypotheses_for(
        self,
        kind: str | None = None,
        status: str | None = None,
    ) -> list[Hypothesis]:
        results = self.hypotheses.values()

        if kind is not None:
            results = [
                item for item in results
                if item.kind == kind
            ]

        if status is not None:
            results = [
                item for item in results
                if item.status == status
            ]

        return list(results)


    def add_experiment(self, experiment: Experiment) -> None:
        self.experiments[experiment.id] = experiment

    def experiments_for(
        self,
        hypothesis_id: str | None = None,
        status: str | None = None,
    ) -> list[Experiment]:
        results = self.experiments.values()

        if hypothesis_id is not None:
            results = [
                item for item in results
                if item.hypothesis_id == hypothesis_id
            ]

        if status is not None:
            results = [
                item for item in results
                if item.status == status
            ]

        return list(results)


    def add_validation_judgment(
        self,
        judgment: ValidationJudgment,
    ) -> None:
        self.validation_judgments[judgment.experiment_id] = judgment

    def add_workflow_plan(self, plan: WorkflowPlan) -> None:
        self.workflow_plans[plan.id] = plan

    def workflow_plans_for(
        self,
        workflow: str | None = None,
        priority: str | None = None,
    ) -> list[WorkflowPlan]:
        results = self.workflow_plans.values()

        if workflow is not None:
            results = [
                item for item in results
                if item.workflow == workflow
            ]

        if priority is not None:
            results = [
                item for item in results
                if item.priority == priority
            ]

        return list(results)
