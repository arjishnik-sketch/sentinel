import json
import sqlite3
from pathlib import Path

from .graph import SecurityGraph
from .models import (
    Action,
    AuthorizationObservation,
    Endpoint,
    Evidence,
    Experiment,
    Observation,
    Principal,
    Relationship,
    Resource,
    Session,
)


class GraphStore:
    def __init__(self, path="security_graph.db"):
        self.path = Path(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS principals (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                roles TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS resources (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                name TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS actions (
                name TEXT PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS endpoints (
                id TEXT PRIMARY KEY,
                method TEXT NOT NULL,
                url TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                principal_id TEXT
            );

            CREATE TABLE IF NOT EXISTS relationships (
                source TEXT NOT NULL,
                relation TEXT NOT NULL,
                target TEXT NOT NULL,
                metadata TEXT NOT NULL,
                PRIMARY KEY (source, relation, target)
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                data TEXT NOT NULL,
                confidence REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS observations (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                subject TEXT NOT NULL,
                data TEXT,
                evidence_ids TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS authorization_observations (
                id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                action TEXT NOT NULL,
                allowed INTEGER NOT NULL,
                status_code INTEGER,
                endpoint_id TEXT,
                evidence_ids TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS experiments (
                id TEXT PRIMARY KEY,
                hypothesis_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence_ids TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def save(self, graph: SecurityGraph):
        with self.conn:
            self.conn.execute("DELETE FROM principals")
            self.conn.execute("DELETE FROM resources")
            self.conn.execute("DELETE FROM actions")
            self.conn.execute("DELETE FROM endpoints")
            self.conn.execute("DELETE FROM sessions")
            self.conn.execute("DELETE FROM relationships")
            self.conn.execute("DELETE FROM evidence")
            self.conn.execute("DELETE FROM observations")
            self.conn.execute(
                "DELETE FROM authorization_observations"
            )
            self.conn.execute("DELETE FROM experiments")

            for item in graph.principals.values():
                self.conn.execute(
                    """
                    INSERT INTO principals
                    (id, name, kind, roles)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        item.id,
                        item.name,
                        item.kind,
                        json.dumps(item.roles),
                    ),
                )

            for item in graph.resources.values():
                self.conn.execute(
                    """
                    INSERT INTO resources
                    (id, type, name)
                    VALUES (?, ?, ?)
                    """,
                    (item.id, item.type, item.name),
                )

            for item in graph.actions.values():
                self.conn.execute(
                    "INSERT INTO actions (name) VALUES (?)",
                    (item.name,),
                )

            for item in graph.endpoints.values():
                self.conn.execute(
                    """
                    INSERT INTO endpoints
                    (id, method, url)
                    VALUES (?, ?, ?)
                    """,
                    (item.id, item.method, item.url),
                )

            for item in graph.sessions.values():
                self.conn.execute(
                    """
                    INSERT INTO sessions
                    (id, principal_id)
                    VALUES (?, ?)
                    """,
                    (item.id, item.principal_id),
                )

            for item in graph.relationships:
                self.conn.execute(
                    """
                    INSERT INTO relationships
                    (source, relation, target, metadata)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        item.source,
                        item.relation,
                        item.target,
                        json.dumps(dict(item.metadata)),
                    ),
                )

            for item in graph.evidence.values():
                self.conn.execute(
                    """
                    INSERT INTO evidence
                    (id, source, data, confidence)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        item.id,
                        item.source,
                        json.dumps(item.data),
                        item.confidence,
                    ),
                )

            for item in graph.observations.values():
                self.conn.execute(
                    """
                    INSERT INTO observations
                    (id, kind, subject, data, evidence_ids)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        item.id,
                        item.kind,
                        item.subject,
                        json.dumps(item.data),
                        json.dumps(item.evidence_ids),
                    ),
                )

            for item in graph.authorization_observations.values():
                self.conn.execute(
                    """
                    INSERT INTO authorization_observations
                    (
                        id,
                        principal_id,
                        resource_id,
                        action,
                        allowed,
                        status_code,
                        endpoint_id,
                        evidence_ids
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item.id,
                        item.principal_id,
                        item.resource_id,
                        item.action,
                        int(item.allowed),
                        item.status_code,
                        item.endpoint_id,
                        json.dumps(item.evidence_ids),
                    ),
                )

            for item in graph.experiments.values():
                self.conn.execute(
                    """
                    INSERT INTO experiments
                    (
                        id,
                        hypothesis_id,
                        kind,
                        description,
                        status,
                        evidence_ids
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item.id,
                        item.hypothesis_id,
                        item.kind,
                        item.description,
                        item.status,
                        json.dumps(item.evidence_ids),
                    ),
                )

    def load(self) -> SecurityGraph:
        graph = SecurityGraph()

        for row in self.conn.execute(
            "SELECT id, name, kind, roles FROM principals"
        ):
            graph.add_principal(
                Principal(
                    id=row["id"],
                    name=row["name"],
                    kind=row["kind"],
                    roles=tuple(json.loads(row["roles"])),
                )
            )

        for row in self.conn.execute(
            "SELECT id, type, name FROM resources"
        ):
            graph.add_resource(
                Resource(
                    id=row["id"],
                    type=row["type"],
                    name=row["name"],
                )
            )

        for row in self.conn.execute("SELECT name FROM actions"):
            graph.add_action(Action(row["name"]))

        for row in self.conn.execute(
            "SELECT id, method, url FROM endpoints"
        ):
            graph.add_endpoint(
                Endpoint(
                    id=row["id"],
                    method=row["method"],
                    url=row["url"],
                )
            )

        for row in self.conn.execute(
            "SELECT id, principal_id FROM sessions"
        ):
            graph.add_session(
                Session(
                    id=row["id"],
                    principal_id=row["principal_id"],
                )
            )

        for row in self.conn.execute(
            """
            SELECT source, relation, target, metadata
            FROM relationships
            """
        ):
            metadata = json.loads(row["metadata"])

            graph.add_relationship(
                Relationship(
                    source=row["source"],
                    relation=row["relation"],
                    target=row["target"],
                    metadata=tuple(sorted(metadata.items())),
                )
            )

        for row in self.conn.execute(
            "SELECT id, source, data, confidence FROM evidence"
        ):
            graph.add_evidence(
                Evidence(
                    id=row["id"],
                    source=row["source"],
                    data=json.loads(row["data"]),
                    confidence=row["confidence"],
                )
            )

        for row in self.conn.execute(
            """
            SELECT id, kind, subject, data, evidence_ids
            FROM observations
            """
        ):
            graph.add_observation(
                Observation(
                    id=row["id"],
                    kind=row["kind"],
                    subject=row["subject"],
                    data=(
                        json.loads(row["data"])
                        if row["data"] is not None
                        else None
                    ),
                    evidence_ids=tuple(
                        json.loads(row["evidence_ids"])
                    ),
                )
            )

        for row in self.conn.execute(
            """
            SELECT
                id,
                principal_id,
                resource_id,
                action,
                allowed,
                status_code,
                endpoint_id,
                evidence_ids
            FROM authorization_observations
            """
        ):
            graph.add_authorization_observation(
                AuthorizationObservation(
                    id=row["id"],
                    principal_id=row["principal_id"],
                    resource_id=row["resource_id"],
                    action=row["action"],
                    allowed=bool(row["allowed"]),
                    status_code=row["status_code"],
                    endpoint_id=row["endpoint_id"],
                    evidence_ids=tuple(
                        json.loads(row["evidence_ids"])
                    ),
                )
            )

        for row in self.conn.execute(
            """
            SELECT
                id,
                hypothesis_id,
                kind,
                description,
                status,
                evidence_ids
            FROM experiments
            """
        ):
            graph.add_experiment(
                Experiment(
                    id=row["id"],
                    hypothesis_id=row["hypothesis_id"],
                    kind=row["kind"],
                    description=row["description"],
                    status=row["status"],
                    evidence_ids=tuple(
                        json.loads(row["evidence_ids"])
                    ),
                )
            )

        return graph

    def close(self):
        self.conn.close()
