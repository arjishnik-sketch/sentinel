import json
import sqlite3
from pathlib import Path

from .graph import SecurityGraph
from .models import (
    Action,
    Endpoint,
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

            for item in graph.principals.values():
                self.conn.execute(
                    """
                    INSERT INTO principals (id, name, kind, roles)
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
                    INSERT INTO resources (id, type, name)
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
                    INSERT INTO endpoints (id, method, url)
                    VALUES (?, ?, ?)
                    """,
                    (item.id, item.method, item.url),
                )

            for item in graph.sessions.values():
                self.conn.execute(
                    """
                    INSERT INTO sessions (id, principal_id)
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

        return graph

    def close(self):
        self.conn.close()
