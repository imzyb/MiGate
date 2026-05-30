from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  protocol TEXT NOT NULL,
  name TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  credential TEXT NOT NULL,
  share_link TEXT NOT NULL,
  subscription TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


@dataclass(frozen=True)
class NodeRecord:
    id: int
    protocol: str
    name: str
    host: str
    port: int
    credential: str
    share_link: str
    subscription: str
    enabled: bool
    created_at: str


class NodeRepository:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def create_node(
        self,
        *,
        protocol: str,
        name: str,
        host: str,
        port: int,
        credential: str,
        share_link: str,
        subscription: str,
    ) -> NodeRecord:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO nodes (protocol, name, host, port, credential, share_link, subscription)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (protocol, name, host, port, credential, share_link, subscription),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("failed to create node record")
            node_id = int(cursor.lastrowid)
            row = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        return self._row_to_node(row)

    def list_nodes(self) -> list[NodeRecord]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM nodes ORDER BY id DESC").fetchall()
        return [self._row_to_node(row) for row in rows]

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_node(row: sqlite3.Row) -> NodeRecord:
        return NodeRecord(
            id=int(row["id"]),
            protocol=str(row["protocol"]),
            name=str(row["name"]),
            host=str(row["host"]),
            port=int(row["port"]),
            credential=str(row["credential"]),
            share_link=str(row["share_link"]),
            subscription=str(row["subscription"]),
            enabled=bool(row["enabled"]),
            created_at=str(row["created_at"]),
        )
