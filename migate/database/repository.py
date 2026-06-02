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
  socks5_host TEXT NOT NULL DEFAULT '',
  socks5_port INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

MIGRATIONS = (
    "ALTER TABLE nodes ADD COLUMN socks5_host TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE nodes ADD COLUMN socks5_port INTEGER",
)

INBOUND_SCHEMA = """
CREATE TABLE IF NOT EXISTS inbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  remark TEXT NOT NULL,
  protocol TEXT NOT NULL,
  port INTEGER NOT NULL,
  listen TEXT NOT NULL DEFAULT '0.0.0.0',
  settings TEXT NOT NULL DEFAULT '{}',
  stream_settings TEXT NOT NULL DEFAULT '{}',
  enabled INTEGER NOT NULL DEFAULT 1,
  up_bytes INTEGER NOT NULL DEFAULT 0,
  down_bytes INTEGER NOT NULL DEFAULT 0,
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
    socks5_host: str = ""
    socks5_port: int | None = None


@dataclass(frozen=True)
class InboundRecord:
    id: int
    remark: str
    protocol: str
    port: int
    listen: str
    settings: str
    stream_settings: str
    enabled: bool
    up_bytes: int
    down_bytes: int
    created_at: str


class NodeRepository:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(nodes)").fetchall()}
            if "socks5_host" not in existing_columns:
                conn.execute(MIGRATIONS[0])
            if "socks5_port" not in existing_columns:
                conn.execute(MIGRATIONS[1])

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
        socks5_host: str = "",
        socks5_port: int | None = None,
    ) -> NodeRecord:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO nodes (protocol, name, host, port, credential, share_link, subscription, socks5_host, socks5_port)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (protocol, name, host, port, credential, share_link, subscription, socks5_host, socks5_port),
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

    def get_node(self, node_id: int) -> NodeRecord | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        return self._row_to_node(row) if row is not None else None

    def set_node_enabled(self, node_id: int, enabled: bool) -> NodeRecord | None:
        with self._connect() as conn:
            conn.execute("UPDATE nodes SET enabled = ? WHERE id = ?", (1 if enabled else 0, node_id))
            row = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        return self._row_to_node(row) if row is not None else None

    def update_node(
        self,
        node_id: int,
        *,
        protocol: str,
        name: str,
        host: str,
        port: int,
        credential: str,
        share_link: str,
        subscription: str,
        socks5_host: str = "",
        socks5_port: int | None = None,
    ) -> NodeRecord | None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE nodes
                SET protocol = ?, name = ?, host = ?, port = ?, credential = ?, share_link = ?, subscription = ?, socks5_host = ?, socks5_port = ?
                WHERE id = ?
                """,
                (protocol, name, host, port, credential, share_link, subscription, socks5_host, socks5_port, node_id),
            )
            row = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        return self._row_to_node(row) if row is not None else None

    def delete_node(self, node_id: int) -> NodeRecord | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
            if row is None:
                return None
            node = self._row_to_node(row)
            conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
        return node

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
            socks5_host=str(row["socks5_host"] or ""),
            socks5_port=int(row["socks5_port"]) if row["socks5_port"] is not None else None,
            enabled=bool(row["enabled"]),
            created_at=str(row["created_at"]),
        )


class InboundRepository:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(INBOUND_SCHEMA)

    def create_inbound(
        self,
        *,
        remark: str,
        protocol: str,
        port: int,
        listen: str = "0.0.0.0",
        settings: str = "{}",
        stream_settings: str = "{}",
    ) -> InboundRecord:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO inbounds (remark, protocol, port, listen, settings, stream_settings)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (remark, protocol, port, listen, settings, stream_settings),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("failed to create inbound record")
            row = conn.execute("SELECT * FROM inbounds WHERE id = ?", (int(cursor.lastrowid),)).fetchone()
        return self._row_to_inbound(row)

    def list_inbounds(self) -> list[InboundRecord]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM inbounds ORDER BY id DESC").fetchall()
        return [self._row_to_inbound(row) for row in rows]

    def get_inbound(self, inbound_id: int) -> InboundRecord | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM inbounds WHERE id = ?", (inbound_id,)).fetchone()
        return self._row_to_inbound(row) if row is not None else None

    def update_inbound(
        self,
        inbound_id: int,
        *,
        remark: str,
        protocol: str,
        port: int,
        listen: str = "0.0.0.0",
        settings: str = "{}",
        stream_settings: str = "{}",
    ) -> InboundRecord | None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE inbounds
                SET remark = ?, protocol = ?, port = ?, listen = ?, settings = ?, stream_settings = ?
                WHERE id = ?
                """,
                (remark, protocol, port, listen, settings, stream_settings, inbound_id),
            )
            row = conn.execute("SELECT * FROM inbounds WHERE id = ?", (inbound_id,)).fetchone()
        return self._row_to_inbound(row) if row is not None else None

    def delete_inbound(self, inbound_id: int) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT id FROM inbounds WHERE id = ?", (inbound_id,)).fetchone()
            if row is None:
                return False
            conn.execute("DELETE FROM inbounds WHERE id = ?", (inbound_id,))
        return True

    def set_inbound_enabled(self, inbound_id: int, *, enabled: bool) -> InboundRecord | None:
        with self._connect() as conn:
            conn.execute("UPDATE inbounds SET enabled = ? WHERE id = ?", (1 if enabled else 0, inbound_id))
            row = conn.execute("SELECT * FROM inbounds WHERE id = ?", (inbound_id,)).fetchone()
        return self._row_to_inbound(row) if row is not None else None

    def update_traffic(self, inbound_id: int, *, up_bytes: int = 0, down_bytes: int = 0) -> InboundRecord | None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE inbounds SET up_bytes = up_bytes + ?, down_bytes = down_bytes + ? WHERE id = ?",
                (up_bytes, down_bytes, inbound_id),
            )
            row = conn.execute("SELECT * FROM inbounds WHERE id = ?", (inbound_id,)).fetchone()
        return self._row_to_inbound(row) if row is not None else None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_inbound(row: sqlite3.Row) -> InboundRecord:
        return InboundRecord(
            id=int(row["id"]),
            remark=str(row["remark"]),
            protocol=str(row["protocol"]),
            port=int(row["port"]),
            listen=str(row["listen"]),
            settings=str(row["settings"]),
            stream_settings=str(row["stream_settings"]),
            enabled=bool(row["enabled"]),
            up_bytes=int(row["up_bytes"]),
            down_bytes=int(row["down_bytes"]),
            created_at=str(row["created_at"]),
        )
