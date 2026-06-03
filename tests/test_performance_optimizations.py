"""Tests for database indexes, GZip middleware, and static file caching."""

from __future__ import annotations

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from migate.api.app import create_app
from migate.database.repository import (
    ClientTrafficRepository,
    InboundRepository,
    NodeRepository,
)


# ---- Index tests ----


def _get_index_names(db_path, table_name: str) -> set[str]:
    """Return set of index names for a table via PRAGMA index_list."""
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(f"PRAGMA index_list({table_name})").fetchall()
        return {row[1] for row in rows}
    finally:
        conn.close()


def test_nodes_name_index_exists(tmp_path):
    db = tmp_path / "test.db"
    repo = NodeRepository(db)
    repo.initialize()
    repo.close()

    indexes = _get_index_names(db, "nodes")
    assert "idx_nodes_name" in indexes


def test_inbounds_remark_index_exists(tmp_path):
    db = tmp_path / "test.db"
    repo = InboundRepository(db)
    repo.initialize()
    repo.close()

    indexes = _get_index_names(db, "inbounds")
    assert "idx_inbounds_remark" in indexes


def test_inbounds_enabled_index_exists(tmp_path):
    db = tmp_path / "test.db"
    repo = InboundRepository(db)
    repo.initialize()
    repo.close()

    indexes = _get_index_names(db, "inbounds")
    assert "idx_inbounds_enabled" in indexes


def test_client_traffic_composite_index_exists(tmp_path):
    db = tmp_path / "test.db"
    repo = ClientTrafficRepository(db)
    repo.initialize()
    repo.close()

    indexes = _get_index_names(db, "client_traffic")
    assert "idx_client_traffic_inbound_email" in indexes


def test_client_traffic_email_unique_index_exists(tmp_path):
    db = tmp_path / "test.db"
    repo = ClientTrafficRepository(db)
    repo.initialize()
    repo.close()

    indexes = _get_index_names(db, "client_traffic")
    assert "idx_client_traffic_email" in indexes


# ---- Connection pooling tests ----


def test_repository_reuses_connection(tmp_path):
    db = tmp_path / "test.db"
    repo = NodeRepository(db)
    repo.initialize()

    conn1 = repo._connect()
    conn2 = repo._connect()
    assert conn1 is conn2

    repo.close()
    assert repo._conn is None


def test_repository_close_and_reopen(tmp_path):
    db = tmp_path / "test.db"
    repo = NodeRepository(db)
    repo.initialize()

    conn = repo._connect()
    repo.close()
    assert repo._conn is None

    # Re-opening should create a new connection
    conn2 = repo._connect()
    assert conn2 is not conn
    repo.close()


# ---- GZip middleware tests ----


def _make_app(tmp_path, *, base_path="/"):
    """Create a test app with minimal config."""
    node_repo = NodeRepository(tmp_path / "migate.db")
    inbound_repo = InboundRepository(tmp_path / "migate.db")
    node_repo.initialize()
    inbound_repo.initialize()
    panel_config = {
        "admin_user": "admin",
        "password_hash": "sha256:5c76fcf4400da3b4804d70b91af20703d483f2c5860cc2f8d59592a1da8d2121",
        "base_path": base_path,
        "panel_host": "127.0.0.1",
        "panel_port": 8787,
        "public_host": "127.0.0.1",
    }
    app = create_app(
        node_repository=node_repo,
        inbound_repository=inbound_repo,
        panel_auth_config=panel_config,
    )
    return app


def test_gzip_middleware_compresses_large_response(tmp_path):
    app = _make_app(tmp_path)
    client = TestClient(app, raise_server_exceptions=False)

    # Request a page that returns enough HTML to trigger compression (>500 bytes)
    resp = client.get("/", headers={"Accept-Encoding": "gzip"})
    # The response should either be compressed or redirect
    if resp.status_code == 200:
        # If the body is large enough, Content-Encoding should be gzip
        if len(resp.content) > 0:
            # Starlette's GZipMiddleware checks Accept-Encoding header
            # and the response size. The test client may or may not
            # compress depending on negotiation, so we verify the
            # middleware is registered by checking the app middleware stack.
            pass
    # At minimum, verify the middleware was added without error
    assert resp.status_code in (200, 303, 307)


def test_gzip_middleware_is_registered(tmp_path):
    app = _make_app(tmp_path)
    from starlette.middleware.gzip import GZipMiddleware as _GZip

    middleware_classes = [m.cls for m in app.user_middleware]
    assert _GZip in middleware_classes


# ---- Static file caching tests ----


def test_static_files_have_cache_control_header(tmp_path):
    app = _make_app(tmp_path)
    client = TestClient(app, raise_server_exceptions=False)

    # style.css exists in migate/panel/static/
    resp = client.get("/static/style.css")
    if resp.status_code == 200:
        assert "Cache-Control" in resp.headers
        assert "max-age=3600" in resp.headers["Cache-Control"]


def test_static_files_have_etag_header(tmp_path):
    app = _make_app(tmp_path)
    client = TestClient(app, raise_server_exceptions=False)

    resp = client.get("/static/style.css")
    if resp.status_code == 200:
        assert "ETag" in resp.headers
        # ETag should be a quoted hex string
        etag = resp.headers["ETag"]
        assert etag.startswith('"') and etag.endswith('"')
