"""Tests for subscription endpoint and token management."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from migate.api.app import create_app
from migate.database.repository import (
    ClientTrafficRepository,
    InboundRepository,
    NodeRepository,
)


@pytest.fixture()
def db(tmp_path):
    return tmp_path / "test.db"


@pytest.fixture()
def inbound_repo(db):
    r = InboundRepository(db)
    r.initialize()
    return r


@pytest.fixture()
def traffic_repo(db, inbound_repo):
    r = ClientTrafficRepository(db)
    r.initialize()
    return r


@pytest.fixture()
def client(tmp_path):
    db = tmp_path / "test.db"
    node_repo = NodeRepository(str(db))
    inbound_repo = InboundRepository(str(db))
    node_repo.initialize()
    inbound_repo.initialize()
    app = create_app(
        node_repository=node_repo,
        inbound_repository=inbound_repo,
    )
    return TestClient(app, raise_server_exceptions=False)


# --- Token generation ---


def test_generate_token_deterministic(traffic_repo):
    """Token generation should be deterministic from email."""
    token1 = traffic_repo.generate_token("user@example.com")
    token2 = traffic_repo.generate_token("user@example.com")
    assert token1 == token2
    assert len(token1) == 32


def test_generate_token_different_emails(traffic_repo):
    """Different emails should produce different tokens."""
    token1 = traffic_repo.generate_token("a@example.com")
    token2 = traffic_repo.generate_token("b@example.com")
    assert token1 != token2


def test_generate_token_hex_format(traffic_repo):
    """Token should be hex string."""
    token = traffic_repo.generate_token("test@example.com")
    int(token, 16)  # Should not raise


# --- get_by_token ---


def test_get_by_token_returns_record(traffic_repo, inbound_repo):
    """Should find a client by their subscription token."""
    ib = inbound_repo.create_inbound(
        remark="test", protocol="vless", port=443, settings="{}", stream_settings="{}"
    )
    traffic_repo.upsert_traffic("user@example.com", ib.id, 100, 200)
    token = traffic_repo.generate_token("user@example.com")

    result = traffic_repo.get_by_token(token)
    assert result is not None
    assert result.email == "user@example.com"
    assert result.subscription_token == token


def test_get_by_token_invalid(traffic_repo):
    """Should return None for an invalid token."""
    result = traffic_repo.get_by_token("nonexistent")
    assert result is None


def test_upsert_traffic_sets_token(traffic_repo, inbound_repo):
    """upsert_traffic should automatically set subscription_token."""
    ib = inbound_repo.create_inbound(
        remark="test", protocol="vless", port=443, settings="{}", stream_settings="{}"
    )
    record = traffic_repo.upsert_traffic("user@example.com", ib.id, 100, 200)
    expected_token = traffic_repo.generate_token("user@example.com")
    assert record.subscription_token == expected_token


def test_upsert_traffic_preserves_existing_token(traffic_repo, inbound_repo):
    """upsert_traffic should not overwrite an existing token."""
    ib = inbound_repo.create_inbound(
        remark="test", protocol="vless", port=443, settings="{}", stream_settings="{}"
    )
    traffic_repo.upsert_traffic("user@example.com", ib.id, 100, 200)
    expected_token = traffic_repo.generate_token("user@example.com")
    # Upsert again
    traffic_repo.upsert_traffic("user@example.com", ib.id, 300, 400)
    record = traffic_repo.get_by_email("user@example.com")
    assert record is not None
    assert record.subscription_token == expected_token


# --- Subscription endpoint ---


def test_subscription_returns_base64_links(client):
    """GET /sub/{token} should return base64-encoded links for normal User-Agent."""
    # Create an inbound with a client
    resp = client.post(
        "/api/inbounds",
        data={
            "remark": "Test",
            "protocol": "vless",
            "port": 443,
            "settings": json.dumps({"clients": [{"id": "test-uuid-1234", "email": "test@example.com"}]}),
            "stream_settings": json.dumps({"network": "tcp", "security": "none"}),
        },
    )
    assert resp.status_code == 200
    ib_id = resp.json()["id"]

    # Add client via API to trigger traffic record creation
    client.post(f"/api/inbounds/{ib_id}/clients/add", data={"email": "test@example.com"})

    # Get token
    traffic_repo = ClientTrafficRepository(str(client.app.state._state.get("db_path", "/var/lib/migate/migate.db")))
    # Instead, use the known deterministic token
    import hashlib
    token = hashlib.sha256(b"test@example.com").hexdigest()[:32]

    # Request subscription
    resp = client.get(f"/sub/{token}", headers={"User-Agent": "V2RayNG/1.0"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/plain; charset=utf-8"

    import base64
    decoded = base64.b64decode(resp.text).decode()
    assert "vless://" in decoded


def test_subscription_clash_returns_yaml(client):
    """GET /sub/{token} with Clash User-Agent should return YAML."""
    resp = client.post(
        "/api/inbounds",
        data={
            "remark": "Test",
            "protocol": "vless",
            "port": 443,
            "settings": json.dumps({"clients": [{"id": "test-uuid-1234", "email": "clash@example.com"}]}),
            "stream_settings": json.dumps({"network": "ws", "security": "tls", "sni": "example.com", "wsSettings": {"path": "/ws", "headers": {"Host": "example.com"}}}),
        },
    )
    assert resp.status_code == 200
    ib_id = resp.json()["id"]
    client.post(f"/api/inbounds/{ib_id}/clients/add", data={"email": "clash@example.com"})

    import hashlib
    token = hashlib.sha256(b"clash@example.com").hexdigest()[:32]

    resp = client.get(f"/sub/{token}", headers={"User-Agent": "ClashForAndroid/2.5.12"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/yaml; charset=utf-8"
    assert "proxies:" in resp.text
    assert "proxy-groups:" in resp.text
    assert "rules:" in resp.text


def test_subscription_invalid_token_returns_404(client):
    """GET /sub/{invalid} should return 404."""
    resp = client.get("/sub/invalidtoken123")
    assert resp.status_code == 404


def test_subscription_no_inbounds_returns_404(client):
    """GET /sub/{token} should return 404 if client has no inbounds."""
    # Create inbound with client, then delete inbound
    resp = client.post(
        "/api/inbounds",
        data={
            "remark": "Test",
            "protocol": "vless",
            "port": 443,
            "settings": json.dumps({"clients": [{"id": "test-uuid", "email": "orphan@example.com"}]}),
            "stream_settings": json.dumps({}),
        },
    )
    ib_id = resp.json()["id"]
    client.post(f"/api/inbounds/{ib_id}/clients/add", data={"email": "orphan@example.com"})

    import hashlib
    token = hashlib.sha256(b"orphan@example.com").hexdigest()[:32]

    # Delete the inbound
    client.post(f"/api/inbounds/{ib_id}/delete")

    resp = client.get(f"/sub/{token}", headers={"User-Agent": "V2RayNG"})
    assert resp.status_code == 404
