"""Tests for client management within inbound rules."""

from __future__ import annotations

import json
import uuid

import pytest

from migate.database.repository import InboundRepository


@pytest.fixture()
def repo(tmp_path):
    db = tmp_path / "test.db"
    r = InboundRepository(str(db))
    r.initialize()
    return r


def _create_vless_inbound(repo: InboundRepository, *, clients: list[dict] | None = None):
    """Helper to create a VLESS inbound with optional clients."""
    settings = json.dumps({"clients": clients or []})
    return repo.create_inbound(
        remark="Test-VLESS",
        protocol="vless",
        port=443,
        settings=settings,
        stream_settings=json.dumps({"network": "tcp"}),
    )


# --- Client parsing helpers ---


class TestClientSettingsHelpers:
    """Test parsing and modifying clients in inbound settings JSON."""

    def test_parse_empty_settings(self):
        from migate.client_manager import parse_clients

        clients = parse_clients("{}")
        assert clients == []

    def test_parse_settings_with_clients(self):
        from migate.client_manager import parse_clients

        settings = json.dumps({"clients": [{"id": "abc-123", "email": "user@test.com"}]})
        clients = parse_clients(settings)
        assert len(clients) == 1
        assert clients[0]["id"] == "abc-123"
        assert clients[0]["email"] == "user@test.com"

    def test_parse_settings_without_clients_key(self):
        from migate.client_manager import parse_clients

        clients = parse_clients('{"some_other_key": "value"}')
        assert clients == []

    def test_parse_invalid_json(self):
        from migate.client_manager import parse_clients

        clients = parse_clients("not-json")
        assert clients == []


class TestAddClient:
    """Test adding a client to inbound settings."""

    def test_add_client_generates_uuid(self):
        from migate.client_manager import add_client

        new_settings, client = add_client("{}")
        parsed = json.loads(new_settings)
        assert len(parsed["clients"]) == 1
        # UUID format check
        uuid.UUID(parsed["clients"][0]["id"])

    def test_add_client_with_email(self):
        from migate.client_manager import add_client

        new_settings, client = add_client("{}", email="user@test.com")
        parsed = json.loads(new_settings)
        assert parsed["clients"][0]["email"] == "user@test.com"

    def test_add_client_preserves_existing(self):
        from migate.client_manager import add_client

        existing = json.dumps({"clients": [{"id": "old-id", "email": "old@test.com"}]})
        new_settings, client = add_client(existing, email="new@test.com")
        parsed = json.loads(new_settings)
        assert len(parsed["clients"]) == 2
        assert parsed["clients"][0]["id"] == "old-id"
        assert parsed["clients"][1]["email"] == "new@test.com"

    def test_add_client_returns_client_dict(self):
        from migate.client_manager import add_client

        _, client = add_client("{}", email="test@test.com")
        assert "id" in client
        assert client["email"] == "test@test.com"


class TestRemoveClient:
    """Test removing a client from inbound settings."""

    def test_remove_existing_client(self):
        from migate.client_manager import remove_client

        settings = json.dumps({"clients": [{"id": "abc", "email": "a@b.com"}, {"id": "def", "email": "c@d.com"}]})
        new_settings, removed = remove_client(settings, "abc")
        assert removed is True
        parsed = json.loads(new_settings)
        assert len(parsed["clients"]) == 1
        assert parsed["clients"][0]["id"] == "def"

    def test_remove_nonexistent_client(self):
        from migate.client_manager import remove_client

        settings = json.dumps({"clients": [{"id": "abc"}]})
        new_settings, removed = remove_client(settings, "nope")
        assert removed is False
        parsed = json.loads(new_settings)
        assert len(parsed["clients"]) == 1


class TestUpdateClient:
    """Test updating a client in inbound settings."""

    def test_update_client_email(self):
        from migate.client_manager import update_client

        settings = json.dumps({"clients": [{"id": "abc", "email": "old@b.com"}]})
        new_settings, updated = update_client(settings, "abc", email="new@b.com")
        assert updated is True
        parsed = json.loads(new_settings)
        assert parsed["clients"][0]["email"] == "new@b.com"

    def test_update_preserves_other_fields(self):
        from migate.client_manager import update_client

        settings = json.dumps({"clients": [{"id": "abc", "email": "a@b.com", "flow": "xtls-rprx-vision"}]})
        new_settings, updated = update_client(settings, "abc", email="new@b.com")
        parsed = json.loads(new_settings)
        assert parsed["clients"][0]["flow"] == "xtls-rprx-vision"

    def test_update_nonexistent_client(self):
        from migate.client_manager import update_client

        settings = json.dumps({"clients": [{"id": "abc"}]})
        _, updated = update_client(settings, "nope", email="x@y.com")
        assert updated is False


# --- Integration with InboundRepository ---


class TestClientRepositoryIntegration:
    """Test client management through the full repository stack."""

    def test_add_client_to_inbound(self, repo):
        ib = _create_vless_inbound(repo, clients=[])
        from migate.client_manager import add_client_to_inbound

        client = add_client_to_inbound(repo, ib.id, email="user@test.com")
        assert client is not None
        assert client["email"] == "user@test.com"
        # Verify persisted
        updated = repo.get_inbound(ib.id)
        assert updated is not None
        parsed = json.loads(updated.settings)
        assert len(parsed["clients"]) == 1

    def test_remove_client_from_inbound(self, repo):
        ib = _create_vless_inbound(repo, clients=[{"id": "client-1", "email": "a@b.com"}])
        from migate.client_manager import remove_client_from_inbound

        removed = remove_client_from_inbound(repo, ib.id, "client-1")
        assert removed is True
        updated = repo.get_inbound(ib.id)
        assert updated is not None
        parsed = json.loads(updated.settings)
        assert len(parsed["clients"]) == 0

    def test_list_clients_of_inbound(self, repo):
        ib = _create_vless_inbound(repo, clients=[{"id": "c1", "email": "a@b.com"}, {"id": "c2", "email": "c@d.com"}])
        from migate.client_manager import list_clients

        clients = list_clients(repo, ib.id)
        assert len(clients) == 2

    def test_list_clients_of_nonexistent_inbound(self, repo):
        from migate.client_manager import list_clients

        clients = list_clients(repo, 9999)
        assert clients == []
