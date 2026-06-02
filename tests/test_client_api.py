"""Integration tests for client management API endpoints."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from migate.api.app import create_app
from migate.database.repository import InboundRepository, NodeRepository


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


def _create_inbound(client):
    return client.post(
        "/api/inbounds",
        data={"remark": "Test", "protocol": "vless", "port": 443},
    )


class TestClientManagementAPI:
    def test_list_clients_empty(self, client):
        resp = _create_inbound(client)
        ib_id = resp.json()["id"]
        r = client.get(f"/api/inbounds/{ib_id}/clients")
        assert r.status_code == 200
        assert r.json()["clients"] == []

    def test_add_client(self, client):
        resp = _create_inbound(client)
        ib_id = resp.json()["id"]
        r = client.post(
            f"/api/inbounds/{ib_id}/clients/add",
            data={"email": "test@example.com"},
        )
        assert r.status_code == 200
        j = r.json()
        assert j["status"] == "created"
        assert j["client"]["email"] == "test@example.com"
        assert "id" in j["client"]

    def test_add_and_list_clients(self, client):
        resp = _create_inbound(client)
        ib_id = resp.json()["id"]
        client.post(f"/api/inbounds/{ib_id}/clients/add", data={"email": "a@b.com"})
        client.post(f"/api/inbounds/{ib_id}/clients/add", data={"email": "c@d.com"})
        r = client.get(f"/api/inbounds/{ib_id}/clients")
        assert len(r.json()["clients"]) == 2

    def test_remove_client(self, client):
        resp = _create_inbound(client)
        ib_id = resp.json()["id"]
        add_r = client.post(f"/api/inbounds/{ib_id}/clients/add", data={"email": "a@b.com"})
        cl_id = add_r.json()["client"]["id"]
        r = client.post(f"/api/inbounds/{ib_id}/clients/{cl_id}/remove")
        assert r.status_code == 200
        assert r.json()["status"] == "removed"
        # Verify gone
        list_r = client.get(f"/api/inbounds/{ib_id}/clients")
        assert len(list_r.json()["clients"]) == 0

    def test_update_client(self, client):
        resp = _create_inbound(client)
        ib_id = resp.json()["id"]
        add_r = client.post(f"/api/inbounds/{ib_id}/clients/add", data={"email": "old@b.com"})
        cl_id = add_r.json()["client"]["id"]
        r = client.post(
            f"/api/inbounds/{ib_id}/clients/{cl_id}/update",
            data={"email": "new@b.com"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "updated"

    def test_add_client_nonexistent_inbound(self, client):
        r = client.post("/api/inbounds/9999/clients/add", data={"email": "a@b.com"})
        assert r.json()["status"] == "not_found"

    def test_remove_client_nonexistent(self, client):
        resp = _create_inbound(client)
        ib_id = resp.json()["id"]
        r = client.post(f"/api/inbounds/{ib_id}/clients/nope/remove")
        assert r.json()["status"] == "not_found"
