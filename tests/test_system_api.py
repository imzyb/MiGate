"""Tests for system monitoring API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from migate.api.app import create_app
from migate.database.repository import NodeRepository


def _make_client(tmp_path):
    return TestClient(create_app(node_repository=NodeRepository(tmp_path / "migate.db")))


def test_api_system_resources_returns_200_with_expected_keys(tmp_path):
    client = _make_client(tmp_path)
    response = client.get("/api/system/resources")
    assert response.status_code == 200
    data = response.json()
    expected_keys = {
        "cpu_percent", "cpu_count", "ram_total", "ram_used", "ram_percent",
        "disk_total", "disk_used", "disk_percent", "net_sent", "net_recv",
        "uptime_seconds", "load_avg",
    }
    assert expected_keys == set(data.keys())
    assert isinstance(data["cpu_percent"], (int, float))
    assert isinstance(data["cpu_count"], int)
    assert isinstance(data["ram_total"], int)
    assert isinstance(data["load_avg"], list)
    assert len(data["load_avg"]) == 3


def test_api_system_resources_values_reasonable(tmp_path):
    client = _make_client(tmp_path)
    data = client.get("/api/system/resources").json()
    assert 0 <= data["cpu_percent"] <= 100
    assert data["cpu_count"] > 0
    assert data["ram_total"] > 0
    assert data["ram_used"] >= 0
    assert data["disk_total"] > 0
    assert data["uptime_seconds"] >= 0


def test_api_system_traffic_history_returns_list(tmp_path):
    client = _make_client(tmp_path)
    response = client.get("/api/system/traffic/history")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    # Initially empty (no samples yet)
    # Each item, if present, should have t, up, down keys
    for item in data:
        assert "t" in item
        assert "up" in item
        assert "down" in item
