"""Tests for system resource monitoring module."""

from __future__ import annotations

import time
from unittest.mock import patch, MagicMock

from migate.system.monitor import (
    SystemResources,
    TrafficHistory,
    TrafficSample,
    get_system_resources,
)


# ---------------------------------------------------------------------------
# get_system_resources
# ---------------------------------------------------------------------------


def test_get_system_resources_returns_valid_data():
    res = get_system_resources()
    assert isinstance(res, SystemResources)
    assert res.cpu_percent >= 0
    assert res.cpu_percent <= 100
    assert res.cpu_count > 0
    assert res.ram_total > 0
    assert res.ram_used >= 0
    assert 0 <= res.ram_percent <= 100
    assert res.disk_total > 0
    assert res.disk_used >= 0
    assert 0 <= res.disk_percent <= 100
    assert res.net_sent >= 0
    assert res.net_recv >= 0
    assert res.uptime_seconds >= 0
    assert isinstance(res.load_avg, tuple)
    assert len(res.load_avg) == 3


def test_get_system_resources_ram_used_le_total():
    res = get_system_resources()
    assert res.ram_used <= res.ram_total


def test_get_system_resources_disk_used_le_total():
    res = get_system_resources()
    assert res.disk_used <= res.disk_total


# ---------------------------------------------------------------------------
# TrafficHistory
# ---------------------------------------------------------------------------


def test_traffic_history_add_and_get_all():
    h = TrafficHistory(max_samples=10)
    h.add(100, 200)
    h.add(300, 400)
    result = h.get_all()
    assert len(result) == 2
    assert result[0]["up"] == 100
    assert result[0]["down"] == 200
    assert result[1]["up"] == 300
    assert result[1]["down"] == 400
    assert "t" in result[0]


def test_traffic_history_max_samples_limit():
    h = TrafficHistory(max_samples=3)
    h.add(1, 1)
    h.add(2, 2)
    h.add(3, 3)
    h.add(4, 4)
    result = h.get_all()
    assert len(result) == 3
    # Oldest sample (1,1) should be dropped
    assert result[0]["up"] == 2
    assert result[-1]["up"] == 4


def test_traffic_history_empty():
    h = TrafficHistory()
    assert h.get_all() == []


def test_traffic_history_default_max_samples():
    h = TrafficHistory()
    assert h._max == 60


def test_traffic_sample_dataclass():
    s = TrafficSample(timestamp=1234567890.0, up_bytes=100, down_bytes=200)
    assert s.timestamp == 1234567890.0
    assert s.up_bytes == 100
    assert s.down_bytes == 200
