"""Tests for xray stats query module."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from migate.xray.stats import XrayStatEntry, XrayTrafficStats, query_xray_stats


def test_xray_traffic_stats_inbound_traffic():
    stats = XrayTrafficStats(entries=[
        XrayStatEntry(name="inbound>>>vless-main>>>traffic>>>uplink", value=1024),
        XrayStatEntry(name="inbound>>>vless-main>>>traffic>>>downlink", value=2048),
        XrayStatEntry(name="inbound>>>trojan-1>>>traffic>>>uplink", value=512),
        XrayStatEntry(name="outbound>>>proxy>>>traffic>>>uplink", value=999),
    ])
    up, down = stats.inbound_traffic("vless-main")
    assert up == 1024
    assert down == 2048


def test_xray_traffic_stats_inbound_traffic_no_match():
    stats = XrayTrafficStats(entries=[
        XrayStatEntry(name="inbound>>>other>>>traffic>>>uplink", value=100),
    ])
    up, down = stats.inbound_traffic("vless-main")
    assert up == 0
    assert down == 0


def test_xray_traffic_stats_inbound_traffic_empty():
    stats = XrayTrafficStats(entries=[])
    up, down = stats.inbound_traffic("vless-main")
    assert up == 0
    assert down == 0


def test_query_xray_stats_parses_stdout():
    mock_output = json.dumps({
        "stat": [
            {"name": "inbound>>>vless-main>>>traffic>>>uplink", "value": "100"},
            {"name": "inbound>>>vless-main>>>traffic>>>downlink", "value": "200"},
        ]
    })
    mock_result = subprocess.CompletedProcess(args=[], returncode=0, stdout=mock_output, stderr="")
    with patch("migate.xray.stats.subprocess.run", return_value=mock_result) as mock_run:
        stats = query_xray_stats(server="127.0.0.1:10085", pattern="inbound")
        mock_run.assert_called_once()
        assert len(stats.entries) == 2
        up, down = stats.inbound_traffic("vless-main")
        assert up == 100
        assert down == 200


def test_query_xray_stats_returns_empty_on_failure():
    mock_result = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error")
    with patch("migate.xray.stats.subprocess.run", return_value=mock_result):
        stats = query_xray_stats()
        assert stats.entries == []


def test_query_xray_stats_returns_empty_on_timeout():
    with patch("migate.xray.stats.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="", timeout=10)):
        stats = query_xray_stats()
        assert stats.entries == []
