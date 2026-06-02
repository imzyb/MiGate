"""Tests for converting InboundRecord to xray inbound config."""

from __future__ import annotations

import json

from migate.database.repository import InboundRecord
from migate.xray.node_adapter import inbound_to_xray_inbound, build_config_from_nodes_and_inbounds
from migate.xray.config_builder import build_full_config
from migate.config import MiGateConfig


def _make_inbound(**overrides) -> InboundRecord:
    defaults = dict(
        id=1,
        remark="test-inbound",
        protocol="vless",
        port=443,
        listen="0.0.0.0",
        settings=json.dumps({"clients": [{"id": "abc-123"}]}),
        stream_settings=json.dumps({"network": "tcp", "security": "tls"}),
        enabled=True,
        up_bytes=0,
        down_bytes=0,
        created_at="2026-01-01T00:00:00",
    )
    defaults.update(overrides)
    return InboundRecord(**defaults)


class TestInboundToXrayInbound:
    def test_vless_inbound_basic(self):
        record = _make_inbound(protocol="vless", port=443)
        result = inbound_to_xray_inbound(record)
        assert result["protocol"] == "vless"
        assert result["port"] == 443
        assert result["listen"] == "0.0.0.0"
        assert result["tag"] == "inbound-test-inbound"

    def test_vless_inbound_with_clients(self):
        record = _make_inbound(
            protocol="vless",
            settings=json.dumps({"clients": [{"id": "uuid-1", "email": "user1"}]}),
        )
        result = inbound_to_xray_inbound(record)
        clients = result["settings"]["clients"]
        assert len(clients) == 1
        assert clients[0]["id"] == "uuid-1"

    def test_vmess_inbound(self):
        record = _make_inbound(
            protocol="vmess",
            settings=json.dumps({"clients": [{"id": "uuid-2"}]}),
        )
        result = inbound_to_xray_inbound(record)
        assert result["protocol"] == "vmess"

    def test_trojan_inbound(self):
        record = _make_inbound(
            protocol="trojan",
            settings=json.dumps({"clients": [{"password": "pass123"}]}),
        )
        result = inbound_to_xray_inbound(record)
        assert result["protocol"] == "trojan"

    def test_shadowsocks_inbound(self):
        record = _make_inbound(
            protocol="shadowsocks",
            port=8388,
            settings=json.dumps({"method": "aes-256-gcm", "password": "ss-pass"}),
        )
        result = inbound_to_xray_inbound(record)
        assert result["protocol"] == "shadowsocks"
        assert result["port"] == 8388

    def test_inbound_with_stream_settings(self):
        record = _make_inbound(
            stream_settings=json.dumps({"network": "ws", "security": "tls", "wsSettings": {"path": "/ws"}}),
        )
        result = inbound_to_xray_inbound(record)
        assert result["streamSettings"]["network"] == "ws"
        assert result["streamSettings"]["wsSettings"]["path"] == "/ws"

    def test_disabled_inbound_skipped(self):
        record = _make_inbound(enabled=False)
        result = inbound_to_xray_inbound(record)
        assert result is None

    def test_inbound_tag_sanitized(self):
        record = _make_inbound(remark="My Server (HK) #1")
        result = inbound_to_xray_inbound(record)
        assert " " not in result["tag"]
        assert "(" not in result["tag"]


class TestBuildConfigFromNodesAndInbounds:
    def test_combines_nodes_and_inbounds(self):
        from migate.database.repository import NodeRecord
        node = NodeRecord(
            id=1, name="test-node", protocol="vless", host="example.com", port=443,
            credential="uuid-test", share_link="vless://...", subscription="...",
            socks5_host="", socks5_port=None, enabled=True, created_at="2026-01-01",
        )
        inbound = _make_inbound(port=8443)
        config = MiGateConfig()
        result = build_config_from_nodes_and_inbounds(config, nodes=[node], inbounds=[inbound])
        # Should have both node-based and rule-based inbounds
        inbounds = result.get("inbounds", [])
        tags = [i["tag"] for i in inbounds]
        assert "node-1-vless" in tags
        assert "inbound-test-inbound" in tags

    def test_empty_inbounds(self):
        config = MiGateConfig()
        result = build_config_from_nodes_and_inbounds(config, nodes=[], inbounds=[])
        assert "inbounds" in result

    def test_only_inbounds_no_nodes(self):
        inbound = _make_inbound(port=8443)
        config = MiGateConfig()
        result = build_config_from_nodes_and_inbounds(config, nodes=[], inbounds=[inbound])
        tags = [i["tag"] for i in result.get("inbounds", [])]
        assert "inbound-test-inbound" in tags
