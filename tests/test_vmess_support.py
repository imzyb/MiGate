"""Tests for VMess protocol support — config_builder, node_adapter, links, clash parsing."""
from __future__ import annotations

import base64
import json

import pytest

from migate.xray.config_builder import build_vmess_inbound
from migate.xray.links import build_vmess_link
from migate.api.app import _parse_link_for_clash, _build_link


# ── build_vmess_inbound ────────────────────────────────────────────────


class TestBuildVmessInbound:
    def test_basic_structure(self):
        result = build_vmess_inbound(
            tag="test-vmess",
            port=4433,
            client_uuid="550e8400-e29b-41d4-a716-446655440000",
            email="user1@example.com",
        )
        assert result["protocol"] == "vmess"
        assert result["tag"] == "test-vmess"
        assert result["port"] == 4433
        assert result["listen"] == "0.0.0.0"
        assert result["streamSettings"]["network"] == "tcp"

    def test_client_fields(self):
        result = build_vmess_inbound(
            tag="t",
            port=1000,
            client_uuid="uuid-123",
            email="e@e.com",
        )
        client = result["settings"]["clients"][0]
        assert client["id"] == "uuid-123"
        assert client["alterId"] == 0
        assert client["email"] == "e@e.com"
        assert client["level"] == 0

    def test_custom_listen(self):
        result = build_vmess_inbound(
            tag="t", port=8080, client_uuid="u", email="e", listen="127.0.0.1"
        )
        assert result["listen"] == "127.0.0.1"


# ── build_vmess_link ──────────────────────────────────────────────────


class TestBuildVmessLink:
    def test_basic_link(self):
        link = build_vmess_link(
            uuid="550e8400-e29b-41d4-a716-446655440000",
            host="example.com",
            port=443,
            name="Test Node",
        )
        assert link.startswith("vmess://")
        raw = link[8:]
        decoded = json.loads(base64.urlsafe_b64decode(raw + "==").decode())
        assert decoded["v"] == "2"
        assert decoded["id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert decoded["add"] == "example.com"
        assert decoded["port"] == "443"
        assert decoded["ps"] == "Test Node"
        assert decoded["aid"] == "0"
        assert decoded["net"] == "tcp"

    def test_link_with_tls(self):
        link = build_vmess_link(
            uuid="uuid-test", host="h.com", port=443, name="tls", security="tls"
        )
        raw = link[8:]
        decoded = json.loads(base64.urlsafe_b64decode(raw + "==").decode())
        assert decoded["tls"] == "tls"

    def test_link_empty_name(self):
        link = build_vmess_link(uuid="u", host="h.com", port=80, name="")
        raw = link[8:]
        decoded = json.loads(base64.urlsafe_b64decode(raw + "==").decode())
        assert decoded["ps"] == ""


# ── node_to_inbound with vmess ────────────────────────────────────────


class TestNodeToInboundVmess:
    def test_vmess_node(self):
        from migate.xray.node_adapter import node_to_inbound, node_tag
        from migate.database.repository import NodeRecord

        node = NodeRecord(
            id=42,
            name="vmess-node",
            protocol="vmess",
            host="1.2.3.4",
            port=4433,
            credential="550e8400-e29b-41d4-a716-446655440000",
            enabled=True,
            share_link="vmess://test",
            subscription="",
            created_at="2024-01-01T00:00:00",
            socks5_host="",
            socks5_port=None,
        )
        inbound = node_to_inbound(node)
        assert inbound["protocol"] == "vmess"
        assert inbound["port"] == 4433
        assert inbound["tag"] == node_tag(node)
        assert inbound["settings"]["clients"][0]["id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert inbound["settings"]["clients"][0]["alterId"] == 0


# ── _parse_link_for_clash with vmess ──────────────────────────────────


class TestParseVmessLinkForClash:
    def test_basic_vmess(self):
        vmess_obj = {
            "v": "2",
            "ps": "JP-Node",
            "add": "jp.example.com",
            "port": "443",
            "id": "uuid-abc",
            "aid": "0",
            "net": "tcp",
            "type": "none",
            "host": "",
            "path": "",
            "tls": "",
        }
        raw = json.dumps(vmess_obj, separators=(",", ":"))
        encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        link = f"vmess://{encoded}"
        result = _parse_link_for_clash(link)
        assert result is not None
        assert result["type"] == "vmess"
        assert result["name"] == "JP-Node"
        assert result["server"] == "jp.example.com"
        assert result["port"] == 443
        assert result["uuid"] == "uuid-abc"
        assert result["alterId"] == 0

    def test_vmess_with_tls(self):
        vmess_obj = {
            "v": "2",
            "ps": "tls-node",
            "add": "t.com",
            "port": "443",
            "id": "uid",
            "aid": "0",
            "net": "tcp",
            "type": "none",
            "host": "",
            "path": "",
            "tls": "tls",
        }
        raw = json.dumps(vmess_obj, separators=(",", ":"))
        encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        link = f"vmess://{encoded}"
        result = _parse_link_for_clash(link)
        assert result is not None
        assert result["tls"] is True


# ── _build_link with vmess ────────────────────────────────────────────


class TestBuildLinkVmess:
    def test_vmess_link_generation(self):
        link = _build_link(
            protocol="vmess",
            host="example.com",
            port=443,
            name="test",
            credential="550e8400-e29b-41d4-a716-446655440000",
        )
        assert link.startswith("vmess://")
        raw = link[8:]
        decoded = json.loads(base64.urlsafe_b64decode(raw + "==").decode())
        assert decoded["id"] == "550e8400-e29b-41d4-a716-446655440000"
        assert decoded["add"] == "example.com"

    def test_unsupported_protocol_raises(self):
        with pytest.raises(ValueError, match="unsupported protocol"):
            _build_link(protocol="hysteria2", host="h.com", port=443, name="n", credential="c")
