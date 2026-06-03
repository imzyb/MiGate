"""Tests for XHTTP transport, Flow/Fingerprint UI, and Clash Reality output."""
from __future__ import annotations

import json

import pytest

from migate.xray.links import build_vless_link
from migate.api.app import _parse_link_for_clash


# ── XHTTP link generation ──────────────────────────────────────────────


class TestVlessXhttpLink:
    def test_xhttp_basic(self):
        link = build_vless_link(
            uuid="test-uuid",
            host="example.com",
            port=443,
            name="xhttp-node",
            network="xhttp",
            path="/split",
            host_header="cdn.example.com",
        )
        assert "type=xhttp" in link
        assert "path=%2Fsplit" in link or "path=/split" in link
        assert "xhttp-node" in link

    def test_xhttp_with_mode(self):
        link = build_vless_link(
            uuid="test-uuid",
            host="example.com",
            port=443,
            name="xhttp-stream",
            network="xhttp",
            xhttp_mode="stream",
        )
        assert "type=xhttp" in link
        assert "mode=stream" in link

    def test_xhttp_with_tls(self):
        link = build_vless_link(
            uuid="test-uuid",
            host="example.com",
            port=443,
            name="xhttp-tls",
            network="xhttp",
            security="tls",
            sni="example.com",
            fp="chrome",
        )
        assert "type=xhttp" in link
        assert "security=tls" in link
        assert "fp=chrome" in link

    def test_xhttp_with_reality(self):
        link = build_vless_link(
            uuid="test-uuid",
            host="example.com",
            port=443,
            name="xhttp-reality",
            network="xhttp",
            security="reality",
            pbk="public-key-123",
            sid="short-id-456",
            flow="xtls-rprx-vision",
        )
        assert "type=xhttp" in link
        assert "security=reality" in link
        assert "pbk=public-key-123" in link
        assert "sid=short-id-456" in link
        assert "flow=xtls-rprx-vision" in link


# ── Flow and Fingerprint link ──────────────────────────────────────────


class TestFlowFingerprintLink:
    def test_flow_in_link(self):
        link = build_vless_link(
            uuid="u", host="h.com", port=443, name="n",
            flow="xtls-rprx-vision",
        )
        assert "flow=xtls-rprx-vision" in link

    def test_fingerprint_in_link(self):
        link = build_vless_link(
            uuid="u", host="h.com", port=443, name="n",
            fp="firefox",
        )
        assert "fp=firefox" in link

    def test_flow_and_fp_together(self):
        link = build_vless_link(
            uuid="u", host="h.com", port=443, name="n",
            security="tls",
            flow="xtls-rprx-vision",
            fp="safari",
        )
        assert "flow=xtls-rprx-vision" in link
        assert "fp=safari" in link


# ── Clash parse: XHTTP ────────────────────────────────────────────────


class TestParseXhttpForClash:
    def test_xhttp_basic(self):
        link = "vless://uuid@host.com:443?type=xhttp&path=%2Fsplit&mode=stream#XHTTP-Node"
        result = _parse_link_for_clash(link)
        assert result is not None
        assert result["network"] == "xhttp"
        assert result["xhttp_path"] == "/split"
        assert result["xhttp_mode"] == "stream"
        assert result["name"] == "XHTTP-Node"

    def test_xhttp_no_mode(self):
        link = "vless://uuid@host.com:443?type=xhttp&path=%2F#XHTTP"
        result = _parse_link_for_clash(link)
        assert result is not None
        assert result["network"] == "xhttp"
        assert result["xhttp_path"] == "/"
        assert result["xhttp_mode"] == ""


# ── Clash parse: Reality ──────────────────────────────────────────────


class TestParseRealityForClash:
    def test_reality_basic(self):
        link = "vless://uuid@host.com:443?type=tcp&security=reality&pbk=pubkey123&sid=shortid456&sni=example.com&flow=xtls-rprx-vision#Reality"
        result = _parse_link_for_clash(link)
        assert result is not None
        assert result["tls"] is True
        assert result["reality"] is True
        assert result["reality_public_key"] == "pubkey123"
        assert result["reality_short_id"] == "shortid456"
        assert result["flow"] == "xtls-rprx-vision"
        assert result["sni"] == "example.com"

    def test_reality_with_fp(self):
        link = "vless://uuid@host.com:443?type=tcp&security=reality&pbk=pk&fp=chrome#R"
        result = _parse_link_for_clash(link)
        assert result is not None
        assert result["reality"] is True
        assert result["fp"] == "chrome"


# ── Clash parse: Flow ─────────────────────────────────────────────────


class TestParseFlowForClash:
    def test_flow_in_link(self):
        link = "vless://uuid@host.com:443?type=tcp&security=tls&flow=xtls-rprx-vision#F"
        result = _parse_link_for_clash(link)
        assert result is not None
        assert result["flow"] == "xtls-rprx-vision"

    def test_no_flow(self):
        link = "vless://uuid@host.com:443?type=tcp#N"
        result = _parse_link_for_clash(link)
        assert result is not None
        assert result["flow"] == ""
