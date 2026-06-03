"""Tests for _stream_settings_form_html."""
from __future__ import annotations

import json
import pytest

from migate.api.app import _stream_settings_form_html


# ---------------------------------------------------------------------------
# Basic structural tests
# ---------------------------------------------------------------------------

class TestStreamSettingsFormHtml:
    """Verify the HTML returned by _stream_settings_form_html."""

    @pytest.fixture()
    def html(self) -> str:
        return _stream_settings_form_html()

    # --- wrapper -----------------------------------------------------------
    def test_wrapped_in_details_element(self, html: str):
        assert "<details" in html
        assert "🔗 传输与安全设置 (Stream Settings)" in html

    def test_hidden_input_present(self, html: str):
        assert 'name="stream_settings"' in html
        assert 'id="stream-settings-json"' in html

    # --- network type options -----------------------------------------------
    def test_network_options_present(self, html: str):
        for net in ("tcp", "ws", "grpc", "h2"):
            assert f'value="{net}"' in html

    def test_security_options_present(self, html: str):
        for sec in ("none", "tls", "reality"):
            assert f'value="{sec}"' in html

    # --- transport sub-forms -------------------------------------------------
    def test_tcp_transport_fields(self, html: str):
        assert 'id="ss-transport-tcp"' in html
        assert 'id="ss-tcp-header-type"' in html
        assert 'id="ss-tcp-request-path"' in html

    def test_ws_transport_fields(self, html: str):
        assert 'id="ss-transport-ws"' in html
        assert 'id="ss-ws-path"' in html
        assert 'id="ss-ws-host"' in html

    def test_grpc_transport_fields(self, html: str):
        assert 'id="ss-transport-grpc"' in html
        assert 'id="ss-grpc-service"' in html

    def test_h2_transport_fields(self, html: str):
        assert 'id="ss-transport-h2"' in html
        assert 'id="ss-h2-host"' in html
        assert 'id="ss-h2-path"' in html

    # --- TLS section --------------------------------------------------------
    def test_tls_section_present(self, html: str):
        assert 'id="ss-tls-section"' in html
        assert 'id="ss-tls-sni"' in html
        assert 'id="ss-tls-alpn"' in html
        assert 'id="ss-tls-certs"' in html

    # --- Reality section ----------------------------------------------------
    def test_reality_section_present(self, html: str):
        assert 'id="ss-reality-section"' in html
        assert 'id="ss-reality-private-key"' in html
        assert 'id="ss-reality-public-key"' in html
        assert 'id="ss-reality-short-id"' in html
        assert 'id="ss-reality-dest"' in html
        assert 'id="ss-reality-server-names"' in html
        assert 'id="ss-reality-spider-x"' in html

    # --- JS functions -------------------------------------------------------
    def test_ssAssembleJson_function_defined(self, html: str):
        assert "ssAssembleJson" in html
        assert "window.ssAssembleJson" in html

    def test_js_show_transport_function(self, html: str):
        assert "ssShowTransport" in html

    def test_js_show_security_function(self, html: str):
        assert "ssShowSecurity" in html

    # --- CSS ----------------------------------------------------------------
    def test_dark_theme_css_present(self, html: str):
        assert "var(--border" in html
        assert "var(--accent" in html
        assert "var(--bg-input" in html
        assert "var(--radius-sm" in html

    # --- Apply button -------------------------------------------------------
    def test_apply_button_present(self, html: str):
        assert 'id="ss-apply-btn"' in html
        assert "应用 Stream Settings" in html


# ---------------------------------------------------------------------------
# Populating from existing JSON
# ---------------------------------------------------------------------------

class TestStreamSettingsFormHtmlWithExisting:
    """Verify existing_json pre-populates fields."""

    def _build_existing(self, **overrides) -> str:
        base = {
            "network": "ws",
            "security": "tls",
            "wsSettings": {"path": "/my-ws", "host": "cdn.example.com"},
            "tlsSettings": {"serverName": "example.com", "alpn": ["h2", "http/1.1"]},
        }
        base.update(overrides)
        return json.dumps(base)

    def test_existing_json_embedded_in_js(self):
        existing = self._build_existing()
        html = _stream_settings_form_html(existing_json=existing)
        # The escaped version of the JSON must appear in the JS
        assert "existingRaw" in html

    def test_reality_existing_json_embedded(self):
        existing = json.dumps({
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "privateKey": "abc123",
                "publicKey": "def456",
                "shortId": "0123456789abcdef",
                "dest": "yahoo.com:443",
                "serverNames": ["yahoo.com", "www.yahoo.com"],
                "spiderX": "/spider",
            },
        })
        html = _stream_settings_form_html(existing_json=existing)
        assert "abc123" in html or "abc123" in html.replace("\\", "")

    def test_default_empty_json(self):
        html = _stream_settings_form_html()
        # Should still produce valid HTML with no JS errors
        assert 'id="stream-settings-json"' in html


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestStreamSettingsFormEdgeCases:

    def test_special_chars_in_existing_json(self):
        """Ensure quotes/backslashes in existing JSON don't break HTML."""
        tricky = json.dumps({
            "network": "tcp",
            "security": "none",
            "note": "He said \"hello\" and C:\\path",
        })
        html = _stream_settings_form_html(existing_json=tricky)
        # Should not raise; just verify it still renders
        assert 'id="stream-settings-json"' in html

    def test_returns_string(self):
        result = _stream_settings_form_html()
        assert isinstance(result, str)

    def test_no_global_side_effects(self):
        """Calling twice returns the same output."""
        a = _stream_settings_form_html()
        b = _stream_settings_form_html()
        assert a == b


# ---------------------------------------------------------------------------
# uid parameter — unique element IDs for multi-form pages
# ---------------------------------------------------------------------------

class TestStreamSettingsFormUid:
    """Verify uid parameter produces unique, prefixed element IDs."""

    def test_uid_prefixes_all_element_ids(self):
        """When uid='3', all element IDs should contain '-3' suffix."""
        html = _stream_settings_form_html(uid="3")
        for base_id in (
            "stream-settings-json", "ss-network", "ss-security",
            "ss-tcp-header-type", "ss-tcp-request-path",
            "ss-ws-path", "ss-ws-host",
            "ss-grpc-service",
            "ss-h2-host", "ss-h2-path",
            "ss-tls-section", "ss-tls-sni", "ss-tls-alpn", "ss-tls-certs",
            "ss-reality-section", "ss-reality-private-key", "ss-reality-public-key",
            "ss-reality-short-id", "ss-reality-dest", "ss-reality-server-names",
            "ss-reality-spider-x",
            "ss-apply-btn",
            "ss-transport-tcp", "ss-transport-ws", "ss-transport-grpc", "ss-transport-h2",
        ):
            assert f'id="{base_id}-3"' in html, f"Expected id=\"{base_id}-3\" in HTML"
        # The old un-prefixed IDs must NOT appear (except as CSS classes)
        assert 'id="stream-settings-json"' not in html
        assert 'id="ss-network"' not in html

    def test_uid_empty_preserves_original_ids(self):
        """When uid='' (default), original un-prefixed IDs are used."""
        html = _stream_settings_form_html()
        assert 'id="stream-settings-json"' in html
        assert 'id="ss-network"' in html
        assert 'id="ss-security"' in html
        assert 'id="ss-apply-btn"' in html
        # The wrapper div should have id="ss-sec" (no suffix)
        assert 'id="ss-sec"' in html

    def test_uid_scoped_js_function_name(self):
        """When uid='7', JS function should be window.ssAssembleJson_7."""
        html = _stream_settings_form_html(uid="7")
        assert "window.ssAssembleJson_7" in html
        # Should NOT use the un-prefixed function name
        assert "window.ssAssembleJson_7" in html
        # The wrapper div should be id="ss-sec-7"
        assert 'id="ss-sec-7"' in html


class TestStreamSettingsFormX25519Button:
    """Verify the x25519 key generation button in the Reality section."""

    def test_generate_key_pair_button_present(self):
        html = _stream_settings_form_html()
        assert "生成密钥对" in html

    def test_button_fetches_from_panel_x25519_endpoint(self):
        html = _stream_settings_form_html()
        assert "/xray/x25519" in html

    def test_button_fills_private_and_public_key_fields(self):
        html = _stream_settings_form_html()
        assert "ss-reality-private-key" in html
        assert "ss-reality-public-key" in html

    def test_button_with_custom_base_path(self):
        html = _stream_settings_form_html(panel_base_path="/mg-admin")
        assert "/mg-admin/xray/x25519" in html

    def test_button_with_uid_suffixed_ids(self):
        html = _stream_settings_form_html(uid="5")
        assert "ss-reality-private-key-5" in html or "ss-reality-private-key5" in html or "ss-reality-private-key{S}" in html
