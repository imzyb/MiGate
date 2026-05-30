import base64
from urllib.parse import parse_qs, unquote, urlparse

from migate.xray.links import build_shadowsocks_link, build_trojan_link, build_vless_link


def test_build_vless_link_contains_uuid_host_port_query_and_name():
    link = build_vless_link(
        uuid="00000000-0000-4000-8000-000000000001",
        host="example.com",
        port=443,
        name="MiGate JP",
        security="none",
        network="tcp",
    )

    parsed = urlparse(link)
    assert parsed.scheme == "vless"
    assert parsed.username == "00000000-0000-4000-8000-000000000001"
    assert parsed.hostname == "example.com"
    assert parsed.port == 443
    assert parse_qs(parsed.query) == {"type": ["tcp"], "security": ["none"]}
    assert unquote(parsed.fragment) == "MiGate JP"


def test_build_trojan_link_contains_password_host_port_query_and_name():
    link = build_trojan_link(
        password="secret password",
        host="example.com",
        port=8443,
        name="MiGate Trojan",
        security="none",
        network="tcp",
    )

    parsed = urlparse(link)
    assert parsed.scheme == "trojan"
    assert unquote(parsed.username) == "secret password"
    assert parsed.hostname == "example.com"
    assert parsed.port == 8443
    assert parse_qs(parsed.query) == {"type": ["tcp"], "security": ["none"]}
    assert unquote(parsed.fragment) == "MiGate Trojan"


def test_build_shadowsocks_link_uses_sip002_userinfo_and_name():
    link = build_shadowsocks_link(
        method="aes-128-gcm",
        password="ss-password",
        host="example.com",
        port=8388,
        name="MiGate SS",
    )

    parsed = urlparse(link)
    assert parsed.scheme == "ss"
    assert parsed.hostname == "example.com"
    assert parsed.port == 8388
    assert unquote(parsed.fragment) == "MiGate SS"
    decoded_userinfo = base64.urlsafe_b64decode(parsed.username + "==").decode()
    assert decoded_userinfo == "aes-128-gcm:ss-password"
