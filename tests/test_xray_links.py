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


def test_build_vless_link_with_tls_and_transport_params():
    link = build_vless_link(
        uuid="abc-def",
        host="my.domain.com",
        port=443,
        name="TLS Node",
        network="ws",
        security="tls",
        sni="my.domain.com",
        alpn="h2,http/1.1",
        fp="chrome",
        path="/ws-path",
        host_header="my.domain.com",
        header_type="http",
    )

    parsed = urlparse(link)
    qs = parse_qs(parsed.query)
    assert qs["type"] == ["ws"]
    assert qs["security"] == ["tls"]
    assert qs["sni"] == ["my.domain.com"]
    assert qs["fp"] == ["chrome"]
    assert qs["alpn"] == ["h2,http/1.1"]
    assert qs["path"] == ["/ws-path"]
    assert qs["host"] == ["my.domain.com"]
    assert qs["headerType"] == ["http"]


def test_build_vless_link_with_reality_params():
    link = build_vless_link(
        uuid="abc-def",
        host="reality.domain.com",
        port=443,
        name="Reality Node",
        network="tcp",
        security="reality",
        sni="www.google.com",
        fp="firefox",
        flow="xtls-rprx-vision",
        pbk="public-key-value",
        sid="short-id",
        spx="/",
    )

    parsed = urlparse(link)
    qs = parse_qs(parsed.query)
    assert qs["security"] == ["reality"]
    assert qs["sni"] == ["www.google.com"]
    assert qs["fp"] == ["firefox"]
    assert qs["flow"] == ["xtls-rprx-vision"]
    assert qs["pbk"] == ["public-key-value"]
    assert qs["sid"] == ["short-id"]
    assert qs["spx"] == ["/"]


def test_build_vless_link_omits_empty_params():
    link = build_vless_link(
        uuid="abc",
        host="h.com",
        port=443,
    )
    parsed = urlparse(link)
    qs = parse_qs(parsed.query)
    # Only type and security defaults should appear (both have non-empty defaults)
    assert "sni" not in qs
    assert "fp" not in qs
    assert "flow" not in qs
    assert "alpn" not in qs
    assert "path" not in qs
    assert "host" not in qs
    assert "headerType" not in qs
    assert "pbk" not in qs
    assert "sid" not in qs
    assert "spx" not in qs


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


def test_build_trojan_link_with_tls_params():
    link = build_trojan_link(
        password="pw",
        host="t.domain.com",
        port=443,
        name="Trojan TLS",
        network="grpc",
        security="tls",
        sni="t.domain.com",
        alpn="h2",
        fp="safari",
        path="/grpc-path",
        host_header="t.domain.com",
        header_type="gun",
    )

    parsed = urlparse(link)
    qs = parse_qs(parsed.query)
    assert qs["type"] == ["grpc"]
    assert qs["security"] == ["tls"]
    assert qs["sni"] == ["t.domain.com"]
    assert qs["alpn"] == ["h2"]
    assert qs["fp"] == ["safari"]
    assert qs["path"] == ["/grpc-path"]
    assert qs["host"] == ["t.domain.com"]
    assert qs["headerType"] == ["gun"]


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
