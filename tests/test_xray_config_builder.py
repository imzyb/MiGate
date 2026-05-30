from migate.config import MiGateConfig
from migate.xray.config_builder import (
    build_full_config,
    build_migate_socks_outbound,
    build_shadowsocks_inbound,
    build_trojan_tcp_inbound,
    build_vless_tcp_inbound,
)


def test_build_migate_socks_outbound_uses_local_socks_proxy():
    cfg = MiGateConfig()

    outbound = build_migate_socks_outbound(cfg)

    assert outbound["tag"] == "migate-vpngate"
    assert outbound["protocol"] == "socks"
    assert outbound["settings"]["servers"][0]["address"] == "127.0.0.1"
    assert outbound["settings"]["servers"][0]["port"] == 34501


def test_build_vless_tcp_inbound_contains_client_uuid_and_tag():
    inbound = build_vless_tcp_inbound(
        tag="vless-main",
        port=443,
        client_uuid="00000000-0000-4000-8000-000000000001",
        email="sam@example.com",
    )

    assert inbound["tag"] == "vless-main"
    assert inbound["protocol"] == "vless"
    assert inbound["port"] == 443
    assert inbound["settings"]["decryption"] == "none"
    assert inbound["settings"]["clients"][0]["id"] == "00000000-0000-4000-8000-000000000001"
    assert inbound["settings"]["clients"][0]["email"] == "sam@example.com"
    assert inbound["streamSettings"]["network"] == "tcp"


def test_build_trojan_tcp_inbound_contains_password_and_email():
    inbound = build_trojan_tcp_inbound(
        tag="trojan-main",
        port=8443,
        password="secret-password",
        email="sam@example.com",
    )

    assert inbound["tag"] == "trojan-main"
    assert inbound["protocol"] == "trojan"
    assert inbound["port"] == 8443
    assert inbound["settings"]["clients"][0]["password"] == "secret-password"
    assert inbound["settings"]["clients"][0]["email"] == "sam@example.com"
    assert inbound["streamSettings"]["network"] == "tcp"


def test_build_shadowsocks_inbound_uses_compatible_default_method():
    inbound = build_shadowsocks_inbound(
        tag="ss-main",
        port=8388,
        password="ss-password",
        email="sam@example.com",
    )

    assert inbound["tag"] == "ss-main"
    assert inbound["protocol"] == "shadowsocks"
    assert inbound["port"] == 8388
    assert inbound["settings"]["method"] == "aes-128-gcm"
    assert inbound["settings"]["password"] == "ss-password"
    assert inbound["settings"]["email"] == "sam@example.com"


def test_full_xray_config_routes_all_inbounds_to_migate_and_has_no_freedom():
    cfg = MiGateConfig()
    inbounds = [
        build_vless_tcp_inbound(
            tag="vless-main",
            port=443,
            client_uuid="00000000-0000-4000-8000-000000000001",
            email="sam@example.com",
        ),
        build_trojan_tcp_inbound(
            tag="trojan-main",
            port=8443,
            password="secret-password",
            email="sam@example.com",
        ),
    ]

    config = build_full_config(cfg, inbounds=inbounds)

    protocols = {outbound["protocol"] for outbound in config["outbounds"]}
    assert "freedom" not in protocols
    assert "socks" in protocols
    assert "blackhole" in protocols
    rules = config["routing"]["rules"]
    assert rules[0]["inboundTag"] == ["vless-main", "trojan-main"]
    assert rules[0]["outboundTag"] == "migate-vpngate"
    assert config["stats"] == {}
    assert config["api"]["services"] == ["StatsService"]
