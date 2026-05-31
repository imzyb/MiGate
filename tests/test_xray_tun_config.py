import json

from migate.config import MiGateConfig, VPNConfig
from migate.xray.tun_config import build_xray_tun_config, render_xray_tun_config


def test_build_xray_tun_config_routes_tun_inbound_to_safe_socks_without_freedom():
    cfg = MiGateConfig(vpn=VPNConfig(interface="tun-migate"))

    config = build_xray_tun_config(cfg)

    assert config["log"] == {"loglevel": "warning"}
    assert config["inbounds"] == [
        {
            "tag": "migate-tun-in",
            "protocol": "tun",
            "settings": {
                "interfaceName": "tun-migate",
                "mtu": 1500,
                "stack": "system",
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }
    ]
    protocols = {outbound["protocol"] for outbound in config["outbounds"]}
    assert protocols == {"socks", "blackhole"}
    assert "freedom" not in protocols
    safe_outbound = config["outbounds"][0]
    assert safe_outbound["tag"] == "migate-vpngate"
    assert safe_outbound["settings"]["servers"] == [{"address": "127.0.0.1", "port": 34501}]
    assert config["routing"]["domainStrategy"] == "IPIfNonMatch"
    assert config["routing"]["rules"] == [
        {"type": "field", "inboundTag": ["migate-tun-in"], "outboundTag": "migate-vpngate"},
        {"type": "field", "outboundTag": "blocked"},
    ]


def test_render_xray_tun_config_is_stable_json_and_side_effect_free():
    rendered = render_xray_tun_config(MiGateConfig())

    parsed = json.loads(rendered)
    assert parsed == build_xray_tun_config(MiGateConfig())
    assert rendered.endswith("\n")
    assert '"freedom"' not in rendered
    assert '"direct"' not in rendered.lower()
    assert '"performed_side_effects"' not in rendered
