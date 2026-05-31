from __future__ import annotations

import json
from typing import Any

from migate.config import MiGateConfig
from migate.xray.config_builder import build_blackhole_outbound, build_migate_socks_outbound

XrayTunObject = dict[str, Any]


def build_xray_tun_inbound(config: MiGateConfig) -> XrayTunObject:
    return {
        "tag": "migate-tun-in",
        "protocol": "tun",
        "settings": {
            "interfaceName": config.vpn.interface,
            "mtu": 1500,
            "stack": "system",
        },
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


def build_xray_tun_config(config: MiGateConfig) -> XrayTunObject:
    tun_inbound = build_xray_tun_inbound(config)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [tun_inbound],
        "outbounds": [
            build_migate_socks_outbound(config),
            build_blackhole_outbound(),
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "inboundTag": [tun_inbound["tag"]], "outboundTag": config.xray.default_outbound_tag},
                {"type": "field", "outboundTag": "blocked"},
            ],
        },
    }


def render_xray_tun_config(config: MiGateConfig) -> str:
    return json.dumps(build_xray_tun_config(config), indent=2, sort_keys=True) + "\n"
