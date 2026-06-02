from __future__ import annotations

from typing import Any

from migate.config import MiGateConfig

XrayObject = dict[str, Any]


def build_migate_socks_outbound(config: MiGateConfig) -> XrayObject:
    return {
        "tag": config.xray.default_outbound_tag,
        "protocol": "socks",
        "settings": {
            "servers": [
                {
                    "address": config.proxy.socks_host,
                    "port": config.proxy.socks_port,
                }
            ]
        },
    }


def build_vless_tcp_inbound(*, tag: str, port: int, client_uuid: str, email: str, listen: str = "0.0.0.0") -> XrayObject:
    return {
        "tag": tag,
        "listen": listen,
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [
                {
                    "id": client_uuid,
                    "email": email,
                    "level": 0,
                }
            ],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "tcp",
        },
    }


def build_trojan_tcp_inbound(*, tag: str, port: int, password: str, email: str, listen: str = "0.0.0.0") -> XrayObject:
    return {
        "tag": tag,
        "listen": listen,
        "port": port,
        "protocol": "trojan",
        "settings": {
            "clients": [
                {
                    "password": password,
                    "email": email,
                    "level": 0,
                }
            ]
        },
        "streamSettings": {
            "network": "tcp",
        },
    }


def build_shadowsocks_inbound(
    *,
    tag: str,
    port: int,
    password: str,
    email: str,
    method: str = "aes-128-gcm",
    listen: str = "0.0.0.0",
) -> XrayObject:
    return {
        "tag": tag,
        "listen": listen,
        "port": port,
        "protocol": "shadowsocks",
        "settings": {
            "method": method,
            "password": password,
            "email": email,
            "network": "tcp,udp",
        },
    }


def build_blackhole_outbound(tag: str = "blocked") -> XrayObject:
    return {
        "tag": tag,
        "protocol": "blackhole",
        "settings": {},
    }


def build_marked_freedom_outbound(tag: str) -> XrayObject:
    return {
        "tag": tag,
        "protocol": "freedom",
        "settings": {},
    }


def build_full_config(config: MiGateConfig, *, inbounds: list[XrayObject]) -> XrayObject:
    inbound_tags = [inbound["tag"] for inbound in inbounds]
    return {
        "log": {
            "loglevel": "warning",
        },
        "api": {
            "tag": "api",
            "services": ["StatsService"],
        },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                }
            }
        },
        "inbounds": inbounds,
        "outbounds": [
            build_migate_socks_outbound(config),
            build_blackhole_outbound(),
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": inbound_tags,
                    "outboundTag": config.xray.default_outbound_tag,
                }
            ]
        },
    }
