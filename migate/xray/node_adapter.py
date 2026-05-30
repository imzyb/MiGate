from __future__ import annotations

from collections.abc import Iterable

from migate.config import MiGateConfig
from migate.database.repository import NodeRecord
from migate.xray.config_builder import (
    XrayObject,
    build_full_config,
    build_shadowsocks_inbound,
    build_trojan_tcp_inbound,
    build_vless_tcp_inbound,
)


def node_tag(node: NodeRecord) -> str:
    return f"node-{node.id}-{node.protocol}"


def node_to_inbound(node: NodeRecord) -> XrayObject:
    tag = node_tag(node)
    if node.protocol == "vless":
        return build_vless_tcp_inbound(
            tag=tag,
            port=node.port,
            client_uuid=node.credential,
            email=node.name,
        )
    if node.protocol == "trojan":
        return build_trojan_tcp_inbound(
            tag=tag,
            port=node.port,
            password=node.credential,
            email=node.name,
        )
    if node.protocol == "shadowsocks":
        return build_shadowsocks_inbound(
            tag=tag,
            port=node.port,
            password=node.credential,
            email=node.name,
        )
    raise ValueError(f"unsupported node protocol: {node.protocol}")


def build_config_from_nodes(config: MiGateConfig, nodes: Iterable[NodeRecord]) -> XrayObject:
    inbounds = [node_to_inbound(node) for node in nodes if node.enabled]
    return build_full_config(config, inbounds=inbounds)
