from __future__ import annotations

import json
import re
from collections.abc import Iterable

from migate.config import MiGateConfig
from migate.database.repository import InboundRecord, NodeRecord
from migate.xray.config_builder import (
    XrayObject,
    build_full_config,
    build_shadowsocks_inbound,
    build_trojan_tcp_inbound,
    build_vless_tcp_inbound,
)


def _sanitize_tag(remark: str) -> str:
    """Convert remark to a safe xray tag: alphanumeric + hyphens only."""
    tag = re.sub(r"[^a-zA-Z0-9\-]", "-", remark)
    tag = re.sub(r"-+", "-", tag).strip("-")
    return f"inbound-{tag}"


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


def inbound_to_xray_inbound(record: InboundRecord) -> XrayObject | None:
    """Convert an InboundRecord to an xray inbound config dict.

    Returns None for disabled inbounds.
    """
    if not record.enabled:
        return None

    tag = _sanitize_tag(record.remark)
    try:
        settings = json.loads(record.settings) if record.settings else {}
    except (json.JSONDecodeError, TypeError):
        settings = {}

    try:
        stream_settings = json.loads(record.stream_settings) if record.stream_settings else {}
    except (json.JSONDecodeError, TypeError):
        stream_settings = {}

    inbound: XrayObject = {
        "tag": tag,
        "listen": record.listen,
        "port": record.port,
        "protocol": record.protocol,
        "settings": settings,
    }

    if stream_settings:
        inbound["streamSettings"] = stream_settings

    return inbound


def build_config_from_nodes(config: MiGateConfig, nodes: Iterable[NodeRecord]) -> XrayObject:
    inbounds = [node_to_inbound(node) for node in nodes if node.enabled]
    return build_full_config(config, inbounds=inbounds)


def build_config_from_nodes_and_inbounds(
    config: MiGateConfig,
    *,
    nodes: Iterable[NodeRecord],
    inbounds: Iterable[InboundRecord],
) -> XrayObject:
    """Build xray config combining node-based inbounds and user-defined inbound rules."""
    node_inbounds = [node_to_inbound(node) for node in nodes if node.enabled]
    rule_inbounds = [ib for record in inbounds if (ib := inbound_to_xray_inbound(record)) is not None]
    all_inbounds = node_inbounds + rule_inbounds
    return build_full_config(config, inbounds=all_inbounds)
