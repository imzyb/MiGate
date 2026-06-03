from migate.config import MiGateConfig
from migate.database.repository import NodeRecord
from migate.xray.node_adapter import build_config_from_nodes, node_to_inbound


def make_node(**overrides):
    values = {
        "id": 1,
        "protocol": "vless",
        "name": "MiGate JP",
        "host": "example.com",
        "port": 443,
        "credential": "00000000-0000-4000-8000-000000000001",
        "share_link": "vless://example",
        "subscription": "dmxlc3M=",
        "enabled": True,
        "created_at": "2026-05-30 00:00:00",
    }
    values.update(overrides)
    return NodeRecord(**values)


def test_node_to_inbound_converts_vless_node():
    inbound = node_to_inbound(make_node(protocol="vless", id=7, name="MiGate JP"))

    assert inbound["tag"] == "node-7-vless"
    assert inbound["protocol"] == "vless"
    assert inbound["port"] == 443
    assert inbound["settings"]["clients"][0]["id"] == "00000000-0000-4000-8000-000000000001"
    assert inbound["settings"]["clients"][0]["email"] == "MiGate JP"


def test_node_to_inbound_converts_trojan_node():
    inbound = node_to_inbound(make_node(id=8, protocol="trojan", port=8443, credential="secret"))

    assert inbound["tag"] == "node-8-trojan"
    assert inbound["protocol"] == "trojan"
    assert inbound["port"] == 8443
    assert inbound["settings"]["clients"][0]["password"] == "secret"


def test_node_to_inbound_converts_shadowsocks_node():
    inbound = node_to_inbound(make_node(id=9, protocol="shadowsocks", port=8388, credential="ss-password"))

    assert inbound["tag"] == "node-9-shadowsocks"
    assert inbound["protocol"] == "shadowsocks"
    assert inbound["port"] == 8388
    assert inbound["settings"]["method"] == "aes-128-gcm"
    assert inbound["settings"]["password"] == "ss-password"


def test_build_config_from_nodes_ignores_disabled_nodes_and_blocks_freedom():
    enabled = make_node(id=1, protocol="vless")
    disabled = make_node(id=2, protocol="trojan", enabled=False)

    config = build_config_from_nodes(MiGateConfig(), [enabled, disabled])

    assert [inbound["tag"] for inbound in config["inbounds"]] == ["api", "node-1-vless"]
    assert {outbound["protocol"] for outbound in config["outbounds"]} == {"freedom", "blackhole"}
    # routing rules: api traffic rule first, then node forwarding rule
    node_rule = next(r for r in config["routing"]["rules"] if "node-1-vless" in r.get("inboundTag", []))
    assert node_rule["outboundTag"] == "migate-vpngate"
