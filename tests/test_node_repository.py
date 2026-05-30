from migate.database.repository import NodeRepository


def test_node_repository_saves_and_lists_nodes(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    repo.initialize()

    node = repo.create_node(
        protocol="vless",
        name="MiGate JP",
        host="example.com",
        port=443,
        credential="00000000-0000-4000-8000-000000000001",
        share_link="vless://00000000-0000-4000-8000-000000000001@example.com:443?type=tcp&security=none#MiGate%20JP",
        subscription="dmxlc3M6Ly9h",
    )

    nodes = repo.list_nodes()

    assert node.id == 1
    assert len(nodes) == 1
    assert nodes[0].protocol == "vless"
    assert nodes[0].name == "MiGate JP"
    assert nodes[0].host == "example.com"
    assert nodes[0].port == 443
    assert nodes[0].enabled is True
    assert nodes[0].share_link.startswith("vless://")
    assert nodes[0].subscription == "dmxlc3M6Ly9h"


def test_node_repository_lists_newest_first(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    repo.initialize()

    repo.create_node(protocol="vless", name="first", host="a.example", port=443, credential="a", share_link="vless://a", subscription="sub-a")
    repo.create_node(protocol="trojan", name="second", host="b.example", port=8443, credential="b", share_link="trojan://b", subscription="sub-b")

    nodes = repo.list_nodes()

    assert [node.name for node in nodes] == ["second", "first"]
