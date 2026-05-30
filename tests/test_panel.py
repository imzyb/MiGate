from fastapi.testclient import TestClient

from migate.api.app import create_app


def test_panel_home_contains_beginner_node_form_and_status_cards():
    client = TestClient(create_app())

    response = client.get("/")

    assert response.status_code == 200
    assert "MiGate" in response.text
    assert "创建节点" in response.text
    assert "VPNGate 出口" in response.text
    assert "Xray 状态" in response.text
    assert "VLESS" in response.text
    assert "Trojan" in response.text
    assert "Shadowsocks" in response.text
    assert 'name="protocol"' in response.text
    assert 'name="host"' in response.text
    assert 'name="port"' in response.text


def test_panel_create_vless_node_returns_share_link_and_subscription():
    client = TestClient(create_app())

    response = client.post(
        "/nodes/create",
        data={
            "protocol": "vless",
            "host": "example.com",
            "port": "443",
            "name": "MiGate JP",
            "credential": "00000000-0000-4000-8000-000000000001",
        },
    )

    assert response.status_code == 200
    assert "节点已生成" in response.text
    assert "vless://00000000-0000-4000-8000-000000000001@example.com:443" in response.text
    assert "订阅内容" in response.text


def test_panel_create_trojan_node_returns_share_link():
    client = TestClient(create_app())

    response = client.post(
        "/nodes/create",
        data={
            "protocol": "trojan",
            "host": "example.com",
            "port": "8443",
            "name": "MiGate Trojan",
            "credential": "secret-password",
        },
    )

    assert response.status_code == 200
    assert "trojan://secret-password@example.com:8443" in response.text


def test_panel_create_shadowsocks_node_returns_share_link():
    client = TestClient(create_app())

    response = client.post(
        "/nodes/create",
        data={
            "protocol": "shadowsocks",
            "host": "example.com",
            "port": "8388",
            "name": "MiGate SS",
            "credential": "ss-password",
        },
    )

    assert response.status_code == 200
    assert "ss://" in response.text
    assert "example.com:8388" in response.text
