from html import unescape

from fastapi.testclient import TestClient

from migate.api.app import create_app
from migate.database.repository import NodeRepository
from migate.systemd.manager import SystemdResult
from migate.xray.validator import XrayValidationResult


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


def test_panel_create_vless_node_returns_share_link_and_subscription(tmp_path):
    client = TestClient(create_app(xray_config_path=tmp_path / "config.json"))

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


def test_panel_persists_created_node_and_lists_it_on_home(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    client = TestClient(create_app(node_repository=repo, xray_config_path=tmp_path / "config.json"))

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
    home = client.get("/")

    assert response.status_code == 200
    assert home.status_code == 200
    assert "已创建节点" in home.text
    assert "MiGate JP" in home.text
    assert "vless" in home.text
    assert "example.com:443" in home.text
    decoded_home = unescape(home.text)
    assert "Xray 配置预览" in decoded_home
    assert '"protocol": "vless"' in decoded_home
    assert '"protocol": "socks"' in decoded_home
    assert '"port": 34501' in decoded_home
    assert '"freedom"' not in decoded_home
    assert "保存 Xray 配置" in decoded_home
    assert "校验 Xray 配置" in decoded_home


def test_panel_save_xray_config_writes_preview_to_config_path(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    config_path = tmp_path / "etc" / "migate" / "xray" / "config.json"
    client = TestClient(create_app(node_repository=repo, xray_config_path=config_path))
    client.post(
        "/nodes/create",
        data={
            "protocol": "vless",
            "host": "example.com",
            "port": "443",
            "name": "MiGate JP",
            "credential": "00000000-0000-4000-8000-000000000001",
        },
    )

    response = client.post("/xray/config/save")

    assert response.status_code == 200
    assert config_path.exists()
    decoded = unescape(response.text)
    assert "Xray 配置已保存" in decoded
    assert str(config_path) in decoded
    assert '"protocol": "vless"' in config_path.read_text(encoding="utf-8")
    assert '"freedom"' not in config_path.read_text(encoding="utf-8")


def test_panel_validate_xray_config_shows_result(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    config_path = tmp_path / "etc" / "migate" / "xray" / "config.json"

    def validator(path):
        assert path == config_path
        return XrayValidationResult(status="valid", returncode=0, stdout="config ok", stderr="")

    client = TestClient(create_app(node_repository=repo, xray_config_path=config_path, xray_validator=validator))

    response = client.post("/xray/config/validate")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Xray 配置校验结果" in decoded
    assert "valid" in decoded
    assert "config ok" in decoded


def test_panel_home_previews_systemd_units_without_starting_services(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    client = TestClient(create_app(node_repository=repo, systemd_unit_dir=tmp_path / "systemd"))

    response = client.get("/")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Systemd 服务文件预览" in decoded
    assert "migate-xray.service" in decoded
    assert "migate-panel.service" in decoded
    assert "ExecStart=/usr/local/bin/xray run -config /etc/migate/xray/config.json" in decoded
    assert "uvicorn migate.api.app:create_app" in decoded
    assert "保存 systemd 服务文件" in decoded
    assert "systemctl" not in decoded


def test_panel_save_systemd_units_writes_unit_files_only(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    unit_dir = tmp_path / "systemd" / "system"
    client = TestClient(create_app(node_repository=repo, systemd_unit_dir=unit_dir))

    response = client.post("/systemd/units/save")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Systemd 服务文件已保存" in decoded
    assert str(unit_dir / "migate-xray.service") in decoded
    assert str(unit_dir / "migate-panel.service") in decoded
    assert (unit_dir / "migate-xray.service").exists()
    assert (unit_dir / "migate-panel.service").exists()
    assert "systemctl" not in decoded


def test_panel_home_shows_safe_service_status_actions_without_restart(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")

    def status_loader(service_name: str) -> SystemdResult:
        if service_name == "migate-xray.service":
            return SystemdResult(status="success", returncode=0, stdout="active (running)", stderr="")
        return SystemdResult(status="failed", returncode=3, stdout="", stderr="inactive")

    client = TestClient(create_app(node_repository=repo, systemd_status_loader=status_loader))

    response = client.get("/")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "服务状态" in decoded
    assert "migate-xray.service" in decoded
    assert "migate-panel.service" in decoded
    assert "active (running)" in decoded
    assert "inactive" in decoded
    assert "刷新服务状态" in decoded
    assert "重启服务" not in decoded
    assert "daemon-reload" not in decoded


def test_panel_service_status_refresh_shows_structured_results(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")

    def status_loader(service_name: str) -> SystemdResult:
        if service_name == "migate-xray.service":
            return SystemdResult(status="systemctl_not_found", returncode=None, stdout="", stderr="systemctl command not found")
        return SystemdResult(status="success", returncode=0, stdout="active (running)", stderr="")

    client = TestClient(create_app(node_repository=repo, systemd_status_loader=status_loader))

    response = client.post("/systemd/status/refresh")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "服务状态已刷新" in decoded
    assert "systemctl_not_found" in decoded
    assert "systemctl command not found" in decoded
    assert "active (running)" in decoded
    assert "重启服务" not in decoded


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
