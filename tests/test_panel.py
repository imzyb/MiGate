from html import unescape

from fastapi.testclient import TestClient

from migate.api.app import create_app
from migate.database.repository import NodeRepository
from migate.egress.lifecycle import EgressLifecycleResult
from migate.egress.status import EgressStatusCheck, EgressStatusReport
from migate.systemd.manager import SystemdResult
from migate.xray.install_executor import XrayInstallDryRunResult, XrayInstallDryRunStep
from migate.xray.install_plan import XrayInstallPlan, XrayInstallStep
from migate.xray.runtime import XrayRuntimeStatus
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
    assert "ExecStart=/usr/local/bin/migate panel --host 127.0.0.1 --port 8787" in decoded
    assert "uvicorn migate.api.app:create_app" not in decoded
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


def test_panel_home_shows_xray_runtime_status_without_install_side_effects(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    calls = []

    def runtime_loader() -> XrayRuntimeStatus:
        calls.append("runtime")
        return XrayRuntimeStatus(
            status="installed",
            bin_path="/usr/local/bin/xray",
            version="1.8.24",
            message="xray is installed",
            returncode=0,
            stdout="Xray 1.8.24\n",
            stderr="",
        )

    client = TestClient(create_app(node_repository=repo, xray_runtime_loader=runtime_loader))

    response = client.get("/")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Xray 运行时" in decoded
    assert "installed" in decoded
    assert "/usr/local/bin/xray" in decoded
    assert "1.8.24" in decoded
    assert "刷新 Xray 运行时" in decoded
    assert "下载 Xray" not in decoded
    assert "安装 Xray" not in decoded
    assert calls == ["runtime"]


def test_panel_xray_runtime_refresh_shows_not_installed_guidance(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")

    def runtime_loader() -> XrayRuntimeStatus:
        return XrayRuntimeStatus(
            status="not_installed",
            bin_path="/usr/local/bin/xray",
            version=None,
            message="xray binary not found: /usr/local/bin/xray",
        )

    client = TestClient(create_app(node_repository=repo, xray_runtime_loader=runtime_loader))

    response = client.post("/xray/runtime/refresh")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Xray 运行时已刷新" in decoded
    assert "not_installed" in decoded
    assert "xray binary not found" in decoded
    assert "请先安装 xray-core，或修改 MiGate Xray bin_path" in decoded
    assert "下载 Xray" not in decoded
    assert "安装 Xray" not in decoded


def test_api_xray_runtime_returns_read_only_runtime_status(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    calls = []

    def runtime_loader() -> XrayRuntimeStatus:
        calls.append("runtime")
        return XrayRuntimeStatus(
            status="installed",
            bin_path="/usr/local/bin/xray",
            version="1.8.24",
            message="xray is installed",
            returncode=0,
            stdout="Xray 1.8.24\n",
            stderr="",
        )

    client = TestClient(create_app(node_repository=repo, xray_runtime_loader=runtime_loader))

    response = client.get("/api/xray/runtime")

    assert response.status_code == 200
    assert response.json() == {
        "status": "installed",
        "bin_path": "/usr/local/bin/xray",
        "version": "1.8.24",
        "message": "xray is installed",
        "returncode": 0,
        "stdout": "Xray 1.8.24\n",
        "stderr": "",
        "performed_side_effects": False,
    }
    assert calls == ["runtime"]


def test_panel_home_shows_xray_install_plan_preview_without_side_effects(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    calls = []

    def install_plan_loader() -> XrayInstallPlan:
        calls.append("install-plan")
        return XrayInstallPlan(
            version="latest",
            system="linux",
            arch="arm64-v8a",
            bin_path="/usr/local/bin/xray",
            config_dir="/etc/migate/xray",
            archive_name="Xray-linux-arm64-v8a.zip",
            download_url="https://github.com/XTLS/Xray-core/releases/download/latest/Xray-linux-arm64-v8a.zip",
            steps=[XrayInstallStep("download_archive", "下载 xray-core zip")],
            commands=[],
            performs_side_effects=False,
        )

    client = TestClient(create_app(node_repository=repo, xray_install_plan_loader=install_plan_loader))

    response = client.get("/")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Xray 安装计划预览" in decoded
    assert "linux-arm64-v8a" in decoded
    assert "Xray-linux-arm64-v8a.zip" in decoded
    assert "https://github.com/XTLS/Xray-core/releases/download/latest/Xray-linux-arm64-v8a.zip" in decoded
    assert "下载 xray-core zip" in decoded
    assert "当前不会执行安装" in decoded
    assert ">执行安装<" not in decoded
    assert "下载并安装" not in decoded
    assert calls == ["install-plan"]


def test_panel_xray_install_plan_refresh_shows_preview(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")

    def install_plan_loader() -> XrayInstallPlan:
        return XrayInstallPlan(
            version="v1.8.24",
            system="linux",
            arch="64",
            bin_path="/usr/local/bin/xray",
            config_dir="/etc/migate/xray",
            archive_name="Xray-linux-64.zip",
            download_url="https://github.com/XTLS/Xray-core/releases/download/v1.8.24/Xray-linux-64.zip",
            steps=[XrayInstallStep("verify_version", "xray version 验证")],
            commands=[],
            performs_side_effects=False,
        )

    client = TestClient(create_app(node_repository=repo, xray_install_plan_loader=install_plan_loader))

    response = client.post("/xray/install-plan/refresh")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Xray 安装计划已刷新" in decoded
    assert "v1.8.24" in decoded
    assert "linux-64" in decoded
    assert "xray version 验证" in decoded
    assert "commands: []" in decoded
    assert "performs_side_effects: False" in decoded


def test_panel_xray_install_dry_run_shows_structured_preview_without_side_effects(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    calls = []

    def dry_run_loader() -> XrayInstallDryRunResult:
        calls.append("dry-run")
        return XrayInstallDryRunResult(
            status="dry_run",
            message="planned only; no commands executed",
            steps=[
                XrayInstallDryRunStep(
                    action="download_archive",
                    description="下载 xray-core zip",
                    status="planned",
                    command_preview="curl -fsSL https://example.invalid/xray.zip -o /tmp/xray.zip",
                ),
                XrayInstallDryRunStep(
                    action="install_binary",
                    description="写入 /usr/local/bin/xray",
                    status="planned",
                    command_preview="install -m 0755 /tmp/xray /usr/local/bin/xray",
                ),
            ],
            commands_executed=[],
            performed_side_effects=False,
        )

    client = TestClient(create_app(node_repository=repo, xray_install_dry_run_loader=dry_run_loader))

    response = client.post("/xray/install/dry-run")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Xray 安装 dry-run 结果" in decoded
    assert "dry_run" in decoded
    assert "planned only; no commands executed" in decoded
    assert "download_archive" in decoded
    assert "curl -fsSL https://example.invalid/xray.zip -o /tmp/xray.zip" in decoded
    assert "install -m 0755 /tmp/xray /usr/local/bin/xray" in decoded
    assert "commands_executed: []" in decoded
    assert "performed_side_effects: False" in decoded
    assert "真正安装" not in decoded
    assert ">执行安装<" not in decoded
    assert calls == ["dry-run"]


def test_panel_xray_install_dry_run_rejection_is_rendered_safely(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")

    def dry_run_loader() -> XrayInstallDryRunResult:
        return XrayInstallDryRunResult(
            status="rejected",
            message="dry-run executor refuses plans with side effects",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    client = TestClient(create_app(node_repository=repo, xray_install_dry_run_loader=dry_run_loader))

    response = client.post("/xray/install/dry-run")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Xray 安装 dry-run 结果" in decoded
    assert "rejected" in decoded
    assert "refuses plans with side effects" in decoded
    assert "commands_executed: []" in decoded
    assert "performed_side_effects: False" in decoded
    assert ">执行安装<" not in decoded


def test_panel_xray_install_apis_return_webui_ready_json_without_side_effects(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    calls = []

    def install_plan_loader() -> XrayInstallPlan:
        calls.append("plan")
        return XrayInstallPlan(
            version="v1.8.24",
            system="linux",
            arch="64",
            bin_path="/usr/local/bin/xray",
            config_dir="/etc/migate/xray",
            archive_name="Xray-linux-64.zip",
            download_url="https://example.invalid/Xray-linux-64.zip",
            steps=[
                XrayInstallStep("download_archive", "下载 xray-core zip"),
                XrayInstallStep("verify_version", "xray version 验证"),
            ],
            commands=[],
            performs_side_effects=False,
        )

    def dry_run_loader() -> XrayInstallDryRunResult:
        calls.append("dry-run")
        return XrayInstallDryRunResult(
            status="dry_run",
            message="planned only; no commands executed",
            steps=[
                XrayInstallDryRunStep(
                    action="download_archive",
                    description="下载 xray-core zip",
                    status="planned",
                    command_preview="curl -fsSL https://example.invalid/Xray-linux-64.zip -o /tmp/Xray-linux-64.zip",
                ),
                XrayInstallDryRunStep(
                    action="verify_version",
                    description="xray version 验证",
                    status="planned",
                    command_preview="/usr/local/bin/xray version",
                ),
            ],
            commands_executed=[],
            performed_side_effects=False,
        )

    client = TestClient(
        create_app(
            node_repository=repo,
            xray_install_plan_loader=install_plan_loader,
            xray_install_dry_run_loader=dry_run_loader,
        )
    )

    plan_response = client.get("/api/xray/install-plan")
    dry_run_response = client.get("/api/xray/install/dry-run")

    assert plan_response.status_code == 200
    assert plan_response.headers["content-type"].startswith("application/json")
    assert plan_response.json() == {
        "version": "v1.8.24",
        "system": "linux",
        "arch": "64",
        "bin_path": "/usr/local/bin/xray",
        "config_dir": "/etc/migate/xray",
        "archive_name": "Xray-linux-64.zip",
        "download_url": "https://example.invalid/Xray-linux-64.zip",
        "steps": [
            {"action": "download_archive", "description": "下载 xray-core zip"},
            {"action": "verify_version", "description": "xray version 验证"},
        ],
        "commands": [],
        "performs_side_effects": False,
    }
    assert dry_run_response.status_code == 200
    assert dry_run_response.headers["content-type"].startswith("application/json")
    assert dry_run_response.json() == {
        "status": "dry_run",
        "message": "planned only; no commands executed",
        "steps": [
            {
                "action": "download_archive",
                "description": "下载 xray-core zip",
                "status": "planned",
                "command_preview": "curl -fsSL https://example.invalid/Xray-linux-64.zip -o /tmp/Xray-linux-64.zip",
            },
            {
                "action": "verify_version",
                "description": "xray version 验证",
                "status": "planned",
                "command_preview": "/usr/local/bin/xray version",
            },
        ],
        "commands_executed": [],
        "performed_side_effects": False,
    }
    assert calls == ["plan", "dry-run"]


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


def test_panel_home_shows_egress_status_card_without_start_stop_actions(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    calls = []

    def egress_status_loader() -> EgressStatusReport:
        calls.append("egress-status")
        return EgressStatusReport(
            status="observed",
            checks=[
                EgressStatusCheck("tun_interface", "failed", "tun-migate interface is missing"),
                EgressStatusCheck("tunnel_process", "failed", "openvpn tunnel for tun-migate is not running"),
                EgressStatusCheck("policy_routing_plan", "ok", "policy routing plan targets table 200 fwmark 0x1 via tun-migate"),
                EgressStatusCheck("egress_guard", "failed", "blocked: tunnel interface is missing"),
            ],
            performed_side_effects=False,
        )

    client = TestClient(create_app(node_repository=repo, egress_status_loader=egress_status_loader))

    response = client.get("/")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Egress 出口状态" in decoded
    assert "刷新 Egress 状态" in decoded
    assert "tun_interface" in decoded
    assert "tun-migate interface is missing" in decoded
    assert "policy_routing_plan" in decoded
    assert "performed_side_effects: False" in decoded
    assert "启动 Egress" not in decoded
    assert "停止 Egress" not in decoded
    assert calls == ["egress-status"]


def test_panel_egress_status_refresh_renders_latest_readonly_report(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")

    def egress_status_loader() -> EgressStatusReport:
        return EgressStatusReport(
            status="observed",
            checks=[
                EgressStatusCheck("tun_interface", "ok", "tun-migate interface exists"),
                EgressStatusCheck("tunnel_process", "ok", "openvpn tunnel for tun-migate is running"),
                EgressStatusCheck("policy_routing_plan", "ok", "policy routing plan targets table 200 fwmark 0x1 via tun-migate"),
                EgressStatusCheck("egress_guard", "ok", "egress is allowed"),
            ],
            performed_side_effects=False,
        )

    client = TestClient(create_app(node_repository=repo, egress_status_loader=egress_status_loader))

    response = client.post("/egress/status/refresh")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Egress 出口状态已刷新" in decoded
    assert "observed" in decoded
    assert "tun-migate interface exists" in decoded
    assert "openvpn tunnel for tun-migate is running" in decoded
    assert "egress is allowed" in decoded
    assert "performed_side_effects: False" in decoded
    assert "启动 Egress" not in decoded
    assert "停止 Egress" not in decoded


def test_panel_home_shows_egress_dry_run_controls_without_real_actions(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    client = TestClient(create_app(node_repository=repo))

    response = client.get("/")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Egress Dry-run 预览" in decoded
    assert "Dry-run Egress Up" in decoded
    assert "Dry-run Egress Down" in decoded
    assert 'action="/egress/up/dry-run"' in decoded
    assert 'action="/egress/down/dry-run"' in decoded
    assert "真正启动 Egress" not in decoded
    assert "真正停止 Egress" not in decoded


def test_panel_egress_up_dry_run_renders_planned_openvpn_and_routing_commands(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    calls = []

    def egress_up_dry_run_loader() -> EgressLifecycleResult:
        calls.append("egress-up-dry-run")
        return EgressLifecycleResult(
            status="dry_run",
            message="planned only; no egress up commands executed",
            phases=[],
            commands_executed=[
                "openvpn --config /var/lib/migate/runtime/active.ovpn --writepid /var/lib/migate/runtime/openvpn.pid",
                "ip rule add fwmark 0x66 table 100",
                "ip route add default dev tun-migate table 100",
            ],
            performed_side_effects=False,
        )

    client = TestClient(create_app(node_repository=repo, egress_up_dry_run_loader=egress_up_dry_run_loader))

    response = client.post("/egress/up/dry-run")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Egress Up dry-run 结果" in decoded
    assert "planned only; no egress up commands executed" in decoded
    assert "openvpn --config /var/lib/migate/runtime/active.ovpn" in decoded
    assert "ip rule add fwmark 0x66 table 100" in decoded
    assert "ip route add default dev tun-migate table 100" in decoded
    assert "performed_side_effects: False" in decoded
    assert calls == ["egress-up-dry-run"]


def test_panel_egress_down_dry_run_renders_planned_cleanup_and_stop_commands(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")

    def egress_down_dry_run_loader() -> EgressLifecycleResult:
        return EgressLifecycleResult(
            status="dry_run",
            message="planned only; no egress down commands executed",
            phases=[],
            commands_executed=[
                "ip route del default dev tun-migate table 100",
                "ip rule del fwmark 0x66 table 100",
                "kill -TERM <pid from /var/lib/migate/runtime/openvpn.pid>",
            ],
            performed_side_effects=False,
        )

    client = TestClient(create_app(node_repository=repo, egress_down_dry_run_loader=egress_down_dry_run_loader))

    response = client.post("/egress/down/dry-run")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Egress Down dry-run 结果" in decoded
    assert "planned only; no egress down commands executed" in decoded
    assert "ip route del default dev tun-migate table 100" in decoded
    assert "ip rule del fwmark 0x66 table 100" in decoded
    assert "kill -TERM <pid from /var/lib/migate/runtime/openvpn.pid>" in decoded
    assert "performed_side_effects: False" in decoded


def test_panel_egress_status_api_returns_readonly_report(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    calls = []

    def egress_status_loader() -> EgressStatusReport:
        calls.append("egress-status")
        return EgressStatusReport(
            status="observed",
            checks=[
                EgressStatusCheck("tun_interface", "ok", "tun-migate interface exists"),
                EgressStatusCheck("tunnel_process", "failed", "xray-tun tunnel for tun-migate is not running"),
                EgressStatusCheck("egress_guard", "failed", "blocked: tunnel is not running"),
            ],
            performed_side_effects=False,
        )

    client = TestClient(create_app(node_repository=repo, egress_status_loader=egress_status_loader))

    response = client.get("/api/egress/status")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "status": "observed",
        "checks": [
            {"name": "tun_interface", "status": "ok", "message": "tun-migate interface exists"},
            {"name": "tunnel_process", "status": "failed", "message": "xray-tun tunnel for tun-migate is not running"},
            {"name": "egress_guard", "status": "failed", "message": "blocked: tunnel is not running"},
        ],
        "performed_side_effects": False,
    }
    assert calls == ["egress-status"]


def test_panel_egress_dry_run_api_returns_up_and_down_json_without_side_effects(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    calls = []

    def egress_up_dry_run_loader() -> EgressLifecycleResult:
        calls.append("up")
        return EgressLifecycleResult(
            status="dry_run",
            message="planned only; no egress up commands executed",
            phases=[],
            commands_executed=[
                "openvpn --config /var/lib/migate/runtime/active.ovpn --writepid /var/lib/migate/runtime/openvpn.pid",
                "ip rule add fwmark 0x66 table 100",
                "ip route add default dev tun-migate table 100",
            ],
            performed_side_effects=False,
        )

    def egress_down_dry_run_loader() -> EgressLifecycleResult:
        calls.append("down")
        return EgressLifecycleResult(
            status="dry_run",
            message="planned only; no egress down commands executed",
            phases=[],
            commands_executed=[
                "ip route del default dev tun-migate table 100",
                "ip rule del fwmark 0x66 table 100",
                "kill -TERM <pid from /var/lib/migate/runtime/openvpn.pid>",
            ],
            performed_side_effects=False,
        )

    client = TestClient(
        create_app(
            node_repository=repo,
            egress_up_dry_run_loader=egress_up_dry_run_loader,
            egress_down_dry_run_loader=egress_down_dry_run_loader,
        )
    )

    up_response = client.get("/api/egress/up/dry-run")
    down_response = client.get("/api/egress/down/dry-run")

    assert up_response.status_code == 200
    assert up_response.headers["content-type"].startswith("application/json")
    assert up_response.json() == {
        "status": "dry_run",
        "message": "planned only; no egress up commands executed",
        "commands_executed": [
            "openvpn --config /var/lib/migate/runtime/active.ovpn --writepid /var/lib/migate/runtime/openvpn.pid",
            "ip rule add fwmark 0x66 table 100",
            "ip route add default dev tun-migate table 100",
        ],
        "phases": [],
        "performed_side_effects": False,
    }
    assert down_response.status_code == 200
    assert down_response.headers["content-type"].startswith("application/json")
    assert down_response.json() == {
        "status": "dry_run",
        "message": "planned only; no egress down commands executed",
        "commands_executed": [
            "ip route del default dev tun-migate table 100",
            "ip rule del fwmark 0x66 table 100",
            "kill -TERM <pid from /var/lib/migate/runtime/openvpn.pid>",
        ],
        "phases": [],
        "performed_side_effects": False,
    }
    assert calls == ["up", "down"]


def test_panel_home_shows_validation_gated_xray_restart_action(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    client = TestClient(create_app(node_repository=repo, xray_config_path=tmp_path / "config.json"))

    response = client.get("/")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "校验并重启 Xray" in decoded
    assert 'action="/xray/restart"' in decoded


def test_panel_xray_restart_does_not_touch_systemd_when_validation_fails(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    calls = []

    def validator(path):
        return XrayValidationResult(status="invalid", returncode=1, stdout="", stderr="bad config")

    def daemon_reloader():
        calls.append("daemon-reload")
        return SystemdResult(status="success", returncode=0, stdout="", stderr="")

    def restarter(service_name: str):
        calls.append(f"restart:{service_name}")
        return SystemdResult(status="success", returncode=0, stdout="", stderr="")

    client = TestClient(
        create_app(
            node_repository=repo,
            xray_config_path=tmp_path / "config.json",
            xray_validator=validator,
            systemd_daemon_reloader=daemon_reloader,
            systemd_restarter=restarter,
        )
    )

    response = client.post("/xray/restart")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Xray 未重启" in decoded
    assert "配置校验失败" in decoded
    assert "bad config" in decoded
    assert calls == []


def test_panel_xray_restart_runs_daemon_reload_then_restart_after_valid_config(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    calls = []

    def validator(path):
        return XrayValidationResult(status="valid", returncode=0, stdout="config ok", stderr="")

    def daemon_reloader():
        calls.append("daemon-reload")
        return SystemdResult(status="success", returncode=0, stdout="daemon ok", stderr="")

    def restarter(service_name: str):
        calls.append(f"restart:{service_name}")
        return SystemdResult(status="success", returncode=0, stdout="restart ok", stderr="")

    client = TestClient(
        create_app(
            node_repository=repo,
            xray_config_path=tmp_path / "config.json",
            xray_validator=validator,
            systemd_daemon_reloader=daemon_reloader,
            systemd_restarter=restarter,
        )
    )

    response = client.post("/xray/restart")

    assert response.status_code == 200
    decoded = unescape(response.text)
    assert "Xray 重启已执行" in decoded
    assert "config ok" in decoded
    assert "daemon ok" in decoded
    assert "restart ok" in decoded
    assert calls == ["daemon-reload", "restart:migate-xray.service"]


def test_panel_status_summary_api_returns_webui_ready_readonly_json(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    repo.initialize()
    repo.create_node(
        protocol="vless",
        name="MiGate JP",
        host="example.com",
        port=443,
        credential="00000000-0000-4000-8000-000000000001",
        share_link="vless://00000000-0000-4000-8000-000000000001@example.com:443#MiGate%20JP",
        subscription="dmxlc3M6Ly8wMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDFAZXhhbXBsZS5jb206NDQzI01pR2F0ZSUyMEpQ",
    )

    calls = []

    def runtime_loader() -> XrayRuntimeStatus:
        calls.append("runtime")
        return XrayRuntimeStatus(
            status="installed",
            bin_path="/usr/local/bin/xray",
            version="1.8.24",
            message="xray is installed",
            returncode=0,
            stdout="Xray 1.8.24\n",
            stderr="",
        )

    def egress_status_loader() -> EgressStatusReport:
        calls.append("egress")
        return EgressStatusReport(
            status="observed",
            checks=[
                EgressStatusCheck("tun_interface", "ok", "tun-migate interface exists"),
                EgressStatusCheck("tunnel_process", "failed", "xray-tun tunnel for tun-migate is not running"),
                EgressStatusCheck("egress_guard", "failed", "blocked: tunnel is not running"),
            ],
            performed_side_effects=False,
        )

    def status_loader(service_name: str) -> SystemdResult:
        calls.append(f"status:{service_name}")
        if service_name == "migate-xray.service":
            return SystemdResult(status="success", returncode=0, stdout="active (running)", stderr="")
        return SystemdResult(status="failed", returncode=3, stdout="", stderr="inactive")

    client = TestClient(
        create_app(
            node_repository=repo,
            xray_runtime_loader=runtime_loader,
            egress_status_loader=egress_status_loader,
            systemd_status_loader=status_loader,
        )
    )

    response = client.get("/api/status/summary")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "status": "degraded",
        "nodes": {"total": 1, "enabled": 1},
        "xray": {
            "status": "installed",
            "bin_path": "/usr/local/bin/xray",
            "version": "1.8.24",
            "message": "xray is installed",
            "returncode": 0,
        },
        "egress": {
            "status": "observed",
            "performed_side_effects": False,
            "checks": [
                {"name": "tun_interface", "status": "ok", "message": "tun-migate interface exists"},
                {"name": "tunnel_process", "status": "failed", "message": "xray-tun tunnel for tun-migate is not running"},
                {"name": "egress_guard", "status": "failed", "message": "blocked: tunnel is not running"},
            ],
        },
        "services": {
            "migate-xray.service": {
                "status": "success",
                "returncode": 0,
                "stdout": "active (running)",
                "stderr": "",
            },
            "migate-panel.service": {
                "status": "failed",
                "returncode": 3,
                "stdout": "",
                "stderr": "inactive",
            },
        },
        "performed_side_effects": False,
    }
    assert calls == ["runtime", "egress", "status:migate-xray.service", "status:migate-panel.service"]


def test_panel_systemd_status_api_returns_readonly_service_statuses(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    calls = []

    def status_loader(service_name: str) -> SystemdResult:
        calls.append(service_name)
        if service_name == "migate-xray.service":
            return SystemdResult(status="success", returncode=0, stdout="active (running)", stderr="")
        return SystemdResult(status="failed", returncode=3, stdout="", stderr="inactive")

    client = TestClient(create_app(node_repository=repo, systemd_status_loader=status_loader))

    response = client.get("/api/systemd/status")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "services": {
            "migate-xray.service": {
                "status": "success",
                "returncode": 0,
                "stdout": "active (running)",
                "stderr": "",
            },
            "migate-panel.service": {
                "status": "failed",
                "returncode": 3,
                "stdout": "",
                "stderr": "inactive",
            },
        },
        "systemctl_commands_executed": [],
        "performed_side_effects": False,
    }
    assert calls == ["migate-xray.service", "migate-panel.service"]


def test_panel_nodes_api_returns_sanitized_webui_ready_json(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    repo.initialize()
    node = repo.create_node(
        protocol="vless",
        name="MiGate JP",
        host="example.com",
        port=443,
        credential="00000000-0000-4000-8000-000000000001",
        share_link="vless://00000000-0000-4000-8000-000000000001@example.com:443#MiGate%20JP",
        subscription="dmxlc3M6Ly8wMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDFAZXhhbXBsZS5jb206NDQzI01pR2F0ZSUyMEpQ",
    )
    client = TestClient(create_app(node_repository=repo))

    response = client.get("/api/nodes")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "nodes": [
            {
                "id": node.id,
                "protocol": "vless",
                "name": "MiGate JP",
                "host": "example.com",
                "port": 443,
                "enabled": True,
                "created_at": node.created_at,
            }
        ],
        "counts": {"total": 1, "enabled": 1},
        "performed_side_effects": False,
    }
    body = response.text
    assert "credential" not in body
    assert "subscription" not in body
    assert "share_link" not in body
    assert "00000000-0000-4000-8000-000000000001" not in body
    assert "dmxlc3M" not in body


def test_panel_xray_config_preview_api_returns_readonly_generated_config(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    repo.initialize()
    repo.create_node(
        protocol="vless",
        name="MiGate JP",
        host="example.com",
        port=443,
        credential="00000000-0000-4000-8000-000000000001",
        share_link="vless://example",
        subscription="dmxlc3M=",
    )
    repo.create_node(
        protocol="trojan",
        name="Disabled Trojan",
        host="disabled.example.com",
        port=8443,
        credential="disabled-secret",
        share_link="trojan://disabled",
        subscription="dHJvamFu",
    )
    with repo._connect() as conn:
        conn.execute("UPDATE nodes SET enabled = 0 WHERE protocol = 'trojan'")
        conn.commit()
    config_path = tmp_path / "etc" / "migate" / "xray" / "config.json"
    client = TestClient(create_app(node_repository=repo, xray_config_path=config_path))

    response = client.get("/api/xray/config/preview")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert payload["status"] == "preview"
    assert payload["target_path"] == str(config_path)
    assert payload["counts"] == {"total_nodes": 2, "enabled_nodes": 1, "inbounds": 1}
    assert payload["performed_side_effects"] is False
    assert payload["config"]["inbounds"][0]["tag"] == "node-1-vless"
    assert payload["config"]["inbounds"][0]["protocol"] == "vless"
    assert {outbound["protocol"] for outbound in payload["config"]["outbounds"]} == {"socks", "blackhole"}
    assert "freedom" not in response.text
    assert "disabled-secret" not in response.text
    assert not config_path.exists()


def test_panel_systemd_units_preview_api_returns_readonly_unit_contract(tmp_path):
    repo = NodeRepository(tmp_path / "migate.db")
    unit_dir = tmp_path / "systemd"
    client = TestClient(create_app(node_repository=repo, systemd_unit_dir=unit_dir))

    response = client.get("/api/systemd/units/preview")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert payload["status"] == "preview"
    assert payload["target_dir"] == str(unit_dir)
    assert payload["performed_side_effects"] is False
    assert payload["systemctl_commands_executed"] == []
    assert payload["units"][0]["name"] == "migate-xray.service"
    assert payload["units"][0]["target_path"] == str(unit_dir / "migate-xray.service")
    assert "ExecStart=/usr/local/bin/xray run -config /etc/migate/xray/config.json" in payload["units"][0]["content"]
    assert payload["units"][1]["name"] == "migate-panel.service"
    assert payload["units"][1]["target_path"] == str(unit_dir / "migate-panel.service")
    assert "ExecStart=/usr/local/bin/migate panel --host 127.0.0.1 --port 8787" in payload["units"][1]["content"]
    assert not unit_dir.exists()


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
