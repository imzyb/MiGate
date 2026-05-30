from typer.testing import CliRunner

import migate.main as main_module
from migate.main import app, build_panel_server_config, build_xray_install_cli_plan, run_xray_install_cli
from migate.xray.doctor import DoctorCheck, DoctorReport
from migate.xray.install_runner import XrayInstallCommandResult, XrayInstallResult


runner = CliRunner()


def test_panel_command_accepts_safe_default_host_and_port_without_starting_server():
    result = runner.invoke(app, ["panel", "--dry-run"])

    assert result.exit_code == 0
    assert "MiGate panel" in result.output
    assert "127.0.0.1" in result.output
    assert "8787" in result.output
    assert "uvicorn" in result.output


def test_panel_command_accepts_custom_host_and_port_in_dry_run():
    result = runner.invoke(app, ["panel", "--host", "0.0.0.0", "--port", "9000", "--dry-run"])

    assert result.exit_code == 0
    assert "0.0.0.0" in result.output
    assert "9000" in result.output


def test_build_panel_server_config_keeps_app_factory_target():
    config = build_panel_server_config(host="127.0.0.1", port=8787)

    assert config.app == "migate.api.app:create_app"
    assert config.host == "127.0.0.1"
    assert config.port == 8787
    assert config.factory is True


def test_xray_install_command_defaults_to_dry_run_without_real_execution():
    result = runner.invoke(app, ["xray", "install"])

    assert result.exit_code == 0
    assert "Xray 安装 dry-run" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert "curl -fsSL" in result.output
    assert "install -m 0755" in result.output
    assert "真实安装" not in result.output


def test_xray_install_command_accepts_explicit_dry_run_version_architecture():
    result = runner.invoke(app, ["xray", "install", "--dry-run", "--version", "v1.8.24", "--system", "Linux", "--machine", "x86_64"])

    assert result.exit_code == 0
    assert "版本：v1.8.24" in result.output
    assert "架构：linux-64" in result.output
    assert "Xray-linux-64.zip" in result.output


def test_xray_install_command_yes_requires_explicit_side_effects_flag_for_now():
    result = runner.invoke(app, ["xray", "install", "--yes", "--system", "Linux", "--machine", "x86_64"])

    assert result.exit_code == 0
    assert "真实安装 CLI 已就绪，但当前未启用系统修改" in result.output
    assert "--allow-system-changes" in result.output
    assert "allow_side_effects=False" in result.output


def test_xray_install_command_requires_allow_system_changes_even_with_yes():
    result = runner.invoke(app, ["xray", "install", "--yes", "--system", "Linux", "--machine", "x86_64"])

    assert result.exit_code == 0
    assert "真实安装 CLI 已就绪，但当前未启用系统修改" in result.output
    assert "--allow-system-changes" in result.output
    assert "allow_side_effects=False" in result.output


def test_run_xray_install_cli_executes_runner_only_with_double_gate():
    calls = []

    def fake_runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    result = run_xray_install_cli(
        yes=True,
        allow_system_changes=True,
        dry_run=False,
        system="Linux",
        machine="x86_64",
        version="v1.8.24",
        command_runner=fake_runner,
        existing_binary_checker=lambda path: False,
    )

    assert result.status == "success"
    assert result.performed_side_effects is True
    assert calls
    assert calls[0][0] == "curl"
    assert calls[-1] == ["/usr/local/bin/xray", "version"]


def test_run_xray_install_cli_blocks_real_runner_when_doctor_fails():
    calls = []

    def fake_runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    failed_doctor = DoctorReport(
        status="failed",
        checks=[DoctorCheck(name="command:unzip", status="missing", message="unzip not found")],
    )

    result = run_xray_install_cli(
        yes=True,
        allow_system_changes=True,
        dry_run=False,
        system="Linux",
        machine="x86_64",
        command_runner=fake_runner,
        doctor_loader=lambda: failed_doctor,
    )

    assert result.status == "rejected"
    assert result.performed_side_effects is False
    assert calls == []
    assert "doctor failed" in result.message
    assert "command:unzip" in result.message


def test_run_xray_install_cli_runs_real_runner_when_doctor_passes():
    calls = []

    def fake_runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    ok_doctor = DoctorReport(
        status="ok",
        checks=[DoctorCheck(name="command:curl", status="ok", message="curl found")],
    )

    result = run_xray_install_cli(
        yes=True,
        allow_system_changes=True,
        dry_run=False,
        system="Linux",
        machine="x86_64",
        command_runner=fake_runner,
        existing_binary_checker=lambda path: False,
        doctor_loader=lambda: ok_doctor,
    )

    assert result.status == "success"
    assert result.performed_side_effects is True
    assert calls


def test_run_xray_install_cli_refuses_real_runner_without_double_gate():
    calls = []

    def fake_runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    result = run_xray_install_cli(
        yes=True,
        allow_system_changes=False,
        dry_run=False,
        system="Linux",
        machine="x86_64",
        command_runner=fake_runner,
    )

    assert result.status == "rejected"
    assert result.performed_side_effects is False
    assert calls == []
    assert "allow_system_changes" in result.message


def test_xray_install_command_with_real_gate_prints_doctor_report_before_result(monkeypatch):
    doctor = DoctorReport(
        status="failed",
        checks=[DoctorCheck(name="command:unzip", status="missing", message="unzip not found")],
    )
    monkeypatch.setattr(main_module, "run_xray_install_doctor", lambda: doctor)

    def fake_install_cli(**kwargs):
        raise AssertionError("install runner should not be called when doctor fails")

    monkeypatch.setattr(main_module, "run_xray_install_cli", fake_install_cli)

    result = runner.invoke(app, ["xray", "install", "--yes", "--allow-system-changes", "--system", "Linux", "--machine", "x86_64"])

    assert result.exit_code == 0
    assert "Xray 安装前检查" in result.output
    assert "command:unzip: missing - unzip not found" in result.output
    assert "status: rejected" in result.output
    assert "message: doctor failed" in result.output
    assert result.output.index("Xray 安装前检查") < result.output.rindex("performed_side_effects:")


def test_xray_install_command_with_real_gate_prints_doctor_report_then_success_result(monkeypatch):
    doctor = DoctorReport(
        status="ok",
        checks=[DoctorCheck(name="command:curl", status="ok", message="curl found")],
    )
    monkeypatch.setattr(main_module, "run_xray_install_doctor", lambda: doctor)

    install_result = XrayInstallResult(
        status="success",
        message="all installer steps completed",
        steps=[],
        performed_side_effects=True,
    )
    monkeypatch.setattr(main_module, "run_xray_install_cli", lambda **kwargs: install_result)

    result = runner.invoke(app, ["xray", "install", "--yes", "--allow-system-changes", "--system", "Linux", "--machine", "x86_64"])

    assert result.exit_code == 0
    assert "Xray 安装前检查" in result.output
    assert "command:curl: ok - curl found" in result.output
    assert "status: success" in result.output
    assert "message: all installer steps completed" in result.output
    assert result.output.index("Xray 安装前检查") < result.output.rindex("status: success")


def test_xray_config_preview_command_prints_json_without_saving():
    result = runner.invoke(app, ["xray", "config", "preview"])

    assert result.exit_code == 0
    assert '"outbounds"' in result.output
    assert '"protocol": "socks"' in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_config_save_command_requires_double_gate():
    result = runner.invoke(app, ["xray", "config", "save"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "config save requires yes=True and allow_system_changes=True" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_config_save_command_shows_backup_and_rollback_fields(monkeypatch, tmp_path):
    target = tmp_path / "config.json"

    from migate.xray.config_cli import XrayConfigSaveResult

    monkeypatch.setattr(
        main_module,
        "save_xray_config",
        lambda *args, **kwargs: XrayConfigSaveResult(
            status="invalid",
            message="config validation failed; restored previous config",
            target=target,
            validation_status="invalid",
            performed_side_effects=True,
            backup_path=target.with_name("config.json.bak"),
            rollback_performed=True,
        ),
    )

    result = runner.invoke(app, ["xray", "config", "save", "--yes", "--allow-system-changes", "--target", str(target)])

    assert result.exit_code == 0
    assert f"target: {target}" in result.output
    assert f"backup_path: {target.with_name('config.json.bak')}" in result.output
    assert "rollback_performed: True" in result.output


def test_xray_service_preview_command_prints_unit_without_systemctl():
    result = runner.invoke(app, ["xray", "service", "preview"])

    assert result.exit_code == 0
    assert "Description=MiGate managed Xray service" in result.output
    assert "ExecStart=/usr/local/bin/xray run -config /etc/migate/xray/config.json" in result.output
    assert "ExecStart=systemctl" not in result.output
    assert "daemon-reload" not in result.output
    assert "systemctl restart" not in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_service_save_command_requires_double_gate():
    result = runner.invoke(app, ["xray", "service", "save"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "service save requires yes=True and allow_system_changes=True" in result.output
    assert "systemctl_commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_systemctl_status_command_prints_structured_status(monkeypatch):
    from migate.xray.systemctl_cli import SystemctlActionResult

    monkeypatch.setattr(
        main_module,
        "run_xray_systemctl_action",
        lambda *args, **kwargs: SystemctlActionResult(
            status="success",
            action="status",
            service="migate-xray.service",
            command=["systemctl", "status", "migate-xray.service", "--no-pager"],
            returncode=0,
            stdout="active",
            stderr="",
            performed_side_effects=False,
        ),
    )

    result = runner.invoke(app, ["xray", "systemctl", "status"])

    assert result.exit_code == 0
    assert "status: success" in result.output
    assert "action: status" in result.output
    assert "service: migate-xray.service" in result.output
    assert "stdout: active" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_systemctl_restart_command_requires_double_gate(monkeypatch):
    calls = []

    def fake_action(*args, **kwargs):
        calls.append((args, kwargs))
        from migate.xray.systemctl_cli import SystemctlActionResult

        return SystemctlActionResult(
            status="rejected",
            action="restart",
            service="migate-xray.service",
            command=[],
            returncode=None,
            stdout="",
            stderr="systemctl restart requires yes=True and allow_system_changes=True",
            performed_side_effects=False,
        )

    monkeypatch.setattr(main_module, "run_xray_systemctl_action", fake_action)

    result = runner.invoke(app, ["xray", "systemctl", "restart"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "systemctl restart requires" in result.output
    assert "performed_side_effects: False" in result.output
    assert calls[0][1]["yes"] is False
    assert calls[0][1]["allow_system_changes"] is False


def test_xray_apply_restart_command_requires_double_gate(monkeypatch):
    from migate.xray.apply_cli import XrayApplyResult
    from migate.xray.validator import XrayValidationResult

    calls = []

    def fake_apply(*args, **kwargs):
        calls.append((args, kwargs))
        return XrayApplyResult(
            status="rejected",
            message="apply restart requires yes=True and allow_system_changes=True",
            config_path="/etc/migate/xray/config.json",
            validation=XrayValidationResult("skipped", None, "", ""),
            systemctl_results=[],
            performed_side_effects=False,
        )

    monkeypatch.setattr(main_module, "apply_validated_xray_restart", fake_apply)

    result = runner.invoke(app, ["xray", "apply", "restart"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "validation_status: skipped" in result.output
    assert "systemctl_results: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert calls[0][1]["yes"] is False
    assert calls[0][1]["allow_system_changes"] is False


def test_xray_apply_restart_command_prints_ordered_systemctl_results(monkeypatch):
    from migate.xray.apply_cli import XrayApplyResult
    from migate.xray.systemctl_cli import ALLOWED_XRAY_SERVICE_NAME, SystemctlActionResult
    from migate.xray.validator import XrayValidationResult

    monkeypatch.setattr(
        main_module,
        "apply_validated_xray_restart",
        lambda *args, **kwargs: XrayApplyResult(
            status="success",
            message="config validated and service restarted",
            config_path="/tmp/config.json",
            validation=XrayValidationResult("valid", 0, "config ok", ""),
            systemctl_results=[
                SystemctlActionResult("success", "daemon-reload", ALLOWED_XRAY_SERVICE_NAME, ["systemctl", "daemon-reload"], 0, "reload ok", "", True),
                SystemctlActionResult("success", "restart", ALLOWED_XRAY_SERVICE_NAME, ["systemctl", "restart", ALLOWED_XRAY_SERVICE_NAME], 0, "restart ok", "", True),
            ],
            performed_side_effects=True,
        ),
    )

    result = runner.invoke(
        app,
        ["xray", "apply", "restart", "--config", "/tmp/config.json", "--yes", "--allow-system-changes"],
    )

    assert result.exit_code == 0
    assert "status: success" in result.output
    assert "validation_status: valid" in result.output
    assert "- action: daemon-reload status: success returncode: 0" in result.output
    assert "- action: restart status: success returncode: 0" in result.output
    assert "performed_side_effects: True" in result.output


def test_xray_deploy_command_defaults_to_dry_run_without_side_effects():
    result = runner.invoke(app, ["xray", "deploy", "--system", "Linux", "--machine", "x86_64", "--version", "v1.8.24"])

    assert result.exit_code == 0
    assert "Xray deploy dry-run" in result.output
    assert "status: dry_run" in result.output
    assert "- doctor: planned read-only" in result.output
    assert "- install: planned side-effect" in result.output
    assert "- config_save: planned side-effect" in result.output
    assert "- service_save: planned side-effect" in result.output
    assert "- apply_restart: planned side-effect" in result.output
    assert "- status: planned read-only" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_deploy_command_runs_real_orchestrator_when_double_gated(monkeypatch):
    from migate.xray.deploy_cli import XrayDeployResult, XrayDeployStepResult

    calls = []

    def fake_deploy(*args, **kwargs):
        calls.append((args, kwargs))
        return XrayDeployResult(
            status="success",
            message="xray deploy completed",
            steps=[XrayDeployStepResult("doctor", "success", "doctor ok", object())],
            performed_side_effects=True,
        )

    monkeypatch.setattr(main_module, "run_xray_deploy", fake_deploy)

    result = runner.invoke(
        app,
        [
            "xray",
            "deploy",
            "--no-dry-run",
            "--yes",
            "--allow-system-changes",
            "--system",
            "Linux",
            "--machine",
            "x86_64",
        ],
    )

    assert result.exit_code == 0
    assert "Xray deploy result" in result.output
    assert "status: success" in result.output
    assert "- doctor: success - doctor ok" in result.output
    assert "performed_side_effects: True" in result.output
    assert calls[0][1]["dry_run"] is False
    assert calls[0][1]["yes"] is True
    assert calls[0][1]["allow_system_changes"] is True


def test_proxy_doctor_command_reports_runtime_preflight(monkeypatch):
    from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport

    monkeypatch.setattr(
        main_module,
        "run_proxy_doctor",
        lambda *args, **kwargs: ProxyRuntimeReport(
            status="failed",
            checks=[ProxyRuntimeCheck("tun_interface", "failed", "tun-migate interface is missing")],
            performed_side_effects=False,
        ),
    )

    result = runner.invoke(app, ["proxy", "doctor"])

    assert result.exit_code == 0
    assert "Proxy doctor" in result.output
    assert "status: failed" in result.output
    assert "tun_interface: failed - tun-migate interface is missing" in result.output
    assert "performed_side_effects: False" in result.output


def test_proxy_status_command_reports_observational_status(monkeypatch):
    from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport

    monkeypatch.setattr(
        main_module,
        "run_proxy_status",
        lambda *args, **kwargs: ProxyRuntimeReport(
            status="observed",
            checks=[ProxyRuntimeCheck("socks_listen", "ok", "127.0.0.1:34501 is listening")],
            performed_side_effects=False,
        ),
    )

    result = runner.invoke(app, ["proxy", "status"])

    assert result.exit_code == 0
    assert "Proxy status" in result.output
    assert "status: observed" in result.output
    assert "socks_listen: ok - 127.0.0.1:34501 is listening" in result.output
    assert "performed_side_effects: False" in result.output

def test_proxy_run_command_rejects_when_preflight_fails(monkeypatch):
    from migate.proxy.run import ProxyRunResult
    from migate.proxy.runtime import ProxyRuntimeCheck

    monkeypatch.setattr(
        main_module,
        "run_proxy_placeholder",
        lambda *args, **kwargs: ProxyRunResult(
            status="rejected",
            message="proxy run preflight failed; listener not started",
            checks=[ProxyRuntimeCheck("tun_interface", "failed", "tun-migate interface is missing")],
            listener_started=False,
            forwarding_started=False,
            performed_side_effects=False,
        ),
    )

    result = runner.invoke(app, ["proxy", "run"])

    assert result.exit_code == 1
    assert "Proxy run" in result.output
    assert "status: rejected" in result.output
    assert "tun_interface: failed - tun-migate interface is missing" in result.output
    assert "listener_started: False" in result.output
    assert "forwarding_started: False" in result.output


def test_proxy_run_command_reports_placeholder_when_preflight_passes(monkeypatch):
    from migate.proxy.run import ProxyRunResult
    from migate.proxy.runtime import ProxyRuntimeCheck

    monkeypatch.setattr(
        main_module,
        "run_proxy_placeholder",
        lambda *args, **kwargs: ProxyRunResult(
            status="placeholder",
            message="proxy forwarding is not implemented yet; listener not started",
            checks=[ProxyRuntimeCheck("fail_policy", "ok", "fail_policy is block")],
            listener_started=False,
            forwarding_started=False,
            performed_side_effects=False,
        ),
    )

    result = runner.invoke(app, ["proxy", "run"])

    assert result.exit_code == 0
    assert "status: placeholder" in result.output
    assert "proxy forwarding is not implemented yet" in result.output
    assert "listener_started: False" in result.output
    assert "forwarding_started: False" in result.output


def test_proxy_socks5_plan_command_prints_dry_run_listener_plan():
    result = runner.invoke(app, ["proxy", "socks5", "plan"])

    assert result.exit_code == 0
    assert "SOCKS5 listener plan" in result.output
    assert "bind_host: 127.0.0.1" in result.output
    assert "bind_port: 34501" in result.output
    assert "connection_driver: Socks5Connection" in result.output
    assert "will_listen: False" in result.output
    assert "will_connect_upstream: False" in result.output
    assert "performed_side_effects: False" in result.output


def test_proxy_socks5_serve_command_defaults_to_dry_run_without_listening():
    result = runner.invoke(app, ["proxy", "socks5", "serve"])

    assert result.exit_code == 0
    assert "SOCKS5 serve result" in result.output
    assert "status: dry_run" in result.output
    assert "listener_started: False" in result.output
    assert "upstream_connections: 0" in result.output
    assert "performed_side_effects: False" in result.output


def test_proxy_socks5_serve_command_rejects_real_listen_without_gate():
    result = runner.invoke(app, ["proxy", "socks5", "serve", "--no-dry-run", "--yes"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "requires yes=True and allow_network_listen=True" in result.output
    assert "listener_started: False" in result.output
    assert "performed_side_effects: False" in result.output


def test_proxy_service_preview_command_prints_unit_without_systemctl():
    result = runner.invoke(app, ["proxy", "service", "preview"])

    assert result.exit_code == 0
    assert "Description=MiGate local proxy service" in result.output
    assert "ExecStart=/usr/local/bin/migate proxy run" in result.output
    assert "ExecStart=systemctl" not in result.output
    assert "daemon-reload" not in result.output
    assert "systemctl restart" not in result.output
    assert "systemctl_commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output


def test_proxy_service_save_command_requires_double_gate():
    result = runner.invoke(app, ["proxy", "service", "save"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "proxy service save requires yes=True and allow_system_changes=True" in result.output
    assert "systemctl_commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_doctor_command_reports_dependency_checks():
    result = runner.invoke(app, ["xray", "doctor"])

    assert result.exit_code == 0
    assert "Xray 安装前检查" in result.output
    assert "command:curl" in result.output
    assert "command:unzip" in result.output
    assert "writable:/usr/local/bin" in result.output
    assert "performed_side_effects: False" in result.output


def test_build_xray_install_cli_plan_uses_safe_defaults():
    plan = build_xray_install_cli_plan(system="Linux", machine="x86_64", version="latest")

    assert plan.system == "linux"
    assert plan.arch == "64"
    assert plan.version == "latest"
    assert plan.bin_path == "/usr/local/bin/xray"
    assert plan.performs_side_effects is False
