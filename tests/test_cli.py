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
