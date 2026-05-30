from typer.testing import CliRunner

from migate.main import app, build_panel_server_config, build_xray_install_cli_plan, run_xray_install_cli
from migate.xray.install_runner import XrayInstallCommandResult


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
