from typer.testing import CliRunner

from migate.main import app, build_panel_server_config, build_xray_install_cli_plan


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
    assert "真实安装 CLI 已就绪，但当前未接入默认执行器" in result.output
    assert "请先使用 --dry-run 检查计划" in result.output
    assert "allow_side_effects" in result.output


def test_build_xray_install_cli_plan_uses_safe_defaults():
    plan = build_xray_install_cli_plan(system="Linux", machine="x86_64", version="latest")

    assert plan.system == "linux"
    assert plan.arch == "64"
    assert plan.version == "latest"
    assert plan.bin_path == "/usr/local/bin/xray"
    assert plan.performs_side_effects is False
