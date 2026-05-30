from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import platform

import typer
import uvicorn

from migate.config import MiGateConfig
from migate.proxy.run import render_proxy_run_result, run_proxy_placeholder
from migate.proxy.runtime import render_proxy_runtime_report, run_proxy_doctor, run_proxy_status
from migate.proxy.service_cli import DEFAULT_PROXY_SERVICE_PATH, preview_proxy_service_unit, save_proxy_service_unit
from migate.proxy.socks5_listener import (
    build_socks5_listener_plan,
    render_socks5_listener_plan,
    render_socks5_serve_output,
    render_socks5_serve_output_write_result,
    run_socks5_serve_placeholder,
    write_socks5_serve_output,
)
from migate.xray.apply_cli import XrayApplyResult, apply_validated_xray_restart
from migate.xray.config_cli import preview_xray_config, save_xray_config
from migate.xray.deploy_cli import render_xray_deploy_plan, render_xray_deploy_result, run_xray_deploy
from migate.xray.doctor import DoctorReport, run_xray_install_doctor
from migate.xray.install_executor import dry_run_xray_install_plan
from migate.xray.install_plan import XrayInstallPlan, build_xray_install_plan
from migate.xray.install_runner import XrayInstallCommandResult, XrayInstallResult, run_xray_install_plan
from migate.xray.service_cli import DEFAULT_XRAY_SERVICE_PATH, preview_xray_service_unit, save_xray_service_unit
from migate.xray.systemctl_cli import ALLOWED_XRAY_SERVICE_NAME, SystemctlActionResult, run_xray_systemctl_action

app = typer.Typer(help="MiGate smart egress gateway")
xray_app = typer.Typer(help="Xray runtime and installer commands")
xray_config_app = typer.Typer(help="Xray config preview and save commands")
xray_service_app = typer.Typer(help="Xray systemd service preview and save commands")
xray_systemctl_app = typer.Typer(help="Safe systemctl controls for MiGate Xray service")
xray_apply_app = typer.Typer(help="Validation-gated Xray apply operations")
proxy_app = typer.Typer(help="MiGate local proxy runtime status commands")
proxy_service_app = typer.Typer(help="MiGate local proxy systemd service preview and save commands")
proxy_socks5_app = typer.Typer(help="SOCKS5 local listener planning commands")
app.add_typer(xray_app, name="xray")
app.add_typer(proxy_app, name="proxy")
proxy_app.add_typer(proxy_service_app, name="service")
proxy_app.add_typer(proxy_socks5_app, name="socks5")
xray_app.add_typer(xray_config_app, name="config")
xray_app.add_typer(xray_service_app, name="service")
xray_app.add_typer(xray_systemctl_app, name="systemctl")
xray_app.add_typer(xray_apply_app, name="apply")


@app.callback()
def cli() -> None:
    """MiGate command line interface."""


@dataclass(frozen=True)
class PanelServerConfig:
    app: str
    host: str
    port: int
    factory: bool = True


def build_panel_server_config(host: str, port: int) -> PanelServerConfig:
    return PanelServerConfig(app="migate.api.app:create_app", host=host, port=port, factory=True)


def build_xray_install_cli_plan(*, system: str | None = None, machine: str | None = None, version: str = "latest") -> XrayInstallPlan:
    return build_xray_install_plan(
        MiGateConfig(),
        system=system or platform.system(),
        machine=machine or platform.machine(),
        version=version,
    )


def _echo_install_plan(plan: XrayInstallPlan) -> None:
    typer.echo(plan.to_preview())


def _echo_dry_run_report(plan: XrayInstallPlan) -> None:
    result = dry_run_xray_install_plan(plan)
    typer.echo(result.to_report())
    typer.echo(f"commands_executed: {result.commands_executed}")
    typer.echo(f"performed_side_effects: {result.performed_side_effects}")


def run_xray_install_cli(
    *,
    yes: bool,
    allow_system_changes: bool,
    dry_run: bool,
    system: str | None = None,
    machine: str | None = None,
    version: str = "latest",
    command_runner: Callable[[list[str]], XrayInstallCommandResult] | None = None,
    existing_binary_checker: Callable[[str], bool] | None = None,
    doctor_loader: Callable[[], DoctorReport] | None = None,
) -> XrayInstallResult:
    plan = build_xray_install_cli_plan(system=system, machine=machine, version=version)
    if dry_run or not yes or not allow_system_changes:
        return XrayInstallResult(
            status="rejected",
            message="real installer requires yes=True and allow_system_changes=True",
            steps=[],
            performed_side_effects=False,
        )
    doctor = (doctor_loader or run_xray_install_doctor)()
    if doctor.status != "ok":
        failed_checks = ", ".join(f"{check.name}={check.status}" for check in doctor.checks if check.status != "ok")
        return XrayInstallResult(
            status="rejected",
            message=f"doctor failed: {failed_checks}",
            steps=[],
            performed_side_effects=False,
        )
    return run_xray_install_plan(
        plan,
        runner=command_runner,
        allow_side_effects=True,
        existing_binary_checker=existing_binary_checker,
    )


def _echo_install_result(result: XrayInstallResult) -> None:
    typer.echo(f"status: {result.status}")
    typer.echo(f"message: {result.message}")
    typer.echo(f"performed_side_effects: {result.performed_side_effects}")
    if result.backup_path:
        typer.echo(f"backup_path: {result.backup_path}")
    for step in result.steps:
        typer.echo(
            f"- {step.action}: {step.status} returncode={step.returncode} command={' '.join(step.command)} stdout={step.stdout} stderr={step.stderr}"
        )
    if result.rollback_steps:
        typer.echo("rollback_steps:")
        for step in result.rollback_steps:
            typer.echo(
                f"- {step.action}: {step.status} returncode={step.returncode} command={' '.join(step.command)} stdout={step.stdout} stderr={step.stderr}"
            )


@proxy_app.command("doctor")
def proxy_doctor() -> None:
    typer.echo(render_proxy_runtime_report("Proxy doctor", run_proxy_doctor(MiGateConfig())))


@proxy_app.command("status")
def proxy_status() -> None:
    typer.echo(render_proxy_runtime_report("Proxy status", run_proxy_status(MiGateConfig())))


@proxy_app.command("run")
def proxy_run() -> None:
    result = run_proxy_placeholder(MiGateConfig())
    typer.echo(render_proxy_run_result(result))
    if result.status == "rejected":
        raise typer.Exit(code=1)


@proxy_service_app.command("preview")
def proxy_service_preview() -> None:
    typer.echo(preview_proxy_service_unit(), nl=False)
    typer.echo("systemctl_commands_executed: []")
    typer.echo("performed_side_effects: False")


@proxy_socks5_app.command("plan")
def proxy_socks5_plan() -> None:
    typer.echo(render_socks5_listener_plan(build_socks5_listener_plan(MiGateConfig())))


@proxy_socks5_app.command("serve")
def proxy_socks5_serve(
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Preview without opening a listening socket."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge that real listen opens a local socket."),
    allow_network_listen: bool = typer.Option(
        False,
        "--allow-network-listen",
        help="Actually allow opening the SOCKS5 listening socket when combined with --no-dry-run and --yes.",
    ),
    max_clients: int = typer.Option(1, "--max-clients", min=1, help="Bounded number of local clients to handle before exiting."),
    client_timeout: float = typer.Option(5.0, "--client-timeout", min=0.001, help="Seconds to wait for each client protocol read before closing."),
    output_format: str = typer.Option("text", "--format", help="Render result as text, json, or jsonl."),
    output: str | None = typer.Option(None, "--output", help="Optional file path to write rendered serve output."),
    allow_file_write: bool = typer.Option(False, "--allow-file-write", help="Actually allow writing --output when combined with --yes."),
) -> None:
    if output_format not in {"text", "json", "jsonl"}:
        typer.echo(f"unsupported format: {output_format}")
        typer.echo("supported formats: text, json, jsonl")
        raise typer.Exit(code=1)
    result = run_socks5_serve_placeholder(
        MiGateConfig(),
        dry_run=dry_run,
        yes=yes,
        allow_network_listen=allow_network_listen,
        max_clients=max_clients,
        client_timeout=client_timeout,
    )
    try:
        if output is not None:
            write_result = write_socks5_serve_output(
                result,
                output_format=output_format,
                target=output,
                yes=yes,
                allow_file_write=allow_file_write,
            )
            typer.echo(render_socks5_serve_output_write_result(write_result))
        else:
            typer.echo(render_socks5_serve_output(result, output_format=output_format), nl=False)
    except ValueError as exc:
        typer.echo(str(exc).replace("; ", "\n"))
        raise typer.Exit(code=1) from exc


@proxy_service_app.command("save")
def proxy_service_save(
    target: str = typer.Option(DEFAULT_PROXY_SERVICE_PATH, "--target", help="Target systemd unit path."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge that saving proxy service writes to disk."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually write service unit when combined with --yes."),
) -> None:
    result = save_proxy_service_unit(target, yes=yes, allow_system_changes=allow_system_changes)
    typer.echo(f"status: {result.status}")
    typer.echo(f"message: {result.message}")
    typer.echo(f"target: {result.target}")
    typer.echo(f"systemctl_commands_executed: {result.systemctl_commands_executed or []}")
    typer.echo(f"performed_side_effects: {result.performed_side_effects}")


@xray_config_app.command("preview")
def xray_config_preview() -> None:
    typer.echo(preview_xray_config(MiGateConfig()), nl=False)
    typer.echo("performed_side_effects: False")


@xray_config_app.command("save")
def xray_config_save(
    target: str = typer.Option("/etc/migate/xray/config.json", "--target", help="Target xray config path."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge that saving config writes to disk."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually write config when combined with --yes."),
) -> None:
    result = save_xray_config(
        MiGateConfig(),
        target,
        yes=yes,
        allow_system_changes=allow_system_changes,
    )
    typer.echo(f"status: {result.status}")
    typer.echo(f"message: {result.message}")
    typer.echo(f"target: {result.target}")
    typer.echo(f"validation_status: {result.validation_status}")
    if result.backup_path:
        typer.echo(f"backup_path: {result.backup_path}")
    typer.echo(f"rollback_performed: {result.rollback_performed}")
    typer.echo(f"performed_side_effects: {result.performed_side_effects}")


@xray_service_app.command("preview")
def xray_service_preview() -> None:
    typer.echo(preview_xray_service_unit(), nl=False)
    typer.echo("systemctl_commands_executed: []")
    typer.echo("performed_side_effects: False")


@xray_service_app.command("save")
def xray_service_save(
    target: str = typer.Option(DEFAULT_XRAY_SERVICE_PATH, "--target", help="Target systemd unit path."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge that saving service writes to disk."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually write service unit when combined with --yes."),
) -> None:
    result = save_xray_service_unit(target, yes=yes, allow_system_changes=allow_system_changes)
    typer.echo(f"status: {result.status}")
    typer.echo(f"message: {result.message}")
    typer.echo(f"target: {result.target}")
    typer.echo(f"systemctl_commands_executed: {result.systemctl_commands_executed or []}")
    typer.echo(f"performed_side_effects: {result.performed_side_effects}")


def _echo_systemctl_result(result: SystemctlActionResult) -> None:
    typer.echo(f"status: {result.status}")
    typer.echo(f"action: {result.action}")
    typer.echo(f"service: {result.service}")
    typer.echo(f"command: {' '.join(result.command)}")
    typer.echo(f"returncode: {result.returncode}")
    typer.echo(f"stdout: {result.stdout}")
    typer.echo(f"stderr: {result.stderr}")
    typer.echo(f"performed_side_effects: {result.performed_side_effects}")


@xray_systemctl_app.command("status")
def xray_systemctl_status(
    service: str = typer.Option(ALLOWED_XRAY_SERVICE_NAME, "--service", help="Service name; only migate-xray.service is allowed."),
) -> None:
    _echo_systemctl_result(run_xray_systemctl_action("status", service=service))


@xray_systemctl_app.command("daemon-reload")
def xray_systemctl_daemon_reload(
    yes: bool = typer.Option(False, "--yes", help="Acknowledge daemon-reload side effects."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually run daemon-reload when combined with --yes."),
) -> None:
    _echo_systemctl_result(
        run_xray_systemctl_action("daemon-reload", yes=yes, allow_system_changes=allow_system_changes)
    )


@xray_systemctl_app.command("restart")
def xray_systemctl_restart(
    service: str = typer.Option(ALLOWED_XRAY_SERVICE_NAME, "--service", help="Service name; only migate-xray.service is allowed."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge restart side effects."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually restart when combined with --yes."),
) -> None:
    _echo_systemctl_result(
        run_xray_systemctl_action("restart", service=service, yes=yes, allow_system_changes=allow_system_changes)
    )


def _echo_apply_result(result: XrayApplyResult) -> None:
    typer.echo(f"status: {result.status}")
    typer.echo(f"message: {result.message}")
    typer.echo(f"config_path: {result.config_path}")
    typer.echo(f"validation_status: {result.validation.status}")
    typer.echo(f"validation_returncode: {result.validation.returncode}")
    typer.echo(f"validation_stdout: {result.validation.stdout}")
    typer.echo(f"validation_stderr: {result.validation.stderr}")
    if not result.systemctl_results:
        typer.echo("systemctl_results: []")
    else:
        typer.echo("systemctl_results:")
        for item in result.systemctl_results:
            typer.echo(f"- action: {item.action} status: {item.status} returncode: {item.returncode}")
            typer.echo(f"  stdout: {item.stdout}")
            typer.echo(f"  stderr: {item.stderr}")
    typer.echo(f"performed_side_effects: {result.performed_side_effects}")


@xray_apply_app.command("restart")
def xray_apply_restart(
    config: str = typer.Option("/etc/migate/xray/config.json", "--config", help="Xray config path to validate before restart."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge validation-gated restart side effects."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually run daemon-reload and restart when combined with --yes."),
) -> None:
    _echo_apply_result(apply_validated_xray_restart(config, yes=yes, allow_system_changes=allow_system_changes))


@xray_app.command("deploy")
def xray_deploy(
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Preview full xray deployment without system changes."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge future real deploy side effects."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Allow future real deploy system changes when implemented."),
    version: str = typer.Option("latest", "--version", help="Xray-core release version for install planning."),
    system: str | None = typer.Option(None, "--system", help="Override detected OS for planning."),
    machine: str | None = typer.Option(None, "--machine", help="Override detected CPU architecture for planning."),
) -> None:
    result = run_xray_deploy(
        MiGateConfig(),
        system=system,
        machine=machine,
        version=version,
        dry_run=dry_run,
        yes=yes,
        allow_system_changes=allow_system_changes,
    )
    if dry_run:
        typer.echo(render_xray_deploy_plan(result))
    else:
        typer.echo(render_xray_deploy_result(result))


@xray_app.command("doctor")
def xray_doctor() -> None:
    report = run_xray_install_doctor()
    typer.echo(report.to_report())
    typer.echo("performed_side_effects: False")


@xray_app.command("install")
def xray_install(
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Preview installer steps without running commands."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge that real installation may modify the system."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually run installer commands when combined with --yes."),
    version: str = typer.Option("latest", "--version", help="Xray-core release version, e.g. v1.8.24 or latest."),
    system: str | None = typer.Option(None, "--system", help="Override detected OS for planning."),
    machine: str | None = typer.Option(None, "--machine", help="Override detected CPU architecture for planning."),
) -> None:
    plan = build_xray_install_cli_plan(system=system, machine=machine, version=version)
    _echo_install_plan(plan)
    if not yes:
        _echo_dry_run_report(plan)
        return
    if not allow_system_changes:
        typer.echo("真实安装 CLI 已就绪，但当前未启用系统修改。")
        typer.echo("如果确认要修改系统，请同时传入 --yes --allow-system-changes。")
        typer.echo("allow_side_effects=False")
        return
    doctor = run_xray_install_doctor()
    typer.echo(doctor.to_report())
    if doctor.status != "ok":
        failed_checks = ", ".join(f"{check.name}={check.status}" for check in doctor.checks if check.status != "ok")
        _echo_install_result(
            XrayInstallResult(
                status="rejected",
                message=f"doctor failed: {failed_checks}",
                steps=[],
                performed_side_effects=False,
            )
        )
        return
    result = run_xray_install_cli(
        yes=yes,
        allow_system_changes=allow_system_changes,
        dry_run=False,
        system=system,
        machine=machine,
        version=version,
        doctor_loader=lambda: doctor,
    )
    _echo_install_result(result)


@app.command()
def panel(
    host: str = typer.Option(MiGateConfig().security.web_bind, help="Panel bind host."),
    port: int = typer.Option(MiGateConfig().security.web_port, help="Panel bind port."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print server settings without starting uvicorn."),
) -> None:
    server = build_panel_server_config(host=host, port=port)
    if dry_run:
        typer.echo(f"MiGate panel: uvicorn {server.app} --factory --host {server.host} --port {server.port}")
        return
    uvicorn.run(server.app, host=server.host, port=server.port, factory=server.factory)


def run() -> None:
    app()
