from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import platform

import typer
import uvicorn

from migate.config import MiGateConfig
from migate.xray.config_cli import preview_xray_config, save_xray_config
from migate.xray.doctor import DoctorReport, run_xray_install_doctor
from migate.xray.install_executor import dry_run_xray_install_plan
from migate.xray.install_plan import XrayInstallPlan, build_xray_install_plan
from migate.xray.install_runner import XrayInstallCommandResult, XrayInstallResult, run_xray_install_plan
from migate.xray.service_cli import DEFAULT_XRAY_SERVICE_PATH, preview_xray_service_unit, save_xray_service_unit

app = typer.Typer(help="MiGate smart egress gateway")
xray_app = typer.Typer(help="Xray runtime and installer commands")
xray_config_app = typer.Typer(help="Xray config preview and save commands")
xray_service_app = typer.Typer(help="Xray systemd service preview and save commands")
app.add_typer(xray_app, name="xray")
xray_app.add_typer(xray_config_app, name="config")
xray_app.add_typer(xray_service_app, name="service")


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
