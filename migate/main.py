from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import platform

import typer
import uvicorn

from migate.config import MiGateConfig
from migate.egress.lifecycle import EgressLifecycleResult, bring_down_egress, bring_up_egress
from migate.egress.openvpn_backend import build_openvpn_tunnel_start_plan, build_openvpn_tunnel_stop_plan
from migate.egress.status import render_egress_status_report, run_egress_doctor, run_egress_status
from migate.egress.tunnel_backend import TunnelStartPlan, TunnelStopPlan
from migate.egress.xray_tun_backend import build_xray_tun_start_plan, build_xray_tun_stop_plan
from migate.proxy.run import render_proxy_run_result, run_proxy_placeholder
from migate.proxy.runtime import render_proxy_runtime_report, run_proxy_doctor, run_proxy_status
from migate.proxy.service_cli import DEFAULT_PROXY_SERVICE_PATH, preview_proxy_service_unit, save_proxy_service_unit
from migate.remote.acceptance import RemoteAcceptanceResult, render_remote_acceptance_result, run_remote_acceptance
from migate.remote.doctor import render_remote_doctor_report, run_remote_doctor
from migate.remote.egress_plan import build_remote_egress_dry_run_plan, render_remote_egress_plan
from migate.remote.egress_runner import RemoteEgressCommandResult, RemoteEgressRunResult, render_remote_egress_run_result, run_remote_egress_plan
from migate.remote.install_plan import build_remote_install_dry_run_plan, render_remote_install_plan
from migate.remote.install_runner import (
    RemoteInstallCommandResult,
    RemoteInstallRunResult,
    render_remote_install_run_result,
    run_remote_install_plan,
)
from migate.remote.leak_check import RemoteLeakCheckReport, render_remote_leak_check_report, run_remote_leak_check
from migate.remote.lifecycle_plan import build_remote_lifecycle_dry_run_plan, render_remote_lifecycle_plan
from migate.remote.lifecycle_runner import render_remote_lifecycle_run_result, run_remote_lifecycle
from migate.remote.readiness import render_remote_readiness_report, run_remote_readiness
from migate.remote.rollout_plan import build_remote_rollout_dry_run_plan, render_remote_rollout_plan
from migate.remote.rollout_runner import (
    PhaseResultLike,
    RemoteRolloutRunResult,
    render_remote_rollout_run_result,
    run_remote_rollout_plan,
)
from migate.remote.rollout_smoke import RemoteRolloutSmokeResult, render_remote_rollout_smoke_result, run_remote_rollout_smoke
from migate.proxy.socks5_listener import (
    build_socks5_listener_plan,
    render_socks5_listener_plan,
    render_socks5_serve_output,
    render_socks5_serve_output_write_json,
    render_socks5_serve_output_write_result,
    run_socks5_serve_placeholder,
    write_socks5_serve_output,
)
from migate.routing.policy_cleanup import build_policy_routing_cleanup_plan
from migate.routing.policy_plan import build_policy_routing_plan
from migate.vpn.config_render import OpenVPNRenderPlan, render_openvpn_config_preview
from migate.vpn.config_save import OpenVPNConfigSaveResult, save_openvpn_config_preview
from migate.xray.apply_cli import XrayApplyResult, apply_validated_xray_restart, apply_validated_xray_tun_start
from migate.xray.config_cli import preview_xray_config, save_xray_config
from migate.xray.deploy_cli import render_xray_deploy_plan, render_xray_deploy_result, run_xray_deploy
from migate.xray.doctor import DoctorReport, run_xray_install_doctor
from migate.xray.install_executor import dry_run_xray_install_plan
from migate.xray.install_plan import XrayInstallPlan, build_xray_install_plan
from migate.xray.install_runner import XrayInstallCommandResult, XrayInstallResult, run_xray_install_plan
from migate.xray.service_cli import (
    DEFAULT_XRAY_SERVICE_PATH,
    DEFAULT_XRAY_TUN_SERVICE_PATH,
    preview_xray_service_unit,
    preview_xray_tun_service_unit,
    save_xray_service_unit,
    save_xray_tun_service_unit,
)
from migate.xray.systemctl_cli import (
    ALLOWED_XRAY_SERVICE_NAME,
    ALLOWED_XRAY_TUN_SERVICE_NAME,
    SystemctlActionResult,
    run_xray_systemctl_action,
)
from migate.xray.tun_config import render_xray_tun_config, save_xray_tun_config

app = typer.Typer(help="MiGate smart egress gateway")
xray_app = typer.Typer(help="Xray runtime and installer commands")
xray_config_app = typer.Typer(help="Xray config preview and save commands")
xray_tun_config_app = typer.Typer(help="Xray TUN config preview commands")
xray_tun_service_app = typer.Typer(help="Xray TUN systemd service preview and save commands")
xray_service_app = typer.Typer(help="Xray systemd service preview and save commands")
xray_systemctl_app = typer.Typer(help="Safe systemctl controls for MiGate Xray service")
xray_apply_app = typer.Typer(help="Validation-gated Xray apply operations")
proxy_app = typer.Typer(help="MiGate local proxy runtime status commands")
proxy_service_app = typer.Typer(help="MiGate local proxy systemd service preview and save commands")
proxy_socks5_app = typer.Typer(help="SOCKS5 local listener planning commands")
egress_app = typer.Typer(help="MiGate VPN egress lifecycle commands")
vpn_app = typer.Typer(help="MiGate VPN/OpenVPN configuration commands")
vpn_config_app = typer.Typer(help="OpenVPN runtime config preview and save commands")
remote_app = typer.Typer(help="Remote test VPS lifecycle planning commands")
remote_egress_app = typer.Typer(help="Remote test VPS egress planning commands")
app.add_typer(xray_app, name="xray")
app.add_typer(proxy_app, name="proxy")
app.add_typer(egress_app, name="egress")
app.add_typer(vpn_app, name="vpn")
app.add_typer(remote_app, name="remote")
proxy_app.add_typer(proxy_service_app, name="service")
proxy_app.add_typer(proxy_socks5_app, name="socks5")
xray_app.add_typer(xray_config_app, name="config")
xray_app.add_typer(xray_tun_config_app, name="tun-config")
xray_app.add_typer(xray_tun_service_app, name="tun-service")
xray_app.add_typer(xray_service_app, name="service")
xray_app.add_typer(xray_systemctl_app, name="systemctl")
xray_app.add_typer(xray_apply_app, name="apply")
remote_app.add_typer(remote_egress_app, name="egress")
vpn_app.add_typer(vpn_config_app, name="config")


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


def build_remote_egress_cli_plan(
    *,
    action: str,
    host: str = "166.88.232.2",
    port: int = 22,
    user: str = "root",
    backend: str | None = None,
):
    return build_remote_egress_dry_run_plan(host=host, port=port, user=user, action=action, backend=backend)


def build_remote_rollout_cli_plan(
    *,
    host: str = "166.88.232.2",
    port: int = 22,
    user: str = "root",
    staging_dir: str = "/tmp/migate-install",
    backend: str | None = None,
):
    return build_remote_rollout_dry_run_plan(host=host, port=port, user=user, staging_dir=staging_dir, backend=backend)


def build_remote_install_cli_plan(
    *,
    host: str = "166.88.232.2",
    port: int = 22,
    user: str = "root",
    staging_dir: str = "/tmp/migate-install",
):
    return build_remote_install_dry_run_plan(host=host, port=port, user=user, staging_dir=staging_dir)


def build_remote_lifecycle_cli_plan(*, host: str = "166.88.232.2", port: int = 22, user: str = "root"):
    return build_remote_lifecycle_dry_run_plan(host=host, port=port, user=user)


def run_remote_egress_cli(
    *,
    action: str,
    host: str,
    port: int,
    user: str,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    backend: str | None = None,
    command_runner: Callable[[str], RemoteEgressCommandResult] | None = None,
) -> RemoteEgressRunResult:
    plan = build_remote_egress_cli_plan(action=action, host=host, port=port, user=user, backend=backend)
    return run_remote_egress_plan(
        plan,
        dry_run=dry_run,
        yes=yes,
        allow_remote_changes=allow_remote_changes,
        runner=command_runner,
    )


def run_remote_install_cli(
    *,
    host: str,
    port: int,
    user: str,
    staging_dir: str,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    command_runner: Callable[[str], RemoteInstallCommandResult] | None = None,
) -> RemoteInstallRunResult:
    plan = build_remote_install_cli_plan(host=host, port=port, user=user, staging_dir=staging_dir)
    return run_remote_install_plan(
        plan,
        dry_run=dry_run,
        yes=yes,
        allow_remote_changes=allow_remote_changes,
        runner=command_runner,
    )


def run_remote_leak_check_cli(
    *,
    host: str,
    port: int,
    user: str,
    socks_port: int,
) -> RemoteLeakCheckReport:
    return run_remote_leak_check(host=host, port=port, user=user, socks_port=socks_port)


def run_remote_rollout_cli(
    *,
    host: str,
    port: int,
    user: str,
    staging_dir: str,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    backend: str | None = None,
    install_runner: Callable[[], PhaseResultLike] | None = None,
    readiness_runner: Callable[[], RemoteReadinessReport] | None = None,
    egress_up_runner: Callable[[], PhaseResultLike] | None = None,
    leak_check_runner: Callable[[], RemoteLeakCheckReport] | None = None,
) -> RemoteRolloutRunResult:
    plan = build_remote_rollout_cli_plan(host=host, port=port, user=user, staging_dir=staging_dir, backend=backend)
    return run_remote_rollout_plan(
        plan,
        dry_run=dry_run,
        yes=yes,
        allow_remote_changes=allow_remote_changes,
        install_runner=install_runner
        or (lambda: run_remote_install_cli(host=host, port=port, user=user, staging_dir=staging_dir, dry_run=False, yes=True, allow_remote_changes=True)),
        readiness_runner=readiness_runner or (lambda: run_remote_readiness(host=host, port=port, user=user)),
        egress_up_runner=egress_up_runner
        or (lambda: run_remote_egress_cli(action="up", host=host, port=port, user=user, dry_run=False, yes=True, allow_remote_changes=True, backend=backend)),
        leak_check_runner=leak_check_runner or (lambda: run_remote_leak_check_cli(host=host, port=port, user=user, socks_port=MiGateConfig().proxy.socks_port)),
    )


def run_remote_rollout_smoke_cli(
    *,
    host: str,
    port: int,
    user: str,
    staging_dir: str,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    rollout_runner: Callable[[], RemoteRolloutRunResult] | None = None,
) -> RemoteRolloutSmokeResult:
    plan = build_remote_rollout_cli_plan(host=host, port=port, user=user, staging_dir=staging_dir)
    return run_remote_rollout_smoke(
        plan,
        dry_run=dry_run,
        yes=yes,
        allow_remote_changes=allow_remote_changes,
        rollout_runner=rollout_runner
        or (
            lambda: run_remote_rollout_cli(
                host=host,
                port=port,
                user=user,
                staging_dir=staging_dir,
                dry_run=False,
                yes=True,
                allow_remote_changes=True,
            )
        ),
    )


def run_remote_acceptance_cli(
    *,
    host: str,
    port: int,
    user: str,
    staging_dir: str,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    doctor_runner: Callable[[], object] | None = None,
    rollout_smoke_runner: Callable[[], RemoteRolloutSmokeResult] | None = None,
) -> RemoteAcceptanceResult:
    return run_remote_acceptance(
        host=host,
        port=port,
        user=user,
        dry_run=dry_run,
        yes=yes,
        allow_remote_changes=allow_remote_changes,
        doctor_runner=doctor_runner or (lambda: run_remote_doctor(host=host, port=port, user=user)),
        rollout_smoke_runner=rollout_smoke_runner
        or (
            lambda: run_remote_rollout_smoke_cli(
                host=host,
                port=port,
                user=user,
                staging_dir=staging_dir,
                dry_run=False,
                yes=True,
                allow_remote_changes=True,
            )
        ),
    )


def run_remote_lifecycle_cli(
    *,
    host: str,
    port: int,
    user: str,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    doctor_runner: Callable[[], object] | None = None,
):
    return run_remote_lifecycle(
        host=host,
        port=port,
        user=user,
        dry_run=dry_run,
        yes=yes,
        allow_remote_changes=allow_remote_changes,
        doctor_runner=doctor_runner,
    )


def _config_with_backend_override(config: MiGateConfig, backend: str | None) -> MiGateConfig:
    if backend is None:
        return config
    return config.model_copy(update={"egress": config.egress.model_copy(update={"backend": backend})})


def _select_tunnel_start_plan(config: MiGateConfig) -> TunnelStartPlan:
    if config.egress.backend == "openvpn":
        return build_openvpn_tunnel_start_plan(config)
    if config.egress.backend == "xray-tun":
        return build_xray_tun_start_plan(config)
    raise ValueError(f"unsupported egress backend: {config.egress.backend}")


def _select_tunnel_stop_plan(config: MiGateConfig, pid_file: Path) -> TunnelStopPlan:
    if config.egress.backend == "openvpn":
        return build_openvpn_tunnel_stop_plan(pid_file)
    if config.egress.backend == "xray-tun":
        return build_xray_tun_stop_plan()
    raise ValueError(f"unsupported egress backend: {config.egress.backend}")


def _echo_unsupported_egress_backend(exc: ValueError) -> None:
    typer.echo("status: rejected")
    typer.echo(f"message: {exc}")
    typer.echo("commands_executed: []")
    typer.echo("performed_side_effects: False")


def _render_egress_result(result: EgressLifecycleResult) -> str:
    lines = [
        f"status: {result.status}",
        f"message: {result.message}",
        f"commands_executed: {result.commands_executed}",
        f"performed_side_effects: {result.performed_side_effects}",
    ]
    if result.phases:
        lines.append("phases:")
        for phase in result.phases:
            lines.append(f"- phase: {phase.name} status: {phase.status}")
    return "\n".join(lines) + "\n"


def _render_egress_up_dry_run(config: MiGateConfig) -> str:
    tunnel_plan = _select_tunnel_start_plan(config)
    routing_plan = build_policy_routing_plan(config)
    lines = [
        "status: dry_run",
        "message: egress up dry-run preview",
        "commands_executed: []",
        "performed_side_effects: False",
        f"backend: {config.egress.backend}",
        "phases:",
        f"- {config.egress.backend} start: {' '.join(tunnel_plan.command)}",
        *[f"- policy routing apply: {' '.join(command)}" for command in routing_plan.commands],
    ]
    return "\n".join(lines) + "\n"


def _render_egress_down_dry_run(config: MiGateConfig, pid_file: Path) -> str:
    cleanup_plan = build_policy_routing_cleanup_plan(config)
    stop_plan = _select_tunnel_stop_plan(config, pid_file)
    lines = [
        "status: dry_run",
        "message: egress down dry-run preview",
        "commands_executed: []",
        "performed_side_effects: False",
        "phases:",
        *[f"- policy routing cleanup: {' '.join(command)}" for command in cleanup_plan.commands],
        f"- {config.egress.backend} stop: {' '.join(stop_plan.command)}",
    ]
    return "\n".join(lines) + "\n"


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


def _echo_remote_egress(
    action: str,
    host: str,
    port: int,
    user: str,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    backend: str | None,
) -> None:
    if dry_run:
        plan = build_remote_egress_cli_plan(action=action, host=host, port=port, user=user, backend=backend)
        typer.echo(render_remote_egress_plan(plan), nl=False)
        if plan.status == "rejected":
            raise typer.Exit(code=1)
        return

    result = run_remote_egress_cli(
        action=action,
        host=host,
        port=port,
        user=user,
        dry_run=dry_run,
        yes=yes,
        allow_remote_changes=allow_remote_changes,
        backend=backend,
    )
    typer.echo(render_remote_egress_run_result(result), nl=False)
    if result.status != "success":
        raise typer.Exit(code=1)


@remote_egress_app.command("up")
def remote_egress_up(
    host: str = typer.Option("166.88.232.2", "--host", help="Dedicated test VPS host or IP; credentials must not be embedded."),
    port: int = typer.Option(22, "--port", help="SSH port for the dedicated test VPS."),
    user: str = typer.Option("root", "--user", help="SSH username; do not include passwords or tokens."),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Preview by default; --no-dry-run requires --yes and --allow-remote-changes."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge remote egress command execution."),
    allow_remote_changes: bool = typer.Option(False, "--allow-remote-changes", help="Allow the gated remote egress runner shell."),
    backend: str | None = typer.Option(None, "--backend", help="Remote egress backend override passed to migate egress up/status."),
) -> None:
    _echo_remote_egress("up", host, port, user, dry_run, yes, allow_remote_changes, backend)


@remote_egress_app.command("down")
def remote_egress_down(
    host: str = typer.Option("166.88.232.2", "--host", help="Dedicated test VPS host or IP; credentials must not be embedded."),
    port: int = typer.Option(22, "--port", help="SSH port for the dedicated test VPS."),
    user: str = typer.Option("root", "--user", help="SSH username; do not include passwords or tokens."),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Preview by default; --no-dry-run requires --yes and --allow-remote-changes."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge remote egress command execution."),
    allow_remote_changes: bool = typer.Option(False, "--allow-remote-changes", help="Allow the gated remote egress runner shell."),
    backend: str | None = typer.Option(None, "--backend", help="Remote egress backend override passed to migate egress down/status."),
) -> None:
    _echo_remote_egress("down", host, port, user, dry_run, yes, allow_remote_changes, backend)


@remote_app.command("rollout")
def remote_rollout(
    host: str = typer.Option("166.88.232.2", "--host", help="Dedicated test VPS host or IP; credentials must not be embedded."),
    port: int = typer.Option(22, "--port", help="SSH port for the dedicated test VPS."),
    user: str = typer.Option("root", "--user", help="SSH username; do not include passwords or tokens."),
    staging_dir: str = typer.Option("/tmp/migate-install", "--staging-dir", help="Remote staging directory preview; must stay under /tmp/ for this dry-run layer."),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Preview by default; --no-dry-run requires --yes and --allow-remote-changes."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge remote rollout phase execution."),
    allow_remote_changes: bool = typer.Option(False, "--allow-remote-changes", help="Allow the gated remote rollout runner shell."),
    backend: str | None = typer.Option(None, "--backend", help="Remote egress backend override passed through rollout egress phase."),
) -> None:
    if dry_run:
        plan = build_remote_rollout_cli_plan(host=host, port=port, user=user, staging_dir=staging_dir, backend=backend)
        typer.echo(render_remote_rollout_plan(plan), nl=False)
        if plan.status == "rejected":
            raise typer.Exit(code=1)
        return

    result = run_remote_rollout_cli(
        host=host,
        port=port,
        user=user,
        staging_dir=staging_dir,
        dry_run=dry_run,
        yes=yes,
        allow_remote_changes=allow_remote_changes,
        backend=backend,
    )
    typer.echo(render_remote_rollout_run_result(result), nl=False)
    if result.status != "success":
        raise typer.Exit(code=1)


@remote_app.command("rollout-smoke")
def remote_rollout_smoke(
    host: str = typer.Option("166.88.232.2", "--host", help="Dedicated test VPS host or IP; credentials must not be embedded."),
    port: int = typer.Option(22, "--port", help="SSH port for the dedicated test VPS."),
    user: str = typer.Option("root", "--user", help="SSH username; do not include passwords or tokens."),
    staging_dir: str = typer.Option("/tmp/migate-install", "--staging-dir", help="Remote staging directory preview; must stay under /tmp/ for this dry-run layer."),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Preview by default; --no-dry-run requires --yes and --allow-remote-changes."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge remote rollout smoke execution."),
    allow_remote_changes: bool = typer.Option(False, "--allow-remote-changes", help="Allow the gated remote rollout smoke shell."),
) -> None:
    result = run_remote_rollout_smoke_cli(
        host=host,
        port=port,
        user=user,
        staging_dir=staging_dir,
        dry_run=dry_run,
        yes=yes,
        allow_remote_changes=allow_remote_changes,
    )
    typer.echo(render_remote_rollout_smoke_result(result), nl=False)
    if result.status not in {"success", "dry_run"}:
        raise typer.Exit(code=1)


@remote_app.command("acceptance")
def remote_acceptance(
    host: str = typer.Option("166.88.232.2", "--host", help="Dedicated test VPS host or IP; credentials must not be embedded."),
    port: int = typer.Option(22, "--port", help="SSH port for the dedicated test VPS."),
    user: str = typer.Option("root", "--user", help="SSH username; do not include passwords or tokens."),
    staging_dir: str = typer.Option("/tmp/migate-install", "--staging-dir", help="Remote staging directory preview; must stay under /tmp/ for this dry-run layer."),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Preview by default; --no-dry-run requires --yes and --allow-remote-changes."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge remote acceptance execution."),
    allow_remote_changes: bool = typer.Option(False, "--allow-remote-changes", help="Allow the gated remote acceptance workflow."),
) -> None:
    result = run_remote_acceptance_cli(
        host=host,
        port=port,
        user=user,
        staging_dir=staging_dir,
        dry_run=dry_run,
        yes=yes,
        allow_remote_changes=allow_remote_changes,
    )
    typer.echo(render_remote_acceptance_result(result), nl=False)
    if result.status not in {"success", "dry_run"}:
        raise typer.Exit(code=1)


@remote_app.command("install")
def remote_install(
    host: str = typer.Option("166.88.232.2", "--host", help="Dedicated test VPS host or IP; credentials must not be embedded."),
    port: int = typer.Option(22, "--port", help="SSH port for the dedicated test VPS."),
    user: str = typer.Option("root", "--user", help="SSH username; do not include passwords or tokens."),
    staging_dir: str = typer.Option("/tmp/migate-install", "--staging-dir", help="Remote staging directory preview; must stay under /tmp/ for this dry-run layer."),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Preview by default; --no-dry-run requires --yes and --allow-remote-changes."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge remote install command execution."),
    allow_remote_changes: bool = typer.Option(False, "--allow-remote-changes", help="Allow the gated remote install runner shell."),
) -> None:
    if dry_run:
        plan = build_remote_install_cli_plan(host=host, port=port, user=user, staging_dir=staging_dir)
        typer.echo(render_remote_install_plan(plan), nl=False)
        if plan.status == "rejected":
            raise typer.Exit(code=1)
        return

    result = run_remote_install_cli(
        host=host,
        port=port,
        user=user,
        staging_dir=staging_dir,
        dry_run=dry_run,
        yes=yes,
        allow_remote_changes=allow_remote_changes,
    )
    typer.echo(render_remote_install_run_result(result), nl=False)
    if result.status != "success":
        raise typer.Exit(code=1)


@remote_app.command("lifecycle")
def remote_lifecycle(
    host: str = typer.Option("166.88.232.2", "--host", help="Dedicated test VPS host or IP; credentials must not be embedded."),
    port: int = typer.Option(22, "--port", help="SSH port for the dedicated test VPS."),
    user: str = typer.Option("root", "--user", help="SSH username; do not include passwords or tokens."),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Preview by default; --no-dry-run requires --yes and --allow-remote-changes."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge remote command execution."),
    allow_remote_changes: bool = typer.Option(False, "--allow-remote-changes", help="Allow the first real remote lifecycle layer to run remote doctor only."),
) -> None:
    if dry_run:
        plan = build_remote_lifecycle_cli_plan(host=host, port=port, user=user)
        typer.echo(render_remote_lifecycle_plan(plan), nl=False)
        if plan.status == "rejected":
            raise typer.Exit(code=1)
        return

    result = run_remote_lifecycle_cli(
        host=host,
        port=port,
        user=user,
        dry_run=dry_run,
        yes=yes,
        allow_remote_changes=allow_remote_changes,
        doctor_runner=lambda: run_remote_doctor(host=host, port=port, user=user),
    )
    typer.echo(render_remote_lifecycle_run_result(result), nl=False)
    if result.status != "success":
        raise typer.Exit(code=1)


@remote_app.command("doctor")
def remote_doctor(
    host: str = typer.Option("166.88.232.2", "--host", help="Dedicated test VPS host or IP; credentials must not be embedded."),
    port: int = typer.Option(22, "--port", help="SSH port for the dedicated test VPS."),
    user: str = typer.Option("root", "--user", help="SSH username; do not include passwords or tokens."),
) -> None:
    report = run_remote_doctor(host=host, port=port, user=user)
    typer.echo(render_remote_doctor_report(report), nl=False)
    if report.status != "ok":
        raise typer.Exit(code=1)


@remote_app.command("readiness")
def remote_readiness(
    host: str = typer.Option("166.88.232.2", "--host", help="Dedicated test VPS host or IP; credentials must not be embedded."),
    port: int = typer.Option(22, "--port", help="SSH port for the dedicated test VPS."),
    user: str = typer.Option("root", "--user", help="SSH username; do not include passwords or tokens."),
) -> None:
    report = run_remote_readiness(host=host, port=port, user=user)
    typer.echo(render_remote_readiness_report(report), nl=False)
    if report.status != "ok":
        raise typer.Exit(code=1)


@remote_app.command("leak-check")
def remote_leak_check(
    host: str = typer.Option("166.88.232.2", "--host", help="Dedicated test VPS host or IP; credentials must not be embedded."),
    port: int = typer.Option(22, "--port", help="SSH port for the dedicated test VPS."),
    user: str = typer.Option("root", "--user", help="SSH username; do not include passwords or tokens."),
    socks_port: int = typer.Option(34501, "--socks-port", min=1, help="Remote local SOCKS5 port used for the egress public-IP probe."),
) -> None:
    report = run_remote_leak_check(host=host, port=port, user=user, socks_port=socks_port)
    typer.echo(render_remote_leak_check_report(report), nl=False)
    if report.status != "ok":
        raise typer.Exit(code=1)


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
    allow_system_output_path: bool = typer.Option(False, "--allow-system-output-path", help="Reserved gate for future system log paths; currently still rejected with an explanatory message."),
    write_result_format: str = typer.Option("text", "--write-result-format", help="Render --output write result as text or json."),
) -> None:
    if output_format not in {"text", "json", "jsonl"}:
        typer.echo(f"unsupported format: {output_format}")
        typer.echo("supported formats: text, json, jsonl")
        raise typer.Exit(code=1)
    if write_result_format not in {"text", "json"}:
        typer.echo(f"unsupported write result format: {write_result_format}")
        typer.echo("supported write result formats: text, json")
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
                allow_system_output_path=allow_system_output_path,
            )
            if write_result_format == "json":
                typer.echo(render_socks5_serve_output_write_json(write_result), nl=False)
            else:
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


@egress_app.command("doctor")
def egress_doctor(
    backend: str | None = typer.Option(None, "--backend", help="Override configured egress backend: openvpn or xray-tun."),
) -> None:
    config = _config_with_backend_override(MiGateConfig(), backend)
    try:
        _select_tunnel_start_plan(config)
    except ValueError as exc:
        _echo_unsupported_egress_backend(exc)
        raise typer.Exit(code=1) from exc
    typer.echo(render_egress_status_report("Egress doctor", run_egress_doctor(config)))


@egress_app.command("status")
def egress_status(
    backend: str | None = typer.Option(None, "--backend", help="Override configured egress backend: openvpn or xray-tun."),
) -> None:
    config = _config_with_backend_override(MiGateConfig(), backend)
    try:
        _select_tunnel_start_plan(config)
    except ValueError as exc:
        _echo_unsupported_egress_backend(exc)
        raise typer.Exit(code=1) from exc
    typer.echo(render_egress_status_report("Egress status", run_egress_status(config)))


def _render_vpn_config_save_result(
    *,
    source: Path,
    target: Path,
    plan: OpenVPNRenderPlan | None,
    save_result: OpenVPNConfigSaveResult | None,
    status: str,
    message: str,
    performed_side_effects: bool,
) -> str:
    lines = [
        f"status: {status}",
        f"message: {message}",
        f"source: {source}",
        f"target: {target}",
        f"performed_side_effects: {performed_side_effects}",
    ]
    if save_result and save_result.backup_path:
        lines.append(f"backup_path: {save_result.backup_path}")
    if plan is not None:
        lines.extend(["config_preview:", plan.config_text.rstrip()])
    return "\n".join(lines) + "\n"


@vpn_config_app.command("save")
def vpn_config_save(
    source: Path = typer.Option(..., "--source", help="Source OpenVPN .ovpn file to render into MiGate runtime config."),
    target: Path = typer.Option(Path("/var/lib/migate/runtime/active.ovpn"), "--target", help="Target MiGate runtime OpenVPN config."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge that saving config writes to disk."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually write config when combined with --yes."),
) -> None:
    if not source.exists():
        typer.echo(
            _render_vpn_config_save_result(
                source=source,
                target=target,
                plan=None,
                save_result=None,
                status="failed",
                message=f"source OpenVPN config not found: {source}",
                performed_side_effects=False,
            ),
            nl=False,
        )
        raise typer.Exit(code=1)

    raw_config = source.read_text(encoding="utf-8")
    plan = render_openvpn_config_preview(
        raw_config,
        tun_interface=MiGateConfig().vpn.interface,
        runtime_dir=str(target.parent),
        log_path="/var/log/migate/openvpn.log",
        status_path=str(target.parent / "status.json"),
    )
    if not yes or not allow_system_changes:
        status = "dry_run" if not yes and not allow_system_changes else "rejected"
        typer.echo(
            _render_vpn_config_save_result(
                source=source,
                target=target,
                plan=plan,
                save_result=None,
                status=status,
                message="OpenVPN runtime config save preview" if status == "dry_run" else "OpenVPN config save requires --yes and --allow-system-changes",
                performed_side_effects=False,
            ),
            nl=False,
        )
        if status == "rejected":
            raise typer.Exit(code=1)
        return

    result = save_openvpn_config_preview(plan, target, yes=yes, allow_file_write=allow_system_changes)
    typer.echo(
        _render_vpn_config_save_result(
            source=source,
            target=target,
            plan=plan,
            save_result=result,
            status=result.status,
            message=result.message,
            performed_side_effects=result.performed_side_effects,
        ),
        nl=False,
    )
    if result.status != "saved":
        raise typer.Exit(code=1)


@egress_app.command("up")
def egress_up(
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Preview egress bring-up without system changes."),
    backend: str | None = typer.Option(None, "--backend", help="Override configured egress backend: openvpn or xray-tun."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge egress bring-up side effects."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually allow egress bring-up when combined with --no-dry-run and --yes."),
) -> None:
    config = _config_with_backend_override(MiGateConfig(), backend)
    if dry_run:
        try:
            typer.echo(_render_egress_up_dry_run(config), nl=False)
        except ValueError as exc:
            _echo_unsupported_egress_backend(exc)
            raise typer.Exit(code=1) from exc
        return
    if not yes or not allow_system_changes:
        typer.echo("status: rejected")
        typer.echo("message: egress up requires yes=True and allow_system_changes=True")
        typer.echo("commands_executed: []")
        typer.echo("performed_side_effects: False")
        return
    try:
        tunnel_plan = _select_tunnel_start_plan(config)
    except ValueError as exc:
        _echo_unsupported_egress_backend(exc)
        raise typer.Exit(code=1) from exc
    result = bring_up_egress(
        tunnel_plan,
        build_policy_routing_plan(config),
        allow_side_effects=True,
    )
    typer.echo(_render_egress_result(result), nl=False)
    if result.status != "up":
        raise typer.Exit(code=1)


@egress_app.command("down")
def egress_down(
    pid_file: str = typer.Option("/var/lib/migate/runtime/openvpn.pid", "--pid-file", help="OpenVPN pid file path for stop planning."),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run", help="Preview egress bring-down without system changes."),
    backend: str | None = typer.Option(None, "--backend", help="Override configured egress backend: openvpn or xray-tun."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge egress bring-down side effects."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually allow egress bring-down when combined with --no-dry-run and --yes."),
) -> None:
    config = _config_with_backend_override(MiGateConfig(), backend)
    pid_path = Path(pid_file)
    if dry_run:
        try:
            typer.echo(_render_egress_down_dry_run(config, pid_path), nl=False)
        except ValueError as exc:
            _echo_unsupported_egress_backend(exc)
            raise typer.Exit(code=1) from exc
        return
    if not yes or not allow_system_changes:
        typer.echo("status: rejected")
        typer.echo("message: egress down requires yes=True and allow_system_changes=True")
        typer.echo("commands_executed: []")
        typer.echo("performed_side_effects: False")
        return
    try:
        tunnel_stop_plan = _select_tunnel_stop_plan(config, pid_path)
    except ValueError as exc:
        _echo_unsupported_egress_backend(exc)
        raise typer.Exit(code=1) from exc
    result = bring_down_egress(
        build_policy_routing_cleanup_plan(config),
        tunnel_stop_plan,
        allow_side_effects=True,
    )
    typer.echo(_render_egress_result(result), nl=False)
    if result.status != "down":
        raise typer.Exit(code=1)


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


@xray_tun_config_app.command("preview")
def xray_tun_config_preview() -> None:
    typer.echo(render_xray_tun_config(MiGateConfig()), nl=False)
    typer.echo("performed_side_effects: False")


@xray_tun_config_app.command("save")
def xray_tun_config_save(
    target: str = typer.Option("/etc/migate/xray/config.json", "--target", help="Target xray TUN config path."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge that saving TUN config writes to disk."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually write config when combined with --yes."),
) -> None:
    result = save_xray_tun_config(
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
    typer.echo(f"systemctl_commands_executed: {result.systemctl_commands_executed or []}")
    typer.echo(f"performed_side_effects: {result.performed_side_effects}")


@xray_tun_service_app.command("preview")
def xray_tun_service_preview() -> None:
    typer.echo(preview_xray_tun_service_unit(), nl=False)
    typer.echo("systemctl_commands_executed: []")
    typer.echo("performed_side_effects: False")


@xray_tun_service_app.command("save")
def xray_tun_service_save(
    target: str = typer.Option(DEFAULT_XRAY_TUN_SERVICE_PATH, "--target", help="Target Xray TUN systemd unit path."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge that saving TUN service writes to disk."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually write TUN service unit when combined with --yes."),
) -> None:
    result = save_xray_tun_service_unit(target, yes=yes, allow_system_changes=allow_system_changes)
    typer.echo(f"status: {result.status}")
    typer.echo(f"message: {result.message}")
    typer.echo(f"target: {result.target}")
    typer.echo(f"systemctl_commands_executed: {result.systemctl_commands_executed or []}")
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


_XRAY_SYSTEMCTL_SERVICE_HELP = (
    f"Service name; allowed: {ALLOWED_XRAY_SERVICE_NAME}, {ALLOWED_XRAY_TUN_SERVICE_NAME}."
)


@xray_systemctl_app.command("status")
def xray_systemctl_status(
    service: str = typer.Option(ALLOWED_XRAY_SERVICE_NAME, "--service", help=_XRAY_SYSTEMCTL_SERVICE_HELP),
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
    service: str = typer.Option(ALLOWED_XRAY_SERVICE_NAME, "--service", help=_XRAY_SYSTEMCTL_SERVICE_HELP),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge restart side effects."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually restart when combined with --yes."),
) -> None:
    _echo_systemctl_result(
        run_xray_systemctl_action("restart", service=service, yes=yes, allow_system_changes=allow_system_changes)
    )


@xray_systemctl_app.command("start")
def xray_systemctl_start(
    service: str = typer.Option(ALLOWED_XRAY_TUN_SERVICE_NAME, "--service", help=_XRAY_SYSTEMCTL_SERVICE_HELP),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge start side effects."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually start when combined with --yes."),
) -> None:
    _echo_systemctl_result(
        run_xray_systemctl_action("start", service=service, yes=yes, allow_system_changes=allow_system_changes)
    )


@xray_systemctl_app.command("stop")
def xray_systemctl_stop(
    service: str = typer.Option(ALLOWED_XRAY_TUN_SERVICE_NAME, "--service", help=_XRAY_SYSTEMCTL_SERVICE_HELP),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge stop side effects."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually stop when combined with --yes."),
) -> None:
    _echo_systemctl_result(
        run_xray_systemctl_action("stop", service=service, yes=yes, allow_system_changes=allow_system_changes)
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


@xray_apply_app.command("tun-start")
def xray_apply_tun_start(
    config: str = typer.Option("/etc/migate/xray/config.json", "--config", help="Xray TUN config path to validate before starting service."),
    yes: bool = typer.Option(False, "--yes", help="Acknowledge validation-gated xray-tun start side effects."),
    allow_system_changes: bool = typer.Option(False, "--allow-system-changes", help="Actually run daemon-reload and start migate-xray-tun.service when combined with --yes."),
) -> None:
    _echo_apply_result(apply_validated_xray_tun_start(config, yes=yes, allow_system_changes=allow_system_changes))


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
        raise typer.Exit(code=1)
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
    if result.status != "success":
        raise typer.Exit(code=1)


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
