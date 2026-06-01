"""Read-only egress status and doctor checks for MiGate."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import socket
import subprocess

from migate.config import MiGateConfig
from migate.proxy.runtime import CommandResult, TunnelProcessStatus, detect_tunnel_process
from migate.routing.leak_guard import EgressGuardState, evaluate_egress_guard
from migate.routing.policy_plan import build_policy_routing_plan


@dataclass(frozen=True)
class EgressStatusCheck:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class EgressStatusReport:
    status: str
    checks: list[EgressStatusCheck]
    performed_side_effects: bool = False


def _default_interface_exists(name: str) -> bool:
    return Path("/sys/class/net", name).exists()


def _default_command_runner(argv: list[str]) -> CommandResult:
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def _default_upstream_proxy_connectable(host: str, port: int) -> bool | None:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False


def _build_egress_status_checks(
    config: MiGateConfig,
    *,
    interface_exists: Callable[[str], bool],
    command_runner: Callable[[list[str]], CommandResult],
    tunnel_process_detector: Callable[[str, str], TunnelProcessStatus] | None = None,
    upstream_proxy_connectable: Callable[[str, int], bool | None] | None = None,
    native_public_ip: str | None = None,
    egress_public_ip: str | None = None,
) -> list[EgressStatusCheck]:
    tun_ok = interface_exists(config.vpn.interface)
    checks = [
        EgressStatusCheck(
            "tun_interface",
            "ok" if tun_ok else "failed",
            f"{config.vpn.interface} interface exists" if tun_ok else f"{config.vpn.interface} interface is missing",
        )
    ]

    detector = tunnel_process_detector or (lambda backend, tun_interface: detect_tunnel_process(backend, tun_interface, runner=command_runner))
    tunnel_process = detector(config.egress.backend, config.vpn.interface)
    tunnel_ok = tunnel_process.status == "running"
    tunnel_running: bool | None = tunnel_ok if tunnel_process.status in {"running", "stopped"} else None
    checks.append(
        EgressStatusCheck(
            "tunnel_process",
            "ok" if tunnel_ok else "failed",
            tunnel_process.message,
        )
    )

    policy_plan = build_policy_routing_plan(config)
    checks.append(
        EgressStatusCheck(
            "policy_routing_plan",
            "ok",
            f"policy routing plan targets table {policy_plan.route_table} fwmark {policy_plan.fwmark} via {policy_plan.tun_interface}",
        )
    )

    upstream_ok: bool | None = None
    upstream_endpoint: str | None = None
    if config.egress.backend == "xray-tun":
        connectable = upstream_proxy_connectable or _default_upstream_proxy_connectable
        upstream_ok = connectable(config.proxy.socks_host, config.proxy.socks_port)
        upstream_endpoint = f"{config.proxy.socks_host}:{config.proxy.socks_port}"
        checks.append(
            EgressStatusCheck(
                "upstream_proxy",
                "ok" if upstream_ok else "failed",
                (
                    f"xray-tun upstream SOCKS proxy {config.proxy.socks_host}:{config.proxy.socks_port} is listening"
                    if upstream_ok is True
                    else f"xray-tun upstream SOCKS proxy {config.proxy.socks_host}:{config.proxy.socks_port} state is unknown; egress blocked"
                    if upstream_ok is None
                    else f"xray-tun upstream SOCKS proxy {config.proxy.socks_host}:{config.proxy.socks_port} is not listening; egress blocked"
                ),
            )
        )

    egress_decision = evaluate_egress_guard(
        EgressGuardState(
            leak_guard_enabled=config.security.leak_guard,
            fail_policy=config.security.fail_policy,
            tun_interface=config.vpn.interface,
            tun_interface_exists=tun_ok,
            tunnel_running=tunnel_running,
            upstream_proxy_required=config.egress.backend == "xray-tun",
            upstream_proxy_ready=upstream_ok,
            upstream_proxy_endpoint=upstream_endpoint,
            native_public_ip=native_public_ip,
            egress_public_ip=egress_public_ip,
        )
    )
    checks.append(
        EgressStatusCheck(
            "egress_guard",
            "ok" if egress_decision.allowed else "failed",
            egress_decision.message,
        )
    )
    return checks


def run_egress_doctor(
    config: MiGateConfig | None = None,
    *,
    interface_exists: Callable[[str], bool] | None = None,
    command_runner: Callable[[list[str]], CommandResult] | None = None,
    tunnel_process_detector: Callable[[str, str], TunnelProcessStatus] | None = None,
    upstream_proxy_connectable: Callable[[str, int], bool | None] | None = None,
    native_public_ip: str | None = None,
    egress_public_ip: str | None = None,
) -> EgressStatusReport:
    cfg = config or MiGateConfig()
    checks = _build_egress_status_checks(
        cfg,
        interface_exists=interface_exists or _default_interface_exists,
        command_runner=command_runner or _default_command_runner,
        tunnel_process_detector=tunnel_process_detector,
        upstream_proxy_connectable=upstream_proxy_connectable or _default_upstream_proxy_connectable,
        native_public_ip=native_public_ip,
        egress_public_ip=egress_public_ip,
    )
    return EgressStatusReport(
        status="ok" if all(check.status == "ok" for check in checks) else "failed",
        checks=checks,
        performed_side_effects=False,
    )


def run_egress_status(
    config: MiGateConfig | None = None,
    *,
    interface_exists: Callable[[str], bool] | None = None,
    command_runner: Callable[[list[str]], CommandResult] | None = None,
    tunnel_process_detector: Callable[[str, str], TunnelProcessStatus] | None = None,
    upstream_proxy_connectable: Callable[[str, int], bool | None] | None = None,
    native_public_ip: str | None = None,
    egress_public_ip: str | None = None,
) -> EgressStatusReport:
    cfg = config or MiGateConfig()
    checks = _build_egress_status_checks(
        cfg,
        interface_exists=interface_exists or _default_interface_exists,
        command_runner=command_runner or _default_command_runner,
        tunnel_process_detector=tunnel_process_detector,
        upstream_proxy_connectable=upstream_proxy_connectable or _default_upstream_proxy_connectable,
        native_public_ip=native_public_ip,
        egress_public_ip=egress_public_ip,
    )
    return EgressStatusReport(status="observed", checks=checks, performed_side_effects=False)


def render_egress_status_report(title: str, report: EgressStatusReport) -> str:
    lines = [title, f"status: {report.status}"]
    lines.extend(f"{check.name}: {check.status} - {check.message}" for check in report.checks)
    lines.append(f"performed_side_effects: {report.performed_side_effects}")
    return "\n".join(lines)
