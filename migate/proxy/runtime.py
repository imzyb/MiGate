"""Proxy runtime status and preflight checks."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import socket
import subprocess
from typing import Protocol

from migate.config import MiGateConfig
from migate.routing.leak_guard import EgressGuardState, evaluate_egress_guard
from migate.xray.systemctl_cli import ALLOWED_XRAY_TUN_SERVICE_NAME


@dataclass(frozen=True)
class ProxyRuntimeCheck:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class ProxyRuntimeReport:
    status: str
    checks: list[ProxyRuntimeCheck]
    performed_side_effects: bool = False


class CommandResult(Protocol):
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class OpenVPNProcessStatus:
    status: str
    message: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    performed_side_effects: bool = False


@dataclass(frozen=True)
class TunnelProcessStatus:
    backend: str
    status: str
    message: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    performed_side_effects: bool = False


def _default_port_listening(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) == 0


def _default_interface_exists(name: str) -> bool:
    return Path("/sys/class/net", name).exists()


def _subprocess_runner(argv: list[str]) -> CommandResult:
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def detect_openvpn_process(
    tun_interface: str,
    *,
    runner: Callable[[list[str]], CommandResult] = _subprocess_runner,
) -> OpenVPNProcessStatus:
    command = ["pgrep", "-f", f"openvpn.*{tun_interface}"]
    try:
        result = runner(command)
    except FileNotFoundError as exc:
        return OpenVPNProcessStatus(
            status="error",
            message=f"OpenVPN process probe failed for {tun_interface}",
            command=command,
            returncode=None,
            stdout="",
            stderr=str(exc),
            performed_side_effects=False,
        )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    if result.returncode == 0:
        return OpenVPNProcessStatus(
            status="running",
            message=f"OpenVPN process for {tun_interface} is running",
            command=command,
            returncode=result.returncode,
            stdout=stdout,
            stderr=stderr,
            performed_side_effects=False,
        )
    if result.returncode == 1:
        return OpenVPNProcessStatus(
            status="stopped",
            message=f"OpenVPN process for {tun_interface} is not running",
            command=command,
            returncode=result.returncode,
            stdout=stdout,
            stderr=stderr,
            performed_side_effects=False,
        )
    return OpenVPNProcessStatus(
        status="error",
        message=f"OpenVPN process probe failed for {tun_interface}",
        command=command,
        returncode=result.returncode,
        stdout=stdout,
        stderr=stderr,
        performed_side_effects=False,
    )


def detect_tunnel_process(
    backend: str,
    tun_interface: str,
    *,
    runner: Callable[[list[str]], CommandResult] = _subprocess_runner,
) -> TunnelProcessStatus:
    if backend == "xray-tun":
        command = ["systemctl", "status", ALLOWED_XRAY_TUN_SERVICE_NAME, "--no-pager"]
    else:
        command = ["pgrep", "-f", f"{backend}.*{tun_interface}"]
    try:
        result = runner(command)
    except FileNotFoundError as exc:
        return TunnelProcessStatus(
            backend=backend,
            status="error",
            message=f"{backend} tunnel probe failed for {tun_interface}",
            command=command,
            returncode=None,
            stdout="",
            stderr=str(exc),
            performed_side_effects=False,
        )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    if result.returncode == 0:
        return TunnelProcessStatus(
            backend=backend,
            status="running",
            message=f"{backend} tunnel for {tun_interface} is running",
            command=command,
            returncode=result.returncode,
            stdout=stdout,
            stderr=stderr,
            performed_side_effects=False,
        )
    if result.returncode == 1:
        return TunnelProcessStatus(
            backend=backend,
            status="stopped",
            message=f"{backend} tunnel for {tun_interface} is not running",
            command=command,
            returncode=result.returncode,
            stdout=stdout,
            stderr=stderr,
            performed_side_effects=False,
        )
    return TunnelProcessStatus(
        backend=backend,
        status="error",
        message=f"{backend} tunnel probe failed for {tun_interface}",
        command=command,
        returncode=result.returncode,
        stdout=stdout,
        stderr=stderr,
        performed_side_effects=False,
    )


def _openvpn_status_from_bool(tun_interface: str, is_running: bool) -> OpenVPNProcessStatus:
    return OpenVPNProcessStatus(
        status="running" if is_running else "stopped",
        message=f"OpenVPN process for {tun_interface} is running"
        if is_running
        else f"OpenVPN process for {tun_interface} is not running",
        command=[],
        returncode=0 if is_running else 1,
        stdout="",
        stderr="",
        performed_side_effects=False,
    )


def _tunnel_status_from_bool(backend: str, tun_interface: str, is_running: bool) -> TunnelProcessStatus:
    return TunnelProcessStatus(
        backend=backend,
        status="running" if is_running else "stopped",
        message=f"{backend} tunnel for {tun_interface} is running"
        if is_running
        else f"{backend} tunnel for {tun_interface} is not running",
        command=[],
        returncode=0 if is_running else 1,
        stdout="",
        stderr="",
        performed_side_effects=False,
    )


def _build_proxy_runtime_checks(
    config: MiGateConfig,
    *,
    port_listening: Callable[[str, int], bool],
    interface_exists: Callable[[str], bool],
    tunnel_status: Callable[[str, str], TunnelProcessStatus],
    native_public_ip: str | None = None,
    egress_public_ip: str | None = None,
) -> list[ProxyRuntimeCheck]:
    checks: list[ProxyRuntimeCheck] = []

    socks_endpoint = f"{config.proxy.socks_host}:{config.proxy.socks_port}"
    socks_ok = port_listening(config.proxy.socks_host, config.proxy.socks_port)
    checks.append(
        ProxyRuntimeCheck(
            "socks_listen",
            "ok" if socks_ok else "failed",
            f"{socks_endpoint} is listening" if socks_ok else f"{socks_endpoint} is not listening",
        )
    )

    http_endpoint = f"{config.proxy.http_host}:{config.proxy.http_port}"
    http_ok = port_listening(config.proxy.http_host, config.proxy.http_port)
    checks.append(
        ProxyRuntimeCheck(
            "http_listen",
            "ok" if http_ok else "failed",
            f"{http_endpoint} is listening" if http_ok else f"{http_endpoint} is not listening",
        )
    )

    tun_ok = interface_exists(config.vpn.interface)
    checks.append(
        ProxyRuntimeCheck(
            "tun_interface",
            "ok" if tun_ok else "failed",
            f"{config.vpn.interface} interface exists" if tun_ok else f"{config.vpn.interface} interface is missing",
        )
    )

    fail_policy_ok = config.security.fail_policy == "block"
    checks.append(
        ProxyRuntimeCheck(
            "fail_policy",
            "ok" if fail_policy_ok else "failed",
            "fail_policy is block" if fail_policy_ok else f"fail_policy is {config.security.fail_policy}; expected block",
        )
    )

    leak_guard_ok = bool(config.security.leak_guard)
    checks.append(
        ProxyRuntimeCheck(
            "leak_guard",
            "ok" if leak_guard_ok else "failed",
            "leak_guard is enabled" if leak_guard_ok else "leak_guard is disabled",
        )
    )

    tunnel_process = tunnel_status(config.egress.backend, config.vpn.interface)
    tunnel_ok = tunnel_process.status == "running"
    tunnel_running: bool | None = tunnel_ok if tunnel_process.status in {"running", "stopped"} else None
    checks.append(
        ProxyRuntimeCheck(
            "tunnel_process",
            "ok" if tunnel_ok else "failed",
            tunnel_process.message,
        )
    )

    egress_decision = evaluate_egress_guard(
        EgressGuardState(
            leak_guard_enabled=config.security.leak_guard,
            fail_policy=config.security.fail_policy,
            tun_interface=config.vpn.interface,
            tun_interface_exists=tun_ok,
            tunnel_running=tunnel_running,
            native_public_ip=native_public_ip,
            egress_public_ip=egress_public_ip,
        )
    )
    checks.append(
        ProxyRuntimeCheck(
            "egress_guard",
            "ok" if egress_decision.allowed else "failed",
            egress_decision.message,
        )
    )

    return checks


def run_proxy_doctor(
    config: MiGateConfig | None = None,
    *,
    port_listening: Callable[[str, int], bool] | None = None,
    interface_exists: Callable[[str], bool] | None = None,
    openvpn_running: Callable[[], bool] | None = None,
    tunnel_running: Callable[[], bool] | None = None,
    tunnel_process_detector: Callable[[str, str], TunnelProcessStatus] | None = None,
    native_public_ip: str | None = None,
    egress_public_ip: str | None = None,
) -> ProxyRuntimeReport:
    cfg = config or MiGateConfig()
    running_probe = tunnel_running or openvpn_running
    tunnel_status = (
        (lambda backend, tun_interface: _tunnel_status_from_bool(backend, tun_interface, running_probe()))
        if running_probe is not None
        else tunnel_process_detector or detect_tunnel_process
    )
    checks = _build_proxy_runtime_checks(
        cfg,
        port_listening=port_listening or _default_port_listening,
        interface_exists=interface_exists or _default_interface_exists,
        tunnel_status=tunnel_status,
        native_public_ip=native_public_ip,
        egress_public_ip=egress_public_ip,
    )
    return ProxyRuntimeReport(
        status="ok" if all(check.status == "ok" for check in checks) else "failed",
        checks=checks,
        performed_side_effects=False,
    )


def run_proxy_status(
    config: MiGateConfig | None = None,
    *,
    port_listening: Callable[[str, int], bool] | None = None,
    interface_exists: Callable[[str], bool] | None = None,
    openvpn_running: Callable[[], bool] | None = None,
    tunnel_running: Callable[[], bool] | None = None,
    tunnel_process_detector: Callable[[str, str], TunnelProcessStatus] | None = None,
    native_public_ip: str | None = None,
    egress_public_ip: str | None = None,
) -> ProxyRuntimeReport:
    cfg = config or MiGateConfig()
    running_probe = tunnel_running or openvpn_running
    tunnel_status = (
        (lambda backend, tun_interface: _tunnel_status_from_bool(backend, tun_interface, running_probe()))
        if running_probe is not None
        else tunnel_process_detector or detect_tunnel_process
    )
    checks = _build_proxy_runtime_checks(
        cfg,
        port_listening=port_listening or _default_port_listening,
        interface_exists=interface_exists or _default_interface_exists,
        tunnel_status=tunnel_status,
        native_public_ip=native_public_ip,
        egress_public_ip=egress_public_ip,
    )
    return ProxyRuntimeReport(status="observed", checks=checks, performed_side_effects=False)


def render_proxy_runtime_report(title: str, report: ProxyRuntimeReport) -> str:
    lines = [title, f"status: {report.status}"]
    lines.extend(f"{check.name}: {check.status} - {check.message}" for check in report.checks)
    lines.append(f"performed_side_effects: {report.performed_side_effects}")
    return "\n".join(lines)
