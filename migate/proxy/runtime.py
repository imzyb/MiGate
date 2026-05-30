"""Proxy runtime status and preflight checks."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import socket
from pathlib import Path

from migate.config import MiGateConfig


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


def _default_port_listening(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) == 0


def _default_interface_exists(name: str) -> bool:
    return Path("/sys/class/net", name).exists()


def _build_proxy_runtime_checks(
    config: MiGateConfig,
    *,
    port_listening: Callable[[str, int], bool],
    interface_exists: Callable[[str], bool],
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

    return checks


def run_proxy_doctor(
    config: MiGateConfig | None = None,
    *,
    port_listening: Callable[[str, int], bool] | None = None,
    interface_exists: Callable[[str], bool] | None = None,
) -> ProxyRuntimeReport:
    cfg = config or MiGateConfig()
    checks = _build_proxy_runtime_checks(
        cfg,
        port_listening=port_listening or _default_port_listening,
        interface_exists=interface_exists or _default_interface_exists,
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
) -> ProxyRuntimeReport:
    cfg = config or MiGateConfig()
    checks = _build_proxy_runtime_checks(
        cfg,
        port_listening=port_listening or _default_port_listening,
        interface_exists=interface_exists or _default_interface_exists,
    )
    return ProxyRuntimeReport(status="observed", checks=checks, performed_side_effects=False)


def render_proxy_runtime_report(title: str, report: ProxyRuntimeReport) -> str:
    lines = [title, f"status: {report.status}"]
    lines.extend(f"{check.name}: {check.status} - {check.message}" for check in report.checks)
    lines.append(f"performed_side_effects: {report.performed_side_effects}")
    return "\n".join(lines)
