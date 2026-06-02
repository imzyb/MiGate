"""Preflight checks for xray-core installation.

The doctor is side-effect free: it checks command availability and whether target
paths look writable/creatable, but it does not install, download, or write files.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import os
import shutil
import socket

from migate.config import MiGateConfig


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class DoctorReport:
    status: str
    checks: list[DoctorCheck]

    def to_report(self) -> str:
        lines = ["Xray 安装前检查", f"status: {self.status}"]
        lines.extend(f"- {check.name}: {check.status} - {check.message}" for check in self.checks)
        return "\n".join(lines)


def _default_command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def _default_path_writable(path: str) -> bool:
    target = Path(path)
    if target.exists():
        return target.is_dir() and _can_write_directory(target)
    parent = target.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    return parent.exists() and _can_write_directory(parent)


def _can_write_directory(path: Path) -> bool:
    return path.is_dir() and bool(path.stat().st_mode & 0o200)


def _default_systemd_available() -> bool:
    return Path("/run/systemd/system").exists()


def _default_is_root() -> bool:
    return os.geteuid() == 0


def _default_port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) != 0


def run_xray_install_doctor(
    config: MiGateConfig | None = None,
    *,
    command_exists: Callable[[str], bool] | None = None,
    path_writable: Callable[[str], bool] | None = None,
    systemd_available: Callable[[], bool] | None = None,
    is_root: Callable[[], bool] | None = None,
    port_available: Callable[[str, int], bool] | None = None,
) -> DoctorReport:
    cfg = config or MiGateConfig()
    command_checker = command_exists or _default_command_exists
    writable_checker = path_writable or _default_path_writable
    systemd_checker = systemd_available or _default_systemd_available
    root_checker = is_root or _default_is_root
    port_checker = port_available or _default_port_available
    checks: list[DoctorCheck] = []

    for command in ["curl", "unzip", "python3", "systemctl"]:
        exists = command_checker(command)
        checks.append(
            DoctorCheck(
                name=f"command:{command}",
                status="ok" if exists else "missing",
                message=f"{command} found" if exists else f"{command} not found",
            )
        )

    systemd_ok = systemd_checker()
    checks.append(
        DoctorCheck(
            name="systemd",
            status="ok" if systemd_ok else "failed",
            message="systemd is available" if systemd_ok else "systemd is not available",
        )
    )

    root_ok = root_checker()
    checks.append(
        DoctorCheck(
            name="root",
            status="ok" if root_ok else "failed",
            message="current user is root" if root_ok else "current user is not root",
        )
    )

    for path in ["/usr/local/bin", "/etc/migate/xray", "/etc/systemd/system"]:
        writable = writable_checker(path)
        checks.append(
            DoctorCheck(
                name=f"writable:{path}",
                status="ok" if writable else "failed",
                message=f"{path} is writable or creatable" if writable else f"{path} is not writable",
            )
        )

    install_port_endpoints = [(cfg.xray.api_host, cfg.xray.api_port)]
    proxy_port_endpoints = [
        (cfg.proxy.socks_host, cfg.proxy.socks_port),
        (cfg.proxy.http_host, cfg.proxy.http_port),
    ]
    for host, port in install_port_endpoints:
        available = port_checker(host, port)
        endpoint = f"{host}:{port}"
        checks.append(
            DoctorCheck(
                name=f"port:{endpoint}",
                status="ok" if available else "busy",
                message=f"{endpoint} is available" if available else f"{endpoint} is already in use",
            )
        )

    for host, port in proxy_port_endpoints:
        available = port_checker(host, port)
        endpoint = f"{host}:{port}"
        checks.append(
            DoctorCheck(
                name=f"port:{endpoint}",
                status="ok",
                message=(
                    f"{endpoint} is available"
                    if available
                    else f"{endpoint} is already in use by an existing proxy listener; safe for idempotent install"
                ),
            )
        )

    status = "ok" if all(check.status == "ok" for check in checks) else "failed"
    return DoctorReport(status=status, checks=checks)
