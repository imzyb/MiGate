"""Preflight checks for xray-core installation.

The doctor is side-effect free: it checks command availability and whether target
paths look writable/creatable, but it does not install, download, or write files.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import shutil


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


def run_xray_install_doctor(
    *,
    command_exists: Callable[[str], bool] | None = None,
    path_writable: Callable[[str], bool] | None = None,
) -> DoctorReport:
    command_checker = command_exists or _default_command_exists
    writable_checker = path_writable or _default_path_writable
    checks: list[DoctorCheck] = []

    for command in ["curl", "unzip", "python"]:
        exists = command_checker(command)
        checks.append(
            DoctorCheck(
                name=f"command:{command}",
                status="ok" if exists else "missing",
                message=f"{command} found" if exists else f"{command} not found",
            )
        )

    for path in ["/usr/local/bin", "/etc/migate/xray"]:
        writable = writable_checker(path)
        checks.append(
            DoctorCheck(
                name=f"writable:{path}",
                status="ok" if writable else "failed",
                message=f"{path} is writable or creatable" if writable else f"{path} is not writable",
            )
        )

    status = "ok" if all(check.status == "ok" for check in checks) else "failed"
    return DoctorReport(status=status, checks=checks)
