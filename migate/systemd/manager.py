"""Safe wrappers around systemctl for MiGate-owned services."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

Runner = Callable[..., subprocess.CompletedProcess[str]]

_ALLOWED_SERVICES = {"migate-xray.service", "migate-panel.service"}


@dataclass(frozen=True)
class SystemdResult:
    status: str
    returncode: int | None
    stdout: str
    stderr: str


def _run_systemctl(args: Sequence[str], *, runner: Runner = subprocess.run) -> SystemdResult:
    try:
        completed = runner(["systemctl", *args], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return SystemdResult(
            status="systemctl_not_found",
            returncode=None,
            stdout="",
            stderr="systemctl command not found",
        )

    status = "success" if completed.returncode == 0 else "failed"
    return SystemdResult(
        status=status,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def _validate_service_name(service_name: str) -> SystemdResult | None:
    if service_name in _ALLOWED_SERVICES:
        return None
    return SystemdResult(
        status="rejected",
        returncode=None,
        stdout="",
        stderr=f"unsupported service: {service_name}",
    )


def daemon_reload(*, runner: Runner = subprocess.run) -> SystemdResult:
    return _run_systemctl(["daemon-reload"], runner=runner)


def restart_service(service_name: str, *, runner: Runner = subprocess.run) -> SystemdResult:
    rejected = _validate_service_name(service_name)
    if rejected is not None:
        return rejected
    return _run_systemctl(["restart", service_name], runner=runner)


def service_status(service_name: str, *, runner: Runner = subprocess.run) -> SystemdResult:
    rejected = _validate_service_name(service_name)
    if rejected is not None:
        return rejected
    return _run_systemctl(["status", service_name, "--no-pager"], runner=runner)
