"""Safe wrapper around systemctl for the MiGate-managed Xray service."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import subprocess


ALLOWED_XRAY_SERVICE_NAME = "migate-xray.service"
ALLOWED_SYSTEMCTL_ACTIONS = {"status", "daemon-reload", "restart"}
SIDE_EFFECT_ACTIONS = {"daemon-reload", "restart"}


@dataclass(frozen=True)
class SystemctlActionResult:
    status: str
    action: str
    service: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    performed_side_effects: bool


def build_systemctl_command(action: str, service: str) -> list[str]:
    if action == "status":
        return ["systemctl", "status", service, "--no-pager"]
    if action == "daemon-reload":
        return ["systemctl", "daemon-reload"]
    if action == "restart":
        return ["systemctl", "restart", service]
    return []


def run_xray_systemctl_action(
    action: str,
    *,
    service: str = ALLOWED_XRAY_SERVICE_NAME,
    yes: bool = False,
    allow_system_changes: bool = False,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
) -> SystemctlActionResult:
    if service != ALLOWED_XRAY_SERVICE_NAME:
        return SystemctlActionResult(
            status="rejected",
            action=action,
            service=service,
            command=[],
            returncode=None,
            stdout="",
            stderr=f"unsupported service: {service}",
            performed_side_effects=False,
        )
    if action not in ALLOWED_SYSTEMCTL_ACTIONS:
        return SystemctlActionResult(
            status="rejected",
            action=action,
            service=service,
            command=[],
            returncode=None,
            stdout="",
            stderr=f"unsupported systemctl action: {action}",
            performed_side_effects=False,
        )
    if action in SIDE_EFFECT_ACTIONS and (not yes or not allow_system_changes):
        return SystemctlActionResult(
            status="rejected",
            action=action,
            service=service,
            command=[],
            returncode=None,
            stdout="",
            stderr=f"systemctl {action} requires yes=True and allow_system_changes=True",
            performed_side_effects=False,
        )

    command = build_systemctl_command(action, service)
    run = runner or _default_runner
    try:
        completed = run(command)
    except FileNotFoundError:
        return SystemctlActionResult(
            status="systemctl_not_found",
            action=action,
            service=service,
            command=command,
            returncode=None,
            stdout="",
            stderr="systemctl command not found",
            performed_side_effects=False,
        )

    return SystemctlActionResult(
        status="success" if completed.returncode == 0 else "failed",
        action=action,
        service=service,
        command=command,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        performed_side_effects=action in SIDE_EFFECT_ACTIONS,
    )


def _default_runner(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, capture_output=True, text=True)
