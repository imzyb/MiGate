"""Start the MiGate systemd services after setup has written their unit files."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass



DEFAULT_SETUP_SERVICE_START_TIMEOUT_SECONDS = 15
MIGATE_XRAY_SERVICE_NAME = "migate-xray.service"
MIGATE_PROXY_SERVICE_NAME = "migate-proxy.service"


@dataclass(frozen=True)
class SetupServiceStartCommandResult:
    name: str
    status: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    performed_side_effects: bool


@dataclass(frozen=True)
class SetupServiceStartResult:
    status: str
    message: str
    steps: list[SetupServiceStartCommandResult]
    commands_executed: list[list[str]]
    performed_side_effects: bool


def run_setup_service_start(
    *,
    yes: bool,
    allow_system_changes: bool,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
) -> SetupServiceStartResult:
    if not yes or not allow_system_changes:
        return SetupServiceStartResult(
            status="rejected",
            message="service start requires yes=True and allow_system_changes=True",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    commands = [
        ("daemon_reload", ["systemctl", "daemon-reload"], True),
        ("enable_xray_service", ["systemctl", "enable", "--now", MIGATE_XRAY_SERVICE_NAME], True),
        ("check_xray_active", ["systemctl", "is-active", MIGATE_XRAY_SERVICE_NAME], False),
        ("stability_wait", [], False),
        ("verify_xray_stable", ["systemctl", "is-active", MIGATE_XRAY_SERVICE_NAME], False),
    ]
    run = runner or _default_runner
    steps: list[SetupServiceStartCommandResult] = []
    commands_executed: list[list[str]] = []
    performed_side_effects = False

    for name, command, is_side_effect in commands:
        if name == "stability_wait":
            time.sleep(1.0)
            continue

        commands_executed.append(command)
        try:
            completed = run(command)
        except FileNotFoundError:
            step = SetupServiceStartCommandResult(
                name=name,
                status="systemctl_not_found",
                command=command,
                returncode=None,
                stdout="",
                stderr="systemctl command not found",
                performed_side_effects=False,
            )
        except subprocess.TimeoutExpired as exc:
            step = SetupServiceStartCommandResult(
                name=name,
                status="timeout",
                command=command,
                returncode=None,
                stdout=_timeout_stream_to_text(exc.output),
                stderr=_format_timeout_stderr(exc),
                performed_side_effects=is_side_effect,
            )
        else:
            step = SetupServiceStartCommandResult(
                name=name,
                status="success" if completed.returncode == 0 else "failed",
                command=command,
                returncode=completed.returncode,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
                performed_side_effects=is_side_effect,
            )

        steps.append(step)
        performed_side_effects = performed_side_effects or step.performed_side_effects
        if step.status != "success":
            return SetupServiceStartResult(
                status=step.status,
                message=f"service start failed at {name}",
                steps=steps,
                commands_executed=commands_executed,
                performed_side_effects=performed_side_effects,
            )

    return SetupServiceStartResult(
        status="success",
        message="MiGate Xray service enabled and started; proxy service left installed but stopped until VPN/TUN prerequisites are ready",
        steps=steps,
        commands_executed=commands_executed,
        performed_side_effects=performed_side_effects,
    )


def _timeout_stream_to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _format_timeout_stderr(exc: subprocess.TimeoutExpired) -> str:
    stderr = _timeout_stream_to_text(exc.stderr)
    timeout_message = f"systemctl command timed out after {exc.timeout:g}s"
    return timeout_message if not stderr else f"{timeout_message}\n{stderr}"


def _default_runner(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, capture_output=True, text=True, timeout=DEFAULT_SETUP_SERVICE_START_TIMEOUT_SECONDS)
