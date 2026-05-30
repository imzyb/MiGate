"""Gated stop runner for MiGate-managed OpenVPN processes."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Protocol


class CommandResult(Protocol):
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class OpenVPNStopPlan:
    pid_file: Path
    kill_signal: str
    performs_side_effects: bool = False


@dataclass(frozen=True)
class OpenVPNStopStepResult:
    action: str
    status: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class OpenVPNStopResult:
    status: str
    message: str
    steps: list[OpenVPNStopStepResult]
    commands_executed: list[str]
    performed_side_effects: bool


@dataclass(frozen=True)
class OpenVPNStopCommandResult:
    returncode: int | None
    stdout: str
    stderr: str


def read_openvpn_pid(pid_file: Path) -> int | None:
    if not pid_file.exists():
        return None
    content = pid_file.read_text(encoding="utf-8").strip()
    if not content:
        return None
    try:
        return int(content)
    except ValueError:
        return None


def build_openvpn_stop_plan(*, pid_file: Path, kill_signal: str = "TERM") -> OpenVPNStopPlan:
    return OpenVPNStopPlan(pid_file=pid_file, kill_signal=kill_signal, performs_side_effects=False)


def _default_runner(command: list[str]) -> OpenVPNStopCommandResult:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    return OpenVPNStopCommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def run_openvpn_stop_plan(
    plan: OpenVPNStopPlan,
    *,
    runner: Callable[[list[str]], CommandResult] | None = None,
    allow_side_effects: bool = False,
) -> OpenVPNStopResult:
    if not allow_side_effects:
        return OpenVPNStopResult(
            status="rejected",
            message="allow_side_effects must be true to stop OpenVPN",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    pid = read_openvpn_pid(plan.pid_file)
    if pid is None:
        return OpenVPNStopResult(
            status="failed",
            message="OpenVPN stop failed; pid file not found",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    command = ["kill", f"-{plan.kill_signal}", str(pid)]
    run_command = runner or _default_runner
    command_result = run_command(command)
    step_status = "success" if command_result.returncode == 0 else "failed"
    return OpenVPNStopResult(
        status="stopped" if step_status == "success" else "failed",
        message="OpenVPN stop command executed" if step_status == "success" else "OpenVPN stop command failed",
        steps=[
            OpenVPNStopStepResult(
                action="stop_openvpn_process",
                status=step_status,
                command=command,
                returncode=command_result.returncode,
                stdout=command_result.stdout,
                stderr=command_result.stderr,
            )
        ],
        commands_executed=[" ".join(command)],
        performed_side_effects=True,
    )
