"""Backend-agnostic tunnel start/stop runner contracts for MiGate egress."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import subprocess
from typing import Protocol


class CommandResult(Protocol):
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class TunnelStartPlan:
    backend: str
    command: list[str]
    runtime_paths: list[str]
    required_paths: list[str] | None = None
    performs_side_effects: bool = False


@dataclass(frozen=True)
class TunnelStopPlan:
    backend: str
    command: list[str]
    performs_side_effects: bool = False


@dataclass(frozen=True)
class TunnelCommandResult:
    backend: str
    status: str
    message: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    commands_executed: list[str]
    performed_side_effects: bool


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _format_command(command: list[str]) -> str:
    return " ".join(command)


def run_tunnel_start_plan(
    plan: TunnelStartPlan,
    *,
    runner: Callable[[list[str]], CommandResult] | None = None,
    allow_side_effects: bool = False,
) -> TunnelCommandResult:
    if not allow_side_effects:
        return TunnelCommandResult(
            backend=plan.backend,
            status="rejected",
            message="allow_side_effects must be true to start tunnel backend",
            command=plan.command,
            returncode=None,
            stdout="",
            stderr="",
            commands_executed=[],
            performed_side_effects=False,
        )

    run_command = runner or _default_runner
    command_preview = _format_command(plan.command)
    try:
        command_result = run_command(plan.command)
    except FileNotFoundError:
        return TunnelCommandResult(
            backend=plan.backend,
            status="command_not_found",
            message=f"tunnel backend start command not found: {plan.command[0]}",
            command=plan.command,
            returncode=None,
            stdout="",
            stderr=f"command not found: {plan.command[0]}",
            commands_executed=[],
            performed_side_effects=True,
        )

    status = "started" if command_result.returncode == 0 else "failed"
    return TunnelCommandResult(
        backend=plan.backend,
        status=status,
        message="tunnel backend start command executed" if status == "started" else f"tunnel backend start command failed: {command_preview}",
        command=plan.command,
        returncode=command_result.returncode,
        stdout=command_result.stdout.strip(),
        stderr=command_result.stderr.strip(),
        commands_executed=[command_preview],
        performed_side_effects=True,
    )


def run_tunnel_stop_plan(
    plan: TunnelStopPlan,
    *,
    runner: Callable[[list[str]], CommandResult] | None = None,
    allow_side_effects: bool = False,
) -> TunnelCommandResult:
    if not allow_side_effects:
        return TunnelCommandResult(
            backend=plan.backend,
            status="rejected",
            message="allow_side_effects must be true to stop tunnel backend",
            command=plan.command,
            returncode=None,
            stdout="",
            stderr="",
            commands_executed=[],
            performed_side_effects=False,
        )

    run_command = runner or _default_runner
    command_preview = _format_command(plan.command)
    try:
        command_result = run_command(plan.command)
    except FileNotFoundError:
        return TunnelCommandResult(
            backend=plan.backend,
            status="command_not_found",
            message=f"tunnel backend stop command not found: {plan.command[0]}",
            command=plan.command,
            returncode=None,
            stdout="",
            stderr=f"command not found: {plan.command[0]}",
            commands_executed=[],
            performed_side_effects=True,
        )

    status = "stopped" if command_result.returncode == 0 else "failed"
    return TunnelCommandResult(
        backend=plan.backend,
        status=status,
        message="tunnel backend stop command executed" if status == "stopped" else f"tunnel backend stop command failed: {command_preview}",
        command=plan.command,
        returncode=command_result.returncode,
        stdout=command_result.stdout.strip(),
        stderr=command_result.stderr.strip(),
        commands_executed=[command_preview],
        performed_side_effects=True,
    )
