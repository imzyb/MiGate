"""Gated command runner for OpenVPN start plans."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import subprocess
from typing import Protocol

from migate.vpn.process_plan import OpenVPNStartPlan


class CommandResult(Protocol):
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class OpenVPNStartCommandResult:
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class OpenVPNStartStepResult:
    action: str
    status: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class OpenVPNStartResult:
    status: str
    message: str
    steps: list[OpenVPNStartStepResult]
    commands_executed: list[str]
    performed_side_effects: bool


def _default_runner(command: list[str]) -> OpenVPNStartCommandResult:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    return OpenVPNStartCommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def run_openvpn_start_plan(
    plan: OpenVPNStartPlan,
    *,
    runner: Callable[[list[str]], CommandResult] | None = None,
    allow_side_effects: bool = False,
) -> OpenVPNStartResult:
    if not allow_side_effects:
        return OpenVPNStartResult(
            status="rejected",
            message="allow_side_effects must be true to run OpenVPN start commands",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    run_command = runner or _default_runner
    try:
        command_result = run_command(plan.command)
    except FileNotFoundError:
        return OpenVPNStartResult(
            status="failed",
            message=f"OpenVPN start failed; command not found: {plan.command[0]}",
            steps=[
                OpenVPNStartStepResult(
                    action="start_openvpn_process",
                    status="command_not_found",
                    command=plan.command,
                    returncode=None,
                    stdout="",
                    stderr=f"command not found: {plan.command[0]}",
                )
            ],
            commands_executed=[],
            performed_side_effects=True,
        )

    step_status = "success" if command_result.returncode == 0 else "failed"
    return OpenVPNStartResult(
        status="started" if step_status == "success" else "failed",
        message="OpenVPN start command executed" if step_status == "success" else "OpenVPN start command failed",
        steps=[
            OpenVPNStartStepResult(
                action="start_openvpn_process",
                status=step_status,
                command=plan.command,
                returncode=command_result.returncode,
                stdout=command_result.stdout,
                stderr=command_result.stderr,
            )
        ],
        commands_executed=[" ".join(plan.command)],
        performed_side_effects=True,
    )
