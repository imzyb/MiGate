"""Gated runner for MiGate policy routing cleanup commands."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import subprocess
from typing import Protocol

from migate.routing.policy_cleanup import PolicyRoutingCleanupPlan


class PolicyRoutingCleanupCommandResult(Protocol):
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class PolicyRoutingCleanupApplyStep:
    action: str
    status: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class PolicyRoutingCleanupApplyResult:
    status: str
    message: str
    steps: list[PolicyRoutingCleanupApplyStep]
    commands_executed: list[str]
    performed_side_effects: bool = False


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def _format_command(command: list[str]) -> str:
    return " ".join(command)


_ALREADY_ABSENT_ERROR_FRAGMENTS = (
    "fib table does not exist",
    "no such process",
    "cannot find device",
    "no such file or directory",
)


def _cleanup_step_status(result: PolicyRoutingCleanupCommandResult) -> str:
    if result.returncode == 0:
        return "success"
    output = f"{result.stdout}\n{result.stderr}".lower()
    if any(fragment in output for fragment in _ALREADY_ABSENT_ERROR_FRAGMENTS):
        return "already_absent"
    return "failed"


def apply_policy_routing_cleanup_plan(
    plan: PolicyRoutingCleanupPlan,
    *,
    runner: Callable[[list[str]], PolicyRoutingCleanupCommandResult] | None = None,
    allow_side_effects: bool = False,
) -> PolicyRoutingCleanupApplyResult:
    if not allow_side_effects:
        return PolicyRoutingCleanupApplyResult(
            status="rejected",
            message="allow_side_effects must be true to apply cleanup routing commands",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    run_command = runner or _default_runner
    steps: list[PolicyRoutingCleanupApplyStep] = []
    commands_executed: list[str] = []

    for command in plan.commands:
        command_preview = _format_command(command)
        commands_executed.append(command_preview)
        try:
            command_result = run_command(command)
        except FileNotFoundError:
            steps.append(
                PolicyRoutingCleanupApplyStep(
                    action="cleanup_policy_routing_command",
                    status="command_not_found",
                    command=command,
                    returncode=None,
                    stdout="",
                    stderr=f"command not found: {command[0]}",
                )
            )
            return PolicyRoutingCleanupApplyResult(
                status="failed",
                message=f"cleanup routing command not found: {command[0]}",
                steps=steps,
                commands_executed=commands_executed,
                performed_side_effects=True,
            )

        step_status = _cleanup_step_status(command_result)
        steps.append(
            PolicyRoutingCleanupApplyStep(
                action="cleanup_policy_routing_command",
                status=step_status,
                command=command,
                returncode=command_result.returncode,
                stdout=command_result.stdout.strip(),
                stderr=command_result.stderr.strip(),
            )
        )
        if command_result.returncode != 0 and step_status != "already_absent":
            return PolicyRoutingCleanupApplyResult(
                status="failed",
                message=f"cleanup routing command failed: {command_preview}",
                steps=steps,
                commands_executed=commands_executed,
                performed_side_effects=True,
            )

    return PolicyRoutingCleanupApplyResult(
        status="applied",
        message="cleanup routing commands applied",
        steps=steps,
        commands_executed=commands_executed,
        performed_side_effects=True,
    )
