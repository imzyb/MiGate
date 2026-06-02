"""Gated runner for MiGate policy routing commands."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import subprocess
from typing import Protocol

from migate.routing.policy_plan import PolicyRoutingPlan


class PolicyRoutingCommandResult(Protocol):
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class PolicyRoutingApplyStep:
    action: str
    status: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class PolicyRoutingApplyResult:
    status: str
    message: str
    steps: list[PolicyRoutingApplyStep]
    commands_executed: list[str]
    performed_side_effects: bool = False


def _default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def _format_command(command: list[str]) -> str:
    return " ".join(command)


def _is_missing_rule_delete(command: list[str], command_result: PolicyRoutingCommandResult) -> bool:
    if command[:3] != ["ip", "rule", "del"]:
        return False
    if command_result.returncode == 0:
        return False
    stderr = command_result.stderr.strip().lower()
    return "no such file or directory" in stderr or "no such process" in stderr


def apply_policy_routing_plan(
    plan: PolicyRoutingPlan,
    *,
    runner: Callable[[list[str]], PolicyRoutingCommandResult] | None = None,
    allow_side_effects: bool = False,
) -> PolicyRoutingApplyResult:
    if not allow_side_effects:
        return PolicyRoutingApplyResult(
            status="rejected",
            message="allow_side_effects must be true to apply policy routing commands",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    run_command = runner or _default_runner
    steps: list[PolicyRoutingApplyStep] = []
    commands_executed: list[str] = []

    for command in plan.commands:
        command_preview = _format_command(command)
        commands_executed.append(command_preview)
        try:
            command_result = run_command(command)
        except FileNotFoundError:
            steps.append(
                PolicyRoutingApplyStep(
                    action="apply_policy_routing_command",
                    status="command_not_found",
                    command=command,
                    returncode=None,
                    stdout="",
                    stderr=f"command not found: {command[0]}",
                )
            )
            return PolicyRoutingApplyResult(
                status="failed",
                message=f"policy routing command not found: {command[0]}",
                steps=steps,
                commands_executed=commands_executed,
                performed_side_effects=True,
            )

        step_status = "success" if command_result.returncode == 0 else "failed"
        if _is_missing_rule_delete(command, command_result):
            step_status = "already_absent"
        steps.append(
            PolicyRoutingApplyStep(
                action="apply_policy_routing_command",
                status=step_status,
                command=command,
                returncode=command_result.returncode,
                stdout=command_result.stdout.strip(),
                stderr=command_result.stderr.strip(),
            )
        )
        if command_result.returncode != 0 and step_status != "already_absent":
            return PolicyRoutingApplyResult(
                status="failed",
                message=f"policy routing command failed: {command_preview}",
                steps=steps,
                commands_executed=commands_executed,
                performed_side_effects=True,
            )

    return PolicyRoutingApplyResult(
        status="applied",
        message="policy routing commands applied",
        steps=steps,
        commands_executed=commands_executed,
        performed_side_effects=True,
    )
