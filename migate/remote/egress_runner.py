"""Gated remote egress runner shell.

This layer executes remote egress command previews only after explicit remote-change gates.
It does not own credentials; tests must inject a runner instead of touching real SSH.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import subprocess

from migate.remote.egress_plan import RemoteEgressPlan


@dataclass(frozen=True)
class RemoteEgressCommandResult:
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class RemoteEgressStepResult:
    action: str
    description: str
    status: str
    command: str
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class RemoteEgressRunResult:
    status: str
    message: str
    action: str
    target: str
    steps: list[RemoteEgressStepResult]
    commands_executed: list[str]
    performed_side_effects: bool


def _default_runner(command: str) -> RemoteEgressCommandResult:
    completed = subprocess.run(command, shell=True, check=False, capture_output=True, text=True)
    return RemoteEgressCommandResult(completed.returncode, completed.stdout, completed.stderr)


def _empty_result(*, status: str, message: str, action: str, target: str) -> RemoteEgressRunResult:
    return RemoteEgressRunResult(
        status=status,
        message=message,
        action=action,
        target=target,
        steps=[],
        commands_executed=[],
        performed_side_effects=False,
    )


def _command_status(command_result: RemoteEgressCommandResult) -> str:
    if command_result.returncode != 0:
        return "failed"
    first_line = command_result.stdout.lstrip().splitlines()[0] if command_result.stdout.strip() else ""
    if first_line in {"status: failed", "status: rejected"}:
        return "failed"
    return "success"


def run_remote_egress_plan(
    plan: RemoteEgressPlan,
    *,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    runner: Callable[[str], RemoteEgressCommandResult] | None = None,
) -> RemoteEgressRunResult:
    if plan.status == "rejected":
        return _empty_result(status="rejected", message=plan.message, action=plan.action, target=plan.target)
    if dry_run:
        return _empty_result(
            status="dry_run",
            message="remote egress dry-run only; no remote commands executed",
            action=plan.action,
            target=plan.target,
        )
    if not yes or not allow_remote_changes:
        return _empty_result(
            status="rejected",
            message="remote egress requires yes=True and allow_remote_changes=True",
            action=plan.action,
            target=plan.target,
        )

    run_command = runner or _default_runner
    results: list[RemoteEgressStepResult] = []
    commands_executed: list[str] = []
    performed_side_effects = False
    for step in plan.steps:
        command = step.command_preview
        try:
            command_result = run_command(command)
        except FileNotFoundError:
            command_result = RemoteEgressCommandResult(
                returncode=None,
                stdout="",
                stderr=f"command not found: {command.split()[0] if command.split() else command}",
            )
            status = "command_not_found"
        else:
            status = _command_status(command_result)

        commands_executed.append(command)
        performed_side_effects = performed_side_effects or step.performs_side_effects
        results.append(
            RemoteEgressStepResult(
                action=step.action,
                description=step.description,
                status=status,
                command=command,
                returncode=command_result.returncode,
                stdout=command_result.stdout,
                stderr=command_result.stderr,
            )
        )
        if status != "success":
            return RemoteEgressRunResult(
                status="failed",
                message=f"remote egress {plan.action} stopped at {step.action}",
                action=plan.action,
                target=plan.target,
                steps=results,
                commands_executed=commands_executed,
                performed_side_effects=performed_side_effects,
            )

    return RemoteEgressRunResult(
        status="success",
        message=f"remote egress {plan.action} completed through injected runner",
        action=plan.action,
        target=plan.target,
        steps=results,
        commands_executed=commands_executed,
        performed_side_effects=performed_side_effects,
    )


def render_remote_egress_run_result(result: RemoteEgressRunResult) -> str:
    lines = [
        "Remote egress result",
        f"status: {result.status}",
        f"message: {result.message}",
        f"action: {result.action}",
        f"target: {result.target}",
        f"commands_executed: {result.commands_executed}",
        f"performed_side_effects: {result.performed_side_effects}",
    ]
    if result.steps:
        lines.append("steps:")
        for step in result.steps:
            lines.append(
                f"- {step.action}: {step.status} returncode={step.returncode} command={step.command} stdout={step.stdout} stderr={step.stderr}"
            )
    return "\n".join(lines) + "\n"
