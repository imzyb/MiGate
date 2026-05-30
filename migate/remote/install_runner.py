"""Gated remote install runner shell.

This layer can hand planned command previews to an injected runner after explicit
remote-change gates. It does not own credentials and should not be used without a
caller-controlled runner in tests.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import subprocess

from migate.remote.install_plan import RemoteInstallPlan


@dataclass(frozen=True)
class RemoteInstallCommandResult:
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class RemoteInstallStepResult:
    action: str
    description: str
    status: str
    command: str
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class RemoteInstallRunResult:
    status: str
    message: str
    target: str
    steps: list[RemoteInstallStepResult]
    commands_executed: list[str]
    performed_side_effects: bool


def _default_runner(command: str) -> RemoteInstallCommandResult:
    completed = subprocess.run(command, shell=True, check=False, capture_output=True, text=True)
    return RemoteInstallCommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _empty_result(*, status: str, message: str, target: str) -> RemoteInstallRunResult:
    return RemoteInstallRunResult(
        status=status,
        message=message,
        target=target,
        steps=[],
        commands_executed=[],
        performed_side_effects=False,
    )


def run_remote_install_plan(
    plan: RemoteInstallPlan,
    *,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    runner: Callable[[str], RemoteInstallCommandResult] | None = None,
) -> RemoteInstallRunResult:
    if plan.status == "rejected":
        return _empty_result(status="rejected", message=plan.message, target=plan.target)
    if dry_run:
        return _empty_result(
            status="dry_run",
            message="remote install dry-run only; no remote commands executed",
            target=plan.target,
        )
    if not yes or not allow_remote_changes:
        return _empty_result(
            status="rejected",
            message="remote install requires yes=True and allow_remote_changes=True",
            target=plan.target,
        )

    run_command = runner or _default_runner
    results: list[RemoteInstallStepResult] = []
    commands_executed: list[str] = []
    performed_side_effects = False
    for step in plan.steps:
        command = step.command_preview
        try:
            command_result = run_command(command)
        except FileNotFoundError:
            command_result = RemoteInstallCommandResult(
                returncode=None,
                stdout="",
                stderr=f"command not found: {command.split()[0] if command.split() else command}",
            )
            status = "command_not_found"
        else:
            status = "success" if command_result.returncode == 0 else "failed"
        commands_executed.append(command)
        performed_side_effects = performed_side_effects or step.performs_side_effects
        results.append(
            RemoteInstallStepResult(
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
            return RemoteInstallRunResult(
                status="failed",
                message=f"remote install stopped at {step.action}",
                target=plan.target,
                steps=results,
                commands_executed=commands_executed,
                performed_side_effects=performed_side_effects,
            )

    return RemoteInstallRunResult(
        status="success",
        message="remote install completed through injected runner",
        target=plan.target,
        steps=results,
        commands_executed=commands_executed,
        performed_side_effects=performed_side_effects,
    )


def render_remote_install_run_result(result: RemoteInstallRunResult) -> str:
    lines = [
        "Remote install result",
        f"status: {result.status}",
        f"message: {result.message}",
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
