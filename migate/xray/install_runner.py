"""Command-runner abstraction for xray-core installation.

This module is the first real-installer layer, but it is intentionally not wired
into the panel. Callers must explicitly opt in with allow_side_effects=True and
inject a runner in tests.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import subprocess

from migate.xray.install_plan import XrayInstallPlan, XrayInstallStep


@dataclass(frozen=True)
class XrayInstallCommandResult:
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class XrayInstallStepResult:
    action: str
    description: str
    status: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class XrayInstallRollbackStep:
    action: str
    status: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str


@dataclass(frozen=True)
class XrayInstallResult:
    status: str
    message: str
    steps: list[XrayInstallStepResult]
    performed_side_effects: bool
    backup_path: str | None = None
    rollback_steps: list[XrayInstallRollbackStep] | None = None
    rollback_performed: bool = False


def _command_for_step(plan: XrayInstallPlan, step: XrayInstallStep) -> list[str]:
    archive_path = f"/tmp/{plan.archive_name}"
    extract_dir = f"/tmp/migate-xray-{plan.version}"
    commands = {
        "download_archive": ["curl", "-fsSL", plan.download_url, "-o", archive_path],
        "verify_archive": ["python3", "-m", "zipfile", "-t", archive_path],
        "extract_binary": ["unzip", "-o", archive_path, "xray", "-d", extract_dir],
        "install_binary": ["install", "-m", "0755", f"{extract_dir}/xray", plan.bin_path],
        "chmod_executable": ["chmod", "+x", plan.bin_path],
        "verify_version": [plan.bin_path, "version"],
    }
    return commands.get(step.action, ["false"])


def _default_runner(command: list[str]) -> XrayInstallCommandResult:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    return XrayInstallCommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _default_existing_binary_checker(path: str) -> bool:
    return Path(path).exists()


def _rollback_backup(
    *,
    backup_path: str,
    bin_path: str,
    run_command: Callable[[list[str]], XrayInstallCommandResult],
) -> XrayInstallRollbackStep:
    command = ["mv", backup_path, bin_path]
    try:
        result = run_command(command)
        status = "success" if result.returncode == 0 else "failed"
        return XrayInstallRollbackStep(
            action="restore_binary",
            status=status,
            command=command,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )
    except FileNotFoundError:
        return XrayInstallRollbackStep(
            action="restore_binary",
            status="command_not_found",
            command=command,
            returncode=None,
            stdout="",
            stderr=f"command not found: {command[0]}",
        )


def _failed_result(
    *,
    message: str,
    steps: list[XrayInstallStepResult],
    backup_path: str | None,
    rollback_steps: list[XrayInstallRollbackStep],
    run_command: Callable[[list[str]], XrayInstallCommandResult],
    bin_path: str,
) -> XrayInstallResult:
    rollback_performed = False
    final_message = message
    if backup_path:
        rollback = _rollback_backup(backup_path=backup_path, bin_path=bin_path, run_command=run_command)
        rollback_steps = [*rollback_steps, rollback]
        rollback_performed = True
        if rollback.status != "success":
            final_message = f"{message}; rollback failed"
    return XrayInstallResult(
        status="failed",
        message=final_message,
        steps=steps,
        performed_side_effects=True,
        backup_path=backup_path,
        rollback_steps=rollback_steps,
        rollback_performed=rollback_performed,
    )


def run_xray_install_plan(
    plan: XrayInstallPlan,
    *,
    runner: Callable[[list[str]], XrayInstallCommandResult] | None = None,
    allow_side_effects: bool = True,
    existing_binary_checker: Callable[[str], bool] | None = None,
    backup_suffix: str = ".bak",
) -> XrayInstallResult:
    if not allow_side_effects:
        return XrayInstallResult(
            status="rejected",
            message="allow_side_effects must be true to run installer commands",
            steps=[],
            performed_side_effects=False,
        )

    run_command = runner or _default_runner
    binary_exists = existing_binary_checker or _default_existing_binary_checker
    results: list[XrayInstallStepResult] = []
    rollback_steps: list[XrayInstallRollbackStep] = []
    backup_path = None
    if binary_exists(plan.bin_path):
        backup_path = f"{plan.bin_path}{backup_suffix}"
        backup_command = ["cp", "-p", plan.bin_path, backup_path]
        try:
            backup_result = run_command(backup_command)
        except FileNotFoundError:
            return XrayInstallResult(
                status="failed",
                message="installer stopped at backup_binary",
                steps=[
                    XrayInstallStepResult(
                        action="backup_binary",
                        description="备份旧 xray 二进制",
                        status="command_not_found",
                        command=backup_command,
                        returncode=None,
                        stdout="",
                        stderr="command not found: cp",
                    )
                ],
                performed_side_effects=True,
                backup_path=backup_path,
                rollback_steps=[],
                rollback_performed=False,
            )
        backup_status = "success" if backup_result.returncode == 0 else "failed"
        results.append(
            XrayInstallStepResult(
                action="backup_binary",
                description="备份旧 xray 二进制",
                status=backup_status,
                command=backup_command,
                returncode=backup_result.returncode,
                stdout=backup_result.stdout,
                stderr=backup_result.stderr,
            )
        )
        if backup_status != "success":
            return XrayInstallResult(
                status="failed",
                message="installer stopped at backup_binary",
                steps=results,
                performed_side_effects=True,
                backup_path=backup_path,
                rollback_steps=[],
                rollback_performed=False,
            )
        rollback_steps.append(
            XrayInstallRollbackStep(
                action="restore_binary",
                status="planned",
                command=["mv", backup_path, plan.bin_path],
                returncode=None,
                stdout="",
                stderr="",
            )
        )

    for step in plan.steps:
        command = _command_for_step(plan, step)
        try:
            command_result = run_command(command)
        except FileNotFoundError:
            results.append(
                XrayInstallStepResult(
                    action=step.action,
                    description=step.description,
                    status="command_not_found",
                    command=command,
                    returncode=None,
                    stdout="",
                    stderr=f"command not found: {command[0]}",
                )
            )
            return _failed_result(
                message=f"installer stopped at {step.action}",
                steps=results,
                backup_path=backup_path,
                rollback_steps=rollback_steps,
                run_command=run_command,
                bin_path=plan.bin_path,
            )

        status = "success" if command_result.returncode == 0 else "failed"
        results.append(
            XrayInstallStepResult(
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
            return _failed_result(
                message=f"installer stopped at {step.action}",
                steps=results,
                backup_path=backup_path,
                rollback_steps=rollback_steps,
                run_command=run_command,
                bin_path=plan.bin_path,
            )

    return XrayInstallResult(
        status="success",
        message="all installer steps completed",
        steps=results,
        performed_side_effects=True,
        backup_path=backup_path,
        rollback_steps=rollback_steps,
        rollback_performed=False,
    )
