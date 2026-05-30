"""Command-runner abstraction for xray-core installation.

This module is the first real-installer layer, but it is intentionally not wired
into the panel. Callers must explicitly opt in with allow_side_effects=True and
inject a runner in tests.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
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
class XrayInstallResult:
    status: str
    message: str
    steps: list[XrayInstallStepResult]
    performed_side_effects: bool


def _command_for_step(plan: XrayInstallPlan, step: XrayInstallStep) -> list[str]:
    archive_path = f"/tmp/{plan.archive_name}"
    extract_dir = f"/tmp/migate-xray-{plan.version}"
    commands = {
        "download_archive": ["curl", "-fsSL", plan.download_url, "-o", archive_path],
        "verify_archive": ["python", "-m", "zipfile", "-t", archive_path],
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


def run_xray_install_plan(
    plan: XrayInstallPlan,
    *,
    runner: Callable[[list[str]], XrayInstallCommandResult] | None = None,
    allow_side_effects: bool = True,
) -> XrayInstallResult:
    if not allow_side_effects:
        return XrayInstallResult(
            status="rejected",
            message="allow_side_effects must be true to run installer commands",
            steps=[],
            performed_side_effects=False,
        )

    run_command = runner or _default_runner
    results: list[XrayInstallStepResult] = []
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
            return XrayInstallResult(
                status="failed",
                message=f"installer stopped at {step.action}",
                steps=results,
                performed_side_effects=True,
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
            return XrayInstallResult(
                status="failed",
                message=f"installer stopped at {step.action}",
                steps=results,
                performed_side_effects=True,
            )

    return XrayInstallResult(
        status="success",
        message="all installer steps completed",
        steps=results,
        performed_side_effects=True,
    )
