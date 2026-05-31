from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class XrayValidationResult:
    status: str
    returncode: int | None
    stdout: str
    stderr: str


def validate_xray_config(
    config_path: str | Path,
    *,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
) -> XrayValidationResult:
    run = runner or _default_runner
    commands = [
        ["xray", "test", "-config", str(config_path)],
        ["xray", "run", "-test", "-config", str(config_path)],
    ]
    try:
        completed = run(commands[0])
        if completed.returncode != 0 and _is_missing_test_subcommand(completed):
            completed = run(commands[1])
    except FileNotFoundError:
        return XrayValidationResult(status="xray_not_found", returncode=None, stdout="", stderr="xray command not found")

    status = "valid" if completed.returncode == 0 else "invalid"
    return XrayValidationResult(
        status=status,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def _is_missing_test_subcommand(completed: subprocess.CompletedProcess[str]) -> bool:
    output = f"{completed.stdout or ''}\n{completed.stderr or ''}".lower()
    return "unknown command" in output and "xray test" in output


def _default_runner(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, capture_output=True, text=True)
