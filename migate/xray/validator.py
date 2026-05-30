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
    command = ["xray", "test", "-config", str(config_path)]
    run = runner or _default_runner
    try:
        completed = run(command)
    except FileNotFoundError:
        return XrayValidationResult(status="xray_not_found", returncode=None, stdout="", stderr="xray command not found")

    status = "valid" if completed.returncode == 0 else "invalid"
    return XrayValidationResult(
        status=status,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def _default_runner(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=False, capture_output=True, text=True)
