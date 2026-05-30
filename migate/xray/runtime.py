"""Runtime detection helpers for xray-core."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

Runner = Callable[..., subprocess.CompletedProcess[str]]
PathExists = Callable[[str], bool]


@dataclass(frozen=True)
class XrayRuntimeStatus:
    status: str
    bin_path: str
    version: str | None
    message: str
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""


def parse_xray_version(output: str) -> str | None:
    first_line = output.splitlines()[0] if output.splitlines() else ""
    match = re.search(r"\bXray\s+(\d+(?:\.\d+)+)\b", first_line)
    if match is None:
        return None
    return match.group(1)


def detect_xray_runtime(
    bin_path: str,
    *,
    runner: Runner = subprocess.run,
    path_exists: PathExists = os.path.exists,
) -> XrayRuntimeStatus:
    if not path_exists(bin_path):
        return XrayRuntimeStatus(
            status="not_installed",
            bin_path=bin_path,
            version=None,
            message=f"xray binary not found: {bin_path}",
        )

    command = [bin_path, "version"]
    try:
        completed = runner(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return XrayRuntimeStatus(
            status="not_installed",
            bin_path=bin_path,
            version=None,
            message=f"xray binary not found: {bin_path}",
        )

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if completed.returncode != 0:
        return XrayRuntimeStatus(
            status="version_failed",
            bin_path=bin_path,
            version=None,
            message="xray version command failed",
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    version = parse_xray_version(stdout) or parse_xray_version(stderr)
    return XrayRuntimeStatus(
        status="installed",
        bin_path=bin_path,
        version=version,
        message="xray is installed" if version else "xray is installed but version was not recognized",
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
    )
