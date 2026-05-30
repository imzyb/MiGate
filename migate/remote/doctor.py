from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import subprocess
from typing import Protocol

from migate.remote.lifecycle_plan import contains_embedded_credentials


class CommandResultLike(Protocol):
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class RemoteDoctorCheck:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class RemoteDoctorReport:
    status: str
    target: str
    checks: list[RemoteDoctorCheck]
    commands_executed: list[str]
    performed_side_effects: bool


REMOTE_PROBE_SCRIPT = "hostname && uname -srm && id -u && command -v python3 && command -v systemctl && command -v ip && command -v openvpn"


def build_remote_ssh_probe_command(*, host: str, port: int, user: str, timeout_seconds: int = 10) -> list[str]:
    return [
        "ssh",
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={timeout_seconds}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        f"{user}@{host}",
        REMOTE_PROBE_SCRIPT,
    ]


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def _command_preview(command: list[str]) -> str:
    return " ".join(command)


def _failed_target_report(message: str) -> RemoteDoctorReport:
    return RemoteDoctorReport(
        status="failed",
        target="[REDACTED]",
        checks=[RemoteDoctorCheck("target", "failed", message)],
        commands_executed=[],
        performed_side_effects=False,
    )


def _build_success_checks(output: str) -> list[RemoteDoctorCheck]:
    lines = [line.strip() for line in output.splitlines()]
    checks = [RemoteDoctorCheck("ssh_connectivity", "ok", "SSH probe succeeded")]
    hostname = lines[0] if len(lines) > 0 and lines[0] else "unknown"
    kernel = lines[1] if len(lines) > 1 and lines[1] else "unknown"
    uid = lines[2] if len(lines) > 2 and lines[2] else "unknown"
    checks.append(RemoteDoctorCheck("hostname", "ok", hostname))
    checks.append(RemoteDoctorCheck("kernel", "ok", kernel))
    checks.append(RemoteDoctorCheck("remote_user", "ok" if uid == "0" else "failed", f"remote id -u is {uid}"))

    command_names = ["python3", "systemctl", "ip", "openvpn"]
    for index, name in enumerate(command_names, start=3):
        path = lines[index] if len(lines) > index and lines[index] else "missing"
        checks.append(RemoteDoctorCheck(f"command:{name}", "ok" if path != "missing" else "failed", path))
    return checks


def run_remote_doctor(
    *,
    host: str,
    port: int,
    user: str,
    runner: Callable[[list[str]], CommandResultLike] | None = None,
) -> RemoteDoctorReport:
    if contains_embedded_credentials(host) or contains_embedded_credentials(user):
        return _failed_target_report("embedded credentials are not allowed")

    target = f"{user}@{host}:{port}"
    command = build_remote_ssh_probe_command(host=host, port=port, user=user)
    result = (runner or _default_runner)(command)
    command_preview = _command_preview(command)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or f"SSH probe failed with returncode {result.returncode}"
        return RemoteDoctorReport(
            status="failed",
            target=target,
            checks=[RemoteDoctorCheck("ssh_connectivity", "failed", message)],
            commands_executed=[command_preview],
            performed_side_effects=False,
        )

    checks = _build_success_checks(result.stdout)
    status = "ok" if all(check.status == "ok" for check in checks) else "failed"
    return RemoteDoctorReport(
        status=status,
        target=target,
        checks=checks,
        commands_executed=[command_preview],
        performed_side_effects=False,
    )


def render_remote_doctor_report(report: RemoteDoctorReport) -> str:
    lines = [
        "Remote doctor",
        f"status: {report.status}",
        f"target: {report.target}",
        f"commands_executed: {report.commands_executed}",
        f"performed_side_effects: {report.performed_side_effects}",
        "checks:",
    ]
    lines.extend(f"- {check.name}: {check.status} - {check.message}" for check in report.checks)
    return "\n".join(lines) + "\n"
