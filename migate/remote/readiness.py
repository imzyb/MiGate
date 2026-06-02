"""Read-only remote readiness checks for MiGate test VPS promotion."""

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
class RemoteReadinessCheck:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class RemoteReadinessReport:
    status: str
    target: str
    checks: list[RemoteReadinessCheck]
    commands_executed: list[str]
    performed_side_effects: bool


REMOTE_READINESS_SCRIPT = " && ".join(
    [
        "printf 'MIGATE_CLI:' && (command -v migate >/dev/null 2>&1 && printf 'ok:' && command -v migate || printf 'failed:missing migate')",
        "printf '\\nMIGATE_VERSION:' && (migate --help >/dev/null 2>&1 && printf 'ok:MiGate smart egress gateway' || printf 'failed:migate cli unavailable')",
        "printf '\\nXRAY_BIN:' && (command -v xray >/dev/null 2>&1 && printf 'ok:' && command -v xray || printf 'failed:missing xray')",
        "printf '\\nOPENVPN_BIN:' && (command -v openvpn >/dev/null 2>&1 && printf 'ok:' && command -v openvpn || printf 'failed:missing openvpn')",
        "printf '\\nSYSTEMCTL_BIN:' && (command -v systemctl >/dev/null 2>&1 && printf 'ok:' && command -v systemctl || printf 'failed:missing systemctl')",
        "printf '\\nIP_BIN:' && (command -v ip >/dev/null 2>&1 && printf 'ok:' && command -v ip || printf 'failed:missing ip')",
        "printf '\\nXRAY_SERVICE_PREVIEW:' && (migate xray service preview >/dev/null 2>&1 && printf 'ok:performed_side_effects: False' || printf 'failed:xray service preview failed')",
        "printf '\\nPROXY_SERVICE_PREVIEW:' && (migate proxy service preview >/dev/null 2>&1 && printf 'ok:performed_side_effects: False' || printf 'failed:proxy service preview failed')",
        "printf '\\nEGRESS_STATUS:' && (migate egress status >/dev/null 2>&1 && printf 'ok:performed_side_effects: False' || printf 'failed:egress status failed')",
    ]
)


_CHECK_NAMES = {
    "MIGATE_CLI": "migate_cli",
    "MIGATE_VERSION": "migate_version",
    "XRAY_BIN": "xray_bin",
    "OPENVPN_BIN": "openvpn_bin",
    "SYSTEMCTL_BIN": "systemctl_bin",
    "IP_BIN": "ip_bin",
    "XRAY_SERVICE_PREVIEW": "xray_service_preview",
    "PROXY_SERVICE_PREVIEW": "proxy_service_preview",
    "EGRESS_STATUS": "egress_status",
}


def build_remote_readiness_command(*, host: str, port: int, user: str, timeout_seconds: int = 10) -> list[str]:
    return [
        "ssh",
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={timeout_seconds}",
        "-o",
        "StrictHostKeyChecking=yes",
        f"{user}@{host}",
        REMOTE_READINESS_SCRIPT,
    ]


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def _command_preview(command: list[str]) -> str:
    return " ".join(command)


def _failed_target_report(message: str) -> RemoteReadinessReport:
    return RemoteReadinessReport(
        status="failed",
        target="[REDACTED]",
        checks=[RemoteReadinessCheck("target", "failed", message)],
        commands_executed=[],
        performed_side_effects=False,
    )


def _parse_probe_output(output: str) -> list[RemoteReadinessCheck]:
    checks: list[RemoteReadinessCheck] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(":", 2)
        if len(parts) != 3:
            checks.append(RemoteReadinessCheck("readiness_output", "failed", line))
            continue
        raw_name, status, message = parts
        checks.append(RemoteReadinessCheck(_CHECK_NAMES.get(raw_name, raw_name.lower()), status, message))
    return checks


def run_remote_readiness(
    *,
    host: str,
    port: int,
    user: str,
    runner: Callable[[list[str]], CommandResultLike] | None = None,
) -> RemoteReadinessReport:
    if contains_embedded_credentials(host) or contains_embedded_credentials(user):
        return _failed_target_report("embedded credentials are not allowed")

    target = f"{user}@{host}:{port}"
    command = build_remote_readiness_command(host=host, port=port, user=user)
    command_preview = _command_preview(command)
    result = (runner or _default_runner)(command)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or f"remote readiness failed with returncode {result.returncode}"
        return RemoteReadinessReport(
            status="failed",
            target=target,
            checks=[RemoteReadinessCheck("ssh_connectivity", "failed", message)],
            commands_executed=[command_preview],
            performed_side_effects=False,
        )

    checks = _parse_probe_output(result.stdout)
    status = "ok" if checks and all(check.status == "ok" for check in checks) else "failed"
    return RemoteReadinessReport(
        status=status,
        target=target,
        checks=checks,
        commands_executed=[command_preview],
        performed_side_effects=False,
    )


def render_remote_readiness_report(report: RemoteReadinessReport) -> str:
    lines = [
        "Remote readiness",
        f"status: {report.status}",
        f"target: {report.target}",
        f"commands_executed: {report.commands_executed}",
        f"performed_side_effects: {report.performed_side_effects}",
        "checks:",
    ]
    lines.extend(f"- {check.name}: {check.status} - {check.message}" for check in report.checks)
    return "\n".join(lines) + "\n"
