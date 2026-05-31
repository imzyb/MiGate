"""Read-only remote leak checks for MiGate egress promotion."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import subprocess
from typing import Protocol

from migate.remote.lifecycle_plan import contains_embedded_credentials
from migate.routing.leak_guard import EgressGuardState, evaluate_egress_guard


class CommandResultLike(Protocol):
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class RemoteLeakCheck:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class RemoteLeakCheckReport:
    status: str
    target: str
    native_public_ip: str | None
    egress_public_ip: str | None
    checks: list[RemoteLeakCheck]
    commands_executed: list[str]
    performed_side_effects: bool


REMOTE_LEAK_CHECK_SCRIPT = " && ".join(
    [
        "printf 'NATIVE_IP:' && (curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null | sed 's/^/ok:/' || printf 'failed:native ip probe failed')",
        "printf '\\nEGRESS_IP:' && (curl -fsS --max-time 8 --socks5-hostname 127.0.0.1:{socks_port} https://api.ipify.org 2>/dev/null | sed 's/^/ok:/' || printf 'failed:egress ip probe failed')",
    ]
)

_CHECK_NAMES = {
    "NATIVE_IP": "native_ip",
    "EGRESS_IP": "egress_ip",
}


def build_remote_leak_check_command(*, host: str, port: int, user: str, socks_port: int = 34501, timeout_seconds: int = 10) -> list[str]:
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
        REMOTE_LEAK_CHECK_SCRIPT.format(socks_port=socks_port),
    ]


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def _command_preview(command: list[str]) -> str:
    return " ".join(command)


def _failed_target_report(message: str) -> RemoteLeakCheckReport:
    return RemoteLeakCheckReport(
        status="failed",
        target="[REDACTED]",
        native_public_ip=None,
        egress_public_ip=None,
        checks=[RemoteLeakCheck("target", "failed", message)],
        commands_executed=[],
        performed_side_effects=False,
    )


def _parse_probe_output(output: str) -> tuple[list[RemoteLeakCheck], str | None, str | None]:
    checks: list[RemoteLeakCheck] = []
    native_ip: str | None = None
    egress_ip: str | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(":", 2)
        if len(parts) != 3:
            checks.append(RemoteLeakCheck("leak_check_output", "failed", line))
            continue
        raw_name, status, message = parts
        name = _CHECK_NAMES.get(raw_name, raw_name.lower())
        checks.append(RemoteLeakCheck(name, status, message))
        if name == "native_ip" and status == "ok":
            native_ip = message
        if name == "egress_ip" and status == "ok":
            egress_ip = message
    return checks, native_ip, egress_ip


def _guard_check(native_ip: str | None, egress_ip: str | None) -> RemoteLeakCheck:
    decision = evaluate_egress_guard(
        EgressGuardState(
            leak_guard_enabled=True,
            fail_policy="block",
            tun_interface="tun-migate",
            tun_interface_exists=True,
            tunnel_running=True,
            native_public_ip=native_ip,
            egress_public_ip=egress_ip,
        )
    )
    return RemoteLeakCheck("egress_guard", "ok" if decision.allowed else "failed", decision.message)


def run_remote_leak_check(
    *,
    host: str,
    port: int,
    user: str,
    socks_port: int = 34501,
    runner: Callable[[list[str]], CommandResultLike] | None = None,
) -> RemoteLeakCheckReport:
    if contains_embedded_credentials(host) or contains_embedded_credentials(user):
        return _failed_target_report("embedded credentials are not allowed")

    target = f"{user}@{host}:{port}"
    command = build_remote_leak_check_command(host=host, port=port, user=user, socks_port=socks_port)
    command_preview = _command_preview(command)
    result = (runner or _default_runner)(command)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or f"remote leak check failed with returncode {result.returncode}"
        return RemoteLeakCheckReport(
            status="failed",
            target=target,
            native_public_ip=None,
            egress_public_ip=None,
            checks=[RemoteLeakCheck("ssh_connectivity", "failed", message)],
            commands_executed=[command_preview],
            performed_side_effects=False,
        )

    checks, native_ip, egress_ip = _parse_probe_output(result.stdout)
    checks.append(_guard_check(native_ip, egress_ip))
    return RemoteLeakCheckReport(
        status="ok" if checks and all(check.status == "ok" for check in checks) else "failed",
        target=target,
        native_public_ip=native_ip,
        egress_public_ip=egress_ip,
        checks=checks,
        commands_executed=[command_preview],
        performed_side_effects=False,
    )


def render_remote_leak_check_report(report: RemoteLeakCheckReport) -> str:
    lines = [
        "Remote leak check",
        f"status: {report.status}",
        f"target: {report.target}",
        f"native_public_ip: {report.native_public_ip}",
        f"egress_public_ip: {report.egress_public_ip}",
        f"commands_executed: {report.commands_executed}",
        f"performed_side_effects: {report.performed_side_effects}",
        "checks:",
    ]
    lines.extend(f"- {check.name}: {check.status} - {check.message}" for check in report.checks)
    return "\n".join(lines) + "\n"
