"""Validation-gated proxy service start operation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import subprocess

from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport, run_proxy_doctor

MIGATE_PROXY_SERVICE_NAME = "migate-proxy.service"


@dataclass(frozen=True)
class ProxyServiceStartCommandResult:
    name: str
    status: str
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    performed_side_effects: bool


@dataclass(frozen=True)
class ProxyServiceStartResult:
    status: str
    message: str
    preflight_status: str
    preflight_checks: list[ProxyRuntimeCheck]
    systemctl_results: list[ProxyServiceStartCommandResult]
    commands_executed: list[list[str]]
    performed_side_effects: bool


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _default_preflight_runner() -> ProxyRuntimeReport:
    return run_proxy_doctor()


def run_proxy_service_start(
    *,
    yes: bool,
    allow_system_changes: bool,
    preflight_runner: Callable[[], ProxyRuntimeReport] | None = None,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]] = _default_runner,
) -> ProxyServiceStartResult:
    if not yes or not allow_system_changes:
        return ProxyServiceStartResult(
            status="rejected",
            message="proxy service start requires yes=True and allow_system_changes=True",
            preflight_status="skipped",
            preflight_checks=[],
            systemctl_results=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    preflight = (preflight_runner or _default_preflight_runner)()
    if preflight.status != "ok":
        return ProxyServiceStartResult(
            status="preflight_failed",
            message=f"proxy service start blocked by preflight: {preflight.status}",
            preflight_status=preflight.status,
            preflight_checks=preflight.checks,
            systemctl_results=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    commands = [
        ("daemon_reload", ["systemctl", "daemon-reload"], False),
        ("enable_proxy_service", ["systemctl", "enable", "--now", MIGATE_PROXY_SERVICE_NAME], True),
        ("verify_proxy_active", ["systemctl", "is-active", MIGATE_PROXY_SERVICE_NAME], False),
    ]
    commands_executed: list[list[str]] = []
    results: list[ProxyServiceStartCommandResult] = []
    performed_side_effects = False

    for name, command, is_side_effect in commands:
        commands_executed.append(command)
        try:
            completed = runner(command)
        except FileNotFoundError as exc:
            result = ProxyServiceStartCommandResult(
                name=name,
                status="systemctl_not_found",
                command=command,
                returncode=None,
                stdout="",
                stderr=str(exc),
                performed_side_effects=False,
            )
            results.append(result)
            return ProxyServiceStartResult(
                status="failed",
                message=f"proxy service start failed at {name}",
                preflight_status=preflight.status,
                preflight_checks=preflight.checks,
                systemctl_results=results,
                commands_executed=commands_executed,
                performed_side_effects=performed_side_effects,
            )
        except subprocess.TimeoutExpired as exc:
            result = ProxyServiceStartCommandResult(
                name=name,
                status="timeout",
                command=command,
                returncode=None,
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "",
                performed_side_effects=is_side_effect,
            )
            results.append(result)
            return ProxyServiceStartResult(
                status="failed",
                message=f"proxy service start failed at {name}",
                preflight_status=preflight.status,
                preflight_checks=preflight.checks,
                systemctl_results=results,
                commands_executed=commands_executed,
                performed_side_effects=performed_side_effects or is_side_effect,
            )

        stdout = completed.stdout.strip()
        stderr = completed.stderr.strip()
        if completed.returncode == 0:
            result = ProxyServiceStartCommandResult(
                name=name,
                status="success",
                command=command,
                returncode=completed.returncode,
                stdout=stdout,
                stderr=stderr,
                performed_side_effects=is_side_effect,
            )
            results.append(result)
            performed_side_effects = performed_side_effects or is_side_effect
            continue

        result = ProxyServiceStartCommandResult(
            name=name,
            status="failed",
            command=command,
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            performed_side_effects=is_side_effect,
        )
        results.append(result)
        return ProxyServiceStartResult(
            status="failed",
            message=f"proxy service start failed at {name}",
            preflight_status=preflight.status,
            preflight_checks=preflight.checks,
            systemctl_results=results,
            commands_executed=commands_executed,
            performed_side_effects=performed_side_effects or is_side_effect,
        )

    return ProxyServiceStartResult(
        status="success",
        message="MiGate proxy service enabled and started",
        preflight_status=preflight.status,
        preflight_checks=preflight.checks,
        systemctl_results=results,
        commands_executed=commands_executed,
        performed_side_effects=performed_side_effects,
    )
