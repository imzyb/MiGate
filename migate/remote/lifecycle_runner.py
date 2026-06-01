from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from migate.remote.acceptance import RemoteAcceptanceResult, run_remote_acceptance
from migate.remote.doctor import RemoteDoctorReport, run_remote_doctor
from migate.remote.lifecycle_plan import build_remote_lifecycle_dry_run_plan, contains_embedded_credentials


@dataclass(frozen=True)
class RemoteLifecyclePhaseResult:
    name: str
    status: str
    message: str
    result: object


@dataclass(frozen=True)
class RemoteLifecycleRunResult:
    status: str
    message: str
    target: str
    phases: list[RemoteLifecyclePhaseResult]
    commands_executed: list[str]
    performed_side_effects: bool


def _target(host: str, port: int, user: str) -> str:
    return f"{user}@{host}:{port}"


def _rejected(message: str, target: str) -> RemoteLifecycleRunResult:
    return RemoteLifecycleRunResult(
        status="rejected",
        message=message,
        target=target,
        phases=[],
        commands_executed=[],
        performed_side_effects=False,
    )


def _dry_run_result(host: str, port: int, user: str) -> RemoteLifecycleRunResult:
    plan = build_remote_lifecycle_dry_run_plan(host=host, port=port, user=user)
    return RemoteLifecycleRunResult(
        status=plan.status,
        message="remote lifecycle dry-run only; no remote commands executed" if plan.status == "dry_run" else plan.message,
        target=plan.target,
        phases=[],
        commands_executed=[],
        performed_side_effects=False,
    )


def run_remote_lifecycle(
    *,
    host: str,
    port: int,
    user: str,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    backend: str | None = None,
    doctor_runner: Callable[[], RemoteDoctorReport] | None = None,
    acceptance_runner: Callable[[], RemoteAcceptanceResult] | None = None,
) -> RemoteLifecycleRunResult:
    if contains_embedded_credentials(host) or contains_embedded_credentials(user):
        return _rejected("embedded credentials are not allowed", "[REDACTED]")

    target = _target(host, port, user)
    if dry_run:
        return _dry_run_result(host, port, user)
    if not yes or not allow_remote_changes:
        return _rejected("remote lifecycle requires yes=True and allow_remote_changes=True", target)

    doctor = (doctor_runner or (lambda: run_remote_doctor(host=host, port=port, user=user)))()
    if doctor.status != "ok":
        return RemoteLifecycleRunResult(
            status="failed",
            message="remote lifecycle stopped at doctor",
            target=target,
            phases=[RemoteLifecyclePhaseResult("doctor", "failed", "remote doctor failed", doctor)],
            commands_executed=doctor.commands_executed,
            performed_side_effects=doctor.performed_side_effects,
        )

    acceptance = (acceptance_runner or (lambda: run_remote_acceptance(host=host, port=port, user=user, dry_run=False, yes=True, allow_remote_changes=True, backend=backend)))()
    phases = [
        RemoteLifecyclePhaseResult("doctor", "success", "remote doctor ok", doctor),
        RemoteLifecyclePhaseResult(
            "acceptance",
            "success" if acceptance.status == "success" else "failed",
            acceptance.message,
            acceptance,
        ),
    ]
    commands_executed = [*doctor.commands_executed, *acceptance.commands_executed]
    performed_side_effects = doctor.performed_side_effects or acceptance.performed_side_effects
    if acceptance.status != "success":
        return RemoteLifecycleRunResult(
            status="failed",
            message="remote lifecycle stopped at acceptance",
            target=target,
            phases=phases,
            commands_executed=commands_executed,
            performed_side_effects=performed_side_effects,
        )

    return RemoteLifecycleRunResult(
        status="success",
        message="remote lifecycle completed through acceptance",
        target=target,
        phases=phases,
        commands_executed=commands_executed,
        performed_side_effects=performed_side_effects,
    )


def render_remote_lifecycle_run_result(result: RemoteLifecycleRunResult) -> str:
    lines = [
        "Remote lifecycle result",
        f"status: {result.status}",
        f"message: {result.message}",
        f"target: {result.target}",
        f"commands_executed: {result.commands_executed}",
        f"performed_side_effects: {result.performed_side_effects}",
    ]
    if result.phases:
        lines.append("phases:")
        lines.extend(f"- {phase.name}: {phase.status} - {phase.message}" for phase in result.phases)
    return "\n".join(lines) + "\n"
