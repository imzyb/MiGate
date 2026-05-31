"""Remote acceptance workflow for safe test-VPS verification.

This layer is a single operator-facing verification entrypoint. It first runs the
read-only remote doctor, then delegates to the already-gated rollout smoke wrapper.
It does not own SSH credentials or rebuild lower-level remote commands.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from migate.remote.doctor import RemoteDoctorReport, run_remote_doctor
from migate.remote.lifecycle_plan import contains_embedded_credentials
from migate.remote.rollout_smoke import RemoteRolloutSmokeResult

EXPECTED_REMOTE_ACCEPTANCE_PHASES = ["doctor", "rollout_smoke"]


@dataclass(frozen=True)
class RemoteAcceptancePhaseResult:
    name: str
    status: str
    message: str
    result: object


@dataclass(frozen=True)
class RemoteAcceptanceResult:
    status: str
    message: str
    target: str
    expected_phases: list[str]
    phases: list[RemoteAcceptancePhaseResult]
    commands_executed: list[str]
    performed_side_effects: bool
    backend: str = "default"


def _target(host: str, port: int, user: str) -> str:
    return f"{user}@{host}:{port}"


def _empty_result(*, status: str, message: str, target: str, backend: str = "default") -> RemoteAcceptanceResult:
    return RemoteAcceptanceResult(
        status=status,
        message=message,
        target=target,
        backend=backend,
        expected_phases=EXPECTED_REMOTE_ACCEPTANCE_PHASES,
        phases=[],
        commands_executed=[],
        performed_side_effects=False,
    )


def run_remote_acceptance(
    *,
    host: str,
    port: int,
    user: str,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    backend: str | None = None,
    doctor_runner: Callable[[], RemoteDoctorReport] | None = None,
    rollout_smoke_runner: Callable[[], RemoteRolloutSmokeResult] | None = None,
) -> RemoteAcceptanceResult:
    backend_label = backend or "default"
    if contains_embedded_credentials(host) or contains_embedded_credentials(user):
        return _empty_result(status="rejected", message="embedded credentials are not allowed", target="[REDACTED]", backend=backend_label)

    target = _target(host, port, user)
    if dry_run:
        return _empty_result(
            status="dry_run",
            message="remote acceptance dry-run only; no remote commands executed",
            target=target,
            backend=backend_label,
        )
    if not yes or not allow_remote_changes:
        return _empty_result(
            status="rejected",
            message="remote acceptance requires yes=True and allow_remote_changes=True",
            target=target,
            backend=backend_label,
        )

    doctor = (doctor_runner or (lambda: run_remote_doctor(host=host, port=port, user=user)))()
    phases = [
        RemoteAcceptancePhaseResult(
            "doctor",
            "success" if doctor.status == "ok" else "failed",
            "remote doctor ok" if doctor.status == "ok" else "remote doctor failed",
            doctor,
        )
    ]
    commands_executed = list(doctor.commands_executed)
    performed_side_effects = doctor.performed_side_effects
    if doctor.status != "ok":
        return RemoteAcceptanceResult(
            status="failed",
            message="remote acceptance stopped at doctor",
            target=target,
            backend=backend_label,
            expected_phases=EXPECTED_REMOTE_ACCEPTANCE_PHASES,
            phases=phases,
            commands_executed=commands_executed,
            performed_side_effects=performed_side_effects,
        )

    if rollout_smoke_runner is None:
        return RemoteAcceptanceResult(
            status="rejected",
            message="remote acceptance requires injected rollout smoke runner",
            target=target,
            backend=backend_label,
            expected_phases=EXPECTED_REMOTE_ACCEPTANCE_PHASES,
            phases=phases,
            commands_executed=commands_executed,
            performed_side_effects=performed_side_effects,
        )

    smoke = rollout_smoke_runner()
    phases.append(
        RemoteAcceptancePhaseResult(
            "rollout_smoke",
            "success" if smoke.status == "success" else "failed",
            smoke.message,
            smoke,
        )
    )
    commands_executed.extend(smoke.commands_executed)
    performed_side_effects = performed_side_effects or smoke.performed_side_effects
    if smoke.status != "success":
        return RemoteAcceptanceResult(
            status="failed",
            message="remote acceptance stopped at rollout_smoke",
            target=target,
            backend=backend_label,
            expected_phases=EXPECTED_REMOTE_ACCEPTANCE_PHASES,
            phases=phases,
            commands_executed=commands_executed,
            performed_side_effects=performed_side_effects,
        )

    return RemoteAcceptanceResult(
        status="success",
        message="remote acceptance passed",
        target=target,
        backend=backend_label,
        expected_phases=EXPECTED_REMOTE_ACCEPTANCE_PHASES,
        phases=phases,
        commands_executed=commands_executed,
        performed_side_effects=performed_side_effects,
    )


def render_remote_acceptance_result(result: RemoteAcceptanceResult) -> str:
    lines = [
        "Remote acceptance result",
        f"status: {result.status}",
        f"message: {result.message}",
        f"target: {result.target}",
        f"backend: {result.backend}",
        f"expected_phases: {result.expected_phases}",
        f"commands_executed: {result.commands_executed}",
        f"performed_side_effects: {result.performed_side_effects}",
    ]
    if result.phases:
        lines.append("phases:")
        lines.extend(f"- {phase.name}: {phase.status} - {phase.message}" for phase in result.phases)
    return "\n".join(lines) + "\n"
