"""Gated remote rollout runner shell.

This layer orchestrates already-tested remote phases only after explicit remote-change
gates. Tests inject phase runners, so the rollout orchestrator itself never owns SSH
credentials or performs direct remote calls.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from migate.remote.readiness import RemoteReadinessReport
from migate.remote.leak_check import RemoteLeakCheckReport
from migate.remote.rollout_plan import RemoteRolloutPlan


class PhaseResultLike(Protocol):
    status: str
    commands_executed: list[str]
    performed_side_effects: bool


@dataclass(frozen=True)
class RemoteRolloutPhaseResult:
    action: str
    status: str
    message: str
    commands_executed: list[str]
    performed_side_effects: bool


@dataclass(frozen=True)
class RemoteRolloutRunResult:
    status: str
    message: str
    target: str
    phases: list[RemoteRolloutPhaseResult]
    commands_executed: list[str]
    performed_side_effects: bool


def _empty_result(*, status: str, message: str, target: str) -> RemoteRolloutRunResult:
    return RemoteRolloutRunResult(
        status=status,
        message=message,
        target=target,
        phases=[],
        commands_executed=[],
        performed_side_effects=False,
    )


def _phase_from_readiness(report: RemoteReadinessReport) -> RemoteRolloutPhaseResult:
    return RemoteRolloutPhaseResult(
        action="readiness",
        status="success" if report.status == "ok" else "failed",
        message="readiness ok" if report.status == "ok" else "readiness failed",
        commands_executed=report.commands_executed,
        performed_side_effects=report.performed_side_effects,
    )


def _phase_from_leak_check(report: RemoteLeakCheckReport) -> RemoteRolloutPhaseResult:
    return RemoteRolloutPhaseResult(
        action="leak_check",
        status="success" if report.status == "ok" else "failed",
        message="leak_check ok" if report.status == "ok" else "leak_check failed",
        commands_executed=report.commands_executed,
        performed_side_effects=report.performed_side_effects,
    )


def _coerce_phase(action: str, phase: PhaseResultLike | RemoteReadinessReport | RemoteLeakCheckReport) -> RemoteRolloutPhaseResult:
    if isinstance(phase, RemoteReadinessReport):
        return _phase_from_readiness(phase)
    if isinstance(phase, RemoteLeakCheckReport):
        return _phase_from_leak_check(phase)
    message = getattr(phase, "message", f"{action} {phase.status}")
    return RemoteRolloutPhaseResult(
        action=action,
        status=phase.status,
        message=message,
        commands_executed=phase.commands_executed,
        performed_side_effects=phase.performed_side_effects,
    )


def run_remote_rollout_plan(
    plan: RemoteRolloutPlan,
    *,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    install_runner: Callable[[], PhaseResultLike] | None = None,
    readiness_runner: Callable[[], RemoteReadinessReport] | None = None,
    egress_up_runner: Callable[[], PhaseResultLike] | None = None,
    leak_check_runner: Callable[[], RemoteLeakCheckReport] | None = None,
) -> RemoteRolloutRunResult:
    if plan.status == "rejected":
        return _empty_result(status="rejected", message=plan.message, target=plan.target)
    if dry_run:
        return _empty_result(
            status="dry_run",
            message="remote rollout dry-run only; no rollout phases executed",
            target=plan.target,
        )
    if not yes or not allow_remote_changes:
        return _empty_result(
            status="rejected",
            message="remote rollout requires yes=True and allow_remote_changes=True",
            target=plan.target,
        )

    if install_runner is None or readiness_runner is None or egress_up_runner is None or leak_check_runner is None:
        return _empty_result(
            status="rejected",
            message="remote rollout requires injected phase runners",
            target=plan.target,
        )

    phases: list[RemoteRolloutPhaseResult] = []
    commands_executed: list[str] = []
    performed_side_effects = False
    runners: list[tuple[str, Callable[[], PhaseResultLike | RemoteReadinessReport | RemoteLeakCheckReport]]] = [
        ("install", install_runner),
        ("readiness", readiness_runner),
        ("egress_up", egress_up_runner),
        ("leak_check", leak_check_runner),
    ]
    for action, runner in runners:
        phase = _coerce_phase(action, runner())
        phases.append(phase)
        commands_executed.extend(phase.commands_executed)
        performed_side_effects = performed_side_effects or phase.performed_side_effects
        if phase.status != "success":
            return RemoteRolloutRunResult(
                status="failed",
                message=f"remote rollout stopped at {action}",
                target=plan.target,
                phases=phases,
                commands_executed=commands_executed,
                performed_side_effects=performed_side_effects,
            )

    return RemoteRolloutRunResult(
        status="success",
        message="remote rollout completed through injected phase runners",
        target=plan.target,
        phases=phases,
        commands_executed=commands_executed,
        performed_side_effects=performed_side_effects,
    )


def render_remote_rollout_run_result(result: RemoteRolloutRunResult) -> str:
    lines = [
        "Remote rollout result",
        f"status: {result.status}",
        f"message: {result.message}",
        f"target: {result.target}",
        f"commands_executed: {result.commands_executed}",
        f"performed_side_effects: {result.performed_side_effects}",
    ]
    if result.phases:
        lines.append("phases:")
        for phase in result.phases:
            lines.append(f"- {phase.action}: {phase.status} - {phase.message}")
    return "\n".join(lines) + "\n"
