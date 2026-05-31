"""Gated remote rollout smoke verification.

This layer wraps the existing rollout runner and verifies the rollout reached the
expected four-phase path. It does not own SSH credentials or run remote commands
itself; tests and CLI inject the rollout runner.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from migate.remote.rollout_plan import RemoteRolloutPlan
from migate.remote.rollout_runner import RemoteRolloutRunResult

EXPECTED_REMOTE_ROLLOUT_SMOKE_PHASES = ["install", "readiness", "egress_up", "leak_check"]


@dataclass(frozen=True)
class RemoteRolloutSmokeResult:
    status: str
    message: str
    target: str
    expected_phases: list[str]
    rollout: RemoteRolloutRunResult | None
    commands_executed: list[str]
    performed_side_effects: bool


def _empty_result(*, status: str, message: str, target: str) -> RemoteRolloutSmokeResult:
    return RemoteRolloutSmokeResult(
        status=status,
        message=message,
        target=target,
        expected_phases=EXPECTED_REMOTE_ROLLOUT_SMOKE_PHASES,
        rollout=None,
        commands_executed=[],
        performed_side_effects=False,
    )


def run_remote_rollout_smoke(
    plan: RemoteRolloutPlan,
    *,
    dry_run: bool,
    yes: bool,
    allow_remote_changes: bool,
    rollout_runner: Callable[[], RemoteRolloutRunResult] | None = None,
) -> RemoteRolloutSmokeResult:
    if plan.status == "rejected":
        return _empty_result(status="rejected", message=plan.message, target=plan.target)
    if dry_run:
        return _empty_result(
            status="dry_run",
            message="remote rollout smoke dry-run only; no rollout executed",
            target=plan.target,
        )
    if not yes or not allow_remote_changes:
        return _empty_result(
            status="rejected",
            message="remote rollout smoke requires yes=True and allow_remote_changes=True",
            target=plan.target,
        )
    if rollout_runner is None:
        return _empty_result(
            status="rejected",
            message="remote rollout smoke requires injected rollout runner",
            target=plan.target,
        )

    rollout = rollout_runner()
    phase_actions = [phase.action for phase in rollout.phases]
    if rollout.status != "success":
        return RemoteRolloutSmokeResult(
            status="failed",
            message=f"remote rollout smoke failed: {rollout.message}",
            target=plan.target,
            expected_phases=EXPECTED_REMOTE_ROLLOUT_SMOKE_PHASES,
            rollout=rollout,
            commands_executed=rollout.commands_executed,
            performed_side_effects=rollout.performed_side_effects,
        )
    if phase_actions != EXPECTED_REMOTE_ROLLOUT_SMOKE_PHASES:
        return RemoteRolloutSmokeResult(
            status="failed",
            message="remote rollout smoke expected phases install -> readiness -> egress_up -> leak_check",
            target=plan.target,
            expected_phases=EXPECTED_REMOTE_ROLLOUT_SMOKE_PHASES,
            rollout=rollout,
            commands_executed=rollout.commands_executed,
            performed_side_effects=rollout.performed_side_effects,
        )
    return RemoteRolloutSmokeResult(
        status="success",
        message="remote rollout smoke passed",
        target=plan.target,
        expected_phases=EXPECTED_REMOTE_ROLLOUT_SMOKE_PHASES,
        rollout=rollout,
        commands_executed=rollout.commands_executed,
        performed_side_effects=rollout.performed_side_effects,
    )


def render_remote_rollout_smoke_result(result: RemoteRolloutSmokeResult) -> str:
    lines = [
        "Remote rollout smoke result",
        f"status: {result.status}",
        f"message: {result.message}",
        f"target: {result.target}",
        f"expected_phases: {result.expected_phases}",
        f"commands_executed: {result.commands_executed}",
        f"performed_side_effects: {result.performed_side_effects}",
    ]
    if result.rollout is not None:
        lines.extend(
            [
                f"rollout_status: {result.rollout.status}",
                f"rollout_message: {result.rollout.message}",
                "rollout_phases:",
            ]
        )
        for phase in result.rollout.phases:
            lines.append(f"- {phase.action}: {phase.status} - {phase.message}")
    return "\n".join(lines) + "\n"
