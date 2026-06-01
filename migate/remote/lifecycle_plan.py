from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RemoteLifecycleStep:
    name: str
    description: str
    performs_side_effects: bool


@dataclass(frozen=True)
class RemoteLifecyclePlan:
    status: str
    message: str
    target: str
    credential_hint: str
    steps: list[RemoteLifecycleStep]
    commands_executed: list[str]
    performed_side_effects: bool


def contains_embedded_credentials(value: str) -> bool:
    return "@" in value and (":" in value.split("@", 1)[0])


def build_remote_lifecycle_dry_run_plan(*, host: str, port: int, user: str) -> RemoteLifecyclePlan:
    if contains_embedded_credentials(host) or contains_embedded_credentials(user):
        return RemoteLifecyclePlan(
            status="rejected",
            message="embedded credentials are not allowed in remote lifecycle targets",
            target="[REDACTED]",
            credential_hint="[REDACTED]",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    target = f"{user}@{host}:{port}"
    return RemoteLifecyclePlan(
        status="dry_run",
        message="remote test VPS lifecycle dry-run only; no SSH or system changes performed",
        target=target,
        credential_hint="[REDACTED]",
        steps=[
            RemoteLifecycleStep("doctor", "run read-only remote doctor/preflight checks", performs_side_effects=False),
            RemoteLifecycleStep("acceptance", "delegate to remote acceptance: doctor -> rollout_smoke", performs_side_effects=True),
        ],
        commands_executed=[],
        performed_side_effects=False,
    )


def render_remote_lifecycle_plan(plan: RemoteLifecyclePlan) -> str:
    lines = [
        "Remote lifecycle dry-run",
        f"status: {plan.status}",
        f"message: {plan.message}",
        f"target: {plan.target}",
        f"credential_hint: {plan.credential_hint}",
        f"commands_executed: {plan.commands_executed}",
        f"performed_side_effects: {plan.performed_side_effects}",
    ]
    if plan.steps:
        lines.append("steps:")
        for step in plan.steps:
            side_effect_label = "side-effect" if step.performs_side_effects else "read-only"
            lines.append(f"- {step.name}: planned {side_effect_label} - {step.description}")
    return "\n".join(lines) + "\n"
