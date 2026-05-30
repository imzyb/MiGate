"""Remote egress dry-run planning for MiGate test VPS orchestration."""

from __future__ import annotations

from dataclasses import dataclass

from migate.remote.lifecycle_plan import contains_embedded_credentials


@dataclass(frozen=True)
class RemoteEgressStep:
    action: str
    description: str
    command_preview: str
    performs_side_effects: bool


@dataclass(frozen=True)
class RemoteEgressPlan:
    status: str
    message: str
    action: str
    target: str
    credential_hint: str
    steps: list[RemoteEgressStep]
    commands_executed: list[str]
    performed_side_effects: bool


def _target(host: str, port: int, user: str) -> str:
    return f"{user}@{host}:{port}"


def _reject(action: str, message: str) -> RemoteEgressPlan:
    return RemoteEgressPlan(
        status="rejected",
        message=message,
        action=action,
        target="[REDACTED]",
        credential_hint="[REDACTED]",
        steps=[],
        commands_executed=[],
        performed_side_effects=False,
    )


def build_remote_egress_dry_run_plan(*, host: str, port: int, user: str, action: str) -> RemoteEgressPlan:
    if action not in {"up", "down"}:
        return _reject(action, "action must be one of: up, down")
    if contains_embedded_credentials(host) or contains_embedded_credentials(user):
        return _reject(action, "embedded credentials are not allowed in remote egress targets")

    target = _target(host, port, user)
    if action == "up":
        steps = [
            RemoteEgressStep("doctor", "run read-only remote doctor before egress up", f"migate remote doctor --host {host} --port {port} --user {user}", False),
            RemoteEgressStep(
                "egress_up",
                "start remote OpenVPN egress and policy routing through MiGate gates",
                f"ssh -p {port} {user}@{host} -- migate egress up --no-dry-run --yes --allow-system-changes",
                True,
            ),
            RemoteEgressStep("post_up_status", "read remote egress status after up preview", f"ssh -p {port} {user}@{host} -- migate egress status", False),
        ]
        message = "remote egress up dry-run only; no SSH or system changes performed"
    else:
        steps = [
            RemoteEgressStep("doctor", "run read-only remote doctor before egress down", f"migate remote doctor --host {host} --port {port} --user {user}", False),
            RemoteEgressStep(
                "egress_down",
                "stop remote OpenVPN egress and cleanup policy routing through MiGate gates",
                f"ssh -p {port} {user}@{host} -- migate egress down --no-dry-run --yes --allow-system-changes",
                True,
            ),
            RemoteEgressStep("post_down_status", "read remote egress status after down preview", f"ssh -p {port} {user}@{host} -- migate egress status", False),
        ]
        message = "remote egress down dry-run only; no SSH or system changes performed"

    return RemoteEgressPlan(
        status="dry_run",
        message=message,
        action=action,
        target=target,
        credential_hint="[REDACTED]",
        steps=steps,
        commands_executed=[],
        performed_side_effects=False,
    )


def render_remote_egress_plan(plan: RemoteEgressPlan) -> str:
    heading = "Remote egress up dry-run" if plan.action == "up" else "Remote egress down dry-run"
    lines = [
        heading,
        f"status: {plan.status}",
        f"message: {plan.message}",
        f"action: {plan.action}",
        f"target: {plan.target}",
        f"credential_hint: {plan.credential_hint}",
        f"commands_executed: {plan.commands_executed}",
        f"performed_side_effects: {plan.performed_side_effects}",
    ]
    if plan.steps:
        lines.append("steps:")
        for step in plan.steps:
            mode = "planned side-effect" if step.performs_side_effects else "planned read-only"
            lines.append(f"- {step.action}: {mode} - {step.description}")
            lines.append(f"  preview: {step.command_preview}")
    return "\n".join(lines) + "\n"
