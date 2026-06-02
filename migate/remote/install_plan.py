"""Remote install dry-run planning for MiGate test VPS lifecycle.

This module only previews what a future installer would do.
It never SSHs, writes files, runs package managers, or stores credentials.
"""

from __future__ import annotations

from dataclasses import dataclass

from migate.remote.lifecycle_plan import contains_embedded_credentials


@dataclass(frozen=True)
class RemoteInstallStep:
    action: str
    description: str
    command_preview: str
    performs_side_effects: bool


@dataclass(frozen=True)
class RemoteInstallPlan:
    status: str
    message: str
    target: str
    credential_hint: str
    staging_dir: str
    steps: list[RemoteInstallStep]
    commands_executed: list[str]
    performed_side_effects: bool


def _target(host: str, port: int, user: str) -> str:
    return f"{user}@{host}:{port}"


def _reject(message: str) -> RemoteInstallPlan:
    return RemoteInstallPlan(
        status="rejected",
        message=message,
        target="[REDACTED]",
        credential_hint="[REDACTED]",
        staging_dir="",
        steps=[],
        commands_executed=[],
        performed_side_effects=False,
    )


def build_remote_install_dry_run_plan(
    *,
    host: str,
    port: int,
    user: str,
    staging_dir: str,
) -> RemoteInstallPlan:
    if contains_embedded_credentials(host) or contains_embedded_credentials(user):
        return _reject("embedded credentials are not allowed")
    if not staging_dir.startswith("/tmp/"):
        return _reject("staging_dir must be under /tmp/ for dry-run install planning")

    target = _target(host, port, user)
    ssh_target = f"{user}@{host}"
    remote_migate = "migate"
    install_remote_script = (
        f"cd {staging_dir} && "
        "python3 -m pip install --break-system-packages --root-user-action=ignore ."
    )
    service_preview_remote_script = f"{remote_migate} xray service preview && {remote_migate} proxy service preview"

    steps = [
        RemoteInstallStep(
            "doctor",
            "run migate remote doctor before install",
            f"migate remote doctor --host {host} --port {port} --user {user}",
            False,
        ),
        RemoteInstallStep(
            "sync_project",
            "sync project to remote staging directory",
            f"rsync -az --delete ./ {user}@{host}:{staging_dir}/",
            True,
        ),
        RemoteInstallStep(
            "install_python_package",
            "install MiGate package system-wide on remote host",
            f"ssh -p {port} {ssh_target} -- '{install_remote_script}'",
            True,
        ),
        RemoteInstallStep(
            "install_xray",
            "install xray-core through MiGate gated installer",
            f"ssh -p {port} {ssh_target} -- migate xray install --yes --allow-system-changes",
            True,
        ),
        RemoteInstallStep(
            "write_services",
            "preview service units only; real service writes stay gated",
            f"ssh -p {port} {ssh_target} -- '{service_preview_remote_script}'",
            False,
        ),
        RemoteInstallStep(
            "post_install_doctor",
            "run read-only remote doctor after install preview",
            f"migate remote doctor --host {host} --port {port} --user {user}",
            False,
        ),
    ]
    return RemoteInstallPlan(
        status="dry_run",
        message="remote install dry-run only; no SSH or system changes performed",
        target=target,
        credential_hint="[REDACTED]",
        staging_dir=staging_dir,
        steps=steps,
        commands_executed=[],
        performed_side_effects=False,
    )


def render_remote_install_plan(plan: RemoteInstallPlan) -> str:
    lines = [
        "Remote install dry-run",
        f"status: {plan.status}",
        f"message: {plan.message}",
        f"target: {plan.target}",
        f"credential_hint: {plan.credential_hint}",
        f"staging_dir: {plan.staging_dir}",
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
