"""Remote rollout dry-run planning for MiGate promotion flow."""

from __future__ import annotations

from dataclasses import dataclass

from migate.remote.lifecycle_plan import contains_embedded_credentials


@dataclass(frozen=True)
class RemoteRolloutStep:
    action: str
    description: str
    command_preview: str
    performs_side_effects: bool


@dataclass(frozen=True)
class RemoteRolloutPlan:
    status: str
    message: str
    target: str
    credential_hint: str
    staging_dir: str
    steps: list[RemoteRolloutStep]
    commands_executed: list[str]
    performed_side_effects: bool


def _target(host: str, port: int, user: str) -> str:
    return f"{user}@{host}:{port}"


def _reject(message: str) -> RemoteRolloutPlan:
    return RemoteRolloutPlan(
        status="rejected",
        message=message,
        target="[REDACTED]",
        credential_hint="[REDACTED]",
        staging_dir="",
        steps=[],
        commands_executed=[],
        performed_side_effects=False,
    )


def build_remote_rollout_dry_run_plan(*, host: str, port: int, user: str, staging_dir: str, backend: str | None = None) -> RemoteRolloutPlan:
    if contains_embedded_credentials(host) or contains_embedded_credentials(user):
        return _reject("embedded credentials are not allowed in remote rollout targets")
    if not staging_dir.startswith("/tmp/"):
        return _reject("staging_dir must be under /tmp/ for dry-run rollout planning")

    backend_arg = f" --backend {backend}" if backend else ""
    ssh_target = f"{user}@{host}"
    if backend == "xray-tun":
        xray_service_save_command = "migate xray tun-service save --yes --allow-system-changes"
        xray_service_name = "migate-xray-tun.service"
    else:
        xray_service_save_command = "migate xray service save --yes --allow-system-changes"
        xray_service_name = "migate-xray.service"
    service_apply_remote_script = (
        f"{xray_service_save_command} && "
        "migate proxy service save --yes --allow-system-changes && "
        "systemctl daemon-reload && "
        f"systemctl restart {xray_service_name} migate-proxy.service && "
        f"systemctl is-active {xray_service_name} migate-proxy.service"
    )
    socks5_smoke_remote_script = (
        'python3 - <<"PY"\n'
        "import socket\n"
        's=socket.create_connection(("127.0.0.1", 34501), timeout=5)\n'
        "s.sendall(bytes([5,1,0]))\n"
        "assert s.recv(2) == bytes([5,0])\n"
        "s.close()\n"
        "PY"
    )
    steps = [
        RemoteRolloutStep(
            action="install",
            description="run gated remote install shell",
            command_preview=(
                f"migate remote install --host {host} --port {port} --user {user} --staging-dir {staging_dir} "
                "--no-dry-run --yes --allow-remote-changes"
            ),
            performs_side_effects=True,
        ),
        RemoteRolloutStep(
            action="readiness",
            description="run read-only post-install readiness probe",
            command_preview=f"migate remote readiness --host {host} --port {port} --user {user}",
            performs_side_effects=False,
        ),
        RemoteRolloutStep(
            action="egress_up",
            description="start remote egress through gated remote egress shell",
            command_preview=f"migate remote egress up --host {host} --port {port} --user {user}{backend_arg} --no-dry-run --yes --allow-remote-changes",
            performs_side_effects=True,
        ),
        RemoteRolloutStep(
            action="service_apply",
            description="save and restart MiGate xray/proxy systemd services on remote host",
            command_preview=f"ssh -p {port} {ssh_target} -- '{service_apply_remote_script}'",
            performs_side_effects=True,
        ),
        RemoteRolloutStep(
            action="socks5_smoke",
            description="run read-only remote SOCKS5 loopback smoke check after proxy service starts",
            command_preview=f"ssh -p {port} {ssh_target} -- '{socks5_smoke_remote_script}'",
            performs_side_effects=False,
        ),
        RemoteRolloutStep(
            action="leak_check",
            description="run read-only remote public-IP leak check and fail closed on unverified egress",
            command_preview=f"migate remote leak-check --host {host} --port {port} --user {user}",
            performs_side_effects=False,
        ),
    ]
    return RemoteRolloutPlan(
        status="dry_run",
        message="remote rollout dry-run only; no SSH or system changes performed",
        target=_target(host, port, user),
        credential_hint="[REDACTED]",
        staging_dir=staging_dir,
        steps=steps,
        commands_executed=[],
        performed_side_effects=False,
    )


def render_remote_rollout_plan(plan: RemoteRolloutPlan) -> str:
    lines = [
        "Remote rollout dry-run",
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
