"""Dry-run deployment plan for Xray lifecycle orchestration."""

from __future__ import annotations

from dataclasses import dataclass
import platform
from migate.config import MiGateConfig
from migate.xray.install_plan import normalize_machine_arch
from migate.xray.service_cli import DEFAULT_XRAY_SERVICE_PATH
from migate.xray.systemctl_cli import ALLOWED_XRAY_SERVICE_NAME


@dataclass(frozen=True)
class XrayDeployStep:
    name: str
    description: str
    performs_side_effects: bool


@dataclass(frozen=True)
class XrayDeployPlan:
    status: str
    message: str
    steps: list[XrayDeployStep]
    commands_executed: list[list[str]]
    performed_side_effects: bool


def build_xray_deploy_dry_run_plan(
    config: MiGateConfig,
    *,
    system: str | None = None,
    machine: str | None = None,
    version: str = "latest",
    dry_run: bool = True,
    yes: bool = False,
    allow_system_changes: bool = False,
) -> XrayDeployPlan:
    if not dry_run:
        return XrayDeployPlan(
            status="rejected",
            message="real xray deploy is not implemented; run with --dry-run",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    normalized_system = (system or platform.system()).strip().lower()
    arch = normalize_machine_arch(machine or platform.machine())
    service_path = DEFAULT_XRAY_SERVICE_PATH
    config_path = config.xray.config_path
    return XrayDeployPlan(
        status="dry_run",
        message="xray deploy dry-run only; no system changes performed",
        steps=[
            XrayDeployStep("doctor", "run xray install doctor/preflight checks", performs_side_effects=False),
            XrayDeployStep("install", f"install xray-core {version} for {normalized_system}-{arch}", performs_side_effects=True),
            XrayDeployStep("config_save", f"atomically save and validate {config_path}", performs_side_effects=True),
            XrayDeployStep("service_save", f"write systemd unit {service_path}", performs_side_effects=True),
            XrayDeployStep("apply_restart", f"validate config then daemon-reload and restart {ALLOWED_XRAY_SERVICE_NAME}", performs_side_effects=True),
            XrayDeployStep("status", f"read {ALLOWED_XRAY_SERVICE_NAME} status", performs_side_effects=False),
        ],
        commands_executed=[],
        performed_side_effects=False,
    )


def render_xray_deploy_plan(plan: XrayDeployPlan) -> str:
    lines = [
        "Xray deploy dry-run",
        f"status: {plan.status}",
        f"message: {plan.message}",
        "steps:",
    ]
    for step in plan.steps:
        mode = "side-effect" if step.performs_side_effects else "read-only"
        lines.append(f"- {step.name}: planned {mode} - {step.description}")
    lines.append(f"commands_executed: {plan.commands_executed}")
    lines.append(f"performed_side_effects: {plan.performed_side_effects}")
    return "\n".join(lines)
