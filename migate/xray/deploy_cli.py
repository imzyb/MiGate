"""Dry-run deployment plan for Xray lifecycle orchestration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import platform
from typing import Any

from migate.config import MiGateConfig
from migate.xray.apply_cli import XrayApplyResult, apply_validated_xray_restart
from migate.xray.config_cli import XrayConfigSaveResult, save_xray_config
from migate.xray.doctor import DoctorReport, run_xray_install_doctor
from migate.xray.install_plan import normalize_machine_arch
from migate.xray.install_runner import XrayInstallResult
from migate.xray.service_cli import DEFAULT_XRAY_SERVICE_PATH, XrayServiceSaveResult, save_xray_service_unit
from migate.xray.systemctl_cli import ALLOWED_XRAY_SERVICE_NAME, SystemctlActionResult, run_xray_systemctl_action


@dataclass(frozen=True)
class XrayDeployStep:
    name: str
    description: str
    performs_side_effects: bool


@dataclass(frozen=True)
class XrayDeployStepResult:
    name: str
    status: str
    message: str
    result: Any


@dataclass(frozen=True)
class XrayDeployResult:
    status: str
    message: str
    steps: list[XrayDeployStepResult]
    performed_side_effects: bool


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
    if not dry_run and (not yes or not allow_system_changes):
        return XrayDeployPlan(
            status="rejected",
            message="real xray deploy requires yes=True and allow_system_changes=True",
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


def _step_status(success: bool) -> str:
    return "success" if success else "failed"


def _stop_result(*, message: str, steps: list[XrayDeployStepResult]) -> XrayDeployResult:
    return XrayDeployResult(
        status="failed",
        message=message,
        steps=steps,
        performed_side_effects=any(_step_performed_side_effects(step.result) for step in steps),
    )


def _step_performed_side_effects(result: Any) -> bool:
    return bool(getattr(result, "performed_side_effects", False))


def run_xray_deploy(
    config: MiGateConfig,
    *,
    dry_run: bool,
    yes: bool,
    allow_system_changes: bool,
    system: str | None = None,
    machine: str | None = None,
    version: str = "latest",
    doctor_runner: Callable[[], DoctorReport] | None = None,
    install_runner: Callable[[], XrayInstallResult] | None = None,
    config_save_runner: Callable[[], XrayConfigSaveResult] | None = None,
    service_save_runner: Callable[[], XrayServiceSaveResult] | None = None,
    apply_restart_runner: Callable[[], XrayApplyResult] | None = None,
    status_runner: Callable[[], SystemctlActionResult] | None = None,
) -> XrayDeployResult | XrayDeployPlan:
    if dry_run:
        return build_xray_deploy_dry_run_plan(
            config,
            system=system,
            machine=machine,
            version=version,
            dry_run=True,
            yes=yes,
            allow_system_changes=allow_system_changes,
        )
    if not yes or not allow_system_changes:
        return XrayDeployResult(
            status="rejected",
            message="real deploy requires yes=True and allow_system_changes=True",
            steps=[],
            performed_side_effects=False,
        )

    steps: list[XrayDeployStepResult] = []

    doctor = (doctor_runner or run_xray_install_doctor)()
    doctor_ok = doctor.status == "ok"
    steps.append(XrayDeployStepResult("doctor", _step_status(doctor_ok), "doctor ok" if doctor_ok else "doctor failed", doctor))
    if not doctor_ok:
        return _stop_result(message="deploy stopped at doctor", steps=steps)

    install = (install_runner or (lambda: _default_install(config, system=system, machine=machine, version=version)))()
    install_ok = install.status == "success"
    steps.append(XrayDeployStepResult("install", _step_status(install_ok), install.message, install))
    if not install_ok:
        return _stop_result(message="deploy stopped at install", steps=steps)

    config_save = (config_save_runner or (lambda: save_xray_config(config, config.xray.config_path, yes=True, allow_system_changes=True)))()
    config_ok = config_save.status == "saved"
    steps.append(XrayDeployStepResult("config_save", _step_status(config_ok), config_save.message, config_save))
    if not config_ok:
        return _stop_result(message="deploy stopped at config_save", steps=steps)

    service_save = (service_save_runner or (lambda: save_xray_service_unit(yes=True, allow_system_changes=True)))()
    service_ok = service_save.status == "saved"
    steps.append(XrayDeployStepResult("service_save", _step_status(service_ok), service_save.message, service_save))
    if not service_ok:
        return _stop_result(message="deploy stopped at service_save", steps=steps)

    apply_restart = (apply_restart_runner or (lambda: apply_validated_xray_restart(config.xray.config_path, yes=True, allow_system_changes=True)))()
    apply_ok = apply_restart.status == "success"
    steps.append(XrayDeployStepResult("apply_restart", _step_status(apply_ok), apply_restart.message, apply_restart))
    if not apply_ok:
        return _stop_result(message="deploy stopped at apply_restart", steps=steps)

    status = (status_runner or (lambda: run_xray_systemctl_action("status")))()
    status_ok = status.status == "success"
    steps.append(XrayDeployStepResult("status", _step_status(status_ok), "service status read" if status_ok else status.stderr, status))
    if not status_ok:
        return _stop_result(message="deploy stopped at status", steps=steps)

    return XrayDeployResult(
        status="success",
        message="xray deploy completed",
        steps=steps,
        performed_side_effects=True,
    )


def _default_install(config: MiGateConfig, *, system: str | None, machine: str | None, version: str) -> XrayInstallResult:
    from migate.xray.install_plan import build_xray_install_plan
    from migate.xray.install_runner import run_xray_install_plan

    plan = build_xray_install_plan(
        config,
        system=system or platform.system(),
        machine=machine or platform.machine(),
        version=version,
    )
    return run_xray_install_plan(plan, allow_side_effects=True)


def render_xray_deploy_result(result: XrayDeployResult) -> str:
    lines = [
        "Xray deploy result",
        f"status: {result.status}",
        f"message: {result.message}",
        "steps:",
    ]
    for step in result.steps:
        lines.append(f"- {step.name}: {step.status} - {step.message}")
    lines.append(f"performed_side_effects: {result.performed_side_effects}")
    return "\n".join(lines)
