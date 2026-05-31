"""Validation-gated Xray apply operations."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from migate.xray.systemctl_cli import ALLOWED_XRAY_TUN_SERVICE_NAME, SystemctlActionResult, run_xray_systemctl_action
from migate.xray.validator import XrayValidationResult, validate_xray_config


@dataclass(frozen=True)
class XrayApplyResult:
    status: str
    message: str
    config_path: str
    validation: XrayValidationResult
    systemctl_results: list[SystemctlActionResult]
    performed_side_effects: bool


def apply_validated_xray_restart(
    config_path: str | Path,
    *,
    yes: bool,
    allow_system_changes: bool,
    validator: Callable[[str | Path], XrayValidationResult] | None = None,
    systemctl_runner: Callable[[str], SystemctlActionResult] | None = None,
) -> XrayApplyResult:
    config_path_text = str(config_path)
    if not yes or not allow_system_changes:
        return XrayApplyResult(
            status="rejected",
            message="apply restart requires yes=True and allow_system_changes=True",
            config_path=config_path_text,
            validation=XrayValidationResult("skipped", None, "", ""),
            systemctl_results=[],
            performed_side_effects=False,
        )

    validate = validator or validate_xray_config
    validation = validate(config_path)
    if validation.status != "valid":
        return XrayApplyResult(
            status="invalid_config",
            message="config validation failed; systemctl actions skipped",
            config_path=config_path_text,
            validation=validation,
            systemctl_results=[],
            performed_side_effects=False,
        )

    run_systemctl = systemctl_runner or _default_systemctl_runner
    daemon_reload_result = run_systemctl("daemon-reload")
    systemctl_results = [daemon_reload_result]
    if daemon_reload_result.status != "success":
        return XrayApplyResult(
            status="systemctl_failed",
            message="daemon-reload failed; restart skipped",
            config_path=config_path_text,
            validation=validation,
            systemctl_results=systemctl_results,
            performed_side_effects=True,
        )

    restart_result = run_systemctl("restart")
    systemctl_results.append(restart_result)
    if restart_result.status != "success":
        return XrayApplyResult(
            status="systemctl_failed",
            message="restart failed",
            config_path=config_path_text,
            validation=validation,
            systemctl_results=systemctl_results,
            performed_side_effects=True,
        )

    return XrayApplyResult(
        status="success",
        message="config validated and service restarted",
        config_path=config_path_text,
        validation=validation,
        systemctl_results=systemctl_results,
        performed_side_effects=True,
    )


def apply_validated_xray_tun_start(
    config_path: str | Path,
    *,
    yes: bool,
    allow_system_changes: bool,
    validator: Callable[[str | Path], XrayValidationResult] | None = None,
    systemctl_runner: Callable[[str], SystemctlActionResult] | None = None,
) -> XrayApplyResult:
    config_path_text = str(config_path)
    if not yes or not allow_system_changes:
        return XrayApplyResult(
            status="rejected",
            message="xray tun start requires yes=True and allow_system_changes=True",
            config_path=config_path_text,
            validation=XrayValidationResult("skipped", None, "", ""),
            systemctl_results=[],
            performed_side_effects=False,
        )

    validate = validator or validate_xray_config
    validation = validate(config_path)
    if validation.status != "valid":
        return XrayApplyResult(
            status="invalid_config",
            message="xray tun config validation failed; systemctl actions skipped",
            config_path=config_path_text,
            validation=validation,
            systemctl_results=[],
            performed_side_effects=False,
        )

    run_systemctl = systemctl_runner or _default_xray_tun_systemctl_runner
    daemon_reload_result = run_systemctl("daemon-reload")
    systemctl_results = [daemon_reload_result]
    if daemon_reload_result.status != "success":
        return XrayApplyResult(
            status="systemctl_failed",
            message="daemon-reload failed; xray tun start skipped",
            config_path=config_path_text,
            validation=validation,
            systemctl_results=systemctl_results,
            performed_side_effects=True,
        )

    start_result = run_systemctl("start")
    systemctl_results.append(start_result)
    if start_result.status != "success":
        return XrayApplyResult(
            status="systemctl_failed",
            message="xray tun start failed",
            config_path=config_path_text,
            validation=validation,
            systemctl_results=systemctl_results,
            performed_side_effects=True,
        )

    return XrayApplyResult(
        status="success",
        message="xray tun config validated and service started",
        config_path=config_path_text,
        validation=validation,
        systemctl_results=systemctl_results,
        performed_side_effects=True,
    )


def _default_systemctl_runner(action: str) -> SystemctlActionResult:
    return run_xray_systemctl_action(action, yes=True, allow_system_changes=True)


def _default_xray_tun_systemctl_runner(action: str) -> SystemctlActionResult:
    return run_xray_systemctl_action(
        action,
        service=ALLOWED_XRAY_TUN_SERVICE_NAME,
        yes=True,
        allow_system_changes=True,
    )
