from pathlib import Path

from migate.config import MiGateConfig
from migate.xray.apply_cli import XrayApplyResult
from migate.xray.config_cli import XrayConfigSaveResult
from migate.xray.deploy_cli import (
    XrayDeployPlan,
    XrayDeployResult,
    XrayDeployStep,
    XrayDeployStepResult,
    build_xray_deploy_dry_run_plan,
    render_xray_deploy_plan,
    run_xray_deploy,
)
from migate.xray.doctor import DoctorCheck, DoctorReport
from migate.xray.install_runner import XrayInstallResult
from migate.xray.service_cli import XrayServiceSaveResult
from migate.xray.systemctl_cli import ALLOWED_XRAY_SERVICE_NAME, SystemctlActionResult
from migate.xray.validator import XrayValidationResult


def test_build_xray_deploy_dry_run_plan_lists_safe_order_without_side_effects():
    plan = build_xray_deploy_dry_run_plan(MiGateConfig(), system="Linux", machine="x86_64", version="v1.8.24")

    assert plan == XrayDeployPlan(
        status="dry_run",
        message="xray deploy dry-run only; no system changes performed",
        steps=[
            XrayDeployStep("doctor", "run xray install doctor/preflight checks", performs_side_effects=False),
            XrayDeployStep("install", "install xray-core v1.8.24 for linux-64", performs_side_effects=True),
            XrayDeployStep("config_save", "atomically save and validate /etc/migate/xray/config.json", performs_side_effects=True),
            XrayDeployStep("service_save", "write systemd unit /etc/systemd/system/migate-xray.service", performs_side_effects=True),
            XrayDeployStep("apply_restart", "validate config then daemon-reload and restart migate-xray.service", performs_side_effects=True),
            XrayDeployStep("status", "read migate-xray.service status", performs_side_effects=False),
        ],
        commands_executed=[],
        performed_side_effects=False,
    )


def test_render_xray_deploy_plan_marks_real_steps_as_planned_not_executed():
    plan = build_xray_deploy_dry_run_plan(MiGateConfig(), system="Linux", machine="x86_64", version="latest")

    rendered = render_xray_deploy_plan(plan)

    assert "Xray deploy dry-run" in rendered
    assert "status: dry_run" in rendered
    assert "commands_executed: []" in rendered
    assert "performed_side_effects: False" in rendered
    assert "- doctor: planned read-only" in rendered
    assert "- install: planned side-effect" in rendered
    assert "- apply_restart: planned side-effect" in rendered
    assert "systemctl restart" not in rendered
    assert "执行" not in rendered


def _ok_doctor() -> DoctorReport:
    return DoctorReport(status="ok", checks=[DoctorCheck("command:curl", "ok", "curl found")])


def _ok_install() -> XrayInstallResult:
    return XrayInstallResult(status="success", message="installed", steps=[], performed_side_effects=True)


def _ok_config() -> XrayConfigSaveResult:
    return XrayConfigSaveResult(
        status="saved",
        message="config saved and validated",
        target=Path("/etc/migate/xray/config.json"),
        validation_status="valid",
        performed_side_effects=True,
    )


def _ok_service() -> XrayServiceSaveResult:
    return XrayServiceSaveResult(
        status="saved",
        message="service unit saved; daemon-reload not run",
        target=Path("/etc/systemd/system/migate-xray.service"),
        performed_side_effects=True,
        systemctl_commands_executed=[],
    )


def _ok_apply() -> XrayApplyResult:
    return XrayApplyResult(
        status="success",
        message="config validated and service restarted",
        config_path="/etc/migate/xray/config.json",
        validation=XrayValidationResult("valid", 0, "ok", ""),
        systemctl_results=[],
        performed_side_effects=True,
    )


def _ok_status() -> SystemctlActionResult:
    return SystemctlActionResult(
        status="success",
        action="status",
        service=ALLOWED_XRAY_SERVICE_NAME,
        command=["systemctl", "status", ALLOWED_XRAY_SERVICE_NAME, "--no-pager"],
        returncode=0,
        stdout="active",
        stderr="",
        performed_side_effects=False,
    )


def test_run_xray_deploy_rejects_real_execution_without_double_gate():
    calls = []

    result = run_xray_deploy(
        MiGateConfig(),
        dry_run=False,
        yes=True,
        allow_system_changes=False,
        doctor_runner=lambda: calls.append("doctor") or _ok_doctor(),
    )

    assert result == XrayDeployResult(
        status="rejected",
        message="real deploy requires yes=True and allow_system_changes=True",
        steps=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_run_xray_deploy_stops_when_doctor_fails():
    calls = []
    failed_doctor = DoctorReport(status="failed", checks=[DoctorCheck("command:curl", "missing", "curl not found")])

    result = run_xray_deploy(
        MiGateConfig(),
        dry_run=False,
        yes=True,
        allow_system_changes=True,
        doctor_runner=lambda: calls.append("doctor") or failed_doctor,
        install_runner=lambda: calls.append("install") or _ok_install(),
    )

    assert result.status == "failed"
    assert result.message == "deploy stopped at doctor"
    assert result.steps == [XrayDeployStepResult("doctor", "failed", "doctor failed", failed_doctor)]
    assert result.performed_side_effects is False
    assert calls == ["doctor"]


def test_run_xray_deploy_executes_all_steps_in_order_on_success():
    calls = []

    result = run_xray_deploy(
        MiGateConfig(),
        dry_run=False,
        yes=True,
        allow_system_changes=True,
        doctor_runner=lambda: calls.append("doctor") or _ok_doctor(),
        install_runner=lambda: calls.append("install") or _ok_install(),
        config_save_runner=lambda: calls.append("config_save") or _ok_config(),
        service_save_runner=lambda: calls.append("service_save") or _ok_service(),
        apply_restart_runner=lambda: calls.append("apply_restart") or _ok_apply(),
        status_runner=lambda: calls.append("status") or _ok_status(),
    )

    assert result.status == "success"
    assert result.message == "xray deploy completed"
    assert [step.name for step in result.steps] == ["doctor", "install", "config_save", "service_save", "apply_restart", "status"]
    assert [step.status for step in result.steps] == ["success", "success", "success", "success", "success", "success"]
    assert result.performed_side_effects is True
    assert calls == ["doctor", "install", "config_save", "service_save", "apply_restart", "status"]


def test_run_xray_deploy_stops_when_config_save_fails_after_install():
    calls = []
    failed_config = XrayConfigSaveResult(
        status="invalid",
        message="config validation failed; restored previous config",
        target=Path("/etc/migate/xray/config.json"),
        validation_status="invalid",
        performed_side_effects=True,
        rollback_performed=True,
    )

    result = run_xray_deploy(
        MiGateConfig(),
        dry_run=False,
        yes=True,
        allow_system_changes=True,
        doctor_runner=lambda: calls.append("doctor") or _ok_doctor(),
        install_runner=lambda: calls.append("install") or _ok_install(),
        config_save_runner=lambda: calls.append("config_save") or failed_config,
        service_save_runner=lambda: calls.append("service_save") or _ok_service(),
    )

    assert result.status == "failed"
    assert result.message == "deploy stopped at config_save"
    assert [step.name for step in result.steps] == ["doctor", "install", "config_save"]
    assert [step.status for step in result.steps] == ["success", "success", "failed"]
    assert result.performed_side_effects is True
    assert calls == ["doctor", "install", "config_save"]


def test_render_xray_deploy_result_includes_structured_step_statuses():
    result = XrayDeployResult(
        status="success",
        message="xray deploy completed",
        steps=[
            XrayDeployStepResult("doctor", "success", "doctor ok", _ok_doctor()),
            XrayDeployStepResult("status", "success", "service status read", _ok_status()),
        ],
        performed_side_effects=True,
    )

    from migate.xray.deploy_cli import render_xray_deploy_result

    rendered = render_xray_deploy_result(result)

    assert "Xray deploy result" in rendered
    assert "status: success" in rendered
    assert "- doctor: success - doctor ok" in rendered
    assert "- status: success - service status read" in rendered
    assert "performed_side_effects: True" in rendered
