import subprocess

from migate.xray.apply_cli import XrayApplyResult, apply_validated_xray_restart, apply_validated_xray_tun_start
from migate.xray.systemctl_cli import ALLOWED_XRAY_SERVICE_NAME, ALLOWED_XRAY_TUN_SERVICE_NAME, SystemctlActionResult
from migate.xray.validator import XrayValidationResult


def test_apply_validated_xray_restart_rejects_without_double_gate():
    validate_calls = []
    systemctl_calls = []

    result = apply_validated_xray_restart(
        "/etc/migate/xray/config.json",
        yes=True,
        allow_system_changes=False,
        validator=lambda path: validate_calls.append(path) or XrayValidationResult("valid", 0, "ok", ""),
        systemctl_runner=lambda action: systemctl_calls.append(action) or SystemctlActionResult(
            "success", action, ALLOWED_XRAY_SERVICE_NAME, [], 0, "", "", True
        ),
    )

    assert result.status == "rejected"
    assert result.message == "apply restart requires yes=True and allow_system_changes=True"
    assert result.validation.status == "skipped"
    assert result.systemctl_results == []
    assert result.performed_side_effects is False
    assert validate_calls == []
    assert systemctl_calls == []


def test_apply_validated_xray_restart_blocks_systemctl_when_validation_fails():
    systemctl_calls = []

    result = apply_validated_xray_restart(
        "/etc/migate/xray/config.json",
        yes=True,
        allow_system_changes=True,
        validator=lambda path: XrayValidationResult("invalid", 1, "", "bad config"),
        systemctl_runner=lambda action: systemctl_calls.append(action) or SystemctlActionResult(
            "success", action, ALLOWED_XRAY_SERVICE_NAME, [], 0, "", "", True
        ),
    )

    assert result.status == "invalid_config"
    assert result.message == "config validation failed; systemctl actions skipped"
    assert result.validation.status == "invalid"
    assert result.systemctl_results == []
    assert result.performed_side_effects is False
    assert systemctl_calls == []


def test_apply_validated_xray_restart_runs_daemon_reload_then_restart_after_valid_config():
    actions = []

    def validator(path):
        assert str(path) == "/etc/migate/xray/config.json"
        return XrayValidationResult("valid", 0, "config ok", "")

    def systemctl_runner(action):
        actions.append(action)
        return SystemctlActionResult(
            status="success",
            action=action,
            service=ALLOWED_XRAY_SERVICE_NAME,
            command=["systemctl", action],
            returncode=0,
            stdout=f"{action} ok",
            stderr="",
            performed_side_effects=True,
        )

    result = apply_validated_xray_restart(
        "/etc/migate/xray/config.json",
        yes=True,
        allow_system_changes=True,
        validator=validator,
        systemctl_runner=systemctl_runner,
    )

    assert result == XrayApplyResult(
        status="success",
        message="config validated and service restarted",
        config_path="/etc/migate/xray/config.json",
        validation=XrayValidationResult("valid", 0, "config ok", ""),
        systemctl_results=[
            SystemctlActionResult("success", "daemon-reload", ALLOWED_XRAY_SERVICE_NAME, ["systemctl", "daemon-reload"], 0, "daemon-reload ok", "", True),
            SystemctlActionResult("success", "restart", ALLOWED_XRAY_SERVICE_NAME, ["systemctl", "restart"], 0, "restart ok", "", True),
        ],
        performed_side_effects=True,
    )
    assert actions == ["daemon-reload", "restart"]


def test_apply_validated_xray_restart_stops_after_daemon_reload_failure():
    actions = []

    def systemctl_runner(action):
        actions.append(action)
        return SystemctlActionResult(
            status="failed",
            action=action,
            service=ALLOWED_XRAY_SERVICE_NAME,
            command=["systemctl", action],
            returncode=1,
            stdout="",
            stderr="daemon reload failed",
            performed_side_effects=True,
        )

    result = apply_validated_xray_restart(
        "/etc/migate/xray/config.json",
        yes=True,
        allow_system_changes=True,
        validator=lambda path: XrayValidationResult("valid", 0, "ok", ""),
        systemctl_runner=systemctl_runner,
    )

    assert result.status == "systemctl_failed"
    assert result.message == "daemon-reload failed; restart skipped"
    assert [item.action for item in result.systemctl_results] == ["daemon-reload"]
    assert result.performed_side_effects is True
    assert actions == ["daemon-reload"]


def test_apply_validated_xray_tun_start_rejects_without_double_gate():
    validate_calls = []
    systemctl_calls = []

    result = apply_validated_xray_tun_start(
        "/etc/migate/xray/config.json",
        yes=True,
        allow_system_changes=False,
        validator=lambda path: validate_calls.append(path) or XrayValidationResult("valid", 0, "ok", ""),
        systemctl_runner=lambda action: systemctl_calls.append(action) or SystemctlActionResult(
            "success", action, ALLOWED_XRAY_TUN_SERVICE_NAME, [], 0, "", "", True
        ),
    )

    assert result == XrayApplyResult(
        status="rejected",
        message="xray tun start requires yes=True and allow_system_changes=True",
        config_path="/etc/migate/xray/config.json",
        validation=XrayValidationResult("skipped", None, "", ""),
        systemctl_results=[],
        performed_side_effects=False,
    )
    assert validate_calls == []
    assert systemctl_calls == []


def test_apply_validated_xray_tun_start_blocks_systemctl_when_validation_fails():
    systemctl_calls = []

    result = apply_validated_xray_tun_start(
        "/etc/migate/xray/config.json",
        yes=True,
        allow_system_changes=True,
        validator=lambda path: XrayValidationResult("invalid", 1, "", "bad tun config"),
        systemctl_runner=lambda action: systemctl_calls.append(action) or SystemctlActionResult(
            "success", action, ALLOWED_XRAY_TUN_SERVICE_NAME, [], 0, "", "", True
        ),
    )

    assert result.status == "invalid_config"
    assert result.message == "xray tun config validation failed; systemctl actions skipped"
    assert result.validation.status == "invalid"
    assert result.systemctl_results == []
    assert result.performed_side_effects is False
    assert systemctl_calls == []


def test_apply_validated_xray_tun_start_runs_daemon_reload_then_start_after_valid_config():
    actions = []

    def systemctl_runner(action):
        actions.append(action)
        return SystemctlActionResult(
            status="success",
            action=action,
            service=ALLOWED_XRAY_TUN_SERVICE_NAME,
            command=["systemctl", action, ALLOWED_XRAY_TUN_SERVICE_NAME] if action != "daemon-reload" else ["systemctl", "daemon-reload"],
            returncode=0,
            stdout=f"{action} ok",
            stderr="",
            performed_side_effects=True,
        )

    result = apply_validated_xray_tun_start(
        "/etc/migate/xray/config.json",
        yes=True,
        allow_system_changes=True,
        validator=lambda path: XrayValidationResult("valid", 0, "config ok", ""),
        systemctl_runner=systemctl_runner,
    )

    assert result == XrayApplyResult(
        status="success",
        message="xray tun config validated and service started",
        config_path="/etc/migate/xray/config.json",
        validation=XrayValidationResult("valid", 0, "config ok", ""),
        systemctl_results=[
            SystemctlActionResult("success", "daemon-reload", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "daemon-reload"], 0, "daemon-reload ok", "", True),
            SystemctlActionResult("success", "start", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME], 0, "start ok", "", True),
        ],
        performed_side_effects=True,
    )
    assert actions == ["daemon-reload", "start"]


def test_apply_validated_xray_tun_start_stops_after_start_failure():
    actions = []

    def systemctl_runner(action):
        actions.append(action)
        status = "failed" if action == "start" else "success"
        return SystemctlActionResult(
            status=status,
            action=action,
            service=ALLOWED_XRAY_TUN_SERVICE_NAME,
            command=["systemctl", action],
            returncode=1 if action == "start" else 0,
            stdout="",
            stderr="start failed" if action == "start" else "",
            performed_side_effects=True,
        )

    result = apply_validated_xray_tun_start(
        "/etc/migate/xray/config.json",
        yes=True,
        allow_system_changes=True,
        validator=lambda path: XrayValidationResult("valid", 0, "ok", ""),
        systemctl_runner=systemctl_runner,
    )

    assert result.status == "systemctl_failed"
    assert result.message == "xray tun start failed"
    assert [item.action for item in result.systemctl_results] == ["daemon-reload", "start"]
    assert result.performed_side_effects is True
    assert actions == ["daemon-reload", "start"]
