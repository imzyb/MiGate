import subprocess

from migate.xray.systemctl_cli import (
    ALLOWED_XRAY_SERVICE_NAME,
    ALLOWED_XRAY_TUN_SERVICE_NAME,
    SystemctlActionResult,
    run_xray_systemctl_action,
)


def test_run_xray_systemctl_status_allows_read_without_double_gate():
    calls = []

    def runner(args):
        calls.append(args)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="active", stderr="")

    result = run_xray_systemctl_action("status", service=ALLOWED_XRAY_SERVICE_NAME, runner=runner)

    assert result == SystemctlActionResult(
        status="success",
        action="status",
        service=ALLOWED_XRAY_SERVICE_NAME,
        command=["systemctl", "status", ALLOWED_XRAY_SERVICE_NAME, "--no-pager"],
        returncode=0,
        stdout="active",
        stderr="",
        performed_side_effects=False,
    )
    assert calls == [["systemctl", "status", ALLOWED_XRAY_SERVICE_NAME, "--no-pager"]]


def test_run_xray_systemctl_status_allows_xray_tun_service_read_without_double_gate():
    calls = []

    def runner(args):
        calls.append(args)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="tun active", stderr="")

    result = run_xray_systemctl_action("status", service=ALLOWED_XRAY_TUN_SERVICE_NAME, runner=runner)

    assert result == SystemctlActionResult(
        status="success",
        action="status",
        service=ALLOWED_XRAY_TUN_SERVICE_NAME,
        command=["systemctl", "status", ALLOWED_XRAY_TUN_SERVICE_NAME, "--no-pager"],
        returncode=0,
        stdout="tun active",
        stderr="",
        performed_side_effects=False,
    )
    assert calls == [["systemctl", "status", ALLOWED_XRAY_TUN_SERVICE_NAME, "--no-pager"]]


def test_run_xray_systemctl_start_stop_for_xray_tun_require_double_gate():
    calls = []

    def runner(args):
        calls.append(args)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="ok", stderr="")

    for action in ("start", "stop"):
        result = run_xray_systemctl_action(action, service=ALLOWED_XRAY_TUN_SERVICE_NAME, runner=runner)

        assert result.status == "rejected"
        assert result.action == action
        assert result.service == ALLOWED_XRAY_TUN_SERVICE_NAME
        assert result.returncode is None
        assert result.performed_side_effects is False
        assert "allow_system_changes" in result.stderr
    assert calls == []


def test_run_xray_systemctl_start_stop_for_xray_tun_run_when_double_gated():
    calls = []

    def runner(args):
        calls.append(args)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="ok", stderr="")

    start_result = run_xray_systemctl_action(
        "start",
        service=ALLOWED_XRAY_TUN_SERVICE_NAME,
        yes=True,
        allow_system_changes=True,
        runner=runner,
    )
    stop_result = run_xray_systemctl_action(
        "stop",
        service=ALLOWED_XRAY_TUN_SERVICE_NAME,
        yes=True,
        allow_system_changes=True,
        runner=runner,
    )

    assert start_result.status == "success"
    assert start_result.command == ["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME]
    assert start_result.performed_side_effects is True
    assert stop_result.status == "success"
    assert stop_result.command == ["systemctl", "stop", ALLOWED_XRAY_TUN_SERVICE_NAME]
    assert stop_result.performed_side_effects is True
    assert calls == [
        ["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME],
        ["systemctl", "stop", ALLOWED_XRAY_TUN_SERVICE_NAME],
    ]


def test_run_xray_systemctl_restart_requires_double_gate():
    calls = []

    def runner(args):
        calls.append(args)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="ok", stderr="")

    result = run_xray_systemctl_action("restart", service=ALLOWED_XRAY_SERVICE_NAME, runner=runner)

    assert result.status == "rejected"
    assert result.action == "restart"
    assert result.service == ALLOWED_XRAY_SERVICE_NAME
    assert result.returncode is None
    assert result.performed_side_effects is False
    assert "allow_system_changes" in result.stderr
    assert calls == []


def test_run_xray_systemctl_daemon_reload_requires_double_gate():
    calls = []

    def runner(args):
        calls.append(args)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="ok", stderr="")

    result = run_xray_systemctl_action("daemon-reload", service=ALLOWED_XRAY_SERVICE_NAME, runner=runner)

    assert result.status == "rejected"
    assert result.action == "daemon-reload"
    assert result.performed_side_effects is False
    assert calls == []


def test_run_xray_systemctl_rejects_unknown_service():
    result = run_xray_systemctl_action("status", service="nginx.service")

    assert result.status == "rejected"
    assert result.service == "nginx.service"
    assert result.returncode is None
    assert result.performed_side_effects is False
    assert "unsupported service" in result.stderr


def test_run_xray_systemctl_maps_file_not_found_to_systemctl_not_found():
    def runner(args):
        raise FileNotFoundError("systemctl missing")

    result = run_xray_systemctl_action("status", service=ALLOWED_XRAY_SERVICE_NAME, runner=runner)

    assert result.status == "systemctl_not_found"
    assert result.returncode is None
    assert result.stdout == ""
    assert result.stderr == "systemctl command not found"
    assert result.performed_side_effects is False


def test_run_xray_systemctl_maps_timeout_to_failed_result():
    command = ["systemctl", "stop", ALLOWED_XRAY_TUN_SERVICE_NAME]

    def runner(args):
        raise subprocess.TimeoutExpired(cmd=args, timeout=15, output="partial out", stderr="partial err")

    result = run_xray_systemctl_action(
        "stop",
        service=ALLOWED_XRAY_TUN_SERVICE_NAME,
        yes=True,
        allow_system_changes=True,
        runner=runner,
    )

    assert result == SystemctlActionResult(
        status="timeout",
        action="stop",
        service=ALLOWED_XRAY_TUN_SERVICE_NAME,
        command=command,
        returncode=None,
        stdout="partial out",
        stderr="systemctl stop timed out after 15s\npartial err",
        performed_side_effects=True,
    )


def test_run_xray_systemctl_preserves_failure_stdout_stderr_and_returncode():
    def runner(args):
        return subprocess.CompletedProcess(args=args, returncode=5, stdout="partial", stderr="access denied")

    result = run_xray_systemctl_action(
        "restart",
        service=ALLOWED_XRAY_SERVICE_NAME,
        yes=True,
        allow_system_changes=True,
        runner=runner,
    )

    assert result.status == "failed"
    assert result.returncode == 5
    assert result.stdout == "partial"
    assert result.stderr == "access denied"
    assert result.performed_side_effects is True
