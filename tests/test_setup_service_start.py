import subprocess

import pytest

from migate.setup_service_start import run_setup_service_start


class FakeCompletedProcess:
    def __init__(self, args, returncode=0, stdout="", stderr=""):
        self.args = args
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_setup_service_start_runs_daemon_reload_then_enables_services():
    calls = []

    def runner(command):
        calls.append(command)
        return FakeCompletedProcess(command, returncode=0, stdout="ok", stderr="")

    result = run_setup_service_start(yes=True, allow_system_changes=True, runner=runner)

    assert result.status == "success"
    assert result.message == "MiGate services enabled and started"
    assert calls == [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", "migate-xray.service"],
        ["systemctl", "enable", "--now", "migate-proxy.service"],
        ["systemctl", "is-active", "migate-xray.service"],
        ["systemctl", "is-active", "migate-proxy.service"],
        ["systemctl", "is-active", "migate-xray.service"],
        ["systemctl", "is-active", "migate-proxy.service"],
    ]
    assert result.commands_executed == calls
    assert [step.name for step in result.steps] == [
        "daemon_reload",
        "enable_xray_service",
        "enable_proxy_service",
        "check_xray_active",
        "check_proxy_active",
        "verify_xray_stable",
        "verify_proxy_stable",
    ]
    assert [step.status for step in result.steps] == ["success", "success", "success", "success", "success", "success", "success"]
    assert result.performed_side_effects is True


def test_run_setup_service_start_checks_services_are_active_after_enable_now():
    calls = []

    def runner(command):
        calls.append(command)
        if command == ["systemctl", "is-active", "migate-xray.service"]:
            return FakeCompletedProcess(command, returncode=3, stdout="activating\n", stderr="")
        return FakeCompletedProcess(command, returncode=0, stdout="ok", stderr="")

    result = run_setup_service_start(yes=True, allow_system_changes=True, runner=runner)

    assert result.status == "failed"
    assert result.message == "service start failed at check_xray_active"
    assert calls == [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", "migate-xray.service"],
        ["systemctl", "enable", "--now", "migate-proxy.service"],
        ["systemctl", "is-active", "migate-xray.service"],
    ]
    assert result.steps[-1].name == "check_xray_active"
    assert result.steps[-1].status == "failed"
    assert result.steps[-1].stdout == "activating\n"
    assert result.steps[-1].performed_side_effects is False
    assert result.performed_side_effects is True


def test_run_setup_service_start_verifies_services_stay_active_after_initial_success(monkeypatch):
    calls = []
    xray_active_checks = 0
    proxy_active_checks = 0

    def runner(command):
        nonlocal xray_active_checks, proxy_active_checks
        calls.append(command)
        if command == ["systemctl", "is-active", "migate-xray.service"]:
            xray_active_checks += 1
            return FakeCompletedProcess(command, returncode=0, stdout="active\n", stderr="")
        if command == ["systemctl", "is-active", "migate-proxy.service"]:
            proxy_active_checks += 1
            if proxy_active_checks == 2:
                return FakeCompletedProcess(command, returncode=3, stdout="activating\n", stderr="")
            return FakeCompletedProcess(command, returncode=0, stdout="active\n", stderr="")
        return FakeCompletedProcess(command, returncode=0, stdout="ok", stderr="")

    sleeps = []
    monkeypatch.setattr("migate.setup_service_start.time.sleep", sleeps.append)

    result = run_setup_service_start(yes=True, allow_system_changes=True, runner=runner)

    assert sleeps == [pytest.approx(1.0)]
    assert result.status == "failed"
    assert result.message == "service start failed at verify_proxy_stable"
    assert calls[-2:] == [
        ["systemctl", "is-active", "migate-xray.service"],
        ["systemctl", "is-active", "migate-proxy.service"],
    ]
    assert xray_active_checks == 2
    assert proxy_active_checks == 2
    assert result.steps[-1].name == "verify_proxy_stable"
    assert result.steps[-1].status == "failed"
    assert result.steps[-1].stdout == "activating\n"
    assert result.steps[-1].performed_side_effects is False
    assert result.performed_side_effects is True


def test_run_setup_service_start_rejects_without_double_gate():
    calls = []

    result = run_setup_service_start(yes=True, allow_system_changes=False, runner=lambda command: calls.append(command))

    assert result.status == "rejected"
    assert result.message == "service start requires yes=True and allow_system_changes=True"
    assert result.commands_executed == []
    assert result.steps == []
    assert result.performed_side_effects is False
    assert calls == []


def test_run_setup_service_start_stops_on_failed_daemon_reload():
    calls = []

    def runner(command):
        calls.append(command)
        return FakeCompletedProcess(command, returncode=1, stdout="", stderr="reload failed")

    result = run_setup_service_start(yes=True, allow_system_changes=True, runner=runner)

    assert result.status == "failed"
    assert result.message == "service start failed at daemon_reload"
    assert calls == [["systemctl", "daemon-reload"]]
    assert result.commands_executed == calls
    assert len(result.steps) == 1
    assert result.steps[0].name == "daemon_reload"
    assert result.steps[0].status == "failed"
    assert result.steps[0].stderr == "reload failed"
    assert result.performed_side_effects is True


def test_run_setup_service_start_reports_missing_systemctl():
    def runner(command):
        raise FileNotFoundError

    result = run_setup_service_start(yes=True, allow_system_changes=True, runner=runner)

    assert result.status == "systemctl_not_found"
    assert result.message == "service start failed at daemon_reload"
    assert result.steps[0].status == "systemctl_not_found"
    assert result.steps[0].stderr == "systemctl command not found"
    assert result.performed_side_effects is False


def test_run_setup_service_start_reports_timeout():
    def runner(command):
        raise subprocess.TimeoutExpired(command, timeout=15, output="partial", stderr="hung")

    result = run_setup_service_start(yes=True, allow_system_changes=True, runner=runner)

    assert result.status == "timeout"
    assert result.message == "service start failed at daemon_reload"
    assert result.steps[0].status == "timeout"
    assert result.steps[0].stdout == "partial"
    assert "systemctl command timed out after 15s" in result.steps[0].stderr
    assert "hung" in result.steps[0].stderr
    assert result.performed_side_effects is True
