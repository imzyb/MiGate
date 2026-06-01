import subprocess

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
    ]
    assert result.commands_executed == calls
    assert [step.name for step in result.steps] == ["daemon_reload", "enable_xray_service", "enable_proxy_service"]
    assert [step.status for step in result.steps] == ["success", "success", "success"]
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
