import subprocess

from migate.systemd.manager import SystemdResult, daemon_reload, restart_service, service_status


class FakeRunner:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def __call__(self, args, capture_output, text, check):
        self.calls.append(
            {
                "args": args,
                "capture_output": capture_output,
                "text": text,
                "check": check,
            }
        )
        if self.error:
            raise self.error
        return self.result


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=["systemctl"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_daemon_reload_runs_systemctl_daemon_reload():
    runner = FakeRunner(completed(stdout="ok"))

    result = daemon_reload(runner=runner)

    assert isinstance(result, SystemdResult)
    assert result.status == "success"
    assert result.returncode == 0
    assert result.stdout == "ok"
    assert runner.calls[0]["args"] == ["systemctl", "daemon-reload"]
    assert runner.calls[0]["capture_output"] is True
    assert runner.calls[0]["text"] is True
    assert runner.calls[0]["check"] is False


def test_restart_service_returns_failed_with_stderr_when_systemctl_fails():
    runner = FakeRunner(completed(returncode=1, stderr="unit failed"))

    result = restart_service("migate-xray.service", runner=runner)

    assert result.status == "failed"
    assert result.returncode == 1
    assert result.stderr == "unit failed"
    assert runner.calls[0]["args"] == ["systemctl", "restart", "migate-xray.service"]


def test_service_status_returns_success_output():
    runner = FakeRunner(completed(stdout="active (running)"))

    result = service_status("migate-panel.service", runner=runner)

    assert result.status == "success"
    assert result.stdout == "active (running)"
    assert runner.calls[0]["args"] == ["systemctl", "status", "migate-panel.service", "--no-pager"]


def test_systemctl_not_found_is_reported_without_exception():
    runner = FakeRunner(error=FileNotFoundError("missing systemctl"))

    result = daemon_reload(runner=runner)

    assert result.status == "systemctl_not_found"
    assert result.returncode is None
    assert "systemctl command not found" in result.stderr


def test_service_name_must_be_migate_scoped():
    runner = FakeRunner(completed(stdout="should not run"))

    result = restart_service("ssh.service", runner=runner)

    assert result.status == "rejected"
    assert result.returncode is None
    assert "unsupported service" in result.stderr
    assert runner.calls == []
