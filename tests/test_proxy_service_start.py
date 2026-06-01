import subprocess

from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport
from migate.proxy.service_start import run_proxy_service_start


def test_run_proxy_service_start_rejects_without_double_gate_and_skips_preflight_and_systemctl():
    calls = []

    result = run_proxy_service_start(
        yes=True,
        allow_system_changes=False,
        preflight_runner=lambda: calls.append("preflight"),
        runner=lambda command: calls.append(command),
    )

    assert result.status == "rejected"
    assert result.message == "proxy service start requires yes=True and allow_system_changes=True"
    assert result.preflight_status == "skipped"
    assert result.systemctl_results == []
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []


def test_run_proxy_service_start_rejects_when_preflight_is_not_ok_and_skips_systemctl():
    calls = []

    def preflight():
        calls.append("preflight")
        return ProxyRuntimeReport(
            status="blocked",
            checks=[ProxyRuntimeCheck("tun_interface", "fail", "tun0 missing")],
            performed_side_effects=False,
        )

    result = run_proxy_service_start(
        yes=True,
        allow_system_changes=True,
        preflight_runner=preflight,
        runner=lambda command: calls.append(command),
    )

    assert result.status == "preflight_failed"
    assert result.message == "proxy service start blocked by preflight: blocked"
    assert result.preflight_status == "blocked"
    assert result.systemctl_results == []
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == ["preflight"]


def test_run_proxy_service_start_runs_daemon_reload_enable_and_verify_when_preflight_ok():
    calls = []

    def runner(command):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="active\n" if "is-active" in command else "", stderr="")

    result = run_proxy_service_start(
        yes=True,
        allow_system_changes=True,
        preflight_runner=lambda: ProxyRuntimeReport(status="ok", checks=[], performed_side_effects=False),
        runner=runner,
    )

    assert result.status == "success"
    assert result.message == "MiGate proxy service enabled and started"
    assert result.preflight_status == "ok"
    assert calls == [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", "migate-proxy.service"],
        ["systemctl", "is-active", "migate-proxy.service"],
    ]
    assert result.commands_executed == calls
    assert [step.name for step in result.systemctl_results] == ["daemon_reload", "enable_proxy_service", "verify_proxy_active"]
    assert [step.status for step in result.systemctl_results] == ["success", "success", "success"]
    assert result.performed_side_effects is True


def test_run_proxy_service_start_stops_when_daemon_reload_fails():
    calls = []

    def runner(command):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="reload failed")

    result = run_proxy_service_start(
        yes=True,
        allow_system_changes=True,
        preflight_runner=lambda: ProxyRuntimeReport(status="ok", checks=[], performed_side_effects=False),
        runner=runner,
    )

    assert result.status == "failed"
    assert result.message == "proxy service start failed at daemon_reload"
    assert calls == [["systemctl", "daemon-reload"]]
    assert result.performed_side_effects is False
    assert result.systemctl_results[0].stderr == "reload failed"


def test_run_proxy_service_start_fails_when_service_is_not_active_after_enable():
    calls = []

    def runner(command):
        calls.append(command)
        if "is-active" in command:
            return subprocess.CompletedProcess(command, 3, stdout="failed\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = run_proxy_service_start(
        yes=True,
        allow_system_changes=True,
        preflight_runner=lambda: ProxyRuntimeReport(status="ok", checks=[], performed_side_effects=False),
        runner=runner,
    )

    assert result.status == "failed"
    assert result.message == "proxy service start failed at verify_proxy_active"
    assert result.commands_executed == calls
    assert result.performed_side_effects is True
