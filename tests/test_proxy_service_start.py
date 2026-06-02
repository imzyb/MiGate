import subprocess

import migate.proxy.service_start as service_start_module
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
    assert result.preflight_checks == [ProxyRuntimeCheck("tun_interface", "fail", "tun0 missing")]
    assert result.systemctl_results == []
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == ["preflight"]


def test_run_proxy_service_start_passes_backend_to_default_preflight_runner(monkeypatch):
    seen: list[str | None] = []

    def fake_doctor(config=None, **_kwargs):
        seen.append(None if config is None else config.egress.backend)
        return ProxyRuntimeReport(status="ok", checks=[], performed_side_effects=False)

    monkeypatch.setattr(service_start_module, "run_proxy_doctor", fake_doctor)

    result = run_proxy_service_start(
        yes=True,
        allow_system_changes=True,
        backend="xray-tun",
        runner=lambda command: subprocess.CompletedProcess(command, 0, stdout="active\n" if "is-active" in command else "", stderr=""),
    )

    assert result.status == "success"
    assert seen == ["xray-tun"]


def test_run_proxy_service_start_xray_tun_does_not_require_proxy_listener_ports_before_start(monkeypatch):
    seen = []

    def fake_doctor(config=None, **_kwargs):
        seen.append(None if config is None else config.egress.backend)
        return ProxyRuntimeReport(
            status="failed",
            checks=[
                ProxyRuntimeCheck("socks_listen", "failed", "127.0.0.1:34501 is not listening"),
                ProxyRuntimeCheck("http_listen", "failed", "127.0.0.1:34502 is not listening"),
                ProxyRuntimeCheck("tun_interface", "ok", "tun-migate interface exists"),
                ProxyRuntimeCheck("fail_policy", "ok", "fail_policy is block"),
                ProxyRuntimeCheck("leak_guard", "ok", "leak_guard is enabled"),
                ProxyRuntimeCheck("tunnel_process", "ok", "xray-tun tunnel for tun-migate is running"),
                ProxyRuntimeCheck("egress_guard", "failed", "required upstream proxy 127.0.0.1:34501 is unavailable; egress blocked"),
            ],
            performed_side_effects=False,
        )

    monkeypatch.setattr(service_start_module, "run_proxy_doctor", fake_doctor)

    result = run_proxy_service_start(
        yes=True,
        allow_system_changes=True,
        backend="xray-tun",
        runner=lambda command: subprocess.CompletedProcess(command, 0, stdout="active\n" if "is-active" in command else "", stderr=""),
    )

    assert result.status == "success"
    assert result.preflight_status == "ok"
    assert seen == ["xray-tun"]
    assert [step.name for step in result.systemctl_results] == ["daemon_reload", "enable_proxy_service", "verify_proxy_active"]


def test_run_proxy_service_start_xray_tun_defers_egress_guard_public_ip_verification(monkeypatch):
    def fake_doctor(config=None, **_kwargs):
        return ProxyRuntimeReport(
            status="failed",
            checks=[
                ProxyRuntimeCheck("socks_listen", "ok", "127.0.0.1:34501 is listening"),
                ProxyRuntimeCheck("http_listen", "failed", "127.0.0.1:34502 is not listening"),
                ProxyRuntimeCheck("tun_interface", "ok", "tun-migate interface exists"),
                ProxyRuntimeCheck("fail_policy", "ok", "fail_policy is block"),
                ProxyRuntimeCheck("leak_guard", "ok", "leak_guard is enabled"),
                ProxyRuntimeCheck("tunnel_process", "ok", "xray-tun tunnel for tun-migate is running"),
                ProxyRuntimeCheck("egress_guard", "failed", "egress public IP could not be verified; egress blocked"),
            ],
            performed_side_effects=False,
        )

    monkeypatch.setattr(service_start_module, "run_proxy_doctor", fake_doctor)

    result = run_proxy_service_start(
        yes=True,
        allow_system_changes=True,
        backend="xray-tun",
        runner=lambda command: subprocess.CompletedProcess(command, 0, stdout="active\n" if "is-active" in command else "", stderr=""),
    )

    assert result.status == "success"
    assert result.preflight_status == "ok"
    assert [step.name for step in result.systemctl_results] == ["daemon_reload", "enable_proxy_service", "verify_proxy_active"]


def test_run_proxy_service_start_xray_tun_still_blocks_when_tunnel_prerequisites_fail(monkeypatch):
    def fake_doctor(config=None, **_kwargs):
        return ProxyRuntimeReport(
            status="failed",
            checks=[
                ProxyRuntimeCheck("socks_listen", "failed", "127.0.0.1:34501 is not listening"),
                ProxyRuntimeCheck("tun_interface", "failed", "tun-migate interface is missing"),
                ProxyRuntimeCheck("fail_policy", "ok", "fail_policy is block"),
                ProxyRuntimeCheck("leak_guard", "ok", "leak_guard is enabled"),
                ProxyRuntimeCheck("tunnel_process", "failed", "xray-tun tunnel for tun-migate is not running"),
                ProxyRuntimeCheck("egress_guard", "failed", "tun-migate interface is missing; egress blocked"),
            ],
            performed_side_effects=False,
        )

    monkeypatch.setattr(service_start_module, "run_proxy_doctor", fake_doctor)

    result = run_proxy_service_start(
        yes=True,
        allow_system_changes=True,
        backend="xray-tun",
        runner=lambda command: subprocess.CompletedProcess(command, 0, stdout="", stderr=""),
    )

    assert result.status == "preflight_failed"
    assert result.commands_executed == []
    assert result.performed_side_effects is False


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
