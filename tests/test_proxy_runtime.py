from migate.config import MiGateConfig
from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport, TunnelProcessStatus, render_proxy_runtime_report, run_proxy_doctor, run_proxy_status


def test_proxy_doctor_reports_ports_tun_and_leak_policy_without_side_effects():
    config = MiGateConfig()
    checked_ports = []
    checked_interfaces = []

    def port_listening(host: str, port: int) -> bool:
        checked_ports.append((host, port))
        return port == config.proxy.socks_port

    def interface_exists(name: str) -> bool:
        checked_interfaces.append(name)
        return False

    report = run_proxy_doctor(
        config,
        port_listening=port_listening,
        interface_exists=interface_exists,
        tunnel_running=lambda: False,
    )

    assert report == ProxyRuntimeReport(
        status="failed",
        checks=[
            ProxyRuntimeCheck("socks_listen", "ok", "127.0.0.1:34501 is listening"),
            ProxyRuntimeCheck("http_listen", "failed", "127.0.0.1:34502 is not listening"),
            ProxyRuntimeCheck("tun_interface", "failed", "tun-migate interface is missing"),
            ProxyRuntimeCheck("fail_policy", "ok", "fail_policy is block"),
            ProxyRuntimeCheck("leak_guard", "ok", "leak_guard is enabled"),
            ProxyRuntimeCheck("tunnel_process", "failed", "openvpn tunnel for tun-migate is not running"),
            ProxyRuntimeCheck("egress_guard", "failed", "tun-migate interface is missing; egress blocked"),
        ],
        performed_side_effects=False,
    )
    assert checked_ports == [("127.0.0.1", 34501), ("127.0.0.1", 34502)]
    assert checked_interfaces == ["tun-migate"]


def test_proxy_doctor_fails_when_leak_guard_is_disabled_or_fail_policy_allows_fallback():
    config = MiGateConfig()
    config.security.fail_policy = "direct"
    config.security.leak_guard = False

    report = run_proxy_doctor(
        config,
        port_listening=lambda host, port: True,
        interface_exists=lambda name: True,
        tunnel_running=lambda: False,
    )

    assert report.status == "failed"
    assert ProxyRuntimeCheck("fail_policy", "failed", "fail_policy is direct; expected block") in report.checks
    assert ProxyRuntimeCheck("leak_guard", "failed", "leak_guard is disabled") in report.checks


def test_proxy_status_is_observational_and_does_not_require_all_checks_to_pass():
    report = run_proxy_status(
        MiGateConfig(),
        port_listening=lambda host, port: False,
        interface_exists=lambda name: False,
        tunnel_running=lambda: False,
    )

    assert report.status == "observed"
    assert report.performed_side_effects is False
    assert any(check.name == "socks_listen" and check.status == "failed" for check in report.checks)


def test_proxy_doctor_reports_tunnel_process_and_egress_guard_decision_without_side_effects():
    config = MiGateConfig()

    report = run_proxy_doctor(
        config,
        port_listening=lambda host, port: True,
        interface_exists=lambda name: True,
        tunnel_running=lambda: False,
    )

    assert report.status == "failed"
    assert ProxyRuntimeCheck("tunnel_process", "failed", "openvpn tunnel for tun-migate is not running") in report.checks
    assert ProxyRuntimeCheck("egress_guard", "failed", "tunnel backend is not running; egress blocked") in report.checks
    assert report.performed_side_effects is False


def test_proxy_doctor_treats_tunnel_probe_errors_as_unknown_guard_state():
    def fake_tunnel_detector(backend: str, tun_interface: str) -> TunnelProcessStatus:
        return TunnelProcessStatus(
            backend=backend,
            status="error",
            message=f"{backend} tunnel probe failed for {tun_interface}",
            command=["pgrep", "-f", f"{backend}.*{tun_interface}"],
            returncode=2,
            stdout="",
            stderr="permission denied",
            performed_side_effects=False,
        )

    report = run_proxy_doctor(
        MiGateConfig(),
        port_listening=lambda host, port: True,
        interface_exists=lambda name: True,
        tunnel_process_detector=fake_tunnel_detector,
        native_public_ip="203.0.113.10",
        egress_public_ip="198.51.100.20",
    )

    assert ProxyRuntimeCheck("tunnel_process", "failed", "openvpn tunnel probe failed for tun-migate") in report.checks
    assert ProxyRuntimeCheck("egress_guard", "failed", "tunnel backend state is unknown; egress blocked") in report.checks
    assert report.status == "failed"
    assert report.performed_side_effects is False


def test_proxy_doctor_xray_tun_blocks_when_required_upstream_proxy_is_unavailable():
    config = MiGateConfig()
    config.egress.backend = "xray-tun"

    def fake_tunnel_detector(backend: str, tun_interface: str) -> TunnelProcessStatus:
        return TunnelProcessStatus(
            backend=backend,
            status="running",
            message=f"{backend} tunnel for {tun_interface} is running",
            command=["systemctl", "status", "migate-xray-tun.service", "--no-pager"],
            returncode=0,
            stdout="active",
            stderr="",
            performed_side_effects=False,
        )

    report = run_proxy_doctor(
        config,
        port_listening=lambda host, port: port != config.proxy.socks_port,
        interface_exists=lambda name: True,
        tunnel_process_detector=fake_tunnel_detector,
        native_public_ip="203.0.113.10",
        egress_public_ip="198.51.100.20",
    )

    assert ProxyRuntimeCheck(
        "egress_guard",
        "failed",
        "required upstream proxy 127.0.0.1:34501 is unavailable; egress blocked",
    ) in report.checks
    assert report.status == "failed"


def test_proxy_doctor_allows_egress_guard_when_tunnel_process_is_running():
    config = MiGateConfig()

    report = run_proxy_doctor(
        config,
        port_listening=lambda host, port: True,
        interface_exists=lambda name: True,
        tunnel_running=lambda: True,
        native_public_ip="203.0.113.10",
        egress_public_ip="198.51.100.20",
    )

    assert report.status == "ok"
    assert ProxyRuntimeCheck("tunnel_process", "ok", "openvpn tunnel for tun-migate is running") in report.checks
    assert ProxyRuntimeCheck("egress_guard", "ok", "egress guard checks passed") in report.checks
    assert report.performed_side_effects is False


def test_render_proxy_runtime_report_is_human_readable():
    report = ProxyRuntimeReport(
        status="failed",
        checks=[ProxyRuntimeCheck("socks_listen", "ok", "127.0.0.1:34501 is listening")],
        performed_side_effects=False,
    )

    rendered = render_proxy_runtime_report("Proxy doctor", report)

    assert "Proxy doctor" in rendered
    assert "status: failed" in rendered
    assert "socks_listen: ok - 127.0.0.1:34501 is listening" in rendered
    assert "performed_side_effects: False" in rendered
