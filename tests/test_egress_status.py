from migate.config import EgressConfig, MiGateConfig
from migate.egress.status import EgressStatusCheck, EgressStatusReport, render_egress_status_report, run_egress_doctor, run_egress_status
from migate.proxy.runtime import TunnelProcessStatus
from migate.xray.systemctl_cli import ALLOWED_XRAY_TUN_SERVICE_NAME


class FakeCommandResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_egress_doctor_fails_closed_when_tun_missing_and_tunnel_not_running():
    calls: list[list[str]] = []

    def fake_runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return FakeCommandResult(returncode=1)

    report = run_egress_doctor(
        MiGateConfig(),
        interface_exists=lambda name: False,
        command_runner=fake_runner,
    )

    assert calls == [["pgrep", "-f", "openvpn.*tun-migate"]]
    assert report == EgressStatusReport(
        status="failed",
        checks=[
            EgressStatusCheck("tun_interface", "failed", "tun-migate interface is missing"),
            EgressStatusCheck("tunnel_process", "failed", "openvpn tunnel for tun-migate is not running"),
            EgressStatusCheck("policy_routing_plan", "ok", "policy routing plan targets table 100 fwmark 0x66 via tun-migate"),
            EgressStatusCheck("egress_guard", "failed", "tun-migate interface is missing; egress blocked"),
        ],
        performed_side_effects=False,
    )


def test_egress_doctor_passes_when_interface_openvpn_and_guard_are_safe():
    report = run_egress_doctor(
        MiGateConfig(),
        interface_exists=lambda name: name == "tun-migate",
        command_runner=lambda argv: FakeCommandResult(returncode=0, stdout="1234\n"),
        native_public_ip="198.51.100.10",
        egress_public_ip="203.0.113.20",
    )

    assert report.status == "ok"
    assert report.performed_side_effects is False
    assert [check.name for check in report.checks] == [
        "tun_interface",
        "tunnel_process",
        "policy_routing_plan",
        "egress_guard",
    ]
    assert all(check.status == "ok" for check in report.checks)


def test_egress_status_is_observational_even_when_checks_fail():
    report = run_egress_status(
        MiGateConfig(),
        interface_exists=lambda name: False,
        command_runner=lambda argv: FakeCommandResult(returncode=1),
    )

    assert report.status == "observed"
    assert any(check.status == "failed" for check in report.checks)
    assert report.performed_side_effects is False


def test_egress_doctor_uses_backend_neutral_tunnel_process_check():
    config = MiGateConfig(egress=EgressConfig(backend="xray-tun"))
    calls: list[tuple[str, str]] = []

    def fake_tunnel_detector(backend: str, tun_interface: str) -> TunnelProcessStatus:
        calls.append((backend, tun_interface))
        return TunnelProcessStatus(
            backend=backend,
            status="stopped",
            message=f"{backend} tunnel for {tun_interface} is not running",
            command=["pgrep", "-f", "xray.*tun-migate"],
            returncode=1,
            stdout="",
            stderr="",
            performed_side_effects=False,
        )

    report = run_egress_doctor(
        config,
        interface_exists=lambda name: True,
        tunnel_process_detector=fake_tunnel_detector,
        native_public_ip="198.51.100.10",
        egress_public_ip="203.0.113.20",
    )

    assert calls == [("xray-tun", "tun-migate")]
    assert EgressStatusCheck(
        "tunnel_process",
        "failed",
        "xray-tun tunnel for tun-migate is not running",
    ) in report.checks
    assert "openvpn_process" not in [check.name for check in report.checks]
    assert next(check for check in report.checks if check.name == "egress_guard") == EgressStatusCheck(
        "egress_guard",
        "failed",
        "tunnel backend is not running; egress blocked",
    )


def test_egress_doctor_treats_tunnel_probe_errors_as_unknown_guard_state():
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

    report = run_egress_doctor(
        MiGateConfig(),
        interface_exists=lambda name: True,
        tunnel_process_detector=fake_tunnel_detector,
        native_public_ip="198.51.100.10",
        egress_public_ip="203.0.113.20",
    )

    assert EgressStatusCheck("tunnel_process", "failed", "openvpn tunnel probe failed for tun-migate") in report.checks
    assert EgressStatusCheck("egress_guard", "failed", "tunnel backend state is unknown; egress blocked") in report.checks
    assert report.status == "failed"
    assert report.performed_side_effects is False


def test_egress_doctor_xray_tun_default_detector_uses_read_only_systemctl_status():
    calls: list[list[str]] = []

    def fake_runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return FakeCommandResult(returncode=0, stdout="active\n")

    report = run_egress_doctor(
        MiGateConfig(egress=EgressConfig(backend="xray-tun")),
        interface_exists=lambda name: name == "tun-migate",
        command_runner=fake_runner,
        native_public_ip="198.51.100.10",
        egress_public_ip="203.0.113.20",
    )

    assert calls == [["systemctl", "status", ALLOWED_XRAY_TUN_SERVICE_NAME, "--no-pager"]]
    assert EgressStatusCheck("tunnel_process", "ok", "xray-tun tunnel for tun-migate is running") in report.checks
    assert report.performed_side_effects is False


def test_egress_doctor_xray_tun_reports_missing_upstream_socks_listener():
    config = MiGateConfig(egress=EgressConfig(backend="xray-tun"))
    calls: list[tuple[str, int]] = []

    report = run_egress_doctor(
        config,
        interface_exists=lambda name: True,
        command_runner=lambda argv: FakeCommandResult(returncode=0, stdout="active\n"),
        upstream_proxy_connectable=lambda host, port: calls.append((host, port)) or False,
        native_public_ip="198.51.100.10",
        egress_public_ip="203.0.113.20",
    )

    assert calls == [("127.0.0.1", 34501)]
    assert EgressStatusCheck(
        "upstream_proxy",
        "failed",
        "xray-tun upstream SOCKS proxy 127.0.0.1:34501 is not listening; egress blocked",
    ) in report.checks
    assert EgressStatusCheck(
        "egress_guard",
        "failed",
        "required upstream proxy 127.0.0.1:34501 is unavailable; egress blocked",
    ) in report.checks
    assert report.status == "failed"


def test_egress_doctor_xray_tun_treats_upstream_socks_probe_unknown_as_guard_unknown():
    config = MiGateConfig(egress=EgressConfig(backend="xray-tun"))

    report = run_egress_doctor(
        config,
        interface_exists=lambda name: True,
        command_runner=lambda argv: FakeCommandResult(returncode=0, stdout="active\n"),
        upstream_proxy_connectable=lambda host, port: None,
        native_public_ip="198.51.100.10",
        egress_public_ip="203.0.113.20",
    )

    assert EgressStatusCheck(
        "upstream_proxy",
        "failed",
        "xray-tun upstream SOCKS proxy 127.0.0.1:34501 state is unknown; egress blocked",
    ) in report.checks
    assert EgressStatusCheck(
        "egress_guard",
        "failed",
        "required upstream proxy 127.0.0.1:34501 state is unknown; egress blocked",
    ) in report.checks
    assert report.status == "failed"


def test_egress_doctor_detects_native_ip_leak():
    report = run_egress_doctor(
        MiGateConfig(),
        interface_exists=lambda name: True,
        command_runner=lambda argv: FakeCommandResult(returncode=0, stdout="1234\n"),
        native_public_ip="198.51.100.10",
        egress_public_ip="198.51.100.10",
    )

    guard = next(check for check in report.checks if check.name == "egress_guard")
    assert report.status == "failed"
    assert guard == EgressStatusCheck("egress_guard", "failed", "egress public IP matches native VPS public IP; egress blocked")


def test_render_egress_status_report_is_stable_for_cli_and_panel():
    report = EgressStatusReport(
        status="failed",
        checks=[
            EgressStatusCheck("tun_interface", "failed", "tun-migate interface is missing"),
            EgressStatusCheck("egress_guard", "failed", "tun-migate interface is missing; egress blocked"),
        ],
        performed_side_effects=False,
    )

    assert render_egress_status_report("Egress doctor", report) == (
        "Egress doctor\n"
        "status: failed\n"
        "tun_interface: failed - tun-migate interface is missing\n"
        "egress_guard: failed - tun-migate interface is missing; egress blocked\n"
        "performed_side_effects: False"
    )
