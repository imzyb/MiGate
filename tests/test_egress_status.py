from migate.config import MiGateConfig
from migate.egress.status import EgressStatusCheck, EgressStatusReport, render_egress_status_report, run_egress_doctor, run_egress_status


class FakeCommandResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_egress_doctor_fails_closed_when_tun_missing_and_openvpn_not_running():
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
            EgressStatusCheck("openvpn_process", "failed", "OpenVPN process for tun-migate is not running"),
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
        "openvpn_process",
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
