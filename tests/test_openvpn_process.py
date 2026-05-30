from dataclasses import dataclass

from migate.proxy.runtime import OpenVPNProcessStatus, detect_openvpn_process


@dataclass(frozen=True)
class FakeCommandResult:
    returncode: int
    stdout: str
    stderr: str


def test_detect_openvpn_process_reports_running_when_pgrep_finds_tun_interface():
    calls = []

    def runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return FakeCommandResult(returncode=0, stdout="1234\n", stderr="")

    status = detect_openvpn_process("tun-migate", runner=runner)

    assert status == OpenVPNProcessStatus(
        status="running",
        message="OpenVPN process for tun-migate is running",
        command=["pgrep", "-f", "openvpn.*tun-migate"],
        returncode=0,
        stdout="1234",
        stderr="",
        performed_side_effects=False,
    )
    assert calls == [["pgrep", "-f", "openvpn.*tun-migate"]]


def test_detect_openvpn_process_reports_stopped_when_pgrep_returns_1():
    status = detect_openvpn_process(
        "tun-migate",
        runner=lambda argv: FakeCommandResult(returncode=1, stdout="", stderr=""),
    )

    assert status.status == "stopped"
    assert status.message == "OpenVPN process for tun-migate is not running"
    assert status.returncode == 1
    assert status.performed_side_effects is False


def test_detect_openvpn_process_reports_probe_error_on_unexpected_failure():
    status = detect_openvpn_process(
        "tun-migate",
        runner=lambda argv: FakeCommandResult(returncode=2, stdout="", stderr="permission denied"),
    )

    assert status.status == "error"
    assert status.message == "OpenVPN process probe failed for tun-migate"
    assert status.stderr == "permission denied"
    assert status.performed_side_effects is False
