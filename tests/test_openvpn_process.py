from dataclasses import dataclass

from migate.proxy.runtime import OpenVPNProcessStatus, TunnelProcessStatus, detect_openvpn_process, detect_tunnel_process
from migate.xray.systemctl_cli import ALLOWED_XRAY_TUN_SERVICE_NAME


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


def test_detect_tunnel_process_uses_xray_tun_systemctl_status_probe():
    calls = []

    def runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return FakeCommandResult(returncode=0, stdout="active\n", stderr="")

    status = detect_tunnel_process("xray-tun", "tun-migate", runner=runner)

    assert status == TunnelProcessStatus(
        backend="xray-tun",
        status="running",
        message="xray-tun tunnel for tun-migate is running",
        command=["systemctl", "status", ALLOWED_XRAY_TUN_SERVICE_NAME, "--no-pager"],
        returncode=0,
        stdout="active",
        stderr="",
        performed_side_effects=False,
    )
    assert calls == [["systemctl", "status", ALLOWED_XRAY_TUN_SERVICE_NAME, "--no-pager"]]


def test_detect_tunnel_process_keeps_generic_pgrep_probe_for_non_xray_tun_backends():
    calls = []

    def runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return FakeCommandResult(returncode=0, stdout="5678\n", stderr="")

    status = detect_tunnel_process("wireguard", "tun-migate", runner=runner)

    assert status == TunnelProcessStatus(
        backend="wireguard",
        status="running",
        message="wireguard tunnel for tun-migate is running",
        command=["pgrep", "-f", "wireguard.*tun-migate"],
        returncode=0,
        stdout="5678",
        stderr="",
        performed_side_effects=False,
    )
    assert calls == [["pgrep", "-f", "wireguard.*tun-migate"]]
