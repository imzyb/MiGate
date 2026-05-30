from pathlib import Path

from migate.vpn.process_plan import OpenVPNStartPlan
from migate.vpn.process_restart import OpenVPNRestartResult, restart_openvpn
from migate.vpn.process_stop import OpenVPNStopPlan


class FakeCommandResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def make_start_plan() -> OpenVPNStartPlan:
    return OpenVPNStartPlan(
        openvpn_bin="openvpn",
        config_path="/var/lib/migate/runtime/active.ovpn",
        tun_interface="tun-migate",
        pid_path="/var/lib/migate/runtime/openvpn.pid",
        status_path="/var/lib/migate/runtime/status.json",
        log_path="/var/log/migate/openvpn.log",
        command=[
            "openvpn",
            "--config",
            "/var/lib/migate/runtime/active.ovpn",
            "--writepid",
            "/var/lib/migate/runtime/openvpn.pid",
            "--status",
            "/var/lib/migate/runtime/status.json",
            "--log-append",
            "/var/log/migate/openvpn.log",
        ],
        performs_side_effects=False,
    )


def test_restart_openvpn_rejects_without_allow_side_effects(tmp_path: Path):
    pid_file = tmp_path / "openvpn.pid"
    pid_file.write_text("4321\n", encoding="utf-8")
    stop_plan = OpenVPNStopPlan(pid_file=pid_file, kill_signal="TERM")
    start_plan = make_start_plan()
    calls: list[list[str]] = []

    def runner(command: list[str]) -> FakeCommandResult:
        calls.append(command)
        return FakeCommandResult(returncode=0)

    result = restart_openvpn(stop_plan, start_plan, runner=runner, allow_side_effects=False)

    assert result == OpenVPNRestartResult(
        status="rejected",
        message="allow_side_effects must be true to restart OpenVPN",
        stop_result=None,
        start_result=None,
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_restart_openvpn_runs_stop_then_start_when_allowed(tmp_path: Path):
    pid_file = tmp_path / "openvpn.pid"
    pid_file.write_text("4321\n", encoding="utf-8")
    stop_plan = OpenVPNStopPlan(pid_file=pid_file, kill_signal="TERM")
    start_plan = make_start_plan()
    calls: list[list[str]] = []

    def runner(command: list[str]) -> FakeCommandResult:
        calls.append(command)
        return FakeCommandResult(returncode=0)

    result = restart_openvpn(stop_plan, start_plan, runner=runner, allow_side_effects=True)

    assert result.status == "restarted"
    assert result.performed_side_effects is True
    assert result.stop_result is not None
    assert result.stop_result.status == "stopped"
    assert result.start_result is not None
    assert result.start_result.status == "started"
    assert result.commands_executed == ["kill -TERM 4321", " ".join(start_plan.command)]
    assert calls == [["kill", "-TERM", "4321"], start_plan.command]


def test_restart_openvpn_does_not_start_when_stop_fails(tmp_path: Path):
    stop_plan = OpenVPNStopPlan(pid_file=tmp_path / "missing.pid", kill_signal="TERM")
    start_plan = make_start_plan()
    calls: list[list[str]] = []

    def runner(command: list[str]) -> FakeCommandResult:
        calls.append(command)
        return FakeCommandResult(returncode=0)

    result = restart_openvpn(stop_plan, start_plan, runner=runner, allow_side_effects=True)

    assert result.status == "failed"
    assert result.message == "OpenVPN restart stopped before start; stop phase failed"
    assert result.stop_result is not None
    assert result.stop_result.status == "failed"
    assert result.start_result is None
    assert result.commands_executed == []
    assert calls == []
