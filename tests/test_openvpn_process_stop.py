from pathlib import Path

from migate.vpn.process_stop import (
    OpenVPNStopResult,
    OpenVPNStopStepResult,
    build_openvpn_stop_plan,
    read_openvpn_pid,
    run_openvpn_stop_plan,
)


class FakeCommandResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr



def test_read_openvpn_pid_returns_integer_from_trimmed_file(tmp_path: Path):
    pid_file = tmp_path / "openvpn.pid"
    pid_file.write_text(" 4321\n", encoding="utf-8")

    assert read_openvpn_pid(pid_file) == 4321


def test_read_openvpn_pid_returns_none_when_file_missing(tmp_path: Path):
    assert read_openvpn_pid(tmp_path / "missing.pid") is None


def test_run_openvpn_stop_plan_rejects_without_allow_side_effects(tmp_path: Path):
    pid_file = tmp_path / "openvpn.pid"
    pid_file.write_text("4321\n", encoding="utf-8")
    plan = build_openvpn_stop_plan(pid_file=pid_file, kill_signal="TERM")
    calls: list[list[str]] = []

    def runner(command: list[str]) -> FakeCommandResult:
        calls.append(command)
        return FakeCommandResult(returncode=0)

    result = run_openvpn_stop_plan(plan, runner=runner, allow_side_effects=False)

    assert result == OpenVPNStopResult(
        status="rejected",
        message="allow_side_effects must be true to stop OpenVPN",
        steps=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_run_openvpn_stop_plan_executes_kill_when_allowed(tmp_path: Path):
    pid_file = tmp_path / "openvpn.pid"
    pid_file.write_text("4321\n", encoding="utf-8")
    plan = build_openvpn_stop_plan(pid_file=pid_file, kill_signal="TERM")
    calls: list[list[str]] = []

    def runner(command: list[str]) -> FakeCommandResult:
        calls.append(command)
        return FakeCommandResult(returncode=0, stdout="", stderr="")

    result = run_openvpn_stop_plan(plan, runner=runner, allow_side_effects=True)

    assert result.status == "stopped"
    assert result.performed_side_effects is True
    assert result.commands_executed == ["kill -TERM 4321"]
    assert result.steps == [
        OpenVPNStopStepResult(
            action="stop_openvpn_process",
            status="success",
            command=["kill", "-TERM", "4321"],
            returncode=0,
            stdout="",
            stderr="",
        )
    ]
    assert calls == [["kill", "-TERM", "4321"]]


def test_run_openvpn_stop_plan_reports_missing_pid_file_as_failed(tmp_path: Path):
    plan = build_openvpn_stop_plan(pid_file=tmp_path / "missing.pid", kill_signal="TERM")

    result = run_openvpn_stop_plan(plan, runner=lambda command: FakeCommandResult(returncode=0), allow_side_effects=True)

    assert result.status == "failed"
    assert result.message == "OpenVPN stop failed; pid file not found"
    assert result.steps == []
    assert result.commands_executed == []
