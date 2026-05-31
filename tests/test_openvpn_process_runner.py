from migate.vpn.process_plan import OpenVPNStartPlan
from migate.vpn.process_runner import OpenVPNStartResult, OpenVPNStartStepResult, run_openvpn_start_plan


class FakeCommandResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


PLAN = OpenVPNStartPlan(
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
        "--daemon",
        "migate-openvpn",
    ],
    performs_side_effects=False,
)


def test_run_openvpn_start_plan_rejects_without_allow_side_effects():
    calls: list[list[str]] = []

    def runner(command: list[str]) -> FakeCommandResult:
        calls.append(command)
        return FakeCommandResult(returncode=0)

    result = run_openvpn_start_plan(PLAN, runner=runner, allow_side_effects=False)

    assert result == OpenVPNStartResult(
        status="rejected",
        message="allow_side_effects must be true to run OpenVPN start commands",
        steps=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_run_openvpn_start_plan_executes_injected_runner_when_allowed():
    calls: list[list[str]] = []

    def runner(command: list[str]) -> FakeCommandResult:
        calls.append(command)
        return FakeCommandResult(returncode=0, stdout="started", stderr="")

    result = run_openvpn_start_plan(PLAN, runner=runner, allow_side_effects=True)

    assert isinstance(result, OpenVPNStartResult)
    assert result.status == "started"
    assert result.performed_side_effects is True
    assert result.commands_executed == [" ".join(PLAN.command)]
    assert result.steps == [
        OpenVPNStartStepResult(
            action="start_openvpn_process",
            status="success",
            command=PLAN.command,
            returncode=0,
            stdout="started",
            stderr="",
        )
    ]
    assert calls == [PLAN.command]


def test_run_openvpn_start_plan_reports_command_not_found_without_crashing():
    def runner(command: list[str]) -> FakeCommandResult:
        raise FileNotFoundError(command[0])

    result = run_openvpn_start_plan(PLAN, runner=runner, allow_side_effects=True)

    assert result.status == "failed"
    assert result.message == "OpenVPN start failed; command not found: openvpn"
    assert result.performed_side_effects is True
    assert result.steps == [
        OpenVPNStartStepResult(
            action="start_openvpn_process",
            status="command_not_found",
            command=PLAN.command,
            returncode=None,
            stdout="",
            stderr="command not found: openvpn",
        )
    ]
