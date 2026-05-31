from migate.egress.tunnel_backend import (
    TunnelCommandResult,
    TunnelStartPlan,
    TunnelStopPlan,
    run_tunnel_start_plan,
    run_tunnel_stop_plan,
)


class FakeCommandResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_tunnel_start_plan_executes_backend_start_command_when_allowed():
    plan = TunnelStartPlan(
        backend="xray-tun",
        command=["xray", "run", "-config", "/etc/migate/xray-tun.json"],
        runtime_paths=["/etc/migate/xray-tun.json", "/var/log/migate/xray-tun.log"],
    )
    calls = []

    def runner(command: list[str]) -> FakeCommandResult:
        calls.append(command)
        return FakeCommandResult(0, stdout="started")

    result = run_tunnel_start_plan(plan, runner=runner, allow_side_effects=True)

    assert calls == [plan.command]
    assert result.status == "started"
    assert result.backend == "xray-tun"
    assert result.commands_executed == ["xray run -config /etc/migate/xray-tun.json"]
    assert result.performed_side_effects is True


def test_run_tunnel_start_plan_rejects_without_side_effect_gate():
    plan = TunnelStartPlan(backend="xray-tun", command=["xray", "run"], runtime_paths=[])
    calls = []

    result = run_tunnel_start_plan(plan, runner=lambda command: calls.append(command), allow_side_effects=False)

    assert result == TunnelCommandResult(
        backend="xray-tun",
        status="rejected",
        message="allow_side_effects must be true to start tunnel backend",
        command=["xray", "run"],
        returncode=None,
        stdout="",
        stderr="",
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_run_tunnel_start_plan_maps_nonzero_exit_to_failed():
    plan = TunnelStartPlan(backend="xray-tun", command=["xray", "run"], runtime_paths=[])

    result = run_tunnel_start_plan(
        plan,
        runner=lambda command: FakeCommandResult(23, stderr="bind failed"),
        allow_side_effects=True,
    )

    assert result.status == "failed"
    assert result.message == "tunnel backend start command failed: xray run"
    assert result.returncode == 23
    assert result.stderr == "bind failed"
    assert result.performed_side_effects is True


def test_run_tunnel_stop_plan_executes_backend_stop_command_when_allowed():
    plan = TunnelStopPlan(backend="xray-tun", command=["systemctl", "stop", "migate-xray-tun.service"])
    calls = []

    result = run_tunnel_stop_plan(
        plan,
        runner=lambda command: calls.append(command) or FakeCommandResult(0, stdout="stopped"),
        allow_side_effects=True,
    )

    assert calls == [plan.command]
    assert result.status == "stopped"
    assert result.backend == "xray-tun"
    assert result.commands_executed == ["systemctl stop migate-xray-tun.service"]
    assert result.performed_side_effects is True
