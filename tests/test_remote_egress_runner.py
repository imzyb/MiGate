from migate.remote.egress_plan import build_remote_egress_dry_run_plan
from migate.remote.egress_runner import (
    RemoteEgressCommandResult,
    RemoteEgressRunResult,
    RemoteEgressStepResult,
    render_remote_egress_run_result,
    run_remote_egress_plan,
)


def _plan(action: str = "up"):
    return build_remote_egress_dry_run_plan(host="166.88.232.2", port=22, user="root", action=action)


def test_remote_egress_runner_defaults_to_dry_run_without_calling_runner():
    calls: list[str] = []

    result = run_remote_egress_plan(
        _plan("up"),
        dry_run=True,
        yes=False,
        allow_remote_changes=False,
        runner=lambda command: calls.append(command) or RemoteEgressCommandResult(0, "ok", ""),
    )

    assert result == RemoteEgressRunResult(
        status="dry_run",
        message="remote egress dry-run only; no remote commands executed",
        action="up",
        target="root@166.88.232.2:22",
        steps=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_remote_egress_runner_rejects_without_double_gate_before_calling_runner():
    calls: list[str] = []

    result = run_remote_egress_plan(
        _plan("down"),
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        runner=lambda command: calls.append(command) or RemoteEgressCommandResult(0, "ok", ""),
    )

    assert result.status == "rejected"
    assert result.message == "remote egress requires yes=True and allow_remote_changes=True"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []


def test_remote_egress_runner_executes_plan_steps_in_order_through_injected_runner():
    calls: list[str] = []

    def runner(command: str) -> RemoteEgressCommandResult:
        calls.append(command)
        return RemoteEgressCommandResult(returncode=0, stdout="ok", stderr="")

    plan = _plan("up")
    result = run_remote_egress_plan(plan, dry_run=False, yes=True, allow_remote_changes=True, runner=runner)

    expected_commands = [step.command_preview for step in plan.steps]
    assert calls == expected_commands
    assert result.status == "success"
    assert result.message == "remote egress up completed through injected runner"
    assert result.action == "up"
    assert result.commands_executed == expected_commands
    assert result.performed_side_effects is True
    assert [step.action for step in result.steps] == ["doctor", "egress_up", "post_up_status"]
    assert [step.status for step in result.steps] == ["success", "success", "success"]


def test_remote_egress_runner_stops_on_first_failed_step():
    calls: list[str] = []

    def runner(command: str) -> RemoteEgressCommandResult:
        calls.append(command)
        if "egress down" in command:
            return RemoteEgressCommandResult(returncode=2, stdout="", stderr="egress failed")
        return RemoteEgressCommandResult(returncode=0, stdout="ok", stderr="")

    plan = _plan("down")
    result = run_remote_egress_plan(plan, dry_run=False, yes=True, allow_remote_changes=True, runner=runner)

    assert calls == [plan.steps[0].command_preview, plan.steps[1].command_preview]
    assert result.status == "failed"
    assert result.message == "remote egress down stopped at egress_down"
    assert result.commands_executed == calls
    assert result.performed_side_effects is True
    assert result.steps[-1] == RemoteEgressStepResult(
        action="egress_down",
        description="stop remote OpenVPN egress and cleanup policy routing through MiGate gates",
        status="failed",
        command=plan.steps[1].command_preview,
        returncode=2,
        stdout="",
        stderr="egress failed",
    )


def test_remote_egress_runner_rejects_rejected_plan_without_calling_runner():
    calls: list[str] = []
    rejected = build_remote_egress_dry_run_plan(host="root:secret@166.88.232.2", port=22, user="root", action="up")

    result = run_remote_egress_plan(
        rejected,
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        runner=lambda command: calls.append(command) or RemoteEgressCommandResult(0, "ok", ""),
    )

    assert result.status == "rejected"
    assert result.target == "[REDACTED]"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []


def test_render_remote_egress_run_result_includes_step_results():
    plan = _plan("up")
    result = run_remote_egress_plan(
        plan,
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        runner=lambda command: RemoteEgressCommandResult(0, "ok", ""),
    )

    rendered = render_remote_egress_run_result(result)

    assert "Remote egress result" in rendered
    assert "status: success" in rendered
    assert "action: up" in rendered
    assert "performed_side_effects: True" in rendered
    assert "- doctor: success returncode=0" in rendered
    assert "- egress_up: success returncode=0" in rendered
    assert "sshpass" not in rendered.lower()
