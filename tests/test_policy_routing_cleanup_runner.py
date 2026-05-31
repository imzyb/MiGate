from migate.config import MiGateConfig
from migate.routing.policy_cleanup import build_policy_routing_cleanup_plan
from migate.routing.policy_cleanup_runner import (
    PolicyRoutingCleanupApplyResult,
    PolicyRoutingCleanupApplyStep,
    apply_policy_routing_cleanup_plan,
)


class FakeCommandResult:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_apply_policy_routing_cleanup_plan_rejects_without_side_effect_gate():
    plan = build_policy_routing_cleanup_plan(MiGateConfig())
    calls: list[list[str]] = []

    result = apply_policy_routing_cleanup_plan(plan, runner=lambda argv: calls.append(argv))

    assert result == PolicyRoutingCleanupApplyResult(
        status="rejected",
        message="allow_side_effects must be true to apply cleanup routing commands",
        steps=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_apply_policy_routing_cleanup_plan_runs_commands_in_order_when_allowed():
    plan = build_policy_routing_cleanup_plan(MiGateConfig())
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return FakeCommandResult(returncode=0, stdout="ok", stderr="")

    result = apply_policy_routing_cleanup_plan(plan, runner=runner, allow_side_effects=True)

    assert calls == plan.commands
    assert result == PolicyRoutingCleanupApplyResult(
        status="applied",
        message="cleanup routing commands applied",
        steps=[
            PolicyRoutingCleanupApplyStep(
                action="cleanup_policy_routing_command",
                status="success",
                command=plan.commands[0],
                returncode=0,
                stdout="ok",
                stderr="",
            ),
            PolicyRoutingCleanupApplyStep(
                action="cleanup_policy_routing_command",
                status="success",
                command=plan.commands[1],
                returncode=0,
                stdout="ok",
                stderr="",
            ),
        ],
        commands_executed=[
            "ip route del default dev tun-migate table 100",
            "ip rule del fwmark 0x66 table 100",
        ],
        performed_side_effects=True,
    )


def test_apply_policy_routing_cleanup_plan_stops_after_first_failed_command():
    plan = build_policy_routing_cleanup_plan(MiGateConfig())
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return FakeCommandResult(returncode=2, stdout="", stderr="permission denied")

    result = apply_policy_routing_cleanup_plan(plan, runner=runner, allow_side_effects=True)

    assert calls == [plan.commands[0]]
    assert result.status == "failed"
    assert result.message == "cleanup routing command failed: ip route del default dev tun-migate table 100"
    assert result.steps == [
        PolicyRoutingCleanupApplyStep(
            action="cleanup_policy_routing_command",
            status="failed",
            command=plan.commands[0],
            returncode=2,
            stdout="",
            stderr="permission denied",
        )
    ]
    assert result.commands_executed == ["ip route del default dev tun-migate table 100"]
    assert result.performed_side_effects is True


def test_apply_policy_routing_cleanup_plan_treats_already_absent_routes_as_clean():
    plan = build_policy_routing_cleanup_plan(MiGateConfig())
    calls: list[list[str]] = []
    failures = [
        FakeCommandResult(returncode=2, stderr="Error: ipv4: FIB table does not exist.\nDump terminated"),
        FakeCommandResult(returncode=2, stderr="Error: No such process"),
    ]

    def runner(argv: list[str]) -> FakeCommandResult:
        calls.append(argv)
        return failures.pop(0)

    result = apply_policy_routing_cleanup_plan(plan, runner=runner, allow_side_effects=True)

    assert calls == plan.commands
    assert result.status == "applied"
    assert result.message == "cleanup routing commands applied"
    assert [step.status for step in result.steps] == ["already_absent", "already_absent"]
    assert result.commands_executed == [
        "ip route del default dev tun-migate table 100",
        "ip rule del fwmark 0x66 table 100",
    ]


def test_apply_policy_routing_cleanup_plan_maps_missing_ip_command_to_structured_failure():
    plan = build_policy_routing_cleanup_plan(MiGateConfig())

    def runner(argv: list[str]) -> FakeCommandResult:
        raise FileNotFoundError(argv[0])

    result = apply_policy_routing_cleanup_plan(plan, runner=runner, allow_side_effects=True)

    assert result.status == "failed"
    assert result.message == "cleanup routing command not found: ip"
    assert result.steps == [
        PolicyRoutingCleanupApplyStep(
            action="cleanup_policy_routing_command",
            status="command_not_found",
            command=plan.commands[0],
            returncode=None,
            stdout="",
            stderr="command not found: ip",
        )
    ]
    assert result.commands_executed == ["ip route del default dev tun-migate table 100"]
    assert result.performed_side_effects is True
