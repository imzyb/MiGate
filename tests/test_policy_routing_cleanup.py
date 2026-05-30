from migate.config import MiGateConfig
from migate.routing.policy_cleanup import (
    PolicyRoutingCleanupDryRunResult,
    PolicyRoutingCleanupDryRunStep,
    PolicyRoutingCleanupPlan,
    build_policy_routing_cleanup_plan,
    dry_run_policy_routing_cleanup_plan,
)


def test_build_policy_routing_cleanup_plan_uses_symmetric_migate_defaults_without_side_effects():
    plan = build_policy_routing_cleanup_plan(MiGateConfig())

    assert plan == PolicyRoutingCleanupPlan(
        tun_interface="tun-migate",
        route_table=100,
        fwmark="0x66",
        commands=[
            ["ip", "route", "del", "default", "dev", "tun-migate", "table", "100"],
            ["ip", "rule", "del", "fwmark", "0x66", "table", "100"],
        ],
        performs_side_effects=False,
    )


def test_dry_run_policy_routing_cleanup_plan_reports_commands_without_execution():
    plan = build_policy_routing_cleanup_plan(MiGateConfig())

    result = dry_run_policy_routing_cleanup_plan(plan)

    assert result == PolicyRoutingCleanupDryRunResult(
        status="dry_run",
        message="planned only; no cleanup routing commands executed",
        steps=[
            PolicyRoutingCleanupDryRunStep(
                action="cleanup_policy_routing_command",
                status="planned",
                command_preview="ip route del default dev tun-migate table 100",
            ),
            PolicyRoutingCleanupDryRunStep(
                action="cleanup_policy_routing_command",
                status="planned",
                command_preview="ip rule del fwmark 0x66 table 100",
            ),
        ],
        commands_executed=[],
        performed_side_effects=False,
    )


def test_dry_run_policy_routing_cleanup_plan_rejects_plans_with_side_effects():
    plan = PolicyRoutingCleanupPlan(
        tun_interface="tun-migate",
        route_table=100,
        fwmark="0x66",
        commands=[],
        performs_side_effects=True,
    )

    result = dry_run_policy_routing_cleanup_plan(plan)

    assert result.status == "rejected"
    assert result.message == "dry-run executor refuses cleanup plans with side effects"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
