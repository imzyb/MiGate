from migate.config import MiGateConfig
from migate.routing.policy_plan import (
    PolicyRoutingDryRunResult,
    PolicyRoutingDryRunStep,
    PolicyRoutingPlan,
    build_policy_routing_plan,
    dry_run_policy_routing_plan,
)


def test_build_policy_routing_plan_uses_migate_vpn_defaults_without_side_effects():
    plan = build_policy_routing_plan(MiGateConfig())

    assert plan == PolicyRoutingPlan(
        tun_interface="tun-migate",
        route_table=100,
        fwmark="0x66",
        commands=[
            ["ip", "rule", "add", "fwmark", "0x66", "table", "100"],
            ["ip", "route", "add", "default", "dev", "tun-migate", "table", "100"],
        ],
        performs_side_effects=False,
    )


def test_dry_run_policy_routing_plan_reports_commands_without_execution():
    plan = build_policy_routing_plan(MiGateConfig())

    result = dry_run_policy_routing_plan(plan)

    assert result == PolicyRoutingDryRunResult(
        status="dry_run",
        message="planned only; no routing commands executed",
        steps=[
            PolicyRoutingDryRunStep(
                action="apply_policy_routing_command",
                status="planned",
                command_preview="ip rule add fwmark 0x66 table 100",
            ),
            PolicyRoutingDryRunStep(
                action="apply_policy_routing_command",
                status="planned",
                command_preview="ip route add default dev tun-migate table 100",
            ),
        ],
        commands_executed=[],
        performed_side_effects=False,
    )


def test_dry_run_policy_routing_plan_rejects_plans_with_side_effects():
    plan = PolicyRoutingPlan(
        tun_interface="tun-migate",
        route_table=100,
        fwmark="0x66",
        commands=[],
        performs_side_effects=True,
    )

    result = dry_run_policy_routing_plan(plan)

    assert result.status == "rejected"
    assert result.message == "dry-run executor refuses plans with side effects"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
