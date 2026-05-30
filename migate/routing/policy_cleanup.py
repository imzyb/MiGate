"""Pure policy routing cleanup planning for MiGate VPN egress."""

from __future__ import annotations

from dataclasses import dataclass

from migate.config import MiGateConfig


@dataclass(frozen=True)
class PolicyRoutingCleanupPlan:
    tun_interface: str
    route_table: int
    fwmark: str
    commands: list[list[str]]
    performs_side_effects: bool = False


@dataclass(frozen=True)
class PolicyRoutingCleanupDryRunStep:
    action: str
    status: str
    command_preview: str


@dataclass(frozen=True)
class PolicyRoutingCleanupDryRunResult:
    status: str
    message: str
    steps: list[PolicyRoutingCleanupDryRunStep]
    commands_executed: list[str]
    performed_side_effects: bool = False


def build_policy_routing_cleanup_plan(config: MiGateConfig) -> PolicyRoutingCleanupPlan:
    route_table = str(config.vpn.route_table)
    commands = [
        ["ip", "route", "del", "default", "dev", config.vpn.interface, "table", route_table],
        ["ip", "rule", "del", "fwmark", config.vpn.fwmark, "table", route_table],
    ]
    return PolicyRoutingCleanupPlan(
        tun_interface=config.vpn.interface,
        route_table=config.vpn.route_table,
        fwmark=config.vpn.fwmark,
        commands=commands,
        performs_side_effects=False,
    )


def dry_run_policy_routing_cleanup_plan(
    plan: PolicyRoutingCleanupPlan,
) -> PolicyRoutingCleanupDryRunResult:
    if plan.performs_side_effects:
        return PolicyRoutingCleanupDryRunResult(
            status="rejected",
            message="dry-run executor refuses cleanup plans with side effects",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    return PolicyRoutingCleanupDryRunResult(
        status="dry_run",
        message="planned only; no cleanup routing commands executed",
        steps=[
            PolicyRoutingCleanupDryRunStep(
                action="cleanup_policy_routing_command",
                status="planned",
                command_preview=" ".join(command),
            )
            for command in plan.commands
        ],
        commands_executed=[],
        performed_side_effects=False,
    )
