"""Pure policy routing command planning for MiGate VPN egress."""

from __future__ import annotations

from dataclasses import dataclass

from migate.config import MiGateConfig


@dataclass(frozen=True)
class PolicyRoutingPlan:
    tun_interface: str
    route_table: int
    fwmark: str
    commands: list[list[str]]
    performs_side_effects: bool = False


@dataclass(frozen=True)
class PolicyRoutingDryRunStep:
    action: str
    status: str
    command_preview: str


@dataclass(frozen=True)
class PolicyRoutingDryRunResult:
    status: str
    message: str
    steps: list[PolicyRoutingDryRunStep]
    commands_executed: list[str]
    performed_side_effects: bool = False


def build_policy_routing_plan(config: MiGateConfig) -> PolicyRoutingPlan:
    route_table = str(config.vpn.route_table)
    commands = [
        ["ip", "rule", "del", "fwmark", config.vpn.fwmark, "table", route_table],
        ["ip", "rule", "add", "fwmark", config.vpn.fwmark, "table", route_table],
        ["ip", "route", "replace", "default", "dev", config.vpn.interface, "table", route_table],
    ]
    return PolicyRoutingPlan(
        tun_interface=config.vpn.interface,
        route_table=config.vpn.route_table,
        fwmark=config.vpn.fwmark,
        commands=commands,
        performs_side_effects=False,
    )


def dry_run_policy_routing_plan(plan: PolicyRoutingPlan) -> PolicyRoutingDryRunResult:
    if plan.performs_side_effects:
        return PolicyRoutingDryRunResult(
            status="rejected",
            message="dry-run executor refuses plans with side effects",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    return PolicyRoutingDryRunResult(
        status="dry_run",
        message="planned only; no routing commands executed",
        steps=[
            PolicyRoutingDryRunStep(
                action="apply_policy_routing_command",
                status="planned",
                command_preview=" ".join(command),
            )
            for command in plan.commands
        ],
        commands_executed=[],
        performed_side_effects=False,
    )
