"""Gated egress lifecycle orchestration for MiGate."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from migate.routing.policy_apply import apply_policy_routing_plan
from migate.routing.policy_cleanup import PolicyRoutingCleanupPlan
from migate.routing.policy_cleanup_runner import PolicyRoutingCleanupCommandResult, apply_policy_routing_cleanup_plan
from migate.routing.policy_plan import PolicyRoutingPlan
from migate.vpn.process_plan import OpenVPNStartPlan
from migate.vpn.process_runner import CommandResult as OpenVPNStartCommandResult, run_openvpn_start_plan
from migate.vpn.process_stop import CommandResult as OpenVPNStopCommandResult, OpenVPNStopPlan, run_openvpn_stop_plan


@dataclass(frozen=True)
class EgressLifecyclePhase:
    name: str
    status: str
    result: object


@dataclass(frozen=True)
class EgressLifecycleResult:
    status: str
    message: str
    phases: list[EgressLifecyclePhase]
    commands_executed: list[str]
    performed_side_effects: bool


def bring_up_egress(
    start_plan: OpenVPNStartPlan,
    routing_plan: PolicyRoutingPlan,
    *,
    runner: Callable[[list[str]], Any] | None = None,
    openvpn_runner: Callable[[list[str]], OpenVPNStartCommandResult] | None = None,
    routing_runner: Callable[[list[str]], Any] | None = None,
    allow_side_effects: bool = False,
) -> EgressLifecycleResult:
    if not allow_side_effects:
        return EgressLifecycleResult(
            status="rejected",
            message="allow_side_effects must be true to bring egress up",
            phases=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    phase_runner = openvpn_runner or runner
    routing_phase_runner = routing_runner or runner
    start_result = run_openvpn_start_plan(start_plan, runner=phase_runner, allow_side_effects=True)
    phases = [EgressLifecyclePhase(name="openvpn_start", status=start_result.status, result=start_result)]
    if start_result.status != "started":
        return EgressLifecycleResult(
            status="failed",
            message="egress up stopped before routing; OpenVPN start failed",
            phases=phases,
            commands_executed=start_result.commands_executed,
            performed_side_effects=start_result.performed_side_effects,
        )

    routing_result = apply_policy_routing_plan(routing_plan, runner=routing_phase_runner, allow_side_effects=True)
    phases.append(EgressLifecyclePhase(name="policy_routing_apply", status=routing_result.status, result=routing_result))
    if routing_result.status != "applied":
        return EgressLifecycleResult(
            status="failed",
            message="egress up failed during policy routing apply",
            phases=phases,
            commands_executed=[*start_result.commands_executed, *routing_result.commands_executed],
            performed_side_effects=start_result.performed_side_effects or routing_result.performed_side_effects,
        )

    return EgressLifecycleResult(
        status="up",
        message="egress brought up",
        phases=phases,
        commands_executed=[*start_result.commands_executed, *routing_result.commands_executed],
        performed_side_effects=start_result.performed_side_effects or routing_result.performed_side_effects,
    )


def bring_down_egress(
    cleanup_plan: PolicyRoutingCleanupPlan,
    stop_plan: OpenVPNStopPlan,
    *,
    runner: Callable[[list[str]], Any] | None = None,
    cleanup_runner: Callable[[list[str]], PolicyRoutingCleanupCommandResult] | None = None,
    stop_runner: Callable[[list[str]], OpenVPNStopCommandResult] | None = None,
    allow_side_effects: bool = False,
) -> EgressLifecycleResult:
    if not allow_side_effects:
        return EgressLifecycleResult(
            status="rejected",
            message="allow_side_effects must be true to bring egress down",
            phases=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    cleanup_phase_runner = cleanup_runner or runner
    stop_phase_runner = stop_runner or runner
    cleanup_result = apply_policy_routing_cleanup_plan(cleanup_plan, runner=cleanup_phase_runner, allow_side_effects=True)
    phases = [EgressLifecyclePhase(name="policy_routing_cleanup", status=cleanup_result.status, result=cleanup_result)]
    if cleanup_result.status != "applied":
        return EgressLifecycleResult(
            status="failed",
            message="egress down stopped before OpenVPN stop; routing cleanup failed",
            phases=phases,
            commands_executed=cleanup_result.commands_executed,
            performed_side_effects=cleanup_result.performed_side_effects,
        )

    stop_result = run_openvpn_stop_plan(stop_plan, runner=stop_phase_runner, allow_side_effects=True)
    phases.append(EgressLifecyclePhase(name="openvpn_stop", status=stop_result.status, result=stop_result))
    if stop_result.status != "stopped":
        return EgressLifecycleResult(
            status="failed",
            message="egress down failed during OpenVPN stop",
            phases=phases,
            commands_executed=[*cleanup_result.commands_executed, *stop_result.commands_executed],
            performed_side_effects=cleanup_result.performed_side_effects or stop_result.performed_side_effects,
        )

    return EgressLifecycleResult(
        status="down",
        message="egress brought down",
        phases=phases,
        commands_executed=[*cleanup_result.commands_executed, *stop_result.commands_executed],
        performed_side_effects=cleanup_result.performed_side_effects or stop_result.performed_side_effects,
    )
