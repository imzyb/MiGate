"""Gated egress lifecycle orchestration for MiGate."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from migate.routing.policy_apply import apply_policy_routing_plan
from migate.routing.policy_cleanup import PolicyRoutingCleanupPlan
from migate.routing.policy_cleanup_runner import PolicyRoutingCleanupCommandResult, apply_policy_routing_cleanup_plan
from migate.routing.policy_plan import PolicyRoutingPlan
from migate.egress.tunnel_backend import (
    CommandResult as TunnelCommandResult,
    TunnelStartPlan,
    TunnelStopPlan,
    run_tunnel_start_plan,
    run_tunnel_stop_plan,
)


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
    start_plan: TunnelStartPlan,
    routing_plan: PolicyRoutingPlan,
    *,
    runner: Callable[[list[str]], Any] | None = None,
    tunnel_runner: Callable[[list[str]], TunnelCommandResult] | None = None,
    openvpn_runner: Callable[[list[str]], TunnelCommandResult] | None = None,
    routing_runner: Callable[[list[str]], Any] | None = None,
    config_exists: Callable[[str], bool] | None = None,
    ensure_directory: Callable[[Path], None] | None = None,
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

    exists = config_exists or (lambda path: Path(path).exists())
    required_paths = start_plan.required_paths or []
    missing_required_paths = [path for path in required_paths if not exists(path)]
    if missing_required_paths:
        missing = missing_required_paths[0]
        return EgressLifecycleResult(
            status="failed",
            message=f"egress up preflight failed; {start_plan.backend} runtime path is missing: {missing}",
            phases=[EgressLifecyclePhase(name="tunnel_preflight", status="failed", result=None)],
            commands_executed=[],
            performed_side_effects=False,
        )

    mkdir = ensure_directory or (lambda path: path.mkdir(parents=True, exist_ok=True))
    ensured_parents: set[Path] = set()
    for runtime_path in start_plan.runtime_paths:
        parent = Path(runtime_path).parent
        if str(parent) != "." and parent not in ensured_parents:
            mkdir(parent)
            ensured_parents.add(parent)

    phase_runner = tunnel_runner or openvpn_runner or runner
    routing_phase_runner = routing_runner or runner
    start_result = run_tunnel_start_plan(start_plan, runner=phase_runner, allow_side_effects=True)
    phases = [EgressLifecyclePhase(name="tunnel_start", status=start_result.status, result=start_result)]
    if start_result.status != "started":
        return EgressLifecycleResult(
            status="failed",
            message=f"egress up stopped before routing; {start_plan.backend} tunnel start failed",
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
    stop_plan: TunnelStopPlan,
    *,
    runner: Callable[[list[str]], Any] | None = None,
    cleanup_runner: Callable[[list[str]], PolicyRoutingCleanupCommandResult] | None = None,
    stop_runner: Callable[[list[str]], TunnelCommandResult] | None = None,
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
            message=f"egress down stopped before {stop_plan.backend} tunnel stop; routing cleanup failed",
            phases=phases,
            commands_executed=cleanup_result.commands_executed,
            performed_side_effects=cleanup_result.performed_side_effects,
        )

    stop_result = run_tunnel_stop_plan(stop_plan, runner=stop_phase_runner, allow_side_effects=True)
    phases.append(EgressLifecyclePhase(name="tunnel_stop", status=stop_result.status, result=stop_result))
    if stop_result.status != "stopped":
        return EgressLifecycleResult(
            status="failed",
            message=f"egress down failed during {stop_plan.backend} tunnel stop",
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
