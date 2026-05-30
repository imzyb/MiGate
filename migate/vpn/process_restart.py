"""Gated OpenVPN restart orchestration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from migate.vpn.process_plan import OpenVPNStartPlan
from migate.vpn.process_runner import CommandResult as StartCommandResult
from migate.vpn.process_runner import OpenVPNStartResult, run_openvpn_start_plan
from migate.vpn.process_stop import OpenVPNStopPlan, OpenVPNStopResult, run_openvpn_stop_plan


@dataclass(frozen=True)
class OpenVPNRestartResult:
    status: str
    message: str
    stop_result: OpenVPNStopResult | None
    start_result: OpenVPNStartResult | None
    commands_executed: list[str]
    performed_side_effects: bool


def restart_openvpn(
    stop_plan: OpenVPNStopPlan,
    start_plan: OpenVPNStartPlan,
    *,
    runner: Callable[[list[str]], StartCommandResult] | None = None,
    allow_side_effects: bool = False,
) -> OpenVPNRestartResult:
    if not allow_side_effects:
        return OpenVPNRestartResult(
            status="rejected",
            message="allow_side_effects must be true to restart OpenVPN",
            stop_result=None,
            start_result=None,
            commands_executed=[],
            performed_side_effects=False,
        )

    stop_result = run_openvpn_stop_plan(stop_plan, runner=runner, allow_side_effects=True)
    if stop_result.status != "stopped":
        return OpenVPNRestartResult(
            status="failed",
            message="OpenVPN restart stopped before start; stop phase failed",
            stop_result=stop_result,
            start_result=None,
            commands_executed=stop_result.commands_executed,
            performed_side_effects=stop_result.performed_side_effects,
        )

    start_result = run_openvpn_start_plan(start_plan, runner=runner, allow_side_effects=True)
    status = "restarted" if start_result.status == "started" else "failed"
    return OpenVPNRestartResult(
        status=status,
        message="OpenVPN restart completed" if status == "restarted" else "OpenVPN restart failed during start phase",
        stop_result=stop_result,
        start_result=start_result,
        commands_executed=[*stop_result.commands_executed, *start_result.commands_executed],
        performed_side_effects=stop_result.performed_side_effects or start_result.performed_side_effects,
    )
