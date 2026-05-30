"""Pure leak-guard decisions for MiGate egress traffic."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EgressGuardState:
    leak_guard_enabled: bool
    fail_policy: str
    tun_interface: str
    tun_interface_exists: bool
    openvpn_running: bool
    native_public_ip: str | None
    egress_public_ip: str | None


@dataclass(frozen=True)
class EgressGuardDecision:
    allowed: bool
    reason: str
    message: str
    blocked_by: list[str]
    performed_side_effects: bool = False


def _block(reason: str, message: str, blocked_by: list[str]) -> EgressGuardDecision:
    return EgressGuardDecision(
        allowed=False,
        reason=reason,
        message=message,
        blocked_by=blocked_by,
        performed_side_effects=False,
    )


def evaluate_egress_guard(state: EgressGuardState) -> EgressGuardDecision:
    if not state.leak_guard_enabled:
        return _block(
            "leak_guard_disabled",
            "leak_guard is disabled; egress blocked",
            ["leak_guard"],
        )
    if state.fail_policy != "block":
        return _block(
            "unsafe_fail_policy",
            f"fail_policy is {state.fail_policy}; expected block",
            ["fail_policy"],
        )
    if not state.tun_interface_exists:
        return _block(
            "tun_interface_missing",
            f"{state.tun_interface} interface is missing; egress blocked",
            ["tun_interface"],
        )
    if not state.openvpn_running:
        return _block(
            "openvpn_not_running",
            "OpenVPN is not running; egress blocked",
            ["openvpn"],
        )
    if not state.native_public_ip or not state.egress_public_ip:
        return _block(
            "egress_ip_unverified",
            "egress public IP could not be verified; egress blocked",
            ["egress_ip"],
        )
    if state.native_public_ip == state.egress_public_ip:
        return _block(
            "native_ip_leak_detected",
            "egress public IP matches native VPS public IP; egress blocked",
            ["egress_ip"],
        )
    return EgressGuardDecision(
        allowed=True,
        reason="egress_safe",
        message="egress guard checks passed",
        blocked_by=[],
        performed_side_effects=False,
    )
