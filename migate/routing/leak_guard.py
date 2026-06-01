"""Pure leak-guard decisions for MiGate egress traffic."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EgressGuardState:
    leak_guard_enabled: bool
    fail_policy: str
    tun_interface: str
    tun_interface_exists: bool
    tunnel_running: bool | None = None
    openvpn_running: bool | None = None
    upstream_proxy_required: bool = False
    upstream_proxy_ready: bool | None = None
    upstream_proxy_endpoint: str | None = None
    native_public_ip: str | None = None
    egress_public_ip: str | None = None


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
    tunnel_running = state.tunnel_running if state.tunnel_running is not None else state.openvpn_running
    if tunnel_running is None:
        return _block(
            "tunnel_state_unknown",
            "tunnel backend state is unknown; egress blocked",
            ["tunnel"],
        )
    if not tunnel_running:
        return _block(
            "tunnel_not_running",
            "tunnel backend is not running; egress blocked",
            ["tunnel"],
        )
    if state.upstream_proxy_required and state.upstream_proxy_ready is None:
        endpoint = state.upstream_proxy_endpoint or "configured upstream proxy"
        return _block(
            "upstream_proxy_state_unknown",
            f"required upstream proxy {endpoint} state is unknown; egress blocked",
            ["upstream_proxy"],
        )
    if state.upstream_proxy_ready is False:
        endpoint = state.upstream_proxy_endpoint or "configured upstream proxy"
        return _block(
            "upstream_proxy_unavailable",
            f"required upstream proxy {endpoint} is unavailable; egress blocked",
            ["upstream_proxy"],
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
