"""OpenVPN implementation adapter for the generic MiGate tunnel backend contract."""

from __future__ import annotations

from pathlib import Path

from migate.config import MiGateConfig
from migate.egress.tunnel_backend import TunnelStartPlan, TunnelStopPlan
from migate.vpn.process_plan import build_openvpn_start_plan


DEFAULT_OPENVPN_CONFIG_PATH = "/var/lib/migate/runtime/active.ovpn"
DEFAULT_OPENVPN_PID_PATH = "/var/lib/migate/runtime/openvpn.pid"
DEFAULT_OPENVPN_STATUS_PATH = "/var/lib/migate/runtime/status.json"
DEFAULT_OPENVPN_LOG_PATH = "/var/log/migate/openvpn.log"


def build_openvpn_tunnel_start_plan(config: MiGateConfig) -> TunnelStartPlan:
    openvpn_plan = build_openvpn_start_plan(
        config,
        config_path=DEFAULT_OPENVPN_CONFIG_PATH,
        pid_path=DEFAULT_OPENVPN_PID_PATH,
        status_path=DEFAULT_OPENVPN_STATUS_PATH,
        log_path=DEFAULT_OPENVPN_LOG_PATH,
    )
    return TunnelStartPlan(
        backend="openvpn",
        command=openvpn_plan.command,
        runtime_paths=[
            openvpn_plan.config_path,
            openvpn_plan.pid_path,
            openvpn_plan.status_path,
            openvpn_plan.log_path,
        ],
        required_paths=[openvpn_plan.config_path],
        performs_side_effects=openvpn_plan.performs_side_effects,
    )


def build_openvpn_tunnel_stop_plan(pid_file: Path) -> TunnelStopPlan:
    return TunnelStopPlan(
        backend="openvpn",
        command=["sh", "-c", f"pid=$(cat {pid_file}); kill -TERM $pid"],
        performs_side_effects=False,
    )
