"""Xray TUN implementation adapter for the generic MiGate tunnel backend contract."""

from __future__ import annotations

from pathlib import Path

from migate.config import MiGateConfig
from migate.egress.tunnel_backend import TunnelStartPlan, TunnelStopPlan


DEFAULT_XRAY_TUN_SERVICE = "migate-xray-tun.service"
DEFAULT_XRAY_TUN_LOG_PATH = "/var/log/migate/xray-tun.log"


def build_xray_tun_start_plan(
    config: MiGateConfig,
    *,
    service_name: str = DEFAULT_XRAY_TUN_SERVICE,
    log_path: Path | str = DEFAULT_XRAY_TUN_LOG_PATH,
) -> TunnelStartPlan:
    config_path = config.xray.config_path
    return TunnelStartPlan(
        backend="xray-tun",
        command=["systemctl", "start", service_name],
        runtime_paths=[config_path, str(log_path)],
        required_paths=[config_path],
        performs_side_effects=False,
    )


def build_xray_tun_stop_plan(
    *,
    service_name: str = DEFAULT_XRAY_TUN_SERVICE,
) -> TunnelStopPlan:
    return TunnelStopPlan(
        backend="xray-tun",
        command=["systemctl", "stop", service_name],
        performs_side_effects=False,
    )
