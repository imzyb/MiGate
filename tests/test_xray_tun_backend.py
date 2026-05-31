from pathlib import Path

from migate.config import EgressConfig, MiGateConfig, XrayConfig
from migate.egress.tunnel_backend import TunnelStartPlan, TunnelStopPlan
from migate.egress.xray_tun_backend import build_xray_tun_start_plan, build_xray_tun_stop_plan


def test_build_xray_tun_start_plan_uses_generic_tunnel_contract_without_side_effects():
    cfg = MiGateConfig(
        egress=EgressConfig(backend="xray-tun"),
        xray=XrayConfig(bin_path="/usr/local/bin/xray", config_path="/etc/migate/xray/tun.json"),
    )

    plan = build_xray_tun_start_plan(cfg)

    assert plan == TunnelStartPlan(
        backend="xray-tun",
        command=["systemctl", "start", "migate-xray-tun.service"],
        runtime_paths=[
            "/etc/migate/xray/tun.json",
            "/var/log/migate/xray-tun.log",
        ],
        required_paths=["/etc/migate/xray/tun.json"],
        performs_side_effects=False,
    )


def test_build_xray_tun_stop_plan_uses_generic_tunnel_contract_without_side_effects():
    plan = build_xray_tun_stop_plan()

    assert plan == TunnelStopPlan(
        backend="xray-tun",
        command=["systemctl", "stop", "migate-xray-tun.service"],
        performs_side_effects=False,
    )


def test_build_xray_tun_start_plan_allows_custom_log_path():
    cfg = MiGateConfig(egress=EgressConfig(backend="xray-tun"))

    plan = build_xray_tun_start_plan(cfg, log_path=Path("/tmp/migate/xray-tun.log"))

    assert plan.runtime_paths[-1] == "/tmp/migate/xray-tun.log"
    assert plan.required_paths == [cfg.xray.config_path]
