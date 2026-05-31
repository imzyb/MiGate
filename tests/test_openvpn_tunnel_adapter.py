from pathlib import Path

from migate.config import MiGateConfig
from migate.egress.openvpn_backend import build_openvpn_tunnel_start_plan, build_openvpn_tunnel_stop_plan
from migate.egress.tunnel_backend import TunnelStartPlan, TunnelStopPlan


def test_build_openvpn_tunnel_start_plan_adapts_existing_openvpn_command_shape():
    plan = build_openvpn_tunnel_start_plan(MiGateConfig())

    assert isinstance(plan, TunnelStartPlan)
    assert plan.backend == "openvpn"
    assert plan.command[:3] == ["openvpn", "--config", "/var/lib/migate/runtime/active.ovpn"]
    assert "--daemon" in plan.command
    assert "migate-openvpn" in plan.command
    assert plan.runtime_paths == [
        "/var/lib/migate/runtime/active.ovpn",
        "/var/lib/migate/runtime/openvpn.pid",
        "/var/lib/migate/runtime/status.json",
        "/var/log/migate/openvpn.log",
    ]
    assert plan.required_paths == ["/var/lib/migate/runtime/active.ovpn"]
    assert plan.performs_side_effects is False


def test_build_openvpn_tunnel_stop_plan_adapts_existing_pid_stop_shape(tmp_path: Path):
    pid_file = tmp_path / "openvpn.pid"
    plan = build_openvpn_tunnel_stop_plan(pid_file)

    assert plan == TunnelStopPlan(
        backend="openvpn",
        command=["sh", "-c", f"pid=$(cat {pid_file}); kill -TERM $pid"],
        performs_side_effects=False,
    )
