from migate.config import MiGateConfig
from migate.vpn.process_plan import (
    OpenVPNStartDryRunResult,
    OpenVPNStartPlan,
    build_openvpn_start_plan,
    dry_run_openvpn_start_plan,
)


def test_build_openvpn_start_plan_freezes_managed_command_without_side_effects():
    plan = build_openvpn_start_plan(
        MiGateConfig(),
        config_path="/var/lib/migate/runtime/active.ovpn",
        pid_path="/var/lib/migate/runtime/openvpn.pid",
        status_path="/var/lib/migate/runtime/status.json",
        log_path="/var/log/migate/openvpn.log",
    )

    assert plan == OpenVPNStartPlan(
        openvpn_bin="openvpn",
        config_path="/var/lib/migate/runtime/active.ovpn",
        tun_interface="tun-migate",
        pid_path="/var/lib/migate/runtime/openvpn.pid",
        status_path="/var/lib/migate/runtime/status.json",
        log_path="/var/log/migate/openvpn.log",
        command=[
            "openvpn",
            "--config",
            "/var/lib/migate/runtime/active.ovpn",
            "--writepid",
            "/var/lib/migate/runtime/openvpn.pid",
            "--status",
            "/var/lib/migate/runtime/status.json",
            "--log-append",
            "/var/log/migate/openvpn.log",
        ],
        performs_side_effects=False,
    )


def test_dry_run_openvpn_start_plan_returns_planned_command_without_execution():
    plan = build_openvpn_start_plan(
        MiGateConfig(),
        config_path="/var/lib/migate/runtime/active.ovpn",
        pid_path="/var/lib/migate/runtime/openvpn.pid",
        status_path="/var/lib/migate/runtime/status.json",
        log_path="/var/log/migate/openvpn.log",
    )

    result = dry_run_openvpn_start_plan(plan)

    assert isinstance(result, OpenVPNStartDryRunResult)
    assert result.status == "dry_run"
    assert result.performed_side_effects is False
    assert result.commands_executed == []
    assert len(result.steps) == 1
    assert result.steps[0].action == "start_openvpn_process"
    assert result.steps[0].status == "planned"
    assert result.steps[0].command_preview == (
        "openvpn --config /var/lib/migate/runtime/active.ovpn "
        "--writepid /var/lib/migate/runtime/openvpn.pid "
        "--status /var/lib/migate/runtime/status.json "
        "--log-append /var/log/migate/openvpn.log"
    )


def test_dry_run_openvpn_start_plan_rejects_plan_that_already_claims_side_effects():
    plan = OpenVPNStartPlan(
        openvpn_bin="openvpn",
        config_path="/var/lib/migate/runtime/active.ovpn",
        tun_interface="tun-migate",
        pid_path="/var/lib/migate/runtime/openvpn.pid",
        status_path="/var/lib/migate/runtime/status.json",
        log_path="/var/log/migate/openvpn.log",
        command=["openvpn", "--config", "/var/lib/migate/runtime/active.ovpn"],
        performs_side_effects=True,
    )

    result = dry_run_openvpn_start_plan(plan)

    assert result.status == "rejected"
    assert result.performed_side_effects is False
    assert result.commands_executed == []
    assert result.steps == []
    assert "refuses plans with side effects" in result.message
