from migate.routing.leak_guard import EgressGuardState, evaluate_egress_guard


def test_egress_guard_allows_when_tunnel_openvpn_and_exit_are_safe():
    decision = evaluate_egress_guard(
        EgressGuardState(
            leak_guard_enabled=True,
            fail_policy="block",
            tun_interface="tun-migate",
            tun_interface_exists=True,
            openvpn_running=True,
            native_public_ip="203.0.113.10",
            egress_public_ip="198.51.100.20",
        )
    )

    assert decision.allowed is True
    assert decision.reason == "egress_safe"
    assert decision.blocked_by == []
    assert decision.performed_side_effects is False


def test_egress_guard_blocks_when_tun_interface_is_missing():
    decision = evaluate_egress_guard(
        EgressGuardState(
            leak_guard_enabled=True,
            fail_policy="block",
            tun_interface="tun-migate",
            tun_interface_exists=False,
            openvpn_running=True,
            native_public_ip="203.0.113.10",
            egress_public_ip="198.51.100.20",
        )
    )

    assert decision.allowed is False
    assert decision.reason == "tun_interface_missing"
    assert decision.blocked_by == ["tun_interface"]
    assert decision.message == "tun-migate interface is missing; egress blocked"
    assert decision.performed_side_effects is False


def test_egress_guard_blocks_when_openvpn_is_not_running():
    decision = evaluate_egress_guard(
        EgressGuardState(
            leak_guard_enabled=True,
            fail_policy="block",
            tun_interface="tun-migate",
            tun_interface_exists=True,
            openvpn_running=False,
            native_public_ip="203.0.113.10",
            egress_public_ip="198.51.100.20",
        )
    )

    assert decision.allowed is False
    assert decision.reason == "openvpn_not_running"
    assert decision.blocked_by == ["openvpn"]
    assert decision.message == "OpenVPN is not running; egress blocked"


def test_egress_guard_blocks_when_egress_ip_matches_native_vps_ip():
    decision = evaluate_egress_guard(
        EgressGuardState(
            leak_guard_enabled=True,
            fail_policy="block",
            tun_interface="tun-migate",
            tun_interface_exists=True,
            openvpn_running=True,
            native_public_ip="203.0.113.10",
            egress_public_ip="203.0.113.10",
        )
    )

    assert decision.allowed is False
    assert decision.reason == "native_ip_leak_detected"
    assert decision.blocked_by == ["egress_ip"]
    assert decision.message == "egress public IP matches native VPS public IP; egress blocked"


def test_egress_guard_blocks_when_egress_ip_cannot_be_verified():
    decision = evaluate_egress_guard(
        EgressGuardState(
            leak_guard_enabled=True,
            fail_policy="block",
            tun_interface="tun-migate",
            tun_interface_exists=True,
            openvpn_running=True,
            native_public_ip="203.0.113.10",
            egress_public_ip=None,
        )
    )

    assert decision.allowed is False
    assert decision.reason == "egress_ip_unverified"
    assert decision.blocked_by == ["egress_ip"]
    assert decision.message == "egress public IP could not be verified; egress blocked"


def test_egress_guard_blocks_when_fail_policy_is_not_block():
    decision = evaluate_egress_guard(
        EgressGuardState(
            leak_guard_enabled=True,
            fail_policy="direct",
            tun_interface="tun-migate",
            tun_interface_exists=True,
            openvpn_running=True,
            native_public_ip="203.0.113.10",
            egress_public_ip="198.51.100.20",
        )
    )

    assert decision.allowed is False
    assert decision.reason == "unsafe_fail_policy"
    assert decision.blocked_by == ["fail_policy"]
    assert decision.message == "fail_policy is direct; expected block"


def test_egress_guard_blocks_when_leak_guard_is_disabled():
    decision = evaluate_egress_guard(
        EgressGuardState(
            leak_guard_enabled=False,
            fail_policy="block",
            tun_interface="tun-migate",
            tun_interface_exists=True,
            openvpn_running=True,
            native_public_ip="203.0.113.10",
            egress_public_ip="198.51.100.20",
        )
    )

    assert decision.allowed is False
    assert decision.reason == "leak_guard_disabled"
    assert decision.blocked_by == ["leak_guard"]
    assert decision.message == "leak_guard is disabled; egress blocked"
