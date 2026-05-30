from migate.vpn.config_render import OpenVPNRenderPlan, render_openvpn_config_preview


RAW_OVPN = """client
proto udp
remote 1.2.3.4 1194
dev tun
persist-key
persist-tun
keepalive 10 60
verb 3
"""


def test_render_openvpn_config_preview_injects_migate_paths_and_device():
    plan = render_openvpn_config_preview(
        RAW_OVPN,
        tun_interface="tun-migate",
        runtime_dir="/var/lib/migate/runtime",
        log_path="/var/log/migate/openvpn.log",
        status_path="/var/lib/migate/runtime/status.json",
    )

    assert plan == OpenVPNRenderPlan(
        source_profile="vpnGate",
        tun_interface="tun-migate",
        runtime_dir="/var/lib/migate/runtime",
        config_text="""client
proto udp
remote 1.2.3.4 1194
dev tun-migate
persist-key
persist-tun
keepalive 10 60
verb 3
status /var/lib/migate/runtime/status.json
log-append /var/log/migate/openvpn.log
""",
        performed_side_effects=False,
    )


def test_render_openvpn_config_preview_replaces_existing_status_and_log_lines():
    raw = """client
status old-status.log
log /tmp/old.log
dev tun
"""

    plan = render_openvpn_config_preview(
        raw,
        tun_interface="tun-migate",
        runtime_dir="/var/lib/migate/runtime",
        log_path="/var/log/migate/openvpn.log",
        status_path="/var/lib/migate/runtime/status.json",
    )

    assert "status old-status.log" not in plan.config_text
    assert "log /tmp/old.log" not in plan.config_text
    assert "status /var/lib/migate/runtime/status.json" in plan.config_text
    assert "log-append /var/log/migate/openvpn.log" in plan.config_text
    assert plan.performed_side_effects is False
