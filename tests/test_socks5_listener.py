from migate.config import MiGateConfig
from migate.proxy.socks5_listener import (
    SOCKS5_LISTENER_BIND_HOST,
    SOCKS5_LISTENER_BIND_PORT,
    Socks5ListenerPlan,
    build_socks5_listener_plan,
    render_socks5_listener_plan,
)


def test_build_socks5_listener_plan_uses_safe_defaults_without_side_effects():
    plan = build_socks5_listener_plan(MiGateConfig())

    assert plan == Socks5ListenerPlan(
        bind_host=SOCKS5_LISTENER_BIND_HOST,
        bind_port=SOCKS5_LISTENER_BIND_PORT,
        protocol="socks5",
        connection_driver="Socks5Connection",
        upstream_mode="not_implemented",
        will_listen=False,
        will_connect_upstream=False,
        performed_side_effects=False,
    )


def test_render_socks5_listener_plan_mentions_no_real_listener_or_upstream():
    plan = build_socks5_listener_plan(MiGateConfig())

    text = render_socks5_listener_plan(plan)

    assert "SOCKS5 listener plan" in text
    assert "bind_host: 127.0.0.1" in text
    assert "bind_port: 34501" in text
    assert "will_listen: False" in text
    assert "will_connect_upstream: False" in text
    assert "performed_side_effects: False" in text
    assert "systemctl" not in text
    assert "connect_upstream(" not in text
    assert "start_server" not in text
