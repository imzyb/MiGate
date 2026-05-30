from migate.config import MiGateConfig


def test_default_config_routes_xray_to_migate_socks():
    cfg = MiGateConfig()

    assert cfg.xray.default_outbound_tag == "migate-vpngate"
    assert cfg.proxy.socks_host == "127.0.0.1"
    assert cfg.proxy.socks_port == 34501
    assert cfg.proxy.http_host == "127.0.0.1"
    assert cfg.proxy.http_port == 34502
    assert cfg.security.fail_policy == "block"


def test_default_config_uses_named_tunnel_and_policy_table():
    cfg = MiGateConfig()

    assert cfg.vpn.interface == "tun-migate"
    assert cfg.vpn.route_table == 100
    assert cfg.vpn.fwmark == "0x66"
