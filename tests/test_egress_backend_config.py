from migate.config import EgressConfig, MiGateConfig


def test_migate_config_exposes_egress_backend_separate_from_openvpn_settings():
    cfg = MiGateConfig()

    assert isinstance(cfg.egress, EgressConfig)
    assert cfg.egress.backend == "openvpn"
    assert cfg.vpn.interface == "tun-migate"


def test_migate_config_accepts_non_openvpn_egress_backend_without_vpn_mutation():
    cfg = MiGateConfig(egress=EgressConfig(backend="xray-tun"))

    assert cfg.egress.backend == "xray-tun"
    assert cfg.vpn.interface == "tun-migate"
