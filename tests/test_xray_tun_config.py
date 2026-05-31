import json
import subprocess

from migate.config import MiGateConfig, VPNConfig
from migate.xray.tun_config import (
    XrayTunConfigSaveResult,
    build_xray_tun_config,
    render_xray_tun_config,
    save_xray_tun_config,
)


def test_build_xray_tun_config_routes_tun_inbound_to_safe_socks_without_freedom():
    cfg = MiGateConfig(vpn=VPNConfig(interface="tun-migate"))

    config = build_xray_tun_config(cfg)

    assert config["log"] == {"loglevel": "warning"}
    assert config["inbounds"] == [
        {
            "tag": "migate-tun-in",
            "protocol": "tun",
            "settings": {
                "interfaceName": "tun-migate",
                "mtu": 1500,
                "stack": "system",
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }
    ]
    protocols = {outbound["protocol"] for outbound in config["outbounds"]}
    assert protocols == {"socks", "blackhole"}
    assert "freedom" not in protocols
    safe_outbound = config["outbounds"][0]
    assert safe_outbound["tag"] == "migate-vpngate"
    assert safe_outbound["settings"]["servers"] == [{"address": "127.0.0.1", "port": 34501}]
    assert config["routing"]["domainStrategy"] == "IPIfNonMatch"
    assert config["routing"]["rules"] == [
        {"type": "field", "inboundTag": ["migate-tun-in"], "outboundTag": "migate-vpngate"},
        {"type": "field", "outboundTag": "blocked"},
    ]


def test_render_xray_tun_config_is_stable_json_and_side_effect_free():
    rendered = render_xray_tun_config(MiGateConfig())

    parsed = json.loads(rendered)
    assert parsed == build_xray_tun_config(MiGateConfig())
    assert rendered.endswith("\n")
    assert '"freedom"' not in rendered
    assert '"direct"' not in rendered.lower()
    assert '"performed_side_effects"' not in rendered


def test_save_xray_tun_config_rejects_without_double_gate(tmp_path):
    calls = []

    def validator(args):
        calls.append(args)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="ok", stderr="")

    target = tmp_path / "tun.json"
    result = save_xray_tun_config(
        MiGateConfig(),
        target,
        yes=True,
        allow_system_changes=False,
        validator_runner=validator,
    )

    assert result == XrayTunConfigSaveResult(
        status="rejected",
        message="xray tun config save requires yes=True and allow_system_changes=True",
        target=target,
        validation_status="skipped",
        performed_side_effects=False,
    )
    assert calls == []
    assert not target.exists()


def test_save_xray_tun_config_writes_tmp_validates_then_replaces_without_systemctl(tmp_path):
    calls = []

    def validator(args):
        calls.append(args)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="config ok", stderr="")

    target = tmp_path / "xray" / "tun.json"
    result = save_xray_tun_config(
        MiGateConfig(),
        target,
        yes=True,
        allow_system_changes=True,
        validator_runner=validator,
    )

    assert result.status == "saved"
    assert result.message == "xray tun config saved and validated"
    assert result.target == target
    assert result.validation_status == "valid"
    assert result.performed_side_effects is True
    assert result.rollback_performed is False
    assert result.systemctl_commands_executed == []
    saved = json.loads(target.read_text(encoding="utf-8"))
    assert saved["inbounds"][0]["protocol"] == "tun"
    assert {outbound["protocol"] for outbound in saved["outbounds"]} == {"socks", "blackhole"}
    assert calls == [["xray", "test", "-config", str(target.with_name("tun.tmp.json"))]]


def test_save_xray_tun_config_restores_existing_config_when_validation_fails(tmp_path):
    target = tmp_path / "tun.json"
    old_content = '{"old": true}\n'
    target.write_text(old_content, encoding="utf-8")

    def validator(args):
        return subprocess.CompletedProcess(args=args, returncode=23, stdout="", stderr="invalid")

    result = save_xray_tun_config(
        MiGateConfig(),
        target,
        yes=True,
        allow_system_changes=True,
        validator_runner=validator,
        backup_suffix=".bak-test",
    )

    assert result.status == "invalid"
    assert result.message == "xray tun config validation failed; restored previous config"
    assert result.validation_status == "invalid"
    assert result.validation_stdout == ""
    assert result.validation_stderr == "invalid"
    assert result.performed_side_effects is True
    assert result.backup_path == target.with_name("tun.json.bak-test")
    assert result.rollback_performed is True
    assert result.systemctl_commands_executed == []
    assert target.read_text(encoding="utf-8") == old_content
