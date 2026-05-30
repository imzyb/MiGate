from pathlib import Path

from migate.vpn.config_render import OpenVPNRenderPlan
from migate.vpn.config_save import OpenVPNConfigSaveResult, save_openvpn_config_preview


PLAN = OpenVPNRenderPlan(
    source_profile="vpnGate",
    tun_interface="tun-migate",
    runtime_dir="/var/lib/migate/runtime",
    config_text="client\ndev tun-migate\nstatus /var/lib/migate/runtime/status.json\nlog-append /var/log/migate/openvpn.log\n",
    performed_side_effects=False,
)


def test_save_openvpn_config_preview_rejects_without_double_file_write_gate(tmp_path):
    target = tmp_path / "active.ovpn"

    result = save_openvpn_config_preview(
        PLAN,
        target,
        yes=True,
        allow_file_write=False,
    )

    assert result == OpenVPNConfigSaveResult(
        status="rejected",
        message="OpenVPN config save requires yes=True and allow_file_write=True",
        target=target,
        bytes_written=0,
        performed_side_effects=False,
        backup_path=None,
    )
    assert not target.exists()


def test_save_openvpn_config_preview_writes_target_file_when_gate_is_open(tmp_path):
    target = tmp_path / "active.ovpn"

    result = save_openvpn_config_preview(
        PLAN,
        target,
        yes=True,
        allow_file_write=True,
    )

    assert result.status == "saved"
    assert result.message == "OpenVPN config preview saved"
    assert result.target == target
    assert result.bytes_written == len(PLAN.config_text.encode("utf-8"))
    assert result.backup_path is None
    assert result.performed_side_effects is True
    assert target.read_text() == PLAN.config_text


def test_save_openvpn_config_preview_backs_up_existing_file_before_replace(tmp_path):
    target = tmp_path / "active.ovpn"
    target.write_text("old-config\n")

    result = save_openvpn_config_preview(
        PLAN,
        target,
        yes=True,
        allow_file_write=True,
    )

    backup_path = tmp_path / "active.ovpn.bak"
    assert result.status == "saved"
    assert result.backup_path == backup_path
    assert backup_path.read_text() == "old-config\n"
    assert target.read_text() == PLAN.config_text
