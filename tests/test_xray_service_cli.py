from migate.xray.service_cli import XrayServiceSaveResult, preview_xray_service_unit, save_xray_service_unit


def test_preview_xray_service_unit_renders_safe_systemd_unit_without_side_effects():
    unit = preview_xray_service_unit()

    assert "[Unit]" in unit
    assert "Description=MiGate managed Xray service" in unit
    assert "After=network-online.target" in unit
    assert "ExecStart=/usr/local/bin/xray run -config /etc/migate/xray/config.json" in unit
    assert "Restart=on-failure" in unit
    assert "WantedBy=multi-user.target" in unit
    assert "systemctl" not in unit
    assert unit.endswith("\n")


def test_save_xray_service_unit_rejects_without_double_gate(tmp_path):
    target = tmp_path / "xray.service"

    result = save_xray_service_unit(target, yes=True, allow_system_changes=False)

    assert result == XrayServiceSaveResult(
        status="rejected",
        message="service save requires yes=True and allow_system_changes=True",
        target=target,
        performed_side_effects=False,
        systemctl_commands_executed=[],
    )
    assert not target.exists()


def test_save_xray_service_unit_writes_unit_when_double_gate_passes(tmp_path):
    target = tmp_path / "xray.service"

    result = save_xray_service_unit(target, yes=True, allow_system_changes=True)

    assert result.status == "saved"
    assert result.message == "service unit saved; daemon-reload not run"
    assert result.target == target
    assert result.performed_side_effects is True
    assert result.systemctl_commands_executed == []
    assert target.exists()
    content = target.read_text(encoding="utf-8")
    assert "ExecStart=/usr/local/bin/xray run -config /etc/migate/xray/config.json" in content
    assert "systemctl" not in content


def test_save_xray_service_unit_allows_custom_binary_and_config_paths(tmp_path):
    target = tmp_path / "custom.service"

    result = save_xray_service_unit(
        target,
        yes=True,
        allow_system_changes=True,
        binary_path="/opt/xray/xray",
        config_path="/tmp/migate/config.json",
    )

    content = target.read_text(encoding="utf-8")
    assert result.status == "saved"
    assert "ExecStart=/opt/xray/xray run -config /tmp/migate/config.json" in content
