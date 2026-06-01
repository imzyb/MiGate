from migate.proxy.service_cli import ProxyServiceSaveResult, preview_proxy_service_unit, save_proxy_service_unit


def test_preview_proxy_service_unit_renders_safe_systemd_unit_without_side_effects():
    unit = preview_proxy_service_unit()

    assert "[Unit]" in unit
    assert "Description=MiGate local proxy service" in unit
    assert "After=network-online.target migate-xray.service" in unit
    assert "ExecStart=/usr/local/bin/migate proxy run --max-clients 0" in unit
    assert "# max_clients=0 keeps the proxy listener in continuous mode until systemd stops it" in unit
    assert "Restart=no" in unit
    assert "Restart=on-failure" not in unit
    assert "RestartSec" not in unit
    assert "WantedBy=multi-user.target" in unit
    assert "systemctl" not in unit
    assert unit.endswith("\n")


def test_save_proxy_service_unit_rejects_without_double_gate(tmp_path):
    target = tmp_path / "migate-proxy.service"

    result = save_proxy_service_unit(target, yes=True, allow_system_changes=False)

    assert result == ProxyServiceSaveResult(
        status="rejected",
        message="proxy service save requires yes=True and allow_system_changes=True",
        target=target,
        performed_side_effects=False,
        systemctl_commands_executed=[],
    )
    assert not target.exists()


def test_save_proxy_service_unit_writes_unit_when_double_gate_passes(tmp_path):
    target = tmp_path / "migate-proxy.service"

    result = save_proxy_service_unit(target, yes=True, allow_system_changes=True)

    assert result.status == "saved"
    assert result.message == "proxy service unit saved; daemon-reload not run"
    assert result.target == target
    assert result.performed_side_effects is True
    assert result.systemctl_commands_executed == []
    content = target.read_text(encoding="utf-8")
    assert "ExecStart=/usr/local/bin/migate proxy run --max-clients 0" in content
    assert "systemctl" not in content


def test_save_proxy_service_unit_allows_custom_migate_binary(tmp_path):
    target = tmp_path / "custom-proxy.service"

    result = save_proxy_service_unit(target, yes=True, allow_system_changes=True, migate_bin_path="/opt/migate/bin/migate")

    assert result.status == "saved"
    assert "ExecStart=/opt/migate/bin/migate proxy run --max-clients 0" in target.read_text(encoding="utf-8")
