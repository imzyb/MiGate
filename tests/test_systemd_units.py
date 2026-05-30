from pathlib import Path

from migate.config import MiGateConfig
from migate.systemd.units import SystemdUnit, build_panel_unit, build_xray_unit, write_unit_file


def test_build_xray_unit_uses_migate_config_path_and_no_direct_fallback():
    config = MiGateConfig()

    unit = build_xray_unit(config)

    assert isinstance(unit, SystemdUnit)
    assert unit.name == "migate-xray.service"
    assert "Description=MiGate managed Xray service" in unit.content
    assert "ExecStart=/usr/local/bin/xray run -config /etc/migate/xray/config.json" in unit.content
    assert "Restart=on-failure" in unit.content
    assert "User=root" in unit.content
    assert "freedom" not in unit.content.lower()


def test_build_panel_unit_uses_migate_panel_cli_and_binds_to_localhost():
    config = MiGateConfig()

    unit = build_panel_unit(config)

    assert unit.name == "migate-panel.service"
    assert "Description=MiGate web panel" in unit.content
    assert "ExecStart=/usr/local/bin/migate panel --host 127.0.0.1 --port 8787" in unit.content
    assert "uvicorn migate.api.app:create_app" not in unit.content
    assert "--host 127.0.0.1" in unit.content
    assert "--port 8787" in unit.content
    assert "Restart=on-failure" in unit.content


def test_write_unit_file_creates_target_directory_and_writes_content(tmp_path):
    unit = SystemdUnit(name="migate-xray.service", content="[Unit]\nDescription=MiGate\n")
    target_dir = tmp_path / "systemd" / "system"

    written = write_unit_file(unit, target_dir)

    assert written == target_dir / "migate-xray.service"
    assert written.read_text(encoding="utf-8") == unit.content
