"""Systemd unit rendering helpers for MiGate services."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from migate.config import MiGateConfig


@dataclass(frozen=True)
class SystemdUnit:
    name: str
    content: str


def build_xray_unit(config: MiGateConfig) -> SystemdUnit:
    content = f"""[Unit]
Description=MiGate managed Xray service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart={config.xray.bin_path} run -config {config.xray.config_path}
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""
    return SystemdUnit(name="migate-xray.service", content=content)


def build_panel_unit(config: MiGateConfig) -> SystemdUnit:
    content = f"""[Unit]
Description=MiGate web panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/migate panel --host {config.security.web_bind} --port {config.security.web_port}
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
"""
    return SystemdUnit(name="migate-panel.service", content=content)


def write_unit_file(unit: SystemdUnit, target_dir: str | Path = "/etc/systemd/system") -> Path:
    directory = Path(target_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / unit.name
    target.write_text(unit.content, encoding="utf-8")
    return target
