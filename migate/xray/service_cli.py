"""Preview and safely save the MiGate-managed Xray systemd unit."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


DEFAULT_XRAY_BINARY_PATH = "/usr/local/bin/xray"
DEFAULT_XRAY_CONFIG_PATH = "/etc/migate/xray/config.json"
DEFAULT_XRAY_SERVICE_PATH = "/etc/systemd/system/migate-xray.service"
DEFAULT_XRAY_TUN_SERVICE_PATH = "/etc/systemd/system/migate-xray-tun.service"


@dataclass(frozen=True)
class XrayServiceSaveResult:
    status: str
    message: str
    target: Path
    performed_side_effects: bool
    systemctl_commands_executed: list[list[str]] | None = None


def preview_xray_service_unit(
    *,
    binary_path: str = DEFAULT_XRAY_BINARY_PATH,
    config_path: str = DEFAULT_XRAY_CONFIG_PATH,
) -> str:
    return f"""[Unit]
Description=MiGate managed Xray service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary_path} run -config {config_path}
Restart=on-failure
RestartSec=3
User=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""


def preview_xray_tun_service_unit(
    *,
    binary_path: str = DEFAULT_XRAY_BINARY_PATH,
    config_path: str = DEFAULT_XRAY_CONFIG_PATH,
) -> str:
    return f"""[Unit]
Description=MiGate managed Xray TUN service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary_path} run -config {config_path}
Restart=on-failure
RestartSec=3
User=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""


def save_xray_tun_service_unit(
    target: str | Path = DEFAULT_XRAY_TUN_SERVICE_PATH,
    *,
    yes: bool,
    allow_system_changes: bool,
    binary_path: str = DEFAULT_XRAY_BINARY_PATH,
    config_path: str = DEFAULT_XRAY_CONFIG_PATH,
) -> XrayServiceSaveResult:
    target_path = Path(target)
    if not yes or not allow_system_changes:
        return XrayServiceSaveResult(
            status="rejected",
            message="xray tun service save requires yes=True and allow_system_changes=True",
            target=target_path,
            performed_side_effects=False,
            systemctl_commands_executed=[],
        )

    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(
        preview_xray_tun_service_unit(binary_path=binary_path, config_path=config_path),
        encoding="utf-8",
    )
    return XrayServiceSaveResult(
        status="saved",
        message="xray tun service unit saved; daemon-reload not run",
        target=target_path,
        performed_side_effects=True,
        systemctl_commands_executed=[],
    )


def save_xray_service_unit(
    target: str | Path = DEFAULT_XRAY_SERVICE_PATH,
    *,
    yes: bool,
    allow_system_changes: bool,
    binary_path: str = DEFAULT_XRAY_BINARY_PATH,
    config_path: str = DEFAULT_XRAY_CONFIG_PATH,
) -> XrayServiceSaveResult:
    target_path = Path(target)
    if not yes or not allow_system_changes:
        return XrayServiceSaveResult(
            status="rejected",
            message="service save requires yes=True and allow_system_changes=True",
            target=target_path,
            performed_side_effects=False,
            systemctl_commands_executed=[],
        )

    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(
        preview_xray_service_unit(binary_path=binary_path, config_path=config_path),
        encoding="utf-8",
    )
    return XrayServiceSaveResult(
        status="saved",
        message="service unit saved; daemon-reload not run",
        target=target_path,
        performed_side_effects=True,
        systemctl_commands_executed=[],
    )
