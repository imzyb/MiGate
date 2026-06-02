"""Preview and safely save the MiGate local proxy systemd unit."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


DEFAULT_MIGATE_BINARY_PATH = "/usr/local/bin/migate"
DEFAULT_PROXY_SERVICE_PATH = "/etc/systemd/system/migate-proxy.service"
DEFAULT_PROXY_SERVICE_BACKEND = "xray-tun"


@dataclass(frozen=True)
class ProxyServiceSaveResult:
    status: str
    message: str
    target: Path
    performed_side_effects: bool
    systemctl_commands_executed: list[list[str]] | None = None


def preview_proxy_service_unit(
    *,
    migate_bin_path: str = DEFAULT_MIGATE_BINARY_PATH,
    backend: str = DEFAULT_PROXY_SERVICE_BACKEND,
) -> str:
    return f"""[Unit]
Description=MiGate local proxy service
After=network-online.target migate-xray.service
Wants=network-online.target

[Service]
Type=simple
# max_clients=0 keeps the proxy listener in continuous mode until systemd stops it
ExecStart={migate_bin_path} proxy run --backend {backend} --max-clients 0
# Preflight failures are terminal until the operator fixes VPN/TUN/listener prerequisites.
Restart=no
User=root
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"""


def save_proxy_service_unit(
    target: str | Path = DEFAULT_PROXY_SERVICE_PATH,
    *,
    yes: bool,
    allow_system_changes: bool,
    migate_bin_path: str = DEFAULT_MIGATE_BINARY_PATH,
    backend: str = DEFAULT_PROXY_SERVICE_BACKEND,
) -> ProxyServiceSaveResult:
    target_path = Path(target)
    if not yes or not allow_system_changes:
        return ProxyServiceSaveResult(
            status="rejected",
            message="proxy service save requires yes=True and allow_system_changes=True",
            target=target_path,
            performed_side_effects=False,
            systemctl_commands_executed=[],
        )

    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(preview_proxy_service_unit(migate_bin_path=migate_bin_path, backend=backend), encoding="utf-8")
    return ProxyServiceSaveResult(
        status="saved",
        message="proxy service unit saved; daemon-reload not run",
        target=target_path,
        performed_side_effects=True,
        systemctl_commands_executed=[],
    )
