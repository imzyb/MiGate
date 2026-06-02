"""Panel service unit management for MiGate."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import json

from migate.config import MiGateConfig
from migate.systemd.units import build_panel_unit, write_unit_file

DEFAULT_PANEL_SERVICE_PATH = "/etc/systemd/system/migate-panel.service"


@dataclass(frozen=True)
class PanelServiceSaveResult:
    status: str
    message: str
    target: Path
    performed_side_effects: bool
    systemctl_commands_executed: list[str]


def _load_panel_bind_config(config_path: str | Path = "/etc/migate/panel.json") -> tuple[str | None, int | None]:
    """Read panel_host and panel_port from panel.json if available."""
    try:
        data = json.loads(Path(config_path).read_text(encoding="utf-8"))
        host = str(data.get("panel_host")) if "panel_host" in data else None
        port = int(data["panel_port"]) if "panel_port" in data else None
        return host, port
    except (FileNotFoundError, json.JSONDecodeError, KeyError, ValueError):
        return None, None


def preview_panel_service_unit() -> str:
    config = MiGateConfig()
    host, port = _load_panel_bind_config()
    unit = build_panel_unit(config, host=host, port=port)
    return unit.content


def save_panel_service_unit(
    target: str | Path = DEFAULT_PANEL_SERVICE_PATH,
    *,
    yes: bool,
    allow_system_changes: bool,
) -> PanelServiceSaveResult:
    target_path = Path(target)
    if not yes or not allow_system_changes:
        return PanelServiceSaveResult(
            status="rejected",
            message="service save requires yes=True and allow_system_changes=True",
            target=target_path,
            performed_side_effects=False,
            systemctl_commands_executed=[],
        )

    config = MiGateConfig()
    host, port = _load_panel_bind_config()
    unit = build_panel_unit(config, host=host, port=port)
    write_unit_file(unit, target_path.parent)
    return PanelServiceSaveResult(
        status="saved",
        message="service unit saved; daemon-reload not run",
        target=target_path,
        performed_side_effects=True,
        systemctl_commands_executed=[],
    )
