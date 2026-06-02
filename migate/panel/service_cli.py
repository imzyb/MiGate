"""Panel service unit management for MiGate."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

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


def preview_panel_service_unit() -> str:
    config = MiGateConfig()
    unit = build_panel_unit(config)
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
    unit = build_panel_unit(config)
    write_unit_file(unit, target_path.parent)
    return PanelServiceSaveResult(
        status="saved",
        message="service unit saved; daemon-reload not run",
        target=target_path,
        performed_side_effects=True,
        systemctl_commands_executed=[],
    )
