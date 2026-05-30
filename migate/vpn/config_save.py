"""Safe file save helpers for MiGate-managed OpenVPN runtime configs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil

from migate.vpn.config_render import OpenVPNRenderPlan


@dataclass(frozen=True)
class OpenVPNConfigSaveResult:
    status: str
    message: str
    target: Path
    bytes_written: int
    performed_side_effects: bool
    backup_path: Path | None = None


def save_openvpn_config_preview(
    plan: OpenVPNRenderPlan,
    target: str | Path,
    *,
    yes: bool,
    allow_file_write: bool,
    backup_suffix: str = ".bak",
) -> OpenVPNConfigSaveResult:
    target_path = Path(target)
    if not yes or not allow_file_write:
        return OpenVPNConfigSaveResult(
            status="rejected",
            message="OpenVPN config save requires yes=True and allow_file_write=True",
            target=target_path,
            bytes_written=0,
            performed_side_effects=False,
            backup_path=None,
        )

    target_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = target_path.with_name(target_path.name + backup_suffix) if target_path.exists() else None
    temp_path = target_path.with_name(target_path.name + ".tmp")

    if backup_path is not None:
        shutil.copy2(target_path, backup_path)

    temp_path.write_text(plan.config_text)
    temp_path.replace(target_path)
    return OpenVPNConfigSaveResult(
        status="saved",
        message="OpenVPN config preview saved",
        target=target_path,
        bytes_written=len(plan.config_text.encode("utf-8")),
        performed_side_effects=True,
        backup_path=backup_path,
    )
