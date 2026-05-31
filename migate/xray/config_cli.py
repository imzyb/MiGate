"""CLI helpers for previewing and safely saving xray config."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess

from migate.config import MiGateConfig
from migate.xray.config_builder import build_full_config, build_vless_tcp_inbound
from migate.xray.validator import validate_xray_config
from migate.xray.writer import write_xray_config


@dataclass(frozen=True)
class XrayConfigSaveResult:
    status: str
    message: str
    target: Path
    validation_status: str
    performed_side_effects: bool
    backup_path: Path | None = None
    rollback_performed: bool = False


def build_default_xray_config(config: MiGateConfig) -> dict:
    return build_full_config(
        config,
        inbounds=[
            build_vless_tcp_inbound(
                tag="vless-main",
                port=443,
                client_uuid="00000000-0000-4000-8000-000000000001",
                email="default@migate.local",
            )
        ],
    )


def preview_xray_config(config: MiGateConfig) -> str:
    return json.dumps(build_default_xray_config(config), ensure_ascii=False, indent=2) + "\n"


def save_xray_config(
    config: MiGateConfig,
    target: str | Path,
    *,
    yes: bool,
    allow_system_changes: bool,
    validator_runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
    backup_suffix: str = ".bak",
) -> XrayConfigSaveResult:
    target_path = Path(target)
    if not yes or not allow_system_changes:
        return XrayConfigSaveResult(
            status="rejected",
            message="config save requires yes=True and allow_system_changes=True",
            target=target_path,
            validation_status="skipped",
            performed_side_effects=False,
        )

    target_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = target_path.with_name(target_path.name + backup_suffix) if target_path.exists() else None
    temp_path = target_path.with_suffix(f".tmp{target_path.suffix}")

    if backup_path is not None:
        shutil.copy2(target_path, backup_path)

    write_xray_config(build_default_xray_config(config), temp_path)
    validation = validate_xray_config(temp_path, runner=validator_runner)
    if validation.status != "valid":
        if temp_path.exists():
            temp_path.unlink()
        if backup_path is not None:
            shutil.copy2(backup_path, target_path)
            message = "config validation failed; restored previous config"
        else:
            if target_path.exists():
                target_path.unlink()
            message = "config validation failed; removed invalid new config"
        return XrayConfigSaveResult(
            status="invalid",
            message=message,
            target=target_path,
            validation_status=validation.status,
            performed_side_effects=True,
            backup_path=backup_path,
            rollback_performed=True,
        )

    temp_path.replace(target_path)
    return XrayConfigSaveResult(
        status="saved",
        message="config saved and validated",
        target=target_path,
        validation_status=validation.status,
        performed_side_effects=True,
        backup_path=backup_path,
        rollback_performed=False,
    )
