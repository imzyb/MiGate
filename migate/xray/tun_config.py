from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

from migate.config import MiGateConfig
from migate.xray.config_builder import build_blackhole_outbound, build_migate_socks_outbound
from migate.xray.validator import validate_xray_config
from migate.xray.writer import write_xray_config

XrayTunObject = dict[str, Any]


@dataclass(frozen=True)
class XrayTunConfigSaveResult:
    status: str
    message: str
    target: Path
    validation_status: str
    performed_side_effects: bool
    backup_path: Path | None = None
    rollback_performed: bool = False
    systemctl_commands_executed: list[str] | None = None


def build_xray_tun_inbound(config: MiGateConfig) -> XrayTunObject:
    return {
        "tag": "migate-tun-in",
        "protocol": "tun",
        "settings": {
            "interfaceName": config.vpn.interface,
            "mtu": 1500,
            "stack": "system",
        },
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


def build_xray_tun_config(config: MiGateConfig) -> XrayTunObject:
    tun_inbound = build_xray_tun_inbound(config)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [tun_inbound],
        "outbounds": [
            build_migate_socks_outbound(config),
            build_blackhole_outbound(),
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "inboundTag": [tun_inbound["tag"]], "outboundTag": config.xray.default_outbound_tag},
                {"type": "field", "outboundTag": "blocked"},
            ],
        },
    }


def render_xray_tun_config(config: MiGateConfig) -> str:
    return json.dumps(build_xray_tun_config(config), indent=2, sort_keys=True) + "\n"


def save_xray_tun_config(
    config: MiGateConfig,
    target: str | Path,
    *,
    yes: bool,
    allow_system_changes: bool,
    validator_runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
    backup_suffix: str = ".bak",
) -> XrayTunConfigSaveResult:
    target_path = Path(target)
    if not yes or not allow_system_changes:
        return XrayTunConfigSaveResult(
            status="rejected",
            message="xray tun config save requires yes=True and allow_system_changes=True",
            target=target_path,
            validation_status="skipped",
            performed_side_effects=False,
        )

    target_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = target_path.with_name(target_path.name + backup_suffix) if target_path.exists() else None
    temp_path = target_path.with_name(target_path.name + ".tmp")

    if backup_path is not None:
        shutil.copy2(target_path, backup_path)

    write_xray_config(build_xray_tun_config(config), temp_path)
    validation = validate_xray_config(temp_path, runner=validator_runner)
    if validation.status != "valid":
        if temp_path.exists():
            temp_path.unlink()
        if backup_path is not None:
            shutil.copy2(backup_path, target_path)
            message = "xray tun config validation failed; restored previous config"
        else:
            if target_path.exists():
                target_path.unlink()
            message = "xray tun config validation failed; removed invalid new config"
        return XrayTunConfigSaveResult(
            status="invalid",
            message=message,
            target=target_path,
            validation_status=validation.status,
            performed_side_effects=True,
            backup_path=backup_path,
            rollback_performed=True,
            systemctl_commands_executed=[],
        )

    temp_path.replace(target_path)
    return XrayTunConfigSaveResult(
        status="saved",
        message="xray tun config saved and validated",
        target=target_path,
        validation_status=validation.status,
        performed_side_effects=True,
        backup_path=backup_path,
        rollback_performed=False,
        systemctl_commands_executed=[],
    )
