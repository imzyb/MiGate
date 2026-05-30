"""Pure xray-core installation plan generation.

This module intentionally does not download, write, chmod, or execute anything.
It only builds a previewable plan that a later installer can consume safely.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from migate.config import MiGateConfig

_XRAY_RELEASE_BASE = "https://github.com/XTLS/Xray-core/releases/download"


@dataclass(frozen=True)
class XrayInstallStep:
    action: str
    description: str


@dataclass(frozen=True)
class XrayInstallPlan:
    version: str
    system: str
    arch: str
    bin_path: str
    config_dir: str
    archive_name: str
    download_url: str
    steps: list[XrayInstallStep]
    commands: list[str]
    performs_side_effects: bool = False

    def to_preview(self) -> str:
        lines = [
            "Xray 安装计划",
            f"版本：{self.version}",
            f"架构：{self.system}-{self.arch}",
            f"目标路径：{self.bin_path}",
            f"配置目录：{self.config_dir}",
            f"下载地址：{self.download_url}",
            "安全说明：当前只是计划预览，不会执行任何安装命令。",
            "操作步骤：",
        ]
        lines.extend(f"- {step.description}" for step in self.steps)
        return "\n".join(lines)


def normalize_machine_arch(machine: str) -> str:
    value = machine.strip().lower()
    mapping = {
        "x86_64": "64",
        "amd64": "64",
        "aarch64": "arm64-v8a",
        "arm64": "arm64-v8a",
    }
    try:
        return mapping[value]
    except KeyError as exc:
        raise ValueError(f"unsupported architecture: {machine}") from exc


def _normalize_system(system: str) -> str:
    value = system.strip().lower()
    if value != "linux":
        raise ValueError(f"unsupported system: {system}")
    return value


def build_xray_install_plan(
    config: MiGateConfig,
    *,
    system: str,
    machine: str,
    version: str = "latest",
) -> XrayInstallPlan:
    normalized_system = _normalize_system(system)
    arch = normalize_machine_arch(machine)
    archive_name = f"Xray-{normalized_system}-{arch}.zip"
    download_url = f"{_XRAY_RELEASE_BASE}/{version}/{archive_name}"
    config_dir = str(Path(config.xray.config_path).parent)
    steps = [
        XrayInstallStep("download_archive", "下载 xray-core zip"),
        XrayInstallStep("verify_archive", "校验压缩包"),
        XrayInstallStep("extract_binary", "解压 xray 二进制"),
        XrayInstallStep("install_binary", f"写入 {config.xray.bin_path}"),
        XrayInstallStep("chmod_executable", "设置 xray 可执行权限"),
        XrayInstallStep("verify_version", "xray version 验证"),
    ]
    return XrayInstallPlan(
        version=version,
        system=normalized_system,
        arch=arch,
        bin_path=config.xray.bin_path,
        config_dir=config_dir,
        archive_name=archive_name,
        download_url=download_url,
        steps=steps,
        commands=[],
        performs_side_effects=False,
    )
