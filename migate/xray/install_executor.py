"""Dry-run execution for xray-core install plans.

This module intentionally does not execute commands. It only transforms a safe
install plan into structured planned step results.
"""

from __future__ import annotations

from dataclasses import dataclass

from migate.xray.install_plan import XrayInstallPlan, XrayInstallStep


@dataclass(frozen=True)
class XrayInstallDryRunStep:
    action: str
    description: str
    status: str
    command_preview: str


@dataclass(frozen=True)
class XrayInstallDryRunResult:
    status: str
    message: str
    steps: list[XrayInstallDryRunStep]
    commands_executed: list[str]
    performed_side_effects: bool = False

    def to_report(self) -> str:
        lines = [
            "Xray 安装 dry-run",
            f"状态：{self.status}",
            f"说明：{self.message}",
            f"实际副作用：{self.performed_side_effects}",
            f"执行命令：{self.commands_executed}",
            "步骤：",
        ]
        lines.extend(f"- {step.action}: {step.status} -> {step.command_preview}" for step in self.steps)
        return "\n".join(lines)


def _command_preview(plan: XrayInstallPlan, step: XrayInstallStep) -> str:
    archive_path = f"/tmp/{plan.archive_name}"
    extract_dir = f"/tmp/migate-xray-{plan.version}"
    previews = {
        "download_archive": f"curl -fsSL {plan.download_url} -o {archive_path}",
        "verify_archive": f"python -m zipfile -t {archive_path}",
        "extract_binary": f"unzip -o {archive_path} xray -d {extract_dir}",
        "install_binary": f"install -m 0755 {extract_dir}/xray {plan.bin_path}",
        "chmod_executable": f"chmod +x {plan.bin_path}",
        "verify_version": f"{plan.bin_path} version",
    }
    return previews.get(step.action, f"# no command preview for {step.action}")


def dry_run_xray_install_plan(plan: XrayInstallPlan) -> XrayInstallDryRunResult:
    if plan.performs_side_effects or plan.commands:
        return XrayInstallDryRunResult(
            status="rejected",
            message="dry-run executor refuses plans with side effects",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    steps = [
        XrayInstallDryRunStep(
            action=step.action,
            description=step.description,
            status="planned",
            command_preview=_command_preview(plan, step),
        )
        for step in plan.steps
    ]
    return XrayInstallDryRunResult(
        status="dry_run",
        message="planned only; no commands executed",
        steps=steps,
        commands_executed=[],
        performed_side_effects=False,
    )
