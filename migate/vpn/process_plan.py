"""Pure OpenVPN process start planning and dry-run rendering."""

from __future__ import annotations

from dataclasses import dataclass

from migate.config import MiGateConfig


@dataclass(frozen=True)
class OpenVPNStartPlan:
    openvpn_bin: str
    config_path: str
    tun_interface: str
    pid_path: str
    status_path: str
    log_path: str
    command: list[str]
    performs_side_effects: bool = False


@dataclass(frozen=True)
class OpenVPNStartDryRunStep:
    action: str
    status: str
    command_preview: str


@dataclass(frozen=True)
class OpenVPNStartDryRunResult:
    status: str
    message: str
    steps: list[OpenVPNStartDryRunStep]
    commands_executed: list[str]
    performed_side_effects: bool = False


def build_openvpn_start_plan(
    config: MiGateConfig,
    *,
    config_path: str,
    pid_path: str,
    status_path: str,
    log_path: str,
    openvpn_bin: str = "openvpn",
) -> OpenVPNStartPlan:
    command = [
        openvpn_bin,
        "--config",
        config_path,
        "--writepid",
        pid_path,
        "--status",
        status_path,
        "--log-append",
        log_path,
        "--daemon",
        "migate-openvpn",
    ]
    return OpenVPNStartPlan(
        openvpn_bin=openvpn_bin,
        config_path=config_path,
        tun_interface=config.vpn.interface,
        pid_path=pid_path,
        status_path=status_path,
        log_path=log_path,
        command=command,
        performs_side_effects=False,
    )


def dry_run_openvpn_start_plan(plan: OpenVPNStartPlan) -> OpenVPNStartDryRunResult:
    if plan.performs_side_effects:
        return OpenVPNStartDryRunResult(
            status="rejected",
            message="dry-run executor refuses plans with side effects",
            steps=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    return OpenVPNStartDryRunResult(
        status="dry_run",
        message="planned only; no commands executed",
        steps=[
            OpenVPNStartDryRunStep(
                action="start_openvpn_process",
                status="planned",
                command_preview=" ".join(plan.command),
            )
        ],
        commands_executed=[],
        performed_side_effects=False,
    )
