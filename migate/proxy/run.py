"""Safe placeholder entrypoint for the MiGate local proxy runtime."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from migate.config import MiGateConfig
from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport, run_proxy_doctor


@dataclass(frozen=True)
class ProxyRunResult:
    status: str
    message: str
    checks: list[ProxyRuntimeCheck]
    listener_started: bool
    forwarding_started: bool
    performed_side_effects: bool


def run_proxy_placeholder(
    config: MiGateConfig | None = None,
    *,
    doctor_loader: Callable[[MiGateConfig], ProxyRuntimeReport] | None = None,
) -> ProxyRunResult:
    cfg = config or MiGateConfig()
    doctor = (doctor_loader or run_proxy_doctor)(cfg)
    if doctor.status != "ok":
        return ProxyRunResult(
            status="rejected",
            message="proxy run preflight failed; listener not started",
            checks=doctor.checks,
            listener_started=False,
            forwarding_started=False,
            performed_side_effects=False,
        )

    return ProxyRunResult(
        status="placeholder",
        message="proxy forwarding is not implemented yet; listener not started",
        checks=doctor.checks,
        listener_started=False,
        forwarding_started=False,
        performed_side_effects=False,
    )


def render_proxy_run_result(result: ProxyRunResult) -> str:
    lines = ["Proxy run", f"status: {result.status}", f"message: {result.message}"]
    lines.extend(f"{check.name}: {check.status} - {check.message}" for check in result.checks)
    lines.append(f"listener_started: {result.listener_started}")
    lines.append(f"forwarding_started: {result.forwarding_started}")
    lines.append(f"performed_side_effects: {result.performed_side_effects}")
    return "\n".join(lines)
