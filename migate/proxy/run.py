"""Safe entrypoint for the MiGate local proxy runtime."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from migate.config import MiGateConfig
from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport, run_proxy_doctor
from migate.proxy.socks5_listener import Socks5ServerStarter, run_socks5_serve


@dataclass(frozen=True)
class ProxyRunResult:
    status: str
    message: str
    checks: list[ProxyRuntimeCheck]
    listener_started: bool
    forwarding_started: bool
    accepted_connections: int = 0
    upstream_connections: int = 0
    timed_out_connections: int = 0
    max_clients: int | None = None
    client_timeout: float | None = None
    performed_side_effects: bool = False


def run_proxy(
    config: MiGateConfig | None = None,
    *,
    doctor_loader: Callable[[MiGateConfig], ProxyRuntimeReport] | None = None,
    server_starter: Socks5ServerStarter | None = None,
    max_clients: int = 0,
    client_timeout: float = 5.0,
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

    serve_result = run_socks5_serve(
        cfg,
        dry_run=False,
        yes=True,
        allow_network_listen=True,
        max_clients=max_clients,
        client_timeout=client_timeout,
        server_starter=server_starter,
    )
    return ProxyRunResult(
        status="running" if serve_result.listener_started else serve_result.status,
        message="SOCKS5 listener started; direct upstream relay enabled" if serve_result.listener_started else serve_result.message,
        checks=doctor.checks,
        listener_started=serve_result.listener_started,
        forwarding_started=serve_result.listener_started,
        accepted_connections=serve_result.accepted_connections,
        upstream_connections=serve_result.upstream_connections,
        timed_out_connections=serve_result.timed_out_connections,
        max_clients=serve_result.max_clients,
        client_timeout=serve_result.client_timeout,
        performed_side_effects=serve_result.performed_side_effects,
    )


run_proxy_placeholder = run_proxy


def render_proxy_run_result(result: ProxyRunResult) -> str:
    lines = ["Proxy run", f"status: {result.status}", f"message: {result.message}"]
    lines.extend(f"{check.name}: {check.status} - {check.message}" for check in result.checks)
    lines.append(f"listener_started: {result.listener_started}")
    lines.append(f"forwarding_started: {result.forwarding_started}")
    lines.append(f"accepted_connections: {result.accepted_connections}")
    lines.append(f"upstream_connections: {result.upstream_connections}")
    lines.append(f"timed_out_connections: {result.timed_out_connections}")
    if result.max_clients is not None:
        lines.append(f"max_clients: {result.max_clients}")
    if result.client_timeout is not None:
        lines.append(f"client_timeout: {result.client_timeout}")
    lines.append(f"performed_side_effects: {result.performed_side_effects}")
    return "\n".join(lines)
