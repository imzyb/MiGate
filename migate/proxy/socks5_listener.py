"""Side-effect-free SOCKS5 listener planning.

The real TCP listener is not implemented in this layer. This module only
materializes the intended bind address and runtime wiring so the future network
server can be introduced behind a tested contract.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from migate.config import MiGateConfig

SOCKS5_LISTENER_BIND_HOST = "127.0.0.1"
SOCKS5_LISTENER_BIND_PORT = 34501


@dataclass(frozen=True)
class Socks5ListenerPlan:
    bind_host: str
    bind_port: int
    protocol: str
    connection_driver: str
    upstream_mode: str
    will_listen: bool
    will_connect_upstream: bool
    performed_side_effects: bool


@dataclass(frozen=True)
class Socks5ServeResult:
    status: str
    message: str
    bind_host: str
    bind_port: int
    listener_started: bool
    accepted_connections: int
    upstream_connections: int
    performed_side_effects: bool


Socks5ServerStarter = Callable[[str, int], Socks5ServeResult]


def build_socks5_listener_plan(config: MiGateConfig) -> Socks5ListenerPlan:
    return Socks5ListenerPlan(
        bind_host=config.proxy.socks_host,
        bind_port=config.proxy.socks_port,
        protocol="socks5",
        connection_driver="Socks5Connection",
        upstream_mode="not_implemented",
        will_listen=False,
        will_connect_upstream=False,
        performed_side_effects=False,
    )


def render_socks5_listener_plan(plan: Socks5ListenerPlan) -> str:
    return "\n".join(
        [
            "SOCKS5 listener plan",
            f"bind_host: {plan.bind_host}",
            f"bind_port: {plan.bind_port}",
            f"protocol: {plan.protocol}",
            f"connection_driver: {plan.connection_driver}",
            f"upstream_mode: {plan.upstream_mode}",
            f"will_listen: {plan.will_listen}",
            f"will_connect_upstream: {plan.will_connect_upstream}",
            f"performed_side_effects: {plan.performed_side_effects}",
        ]
    )


def run_socks5_serve_placeholder(
    config: MiGateConfig,
    *,
    dry_run: bool = True,
    yes: bool = False,
    allow_network_listen: bool = False,
    server_starter: Socks5ServerStarter | None = None,
) -> Socks5ServeResult:
    bind_host = config.proxy.socks_host
    bind_port = config.proxy.socks_port
    if dry_run:
        return Socks5ServeResult(
            status="dry_run",
            message="SOCKS5 listener dry-run; no socket opened",
            bind_host=bind_host,
            bind_port=bind_port,
            listener_started=False,
            accepted_connections=0,
            upstream_connections=0,
            performed_side_effects=False,
        )
    if not yes or not allow_network_listen:
        return Socks5ServeResult(
            status="rejected",
            message="SOCKS5 listener requires yes=True and allow_network_listen=True",
            bind_host=bind_host,
            bind_port=bind_port,
            listener_started=False,
            accepted_connections=0,
            upstream_connections=0,
            performed_side_effects=False,
        )
    starter = server_starter or start_socks5_placeholder_server
    return starter(bind_host, bind_port)


def start_socks5_placeholder_server(bind_host: str, bind_port: int) -> Socks5ServeResult:
    return Socks5ServeResult(
        status="listening_placeholder",
        message="SOCKS5 listener placeholder is not wired to asyncio yet",
        bind_host=bind_host,
        bind_port=bind_port,
        listener_started=False,
        accepted_connections=0,
        upstream_connections=0,
        performed_side_effects=False,
    )


def render_socks5_serve_result(result: Socks5ServeResult) -> str:
    return "\n".join(
        [
            "SOCKS5 serve result",
            f"status: {result.status}",
            f"message: {result.message}",
            f"bind_host: {result.bind_host}",
            f"bind_port: {result.bind_port}",
            f"listener_started: {result.listener_started}",
            f"accepted_connections: {result.accepted_connections}",
            f"upstream_connections: {result.upstream_connections}",
            f"performed_side_effects: {result.performed_side_effects}",
        ]
    )
