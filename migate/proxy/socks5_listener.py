"""Side-effect-free SOCKS5 listener planning.

The real TCP listener is not implemented in this layer. This module only
materializes the intended bind address and runtime wiring so the future network
server can be introduced behind a tested contract.
"""

from __future__ import annotations

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
