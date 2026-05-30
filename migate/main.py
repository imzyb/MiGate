from __future__ import annotations

from dataclasses import dataclass

import typer
import uvicorn

from migate.config import MiGateConfig

app = typer.Typer(help="MiGate smart egress gateway")


@app.callback()
def cli() -> None:
    """MiGate command line interface."""


@dataclass(frozen=True)
class PanelServerConfig:
    app: str
    host: str
    port: int
    factory: bool = True


def build_panel_server_config(host: str, port: int) -> PanelServerConfig:
    return PanelServerConfig(app="migate.api.app:create_app", host=host, port=port, factory=True)


@app.command()
def panel(
    host: str = typer.Option(MiGateConfig().security.web_bind, help="Panel bind host."),
    port: int = typer.Option(MiGateConfig().security.web_port, help="Panel bind port."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print server settings without starting uvicorn."),
) -> None:
    server = build_panel_server_config(host=host, port=port)
    if dry_run:
        typer.echo(f"MiGate panel: uvicorn {server.app} --factory --host {server.host} --port {server.port}")
        return
    uvicorn.run(server.app, host=server.host, port=server.port, factory=server.factory)


def run() -> None:
    app()
