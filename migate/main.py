import typer

app = typer.Typer(help="MiGate smart egress gateway")


def run() -> None:
    app()
