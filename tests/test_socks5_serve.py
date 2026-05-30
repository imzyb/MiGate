from migate.config import MiGateConfig
from migate.proxy.socks5_listener import (
    Socks5ServeResult,
    render_socks5_serve_result,
    run_socks5_serve_placeholder,
    start_socks5_placeholder_server,
)


def test_run_socks5_serve_placeholder_defaults_to_dry_run_without_listening():
    calls = []

    result = run_socks5_serve_placeholder(MiGateConfig(), server_starter=lambda *_args, **_kwargs: calls.append("called"))

    assert result == Socks5ServeResult(
        status="dry_run",
        message="SOCKS5 listener dry-run; no socket opened",
        bind_host="127.0.0.1",
        bind_port=34501,
        listener_started=False,
        accepted_connections=0,
        upstream_connections=0,
        max_clients=1,
        performed_side_effects=False,
    )
    assert calls == []


def test_run_socks5_serve_placeholder_rejects_real_listen_without_double_gate():
    calls = []

    result = run_socks5_serve_placeholder(
        MiGateConfig(),
        dry_run=False,
        yes=True,
        allow_network_listen=False,
        server_starter=lambda *_args, **_kwargs: calls.append("called"),
    )

    assert result.status == "rejected"
    assert result.listener_started is False
    assert result.performed_side_effects is False
    assert "requires yes=True and allow_network_listen=True" in result.message
    assert calls == []


def test_run_socks5_serve_placeholder_calls_injected_server_starter_only_when_double_gated():
    calls = []

    def fake_server_starter(host: str, port: int, max_clients: int):
        calls.append((host, port, max_clients))
        return Socks5ServeResult(
            status="listening_placeholder",
            message="SOCKS5 listener placeholder handled zero clients",
            bind_host=host,
            bind_port=port,
            listener_started=True,
            accepted_connections=0,
            upstream_connections=0,
            max_clients=max_clients,
            performed_side_effects=True,
        )

    result = run_socks5_serve_placeholder(
        MiGateConfig(),
        dry_run=False,
        yes=True,
        allow_network_listen=True,
        server_starter=fake_server_starter,
    )

    assert result.status == "listening_placeholder"
    assert result.listener_started is True
    assert result.upstream_connections == 0
    assert result.performed_side_effects is True
    assert calls == [("127.0.0.1", 34501, 1)]


def test_start_socks5_placeholder_server_delegates_to_asyncio_server(monkeypatch):
    calls = []

    async def fake_serve_once(host: str, port: int, max_clients: int):
        calls.append((host, port, max_clients))
        return Socks5ServeResult(
            status="stopped",
            message="handled one client",
            bind_host=host,
            bind_port=port,
            listener_started=True,
            accepted_connections=1,
            upstream_connections=0,
            max_clients=max_clients,
            performed_side_effects=True,
        )

    import migate.proxy.socks5_listener as listener_module

    monkeypatch.setattr(listener_module, "_serve_socks5_once", fake_serve_once)

    result = start_socks5_placeholder_server("127.0.0.1", 0, 1)

    assert result.status == "stopped"
    assert result.listener_started is True
    assert result.accepted_connections == 1
    assert result.upstream_connections == 0
    assert result.performed_side_effects is True
    assert calls == [("127.0.0.1", 0, 1)]


def test_render_socks5_serve_result_is_structured_and_mentions_no_upstream_connections():
    result = Socks5ServeResult(
        status="dry_run",
        message="SOCKS5 listener dry-run; no socket opened",
        bind_host="127.0.0.1",
        bind_port=34501,
        listener_started=False,
        accepted_connections=0,
        upstream_connections=0,
        max_clients=1,
        performed_side_effects=False,
    )

    text = render_socks5_serve_result(result)

    assert "SOCKS5 serve result" in text
    assert "status: dry_run" in text
    assert "listener_started: False" in text
    assert "accepted_connections: 0" in text
    assert "upstream_connections: 0" in text
    assert "max_clients: 1" in text
    assert "performed_side_effects: False" in text
