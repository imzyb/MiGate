from migate.config import MiGateConfig
import asyncio
import migate.proxy.run as proxy_run_module
from migate.proxy.run import ProxyRunResult, render_proxy_run_result, run_proxy
from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport
from migate.proxy.socks5_listener import Socks5ServeEvent, Socks5ServeResult


def test_upstream_connector_for_default_backend_uses_direct_relay():
    config = MiGateConfig()
    config.egress.backend = "openvpn"

    assert proxy_run_module._upstream_connector_for_backend(config) is None


def test_upstream_connector_for_xray_tun_sets_socket_mark(monkeypatch):
    config = MiGateConfig()
    config.egress.backend = "xray-tun"
    config.vpn.fwmark = "0x66"
    calls = []

    class FakeSocket:
        def __init__(self, family, sock_type):
            calls.append(("socket", family, sock_type))

        def setsockopt(self, level, optname, value):
            calls.append(("setsockopt", level, optname, value))

        def setblocking(self, value):
            calls.append(("setblocking", value))

        def close(self):
            calls.append(("close",))

    fake_reader = object()
    fake_writer = object()

    class FakeLoop:
        async def sock_connect(self, sock, address):
            calls.append(("sock_connect", sock, address))

    async def fake_wait_for(awaitable, *, timeout):
        calls.append(("wait_for", timeout))
        return await awaitable

    async def fake_open_connection(*, sock):
        calls.append(("open_connection", sock))
        return fake_reader, fake_writer

    monkeypatch.setattr(proxy_run_module.asyncio, "get_running_loop", lambda: FakeLoop())
    monkeypatch.setattr(proxy_run_module.asyncio, "wait_for", fake_wait_for)
    monkeypatch.setattr(proxy_run_module.asyncio, "open_connection", fake_open_connection)

    connector = proxy_run_module._upstream_connector_for_backend(config, socket_factory=FakeSocket)
    assert connector is not None
    reader, writer = asyncio.run(connector("203.0.113.10", 443, 0.5))

    assert reader is fake_reader
    assert writer is fake_writer
    assert ("setsockopt", proxy_run_module.socket.SOL_SOCKET, proxy_run_module.socket.SO_MARK, 0x66) in calls
    assert any(call[0] == "sock_connect" and call[2] == ("203.0.113.10", 443) for call in calls)


def test_proxy_run_no_longer_exports_placeholder_alias():
    assert proxy_run_module.run_proxy is run_proxy
    assert not hasattr(proxy_run_module, "run_proxy_placeholder")


def test_proxy_run_rejects_when_safety_preflight_fails():
    calls = []
    server_calls = []

    def doctor_loader(config: MiGateConfig) -> ProxyRuntimeReport:
        calls.append(config)
        return ProxyRuntimeReport(
            status="failed",
            checks=[ProxyRuntimeCheck("tun_interface", "failed", "tun-migate interface is missing")],
            performed_side_effects=False,
        )

    result = run_proxy(
        MiGateConfig(),
        doctor_loader=doctor_loader,
        server_starter=lambda *_args, **_kwargs: server_calls.append("started"),
    )

    assert result == ProxyRunResult(
        status="rejected",
        message="proxy run preflight failed; listener not started",
        checks=[ProxyRuntimeCheck("tun_interface", "failed", "tun-migate interface is missing")],
        listener_started=False,
        forwarding_started=False,
        performed_side_effects=False,
    )
    assert len(calls) == 1
    assert server_calls == []


def test_proxy_run_xray_tun_ignores_own_listener_preflight_before_starting_listener():
    config = MiGateConfig()
    config.egress.backend = "xray-tun"
    server_calls = []

    def fake_server_starter(host: str, port: int, max_clients: int, client_timeout: float) -> Socks5ServeResult:
        server_calls.append((host, port, max_clients, client_timeout))
        return Socks5ServeResult(
            status="stopped",
            message="SOCKS5 listener handled one client with direct upstream relay",
            bind_host=host,
            bind_port=port,
            listener_started=True,
            accepted_connections=1,
            upstream_connections=1,
            timed_out_connections=0,
            max_clients=max_clients,
            client_timeout=client_timeout,
            events=[],
            performed_side_effects=True,
        )

    result = run_proxy(
        config,
        doctor_loader=lambda loaded_config: ProxyRuntimeReport(
            status="failed",
            checks=[
                ProxyRuntimeCheck("socks_listen", "failed", "127.0.0.1:34501 state is unknown"),
                ProxyRuntimeCheck("http_listen", "failed", "127.0.0.1:34502 is not listening"),
                ProxyRuntimeCheck("tun_interface", "ok", "tun-migate interface exists"),
                ProxyRuntimeCheck("fail_policy", "ok", "fail_policy is block"),
                ProxyRuntimeCheck("leak_guard", "ok", "leak_guard is enabled"),
                ProxyRuntimeCheck("tunnel_process", "ok", "xray-tun tunnel for tun-migate is running"),
                ProxyRuntimeCheck(
                    "egress_guard",
                    "failed",
                    "required upstream proxy 127.0.0.1:34501 state is unknown; egress blocked",
                ),
            ],
            performed_side_effects=False,
        ),
        server_starter=fake_server_starter,
        max_clients=1,
        client_timeout=0.25,
    )

    assert result.status == "running"
    assert result.listener_started is True
    assert result.forwarding_started is True
    assert server_calls == [("127.0.0.1", 34501, 1, 0.25)]


def test_proxy_run_xray_tun_still_blocks_when_tunnel_prerequisites_fail():
    config = MiGateConfig()
    config.egress.backend = "xray-tun"
    server_calls = []

    result = run_proxy(
        config,
        doctor_loader=lambda loaded_config: ProxyRuntimeReport(
            status="failed",
            checks=[
                ProxyRuntimeCheck("socks_listen", "failed", "127.0.0.1:34501 state is unknown"),
                ProxyRuntimeCheck("tun_interface", "failed", "tun-migate interface is missing"),
                ProxyRuntimeCheck("tunnel_process", "failed", "xray-tun tunnel for tun-migate is not running"),
            ],
            performed_side_effects=False,
        ),
        server_starter=lambda *_args, **_kwargs: server_calls.append("started"),
    )

    assert result.status == "rejected"
    assert result.listener_started is False
    assert server_calls == []


def test_proxy_run_xray_tun_passes_marked_upstream_connector_to_socks5_runtime(monkeypatch):
    config = MiGateConfig()
    config.egress.backend = "xray-tun"
    calls = []

    def fake_serve(config_arg, **kwargs):
        calls.append((config_arg, kwargs))
        return Socks5ServeResult(
            status="stopped",
            message="SOCKS5 listener handled one client with marked upstream relay",
            bind_host=config_arg.proxy.socks_host,
            bind_port=config_arg.proxy.socks_port,
            listener_started=True,
            accepted_connections=1,
            upstream_connections=1,
            timed_out_connections=0,
            max_clients=kwargs["max_clients"],
            client_timeout=kwargs["client_timeout"],
            events=[],
            performed_side_effects=True,
        )

    monkeypatch.setattr(proxy_run_module, "run_socks5_serve", fake_serve)

    result = run_proxy(
        config,
        doctor_loader=lambda loaded_config: ProxyRuntimeReport(
            status="ok",
            checks=[
                ProxyRuntimeCheck("tun_interface", "ok", "tun-migate interface exists"),
                ProxyRuntimeCheck("fail_policy", "ok", "fail_policy is block"),
                ProxyRuntimeCheck("leak_guard", "ok", "leak_guard is enabled"),
                ProxyRuntimeCheck("tunnel_process", "ok", "xray-tun tunnel for tun-migate is running"),
            ],
            performed_side_effects=False,
        ),
        max_clients=1,
        client_timeout=0.25,
    )

    assert result.status == "running"
    assert len(calls) == 1
    assert calls[0][1]["upstream_connector"] is not None
    assert calls[0][1]["upstream_connector"].__name__ == "connect_with_fwmark"


def test_proxy_run_starts_local_socks_listener_when_preflight_passes():
    calls: list[tuple[str, int, int, float]] = []

    def fake_server_starter(host: str, port: int, max_clients: int, client_timeout: float) -> Socks5ServeResult:
        calls.append((host, port, max_clients, client_timeout))
        return Socks5ServeResult(
            status="stopped",
            message="SOCKS5 listener handled one client with direct upstream relay",
            bind_host=host,
            bind_port=port,
            listener_started=True,
            accepted_connections=2,
            upstream_connections=1,
            timed_out_connections=1,
            max_clients=max_clients,
            client_timeout=client_timeout,
            events=[
                Socks5ServeEvent(
                    client_id=1,
                    phase="connect",
                    status="accepted",
                    target_host="127.0.0.1",
                    target_port=8080,
                    upstream_connected=True,
                    bytes_from_client=4,
                    bytes_from_upstream=4,
                ),
                Socks5ServeEvent(
                    client_id=2,
                    phase="greeting",
                    status="timed_out",
                    target_host=None,
                    target_port=None,
                    upstream_connected=False,
                ),
            ],
            performed_side_effects=True,
        )

    result = run_proxy(
        MiGateConfig(),
        doctor_loader=lambda config: ProxyRuntimeReport(
            status="ok",
            checks=[
                ProxyRuntimeCheck("tun_interface", "ok", "tun-migate interface exists"),
                ProxyRuntimeCheck("fail_policy", "ok", "fail_policy is block"),
                ProxyRuntimeCheck("leak_guard", "ok", "leak_guard is enabled"),
            ],
            performed_side_effects=False,
        ),
        server_starter=fake_server_starter,
        client_timeout=0.25,
    )

    assert calls == [("127.0.0.1", 34501, 0, 0.25)]
    assert result.status == "running"
    assert result.message == "SOCKS5 listener started; direct upstream relay enabled"
    assert result.listener_started is True
    assert result.forwarding_started is True
    assert result.accepted_connections == 2
    assert result.upstream_connections == 1
    assert result.timed_out_connections == 1
    assert result.max_clients == 0
    assert result.serve_mode == "continuous"
    assert result.client_timeout == 0.25
    assert len(result.events) == 2
    assert result.events[0].status == "accepted"
    assert result.events[0].bytes_from_client == 4
    assert result.events[0].bytes_from_upstream == 4
    assert result.performed_side_effects is True


def test_render_proxy_run_result_includes_runtime_counters_when_listener_runs():
    result = ProxyRunResult(
        status="running",
        message="SOCKS5 listener started; direct upstream relay enabled",
        checks=[ProxyRuntimeCheck("fail_policy", "ok", "fail_policy is block")],
        listener_started=True,
        forwarding_started=True,
        accepted_connections=2,
        upstream_connections=1,
        timed_out_connections=1,
        max_clients=0,
        serve_mode="continuous",
        client_timeout=0.25,
        events=[
            Socks5ServeEvent(
                client_id=1,
                phase="connect",
                status="accepted",
                target_host="127.0.0.1",
                target_port=8080,
                upstream_connected=True,
                bytes_from_client=4,
                bytes_from_upstream=4,
            ),
            Socks5ServeEvent(
                client_id=2,
                phase="greeting",
                status="timed_out",
                target_host=None,
                target_port=None,
                upstream_connected=False,
            ),
        ],
        performed_side_effects=True,
    )

    rendered = render_proxy_run_result(result)

    assert "accepted_connections: 2" in rendered
    assert "upstream_connections: 1" in rendered
    assert "timed_out_connections: 1" in rendered
    assert "max_clients: 0" in rendered
    assert "serve_mode: continuous" in rendered
    assert "client_timeout: 0.25" in rendered
    assert "event[1]: client_id=1 phase=connect status=accepted target=127.0.0.1:8080 upstream_connected=True bytes_from_client=4 bytes_from_upstream=4" in rendered
    assert "event[2]: client_id=2 phase=greeting status=timed_out target=n/a upstream_connected=False bytes_from_client=0 bytes_from_upstream=0" in rendered


def test_render_proxy_run_result_is_structured():
    result = ProxyRunResult(
        status="rejected",
        message="proxy run preflight failed; listener not started",
        checks=[ProxyRuntimeCheck("leak_guard", "failed", "leak_guard is disabled")],
        listener_started=False,
        forwarding_started=False,
        performed_side_effects=False,
    )

    rendered = render_proxy_run_result(result)

    assert "Proxy run" in rendered
    assert "status: rejected" in rendered
    assert "message: proxy run preflight failed; listener not started" in rendered
    assert "leak_guard: failed - leak_guard is disabled" in rendered
    assert "listener_started: False" in rendered
    assert "forwarding_started: False" in rendered
    assert "performed_side_effects: False" in rendered
