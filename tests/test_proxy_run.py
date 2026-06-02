from migate.config import MiGateConfig
import migate.proxy.run as proxy_run_module
from migate.proxy.run import ProxyRunResult, render_proxy_run_result, run_proxy
from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport
from migate.proxy.socks5_listener import Socks5ServeEvent, Socks5ServeResult


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
