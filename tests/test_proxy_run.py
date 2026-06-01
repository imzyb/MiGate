from migate.config import MiGateConfig
from migate.proxy.run import ProxyRunResult, render_proxy_run_result, run_proxy
from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport
from migate.proxy.socks5_listener import Socks5ServeResult


def test_run_proxy_legacy_placeholder_alias_points_to_runtime_entrypoint():
    from migate.proxy.run import run_proxy_placeholder

    assert run_proxy_placeholder is run_proxy


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


def test_proxy_run_rejects_xray_tun_upstream_guard_failures_without_starting_listener():
    config = MiGateConfig()
    config.egress.backend = "xray-tun"
    server_calls = []

    result = run_proxy(
        config,
        doctor_loader=lambda loaded_config: ProxyRuntimeReport(
            status="failed",
            checks=[
                ProxyRuntimeCheck("socks_listen", "failed", "127.0.0.1:34501 state is unknown"),
                ProxyRuntimeCheck(
                    "egress_guard",
                    "failed",
                    "required upstream proxy 127.0.0.1:34501 state is unknown; egress blocked",
                ),
            ],
            performed_side_effects=False,
        ),
        server_starter=lambda *_args, **_kwargs: server_calls.append("started"),
    )

    assert result == ProxyRunResult(
        status="rejected",
        message="proxy run preflight failed; listener not started",
        checks=[
            ProxyRuntimeCheck("socks_listen", "failed", "127.0.0.1:34501 state is unknown"),
            ProxyRuntimeCheck(
                "egress_guard",
                "failed",
                "required upstream proxy 127.0.0.1:34501 state is unknown; egress blocked",
            ),
        ],
        listener_started=False,
        forwarding_started=False,
        performed_side_effects=False,
    )
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
            accepted_connections=1,
            upstream_connections=1,
            timed_out_connections=0,
            max_clients=max_clients,
            client_timeout=client_timeout,
            events=[],
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
    assert result.performed_side_effects is True


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
