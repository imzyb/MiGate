from migate.config import MiGateConfig
from migate.proxy.run import ProxyRunResult, render_proxy_run_result, run_proxy_placeholder
from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport


def test_proxy_run_rejects_when_safety_preflight_fails():
    calls = []

    def doctor_loader(config: MiGateConfig) -> ProxyRuntimeReport:
        calls.append(config)
        return ProxyRuntimeReport(
            status="failed",
            checks=[ProxyRuntimeCheck("tun_interface", "failed", "tun-migate interface is missing")],
            performed_side_effects=False,
        )

    result = run_proxy_placeholder(MiGateConfig(), doctor_loader=doctor_loader)

    assert result == ProxyRunResult(
        status="rejected",
        message="proxy run preflight failed; listener not started",
        checks=[ProxyRuntimeCheck("tun_interface", "failed", "tun-migate interface is missing")],
        listener_started=False,
        forwarding_started=False,
        performed_side_effects=False,
    )
    assert len(calls) == 1


def test_proxy_run_placeholder_does_not_listen_even_when_preflight_passes():
    result = run_proxy_placeholder(
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
    )

    assert result.status == "placeholder"
    assert result.message == "proxy forwarding is not implemented yet; listener not started"
    assert result.listener_started is False
    assert result.forwarding_started is False
    assert result.performed_side_effects is False


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
