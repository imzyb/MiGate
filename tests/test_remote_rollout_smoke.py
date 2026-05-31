from migate.remote.rollout_plan import build_remote_rollout_dry_run_plan
from migate.remote.rollout_runner import RemoteRolloutPhaseResult, RemoteRolloutRunResult
from migate.remote.rollout_smoke import (
    RemoteRolloutSmokeResult,
    render_remote_rollout_smoke_result,
    run_remote_rollout_smoke,
)


EXPECTED_PHASES = ["install", "readiness", "egress_up", "service_apply", "socks5_smoke", "leak_check"]


def _plan():
    return build_remote_rollout_dry_run_plan(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
    )


def _phase(action: str, *, status: str = "success", side_effects: bool = False) -> RemoteRolloutPhaseResult:
    return RemoteRolloutPhaseResult(
        action=action,
        status=status,
        message=f"{action} {status}",
        commands_executed=[f"{action} command"],
        performed_side_effects=side_effects,
    )


def _successful_rollout() -> RemoteRolloutRunResult:
    phases = [
        _phase("install", side_effects=True),
        _phase("readiness"),
        _phase("egress_up", side_effects=True),
        _phase("service_apply", side_effects=True),
        _phase("socks5_smoke"),
        _phase("leak_check"),
    ]
    return RemoteRolloutRunResult(
        status="success",
        message="remote rollout completed through injected phase runners",
        target="root@166.88.232.2:22",
        phases=phases,
        commands_executed=[command for phase in phases for command in phase.commands_executed],
        performed_side_effects=True,
    )


def test_remote_rollout_smoke_defaults_to_dry_run_and_calls_no_rollout_runner():
    calls = []

    result = run_remote_rollout_smoke(
        _plan(),
        dry_run=True,
        yes=False,
        allow_remote_changes=False,
        rollout_runner=lambda: calls.append("rollout"),
    )

    assert result == RemoteRolloutSmokeResult(
        status="dry_run",
        message="remote rollout smoke dry-run only; no rollout executed",
        target="root@166.88.232.2:22",
        expected_phases=EXPECTED_PHASES,
        rollout=None,
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_remote_rollout_smoke_rejects_real_execution_without_double_gate():
    calls = []

    result = run_remote_rollout_smoke(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        rollout_runner=lambda: calls.append("rollout"),
    )

    assert result.status == "rejected"
    assert result.message == "remote rollout smoke requires yes=True and allow_remote_changes=True"
    assert result.rollout is None
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []


def test_remote_rollout_smoke_passes_when_rollout_reaches_expected_service_and_smoke_phases():
    calls = []

    result = run_remote_rollout_smoke(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        rollout_runner=lambda: calls.append("rollout") or _successful_rollout(),
    )

    assert result.status == "success"
    assert result.message == "remote rollout smoke passed"
    assert calls == ["rollout"]
    assert result.expected_phases == EXPECTED_PHASES
    assert result.commands_executed == [
        "install command",
        "readiness command",
        "egress_up command",
        "service_apply command",
        "socks5_smoke command",
        "leak_check command",
    ]
    assert result.performed_side_effects is True


def test_remote_rollout_smoke_fails_when_rollout_fails():
    rollout = RemoteRolloutRunResult(
        status="failed",
        message="remote rollout stopped at leak_check",
        target="root@166.88.232.2:22",
        phases=[
            _phase("install", side_effects=True),
            _phase("readiness"),
            _phase("egress_up", side_effects=True),
            _phase("service_apply", side_effects=True),
            _phase("socks5_smoke"),
            _phase("leak_check", status="failed"),
        ],
        commands_executed=["install command", "readiness command", "egress_up command", "service_apply command", "socks5_smoke command", "leak_check command"],
        performed_side_effects=True,
    )

    result = run_remote_rollout_smoke(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        rollout_runner=lambda: rollout,
    )

    assert result.status == "failed"
    assert result.message == "remote rollout smoke failed: remote rollout stopped at leak_check"
    assert result.rollout == rollout
    assert result.commands_executed == rollout.commands_executed
    assert result.performed_side_effects is True


def test_remote_rollout_smoke_fails_when_service_smoke_phase_is_missing():
    rollout = RemoteRolloutRunResult(
        status="success",
        message="remote rollout completed but old phase list was returned",
        target="root@166.88.232.2:22",
        phases=[
            _phase("install", side_effects=True),
            _phase("readiness"),
            _phase("egress_up", side_effects=True),
        ],
        commands_executed=["install command", "readiness command", "egress_up command"],
        performed_side_effects=True,
    )

    result = run_remote_rollout_smoke(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        rollout_runner=lambda: rollout,
    )

    assert result.status == "failed"
    assert result.message == "remote rollout smoke expected phases install -> readiness -> egress_up -> service_apply -> socks5_smoke -> leak_check"
    assert result.rollout == rollout
    assert result.commands_executed == rollout.commands_executed
    assert result.performed_side_effects is True


def test_remote_rollout_smoke_rejects_rejected_plan_without_rollout_runner():
    calls = []
    plan = build_remote_rollout_dry_run_plan(
        host="root:secret@203.0.113.10",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
    )

    result = run_remote_rollout_smoke(
        plan,
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        rollout_runner=lambda: calls.append("rollout"),
    )

    assert result.status == "rejected"
    assert result.target == "[REDACTED]"
    assert result.rollout is None
    assert calls == []


def test_render_remote_rollout_smoke_result_is_structured_and_redacted():
    result = run_remote_rollout_smoke(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        rollout_runner=_successful_rollout,
    )

    rendered = render_remote_rollout_smoke_result(result)

    assert "Remote rollout smoke result" in rendered
    assert "status: success" in rendered
    assert "expected_phases: ['install', 'readiness', 'egress_up', 'service_apply', 'socks5_smoke', 'leak_check']" in rendered
    assert "rollout_status: success" in rendered
    assert "- service_apply: success - service_apply success" in rendered
    assert "- socks5_smoke: success - socks5_smoke success" in rendered
    assert "- leak_check: success - leak_check success" in rendered
    assert "commands_executed: ['install command', 'readiness command', 'egress_up command', 'service_apply command', 'socks5_smoke command', 'leak_check command']" in rendered
    assert "password" not in rendered.lower()
    assert "secret" not in rendered.lower()
    assert "sshpass" not in rendered.lower()
