from migate.remote.readiness import RemoteReadinessCheck, RemoteReadinessReport
from migate.remote.rollout_plan import build_remote_rollout_dry_run_plan
from migate.remote.rollout_runner import (
    RemoteRolloutPhaseResult,
    RemoteRolloutRunResult,
    render_remote_rollout_run_result,
    run_remote_rollout_plan,
)


def _plan():
    return build_remote_rollout_dry_run_plan(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
    )


def _ok_readiness():
    return RemoteReadinessReport(
        status="ok",
        target="root@166.88.232.2:22",
        checks=[RemoteReadinessCheck("migate_cli", "ok", "/usr/local/bin/migate")],
        commands_executed=["ssh readiness"],
        performed_side_effects=False,
    )


def test_run_remote_rollout_plan_defaults_to_dry_run_and_calls_no_phases():
    calls = []

    result = run_remote_rollout_plan(
        _plan(),
        dry_run=True,
        yes=False,
        allow_remote_changes=False,
        install_runner=lambda: calls.append("install"),
        readiness_runner=lambda: calls.append("readiness"),
        egress_up_runner=lambda: calls.append("egress_up"),
    )

    assert result == RemoteRolloutRunResult(
        status="dry_run",
        message="remote rollout dry-run only; no rollout phases executed",
        target="root@166.88.232.2:22",
        phases=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_run_remote_rollout_plan_rejects_real_execution_without_double_gate():
    calls = []

    result = run_remote_rollout_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        install_runner=lambda: calls.append("install"),
        readiness_runner=lambda: calls.append("readiness"),
        egress_up_runner=lambda: calls.append("egress_up"),
    )

    assert result == RemoteRolloutRunResult(
        status="rejected",
        message="remote rollout requires yes=True and allow_remote_changes=True",
        target="root@166.88.232.2:22",
        phases=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_run_remote_rollout_plan_executes_install_readiness_then_egress_up_with_injected_phases():
    calls = []

    def install_runner():
        calls.append("install")
        return RemoteRolloutPhaseResult(
            action="install",
            status="success",
            message="installed",
            commands_executed=["migate remote install --no-dry-run"],
            performed_side_effects=True,
        )

    def readiness_runner():
        calls.append("readiness")
        return _ok_readiness()

    def egress_up_runner():
        calls.append("egress_up")
        return RemoteRolloutPhaseResult(
            action="egress_up",
            status="success",
            message="egress up",
            commands_executed=["migate remote egress up --no-dry-run"],
            performed_side_effects=True,
        )

    result = run_remote_rollout_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=install_runner,
        readiness_runner=readiness_runner,
        egress_up_runner=egress_up_runner,
    )

    assert result.status == "success"
    assert result.message == "remote rollout completed through injected phase runners"
    assert calls == ["install", "readiness", "egress_up"]
    assert [phase.action for phase in result.phases] == ["install", "readiness", "egress_up"]
    assert result.commands_executed == [
        "migate remote install --no-dry-run",
        "ssh readiness",
        "migate remote egress up --no-dry-run",
    ]
    assert result.performed_side_effects is True


def test_run_remote_rollout_plan_stops_before_egress_when_readiness_fails():
    calls = []

    result = run_remote_rollout_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=lambda: calls.append("install")
        or RemoteRolloutPhaseResult(
            action="install",
            status="success",
            message="installed",
            commands_executed=["install command"],
            performed_side_effects=True,
        ),
        readiness_runner=lambda: calls.append("readiness")
        or RemoteReadinessReport(
            status="failed",
            target="root@166.88.232.2:22",
            checks=[RemoteReadinessCheck("xray_bin", "failed", "missing xray")],
            commands_executed=["readiness command"],
            performed_side_effects=False,
        ),
        egress_up_runner=lambda: calls.append("egress_up"),
    )

    assert result.status == "failed"
    assert result.message == "remote rollout stopped at readiness"
    assert calls == ["install", "readiness"]
    assert [phase.action for phase in result.phases] == ["install", "readiness"]
    assert result.commands_executed == ["install command", "readiness command"]
    assert result.performed_side_effects is True


def test_run_remote_rollout_plan_rejects_rejected_plan_without_phase_calls():
    calls = []
    rejected_plan = build_remote_rollout_dry_run_plan(
        host="root:secret@166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
    )

    result = run_remote_rollout_plan(
        rejected_plan,
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=lambda: calls.append("install"),
        readiness_runner=lambda: calls.append("readiness"),
        egress_up_runner=lambda: calls.append("egress_up"),
    )

    assert result.status == "rejected"
    assert result.target == "[REDACTED]"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []
    rendered = render_remote_rollout_run_result(result)
    assert "embedded credentials are not allowed" in rendered
    assert "secret" not in rendered


def test_render_remote_rollout_run_result_is_structured_and_redacted():
    result = run_remote_rollout_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=lambda: RemoteRolloutPhaseResult("install", "success", "installed", ["install command"], True),
        readiness_runner=_ok_readiness,
        egress_up_runner=lambda: RemoteRolloutPhaseResult("egress_up", "success", "egress up", ["egress command"], True),
    )

    rendered = render_remote_rollout_run_result(result)

    assert "Remote rollout result" in rendered
    assert "status: success" in rendered
    assert "target: root@166.88.232.2:22" in rendered
    assert "commands_executed:" in rendered
    assert "performed_side_effects: True" in rendered
    assert "- install: success - installed" in rendered
    assert "- readiness: success - readiness ok" in rendered
    assert "- egress_up: success - egress up" in rendered
    assert "password" not in rendered.lower()
    assert "sshpass" not in rendered.lower()
