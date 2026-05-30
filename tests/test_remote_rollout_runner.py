from migate.remote.readiness import RemoteReadinessCheck, RemoteReadinessReport
from migate.remote.leak_check import RemoteLeakCheck, RemoteLeakCheckReport
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


def test_run_remote_rollout_plan_executes_install_readiness_egress_up_then_leak_check_with_injected_phases():
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

    def leak_check_runner():
        calls.append("leak_check")
        return RemoteLeakCheckReport(
            status="ok",
            target="root@166.88.232.2:22",
            native_public_ip="198.51.100.10",
            egress_public_ip="203.0.113.20",
            checks=[
                RemoteLeakCheck("native_ip", "ok", "198.51.100.10"),
                RemoteLeakCheck("egress_ip", "ok", "203.0.113.20"),
                RemoteLeakCheck("egress_guard", "ok", "egress guard passed"),
            ],
            commands_executed=["ssh leak-check"],
            performed_side_effects=False,
        )

    result = run_remote_rollout_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=install_runner,
        readiness_runner=readiness_runner,
        egress_up_runner=egress_up_runner,
        leak_check_runner=leak_check_runner,
    )

    assert result.status == "success"
    assert result.message == "remote rollout completed through injected phase runners"
    assert calls == ["install", "readiness", "egress_up", "leak_check"]
    assert [phase.action for phase in result.phases] == ["install", "readiness", "egress_up", "leak_check"]
    assert result.commands_executed == [
        "migate remote install --no-dry-run",
        "ssh readiness",
        "migate remote egress up --no-dry-run",
        "ssh leak-check",
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
        leak_check_runner=lambda: calls.append("leak_check"),
    )

    assert result.status == "failed"
    assert result.message == "remote rollout stopped at readiness"
    assert calls == ["install", "readiness"]
    assert [phase.action for phase in result.phases] == ["install", "readiness"]
    assert result.commands_executed == ["install command", "readiness command"]
    assert result.performed_side_effects is True


def test_run_remote_rollout_plan_stops_after_egress_when_leak_check_fails():
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
        readiness_runner=lambda: calls.append("readiness") or _ok_readiness(),
        egress_up_runner=lambda: calls.append("egress_up")
        or RemoteRolloutPhaseResult(
            action="egress_up",
            status="success",
            message="egress up",
            commands_executed=["egress command"],
            performed_side_effects=True,
        ),
        leak_check_runner=lambda: calls.append("leak_check")
        or RemoteLeakCheckReport(
            status="failed",
            target="root@166.88.232.2:22",
            native_public_ip="198.51.100.10",
            egress_public_ip="198.51.100.10",
            checks=[RemoteLeakCheck("egress_guard", "failed", "native_ip_leak_detected")],
            commands_executed=["leak check command"],
            performed_side_effects=False,
        ),
    )

    assert result.status == "failed"
    assert result.message == "remote rollout stopped at leak_check"
    assert calls == ["install", "readiness", "egress_up", "leak_check"]
    assert [phase.action for phase in result.phases] == ["install", "readiness", "egress_up", "leak_check"]
    assert result.commands_executed == ["install command", "ssh readiness", "egress command", "leak check command"]
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
        leak_check_runner=lambda: calls.append("leak_check"),
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
        leak_check_runner=lambda: RemoteLeakCheckReport(
            status="ok",
            target="root@166.88.232.2:22",
            native_public_ip="198.51.100.10",
            egress_public_ip="203.0.113.20",
            checks=[RemoteLeakCheck("egress_guard", "ok", "egress guard passed")],
            commands_executed=["leak check command"],
            performed_side_effects=False,
        ),
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
    assert "- leak_check: success - leak_check ok" in rendered
    assert "password" not in rendered.lower()
    assert "sshpass" not in rendered.lower()
