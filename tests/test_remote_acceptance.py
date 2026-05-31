from migate.remote.acceptance import (
    RemoteAcceptancePhaseResult,
    RemoteAcceptanceResult,
    render_remote_acceptance_result,
    run_remote_acceptance,
)
from migate.remote.doctor import RemoteDoctorCheck, RemoteDoctorReport
from migate.remote.rollout_runner import RemoteRolloutPhaseResult, RemoteRolloutRunResult
from migate.remote.rollout_smoke import RemoteRolloutSmokeResult


EXPECTED_PHASES = ["doctor", "rollout_smoke"]
ROLLOUT_PHASES = ["install", "readiness", "egress_up", "leak_check"]


def _ok_doctor() -> RemoteDoctorReport:
    return RemoteDoctorReport(
        status="ok",
        target="root@166.88.232.2:22",
        checks=[RemoteDoctorCheck("ssh_connectivity", "ok", "SSH probe succeeded")],
        commands_executed=["ssh doctor"],
        performed_side_effects=False,
    )


def _failed_doctor() -> RemoteDoctorReport:
    return RemoteDoctorReport(
        status="failed",
        target="root@166.88.232.2:22",
        checks=[RemoteDoctorCheck("ssh_connectivity", "failed", "Permission denied (publickey).")],
        commands_executed=["ssh doctor"],
        performed_side_effects=False,
    )


def _ok_smoke() -> RemoteRolloutSmokeResult:
    rollout_phases = [
        RemoteRolloutPhaseResult("install", "success", "installed", ["install command"], True),
        RemoteRolloutPhaseResult("readiness", "success", "readiness ok", ["readiness command"], False),
        RemoteRolloutPhaseResult("egress_up", "success", "egress up", ["egress command"], True),
        RemoteRolloutPhaseResult("leak_check", "success", "leak_check ok", ["leak check command"], False),
    ]
    rollout = RemoteRolloutRunResult(
        status="success",
        message="remote rollout completed through injected phase runners",
        target="root@166.88.232.2:22",
        phases=rollout_phases,
        commands_executed=[command for phase in rollout_phases for command in phase.commands_executed],
        performed_side_effects=True,
    )
    return RemoteRolloutSmokeResult(
        status="success",
        message="remote rollout smoke passed",
        target="root@166.88.232.2:22",
        expected_phases=ROLLOUT_PHASES,
        rollout=rollout,
        commands_executed=rollout.commands_executed,
        performed_side_effects=True,
    )


def _failed_smoke() -> RemoteRolloutSmokeResult:
    smoke = _ok_smoke()
    return RemoteRolloutSmokeResult(
        status="failed",
        message="remote rollout smoke failed: remote rollout stopped at leak_check",
        target=smoke.target,
        expected_phases=smoke.expected_phases,
        rollout=smoke.rollout,
        commands_executed=smoke.commands_executed,
        performed_side_effects=smoke.performed_side_effects,
    )


def test_remote_acceptance_defaults_to_dry_run_and_calls_no_runners():
    calls = []

    result = run_remote_acceptance(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=True,
        yes=False,
        allow_remote_changes=False,
        doctor_runner=lambda: calls.append("doctor") or _ok_doctor(),
        rollout_smoke_runner=lambda: calls.append("rollout_smoke") or _ok_smoke(),
    )

    assert result == RemoteAcceptanceResult(
        status="dry_run",
        message="remote acceptance dry-run only; no remote commands executed",
        target="root@166.88.232.2:22",
        expected_phases=EXPECTED_PHASES,
        phases=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_remote_acceptance_rejects_real_execution_without_double_gate():
    calls = []

    result = run_remote_acceptance(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        doctor_runner=lambda: calls.append("doctor") or _ok_doctor(),
        rollout_smoke_runner=lambda: calls.append("rollout_smoke") or _ok_smoke(),
    )

    assert result.status == "rejected"
    assert result.message == "remote acceptance requires yes=True and allow_remote_changes=True"
    assert result.phases == []
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []


def test_remote_acceptance_runs_doctor_then_rollout_smoke_with_double_gate():
    calls = []

    result = run_remote_acceptance(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        doctor_runner=lambda: calls.append("doctor") or _ok_doctor(),
        rollout_smoke_runner=lambda: calls.append("rollout_smoke") or _ok_smoke(),
    )

    assert result.status == "success"
    assert result.message == "remote acceptance passed"
    assert result.backend == "default"
    assert calls == ["doctor", "rollout_smoke"]
    assert [phase.name for phase in result.phases] == EXPECTED_PHASES
    assert result.phases == [
        RemoteAcceptancePhaseResult("doctor", "success", "remote doctor ok", _ok_doctor()),
        RemoteAcceptancePhaseResult("rollout_smoke", "success", "remote rollout smoke passed", _ok_smoke()),
    ]
    assert result.commands_executed == ["ssh doctor", "install command", "readiness command", "egress command", "leak check command"]
    assert result.performed_side_effects is True


def test_remote_acceptance_records_backend_override_for_operator_audit():
    result = run_remote_acceptance(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        backend="xray-tun",
        doctor_runner=_ok_doctor,
        rollout_smoke_runner=_ok_smoke,
    )

    assert result.status == "success"
    assert result.backend == "xray-tun"
    assert "backend: xray-tun" in render_remote_acceptance_result(result)


def test_remote_acceptance_stops_before_rollout_smoke_when_doctor_fails():
    calls = []

    result = run_remote_acceptance(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        doctor_runner=lambda: calls.append("doctor") or _failed_doctor(),
        rollout_smoke_runner=lambda: calls.append("rollout_smoke") or _ok_smoke(),
    )

    assert result.status == "failed"
    assert result.message == "remote acceptance stopped at doctor"
    assert calls == ["doctor"]
    assert result.phases == [RemoteAcceptancePhaseResult("doctor", "failed", "remote doctor failed", _failed_doctor())]
    assert result.commands_executed == ["ssh doctor"]
    assert result.performed_side_effects is False


def test_remote_acceptance_stops_when_rollout_smoke_fails():
    result = run_remote_acceptance(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        doctor_runner=_ok_doctor,
        rollout_smoke_runner=_failed_smoke,
    )

    assert result.status == "failed"
    assert result.message == "remote acceptance stopped at rollout_smoke"
    assert [phase.name for phase in result.phases] == EXPECTED_PHASES
    assert result.phases[-1] == RemoteAcceptancePhaseResult(
        "rollout_smoke",
        "failed",
        "remote rollout smoke failed: remote rollout stopped at leak_check",
        _failed_smoke(),
    )
    assert result.performed_side_effects is True


def test_remote_acceptance_rejects_embedded_credentials_before_runner_call():
    calls = []

    result = run_remote_acceptance(
        host="root:secret@166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        doctor_runner=lambda: calls.append("doctor") or _ok_doctor(),
        rollout_smoke_runner=lambda: calls.append("rollout_smoke") or _ok_smoke(),
    )

    assert result.status == "rejected"
    assert result.target == "[REDACTED]"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []
    rendered = render_remote_acceptance_result(result)
    assert "embedded credentials are not allowed" in rendered
    assert "secret" not in rendered


def test_remote_acceptance_rejects_embedded_credentials_but_preserves_backend_audit():
    result = run_remote_acceptance(
        host="root:secret@166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        backend="xray-tun",
        doctor_runner=_ok_doctor,
        rollout_smoke_runner=_ok_smoke,
    )

    rendered = render_remote_acceptance_result(result)

    assert result.status == "rejected"
    assert result.target == "[REDACTED]"
    assert result.backend == "xray-tun"
    assert "backend: xray-tun" in rendered
    assert "secret" not in rendered


def test_render_remote_acceptance_result_is_structured_and_redacted():
    result = run_remote_acceptance(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        doctor_runner=_ok_doctor,
        rollout_smoke_runner=_ok_smoke,
    )

    rendered = render_remote_acceptance_result(result)

    assert "Remote acceptance result" in rendered
    assert "status: success" in rendered
    assert "target: root@166.88.232.2:22" in rendered
    assert "expected_phases: ['doctor', 'rollout_smoke']" in rendered
    assert "- doctor: success - remote doctor ok" in rendered
    assert "- rollout_smoke: success - remote rollout smoke passed" in rendered
    assert "commands_executed: ['ssh doctor', 'install command', 'readiness command', 'egress command', 'leak check command']" in rendered
    assert "performed_side_effects: True" in rendered
    assert "password" not in rendered.lower()
    assert "secret" not in rendered.lower()
    assert "sshpass" not in rendered.lower()
