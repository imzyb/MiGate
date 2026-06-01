from migate.remote.acceptance import RemoteAcceptanceResult
from migate.remote.doctor import RemoteDoctorCheck, RemoteDoctorReport
from migate.remote.lifecycle_runner import (
    RemoteLifecyclePhaseResult,
    RemoteLifecycleRunResult,
    render_remote_lifecycle_run_result,
    run_remote_lifecycle,
)


def _ok_doctor() -> RemoteDoctorReport:
    return RemoteDoctorReport(
        status="ok",
        target="root@166.88.232.2:22",
        checks=[RemoteDoctorCheck("ssh_connectivity", "ok", "SSH probe succeeded")],
        commands_executed=["ssh -p 22 root@166.88.232.2 ..."],
        performed_side_effects=False,
    )


def _failed_doctor() -> RemoteDoctorReport:
    return RemoteDoctorReport(
        status="failed",
        target="root@166.88.232.2:22",
        checks=[RemoteDoctorCheck("ssh_connectivity", "failed", "Permission denied (publickey).")],
        commands_executed=["ssh -p 22 root@166.88.232.2 ..."],
        performed_side_effects=False,
    )


def _ok_acceptance() -> RemoteAcceptanceResult:
    return RemoteAcceptanceResult(
        status="success",
        message="remote acceptance passed",
        target="root@166.88.232.2:22",
        expected_phases=["doctor", "rollout_smoke"],
        phases=[],
        commands_executed=["acceptance command"],
        performed_side_effects=True,
        backend="xray-tun",
    )


def _failed_acceptance() -> RemoteAcceptanceResult:
    return RemoteAcceptanceResult(
        status="failed",
        message="remote acceptance stopped at rollout_smoke",
        target="root@166.88.232.2:22",
        expected_phases=["doctor", "rollout_smoke"],
        phases=[],
        commands_executed=["acceptance command"],
        performed_side_effects=True,
        backend="xray-tun",
    )


def test_run_remote_lifecycle_defaults_to_dry_run_and_calls_no_runner():
    calls = []

    result = run_remote_lifecycle(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=True,
        yes=False,
        allow_remote_changes=False,
        doctor_runner=lambda: calls.append("doctor") or _ok_doctor(),
    )

    assert result.status == "dry_run"
    assert result.message == "remote lifecycle dry-run only; no remote commands executed"
    assert result.target == "root@166.88.232.2:22"
    assert result.phases == []
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []


def test_run_remote_lifecycle_rejects_real_execution_without_double_gate():
    calls = []

    result = run_remote_lifecycle(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        doctor_runner=lambda: calls.append("doctor") or _ok_doctor(),
    )

    assert result == RemoteLifecycleRunResult(
        status="rejected",
        message="remote lifecycle requires yes=True and allow_remote_changes=True",
        target="root@166.88.232.2:22",
        phases=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_run_remote_lifecycle_runs_doctor_then_acceptance_with_double_gate():
    calls = []

    result = run_remote_lifecycle(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        doctor_runner=lambda: calls.append("doctor") or _ok_doctor(),
        acceptance_runner=lambda: calls.append("acceptance") or _ok_acceptance(),
    )

    assert result == RemoteLifecycleRunResult(
        status="success",
        message="remote lifecycle completed through acceptance",
        target="root@166.88.232.2:22",
        phases=[
            RemoteLifecyclePhaseResult("doctor", "success", "remote doctor ok", _ok_doctor()),
            RemoteLifecyclePhaseResult("acceptance", "success", "remote acceptance passed", _ok_acceptance()),
        ],
        commands_executed=["ssh -p 22 root@166.88.232.2 ...", "acceptance command"],
        performed_side_effects=True,
    )
    assert calls == ["doctor", "acceptance"]


def test_run_remote_lifecycle_stops_when_acceptance_fails():
    result = run_remote_lifecycle(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        doctor_runner=_ok_doctor,
        acceptance_runner=_failed_acceptance,
    )

    assert result.status == "failed"
    assert result.message == "remote lifecycle stopped at acceptance"
    assert result.phases == [
        RemoteLifecyclePhaseResult("doctor", "success", "remote doctor ok", _ok_doctor()),
        RemoteLifecyclePhaseResult("acceptance", "failed", "remote acceptance stopped at rollout_smoke", _failed_acceptance()),
    ]
    assert result.commands_executed == ["ssh -p 22 root@166.88.232.2 ...", "acceptance command"]
    assert result.performed_side_effects is True


def test_run_remote_lifecycle_stops_when_doctor_fails():
    result = run_remote_lifecycle(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        doctor_runner=_failed_doctor,
    )

    assert result.status == "failed"
    assert result.message == "remote lifecycle stopped at doctor"
    assert result.phases == [RemoteLifecyclePhaseResult("doctor", "failed", "remote doctor failed", _failed_doctor())]
    assert result.commands_executed == ["ssh -p 22 root@166.88.232.2 ..."]
    assert result.performed_side_effects is False


def test_run_remote_lifecycle_rejects_embedded_credentials_before_runner_call():
    calls = []

    result = run_remote_lifecycle(
        host="root:secret@166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        doctor_runner=lambda: calls.append("doctor") or _ok_doctor(),
    )

    assert result.status == "rejected"
    assert result.target == "[REDACTED]"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []
    rendered = render_remote_lifecycle_run_result(result)
    assert "embedded credentials are not allowed" in rendered
    assert "secret" not in rendered


def test_render_remote_lifecycle_run_result_is_structured_and_redacted():
    result = run_remote_lifecycle(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        doctor_runner=_ok_doctor,
        acceptance_runner=_ok_acceptance,
    )

    rendered = render_remote_lifecycle_run_result(result)

    assert "Remote lifecycle result" in rendered
    assert "status: success" in rendered
    assert "target: root@166.88.232.2:22" in rendered
    assert "- doctor: success - remote doctor ok" in rendered
    assert "- acceptance: success - remote acceptance passed" in rendered
    assert "performed_side_effects: True" in rendered
    assert "not implemented" not in rendered
    assert "password" not in rendered.lower()
    assert "sshpass" not in rendered.lower()
