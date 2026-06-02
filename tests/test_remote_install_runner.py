from migate.remote.install_plan import build_remote_install_dry_run_plan
from migate.remote.install_runner import (
    RemoteInstallCommandResult,
    RemoteInstallRunResult,
    RemoteInstallStepResult,
    render_remote_install_run_result,
    run_remote_install_plan,
)


def _plan():
    return build_remote_install_dry_run_plan(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
    )


def test_run_remote_install_plan_defaults_to_dry_run_and_calls_no_runner():
    calls = []

    result = run_remote_install_plan(
        _plan(),
        dry_run=True,
        yes=False,
        allow_remote_changes=False,
        runner=lambda command: calls.append(command) or RemoteInstallCommandResult(0, "ok", ""),
    )

    assert result == RemoteInstallRunResult(
        status="dry_run",
        message="remote install dry-run only; no remote commands executed",
        target="root@166.88.232.2:22",
        steps=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_run_remote_install_plan_rejects_real_execution_without_double_gate():
    calls = []

    result = run_remote_install_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        runner=lambda command: calls.append(command) or RemoteInstallCommandResult(0, "ok", ""),
    )

    assert result == RemoteInstallRunResult(
        status="rejected",
        message="remote install requires yes=True and allow_remote_changes=True",
        target="root@166.88.232.2:22",
        steps=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_run_remote_install_plan_executes_planned_steps_in_order_with_injected_runner():
    calls = []

    def runner(command: str) -> RemoteInstallCommandResult:
        calls.append(command)
        return RemoteInstallCommandResult(returncode=0, stdout="ok", stderr="")

    result = run_remote_install_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        runner=runner,
    )

    assert result.status == "success"
    assert result.message == "remote install completed through injected runner"
    assert result.target == "root@166.88.232.2:22"
    assert result.performed_side_effects is True
    assert calls == [step.command_preview for step in _plan().steps]
    assert result.commands_executed == calls
    assert [step.action for step in result.steps] == [step.action for step in _plan().steps]
    assert all(step.status == "success" for step in result.steps)


def test_run_remote_install_plan_stops_on_first_failed_step():
    calls = []

    def runner(command: str) -> RemoteInstallCommandResult:
        calls.append(command)
        if "pip install" in command and "migate-install" in command:
            return RemoteInstallCommandResult(returncode=1, stdout="", stderr="pip failed")
        return RemoteInstallCommandResult(returncode=0, stdout="ok", stderr="")

    result = run_remote_install_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        runner=runner,
    )

    assert result.status == "failed"
    assert result.message == "remote install stopped at install_python_package"
    assert result.performed_side_effects is True
    assert len(result.steps) == 3
    assert result.steps[-1] == RemoteInstallStepResult(
        action="install_python_package",
        description="install MiGate package system-wide on remote host",
        status="failed",
        command="ssh -p 22 root@166.88.232.2 -- 'cd /tmp/migate-install && python3 -m pip install --break-system-packages --root-user-action=ignore .'",
        returncode=1,
        stdout="",
        stderr="pip failed",
    )
    assert len(calls) == 3


def test_run_remote_install_plan_rejects_rejected_plan_without_runner_call():
    calls = []
    rejected_plan = build_remote_install_dry_run_plan(
        host="root:secret@166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
    )

    result = run_remote_install_plan(
        rejected_plan,
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        runner=lambda command: calls.append(command) or RemoteInstallCommandResult(0, "ok", ""),
    )

    assert result.status == "rejected"
    assert result.target == "[REDACTED]"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []
    rendered = render_remote_install_run_result(result)
    assert "embedded credentials are not allowed" in rendered
    assert "secret" not in rendered


def test_render_remote_install_run_result_is_structured_and_redacted():
    result = run_remote_install_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        runner=lambda command: RemoteInstallCommandResult(returncode=0, stdout="ok", stderr=""),
    )

    rendered = render_remote_install_run_result(result)

    assert "Remote install result" in rendered
    assert "status: success" in rendered
    assert "target: root@166.88.232.2:22" in rendered
    assert "commands_executed:" in rendered
    assert "performed_side_effects: True" in rendered
    assert "- sync_project: success returncode=0" in rendered
    assert "password" not in rendered.lower()
    assert "sshpass" not in rendered.lower()
