from migate.config import MiGateConfig
from migate.xray.install_plan import build_xray_install_plan
from migate.xray.install_runner import (
    XrayInstallCommandResult,
    XrayInstallResult,
    XrayInstallRollbackStep,
    run_xray_install_plan,
)


def test_run_xray_install_plan_executes_steps_in_order_with_injected_runner():
    plan = build_xray_install_plan(MiGateConfig(), system="Linux", machine="x86_64", version="v1.8.24")
    calls = []

    def runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    result = run_xray_install_plan(plan, runner=runner)

    assert isinstance(result, XrayInstallResult)
    assert result.status == "success"
    assert result.performed_side_effects is True
    assert len(result.steps) == len(plan.steps)
    assert [step.action for step in result.steps] == [step.action for step in plan.steps]
    assert all(step.status == "success" for step in result.steps)
    assert result.steps[0].command == [
        "curl",
        "-fsSL",
        plan.download_url,
        "-o",
        "/tmp/Xray-linux-64.zip",
    ]
    assert result.steps[1].command == ["python3", "-m", "zipfile", "-t", "/tmp/Xray-linux-64.zip"]
    assert result.steps[-1].command == ["/usr/local/bin/xray", "version"]
    assert calls == [step.command for step in result.steps]


def test_run_xray_install_plan_stops_on_first_nonzero_returncode():
    plan = build_xray_install_plan(MiGateConfig(), system="Linux", machine="x86_64", version="latest")
    calls = []

    def runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        if len(calls) == 2:
            return XrayInstallCommandResult(returncode=1, stdout="", stderr="bad zip")
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    result = run_xray_install_plan(plan, runner=runner)

    assert result.status == "failed"
    assert result.performed_side_effects is True
    assert len(result.steps) == 2
    assert result.steps[0].status == "success"
    assert result.steps[1].status == "failed"
    assert result.steps[1].returncode == 1
    assert result.steps[1].stderr == "bad zip"
    assert len(calls) == 2


def test_run_xray_install_plan_maps_filenotfound_to_structured_failure():
    plan = build_xray_install_plan(MiGateConfig(), system="Linux", machine="x86_64")

    def runner(command: list[str]) -> XrayInstallCommandResult:
        raise FileNotFoundError(command[0])

    result = run_xray_install_plan(plan, runner=runner)

    assert result.status == "failed"
    assert result.performed_side_effects is True
    assert len(result.steps) == 1
    assert result.steps[0].status == "command_not_found"
    assert result.steps[0].returncode is None
    assert "command not found" in result.steps[0].stderr
    assert "curl" in result.steps[0].stderr


def test_run_xray_install_plan_backs_up_existing_binary_before_install_and_records_rollback_plan():
    plan = build_xray_install_plan(MiGateConfig(), system="Linux", machine="x86_64", version="v1.8.24")
    calls = []

    def runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    result = run_xray_install_plan(
        plan,
        runner=runner,
        existing_binary_checker=lambda path: path == "/usr/local/bin/xray",
        backup_suffix=".bak-test",
    )

    assert result.status == "success"
    assert result.backup_path == "/usr/local/bin/xray.bak-test"
    assert result.rollback_performed is False
    assert result.rollback_steps == [
        XrayInstallRollbackStep(
            action="restore_binary",
            status="planned",
            command=["mv", "/usr/local/bin/xray.bak-test", "/usr/local/bin/xray"],
            returncode=None,
            stdout="",
            stderr="",
        )
    ]
    assert calls[0] == ["cp", "-p", "/usr/local/bin/xray", "/usr/local/bin/xray.bak-test"]
    assert calls[1][0] == "curl"


def test_run_xray_install_plan_restores_backup_when_later_step_fails():
    plan = build_xray_install_plan(MiGateConfig(), system="Linux", machine="x86_64", version="latest")
    calls = []

    def runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        if command[:3] == ["install", "-m", "0755"]:
            return XrayInstallCommandResult(returncode=1, stdout="", stderr="install failed")
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    result = run_xray_install_plan(
        plan,
        runner=runner,
        existing_binary_checker=lambda path: True,
        backup_suffix=".bak-test",
    )

    assert result.status == "failed"
    assert result.backup_path == "/usr/local/bin/xray.bak-test"
    assert result.rollback_performed is True
    assert result.rollback_steps[-1] == XrayInstallRollbackStep(
        action="restore_binary",
        status="success",
        command=["mv", "/usr/local/bin/xray.bak-test", "/usr/local/bin/xray"],
        returncode=0,
        stdout="ok",
        stderr="",
    )
    assert calls[-1] == ["mv", "/usr/local/bin/xray.bak-test", "/usr/local/bin/xray"]


def test_run_xray_install_plan_reports_failed_rollback():
    plan = build_xray_install_plan(MiGateConfig(), system="Linux", machine="x86_64", version="latest")

    def runner(command: list[str]) -> XrayInstallCommandResult:
        if command[:3] == ["install", "-m", "0755"]:
            return XrayInstallCommandResult(returncode=1, stdout="", stderr="install failed")
        if command[0] == "mv":
            return XrayInstallCommandResult(returncode=1, stdout="", stderr="restore failed")
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    result = run_xray_install_plan(
        plan,
        runner=runner,
        existing_binary_checker=lambda path: True,
        backup_suffix=".bak-test",
    )

    assert result.status == "failed"
    assert result.rollback_performed is True
    assert result.rollback_steps[-1].status == "failed"
    assert result.rollback_steps[-1].stderr == "restore failed"
    assert "rollback failed" in result.message


def test_run_xray_install_plan_rejects_unsafe_plan_without_running_commands():
    plan = build_xray_install_plan(MiGateConfig(), system="Linux", machine="x86_64")
    unsafe_plan = plan.__class__(
        version=plan.version,
        system=plan.system,
        arch=plan.arch,
        bin_path=plan.bin_path,
        config_dir=plan.config_dir,
        archive_name=plan.archive_name,
        download_url=plan.download_url,
        steps=plan.steps,
        commands=[],
        performs_side_effects=False,
    )
    calls = []

    def runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    result = run_xray_install_plan(unsafe_plan, runner=runner, allow_side_effects=False)

    assert result.status == "rejected"
    assert result.performed_side_effects is False
    assert result.steps == []
    assert calls == []
    assert "allow_side_effects" in result.message
