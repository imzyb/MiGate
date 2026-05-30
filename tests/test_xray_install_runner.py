from migate.config import MiGateConfig
from migate.xray.install_plan import build_xray_install_plan
from migate.xray.install_runner import XrayInstallCommandResult, XrayInstallResult, run_xray_install_plan


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
