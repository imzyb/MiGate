from migate.config import MiGateConfig
from migate.xray.install_executor import XrayInstallDryRunResult, dry_run_xray_install_plan
from migate.xray.install_plan import build_xray_install_plan


def test_dry_run_xray_install_plan_returns_structured_step_results_without_side_effects():
    plan = build_xray_install_plan(MiGateConfig(), system="Linux", machine="aarch64", version="v1.8.24")

    result = dry_run_xray_install_plan(plan)

    assert isinstance(result, XrayInstallDryRunResult)
    assert result.status == "dry_run"
    assert result.performed_side_effects is False
    assert result.commands_executed == []
    assert len(result.steps) == len(plan.steps)
    assert [step.action for step in result.steps] == [step.action for step in plan.steps]
    assert all(step.status == "planned" for step in result.steps)
    assert result.steps[0].command_preview.startswith("curl -fsSL")
    assert plan.download_url in result.steps[0].command_preview
    assert result.steps[-1].command_preview == "/usr/local/bin/xray version"


def test_dry_run_xray_install_plan_can_render_human_readable_report():
    plan = build_xray_install_plan(MiGateConfig(), system="Linux", machine="x86_64", version="latest")

    report = dry_run_xray_install_plan(plan).to_report()

    assert "Xray 安装 dry-run" in report
    assert "状态：dry_run" in report
    assert "实际副作用：False" in report
    assert "执行命令：[]" in report
    assert "download_archive" in report
    assert "install -m 0755" in report
    assert "xray version" in report


def test_dry_run_rejects_plan_that_already_claims_side_effects():
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
        commands=["curl example"],
        performs_side_effects=True,
    )

    result = dry_run_xray_install_plan(unsafe_plan)

    assert result.status == "rejected"
    assert result.performed_side_effects is False
    assert result.commands_executed == []
    assert result.steps == []
    assert "refuses plans with side effects" in result.message
