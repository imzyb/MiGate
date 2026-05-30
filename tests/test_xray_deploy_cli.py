from migate.config import MiGateConfig
from migate.xray.deploy_cli import XrayDeployPlan, XrayDeployStep, build_xray_deploy_dry_run_plan, render_xray_deploy_plan


def test_build_xray_deploy_dry_run_plan_lists_safe_order_without_side_effects():
    plan = build_xray_deploy_dry_run_plan(MiGateConfig(), system="Linux", machine="x86_64", version="v1.8.24")

    assert plan == XrayDeployPlan(
        status="dry_run",
        message="xray deploy dry-run only; no system changes performed",
        steps=[
            XrayDeployStep("doctor", "run xray install doctor/preflight checks", performs_side_effects=False),
            XrayDeployStep("install", "install xray-core v1.8.24 for linux-64", performs_side_effects=True),
            XrayDeployStep("config_save", "atomically save and validate /etc/migate/xray/config.json", performs_side_effects=True),
            XrayDeployStep("service_save", "write systemd unit /etc/systemd/system/migate-xray.service", performs_side_effects=True),
            XrayDeployStep("apply_restart", "validate config then daemon-reload and restart migate-xray.service", performs_side_effects=True),
            XrayDeployStep("status", "read migate-xray.service status", performs_side_effects=False),
        ],
        commands_executed=[],
        performed_side_effects=False,
    )


def test_render_xray_deploy_plan_marks_real_steps_as_planned_not_executed():
    plan = build_xray_deploy_dry_run_plan(MiGateConfig(), system="Linux", machine="x86_64", version="latest")

    rendered = render_xray_deploy_plan(plan)

    assert "Xray deploy dry-run" in rendered
    assert "status: dry_run" in rendered
    assert "commands_executed: []" in rendered
    assert "performed_side_effects: False" in rendered
    assert "- doctor: planned read-only" in rendered
    assert "- install: planned side-effect" in rendered
    assert "- apply_restart: planned side-effect" in rendered
    assert "systemctl restart" not in rendered
    assert "执行" not in rendered


def test_real_xray_deploy_is_rejected_until_enabled():
    plan = build_xray_deploy_dry_run_plan(
        MiGateConfig(),
        system="Linux",
        machine="x86_64",
        version="latest",
        dry_run=False,
        yes=True,
        allow_system_changes=True,
    )

    assert plan.status == "rejected"
    assert plan.message == "real xray deploy is not implemented; run with --dry-run"
    assert plan.commands_executed == []
    assert plan.performed_side_effects is False
