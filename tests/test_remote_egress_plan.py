from migate.remote.egress_plan import (
    RemoteEgressPlan,
    RemoteEgressStep,
    build_remote_egress_dry_run_plan,
    render_remote_egress_plan,
)


def test_remote_egress_up_dry_run_plan_previews_remote_up_without_side_effects():
    plan = build_remote_egress_dry_run_plan(host="166.88.232.2", port=22, user="root", action="up")

    assert plan == RemoteEgressPlan(
        status="dry_run",
        message="remote egress up dry-run only; no SSH or system changes performed",
        action="up",
        target="root@166.88.232.2:22",
        credential_hint="[REDACTED]",
        steps=[
            RemoteEgressStep("doctor", "run read-only remote doctor before egress up", "migate remote doctor --host 166.88.232.2 --port 22 --user root", performs_side_effects=False),
            RemoteEgressStep("egress_up", "start remote OpenVPN egress and policy routing through MiGate gates", "ssh -p 22 root@166.88.232.2 -- migate egress up --no-dry-run --yes --allow-system-changes", performs_side_effects=True),
            RemoteEgressStep("post_up_status", "read remote egress status after up preview", "ssh -p 22 root@166.88.232.2 -- migate egress status", performs_side_effects=False),
        ],
        commands_executed=[],
        performed_side_effects=False,
    )


def test_remote_egress_down_dry_run_plan_previews_remote_down_without_side_effects():
    plan = build_remote_egress_dry_run_plan(host="166.88.232.2", port=22, user="root", action="down")

    assert plan.status == "dry_run"
    assert plan.message == "remote egress down dry-run only; no SSH or system changes performed"
    assert [step.action for step in plan.steps] == ["doctor", "egress_down", "post_down_status"]
    assert plan.steps[1].command_preview == "ssh -p 22 root@166.88.232.2 -- migate egress down --no-dry-run --yes --allow-system-changes"
    assert plan.commands_executed == []
    assert plan.performed_side_effects is False


def test_remote_egress_plan_threads_backend_override_into_remote_egress_commands():
    plan = build_remote_egress_dry_run_plan(host="166.88.232.2", port=22, user="root", action="up", backend="xray-tun")

    assert plan.status == "dry_run"
    assert plan.steps[0].command_preview == "migate remote doctor --host 166.88.232.2 --port 22 --user root"
    assert plan.steps[1].command_preview == "ssh -p 22 root@166.88.232.2 -- migate egress up --backend xray-tun --no-dry-run --yes --allow-system-changes"
    assert plan.steps[2].command_preview == "ssh -p 22 root@166.88.232.2 -- migate egress status --backend xray-tun"


def test_remote_egress_down_plan_threads_backend_override_into_remote_egress_commands():
    plan = build_remote_egress_dry_run_plan(host="166.88.232.2", port=22, user="root", action="down", backend="xray-tun")

    assert plan.status == "dry_run"
    assert plan.steps[1].command_preview == "ssh -p 22 root@166.88.232.2 -- migate egress down --backend xray-tun --no-dry-run --yes --allow-system-changes"
    assert plan.steps[2].command_preview == "ssh -p 22 root@166.88.232.2 -- migate egress status --backend xray-tun"


def test_remote_egress_plan_rejects_unknown_action():
    plan = build_remote_egress_dry_run_plan(host="166.88.232.2", port=22, user="root", action="restart")

    assert plan.status == "rejected"
    assert "action must be one of: up, down" in plan.message
    assert plan.target == "[REDACTED]"
    assert plan.steps == []
    assert plan.commands_executed == []
    assert plan.performed_side_effects is False


def test_remote_egress_plan_rejects_embedded_credentials_before_building_steps():
    plan = build_remote_egress_dry_run_plan(host="root:secret@166.88.232.2", port=22, user="root", action="up")

    assert plan.status == "rejected"
    assert plan.target == "[REDACTED]"
    assert plan.steps == []
    rendered = render_remote_egress_plan(plan)
    assert "embedded credentials are not allowed" in rendered
    assert "secret" not in rendered


def test_render_remote_egress_plan_marks_planned_steps_not_executed():
    plan = build_remote_egress_dry_run_plan(host="203.0.113.10", port=62422, user="ubuntu", action="up")

    rendered = render_remote_egress_plan(plan)

    assert "Remote egress up dry-run" in rendered
    assert "target: ubuntu@203.0.113.10:62422" in rendered
    assert "credential_hint: [REDACTED]" in rendered
    assert "commands_executed: []" in rendered
    assert "performed_side_effects: False" in rendered
    assert "- doctor: planned read-only" in rendered
    assert "- egress_up: planned side-effect" in rendered
    assert "ssh -p 62422 ubuntu@203.0.113.10 -- migate egress up --no-dry-run --yes --allow-system-changes" in rendered
    assert "sshpass" not in rendered.lower()
    assert "password" not in rendered.lower()
