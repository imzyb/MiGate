from migate.remote.lifecycle_plan import (
    RemoteLifecyclePlan,
    RemoteLifecycleStep,
    build_remote_lifecycle_dry_run_plan,
    render_remote_lifecycle_plan,
)


def test_build_remote_lifecycle_dry_run_plan_uses_redacted_target_and_no_side_effects():
    plan = build_remote_lifecycle_dry_run_plan(host="166.88.232.2", port=22, user="root")

    assert plan == RemoteLifecyclePlan(
        status="dry_run",
        message="remote test VPS lifecycle dry-run only; no SSH or system changes performed",
        target="root@166.88.232.2:22",
        credential_hint="[REDACTED]",
        steps=[
            RemoteLifecycleStep("preflight", "ssh root@166.88.232.2 -p 22 -- hostname && uname -a", performs_side_effects=False),
            RemoteLifecycleStep("sync", "rsync project to test VPS staging directory", performs_side_effects=True),
            RemoteLifecycleStep("install", "run MiGate installer on test VPS", performs_side_effects=True),
            RemoteLifecycleStep("egress_up", "start OpenVPN egress and policy routing on test VPS", performs_side_effects=True),
            RemoteLifecycleStep("leak_check", "verify egress IP is not native VPS IP and fail closed on mismatch", performs_side_effects=False),
            RemoteLifecycleStep("cleanup", "stop egress and remove temporary MiGate artifacts from test VPS", performs_side_effects=True),
        ],
        commands_executed=[],
        performed_side_effects=False,
    )


def test_render_remote_lifecycle_plan_never_prints_password_or_real_execution_words():
    plan = build_remote_lifecycle_dry_run_plan(host="166.88.232.2", port=22, user="root")

    rendered = render_remote_lifecycle_plan(plan)

    assert "Remote lifecycle dry-run" in rendered
    assert "target: root@166.88.232.2:22" in rendered
    assert "credential_hint: [REDACTED]" in rendered
    assert "commands_executed: []" in rendered
    assert "performed_side_effects: False" in rendered
    assert "- preflight: planned read-only" in rendered
    assert "- install: planned side-effect" in rendered
    assert "- cleanup: planned side-effect" in rendered
    assert "password" not in rendered.lower()
    assert "sshpass" not in rendered.lower()
    assert "执行" not in rendered


def test_remote_lifecycle_plan_rejects_embedded_credentials_in_target_fields():
    plan = build_remote_lifecycle_dry_run_plan(host="root:secret@166.88.232.2", port=22, user="root")

    assert plan.status == "rejected"
    assert plan.steps == []
    assert plan.commands_executed == []
    assert plan.performed_side_effects is False
    rendered = render_remote_lifecycle_plan(plan)
    assert "embedded credentials are not allowed" in rendered
    assert "secret" not in rendered
