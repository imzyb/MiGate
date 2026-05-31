from migate.remote.install_plan import (
    RemoteInstallPlan,
    RemoteInstallStep,
    build_remote_install_dry_run_plan,
    render_remote_install_plan,
)


def test_build_remote_install_dry_run_plan_lists_remote_command_previews_without_side_effects():
    plan = build_remote_install_dry_run_plan(host="166.88.232.2", port=22, user="root", staging_dir="/tmp/migate-install")

    assert plan == RemoteInstallPlan(
        status="dry_run",
        message="remote install dry-run only; no SSH or system changes performed",
        target="root@166.88.232.2:22",
        credential_hint="[REDACTED]",
        staging_dir="/tmp/migate-install",
        steps=[
            RemoteInstallStep("doctor", "run migate remote doctor before install", "migate remote doctor --host 166.88.232.2 --port 22 --user root", performs_side_effects=False),
            RemoteInstallStep("sync_project", "sync project to remote staging directory", "rsync -az --delete ./ root@166.88.232.2:/tmp/migate-install/", performs_side_effects=True),
            RemoteInstallStep("install_python_package", "install MiGate package in an isolated remote venv", "ssh -p 22 root@166.88.232.2 -- 'cd /tmp/migate-install && python3 -m venv .venv && .venv/bin/python -m pip install . && ln -sf /tmp/migate-install/.venv/bin/migate /usr/local/bin/migate'", performs_side_effects=True),
            RemoteInstallStep("install_xray", "install xray-core through MiGate gated installer", "ssh -p 22 root@166.88.232.2 -- migate xray install --yes --allow-system-changes", performs_side_effects=True),
            RemoteInstallStep("write_services", "preview service units only; real service writes stay gated", "ssh -p 22 root@166.88.232.2 -- 'migate xray service preview && migate proxy service preview'", performs_side_effects=False),
            RemoteInstallStep("post_install_doctor", "run read-only remote doctor after install preview", "migate remote doctor --host 166.88.232.2 --port 22 --user root", performs_side_effects=False),
        ],
        commands_executed=[],
        performed_side_effects=False,
    )


def test_render_remote_install_plan_marks_side_effect_steps_as_planned_not_executed():
    plan = build_remote_install_dry_run_plan(host="166.88.232.2", port=22, user="root", staging_dir="/tmp/migate-install")

    rendered = render_remote_install_plan(plan)

    assert "Remote install dry-run" in rendered
    assert "target: root@166.88.232.2:22" in rendered
    assert "credential_hint: [REDACTED]" in rendered
    assert "commands_executed: []" in rendered
    assert "performed_side_effects: False" in rendered
    assert "- doctor: planned read-only" in rendered
    assert "- sync_project: planned side-effect" in rendered
    assert "rsync -az --delete ./ root@166.88.232.2:/tmp/migate-install/" in rendered
    assert "sshpass" not in rendered.lower()
    assert "password" not in rendered.lower()
    assert "执行" not in rendered


def test_remote_install_plan_rejects_embedded_credentials_before_building_steps():
    plan = build_remote_install_dry_run_plan(host="root:secret@166.88.232.2", port=22, user="root", staging_dir="/tmp/migate-install")

    assert plan.status == "rejected"
    assert plan.target == "[REDACTED]"
    assert plan.steps == []
    assert plan.commands_executed == []
    assert plan.performed_side_effects is False
    rendered = render_remote_install_plan(plan)
    assert "embedded credentials are not allowed" in rendered
    assert "secret" not in rendered


def test_remote_install_plan_rejects_unsafe_staging_dir():
    plan = build_remote_install_dry_run_plan(host="166.88.232.2", port=22, user="root", staging_dir="/etc/migate")

    assert plan.status == "rejected"
    assert "staging_dir must be under /tmp/" in plan.message
    assert plan.steps == []
    assert plan.commands_executed == []
    assert plan.performed_side_effects is False
