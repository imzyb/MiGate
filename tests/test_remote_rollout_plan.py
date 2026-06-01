from migate.remote.rollout_plan import (
    RemoteRolloutPlan,
    RemoteRolloutStep,
    build_remote_rollout_dry_run_plan,
    render_remote_rollout_plan,
)


def test_remote_rollout_dry_run_orders_install_readiness_egress_service_smoke_then_leak_check_without_side_effects():
    plan = build_remote_rollout_dry_run_plan(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
    )

    assert plan == RemoteRolloutPlan(
        status="dry_run",
        message="remote rollout dry-run only; no SSH or system changes performed",
        target="root@166.88.232.2:22",
        credential_hint="[REDACTED]",
        staging_dir="/tmp/migate-install",
        steps=[
            RemoteRolloutStep(
                action="install",
                description="run gated remote install shell",
                command_preview="migate remote install --host 166.88.232.2 --port 22 --user root --staging-dir /tmp/migate-install --no-dry-run --yes --allow-remote-changes",
                performs_side_effects=True,
            ),
            RemoteRolloutStep(
                action="readiness",
                description="run read-only post-install readiness probe",
                command_preview="migate remote readiness --host 166.88.232.2 --port 22 --user root",
                performs_side_effects=False,
            ),
            RemoteRolloutStep(
                action="egress_up",
                description="start remote egress through gated remote egress shell",
                command_preview="migate remote egress up --host 166.88.232.2 --port 22 --user root --no-dry-run --yes --allow-remote-changes",
                performs_side_effects=True,
            ),
            RemoteRolloutStep(
                action="service_apply",
                description="save and restart MiGate xray/proxy systemd services on remote host",
                command_preview="ssh -p 22 root@166.88.232.2 -- 'migate xray service save --yes --allow-system-changes && migate proxy service save --yes --allow-system-changes && systemctl daemon-reload && systemctl restart migate-xray.service migate-proxy.service && systemctl is-active migate-xray.service migate-proxy.service'",
                performs_side_effects=True,
            ),
            RemoteRolloutStep(
                action="socks5_smoke",
                description="run read-only remote SOCKS5 loopback smoke check after proxy service starts",
                command_preview="ssh -p 22 root@166.88.232.2 -- 'python3 - <<\"PY\"\nimport socket\ns=socket.create_connection((\"127.0.0.1\", 1080), timeout=5)\ns.sendall(bytes([5,1,0]))\nassert s.recv(2) == bytes([5,0])\ns.close()\nPY'",
                performs_side_effects=False,
            ),
            RemoteRolloutStep(
                action="leak_check",
                description="run read-only remote public-IP leak check and fail closed on unverified egress",
                command_preview="migate remote leak-check --host 166.88.232.2 --port 22 --user root",
                performs_side_effects=False,
            ),
        ],
        commands_executed=[],
        performed_side_effects=False,
    )


def test_remote_rollout_dry_run_accepts_custom_target_and_staging_dir():
    plan = build_remote_rollout_dry_run_plan(
        host="203.0.113.10",
        port=62422,
        user="ubuntu",
        staging_dir="/tmp/migate-rollout",
    )

    assert plan.status == "dry_run"
    assert plan.target == "ubuntu@203.0.113.10:62422"
    assert plan.staging_dir == "/tmp/migate-rollout"
    assert plan.credential_hint == "[REDACTED]"
    assert [step.action for step in plan.steps] == ["install", "readiness", "egress_up", "service_apply", "socks5_smoke", "leak_check"]
    assert plan.steps[0].command_preview.startswith("migate remote install --host 203.0.113.10 --port 62422 --user ubuntu")
    assert plan.steps[2].command_preview.startswith("migate remote egress up --host 203.0.113.10 --port 62422 --user ubuntu")
    assert plan.steps[3].command_preview == "ssh -p 62422 ubuntu@203.0.113.10 -- 'migate xray service save --yes --allow-system-changes && migate proxy service save --yes --allow-system-changes && systemctl daemon-reload && systemctl restart migate-xray.service migate-proxy.service && systemctl is-active migate-xray.service migate-proxy.service'"
    assert plan.steps[4].command_preview.startswith("ssh -p 62422 ubuntu@203.0.113.10 -- 'python3 - <<")
    assert plan.steps[5].command_preview == "migate remote leak-check --host 203.0.113.10 --port 62422 --user ubuntu"


def test_remote_rollout_plan_threads_backend_override_into_remote_egress_and_service_apply_phases():
    plan = build_remote_rollout_dry_run_plan(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
        backend="xray-tun",
    )

    assert plan.status == "dry_run"
    assert plan.steps[0].command_preview == "migate remote install --host 166.88.232.2 --port 22 --user root --staging-dir /tmp/migate-install --no-dry-run --yes --allow-remote-changes"
    assert plan.steps[1].command_preview == "migate remote readiness --host 166.88.232.2 --port 22 --user root"
    assert plan.steps[2].command_preview == "migate remote egress up --host 166.88.232.2 --port 22 --user root --backend xray-tun --no-dry-run --yes --allow-remote-changes"
    assert plan.steps[3].action == "service_apply"
    assert plan.steps[3].command_preview == "ssh -p 22 root@166.88.232.2 -- 'migate xray tun-service save --yes --allow-system-changes && migate proxy service save --yes --allow-system-changes && systemctl daemon-reload && systemctl restart migate-xray-tun.service migate-proxy.service && systemctl is-active migate-xray-tun.service migate-proxy.service'"
    assert plan.steps[4].action == "socks5_smoke"
    assert plan.steps[5].command_preview == "migate remote leak-check --host 166.88.232.2 --port 22 --user root"


def test_remote_rollout_rejects_embedded_credentials_without_leaking_secret():
    plan = build_remote_rollout_dry_run_plan(
        host="root:secret@166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
    )

    assert plan.status == "rejected"
    assert plan.message == "embedded credentials are not allowed in remote rollout targets"
    assert plan.target == "[REDACTED]"
    assert plan.credential_hint == "[REDACTED]"
    assert plan.steps == []
    assert plan.commands_executed == []
    assert plan.performed_side_effects is False
    assert "secret" not in render_remote_rollout_plan(plan)


def test_remote_rollout_rejects_staging_dir_outside_tmp():
    plan = build_remote_rollout_dry_run_plan(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/etc/migate",
    )

    assert plan.status == "rejected"
    assert plan.message == "staging_dir must be under /tmp/ for dry-run rollout planning"
    assert plan.staging_dir == ""
    assert plan.commands_executed == []
    assert plan.performed_side_effects is False


def test_render_remote_rollout_plan_marks_planned_side_effects_without_execution_language():
    plan = build_remote_rollout_dry_run_plan(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
    )

    rendered = render_remote_rollout_plan(plan)

    assert "Remote rollout dry-run" in rendered
    assert "status: dry_run" in rendered
    assert "message: remote rollout dry-run only; no SSH or system changes performed" in rendered
    assert "target: root@166.88.232.2:22" in rendered
    assert "credential_hint: [REDACTED]" in rendered
    assert "staging_dir: /tmp/migate-install" in rendered
    assert "commands_executed: []" in rendered
    assert "performed_side_effects: False" in rendered
    assert "- install: planned side-effect - run gated remote install shell" in rendered
    assert "- readiness: planned read-only - run read-only post-install readiness probe" in rendered
    assert "- egress_up: planned side-effect - start remote egress through gated remote egress shell" in rendered
    assert "- service_apply: planned side-effect - save and restart MiGate xray/proxy systemd services on remote host" in rendered
    assert "- socks5_smoke: planned read-only - run read-only remote SOCKS5 loopback smoke check after proxy service starts" in rendered
    assert "- leak_check: planned read-only - run read-only remote public-IP leak check and fail closed on unverified egress" in rendered
    assert "sshpass" not in rendered.lower()
    assert "password" not in rendered.lower()
