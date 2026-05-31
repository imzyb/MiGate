from migate.remote.readiness import RemoteReadinessCheck, RemoteReadinessReport
from migate.remote.leak_check import RemoteLeakCheck, RemoteLeakCheckReport
from migate.remote.rollout_plan import build_remote_rollout_dry_run_plan
from migate.remote.rollout_runner import (
    RemoteRolloutCommandResult,
    RemoteRolloutPhaseResult,
    RemoteRolloutRunResult,
    RemoteRolloutSubstepResult,
    build_remote_rollout_service_apply_runner,
    build_remote_rollout_socks5_smoke_runner,
    render_remote_rollout_run_result,
    run_remote_rollout_plan,
)


def _plan():
    return build_remote_rollout_dry_run_plan(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
    )


def _ok_readiness():
    return RemoteReadinessReport(
        status="ok",
        target="root@166.88.232.2:22",
        checks=[RemoteReadinessCheck("migate_cli", "ok", "/usr/local/bin/migate")],
        commands_executed=["ssh readiness"],
        performed_side_effects=False,
    )


def test_run_remote_rollout_plan_defaults_to_dry_run_and_calls_no_phases():
    calls = []

    result = run_remote_rollout_plan(
        _plan(),
        dry_run=True,
        yes=False,
        allow_remote_changes=False,
        install_runner=lambda: calls.append("install"),
        readiness_runner=lambda: calls.append("readiness"),
        egress_up_runner=lambda: calls.append("egress_up"),
    )

    assert result == RemoteRolloutRunResult(
        status="dry_run",
        message="remote rollout dry-run only; no rollout phases executed",
        target="root@166.88.232.2:22",
        phases=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_run_remote_rollout_plan_rejects_real_execution_without_double_gate():
    calls = []

    result = run_remote_rollout_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        install_runner=lambda: calls.append("install"),
        readiness_runner=lambda: calls.append("readiness"),
        egress_up_runner=lambda: calls.append("egress_up"),
    )

    assert result == RemoteRolloutRunResult(
        status="rejected",
        message="remote rollout requires yes=True and allow_remote_changes=True",
        target="root@166.88.232.2:22",
        phases=[],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_run_remote_rollout_plan_executes_install_readiness_egress_service_smoke_then_leak_check_with_injected_phases():
    calls = []

    def install_runner():
        calls.append("install")
        return RemoteRolloutPhaseResult(
            action="install",
            status="success",
            message="installed",
            commands_executed=["migate remote install --no-dry-run"],
            performed_side_effects=True,
        )

    def readiness_runner():
        calls.append("readiness")
        return _ok_readiness()

    def egress_up_runner():
        calls.append("egress_up")
        return RemoteRolloutPhaseResult(
            action="egress_up",
            status="success",
            message="egress up",
            commands_executed=["migate remote egress up --no-dry-run"],
            performed_side_effects=True,
        )

    def service_apply_runner():
        calls.append("service_apply")
        return RemoteRolloutPhaseResult(
            action="service_apply",
            status="success",
            message="service_apply ok",
            commands_executed=["ssh service apply"],
            performed_side_effects=True,
        )

    def socks5_smoke_runner():
        calls.append("socks5_smoke")
        return RemoteRolloutPhaseResult(
            action="socks5_smoke",
            status="success",
            message="socks5_smoke ok",
            commands_executed=["ssh socks5 smoke"],
            performed_side_effects=False,
        )

    def leak_check_runner():
        calls.append("leak_check")
        return RemoteLeakCheckReport(
            status="ok",
            target="root@166.88.232.2:22",
            native_public_ip="198.51.100.10",
            egress_public_ip="203.0.113.20",
            checks=[
                RemoteLeakCheck("native_ip", "ok", "198.51.100.10"),
                RemoteLeakCheck("egress_ip", "ok", "203.0.113.20"),
                RemoteLeakCheck("egress_guard", "ok", "egress guard passed"),
            ],
            commands_executed=["ssh leak-check"],
            performed_side_effects=False,
        )

    result = run_remote_rollout_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=install_runner,
        readiness_runner=readiness_runner,
        egress_up_runner=egress_up_runner,
        service_apply_runner=service_apply_runner,
        socks5_smoke_runner=socks5_smoke_runner,
        leak_check_runner=leak_check_runner,
    )

    assert result.status == "success"
    assert result.message == "remote rollout completed through injected phase runners"
    assert calls == ["install", "readiness", "egress_up", "service_apply", "socks5_smoke", "leak_check"]
    assert [phase.action for phase in result.phases] == ["install", "readiness", "egress_up", "service_apply", "socks5_smoke", "leak_check"]
    assert result.commands_executed == [
        "migate remote install --no-dry-run",
        "ssh readiness",
        "migate remote egress up --no-dry-run",
        "ssh service apply",
        "ssh socks5 smoke",
        "ssh leak-check",
    ]
    assert result.performed_side_effects is True


def test_service_apply_runner_reports_ordered_substep_results_and_stops_on_first_failure():
    plan = _plan()
    calls = []

    def runner(command: str) -> RemoteRolloutCommandResult:
        calls.append(command)
        if "proxy service save" in command:
            return RemoteRolloutCommandResult(1, "proxy stdout", "proxy stderr")
        return RemoteRolloutCommandResult(0, f"ok: {command}", "")

    phase = build_remote_rollout_service_apply_runner(plan, runner=runner)()

    assert phase.action == "service_apply"
    assert phase.status == "failed"
    assert phase.message == "service_apply failed at proxy_service_save"
    assert calls == [
        "ssh -p 22 root@166.88.232.2 -- 'migate xray service save --yes --allow-system-changes'",
        "ssh -p 22 root@166.88.232.2 -- 'migate proxy service save --yes --allow-system-changes'",
    ]
    assert phase.commands_executed == calls
    assert phase.performed_side_effects is True
    assert [step.name for step in phase.command_results] == ["xray_service_save", "proxy_service_save"]
    assert [step.command for step in phase.command_results] == calls
    assert [step.returncode for step in phase.command_results] == [0, 1]
    assert [step.stdout for step in phase.command_results] == [calls[0].join(["ok: ", ""]), "proxy stdout"]
    assert [step.stderr for step in phase.command_results] == ["", "proxy stderr"]
    assert [step.status for step in phase.command_results] == ["success", "failed"]


def test_socks5_smoke_runner_reports_loopback_greeting_diagnostics_without_side_effects():
    plan = _plan()
    calls = []

    def runner(command: str) -> RemoteRolloutCommandResult:
        calls.append(command)
        return RemoteRolloutCommandResult(1, "connect stdout", "connection refused")

    phase = build_remote_rollout_socks5_smoke_runner(plan, runner=runner)()

    expected_command = (
        "ssh -p 22 root@166.88.232.2 -- 'python3 - <<\"PY\"\n"
        "import socket\n"
        "s=socket.create_connection((\"127.0.0.1\", 1080), timeout=5)\n"
        "s.sendall(bytes([5,1,0]))\n"
        "assert s.recv(2) == bytes([5,0])\n"
        "s.close()\n"
        "PY'"
    )
    assert phase.action == "socks5_smoke"
    assert phase.status == "failed"
    assert phase.message == "socks5_smoke failed at loopback_greeting"
    assert calls == [expected_command]
    assert phase.commands_executed == [expected_command]
    assert phase.performed_side_effects is False
    assert phase.command_results == [
        RemoteRolloutSubstepResult(
            name="loopback_greeting",
            status="failed",
            command=expected_command,
            returncode=1,
            stdout="connect stdout",
            stderr="connection refused",
        )
    ]


def test_run_remote_rollout_plan_preserves_failed_service_apply_substep_diagnostics_and_skips_later_phases():
    calls = []
    service_phase = RemoteRolloutPhaseResult(
        action="service_apply",
        status="failed",
        message="service_apply failed at daemon_reload",
        commands_executed=["ssh daemon-reload"],
        performed_side_effects=True,
        command_results=[
            RemoteRolloutSubstepResult(
                name="daemon_reload",
                status="failed",
                command="ssh daemon-reload",
                returncode=1,
                stdout="",
                stderr="systemd unavailable",
            )
        ],
    )

    result = run_remote_rollout_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=lambda: calls.append("install")
        or RemoteRolloutPhaseResult("install", "success", "installed", ["install command"], True),
        readiness_runner=lambda: calls.append("readiness") or _ok_readiness(),
        egress_up_runner=lambda: calls.append("egress_up")
        or RemoteRolloutPhaseResult("egress_up", "success", "egress up", ["egress command"], True),
        service_apply_runner=lambda: calls.append("service_apply") or service_phase,
        socks5_smoke_runner=lambda: calls.append("socks5_smoke"),
        leak_check_runner=lambda: calls.append("leak_check"),
    )

    assert result.status == "failed"
    assert result.message == "remote rollout stopped at service_apply"
    assert calls == ["install", "readiness", "egress_up", "service_apply"]
    assert result.phases[-1].command_results == service_phase.command_results
    assert result.commands_executed == ["install command", "ssh readiness", "egress command", "ssh daemon-reload"]
    rendered = render_remote_rollout_run_result(result)
    assert "  - daemon_reload: failed returncode=1" in rendered
    assert "    stderr: systemd unavailable" in rendered


def test_run_remote_rollout_plan_preserves_failed_socks5_smoke_substep_diagnostics_and_skips_leak_check():
    calls = []
    socks_phase = RemoteRolloutPhaseResult(
        action="socks5_smoke",
        status="failed",
        message="socks5_smoke failed at loopback_greeting",
        commands_executed=["ssh socks smoke"],
        performed_side_effects=False,
        command_results=[
            RemoteRolloutSubstepResult(
                name="loopback_greeting",
                status="failed",
                command="ssh socks smoke",
                returncode=1,
                stdout="",
                stderr="connection refused",
            )
        ],
    )

    result = run_remote_rollout_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=lambda: calls.append("install")
        or RemoteRolloutPhaseResult("install", "success", "installed", ["install command"], True),
        readiness_runner=lambda: calls.append("readiness") or _ok_readiness(),
        egress_up_runner=lambda: calls.append("egress_up")
        or RemoteRolloutPhaseResult("egress_up", "success", "egress up", ["egress command"], True),
        service_apply_runner=lambda: calls.append("service_apply")
        or RemoteRolloutPhaseResult("service_apply", "success", "service_apply ok", ["service command"], True),
        socks5_smoke_runner=lambda: calls.append("socks5_smoke") or socks_phase,
        leak_check_runner=lambda: calls.append("leak_check"),
    )

    assert result.status == "failed"
    assert result.message == "remote rollout stopped at socks5_smoke"
    assert calls == ["install", "readiness", "egress_up", "service_apply", "socks5_smoke"]
    assert result.phases[-1].command_results == socks_phase.command_results
    assert result.commands_executed == ["install command", "ssh readiness", "egress command", "service command", "ssh socks smoke"]
    rendered = render_remote_rollout_run_result(result)
    assert "  - loopback_greeting: failed returncode=1" in rendered
    assert "    stderr: connection refused" in rendered


def test_run_remote_rollout_plan_stops_before_egress_when_readiness_fails():
    calls = []

    result = run_remote_rollout_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=lambda: calls.append("install")
        or RemoteRolloutPhaseResult(
            action="install",
            status="success",
            message="installed",
            commands_executed=["install command"],
            performed_side_effects=True,
        ),
        readiness_runner=lambda: calls.append("readiness")
        or RemoteReadinessReport(
            status="failed",
            target="root@166.88.232.2:22",
            checks=[RemoteReadinessCheck("xray_bin", "failed", "missing xray")],
            commands_executed=["readiness command"],
            performed_side_effects=False,
        ),
        egress_up_runner=lambda: calls.append("egress_up"),
        service_apply_runner=lambda: calls.append("service_apply"),
        socks5_smoke_runner=lambda: calls.append("socks5_smoke"),
        leak_check_runner=lambda: calls.append("leak_check"),
    )

    assert result.status == "failed"
    assert result.message == "remote rollout stopped at readiness"
    assert calls == ["install", "readiness"]
    assert [phase.action for phase in result.phases] == ["install", "readiness"]
    assert result.commands_executed == ["install command", "readiness command"]
    assert result.performed_side_effects is True


def test_run_remote_rollout_plan_stops_after_egress_when_leak_check_fails():
    calls = []

    result = run_remote_rollout_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=lambda: calls.append("install")
        or RemoteRolloutPhaseResult(
            action="install",
            status="success",
            message="installed",
            commands_executed=["install command"],
            performed_side_effects=True,
        ),
        readiness_runner=lambda: calls.append("readiness") or _ok_readiness(),
        egress_up_runner=lambda: calls.append("egress_up")
        or RemoteRolloutPhaseResult(
            action="egress_up",
            status="success",
            message="egress up",
            commands_executed=["egress command"],
            performed_side_effects=True,
        ),
        service_apply_runner=lambda: calls.append("service_apply")
        or RemoteRolloutPhaseResult("service_apply", "success", "service_apply ok", ["service apply command"], True),
        socks5_smoke_runner=lambda: calls.append("socks5_smoke")
        or RemoteRolloutPhaseResult("socks5_smoke", "success", "socks5_smoke ok", ["socks smoke command"], False),
        leak_check_runner=lambda: calls.append("leak_check")
        or RemoteLeakCheckReport(
            status="failed",
            target="root@166.88.232.2:22",
            native_public_ip="198.51.100.10",
            egress_public_ip="198.51.100.10",
            checks=[RemoteLeakCheck("egress_guard", "failed", "native_ip_leak_detected")],
            commands_executed=["leak check command"],
            performed_side_effects=False,
        ),
    )

    assert result.status == "failed"
    assert result.message == "remote rollout stopped at leak_check"
    assert calls == ["install", "readiness", "egress_up", "service_apply", "socks5_smoke", "leak_check"]
    assert [phase.action for phase in result.phases] == ["install", "readiness", "egress_up", "service_apply", "socks5_smoke", "leak_check"]
    assert result.commands_executed == ["install command", "ssh readiness", "egress command", "service apply command", "socks smoke command", "leak check command"]
    assert result.performed_side_effects is True


def test_run_remote_rollout_plan_rejects_rejected_plan_without_phase_calls():
    calls = []
    rejected_plan = build_remote_rollout_dry_run_plan(
        host="root:secret@166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
    )

    result = run_remote_rollout_plan(
        rejected_plan,
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=lambda: calls.append("install"),
        readiness_runner=lambda: calls.append("readiness"),
        egress_up_runner=lambda: calls.append("egress_up"),
        leak_check_runner=lambda: calls.append("leak_check"),
    )

    assert result.status == "rejected"
    assert result.target == "[REDACTED]"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []
    rendered = render_remote_rollout_run_result(result)
    assert "embedded credentials are not allowed" in rendered
    assert "secret" not in rendered


def test_render_remote_rollout_run_result_is_structured_and_redacted():
    result = run_remote_rollout_plan(
        _plan(),
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=lambda: RemoteRolloutPhaseResult("install", "success", "installed", ["install command"], True),
        readiness_runner=_ok_readiness,
        egress_up_runner=lambda: RemoteRolloutPhaseResult("egress_up", "success", "egress up", ["egress command"], True),
        service_apply_runner=lambda: RemoteRolloutPhaseResult("service_apply", "success", "service_apply ok", ["service apply command"], True),
        socks5_smoke_runner=lambda: RemoteRolloutPhaseResult("socks5_smoke", "success", "socks5_smoke ok", ["socks smoke command"], False),
        leak_check_runner=lambda: RemoteLeakCheckReport(
            status="ok",
            target="root@166.88.232.2:22",
            native_public_ip="198.51.100.10",
            egress_public_ip="203.0.113.20",
            checks=[RemoteLeakCheck("egress_guard", "ok", "egress guard passed")],
            commands_executed=["leak check command"],
            performed_side_effects=False,
        ),
    )

    rendered = render_remote_rollout_run_result(result)

    assert "Remote rollout result" in rendered
    assert "status: success" in rendered
    assert "target: root@166.88.232.2:22" in rendered
    assert "commands_executed:" in rendered
    assert "performed_side_effects: True" in rendered
    assert "- install: success - installed" in rendered
    assert "- readiness: success - readiness ok" in rendered
    assert "- egress_up: success - egress up" in rendered
    assert "- service_apply: success - service_apply ok" in rendered
    assert "- socks5_smoke: success - socks5_smoke ok" in rendered
    assert "- leak_check: success - leak_check ok" in rendered
    assert "password" not in rendered.lower()
    assert "sshpass" not in rendered.lower()


def test_render_remote_rollout_run_result_includes_service_apply_substep_diagnostics():
    result = RemoteRolloutRunResult(
        status="failed",
        message="remote rollout stopped at service_apply",
        target="root@166.88.232.2:22",
        phases=[
            RemoteRolloutPhaseResult(
                action="service_apply",
                status="failed",
                message="service_apply failed at proxy_service_save",
                commands_executed=["ssh proxy service save"],
                performed_side_effects=True,
                command_results=[
                    RemoteRolloutSubstepResult(
                        name="proxy_service_save",
                        status="failed",
                        command="ssh proxy service save",
                        returncode=1,
                        stdout="proxy stdout",
                        stderr="proxy stderr",
                    )
                ],
            )
        ],
        commands_executed=["ssh proxy service save"],
        performed_side_effects=True,
    )

    rendered = render_remote_rollout_run_result(result)

    assert "- service_apply: failed - service_apply failed at proxy_service_save" in rendered
    assert "  - proxy_service_save: failed returncode=1" in rendered
    assert "    stdout: proxy stdout" in rendered
    assert "    stderr: proxy stderr" in rendered
