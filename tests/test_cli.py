import json
from pathlib import Path

from typer.testing import CliRunner

import migate.main as main_module
from migate.main import (
    app,
    build_panel_server_config,
    build_remote_egress_cli_plan,
    build_remote_install_cli_plan,
    build_remote_lifecycle_cli_plan,
    build_remote_rollout_cli_plan,
    build_xray_install_cli_plan,
    run_remote_acceptance_cli,
    run_remote_egress_cli,
    run_remote_install_cli,
    run_remote_lifecycle_cli,
    run_remote_rollout_cli,
    run_remote_rollout_smoke_cli,
    run_xray_install_cli,
)
from migate.egress.lifecycle import EgressLifecyclePhase, EgressLifecycleResult
from migate.egress.status import EgressStatusCheck, EgressStatusReport
from migate.proxy.socks5_listener import Socks5ServeEvent, Socks5ServeResult
from migate.xray.doctor import DoctorCheck, DoctorReport
from migate.xray.apply_cli import XrayApplyResult
from migate.xray.install_runner import XrayInstallCommandResult, XrayInstallResult
from migate.xray.validator import XrayValidationResult
from migate.remote.egress_runner import RemoteEgressCommandResult
from migate.remote.install_runner import RemoteInstallCommandResult
from migate.remote.leak_check import RemoteLeakCheck, RemoteLeakCheckReport
from migate.remote.readiness import RemoteReadinessCheck, RemoteReadinessReport
from migate.remote.rollout_runner import RemoteRolloutCommandResult, RemoteRolloutPhaseResult, RemoteRolloutRunResult, render_remote_rollout_run_result
from migate.remote.rollout_smoke import RemoteRolloutSmokeResult
from migate.remote.acceptance import RemoteAcceptanceResult


runner = CliRunner()


def test_remote_readiness_command_runs_read_only_probe(monkeypatch):
    report = RemoteReadinessReport(
        status="ok",
        target="root@166.88.232.2:22",
        checks=[RemoteReadinessCheck("migate_cli", "ok", "/usr/local/bin/migate")],
        commands_executed=["ssh -p 22 root@166.88.232.2 readonly"],
        performed_side_effects=False,
    )
    monkeypatch.setattr(main_module, "run_remote_readiness", lambda **kwargs: report)

    result = runner.invoke(app, ["remote", "readiness"])

    assert result.exit_code == 0
    assert "Remote readiness" in result.output
    assert "status: ok" in result.output
    assert "target: root@166.88.232.2:22" in result.output
    assert "- migate_cli: ok - /usr/local/bin/migate" in result.output
    assert "performed_side_effects: False" in result.output


def test_remote_readiness_command_exits_nonzero_when_failed(monkeypatch):
    report = RemoteReadinessReport(
        status="failed",
        target="root@166.88.232.2:22",
        checks=[RemoteReadinessCheck("xray_bin", "failed", "missing xray")],
        commands_executed=["ssh -p 22 root@166.88.232.2 readonly"],
        performed_side_effects=False,
    )
    monkeypatch.setattr(main_module, "run_remote_readiness", lambda **kwargs: report)

    result = runner.invoke(app, ["remote", "readiness"])

    assert result.exit_code == 1
    assert "status: failed" in result.output
    assert "missing xray" in result.output
    assert "performed_side_effects: False" in result.output


def test_remote_leak_check_command_runs_read_only_probe_with_socks_port(monkeypatch):
    captured = {}
    report = RemoteLeakCheckReport(
        status="ok",
        target="root@166.88.232.2:22",
        native_public_ip="198.51.100.10",
        egress_public_ip="203.0.113.20",
        checks=[RemoteLeakCheck("egress_guard", "ok", "egress guard passed")],
        commands_executed=["ssh leak-check --socks-port 34502"],
        performed_side_effects=False,
    )

    def fake_run_remote_leak_check(**kwargs):
        captured.update(kwargs)
        return report

    monkeypatch.setattr(main_module, "run_remote_leak_check", fake_run_remote_leak_check)

    result = runner.invoke(app, ["remote", "leak-check", "--socks-port", "34502"])

    assert result.exit_code == 0
    assert captured == {"host": "166.88.232.2", "port": 22, "user": "root", "socks_port": 34502}
    assert "Remote leak check" in result.output
    assert "status: ok" in result.output
    assert "egress_public_ip: 203.0.113.20" in result.output
    assert "performed_side_effects: False" in result.output
    assert "- egress_guard: ok - egress guard passed" in result.output
    assert "sshpass" not in result.output.lower()
    assert "password" not in result.output.lower()


def test_remote_leak_check_command_exits_nonzero_when_failed(monkeypatch):
    report = RemoteLeakCheckReport(
        status="failed",
        target="root@166.88.232.2:22",
        native_public_ip="198.51.100.10",
        egress_public_ip=None,
        checks=[RemoteLeakCheck("egress_guard", "failed", "egress public IP could not be verified; egress blocked")],
        commands_executed=["ssh leak-check"],
        performed_side_effects=False,
    )
    monkeypatch.setattr(main_module, "run_remote_leak_check", lambda **kwargs: report)

    result = runner.invoke(app, ["remote", "leak-check"])

    assert result.exit_code == 1
    assert "status: failed" in result.output
    assert "egress public IP could not be verified; egress blocked" in result.output
    assert "performed_side_effects: False" in result.output


def test_remote_leak_check_command_rejects_embedded_credentials():
    result = runner.invoke(app, ["remote", "leak-check", "--host", "root:secret@203.0.113.10"])

    assert result.exit_code == 1
    assert "embedded credentials are not allowed" in result.output
    assert "secret" not in result.output


def test_build_remote_rollout_cli_plan_defaults_to_install_readiness_egress_service_smoke_leak_check():
    plan = build_remote_rollout_cli_plan()

    assert plan.status == "dry_run"
    assert plan.target == "root@166.88.232.2:22"
    assert plan.staging_dir == "/tmp/migate-install"
    assert plan.commands_executed == []
    assert plan.performed_side_effects is False
    assert [step.action for step in plan.steps] == ["install", "readiness", "egress_up", "service_apply", "socks5_smoke", "leak_check"]


def test_remote_rollout_command_defaults_to_dry_run_without_remote_side_effects():
    result = runner.invoke(app, ["remote", "rollout"])

    assert result.exit_code == 0
    assert "Remote rollout dry-run" in result.output
    assert "target: root@166.88.232.2:22" in result.output
    assert "staging_dir: /tmp/migate-install" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert "- install: planned side-effect" in result.output
    assert "- readiness: planned read-only" in result.output
    assert "- egress_up: planned side-effect" in result.output
    assert "- service_apply: planned side-effect" in result.output
    assert "- socks5_smoke: planned read-only" in result.output
    assert "- leak_check: planned read-only" in result.output
    assert "migate remote install --host 166.88.232.2 --port 22 --user root" in result.output
    assert "migate remote readiness --host 166.88.232.2 --port 22 --user root" in result.output
    assert "migate remote egress up --host 166.88.232.2 --port 22 --user root" in result.output
    assert "migate xray service save --yes --allow-system-changes" in result.output
    assert "migate proxy service save --yes --allow-system-changes" in result.output
    assert "python3 - <<\"PY\"" in result.output
    assert "migate remote leak-check --host 166.88.232.2 --port 22 --user root" in result.output
    assert "sshpass" not in result.output.lower()
    assert "password" not in result.output.lower()


def test_remote_rollout_command_accepts_backend_xray_tun_in_dry_run_plan():
    result = runner.invoke(app, ["remote", "rollout", "--backend", "xray-tun"])

    assert result.exit_code == 0
    assert "migate remote egress up --host 166.88.232.2 --port 22 --user root --backend xray-tun --no-dry-run --yes --allow-remote-changes" in result.output
    assert "performed_side_effects: False" in result.output


def test_run_remote_rollout_cli_rejects_real_execution_without_double_gate():
    calls = []

    result = run_remote_rollout_cli(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        install_runner=lambda: calls.append("install"),
        readiness_runner=lambda: calls.append("readiness"),
        egress_up_runner=lambda: calls.append("egress_up"),
        leak_check_runner=lambda: calls.append("leak_check"),
    )

    assert result.status == "rejected"
    assert result.message == "remote rollout requires yes=True and allow_remote_changes=True"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []


def test_run_remote_rollout_cli_stops_at_default_service_apply_failure_and_renders_diagnostics():
    calls = []
    service_commands = []

    def service_apply_command_runner(command: str) -> RemoteRolloutCommandResult:
        service_commands.append(command)
        if "proxy service save" in command:
            return RemoteRolloutCommandResult(1, "proxy stdout", "proxy stderr")
        return RemoteRolloutCommandResult(0, "ok", "")

    result = run_remote_rollout_cli(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=lambda: calls.append("install")
        or RemoteRolloutPhaseResult("install", "success", "installed", ["install command"], True),
        readiness_runner=lambda: calls.append("readiness")
        or RemoteReadinessReport("ok", "root@166.88.232.2:22", [], ["readiness command"], False),
        egress_up_runner=lambda: calls.append("egress_up")
        or RemoteRolloutPhaseResult("egress_up", "success", "egress up", ["egress command"], True),
        service_apply_command_runner=service_apply_command_runner,
        socks5_smoke_runner=lambda: calls.append("socks5_smoke"),
        leak_check_runner=lambda: calls.append("leak_check"),
    )

    assert result.status == "failed"
    assert result.message == "remote rollout stopped at service_apply"
    assert calls == ["install", "readiness", "egress_up"]
    assert [phase.action for phase in result.phases] == ["install", "readiness", "egress_up", "service_apply"]
    assert result.phases[-1].message == "service_apply failed at proxy_service_save"
    assert result.phases[-1].performed_side_effects is True
    assert service_commands == result.phases[-1].commands_executed
    rendered = render_remote_rollout_run_result(result)
    assert "- service_apply: failed - service_apply failed at proxy_service_save" in rendered
    assert "  - proxy_service_save: failed returncode=1" in rendered
    assert "    stdout: proxy stdout" in rendered
    assert "    stderr: proxy stderr" in rendered
    assert "socks5_smoke" not in calls
    assert "leak_check" not in calls


def test_run_remote_rollout_cli_stops_at_default_socks5_smoke_failure_and_renders_diagnostics():
    calls = []
    smoke_commands = []

    def socks5_smoke_command_runner(command: str) -> RemoteRolloutCommandResult:
        smoke_commands.append(command)
        return RemoteRolloutCommandResult(1, "smoke stdout", "connection refused")

    result = run_remote_rollout_cli(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=lambda: calls.append("install")
        or RemoteRolloutPhaseResult("install", "success", "installed", ["install command"], True),
        readiness_runner=lambda: calls.append("readiness")
        or RemoteReadinessReport("ok", "root@166.88.232.2:22", [], ["readiness command"], False),
        egress_up_runner=lambda: calls.append("egress_up")
        or RemoteRolloutPhaseResult("egress_up", "success", "egress up", ["egress command"], True),
        service_apply_runner=lambda: calls.append("service_apply")
        or RemoteRolloutPhaseResult("service_apply", "success", "service_apply ok", ["service apply command"], True),
        socks5_smoke_command_runner=socks5_smoke_command_runner,
        leak_check_runner=lambda: calls.append("leak_check"),
    )

    assert result.status == "failed"
    assert result.message == "remote rollout stopped at socks5_smoke"
    assert calls == ["install", "readiness", "egress_up", "service_apply"]
    assert [phase.action for phase in result.phases] == ["install", "readiness", "egress_up", "service_apply", "socks5_smoke"]
    assert result.phases[-1].message == "socks5_smoke failed at loopback_greeting"
    assert result.phases[-1].performed_side_effects is False
    assert smoke_commands == result.phases[-1].commands_executed
    rendered = render_remote_rollout_run_result(result)
    assert "- socks5_smoke: failed - socks5_smoke failed at loopback_greeting" in rendered
    assert "  - loopback_greeting: failed returncode=1" in rendered
    assert "    stderr: connection refused" in rendered
    assert "leak_check" not in calls


def test_remote_rollout_command_real_path_uses_phase_runners_with_double_gate(monkeypatch):
    calls = []

    def fake_run_remote_rollout_cli(**kwargs):
        return main_module.run_remote_rollout_plan(
            main_module.build_remote_rollout_cli_plan(
                host=kwargs["host"],
                port=kwargs["port"],
                user=kwargs["user"],
                staging_dir=kwargs["staging_dir"],
            ),
            dry_run=kwargs["dry_run"],
            yes=kwargs["yes"],
            allow_remote_changes=kwargs["allow_remote_changes"],
            install_runner=lambda: calls.append("install")
            or RemoteRolloutPhaseResult("install", "success", "installed", ["install command"], True),
            readiness_runner=lambda: calls.append("readiness")
            or RemoteReadinessReport("ok", "root@166.88.232.2:22", [], ["readiness command"], False),
            egress_up_runner=lambda: calls.append("egress_up")
            or RemoteRolloutPhaseResult("egress_up", "success", "egress up", ["egress command"], True),
            service_apply_runner=lambda: calls.append("service_apply")
            or RemoteRolloutPhaseResult("service_apply", "success", "service_apply ok", ["service apply command"], True),
            socks5_smoke_runner=lambda: calls.append("socks5_smoke")
            or RemoteRolloutPhaseResult("socks5_smoke", "success", "socks5_smoke ok", ["socks smoke command"], False),
            leak_check_runner=lambda: calls.append("leak_check")
            or RemoteLeakCheckReport(
                "ok",
                "root@166.88.232.2:22",
                "198.51.100.10",
                "203.0.113.20",
                [RemoteLeakCheck("egress_guard", "ok", "egress guard passed")],
                ["leak check command"],
                False,
            ),
        )

    monkeypatch.setattr(main_module, "run_remote_rollout_cli", fake_run_remote_rollout_cli)

    result = runner.invoke(app, ["remote", "rollout", "--no-dry-run", "--yes", "--allow-remote-changes"])

    assert result.exit_code == 0
    assert "Remote rollout result" in result.output
    assert "status: success" in result.output
    assert "performed_side_effects: True" in result.output
    assert "- install: success - installed" in result.output
    assert "- readiness: success - readiness ok" in result.output
    assert "- egress_up: success - egress up" in result.output
    assert "- service_apply: success - service_apply ok" in result.output
    assert "- socks5_smoke: success - socks5_smoke ok" in result.output
    assert "- leak_check: success - leak_check ok" in result.output
    assert calls == ["install", "readiness", "egress_up", "service_apply", "socks5_smoke", "leak_check"]


def test_run_remote_rollout_cli_default_leak_check_uses_proxy_config_socks_port(monkeypatch):
    captured = {}

    def fake_leak_check_cli(**kwargs):
        captured.update(kwargs)
        return RemoteLeakCheckReport(
            "ok",
            "root@166.88.232.2:22",
            "198.51.100.10",
            "203.0.113.20",
            [RemoteLeakCheck("egress_guard", "ok", "egress guard passed")],
            ["leak check command"],
            False,
        )

    monkeypatch.setattr(main_module, "run_remote_leak_check_cli", fake_leak_check_cli)

    result = run_remote_rollout_cli(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        install_runner=lambda: RemoteRolloutPhaseResult("install", "success", "installed", ["install command"], True),
        readiness_runner=lambda: RemoteReadinessReport("ok", "root@166.88.232.2:22", [], ["readiness command"], False),
        egress_up_runner=lambda: RemoteRolloutPhaseResult("egress_up", "success", "egress up", ["egress command"], True),
        service_apply_runner=lambda: RemoteRolloutPhaseResult("service_apply", "success", "service_apply ok", ["service apply command"], True),
        socks5_smoke_runner=lambda: RemoteRolloutPhaseResult("socks5_smoke", "success", "socks5_smoke ok", ["socks smoke command"], False),
    )

    assert result.status == "success"
    assert captured == {"host": "166.88.232.2", "port": 22, "user": "root", "socks_port": 34501}


def test_remote_rollout_command_real_path_rejects_without_allow_remote_changes():
    result = runner.invoke(app, ["remote", "rollout", "--no-dry-run", "--yes"])

    assert result.exit_code == 1
    assert "remote rollout requires yes=True and allow_remote_changes=True" in result.output
    assert "performed_side_effects: False" in result.output


def test_remote_rollout_command_rejects_embedded_credentials():
    result = runner.invoke(app, ["remote", "rollout", "--host", "root:secret@203.0.113.10"])

    assert result.exit_code == 1
    assert "embedded credentials are not allowed" in result.output
    assert "secret" not in result.output


def test_run_remote_rollout_smoke_cli_rejects_real_execution_without_double_gate():
    calls = []

    result = run_remote_rollout_smoke_cli(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        rollout_runner=lambda: calls.append("rollout"),
    )

    assert result.status == "rejected"
    assert result.message == "remote rollout smoke requires yes=True and allow_remote_changes=True"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []


def test_remote_rollout_smoke_command_defaults_to_dry_run_without_remote_side_effects():
    result = runner.invoke(app, ["remote", "rollout-smoke"])

    assert result.exit_code == 0
    assert "Remote rollout smoke result" in result.output
    assert "status: dry_run" in result.output
    assert "target: root@166.88.232.2:22" in result.output
    assert "expected_phases: ['install', 'readiness', 'egress_up', 'service_apply', 'socks5_smoke', 'leak_check']" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert "sshpass" not in result.output.lower()
    assert "password" not in result.output.lower()


def test_remote_rollout_smoke_command_real_path_uses_rollout_runner_with_double_gate(monkeypatch):
    captured = {}
    rollout = RemoteRolloutRunResult(
        status="success",
        message="remote rollout completed through injected phase runners",
        target="root@166.88.232.2:22",
        phases=[
            RemoteRolloutPhaseResult("install", "success", "installed", ["install command"], True),
            RemoteRolloutPhaseResult("readiness", "success", "readiness ok", ["readiness command"], False),
            RemoteRolloutPhaseResult("egress_up", "success", "egress up", ["egress command"], True),
            RemoteRolloutPhaseResult("service_apply", "success", "service_apply ok", ["service apply command"], True),
            RemoteRolloutPhaseResult("socks5_smoke", "success", "socks5_smoke ok", ["socks smoke command"], False),
            RemoteRolloutPhaseResult("leak_check", "success", "leak_check ok", ["leak check command"], False),
        ],
        commands_executed=["install command", "readiness command", "egress command", "service apply command", "socks smoke command", "leak check command"],
        performed_side_effects=True,
    )
    smoke = RemoteRolloutSmokeResult(
        status="success",
        message="remote rollout smoke passed",
        target="root@166.88.232.2:22",
        expected_phases=["install", "readiness", "egress_up", "service_apply", "socks5_smoke", "leak_check"],
        rollout=rollout,
        commands_executed=rollout.commands_executed,
        performed_side_effects=True,
    )

    def fake_run_remote_rollout_smoke_cli(**kwargs):
        captured.update(kwargs)
        return smoke

    monkeypatch.setattr(main_module, "run_remote_rollout_smoke_cli", fake_run_remote_rollout_smoke_cli)

    result = runner.invoke(app, ["remote", "rollout-smoke", "--no-dry-run", "--yes", "--allow-remote-changes"])

    assert result.exit_code == 0
    assert captured["host"] == "166.88.232.2"
    assert captured["port"] == 22
    assert captured["user"] == "root"
    assert captured["staging_dir"] == "/tmp/migate-install"
    assert captured["dry_run"] is False
    assert captured["yes"] is True
    assert captured["allow_remote_changes"] is True
    assert "rollout_runner" not in captured
    assert "status: success" in result.output
    assert "rollout_status: success" in result.output
    assert "- service_apply: success - service_apply ok" in result.output
    assert "- socks5_smoke: success - socks5_smoke ok" in result.output
    assert "- leak_check: success - leak_check ok" in result.output
    assert "performed_side_effects: True" in result.output


def test_remote_rollout_smoke_command_real_path_accepts_backend_xray_tun(monkeypatch):
    captured = {}
    smoke = RemoteRolloutSmokeResult(
        status="success",
        message="remote rollout smoke passed",
        target="root@166.88.232.2:22",
        expected_phases=["install", "readiness", "egress_up", "service_apply", "socks5_smoke", "leak_check"],
        rollout=None,
        commands_executed=["egress xray-tun"],
        performed_side_effects=True,
    )

    def fake_run_remote_rollout_smoke_cli(**kwargs):
        captured.update(kwargs)
        return smoke

    monkeypatch.setattr(main_module, "run_remote_rollout_smoke_cli", fake_run_remote_rollout_smoke_cli)

    result = runner.invoke(app, ["remote", "rollout-smoke", "--backend", "xray-tun", "--no-dry-run", "--yes", "--allow-remote-changes"])

    assert result.exit_code == 0
    assert captured["backend"] == "xray-tun"
    assert "status: success" in result.output


def test_run_remote_rollout_smoke_cli_threads_backend_to_default_rollout_runner(monkeypatch):
    captured = {}
    rollout = RemoteRolloutRunResult(
        status="success",
        message="remote rollout completed through injected phase runners",
        target="root@166.88.232.2:22",
        phases=[
            RemoteRolloutPhaseResult("install", "success", "installed", ["install command"], True),
            RemoteRolloutPhaseResult("readiness", "success", "readiness ok", ["readiness command"], False),
            RemoteRolloutPhaseResult("egress_up", "success", "egress up", ["egress command"], True),
            RemoteRolloutPhaseResult("service_apply", "success", "service_apply ok", ["service apply command"], True),
            RemoteRolloutPhaseResult("socks5_smoke", "success", "socks5_smoke ok", ["socks smoke command"], False),
            RemoteRolloutPhaseResult("leak_check", "success", "leak_check ok", ["leak check command"], False),
        ],
        commands_executed=["install command", "readiness command", "egress command", "service apply command", "socks smoke command", "leak check command"],
        performed_side_effects=True,
    )

    def fake_run_remote_rollout_cli(**kwargs):
        captured.update(kwargs)
        return rollout

    monkeypatch.setattr(main_module, "run_remote_rollout_cli", fake_run_remote_rollout_cli)

    result = run_remote_rollout_smoke_cli(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        backend="xray-tun",
    )

    assert result.status == "success"
    assert captured["backend"] == "xray-tun"


def test_remote_rollout_smoke_command_real_path_rejects_without_allow_remote_changes():
    result = runner.invoke(app, ["remote", "rollout-smoke", "--no-dry-run", "--yes"])

    assert result.exit_code == 1
    assert "remote rollout smoke requires yes=True and allow_remote_changes=True" in result.output
    assert "performed_side_effects: False" in result.output


def test_remote_rollout_smoke_command_rejects_embedded_credentials():
    result = runner.invoke(app, ["remote", "rollout-smoke", "--host", "root:secret@203.0.113.10"])

    assert result.exit_code == 1
    assert "embedded credentials are not allowed" in result.output
    assert "secret" not in result.output


def test_run_remote_acceptance_cli_rejects_real_execution_without_double_gate():
    calls = []

    result = run_remote_acceptance_cli(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        doctor_runner=lambda: calls.append("doctor"),
        rollout_smoke_runner=lambda: calls.append("rollout_smoke"),
    )

    assert result.status == "rejected"
    assert result.message == "remote acceptance requires yes=True and allow_remote_changes=True"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []


def test_remote_acceptance_command_defaults_to_dry_run_without_remote_side_effects():
    result = runner.invoke(app, ["remote", "acceptance"])

    assert result.exit_code == 0
    assert "Remote acceptance result" in result.output
    assert "status: dry_run" in result.output
    assert "target: root@166.88.232.2:22" in result.output
    assert "expected_phases: ['doctor', 'rollout_smoke']" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert "Remote rollout dry-run" in result.output
    assert "migate remote egress up --host 166.88.232.2 --port 22 --user root --no-dry-run --yes --allow-remote-changes" in result.output
    assert "sshpass" not in result.output.lower()
    assert "password" not in result.output.lower()


def test_remote_acceptance_command_dry_run_with_backend_xray_tun_shows_rollout_egress_preview():
    result = runner.invoke(app, ["remote", "acceptance", "--backend", "xray-tun"])

    assert result.exit_code == 0
    assert "Remote acceptance result" in result.output
    assert "status: dry_run" in result.output
    assert "Remote rollout dry-run" in result.output
    assert "migate remote egress up --host 166.88.232.2 --port 22 --user root --backend xray-tun --no-dry-run --yes --allow-remote-changes" in result.output
    assert "performed_side_effects: False" in result.output
    assert "sshpass" not in result.output.lower()
    assert "password" not in result.output.lower()


def test_remote_acceptance_command_real_path_delegates_with_double_gate(monkeypatch):
    captured = {}
    acceptance = RemoteAcceptanceResult(
        status="success",
        message="remote acceptance passed",
        target="root@166.88.232.2:22",
        expected_phases=["doctor", "rollout_smoke"],
        phases=[],
        commands_executed=["ssh doctor", "rollout smoke"],
        performed_side_effects=True,
    )

    def fake_run_remote_acceptance_cli(**kwargs):
        captured.update(kwargs)
        return acceptance

    monkeypatch.setattr(main_module, "run_remote_acceptance_cli", fake_run_remote_acceptance_cli)

    result = runner.invoke(app, ["remote", "acceptance", "--no-dry-run", "--yes", "--allow-remote-changes"])

    assert result.exit_code == 0
    assert captured["host"] == "166.88.232.2"
    assert captured["port"] == 22
    assert captured["user"] == "root"
    assert captured["staging_dir"] == "/tmp/migate-install"
    assert captured["dry_run"] is False
    assert captured["yes"] is True
    assert captured["allow_remote_changes"] is True
    assert "doctor_runner" not in captured
    assert "rollout_smoke_runner" not in captured
    assert "Remote acceptance result" in result.output
    assert "status: success" in result.output
    assert "message: remote acceptance passed" in result.output
    assert "performed_side_effects: True" in result.output


def test_remote_acceptance_command_real_path_accepts_backend_xray_tun(monkeypatch):
    captured = {}
    acceptance = RemoteAcceptanceResult(
        status="success",
        message="remote acceptance passed",
        target="root@166.88.232.2:22",
        expected_phases=["doctor", "rollout_smoke"],
        phases=[],
        commands_executed=["ssh doctor", "rollout smoke xray-tun"],
        performed_side_effects=True,
        backend="xray-tun",
    )

    def fake_run_remote_acceptance_cli(**kwargs):
        captured.update(kwargs)
        return acceptance

    monkeypatch.setattr(main_module, "run_remote_acceptance_cli", fake_run_remote_acceptance_cli)

    result = runner.invoke(app, ["remote", "acceptance", "--backend", "xray-tun", "--no-dry-run", "--yes", "--allow-remote-changes"])

    assert result.exit_code == 0
    assert captured["backend"] == "xray-tun"
    assert "status: success" in result.output
    assert "backend: xray-tun" in result.output


def test_run_remote_acceptance_cli_threads_backend_to_default_rollout_smoke_runner(monkeypatch):
    captured = {}
    smoke = RemoteRolloutSmokeResult(
        status="success",
        message="remote rollout smoke passed",
        target="root@166.88.232.2:22",
        expected_phases=["install", "readiness", "egress_up", "service_apply", "socks5_smoke", "leak_check"],
        rollout=None,
        commands_executed=["rollout smoke xray-tun"],
        performed_side_effects=True,
    )

    def fake_run_remote_rollout_smoke_cli(**kwargs):
        captured.update(kwargs)
        return smoke

    monkeypatch.setattr(main_module, "run_remote_rollout_smoke_cli", fake_run_remote_rollout_smoke_cli)

    result = run_remote_acceptance_cli(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        backend="xray-tun",
    )

    assert result.status == "success"
    assert captured["backend"] == "xray-tun"


def test_remote_acceptance_command_real_path_rejects_without_allow_remote_changes():
    result = runner.invoke(app, ["remote", "acceptance", "--no-dry-run", "--yes"])

    assert result.exit_code == 1
    assert "remote acceptance requires yes=True and allow_remote_changes=True" in result.output
    assert "performed_side_effects: False" in result.output


def test_remote_acceptance_command_rejects_embedded_credentials():
    result = runner.invoke(app, ["remote", "acceptance", "--host", "root:secret@203.0.113.10"])

    assert result.exit_code == 1
    assert "embedded credentials are not allowed" in result.output
    assert "secret" not in result.output


def test_build_remote_egress_cli_plan_defaults_to_dedicated_test_vps_redacted():
    plan = build_remote_egress_cli_plan(action="up")

    assert plan.status == "dry_run"
    assert plan.action == "up"
    assert plan.target == "root@166.88.232.2:22"
    assert plan.credential_hint == "[REDACTED]"
    assert plan.commands_executed == []
    assert plan.performed_side_effects is False
    assert [step.action for step in plan.steps] == ["doctor", "egress_up", "post_up_status"]


def test_remote_egress_up_command_defaults_to_dry_run_without_ssh_or_side_effects():
    result = runner.invoke(app, ["remote", "egress", "up"])

    assert result.exit_code == 0
    assert "Remote egress up dry-run" in result.output
    assert "target: root@166.88.232.2:22" in result.output
    assert "credential_hint: [REDACTED]" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert "- doctor: planned read-only" in result.output
    assert "- egress_up: planned side-effect" in result.output
    assert "ssh -p 22 root@166.88.232.2 -- migate egress up --no-dry-run --yes --allow-system-changes" in result.output
    assert "sshpass" not in result.output.lower()
    assert "password" not in result.output.lower()


def test_remote_egress_down_command_accepts_custom_target_without_side_effects():
    result = runner.invoke(app, ["remote", "egress", "down", "--host", "203.0.113.10", "--port", "62422", "--user", "ubuntu"])

    assert result.exit_code == 0
    assert "Remote egress down dry-run" in result.output
    assert "target: ubuntu@203.0.113.10:62422" in result.output
    assert "ssh -p 62422 ubuntu@203.0.113.10 -- migate egress down --no-dry-run --yes --allow-system-changes" in result.output
    assert "performed_side_effects: False" in result.output


def test_remote_egress_command_rejects_embedded_credentials():
    result = runner.invoke(app, ["remote", "egress", "up", "--host", "root:secret@203.0.113.10"])

    assert result.exit_code == 1
    assert "embedded credentials are not allowed" in result.output
    assert "secret" not in result.output


def test_remote_egress_up_command_accepts_backend_xray_tun_in_dry_run_plan():
    result = runner.invoke(app, ["remote", "egress", "up", "--backend", "xray-tun"])

    assert result.exit_code == 0
    assert "ssh -p 22 root@166.88.232.2 -- migate egress up --backend xray-tun --no-dry-run --yes --allow-system-changes" in result.output
    assert "ssh -p 22 root@166.88.232.2 -- migate egress status --backend xray-tun" in result.output
    assert "performed_side_effects: False" in result.output


def test_remote_egress_down_command_accepts_backend_xray_tun_in_dry_run_plan():
    result = runner.invoke(app, ["remote", "egress", "down", "--backend", "xray-tun"])

    assert result.exit_code == 0
    assert "ssh -p 22 root@166.88.232.2 -- migate egress down --backend xray-tun --no-dry-run --yes --allow-system-changes" in result.output
    assert "ssh -p 22 root@166.88.232.2 -- migate egress status --backend xray-tun" in result.output
    assert "performed_side_effects: False" in result.output


def test_run_remote_egress_cli_rejects_real_execution_without_double_gate():
    calls: list[str] = []

    result = run_remote_egress_cli(
        action="up",
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        command_runner=lambda command: calls.append(command) or RemoteEgressCommandResult(0, "ok", ""),
    )

    assert result.status == "rejected"
    assert result.message == "remote egress requires yes=True and allow_remote_changes=True"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []


def test_remote_egress_command_real_path_uses_runner_shell_with_double_gate(monkeypatch):
    calls: list[str] = []

    def fake_run_remote_egress_cli(**kwargs):
        return main_module.run_remote_egress_plan(
            main_module.build_remote_egress_cli_plan(
                action=kwargs["action"],
                host=kwargs["host"],
                port=kwargs["port"],
                user=kwargs["user"],
            ),
            dry_run=kwargs["dry_run"],
            yes=kwargs["yes"],
            allow_remote_changes=kwargs["allow_remote_changes"],
            runner=lambda command: calls.append(command) or RemoteEgressCommandResult(0, "ok", ""),
        )

    monkeypatch.setattr(main_module, "run_remote_egress_cli", fake_run_remote_egress_cli)

    result = runner.invoke(app, ["remote", "egress", "up", "--no-dry-run", "--yes", "--allow-remote-changes"])

    assert result.exit_code == 0
    assert "Remote egress result" in result.output
    assert "status: success" in result.output
    assert "action: up" in result.output
    assert "performed_side_effects: True" in result.output
    assert "- egress_up: success returncode=0" in result.output
    assert calls[0] == "migate remote doctor --host 166.88.232.2 --port 22 --user root"
    assert len(calls) == 3


def test_remote_egress_command_real_path_rejects_without_allow_remote_changes():
    result = runner.invoke(app, ["remote", "egress", "down", "--no-dry-run", "--yes"])

    assert result.exit_code == 1
    assert "remote egress requires yes=True and allow_remote_changes=True" in result.output
    assert "performed_side_effects: False" in result.output


def test_egress_up_command_exits_nonzero_when_lifecycle_fails(monkeypatch):
    def fake_bring_up_egress(*args, **kwargs):
        return EgressLifecycleResult(
            status="failed",
            message="egress up stopped before routing; OpenVPN start failed",
            phases=[],
            commands_executed=["openvpn --config /var/lib/migate/runtime/active.ovpn"],
            performed_side_effects=True,
        )

    monkeypatch.setattr(main_module, "bring_up_egress", fake_bring_up_egress)

    result = runner.invoke(app, ["egress", "up", "--no-dry-run", "--yes", "--allow-system-changes"])

    assert result.exit_code == 1
    assert "status: failed" in result.output
    assert "OpenVPN start failed" in result.output


def test_egress_result_renderer_includes_xray_tun_phase_failure_details():
    lifecycle_result = EgressLifecycleResult(
        status="failed",
        message="egress up stopped before routing; xray-tun apply start failed",
        phases=[
            EgressLifecyclePhase(
                name="xray_tun_apply_start",
                status="invalid_config",
                result=XrayApplyResult(
                    status="invalid_config",
                    message="xray tun config bootstrap failed; service start skipped",
                    config_path="/etc/migate/xray/config.json",
                    validation=XrayValidationResult(
                        "invalid",
                        1,
                        "",
                        "failed to parse inbound protocol tun: unknown protocol",
                    ),
                    systemctl_results=[],
                    performed_side_effects=True,
                ),
            )
        ],
        commands_executed=[],
        performed_side_effects=True,
    )

    rendered = main_module._render_egress_result(lifecycle_result)

    assert "- phase: xray_tun_apply_start status: invalid_config" in rendered
    assert "message: xray tun config bootstrap failed; service start skipped" in rendered
    assert "validation_status: invalid" in rendered
    assert "validation_stderr: failed to parse inbound protocol tun: unknown protocol" in rendered


def test_egress_up_dry_run_accepts_backend_xray_tun_without_side_effects():
    result = runner.invoke(app, ["egress", "up", "--backend", "xray-tun"])

    assert result.exit_code == 0
    assert "status: dry_run" in result.output
    assert "backend: xray-tun" in result.output
    assert "systemctl start migate-xray-tun.service" in result.output
    assert "performed_side_effects: False" in result.output


def test_egress_up_dry_run_rejects_unknown_backend_without_traceback():
    result = runner.invoke(app, ["egress", "up", "--backend", "wireguard"])

    assert result.exit_code == 1
    assert "status: rejected" in result.output
    assert "unsupported egress backend: wireguard" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert "Traceback" not in result.output


def test_egress_down_dry_run_accepts_backend_xray_tun_without_side_effects():
    result = runner.invoke(app, ["egress", "down", "--backend", "xray-tun"])

    assert result.exit_code == 0
    assert "status: dry_run" in result.output
    assert "systemctl stop migate-xray-tun.service" in result.output
    assert "performed_side_effects: False" in result.output


def test_egress_down_dry_run_rejects_unknown_backend_without_traceback():
    result = runner.invoke(app, ["egress", "down", "--backend", "wireguard"])

    assert result.exit_code == 1
    assert "status: rejected" in result.output
    assert "unsupported egress backend: wireguard" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert "Traceback" not in result.output


def test_egress_up_command_accepts_backend_xray_tun_and_delegates_to_lifecycle(monkeypatch):
    captured = {}

    def fake_bring_up_egress(tunnel_plan, routing_plan, **kwargs):
        captured["tunnel_backend"] = tunnel_plan.backend
        captured["tunnel_command"] = tunnel_plan.command
        captured["required_paths"] = tunnel_plan.required_paths
        captured["routing_commands"] = routing_plan.commands
        captured["kwargs"] = kwargs
        return EgressLifecycleResult(
            status="up",
            message="egress brought up",
            phases=[EgressLifecyclePhase("xray_tun_apply_start", "success", None)],
            commands_executed=["systemctl start migate-xray-tun.service"],
            performed_side_effects=True,
        )

    monkeypatch.setattr(main_module, "bring_up_egress", fake_bring_up_egress)

    result = runner.invoke(app, ["egress", "up", "--backend", "xray-tun", "--no-dry-run", "--yes", "--allow-system-changes"])

    assert result.exit_code == 0
    assert captured["tunnel_backend"] == "xray-tun"
    assert captured["tunnel_command"] == ["systemctl", "start", "migate-xray-tun.service"]
    assert captured["required_paths"] == ["/etc/migate/xray/config.json"]
    assert captured["kwargs"] == {"allow_side_effects": True}
    assert "status: up" in result.output
    assert "xray_tun_apply_start" in result.output


def test_egress_down_command_accepts_backend_xray_tun_and_delegates_to_lifecycle(monkeypatch):
    captured = {}

    def fake_bring_down_egress(cleanup_plan, stop_plan, **kwargs):
        captured["stop_backend"] = stop_plan.backend
        captured["stop_command"] = stop_plan.command
        captured["cleanup_commands"] = cleanup_plan.commands
        captured["kwargs"] = kwargs
        return EgressLifecycleResult(
            status="down",
            message="egress brought down",
            phases=[EgressLifecyclePhase("xray_tun_stop", "success", None)],
            commands_executed=["systemctl stop migate-xray-tun.service"],
            performed_side_effects=True,
        )

    monkeypatch.setattr(main_module, "bring_down_egress", fake_bring_down_egress)

    result = runner.invoke(app, ["egress", "down", "--backend", "xray-tun", "--no-dry-run", "--yes", "--allow-system-changes"])

    assert result.exit_code == 0
    assert captured["stop_backend"] == "xray-tun"
    assert captured["stop_command"] == ["systemctl", "stop", "migate-xray-tun.service"]
    assert captured["kwargs"] == {"allow_side_effects": True}
    assert "status: down" in result.output
    assert "xray_tun_stop" in result.output


def test_build_remote_install_cli_plan_defaults_to_dedicated_test_vps_redacted():
    plan = build_remote_install_cli_plan()

    assert plan.status == "dry_run"
    assert plan.target == "root@166.88.232.2:22"
    assert plan.credential_hint == "[REDACTED]"
    assert plan.commands_executed == []
    assert plan.performed_side_effects is False
    assert [step.action for step in plan.steps] == [
        "doctor",
        "sync_project",
        "install_python_package",
        "install_xray",
        "write_services",
        "post_install_doctor",
    ]


def test_remote_install_command_defaults_to_dry_run_without_ssh_or_side_effects():
    result = runner.invoke(app, ["remote", "install"])

    assert result.exit_code == 0
    assert "Remote install dry-run" in result.output
    assert "target: root@166.88.232.2:22" in result.output
    assert "credential_hint: [REDACTED]" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert "- doctor: planned read-only" in result.output
    assert "- sync_project: planned side-effect" in result.output
    assert "rsync -az --delete ./ root@166.88.232.2:/tmp/migate-install/" in result.output
    assert "sshpass" not in result.output.lower()
    assert "password" not in result.output.lower()


def test_remote_install_command_accepts_custom_target_and_staging_dir():
    result = runner.invoke(
        app,
        [
            "remote",
            "install",
            "--host",
            "203.0.113.10",
            "--port",
            "62422",
            "--user",
            "ubuntu",
            "--staging-dir",
            "/tmp/migate-custom",
        ],
    )

    assert result.exit_code == 0
    assert "target: ubuntu@203.0.113.10:62422" in result.output
    assert "rsync -az --delete ./ ubuntu@203.0.113.10:/tmp/migate-custom/" in result.output
    assert "ssh -p 62422 ubuntu@203.0.113.10 -- 'cd /tmp/migate-custom && python3 -m venv .venv && .venv/bin/python -m pip install . && ln -sf /tmp/migate-custom/.venv/bin/migate /usr/local/bin/migate'" in result.output
    assert "performed_side_effects: False" in result.output


def test_remote_install_command_rejects_embedded_credentials():
    result = runner.invoke(app, ["remote", "install", "--host", "root:secret@203.0.113.10"])

    assert result.exit_code == 1
    assert "embedded credentials are not allowed" in result.output
    assert "secret" not in result.output


def test_remote_install_command_rejects_unsafe_staging_dir():
    result = runner.invoke(app, ["remote", "install", "--staging-dir", "/etc/migate"])

    assert result.exit_code == 1
    assert "staging_dir must be under /tmp/" in result.output


def test_run_remote_install_cli_rejects_real_execution_without_double_gate():
    calls = []

    result = run_remote_install_cli(
        host="166.88.232.2",
        port=22,
        user="root",
        staging_dir="/tmp/migate-install",
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        command_runner=lambda command: calls.append(command) or RemoteInstallCommandResult(0, "ok", ""),
    )

    assert result.status == "rejected"
    assert result.message == "remote install requires yes=True and allow_remote_changes=True"
    assert result.commands_executed == []
    assert result.performed_side_effects is False
    assert calls == []


def test_remote_install_command_real_path_uses_runner_shell_with_double_gate(monkeypatch):
    calls = []

    def fake_run_remote_install_cli(**kwargs):
        result = main_module.run_remote_install_plan(
            main_module.build_remote_install_cli_plan(
                host=kwargs["host"],
                port=kwargs["port"],
                user=kwargs["user"],
                staging_dir=kwargs["staging_dir"],
            ),
            dry_run=kwargs["dry_run"],
            yes=kwargs["yes"],
            allow_remote_changes=kwargs["allow_remote_changes"],
            runner=lambda command: calls.append(command) or RemoteInstallCommandResult(0, "ok", ""),
        )
        return result

    monkeypatch.setattr(main_module, "run_remote_install_cli", fake_run_remote_install_cli)

    result = runner.invoke(app, ["remote", "install", "--no-dry-run", "--yes", "--allow-remote-changes"])

    assert result.exit_code == 0
    assert "Remote install result" in result.output
    assert "status: success" in result.output
    assert "performed_side_effects: True" in result.output
    assert "- sync_project: success returncode=0" in result.output
    assert calls[0] == "migate remote doctor --host 166.88.232.2 --port 22 --user root"
    assert len(calls) == 6


def test_remote_install_command_real_path_rejects_without_allow_remote_changes():
    result = runner.invoke(app, ["remote", "install", "--no-dry-run", "--yes"])

    assert result.exit_code == 1
    assert "remote install requires yes=True and allow_remote_changes=True" in result.output
    assert "performed_side_effects: False" in result.output


def test_build_remote_lifecycle_cli_plan_defaults_to_dedicated_test_vps_redacted():
    plan = build_remote_lifecycle_cli_plan()

    assert plan.status == "dry_run"
    assert plan.target == "root@166.88.232.2:22"
    assert plan.credential_hint == "[REDACTED]"
    assert plan.commands_executed == []
    assert plan.performed_side_effects is False


def test_remote_lifecycle_command_defaults_to_dry_run_without_ssh_or_side_effects():
    result = runner.invoke(app, ["remote", "lifecycle"])

    assert result.exit_code == 0
    assert "Remote lifecycle dry-run" in result.output
    assert "target: root@166.88.232.2:22" in result.output
    assert "credential_hint: [REDACTED]" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert "- doctor: planned read-only - run read-only remote doctor/preflight checks" in result.output
    assert "- acceptance: planned side-effect - delegate to remote acceptance: doctor -> rollout_smoke" in result.output
    assert "- cleanup:" not in result.output
    assert "sshpass" not in result.output.lower()
    assert "password" not in result.output.lower()


def test_remote_lifecycle_command_accepts_custom_target_without_credentials():
    result = runner.invoke(app, ["remote", "lifecycle", "--host", "203.0.113.10", "--port", "62422", "--user", "ubuntu"])

    assert result.exit_code == 0
    assert "target: ubuntu@203.0.113.10:62422" in result.output
    assert "- doctor: planned read-only - run read-only remote doctor/preflight checks" in result.output
    assert "ssh ubuntu@203.0.113.10 -p 62422" not in result.output
    assert "performed_side_effects: False" in result.output


def test_remote_lifecycle_command_rejects_embedded_credentials():
    result = runner.invoke(app, ["remote", "lifecycle", "--host", "root:secret@203.0.113.10"])

    assert result.exit_code == 1
    assert "embedded credentials are not allowed" in result.output
    assert "secret" not in result.output


def test_run_remote_lifecycle_cli_rejects_real_execution_without_double_gate(monkeypatch):
    from migate.remote.doctor import RemoteDoctorCheck, RemoteDoctorReport

    calls = []
    report = RemoteDoctorReport("ok", "root@166.88.232.2:22", [RemoteDoctorCheck("ssh", "ok", "ok")], [], False)

    result = run_remote_lifecycle_cli(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=False,
        doctor_runner=lambda: calls.append("doctor") or report,
    )

    assert result.status == "rejected"
    assert result.performed_side_effects is False
    assert calls == []


def test_run_remote_lifecycle_cli_threads_backend_to_acceptance_runner(monkeypatch):
    from migate.remote.doctor import RemoteDoctorCheck, RemoteDoctorReport

    captured = {}
    acceptance = RemoteAcceptanceResult(
        status="success",
        message="remote acceptance passed",
        target="root@166.88.232.2:22",
        expected_phases=["doctor", "rollout_smoke"],
        phases=[],
        commands_executed=["acceptance command"],
        performed_side_effects=True,
        backend="xray-tun",
    )

    monkeypatch.setattr(main_module, "run_remote_acceptance_cli", lambda **kwargs: captured.update(kwargs) or acceptance)

    result = run_remote_lifecycle_cli(
        host="166.88.232.2",
        port=22,
        user="root",
        dry_run=False,
        yes=True,
        allow_remote_changes=True,
        backend="xray-tun",
        doctor_runner=lambda: RemoteDoctorReport("ok", "root@166.88.232.2:22", [RemoteDoctorCheck("ssh", "ok", "ok")], ["ssh doctor"], False),
    )

    assert result.status == "success"
    assert result.commands_executed == ["ssh doctor", "acceptance command"]
    assert result.performed_side_effects is True
    assert captured["backend"] == "xray-tun"
    assert captured["dry_run"] is False
    assert captured["yes"] is True
    assert captured["allow_remote_changes"] is True


def test_remote_lifecycle_command_real_path_runs_acceptance_with_double_gate(monkeypatch):
    from migate.remote.doctor import RemoteDoctorCheck, RemoteDoctorReport

    captured = {}
    report = RemoteDoctorReport(
        status="ok",
        target="root@166.88.232.2:22",
        checks=[RemoteDoctorCheck("ssh_connectivity", "ok", "SSH probe succeeded")],
        commands_executed=["ssh -p 22 root@166.88.232.2 ..."],
        performed_side_effects=False,
    )
    acceptance = RemoteAcceptanceResult(
        status="success",
        message="remote acceptance passed",
        target="root@166.88.232.2:22",
        expected_phases=["doctor", "rollout_smoke"],
        phases=[],
        commands_executed=["acceptance command"],
        performed_side_effects=True,
        backend="xray-tun",
    )
    monkeypatch.setattr(main_module, "run_remote_doctor", lambda **kwargs: report)
    monkeypatch.setattr(main_module, "run_remote_acceptance_cli", lambda **kwargs: captured.update(kwargs) or acceptance)

    result = runner.invoke(app, ["remote", "lifecycle", "--backend", "xray-tun", "--no-dry-run", "--yes", "--allow-remote-changes"])

    assert result.exit_code == 0
    assert "Remote lifecycle result" in result.output
    assert "status: success" in result.output
    assert "- doctor: success - remote doctor ok" in result.output
    assert "- acceptance: success - remote acceptance passed" in result.output
    assert "performed_side_effects: True" in result.output
    assert "not implemented" not in result.output
    assert captured["backend"] == "xray-tun"


def test_remote_lifecycle_command_real_path_rejects_without_allow_remote_changes(monkeypatch):
    calls = []
    monkeypatch.setattr(main_module, "run_remote_doctor", lambda **kwargs: calls.append(kwargs))

    result = runner.invoke(app, ["remote", "lifecycle", "--no-dry-run", "--yes"])

    assert result.exit_code == 1
    assert "remote lifecycle requires yes=True and allow_remote_changes=True" in result.output
    assert "performed_side_effects: False" in result.output
    assert calls == []


def test_remote_doctor_command_renders_injected_read_only_report(monkeypatch):
    from migate.remote.doctor import RemoteDoctorCheck, RemoteDoctorReport

    report = RemoteDoctorReport(
        status="ok",
        target="root@166.88.232.2:22",
        checks=[RemoteDoctorCheck("ssh_connectivity", "ok", "SSH probe succeeded")],
        commands_executed=["ssh -p 22 root@166.88.232.2 ..."],
        performed_side_effects=False,
    )
    monkeypatch.setattr(main_module, "run_remote_doctor", lambda **kwargs: report)

    result = runner.invoke(app, ["remote", "doctor"])

    assert result.exit_code == 0
    assert "Remote doctor" in result.output
    assert "target: root@166.88.232.2:22" in result.output
    assert "ssh_connectivity: ok - SSH probe succeeded" in result.output
    assert "commands_executed: ['ssh -p 22 root@166.88.232.2 ...']" in result.output
    assert "performed_side_effects: False" in result.output


def test_remote_doctor_command_rejects_embedded_credentials_without_probe():
    result = runner.invoke(app, ["remote", "doctor", "--host", "root:secret@203.0.113.10"])

    assert result.exit_code == 1
    assert "embedded credentials are not allowed" in result.output
    assert "secret" not in result.output


def test_vpn_config_save_defaults_to_preview_without_writing(tmp_path: Path):
    source = tmp_path / "source.ovpn"
    target = tmp_path / "active.ovpn"
    source.write_text("client\nremote 1.2.3.4 1194\ndev tun\n", encoding="utf-8")

    result = runner.invoke(app, ["vpn", "config", "save", "--source", str(source), "--target", str(target)])

    assert result.exit_code == 0
    assert "status: dry_run" in result.output
    assert f"source: {source}" in result.output
    assert f"target: {target}" in result.output
    assert "performed_side_effects: False" in result.output
    assert "dev tun-migate" in result.output
    assert not target.exists()


def test_vpn_config_save_requires_double_gate_before_writing(tmp_path: Path):
    source = tmp_path / "source.ovpn"
    target = tmp_path / "active.ovpn"
    source.write_text("client\nremote 1.2.3.4 1194\ndev tun\n", encoding="utf-8")

    result = runner.invoke(app, ["vpn", "config", "save", "--source", str(source), "--target", str(target), "--yes"])

    assert result.exit_code == 1
    assert "status: rejected" in result.output
    assert "performed_side_effects: False" in result.output
    assert not target.exists()


def test_vpn_config_save_writes_rendered_active_ovpn_with_double_gate(tmp_path: Path):
    source = tmp_path / "source.ovpn"
    target = tmp_path / "runtime" / "active.ovpn"
    source.write_text("client\nremote 1.2.3.4 1194\ndev tun\nstatus old.log\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "vpn",
            "config",
            "save",
            "--source",
            str(source),
            "--target",
            str(target),
            "--yes",
            "--allow-system-changes",
        ],
    )

    assert result.exit_code == 0
    assert "status: saved" in result.output
    assert "performed_side_effects: True" in result.output
    saved = target.read_text(encoding="utf-8")
    assert "dev tun-migate" in saved
    assert "status old.log" not in saved
    assert f"status {target.parent / 'status.json'}" in saved


def test_vpn_config_save_fails_when_source_is_missing(tmp_path: Path):
    source = tmp_path / "missing.ovpn"
    target = tmp_path / "active.ovpn"

    result = runner.invoke(app, ["vpn", "config", "save", "--source", str(source), "--target", str(target)])

    assert result.exit_code == 1
    assert "status: failed" in result.output
    assert "source OpenVPN config not found" in result.output
    assert not target.exists()


def test_egress_up_command_defaults_to_dry_run_without_side_effects(monkeypatch):
    calls = []

    def fake_bring_up_egress(*args, **kwargs):
        calls.append((args, kwargs))
        return EgressLifecycleResult(
            status="rejected",
            message="allow_side_effects must be true to bring egress up",
            phases=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    monkeypatch.setattr(main_module, "bring_up_egress", fake_bring_up_egress)

    result = runner.invoke(app, ["egress", "up"])

    assert result.exit_code == 0
    assert "status: dry_run" in result.output
    assert "message: egress up dry-run preview" in result.output
    assert "performed_side_effects: False" in result.output
    assert "commands_executed: []" in result.output
    assert "backend: openvpn" in result.output
    assert "openvpn start" in result.output
    assert "policy routing apply" in result.output
    assert calls == []


def test_egress_up_dry_run_renders_xray_tun_backend_plan(monkeypatch):
    def fake_config():
        from migate.config import EgressConfig, MiGateConfig

        return MiGateConfig(egress=EgressConfig(backend="xray-tun"))

    monkeypatch.setattr(main_module, "MiGateConfig", fake_config)

    result = runner.invoke(app, ["egress", "up"])

    assert result.exit_code == 0
    assert "status: dry_run" in result.output
    assert "backend: xray-tun" in result.output
    assert "xray-tun start: systemctl start migate-xray-tun.service" in result.output
    assert "performed_side_effects: False" in result.output


def test_egress_down_command_defaults_to_dry_run_without_side_effects(monkeypatch, tmp_path: Path):
    calls = []
    pid_file = tmp_path / "openvpn.pid"
    pid_file.write_text("4321\n", encoding="utf-8")

    def fake_bring_down_egress(*args, **kwargs):
        calls.append((args, kwargs))
        return EgressLifecycleResult(
            status="rejected",
            message="allow_side_effects must be true to bring egress down",
            phases=[],
            commands_executed=[],
            performed_side_effects=False,
        )

    monkeypatch.setattr(main_module, "bring_down_egress", fake_bring_down_egress)

    result = runner.invoke(app, ["egress", "down", "--pid-file", str(pid_file)])

    assert result.exit_code == 0
    assert "status: dry_run" in result.output
    assert "message: egress down dry-run preview" in result.output
    assert "performed_side_effects: False" in result.output
    assert "commands_executed: []" in result.output
    assert "policy routing cleanup" in result.output
    assert "openvpn stop" in result.output
    assert calls == []


def test_egress_down_dry_run_renders_xray_tun_backend_plan(monkeypatch, tmp_path: Path):
    def fake_config():
        from migate.config import EgressConfig, MiGateConfig

        return MiGateConfig(egress=EgressConfig(backend="xray-tun"))

    monkeypatch.setattr(main_module, "MiGateConfig", fake_config)

    result = runner.invoke(app, ["egress", "down", "--pid-file", str(tmp_path / "ignored.pid")])

    assert result.exit_code == 0
    assert "status: dry_run" in result.output
    assert "xray-tun stop: systemctl stop migate-xray-tun.service" in result.output
    assert "openvpn stop" not in result.output
    assert "performed_side_effects: False" in result.output


def test_egress_up_command_runs_orchestration_only_with_double_gate(monkeypatch):
    calls = []
    fake_result = EgressLifecycleResult(
        status="up",
        message="egress brought up",
        phases=[
            EgressLifecyclePhase(name="openvpn_start", status="started", result=object()),
            EgressLifecyclePhase(name="policy_routing_apply", status="applied", result=object()),
        ],
        commands_executed=["openvpn --config /var/lib/migate/runtime/active.ovpn", "ip rule add fwmark 0x66 table 100"],
        performed_side_effects=True,
    )

    def fake_bring_up_egress(*args, **kwargs):
        calls.append((args, kwargs))
        return fake_result

    monkeypatch.setattr(main_module, "bring_up_egress", fake_bring_up_egress)

    result = runner.invoke(app, ["egress", "up", "--no-dry-run", "--yes", "--allow-system-changes"])

    assert result.exit_code == 0
    assert "status: up" in result.output
    assert "message: egress brought up" in result.output
    assert "performed_side_effects: True" in result.output
    assert "phase: openvpn_start status: started" in result.output
    assert "phase: policy_routing_apply status: applied" in result.output
    assert len(calls) == 1


def test_egress_up_command_uses_xray_tun_backend_plan_when_selected(monkeypatch):
    calls = []

    def fake_config():
        from migate.config import EgressConfig, MiGateConfig

        return MiGateConfig(egress=EgressConfig(backend="xray-tun"))

    def fake_bring_up_egress(*args, **kwargs):
        calls.append((args, kwargs))
        return EgressLifecycleResult(
            status="up",
            message="egress brought up",
            phases=[EgressLifecyclePhase(name="tunnel_start", status="started", result=object())],
            commands_executed=["systemctl start migate-xray-tun.service"],
            performed_side_effects=True,
        )

    monkeypatch.setattr(main_module, "MiGateConfig", fake_config)
    monkeypatch.setattr(main_module, "bring_up_egress", fake_bring_up_egress)

    result = runner.invoke(app, ["egress", "up", "--no-dry-run", "--yes", "--allow-system-changes"])

    assert result.exit_code == 0
    assert "status: up" in result.output
    assert "systemctl start migate-xray-tun.service" in result.output
    assert len(calls) == 1
    tunnel_plan = calls[0][0][0]
    assert tunnel_plan.backend == "xray-tun"
    assert tunnel_plan.command == ["systemctl", "start", "migate-xray-tun.service"]


def test_egress_up_command_rejects_unknown_backend_without_orchestration(monkeypatch):
    calls = []

    def fake_config():
        from migate.config import EgressConfig, MiGateConfig

        return MiGateConfig(egress=EgressConfig(backend="wireguard"))

    def fake_bring_up_egress(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("bring_up_egress should not run for unknown backend")

    monkeypatch.setattr(main_module, "MiGateConfig", fake_config)
    monkeypatch.setattr(main_module, "bring_up_egress", fake_bring_up_egress)

    result = runner.invoke(app, ["egress", "up", "--no-dry-run", "--yes", "--allow-system-changes"])

    assert result.exit_code == 1
    assert "status: rejected" in result.output
    assert "unsupported egress backend: wireguard" in result.output
    assert "performed_side_effects: False" in result.output
    assert calls == []


def test_egress_down_command_requires_double_gate_before_orchestration(monkeypatch, tmp_path: Path):
    calls = []
    pid_file = tmp_path / "openvpn.pid"
    pid_file.write_text("4321\n", encoding="utf-8")

    def fake_bring_down_egress(*args, **kwargs):
        calls.append((args, kwargs))
        return EgressLifecycleResult(
            status="down",
            message="egress brought down",
            phases=[],
            commands_executed=[],
            performed_side_effects=True,
        )

    monkeypatch.setattr(main_module, "bring_down_egress", fake_bring_down_egress)

    result = runner.invoke(app, ["egress", "down", "--pid-file", str(pid_file), "--no-dry-run", "--yes"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "egress down requires yes=True and allow_system_changes=True" in result.output
    assert "performed_side_effects: False" in result.output
    assert calls == []


def test_egress_doctor_command_renders_read_only_report(monkeypatch):
    report = EgressStatusReport(
        status="failed",
        checks=[
            EgressStatusCheck("tun_interface", "failed", "tun-migate interface is missing"),
            EgressStatusCheck("egress_guard", "failed", "tun-migate interface is missing; egress blocked"),
        ],
        performed_side_effects=False,
    )
    monkeypatch.setattr(main_module, "run_egress_doctor", lambda config=None: report)

    result = runner.invoke(app, ["egress", "doctor"])

    assert result.exit_code == 0
    assert "Egress doctor" in result.output
    assert "status: failed" in result.output
    assert "tun_interface: failed - tun-migate interface is missing" in result.output
    assert "performed_side_effects: False" in result.output


def test_egress_status_command_renders_observational_report(monkeypatch):
    report = EgressStatusReport(
        status="observed",
        checks=[
            EgressStatusCheck("tunnel_process", "failed", "openvpn tunnel for tun-migate is not running"),
            EgressStatusCheck("policy_routing_plan", "ok", "policy routing plan targets table 100 fwmark 0x66 via tun-migate"),
        ],
        performed_side_effects=False,
    )
    monkeypatch.setattr(main_module, "run_egress_status", lambda config=None: report)

    result = runner.invoke(app, ["egress", "status"])

    assert result.exit_code == 0
    assert "Egress status" in result.output
    assert "status: observed" in result.output
    assert "tunnel_process: failed - openvpn tunnel for tun-migate is not running" in result.output
    assert "policy_routing_plan: ok - policy routing plan targets table 100 fwmark 0x66 via tun-migate" in result.output
    assert "performed_side_effects: False" in result.output


def test_egress_status_command_accepts_backend_xray_tun_override(monkeypatch):
    captured = {}

    def fake_run_egress_status(config=None):
        captured["backend"] = config.egress.backend
        return EgressStatusReport(
            status="observed",
            checks=[EgressStatusCheck("tunnel_process", "ok", "xray-tun tunnel for tun-migate is running")],
            performed_side_effects=False,
        )

    monkeypatch.setattr(main_module, "run_egress_status", fake_run_egress_status)

    result = runner.invoke(app, ["egress", "status", "--backend", "xray-tun"])

    assert result.exit_code == 0
    assert captured == {"backend": "xray-tun"}
    assert "xray-tun tunnel for tun-migate is running" in result.output
    assert "performed_side_effects: False" in result.output


def test_egress_doctor_command_accepts_backend_xray_tun_override(monkeypatch):
    captured = {}

    def fake_run_egress_doctor(config=None):
        captured["backend"] = config.egress.backend
        return EgressStatusReport(
            status="ok",
            checks=[EgressStatusCheck("tunnel_process", "ok", "xray-tun tunnel for tun-migate is running")],
            performed_side_effects=False,
        )

    monkeypatch.setattr(main_module, "run_egress_doctor", fake_run_egress_doctor)

    result = runner.invoke(app, ["egress", "doctor", "--backend", "xray-tun"])

    assert result.exit_code == 0
    assert captured == {"backend": "xray-tun"}
    assert "Egress doctor" in result.output
    assert "xray-tun tunnel for tun-migate is running" in result.output


def test_egress_status_command_rejects_unknown_backend_without_host_probe(monkeypatch):
    calls = []

    def fake_run_egress_status(config=None):
        calls.append(config.egress.backend)
        return EgressStatusReport(status="observed", checks=[], performed_side_effects=False)

    monkeypatch.setattr(main_module, "run_egress_status", fake_run_egress_status)

    result = runner.invoke(app, ["egress", "status", "--backend", "wireguard"])

    assert result.exit_code == 1
    assert "status: rejected" in result.output
    assert "unsupported egress backend: wireguard" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert calls == []


def test_egress_doctor_command_rejects_unknown_backend_without_host_probe(monkeypatch):
    calls = []

    def fake_run_egress_doctor(config=None):
        calls.append(config.egress.backend)
        return EgressStatusReport(status="failed", checks=[], performed_side_effects=False)

    monkeypatch.setattr(main_module, "run_egress_doctor", fake_run_egress_doctor)

    result = runner.invoke(app, ["egress", "doctor", "--backend", "wireguard"])

    assert result.exit_code == 1
    assert "status: rejected" in result.output
    assert "unsupported egress backend: wireguard" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert calls == []


def test_panel_command_accepts_safe_default_host_and_port_without_starting_server():
    result = runner.invoke(app, ["panel", "--dry-run"])

    assert result.exit_code == 0
    assert "MiGate panel" in result.output
    assert "127.0.0.1" in result.output
    assert "8787" in result.output
    assert "uvicorn" in result.output


def test_panel_command_accepts_custom_host_and_port_in_dry_run():
    result = runner.invoke(app, ["panel", "--host", "0.0.0.0", "--port", "9000", "--dry-run"])

    assert result.exit_code == 0
    assert "0.0.0.0" in result.output
    assert "9000" in result.output


def test_build_panel_server_config_keeps_app_factory_target():
    config = build_panel_server_config(host="127.0.0.1", port=8787)

    assert config.app == "migate.api.app:create_app"
    assert config.host == "127.0.0.1"
    assert config.port == 8787
    assert config.factory is True


def test_xray_install_command_defaults_to_dry_run_without_real_execution():
    result = runner.invoke(app, ["xray", "install"])

    assert result.exit_code == 0
    assert "Xray 安装 dry-run" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert "curl -fsSL" in result.output
    assert "install -m 0755" in result.output
    assert "真实安装" not in result.output


def test_xray_install_command_accepts_explicit_dry_run_version_architecture():
    result = runner.invoke(app, ["xray", "install", "--dry-run", "--version", "v1.8.24", "--system", "Linux", "--machine", "x86_64"])

    assert result.exit_code == 0
    assert "版本：v1.8.24" in result.output
    assert "架构：linux-64" in result.output
    assert "Xray-linux-64.zip" in result.output


def test_xray_install_command_yes_requires_explicit_side_effects_flag_for_now():
    result = runner.invoke(app, ["xray", "install", "--yes", "--system", "Linux", "--machine", "x86_64"])

    assert result.exit_code == 0
    assert "真实安装 CLI 已就绪，但当前未启用系统修改" in result.output
    assert "--allow-system-changes" in result.output
    assert "allow_side_effects=False" in result.output


def test_xray_install_command_requires_allow_system_changes_even_with_yes():
    result = runner.invoke(app, ["xray", "install", "--yes", "--system", "Linux", "--machine", "x86_64"])

    assert result.exit_code == 0
    assert "真实安装 CLI 已就绪，但当前未启用系统修改" in result.output
    assert "--allow-system-changes" in result.output
    assert "allow_side_effects=False" in result.output


def test_run_xray_install_cli_executes_runner_only_with_double_gate():
    calls = []

    def fake_runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    result = run_xray_install_cli(
        yes=True,
        allow_system_changes=True,
        dry_run=False,
        system="Linux",
        machine="x86_64",
        version="v1.8.24",
        command_runner=fake_runner,
        existing_binary_checker=lambda path: False,
    )

    assert result.status == "success"
    assert result.performed_side_effects is True
    assert calls
    assert calls[0][0] == "curl"
    assert calls[-1] == ["/usr/local/bin/xray", "version"]


def test_run_xray_install_cli_blocks_real_runner_when_doctor_fails():
    calls = []

    def fake_runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    failed_doctor = DoctorReport(
        status="failed",
        checks=[DoctorCheck(name="command:unzip", status="missing", message="unzip not found")],
    )

    result = run_xray_install_cli(
        yes=True,
        allow_system_changes=True,
        dry_run=False,
        system="Linux",
        machine="x86_64",
        command_runner=fake_runner,
        doctor_loader=lambda: failed_doctor,
    )

    assert result.status == "rejected"
    assert result.performed_side_effects is False
    assert calls == []
    assert "doctor failed" in result.message
    assert "command:unzip" in result.message


def test_run_xray_install_cli_runs_real_runner_when_doctor_passes():
    calls = []

    def fake_runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    ok_doctor = DoctorReport(
        status="ok",
        checks=[DoctorCheck(name="command:curl", status="ok", message="curl found")],
    )

    result = run_xray_install_cli(
        yes=True,
        allow_system_changes=True,
        dry_run=False,
        system="Linux",
        machine="x86_64",
        command_runner=fake_runner,
        existing_binary_checker=lambda path: False,
        doctor_loader=lambda: ok_doctor,
    )

    assert result.status == "success"
    assert result.performed_side_effects is True
    assert calls


def test_run_xray_install_cli_refuses_real_runner_without_double_gate():
    calls = []

    def fake_runner(command: list[str]) -> XrayInstallCommandResult:
        calls.append(command)
        return XrayInstallCommandResult(returncode=0, stdout="ok", stderr="")

    result = run_xray_install_cli(
        yes=True,
        allow_system_changes=False,
        dry_run=False,
        system="Linux",
        machine="x86_64",
        command_runner=fake_runner,
    )

    assert result.status == "rejected"
    assert result.performed_side_effects is False
    assert calls == []
    assert "allow_system_changes" in result.message


def test_xray_install_command_with_real_gate_prints_doctor_report_before_result(monkeypatch):
    doctor = DoctorReport(
        status="failed",
        checks=[DoctorCheck(name="command:unzip", status="missing", message="unzip not found")],
    )
    monkeypatch.setattr(main_module, "run_xray_install_doctor", lambda: doctor)

    def fake_install_cli(**kwargs):
        raise AssertionError("install runner should not be called when doctor fails")

    monkeypatch.setattr(main_module, "run_xray_install_cli", fake_install_cli)

    result = runner.invoke(app, ["xray", "install", "--yes", "--allow-system-changes", "--system", "Linux", "--machine", "x86_64"])

    assert result.exit_code == 1
    assert "Xray 安装前检查" in result.output
    assert "command:unzip: missing - unzip not found" in result.output
    assert "status: rejected" in result.output
    assert "message: doctor failed" in result.output
    assert result.output.index("Xray 安装前检查") < result.output.rindex("performed_side_effects:")


def test_xray_install_command_with_real_gate_prints_doctor_report_then_success_result(monkeypatch):
    doctor = DoctorReport(
        status="ok",
        checks=[DoctorCheck(name="command:curl", status="ok", message="curl found")],
    )
    monkeypatch.setattr(main_module, "run_xray_install_doctor", lambda: doctor)

    install_result = XrayInstallResult(
        status="success",
        message="all installer steps completed",
        steps=[],
        performed_side_effects=True,
    )
    monkeypatch.setattr(main_module, "run_xray_install_cli", lambda **kwargs: install_result)

    result = runner.invoke(app, ["xray", "install", "--yes", "--allow-system-changes", "--system", "Linux", "--machine", "x86_64"])

    assert result.exit_code == 0
    assert "Xray 安装前检查" in result.output
    assert "command:curl: ok - curl found" in result.output
    assert "status: success" in result.output
    assert "message: all installer steps completed" in result.output
    assert result.output.index("Xray 安装前检查") < result.output.rindex("status: success")


def test_xray_config_preview_command_prints_json_without_saving():
    result = runner.invoke(app, ["xray", "config", "preview"])

    assert result.exit_code == 0
    assert '"outbounds"' in result.output
    assert '"protocol": "socks"' in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_config_save_command_requires_double_gate():
    result = runner.invoke(app, ["xray", "config", "save"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "config save requires yes=True and allow_system_changes=True" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_config_save_command_shows_backup_and_rollback_fields(monkeypatch, tmp_path):
    target = tmp_path / "config.json"

    from migate.xray.config_cli import XrayConfigSaveResult

    monkeypatch.setattr(
        main_module,
        "save_xray_config",
        lambda *args, **kwargs: XrayConfigSaveResult(
            status="invalid",
            message="config validation failed; restored previous config",
            target=target,
            validation_status="invalid",
            performed_side_effects=True,
            backup_path=target.with_name("config.json.bak"),
            rollback_performed=True,
        ),
    )

    result = runner.invoke(app, ["xray", "config", "save", "--yes", "--allow-system-changes", "--target", str(target)])

    assert result.exit_code == 0
    assert f"target: {target}" in result.output
    assert f"backup_path: {target.with_name('config.json.bak')}" in result.output
    assert "rollback_performed: True" in result.output


def test_xray_tun_config_preview_command_prints_json_without_saving():
    result = runner.invoke(app, ["xray", "tun-config", "preview"])

    assert result.exit_code == 0
    assert '"protocol": "tun"' in result.output
    assert '"name": "tun-migate"' in result.output
    assert '"protocol": "freedom"' not in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_tun_config_save_command_requires_double_gate():
    result = runner.invoke(app, ["xray", "tun-config", "save"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "xray tun config save requires yes=True and allow_system_changes=True" in result.output
    assert "systemctl_commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_tun_config_save_command_shows_validation_and_no_systemctl(monkeypatch, tmp_path):
    from migate.xray.tun_config import XrayTunConfigSaveResult

    target = tmp_path / "tun.json"
    monkeypatch.setattr(
        main_module,
        "save_xray_tun_config",
        lambda *args, **kwargs: XrayTunConfigSaveResult(
            status="saved",
            message="xray tun config saved and validated",
            target=target,
            validation_status="valid",
            performed_side_effects=True,
            backup_path=None,
            rollback_performed=False,
            systemctl_commands_executed=[],
        ),
    )

    result = runner.invoke(app, ["xray", "tun-config", "save", "--yes", "--allow-system-changes", "--target", str(target)])

    assert result.exit_code == 0
    assert "status: saved" in result.output
    assert f"target: {target}" in result.output
    assert "validation_status: valid" in result.output
    assert "rollback_performed: False" in result.output
    assert "systemctl_commands_executed: []" in result.output
    assert "performed_side_effects: True" in result.output


def test_xray_tun_service_preview_command_prints_unit_without_systemctl():
    result = runner.invoke(app, ["xray", "tun-service", "preview"])

    assert result.exit_code == 0
    assert "Description=MiGate managed Xray TUN service" in result.output
    assert "ExecStart=/usr/local/bin/xray run -config /etc/migate/xray/config.json" in result.output
    assert "daemon-reload" not in result.output
    assert "restart" not in result.output
    assert "systemctl_commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_tun_service_save_command_requires_double_gate():
    result = runner.invoke(app, ["xray", "tun-service", "save"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "xray tun service save requires yes=True and allow_system_changes=True" in result.output
    assert "systemctl_commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_tun_service_save_command_shows_saved_without_systemctl(monkeypatch, tmp_path):
    from migate.xray.service_cli import XrayServiceSaveResult

    target = tmp_path / "migate-xray-tun.service"
    monkeypatch.setattr(
        main_module,
        "save_xray_tun_service_unit",
        lambda *args, **kwargs: XrayServiceSaveResult(
            status="saved",
            message="xray tun service unit saved; daemon-reload not run",
            target=target,
            performed_side_effects=True,
            systemctl_commands_executed=[],
        ),
    )

    result = runner.invoke(app, ["xray", "tun-service", "save", "--yes", "--allow-system-changes", "--target", str(target)])

    assert result.exit_code == 0
    assert "status: saved" in result.output
    assert "xray tun service unit saved; daemon-reload not run" in result.output
    assert f"target: {target}" in result.output
    assert "systemctl_commands_executed: []" in result.output
    assert "performed_side_effects: True" in result.output


def test_xray_service_preview_command_prints_unit_without_systemctl():
    result = runner.invoke(app, ["xray", "service", "preview"])

    assert result.exit_code == 0
    assert "Description=MiGate managed Xray service" in result.output
    assert "ExecStart=/usr/local/bin/xray run -config /etc/migate/xray/config.json" in result.output
    assert "ExecStart=systemctl" not in result.output
    assert "daemon-reload" not in result.output
    assert "systemctl restart" not in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_service_save_command_requires_double_gate():
    result = runner.invoke(app, ["xray", "service", "save"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "service save requires yes=True and allow_system_changes=True" in result.output
    assert "systemctl_commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_systemctl_status_command_prints_structured_status(monkeypatch):
    from migate.xray.systemctl_cli import SystemctlActionResult

    monkeypatch.setattr(
        main_module,
        "run_xray_systemctl_action",
        lambda *args, **kwargs: SystemctlActionResult(
            status="success",
            action="status",
            service="migate-xray.service",
            command=["systemctl", "status", "migate-xray.service", "--no-pager"],
            returncode=0,
            stdout="active",
            stderr="",
            performed_side_effects=False,
        ),
    )

    result = runner.invoke(app, ["xray", "systemctl", "status"])

    assert result.exit_code == 0
    assert "status: success" in result.output
    assert "action: status" in result.output
    assert "service: migate-xray.service" in result.output
    assert "stdout: active" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_systemctl_restart_command_requires_double_gate(monkeypatch):
    calls = []

    def fake_action(*args, **kwargs):
        calls.append((args, kwargs))
        from migate.xray.systemctl_cli import SystemctlActionResult

        return SystemctlActionResult(
            status="rejected",
            action="restart",
            service="migate-xray.service",
            command=[],
            returncode=None,
            stdout="",
            stderr="systemctl restart requires yes=True and allow_system_changes=True",
            performed_side_effects=False,
        )

    monkeypatch.setattr(main_module, "run_xray_systemctl_action", fake_action)

    result = runner.invoke(app, ["xray", "systemctl", "restart"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "systemctl restart requires" in result.output
    assert "performed_side_effects: False" in result.output
    assert calls[0][1]["yes"] is False
    assert calls[0][1]["allow_system_changes"] is False


def test_xray_systemctl_status_command_accepts_xray_tun_service(monkeypatch):
    calls = []

    def fake_action(*args, **kwargs):
        calls.append((args, kwargs))
        from migate.xray.systemctl_cli import SystemctlActionResult

        return SystemctlActionResult(
            status="success",
            action="status",
            service="migate-xray-tun.service",
            command=["systemctl", "status", "migate-xray-tun.service", "--no-pager"],
            returncode=0,
            stdout="tun active",
            stderr="",
            performed_side_effects=False,
        )

    monkeypatch.setattr(main_module, "run_xray_systemctl_action", fake_action)

    result = runner.invoke(app, ["xray", "systemctl", "status", "--service", "migate-xray-tun.service"])

    assert result.exit_code == 0
    assert "service: migate-xray-tun.service" in result.output
    assert "stdout: tun active" in result.output
    assert calls == [(("status",), {"service": "migate-xray-tun.service"})]


def test_xray_systemctl_start_stop_commands_pass_xray_tun_service_and_gates(monkeypatch):
    calls = []

    def fake_action(*args, **kwargs):
        calls.append((args, kwargs))
        from migate.xray.systemctl_cli import SystemctlActionResult

        return SystemctlActionResult(
            status="success",
            action=args[0],
            service=kwargs["service"],
            command=["systemctl", args[0], kwargs["service"]],
            returncode=0,
            stdout="ok",
            stderr="",
            performed_side_effects=True,
        )

    monkeypatch.setattr(main_module, "run_xray_systemctl_action", fake_action)

    start_result = runner.invoke(
        app,
        [
            "xray",
            "systemctl",
            "start",
            "--service",
            "migate-xray-tun.service",
            "--yes",
            "--allow-system-changes",
        ],
    )
    stop_result = runner.invoke(
        app,
        [
            "xray",
            "systemctl",
            "stop",
            "--service",
            "migate-xray-tun.service",
            "--yes",
            "--allow-system-changes",
        ],
    )

    assert start_result.exit_code == 0
    assert "action: start" in start_result.output
    assert "service: migate-xray-tun.service" in start_result.output
    assert "performed_side_effects: True" in start_result.output
    assert stop_result.exit_code == 0
    assert "action: stop" in stop_result.output
    assert "service: migate-xray-tun.service" in stop_result.output
    assert calls == [
        (("start",), {"service": "migate-xray-tun.service", "yes": True, "allow_system_changes": True}),
        (("stop",), {"service": "migate-xray-tun.service", "yes": True, "allow_system_changes": True}),
    ]


def test_xray_apply_restart_command_requires_double_gate(monkeypatch):
    from migate.xray.apply_cli import XrayApplyResult
    from migate.xray.validator import XrayValidationResult

    calls = []

    def fake_apply(*args, **kwargs):
        calls.append((args, kwargs))
        return XrayApplyResult(
            status="rejected",
            message="apply restart requires yes=True and allow_system_changes=True",
            config_path="/etc/migate/xray/config.json",
            validation=XrayValidationResult("skipped", None, "", ""),
            systemctl_results=[],
            performed_side_effects=False,
        )

    monkeypatch.setattr(main_module, "apply_validated_xray_restart", fake_apply)

    result = runner.invoke(app, ["xray", "apply", "restart"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "validation_status: skipped" in result.output
    assert "systemctl_results: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert calls[0][1]["yes"] is False
    assert calls[0][1]["allow_system_changes"] is False


def test_xray_apply_restart_command_prints_ordered_systemctl_results(monkeypatch):
    from migate.xray.apply_cli import XrayApplyResult
    from migate.xray.systemctl_cli import ALLOWED_XRAY_SERVICE_NAME, SystemctlActionResult
    from migate.xray.validator import XrayValidationResult

    monkeypatch.setattr(
        main_module,
        "apply_validated_xray_restart",
        lambda *args, **kwargs: XrayApplyResult(
            status="success",
            message="config validated and service restarted",
            config_path="/tmp/config.json",
            validation=XrayValidationResult("valid", 0, "config ok", ""),
            systemctl_results=[
                SystemctlActionResult("success", "daemon-reload", ALLOWED_XRAY_SERVICE_NAME, ["systemctl", "daemon-reload"], 0, "reload ok", "", True),
                SystemctlActionResult("success", "restart", ALLOWED_XRAY_SERVICE_NAME, ["systemctl", "restart", ALLOWED_XRAY_SERVICE_NAME], 0, "restart ok", "", True),
            ],
            performed_side_effects=True,
        ),
    )

    result = runner.invoke(
        app,
        ["xray", "apply", "restart", "--config", "/tmp/config.json", "--yes", "--allow-system-changes"],
    )

    assert result.exit_code == 0
    assert "status: success" in result.output
    assert "validation_status: valid" in result.output
    assert "- action: daemon-reload status: success returncode: 0" in result.output
    assert "- action: restart status: success returncode: 0" in result.output
    assert "performed_side_effects: True" in result.output


def test_xray_apply_tun_start_command_requires_double_gate(monkeypatch):
    from migate.xray.apply_cli import XrayApplyResult
    from migate.xray.validator import XrayValidationResult

    calls = []

    def fake_apply(*args, **kwargs):
        calls.append((args, kwargs))
        return XrayApplyResult(
            status="rejected",
            message="xray tun start requires yes=True and allow_system_changes=True",
            config_path="/etc/migate/xray/config.json",
            validation=XrayValidationResult("skipped", None, "", ""),
            systemctl_results=[],
            performed_side_effects=False,
        )

    monkeypatch.setattr(main_module, "apply_validated_xray_tun_start", fake_apply)

    result = runner.invoke(app, ["xray", "apply", "tun-start"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "validation_status: skipped" in result.output
    assert "systemctl_results: []" in result.output
    assert "performed_side_effects: False" in result.output
    assert calls[0][1]["yes"] is False
    assert calls[0][1]["allow_system_changes"] is False


def test_xray_apply_tun_start_command_prints_ordered_systemctl_results(monkeypatch):
    from migate.xray.apply_cli import XrayApplyResult
    from migate.xray.systemctl_cli import ALLOWED_XRAY_TUN_SERVICE_NAME, SystemctlActionResult
    from migate.xray.validator import XrayValidationResult

    monkeypatch.setattr(
        main_module,
        "apply_validated_xray_tun_start",
        lambda *args, **kwargs: XrayApplyResult(
            status="success",
            message="xray tun config validated and service started",
            config_path="/tmp/config.json",
            validation=XrayValidationResult("valid", 0, "config ok", ""),
            systemctl_results=[
                SystemctlActionResult("success", "daemon-reload", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "daemon-reload"], 0, "reload ok", "", True),
                SystemctlActionResult("success", "start", ALLOWED_XRAY_TUN_SERVICE_NAME, ["systemctl", "start", ALLOWED_XRAY_TUN_SERVICE_NAME], 0, "start ok", "", True),
            ],
            performed_side_effects=True,
        ),
    )

    result = runner.invoke(
        app,
        ["xray", "apply", "tun-start", "--config", "/tmp/config.json", "--yes", "--allow-system-changes"],
    )

    assert result.exit_code == 0
    assert "status: success" in result.output
    assert "validation_status: valid" in result.output
    assert "- action: daemon-reload status: success returncode: 0" in result.output
    assert "- action: start status: success returncode: 0" in result.output
    assert "performed_side_effects: True" in result.output


def test_xray_deploy_command_defaults_to_dry_run_without_side_effects():
    result = runner.invoke(app, ["xray", "deploy", "--system", "Linux", "--machine", "x86_64", "--version", "v1.8.24"])

    assert result.exit_code == 0
    assert "Xray deploy dry-run" in result.output
    assert "status: dry_run" in result.output
    assert "- doctor: planned read-only" in result.output
    assert "- install: planned side-effect" in result.output
    assert "- config_save: planned side-effect" in result.output
    assert "- service_save: planned side-effect" in result.output
    assert "- apply_restart: planned side-effect" in result.output
    assert "- status: planned read-only" in result.output
    assert "commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_deploy_command_runs_real_orchestrator_when_double_gated(monkeypatch):
    from migate.xray.deploy_cli import XrayDeployResult, XrayDeployStepResult

    calls = []

    def fake_deploy(*args, **kwargs):
        calls.append((args, kwargs))
        return XrayDeployResult(
            status="success",
            message="xray deploy completed",
            steps=[XrayDeployStepResult("doctor", "success", "doctor ok", object())],
            performed_side_effects=True,
        )

    monkeypatch.setattr(main_module, "run_xray_deploy", fake_deploy)

    result = runner.invoke(
        app,
        [
            "xray",
            "deploy",
            "--no-dry-run",
            "--yes",
            "--allow-system-changes",
            "--system",
            "Linux",
            "--machine",
            "x86_64",
        ],
    )

    assert result.exit_code == 0
    assert "Xray deploy result" in result.output
    assert "status: success" in result.output
    assert "- doctor: success - doctor ok" in result.output
    assert "performed_side_effects: True" in result.output
    assert calls[0][1]["dry_run"] is False
    assert calls[0][1]["yes"] is True
    assert calls[0][1]["allow_system_changes"] is True


def test_xray_deploy_command_exits_nonzero_when_real_orchestrator_rejects(monkeypatch):
    from migate.xray.deploy_cli import XrayDeployResult

    def fake_deploy(*_args, **_kwargs):
        return XrayDeployResult(
            status="rejected",
            message="real deploy requires yes=True and allow_system_changes=True",
            steps=[],
            performed_side_effects=False,
        )

    monkeypatch.setattr(main_module, "run_xray_deploy", fake_deploy)

    result = runner.invoke(app, ["xray", "deploy", "--no-dry-run", "--yes"])

    assert result.exit_code == 1
    assert "Xray deploy result" in result.output
    assert "status: rejected" in result.output
    assert "real deploy requires yes=True and allow_system_changes=True" in result.output
    assert "performed_side_effects: False" in result.output


def test_proxy_doctor_command_reports_runtime_preflight(monkeypatch):
    from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport

    monkeypatch.setattr(
        main_module,
        "run_proxy_doctor",
        lambda *args, **kwargs: ProxyRuntimeReport(
            status="failed",
            checks=[ProxyRuntimeCheck("tun_interface", "failed", "tun-migate interface is missing")],
            performed_side_effects=False,
        ),
    )

    result = runner.invoke(app, ["proxy", "doctor"])

    assert result.exit_code == 0
    assert "Proxy doctor" in result.output
    assert "status: failed" in result.output
    assert "tun_interface: failed - tun-migate interface is missing" in result.output
    assert "performed_side_effects: False" in result.output


def test_proxy_status_command_reports_observational_status(monkeypatch):
    from migate.proxy.runtime import ProxyRuntimeCheck, ProxyRuntimeReport

    monkeypatch.setattr(
        main_module,
        "run_proxy_status",
        lambda *args, **kwargs: ProxyRuntimeReport(
            status="observed",
            checks=[ProxyRuntimeCheck("socks_listen", "ok", "127.0.0.1:34501 is listening")],
            performed_side_effects=False,
        ),
    )

    result = runner.invoke(app, ["proxy", "status"])

    assert result.exit_code == 0
    assert "Proxy status" in result.output
    assert "status: observed" in result.output
    assert "socks_listen: ok - 127.0.0.1:34501 is listening" in result.output
    assert "performed_side_effects: False" in result.output

def test_proxy_run_command_rejects_when_preflight_fails(monkeypatch):
    from migate.proxy.run import ProxyRunResult
    from migate.proxy.runtime import ProxyRuntimeCheck

    monkeypatch.setattr(
        main_module,
        "run_proxy_placeholder",
        lambda *args, **kwargs: ProxyRunResult(
            status="rejected",
            message="proxy run preflight failed; listener not started",
            checks=[ProxyRuntimeCheck("tun_interface", "failed", "tun-migate interface is missing")],
            listener_started=False,
            forwarding_started=False,
            performed_side_effects=False,
        ),
    )

    result = runner.invoke(app, ["proxy", "run"])

    assert result.exit_code == 1
    assert "Proxy run" in result.output
    assert "status: rejected" in result.output
    assert "tun_interface: failed - tun-migate interface is missing" in result.output
    assert "listener_started: False" in result.output
    assert "forwarding_started: False" in result.output


def test_proxy_run_command_reports_listener_started_when_preflight_passes(monkeypatch):
    from migate.proxy.run import ProxyRunResult
    from migate.proxy.runtime import ProxyRuntimeCheck

    monkeypatch.setattr(
        main_module,
        "run_proxy_placeholder",
        lambda *args, **kwargs: ProxyRunResult(
            status="running",
            message="SOCKS5 listener started; direct upstream relay enabled",
            checks=[ProxyRuntimeCheck("fail_policy", "ok", "fail_policy is block")],
            listener_started=True,
            forwarding_started=True,
            performed_side_effects=True,
        ),
    )

    result = runner.invoke(app, ["proxy", "run"])

    assert result.exit_code == 0
    assert "status: running" in result.output
    assert "SOCKS5 listener started; direct upstream relay enabled" in result.output
    assert "listener_started: True" in result.output
    assert "forwarding_started: True" in result.output
    assert "performed_side_effects: True" in result.output


def test_proxy_socks5_plan_command_prints_dry_run_listener_plan():
    result = runner.invoke(app, ["proxy", "socks5", "plan"])

    assert result.exit_code == 0
    assert "SOCKS5 listener plan" in result.output
    assert "bind_host: 127.0.0.1" in result.output
    assert "bind_port: 34501" in result.output
    assert "connection_driver: Socks5Connection" in result.output
    assert "will_listen: True" in result.output
    assert "upstream_mode: direct_tcp_relay" in result.output
    assert "will_connect_upstream: True" in result.output
    assert "performed_side_effects: False" in result.output


def test_proxy_socks5_serve_command_defaults_to_dry_run_without_listening():
    result = runner.invoke(app, ["proxy", "socks5", "serve"])

    assert result.exit_code == 0
    assert "SOCKS5 serve result" in result.output
    assert "status: dry_run" in result.output
    assert "listener_started: False" in result.output
    assert "upstream_connections: 0" in result.output
    assert "performed_side_effects: False" in result.output


def test_proxy_socks5_serve_command_outputs_json_dry_run_result():
    result = runner.invoke(app, ["proxy", "socks5", "serve", "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "dry_run"
    assert payload["listener_started"] is False
    assert payload["accepted_connections"] == 0
    assert payload["upstream_connections"] == 0
    assert payload["timed_out_connections"] == 0
    assert payload["max_clients"] == 1
    assert payload["client_timeout"] == 5.0
    assert payload["event_summary"] == {
        "total_events": 0,
        "accepted_events": 0,
        "rejected_events": 0,
        "timed_out_events": 0,
        "upstream_connected_events": 0,
        "performed_side_effects": False,
    }
    assert payload["events"] == []
    assert payload["performed_side_effects"] is False


def test_proxy_socks5_serve_command_rejects_unknown_format():
    result = runner.invoke(app, ["proxy", "socks5", "serve", "--format", "yaml"])

    assert result.exit_code == 1
    assert "unsupported format: yaml" in result.output
    assert "supported formats: text, json, jsonl" in result.output


def test_proxy_socks5_serve_command_outputs_jsonl_dry_run_summary_only():
    result = runner.invoke(app, ["proxy", "socks5", "serve", "--format", "jsonl"])

    assert result.exit_code == 0
    lines = [json.loads(line) for line in result.output.splitlines()]
    assert lines == [
        {
            "type": "summary",
            "status": "dry_run",
            "message": "SOCKS5 listener dry-run; no socket opened",
            "bind_host": "127.0.0.1",
            "bind_port": 34501,
            "listener_started": False,
            "accepted_connections": 0,
            "upstream_connections": 0,
            "timed_out_connections": 0,
            "max_clients": 1,
            "client_timeout": 5.0,
            "total_events": 0,
            "accepted_events": 0,
            "rejected_events": 0,
            "timed_out_events": 0,
            "upstream_connected_events": 0,
            "performed_side_effects": False,
        }
    ]


def test_proxy_socks5_serve_command_rejects_real_listen_without_gate():
    result = runner.invoke(app, ["proxy", "socks5", "serve", "--no-dry-run", "--yes"])

    assert result.exit_code == 1
    assert "status: rejected" in result.output
    assert "requires yes=True and allow_network_listen=True" in result.output
    assert "listener_started: False" in result.output
    assert "performed_side_effects: False" in result.output


def test_proxy_socks5_serve_command_outputs_json_rejected_gate_result():
    result = runner.invoke(app, ["proxy", "socks5", "serve", "--no-dry-run", "--yes", "--format", "json"])

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["status"] == "rejected"
    assert payload["listener_started"] is False
    assert payload["accepted_connections"] == 0
    assert payload["upstream_connections"] == 0
    assert payload["event_summary"]["total_events"] == 0
    assert payload["events"] == []
    assert payload["performed_side_effects"] is False


def test_proxy_socks5_serve_command_delegates_output_rendering_to_formatter(monkeypatch):
    calls = []

    def fake_render_output(result, output_format: str):
        calls.append((result.status, output_format))
        return f"formatted::{result.status}::{output_format}\n"

    monkeypatch.setattr(main_module, "render_socks5_serve_output", fake_render_output)

    result = runner.invoke(app, ["proxy", "socks5", "serve", "--format", "json"])

    assert result.exit_code == 0
    assert result.output == "formatted::dry_run::json\n"
    assert calls == [("dry_run", "json")]


def test_proxy_socks5_serve_command_json_includes_injected_real_result_events(monkeypatch):
    def fake_run_socks5_serve_placeholder(*_args, **_kwargs):
        return Socks5ServeResult(
            status="stopped",
            message="handled one client",
            bind_host="127.0.0.1",
            bind_port=34501,
            listener_started=True,
            accepted_connections=1,
            upstream_connections=0,
            timed_out_connections=0,
            max_clients=1,
            client_timeout=5.0,
            events=[Socks5ServeEvent(1, "connect", "accepted", "example.com", 443, False)],
            performed_side_effects=True,
        )

    monkeypatch.setattr(main_module, "run_socks5_serve_placeholder", fake_run_socks5_serve_placeholder)

    result = runner.invoke(app, ["proxy", "socks5", "serve", "--no-dry-run", "--yes", "--allow-network-listen", "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "stopped"
    assert payload["listener_started"] is True
    assert payload["accepted_connections"] == 1
    assert payload["upstream_connections"] == 0
    assert payload["event_summary"]["accepted_events"] == 1
    assert payload["event_summary"]["upstream_connected_events"] == 0
    assert payload["events"] == [
        {
            "client_id": 1,
            "phase": "connect",
            "status": "accepted",
            "target_host": "example.com",
            "target_port": 443,
            "upstream_connected": False,
        }
    ]
    assert payload["performed_side_effects"] is True


def test_proxy_socks5_serve_command_jsonl_includes_injected_real_result_events(monkeypatch):
    def fake_run_socks5_serve_placeholder(*_args, **_kwargs):
        return Socks5ServeResult(
            status="stopped",
            message="handled one client",
            bind_host="127.0.0.1",
            bind_port=34501,
            listener_started=True,
            accepted_connections=1,
            upstream_connections=0,
            timed_out_connections=0,
            max_clients=1,
            client_timeout=5.0,
            events=[Socks5ServeEvent(1, "connect", "accepted", "example.com", 443, False)],
            performed_side_effects=True,
        )

    monkeypatch.setattr(main_module, "run_socks5_serve_placeholder", fake_run_socks5_serve_placeholder)

    result = runner.invoke(app, ["proxy", "socks5", "serve", "--no-dry-run", "--yes", "--allow-network-listen", "--format", "jsonl"])

    assert result.exit_code == 0
    lines = [json.loads(line) for line in result.output.splitlines()]
    assert lines[0]["type"] == "summary"
    assert lines[0]["status"] == "stopped"
    assert lines[0]["accepted_events"] == 1
    assert lines[0]["upstream_connected_events"] == 0
    assert lines[1] == {
        "type": "event",
        "client_id": 1,
        "phase": "connect",
        "status": "accepted",
        "target_host": "example.com",
        "target_port": 443,
        "upstream_connected": False,
    }


def test_proxy_socks5_serve_command_rejects_output_file_without_file_write_gate(tmp_path):
    target = tmp_path / "serve.jsonl"

    result = runner.invoke(app, ["proxy", "socks5", "serve", "--format", "jsonl", "--output", str(target), "--yes"])

    assert result.exit_code == 0
    assert "SOCKS5 serve output write result" in result.output
    assert "status: rejected" in result.output
    assert "requires yes=True and allow_file_write=True" in result.output
    assert "bytes_written: 0" in result.output
    assert "performed_side_effects: False" in result.output
    assert not target.exists()


def test_proxy_socks5_serve_command_rejects_sensitive_output_path_even_when_double_gated():
    result = runner.invoke(
        app,
        [
            "proxy",
            "socks5",
            "serve",
            "--format",
            "jsonl",
            "--output",
            "/etc/migate/serve.jsonl",
            "--yes",
            "--allow-file-write",
        ],
    )

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "SOCKS5 serve output target path is not allowed" in result.output
    assert "path_policy_reason: sensitive_absolute_path_denied" in result.output
    assert "file_performed_side_effects: False" in result.output


def test_proxy_socks5_serve_command_rejects_reserved_system_output_path_gate():
    result = runner.invoke(
        app,
        [
            "proxy",
            "socks5",
            "serve",
            "--format",
            "jsonl",
            "--output",
            "/var/log/migate/serve.jsonl",
            "--yes",
            "--allow-file-write",
            "--allow-system-output-path",
        ],
    )

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "system output paths are intentionally unsupported until log rotation and ownership policy exist" in result.output
    assert "path_policy_reason: system_path_reserved" in result.output
    assert "file_performed_side_effects: False" in result.output


def test_proxy_socks5_serve_command_writes_output_file_when_double_gated(tmp_path):
    target = tmp_path / "serve.jsonl"

    result = runner.invoke(
        app,
        [
            "proxy",
            "socks5",
            "serve",
            "--format",
            "jsonl",
            "--output",
            str(target),
            "--yes",
            "--allow-file-write",
        ],
    )

    assert result.exit_code == 0
    assert "SOCKS5 serve output write result" in result.output
    assert "status: written" in result.output
    assert f"target: {target}" in result.output
    assert "path_policy_reason: tmp_allowed" in result.output
    assert "serve_performed_side_effects: False" in result.output
    assert "file_performed_side_effects: True" in result.output
    assert "performed_side_effects: True" in result.output
    lines = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["type"] == "summary"
    assert lines[0]["status"] == "dry_run"
    assert lines[0]["upstream_connections"] == 0


def test_proxy_socks5_serve_command_writes_output_file_with_json_write_result(tmp_path):
    target = tmp_path / "serve.jsonl"

    result = runner.invoke(
        app,
        [
            "proxy",
            "socks5",
            "serve",
            "--format",
            "jsonl",
            "--output",
            str(target),
            "--yes",
            "--allow-file-write",
            "--write-result-format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["status"] == "written"
    assert payload["target"] == str(target)
    assert payload["path_policy_reason"] == "tmp_allowed"
    assert payload["file_performed_side_effects"] is True
    assert target.exists()
    file_lines = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    assert file_lines[0]["type"] == "summary"
    assert file_lines[0]["upstream_connections"] == 0


def test_proxy_socks5_serve_command_rejects_unknown_write_result_format(tmp_path):
    target = tmp_path / "serve.jsonl"

    result = runner.invoke(
        app,
        [
            "proxy",
            "socks5",
            "serve",
            "--format",
            "jsonl",
            "--output",
            str(target),
            "--yes",
            "--allow-file-write",
            "--write-result-format",
            "yaml",
        ],
    )

    assert result.exit_code == 1
    assert "unsupported write result format: yaml" in result.output
    assert "supported write result formats: text, json" in result.output
    assert not target.exists()


def test_proxy_socks5_serve_command_writes_injected_real_result_events_to_output_file(tmp_path, monkeypatch):
    target = tmp_path / "serve.jsonl"

    def fake_run_socks5_serve_placeholder(*_args, **_kwargs):
        return Socks5ServeResult(
            status="stopped",
            message="handled one client",
            bind_host="127.0.0.1",
            bind_port=34501,
            listener_started=True,
            accepted_connections=1,
            upstream_connections=0,
            timed_out_connections=0,
            max_clients=1,
            client_timeout=5.0,
            events=[Socks5ServeEvent(1, "connect", "accepted", "example.com", 443, False)],
            performed_side_effects=True,
        )

    monkeypatch.setattr(main_module, "run_socks5_serve_placeholder", fake_run_socks5_serve_placeholder)

    result = runner.invoke(
        app,
        [
            "proxy",
            "socks5",
            "serve",
            "--no-dry-run",
            "--yes",
            "--allow-network-listen",
            "--allow-file-write",
            "--format",
            "jsonl",
            "--output",
            str(target),
        ],
    )

    assert result.exit_code == 0
    assert "serve_performed_side_effects: True" in result.output
    assert "file_performed_side_effects: True" in result.output
    lines = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["status"] == "stopped"
    assert lines[0]["upstream_connections"] == 0
    assert lines[1]["status"] == "accepted"
    assert lines[1]["target_host"] == "example.com"


def test_proxy_socks5_serve_command_accepts_max_clients_option_in_dry_run():
    result = runner.invoke(app, ["proxy", "socks5", "serve", "--max-clients", "2"])

    assert result.exit_code == 0
    assert "status: dry_run" in result.output
    assert "max_clients: 2" in result.output
    assert "listener_started: False" in result.output
    assert "upstream_connections: 0" in result.output


def test_proxy_socks5_serve_command_accepts_client_timeout_option_in_dry_run():
    result = runner.invoke(app, ["proxy", "socks5", "serve", "--client-timeout", "0.5"])

    assert result.exit_code == 0
    assert "status: dry_run" in result.output
    assert "client_timeout: 0.5" in result.output
    assert "timed_out_connections: 0" in result.output
    assert "listener_started: False" in result.output
    assert "upstream_connections: 0" in result.output


def test_proxy_service_preview_command_prints_unit_without_systemctl():
    result = runner.invoke(app, ["proxy", "service", "preview"])

    assert result.exit_code == 0
    assert "Description=MiGate local proxy service" in result.output
    assert "ExecStart=/usr/local/bin/migate proxy run" in result.output
    assert "ExecStart=systemctl" not in result.output
    assert "daemon-reload" not in result.output
    assert "systemctl restart" not in result.output
    assert "systemctl_commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output


def test_proxy_service_save_command_requires_double_gate():
    result = runner.invoke(app, ["proxy", "service", "save"])

    assert result.exit_code == 0
    assert "status: rejected" in result.output
    assert "proxy service save requires yes=True and allow_system_changes=True" in result.output
    assert "systemctl_commands_executed: []" in result.output
    assert "performed_side_effects: False" in result.output


def test_xray_doctor_command_reports_dependency_checks():
    result = runner.invoke(app, ["xray", "doctor"])

    assert result.exit_code == 0
    assert "Xray 安装前检查" in result.output
    assert "command:curl" in result.output
    assert "command:unzip" in result.output
    assert "writable:/usr/local/bin" in result.output
    assert "performed_side_effects: False" in result.output


def test_build_xray_install_cli_plan_uses_safe_defaults():
    plan = build_xray_install_cli_plan(system="Linux", machine="x86_64", version="latest")

    assert plan.system == "linux"
    assert plan.arch == "64"
    assert plan.version == "latest"
    assert plan.bin_path == "/usr/local/bin/xray"
    assert plan.performs_side_effects is False
