from migate.remote.readiness import (
    REMOTE_READINESS_SCRIPT,
    RemoteReadinessCheck,
    RemoteReadinessReport,
    build_remote_readiness_command,
    render_remote_readiness_report,
    run_remote_readiness,
)


def test_build_remote_readiness_command_is_read_only_and_batched():
    command = build_remote_readiness_command(host="166.88.232.2", port=22, user="root", timeout_seconds=7)

    assert command == [
        "ssh",
        "-p",
        "22",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=7",
        "-o",
        "StrictHostKeyChecking=yes",
        "root@166.88.232.2",
        REMOTE_READINESS_SCRIPT,
    ]
    assert "accept-new" not in command
    preview = " ".join(command).lower()
    assert "sshpass" not in preview
    assert "password" not in preview
    assert "systemctl restart" not in preview
    assert "openvpn --config" not in preview
    assert "ip route add" not in preview


def test_run_remote_readiness_success_maps_probe_output_to_checks():
    calls: list[list[str]] = []

    stdout = "\n".join(
        [
            "MIGATE_CLI:ok:/usr/local/bin/migate",
            "MIGATE_VERSION:ok:MiGate smart egress gateway",
            "XRAY_BIN:ok:/usr/local/bin/xray",
            "OPENVPN_BIN:ok:/usr/sbin/openvpn",
            "SYSTEMCTL_BIN:ok:/usr/bin/systemctl",
            "IP_BIN:ok:/usr/sbin/ip",
            "XRAY_SERVICE_PREVIEW:ok:performed_side_effects: False",
            "PROXY_SERVICE_PREVIEW:ok:performed_side_effects: False",
            "EGRESS_STATUS:ok:performed_side_effects: False",
        ]
    ) + "\n"

    def fake_runner(command: list[str]):
        calls.append(command)
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    report = run_remote_readiness(host="166.88.232.2", port=22, user="root", runner=fake_runner)

    assert report.status == "ok"
    assert report.target == "root@166.88.232.2:22"
    assert report.commands_executed == [" ".join(build_remote_readiness_command(host="166.88.232.2", port=22, user="root"))]
    assert report.performed_side_effects is False
    assert RemoteReadinessCheck("migate_cli", "ok", "/usr/local/bin/migate") in report.checks
    assert RemoteReadinessCheck("egress_status", "ok", "performed_side_effects: False") in report.checks
    assert calls


def test_run_remote_readiness_failure_marks_failed_checks_without_side_effects():
    stdout = "\n".join(
        [
            "MIGATE_CLI:ok:/usr/local/bin/migate",
            "MIGATE_VERSION:ok:MiGate smart egress gateway",
            "XRAY_BIN:failed:missing xray",
            "OPENVPN_BIN:ok:/usr/sbin/openvpn",
            "SYSTEMCTL_BIN:ok:/usr/bin/systemctl",
            "IP_BIN:ok:/usr/sbin/ip",
            "XRAY_SERVICE_PREVIEW:failed:preview failed",
            "PROXY_SERVICE_PREVIEW:ok:performed_side_effects: False",
            "EGRESS_STATUS:ok:performed_side_effects: False",
        ]
    ) + "\n"

    def fake_runner(command: list[str]):
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    report = run_remote_readiness(host="166.88.232.2", port=22, user="root", runner=fake_runner)

    assert report.status == "failed"
    assert RemoteReadinessCheck("xray_bin", "failed", "missing xray") in report.checks
    assert RemoteReadinessCheck("xray_service_preview", "failed", "preview failed") in report.checks
    assert report.performed_side_effects is False


def test_run_remote_readiness_rejects_embedded_credentials_before_runner_call():
    calls: list[list[str]] = []

    report = run_remote_readiness(host="root:secret@166.88.232.2", port=22, user="root", runner=lambda command: calls.append(command))

    assert report == RemoteReadinessReport(
        status="failed",
        target="[REDACTED]",
        checks=[RemoteReadinessCheck("target", "failed", "embedded credentials are not allowed")],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []
    assert "secret" not in render_remote_readiness_report(report)


def test_render_remote_readiness_report_is_structured_and_safe():
    report = RemoteReadinessReport(
        status="failed",
        target="root@166.88.232.2:22",
        checks=[RemoteReadinessCheck("xray_bin", "failed", "missing xray")],
        commands_executed=["ssh -p 22 root@166.88.232.2 readonly"],
        performed_side_effects=False,
    )

    rendered = render_remote_readiness_report(report)

    assert "Remote readiness" in rendered
    assert "status: failed" in rendered
    assert "target: root@166.88.232.2:22" in rendered
    assert "commands_executed: ['ssh -p 22 root@166.88.232.2 readonly']" in rendered
    assert "performed_side_effects: False" in rendered
    assert "- xray_bin: failed - missing xray" in rendered
    assert "password" not in rendered.lower()
    assert "sshpass" not in rendered.lower()
