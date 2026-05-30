from migate.remote.leak_check import (
    REMOTE_LEAK_CHECK_SCRIPT,
    RemoteLeakCheck,
    RemoteLeakCheckReport,
    build_remote_leak_check_command,
    render_remote_leak_check_report,
    run_remote_leak_check,
)


def test_build_remote_leak_check_command_is_read_only_batched_and_uses_local_socks_proxy():
    command = build_remote_leak_check_command(host="166.88.232.2", port=22, user="root", socks_port=34501, timeout_seconds=7)

    assert command == [
        "ssh",
        "-p",
        "22",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=7",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "root@166.88.232.2",
        REMOTE_LEAK_CHECK_SCRIPT.format(socks_port=34501),
    ]
    preview = " ".join(command).lower()
    assert "socks5-hostname 127.0.0.1:34501" in preview
    assert "sshpass" not in preview
    assert "password" not in preview
    assert "systemctl" not in preview
    assert "openvpn --config" not in preview
    assert "ip route add" not in preview


def test_run_remote_leak_check_allows_when_egress_ip_differs_from_native_ip():
    calls: list[list[str]] = []
    stdout = "NATIVE_IP:ok:203.0.113.10\nEGRESS_IP:ok:198.51.100.20\n"

    def fake_runner(command: list[str]):
        calls.append(command)
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    report = run_remote_leak_check(host="166.88.232.2", port=22, user="root", runner=fake_runner)

    assert report == RemoteLeakCheckReport(
        status="ok",
        target="root@166.88.232.2:22",
        native_public_ip="203.0.113.10",
        egress_public_ip="198.51.100.20",
        checks=[
            RemoteLeakCheck("native_ip", "ok", "203.0.113.10"),
            RemoteLeakCheck("egress_ip", "ok", "198.51.100.20"),
            RemoteLeakCheck("egress_guard", "ok", "egress guard checks passed"),
        ],
        commands_executed=[" ".join(build_remote_leak_check_command(host="166.88.232.2", port=22, user="root"))],
        performed_side_effects=False,
    )
    assert calls


def test_run_remote_leak_check_fails_closed_when_egress_ip_matches_native_ip():
    stdout = "NATIVE_IP:ok:203.0.113.10\nEGRESS_IP:ok:203.0.113.10\n"

    def fake_runner(command: list[str]):
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    report = run_remote_leak_check(host="166.88.232.2", port=22, user="root", runner=fake_runner)

    assert report.status == "failed"
    assert report.native_public_ip == "203.0.113.10"
    assert report.egress_public_ip == "203.0.113.10"
    assert RemoteLeakCheck("egress_guard", "failed", "egress public IP matches native VPS public IP; egress blocked") in report.checks
    assert report.performed_side_effects is False


def test_run_remote_leak_check_fails_closed_when_probe_output_is_missing():
    stdout = "NATIVE_IP:ok:203.0.113.10\nEGRESS_IP:failed:curl failed\n"

    def fake_runner(command: list[str]):
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    report = run_remote_leak_check(host="166.88.232.2", port=22, user="root", runner=fake_runner)

    assert report.status == "failed"
    assert RemoteLeakCheck("egress_ip", "failed", "curl failed") in report.checks
    assert RemoteLeakCheck("egress_guard", "failed", "egress public IP could not be verified; egress blocked") in report.checks
    assert report.performed_side_effects is False


def test_run_remote_leak_check_rejects_embedded_credentials_without_runner_call():
    calls: list[list[str]] = []

    report = run_remote_leak_check(host="root:secret@166.88.232.2", port=22, user="root", runner=lambda command: calls.append(command))

    assert report == RemoteLeakCheckReport(
        status="failed",
        target="[REDACTED]",
        native_public_ip=None,
        egress_public_ip=None,
        checks=[RemoteLeakCheck("target", "failed", "embedded credentials are not allowed")],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []
    assert "secret" not in render_remote_leak_check_report(report)


def test_render_remote_leak_check_report_is_structured_and_safe():
    report = RemoteLeakCheckReport(
        status="failed",
        target="root@166.88.232.2:22",
        native_public_ip="203.0.113.10",
        egress_public_ip="203.0.113.10",
        checks=[RemoteLeakCheck("egress_guard", "failed", "egress public IP matches native VPS public IP; egress blocked")],
        commands_executed=["ssh -p 22 root@166.88.232.2 readonly leak check"],
        performed_side_effects=False,
    )

    rendered = render_remote_leak_check_report(report)

    assert "Remote leak check" in rendered
    assert "status: failed" in rendered
    assert "target: root@166.88.232.2:22" in rendered
    assert "native_public_ip: 203.0.113.10" in rendered
    assert "egress_public_ip: 203.0.113.10" in rendered
    assert "commands_executed: ['ssh -p 22 root@166.88.232.2 readonly leak check']" in rendered
    assert "performed_side_effects: False" in rendered
    assert "- egress_guard: failed - egress public IP matches native VPS public IP; egress blocked" in rendered
    assert "password" not in rendered.lower()
    assert "sshpass" not in rendered.lower()
