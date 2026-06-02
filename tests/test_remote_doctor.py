from migate.remote.doctor import (
    RemoteDoctorCheck,
    RemoteDoctorReport,
    build_remote_ssh_probe_command,
    render_remote_doctor_report,
    run_remote_doctor,
)


def test_build_remote_ssh_probe_command_is_read_only_and_batched():
    command = build_remote_ssh_probe_command(host="166.88.232.2", port=22, user="root", timeout_seconds=7)

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
        "hostname && uname -srm && id -u && command -v python3 && command -v systemctl && command -v ip && command -v openvpn",
    ]
    assert "accept-new" not in command
    assert "sshpass" not in " ".join(command).lower()
    assert "password" not in " ".join(command).lower()


def test_run_remote_doctor_rejects_embedded_credentials_before_runner_call():
    calls = []

    report = run_remote_doctor(host="root:secret@166.88.232.2", port=22, user="root", runner=lambda command: calls.append(command))

    assert report == RemoteDoctorReport(
        status="failed",
        target="[REDACTED]",
        checks=[RemoteDoctorCheck("target", "failed", "embedded credentials are not allowed")],
        commands_executed=[],
        performed_side_effects=False,
    )
    assert calls == []
    rendered = render_remote_doctor_report(report)
    assert "secret" not in rendered


def test_run_remote_doctor_success_maps_probe_output_to_checks():
    calls = []

    def fake_runner(command: list[str]):
        calls.append(command)
        return type("Result", (), {"returncode": 0, "stdout": "migate-test\nLinux aarch64 6.8\n0\n/usr/bin/python3\n/usr/bin/systemctl\n/usr/sbin/ip\n/usr/sbin/openvpn\n", "stderr": ""})()

    report = run_remote_doctor(host="166.88.232.2", port=22, user="root", runner=fake_runner)

    assert report.status == "ok"
    assert report.target == "root@166.88.232.2:22"
    assert report.commands_executed == ["ssh -p 22 -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes root@166.88.232.2 hostname && uname -srm && id -u && command -v python3 && command -v systemctl && command -v ip && command -v openvpn"]
    assert report.performed_side_effects is False
    assert RemoteDoctorCheck("ssh_connectivity", "ok", "SSH probe succeeded") in report.checks
    assert RemoteDoctorCheck("remote_user", "ok", "remote id -u is 0") in report.checks
    assert RemoteDoctorCheck("command:openvpn", "ok", "/usr/sbin/openvpn") in report.checks
    assert calls


def test_run_remote_doctor_failure_preserves_stderr_without_credentials():
    def fake_runner(command: list[str]):
        return type("Result", (), {"returncode": 255, "stdout": "", "stderr": "Permission denied (publickey)."})()

    report = run_remote_doctor(host="166.88.232.2", port=22, user="root", runner=fake_runner)

    assert report.status == "failed"
    assert report.performed_side_effects is False
    assert RemoteDoctorCheck("ssh_connectivity", "failed", "Permission denied (publickey).") in report.checks
    rendered = render_remote_doctor_report(report)
    assert "Remote doctor" in rendered
    assert "status: failed" in rendered
    assert "performed_side_effects: False" in rendered
    assert "Permission denied (publickey)." in rendered
    assert "password" not in rendered.lower()
    assert "sshpass" not in rendered.lower()
