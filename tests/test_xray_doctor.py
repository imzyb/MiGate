from migate.xray.doctor import DoctorCheck, DoctorReport, run_xray_install_doctor


def test_xray_install_doctor_reports_required_commands_and_writable_paths():
    checked_commands = []
    checked_writable_paths = []

    def command_exists(command: str) -> bool:
        checked_commands.append(command)
        return command != "unzip"

    def path_writable(path: str) -> bool:
        checked_writable_paths.append(path)
        return path != "/usr/local/bin"

    report = run_xray_install_doctor(command_exists=command_exists, path_writable=path_writable)

    assert isinstance(report, DoctorReport)
    assert report.status == "failed"
    assert checked_commands == ["curl", "unzip", "python"]
    assert checked_writable_paths == ["/usr/local/bin", "/etc/migate/xray"]
    assert report.checks == [
        DoctorCheck(name="command:curl", status="ok", message="curl found"),
        DoctorCheck(name="command:unzip", status="missing", message="unzip not found"),
        DoctorCheck(name="command:python", status="ok", message="python found"),
        DoctorCheck(name="writable:/usr/local/bin", status="failed", message="/usr/local/bin is not writable"),
        DoctorCheck(name="writable:/etc/migate/xray", status="ok", message="/etc/migate/xray is writable or creatable"),
    ]


def test_xray_install_doctor_passes_when_all_checks_are_ok():
    report = run_xray_install_doctor(command_exists=lambda command: True, path_writable=lambda path: True)

    assert report.status == "ok"
    assert all(check.status == "ok" for check in report.checks)


def test_xray_install_doctor_report_renders_human_readable_output():
    report = DoctorReport(
        status="failed",
        checks=[
            DoctorCheck(name="command:curl", status="ok", message="curl found"),
            DoctorCheck(name="command:unzip", status="missing", message="unzip not found"),
        ],
    )

    rendered = report.to_report()

    assert "Xray 安装前检查" in rendered
    assert "status: failed" in rendered
    assert "command:curl: ok - curl found" in rendered
    assert "command:unzip: missing - unzip not found" in rendered
