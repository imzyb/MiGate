from migate.config import MiGateConfig
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

    report = run_xray_install_doctor(
        command_exists=command_exists,
        path_writable=path_writable,
        systemd_available=lambda: True,
        is_root=lambda: True,
        port_available=lambda host, port: True,
    )

    assert isinstance(report, DoctorReport)
    assert report.status == "failed"
    assert checked_commands == ["curl", "unzip", "python3", "systemctl"]
    assert checked_writable_paths == ["/usr/local/bin", "/etc/migate/xray", "/etc/systemd/system"]
    assert report.checks == [
        DoctorCheck(name="command:curl", status="ok", message="curl found"),
        DoctorCheck(name="command:unzip", status="missing", message="unzip not found"),
        DoctorCheck(name="command:python3", status="ok", message="python3 found"),
        DoctorCheck(name="command:systemctl", status="ok", message="systemctl found"),
        DoctorCheck(name="systemd", status="ok", message="systemd is available"),
        DoctorCheck(name="root", status="ok", message="current user is root"),
        DoctorCheck(name="writable:/usr/local/bin", status="failed", message="/usr/local/bin is not writable"),
        DoctorCheck(name="writable:/etc/migate/xray", status="ok", message="/etc/migate/xray is writable or creatable"),
        DoctorCheck(name="writable:/etc/systemd/system", status="ok", message="/etc/systemd/system is writable or creatable"),
        DoctorCheck(name="port:127.0.0.1:10085", status="ok", message="127.0.0.1:10085 is available"),
        DoctorCheck(name="port:127.0.0.1:34501", status="ok", message="127.0.0.1:34501 is available"),
        DoctorCheck(name="port:127.0.0.1:34502", status="ok", message="127.0.0.1:34502 is available"),
    ]


def test_xray_install_doctor_passes_when_all_checks_are_ok():
    report = run_xray_install_doctor(
        command_exists=lambda command: True,
        path_writable=lambda path: True,
        systemd_available=lambda: True,
        is_root=lambda: True,
        port_available=lambda host, port: True,
    )

    assert report.status == "ok"
    assert all(check.status == "ok" for check in report.checks)


def test_xray_install_doctor_accepts_python3_when_python_alias_is_missing():
    def command_exists(command: str) -> bool:
        return command in {"curl", "unzip", "python3", "systemctl"}

    report = run_xray_install_doctor(
        command_exists=command_exists,
        path_writable=lambda path: True,
        systemd_available=lambda: True,
        is_root=lambda: True,
        port_available=lambda host, port: True,
    )

    assert report.status == "ok"
    assert DoctorCheck(name="command:python3", status="ok", message="python3 found") in report.checks
    assert not any(check.name == "command:python" for check in report.checks)


def test_xray_install_doctor_reports_deploy_preflight_checks_without_side_effects():
    checked_ports = []
    checked_paths = []
    config = MiGateConfig()

    def path_writable(path: str) -> bool:
        checked_paths.append(path)
        return path != "/etc/systemd/system"

    def port_available(host: str, port: int) -> bool:
        checked_ports.append((host, port))
        return port != config.xray.api_port

    report = run_xray_install_doctor(
        config,
        command_exists=lambda command: command != "systemctl",
        path_writable=path_writable,
        systemd_available=lambda: False,
        is_root=lambda: False,
        port_available=port_available,
    )

    assert report.status == "failed"
    assert checked_paths == ["/usr/local/bin", "/etc/migate/xray", "/etc/systemd/system"]
    assert checked_ports == [
        (config.xray.api_host, config.xray.api_port),
        (config.proxy.socks_host, config.proxy.socks_port),
        (config.proxy.http_host, config.proxy.http_port),
    ]
    assert DoctorCheck("command:systemctl", "missing", "systemctl not found") in report.checks
    assert DoctorCheck("systemd", "failed", "systemd is not available") in report.checks
    assert DoctorCheck("root", "failed", "current user is not root") in report.checks
    assert DoctorCheck("writable:/etc/systemd/system", "failed", "/etc/systemd/system is not writable") in report.checks
    assert DoctorCheck(f"port:{config.xray.api_host}:{config.xray.api_port}", "busy", f"{config.xray.api_host}:{config.xray.api_port} is already in use") in report.checks
    assert DoctorCheck(f"port:{config.proxy.socks_host}:{config.proxy.socks_port}", "ok", f"{config.proxy.socks_host}:{config.proxy.socks_port} is available") in report.checks
    assert DoctorCheck(f"port:{config.proxy.http_host}:{config.proxy.http_port}", "ok", f"{config.proxy.http_host}:{config.proxy.http_port} is available") in report.checks


def test_xray_install_doctor_allows_existing_proxy_listener_ports_during_idempotent_install():
    config = MiGateConfig()

    def port_available(host: str, port: int) -> bool:
        return port == config.xray.api_port

    report = run_xray_install_doctor(
        config,
        command_exists=lambda command: True,
        path_writable=lambda path: True,
        systemd_available=lambda: True,
        is_root=lambda: True,
        port_available=port_available,
    )

    assert report.status == "ok"
    assert DoctorCheck(
        f"port:{config.xray.api_host}:{config.xray.api_port}",
        "ok",
        f"{config.xray.api_host}:{config.xray.api_port} is available",
    ) in report.checks
    assert DoctorCheck(
        f"port:{config.proxy.socks_host}:{config.proxy.socks_port}",
        "ok",
        f"{config.proxy.socks_host}:{config.proxy.socks_port} is already in use by an existing proxy listener; safe for idempotent install",
    ) in report.checks
    assert DoctorCheck(
        f"port:{config.proxy.http_host}:{config.proxy.http_port}",
        "ok",
        f"{config.proxy.http_host}:{config.proxy.http_port} is already in use by an existing proxy listener; safe for idempotent install",
    ) in report.checks


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
