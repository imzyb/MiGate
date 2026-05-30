import os
import subprocess

from migate.xray.runtime import XrayRuntimeStatus, detect_xray_runtime, parse_xray_version


def test_parse_xray_version_from_standard_output():
    output = "Xray 1.8.24 (Xray, Penetrates Everything.) Custom\nA unified platform for anti-censorship.\n"

    assert parse_xray_version(output) == "1.8.24"


def test_parse_xray_version_returns_none_for_unrecognized_output():
    assert parse_xray_version("not an xray version") is None


def test_detect_xray_runtime_reports_missing_binary_without_running_version(tmp_path):
    missing = tmp_path / "xray"
    calls = []

    def runner(*args, **kwargs):
        calls.append(args)
        raise AssertionError("runner should not be called for missing binary")

    status = detect_xray_runtime(str(missing), runner=runner, path_exists=lambda path: False)

    assert isinstance(status, XrayRuntimeStatus)
    assert status.status == "not_installed"
    assert status.bin_path == str(missing)
    assert status.version is None
    assert "not found" in status.message
    assert calls == []


def test_detect_xray_runtime_reports_installed_version_from_stdout():
    def runner(command, capture_output, text, check):
        assert command == ["/usr/local/bin/xray", "version"]
        assert capture_output is True
        assert text is True
        assert check is False
        return subprocess.CompletedProcess(command, 0, stdout="Xray 1.8.24\n", stderr="")

    status = detect_xray_runtime("/usr/local/bin/xray", runner=runner, path_exists=lambda path: True)

    assert status.status == "installed"
    assert status.version == "1.8.24"
    assert status.returncode == 0
    assert status.stdout == "Xray 1.8.24\n"
    assert status.stderr == ""


def test_detect_xray_runtime_preserves_version_command_failure_details():
    def runner(command, capture_output, text, check):
        return subprocess.CompletedProcess(command, 2, stdout="", stderr="permission denied")

    status = detect_xray_runtime("/usr/local/bin/xray", runner=runner, path_exists=lambda path: True)

    assert status.status == "version_failed"
    assert status.version is None
    assert status.returncode == 2
    assert status.stderr == "permission denied"


def test_detect_xray_runtime_handles_runner_file_not_found_race():
    def runner(command, capture_output, text, check):
        raise FileNotFoundError

    status = detect_xray_runtime("/usr/local/bin/xray", runner=runner, path_exists=lambda path: True)

    assert status.status == "not_installed"
    assert status.version is None
    assert status.returncode is None
    assert "not found" in status.message
