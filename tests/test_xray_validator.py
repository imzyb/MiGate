import subprocess

from migate.xray.validator import XrayValidationResult, validate_xray_config


def test_validate_xray_config_reports_missing_xray_binary(tmp_path):
    result = validate_xray_config(tmp_path / "config.json", runner=lambda *_args: (_ for _ in ()).throw(FileNotFoundError()))

    assert result == XrayValidationResult(status="xray_not_found", returncode=None, stdout="", stderr="xray command not found")


def test_validate_xray_config_reports_valid_config(tmp_path):
    def runner(args):
        assert args == ["xray", "test", "-config", str(tmp_path / "config.json")]
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="config ok", stderr="")

    result = validate_xray_config(tmp_path / "config.json", runner=runner)

    assert result.status == "valid"
    assert result.returncode == 0
    assert result.stdout == "config ok"
    assert result.stderr == ""


def test_validate_xray_config_falls_back_when_xray_test_subcommand_is_missing(tmp_path):
    calls = []

    def runner(args):
        calls.append(args)
        if args[1] == "test":
            return subprocess.CompletedProcess(args=args, returncode=2, stdout="", stderr="xray test: unknown command")
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="config ok", stderr="")

    result = validate_xray_config(tmp_path / "config.json", runner=runner)

    assert result.status == "valid"
    assert result.returncode == 0
    assert result.stdout == "config ok"
    assert result.stderr == ""
    assert calls == [
        ["xray", "test", "-config", str(tmp_path / "config.json")],
        ["xray", "run", "-test", "-config", str(tmp_path / "config.json")],
    ]


def test_validate_xray_config_reports_invalid_config(tmp_path):
    def runner(args):
        return subprocess.CompletedProcess(args=args, returncode=23, stdout="", stderr="invalid inbound")

    result = validate_xray_config(tmp_path / "bad.json", runner=runner)

    assert result.status == "invalid"
    assert result.returncode == 23
    assert result.stdout == ""
    assert result.stderr == "invalid inbound"
