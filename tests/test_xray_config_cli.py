import json
import subprocess

from migate.config import MiGateConfig
from migate.xray.config_cli import XrayConfigSaveResult, build_default_xray_config, preview_xray_config, save_xray_config


def test_preview_xray_config_renders_safe_default_json_without_side_effects():
    rendered = preview_xray_config(MiGateConfig())
    data = json.loads(rendered)

    assert data["outbounds"][0]["protocol"] == "socks"
    assert data["outbounds"][0]["settings"]["servers"][0]["address"] == "127.0.0.1"
    assert {outbound["protocol"] for outbound in data["outbounds"]} == {"socks", "blackhole"}
    assert data["inbounds"][-1]["tag"] == "vless-main"
    assert data["inbounds"][0]["tag"] == "api"
    assert rendered.endswith("\n")


def test_build_default_xray_config_uses_placeholder_client_values():
    config = build_default_xray_config(MiGateConfig())
    inbound = config["inbounds"][-1]

    assert inbound["protocol"] == "vless"
    assert inbound["settings"]["clients"][0]["id"] == "00000000-0000-4000-8000-000000000001"
    assert inbound["settings"]["clients"][0]["email"] == "default@migate.local"


def test_save_xray_config_rejects_without_double_gate(tmp_path):
    calls = []

    def validator(path):
        calls.append(path)
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

    result = save_xray_config(
        MiGateConfig(),
        tmp_path / "config.json",
        yes=True,
        allow_system_changes=False,
        validator_runner=validator,
    )

    assert result == XrayConfigSaveResult(
        status="rejected",
        message="config save requires yes=True and allow_system_changes=True",
        target=tmp_path / "config.json",
        validation_status="skipped",
        performed_side_effects=False,
    )
    assert calls == []
    assert not (tmp_path / "config.json").exists()


def test_save_xray_config_writes_then_validates_when_double_gate_passes(tmp_path):
    calls = []

    def validator(args):
        calls.append(args)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="config ok", stderr="")

    target = tmp_path / "xray" / "config.json"
    result = save_xray_config(
        MiGateConfig(),
        target,
        yes=True,
        allow_system_changes=True,
        validator_runner=validator,
    )

    assert result.status == "saved"
    assert result.message == "config saved and validated"
    assert result.target == target
    assert result.validation_status == "valid"
    assert result.performed_side_effects is True
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8"))["outbounds"][0]["protocol"] == "socks"
    assert calls == [["xray", "test", "-config", str(target.with_name("config.tmp.json"))]]


def test_save_xray_config_backs_up_existing_config_and_keeps_backup_on_success(tmp_path):
    target = tmp_path / "config.json"
    target.write_text('{"old": true}\n', encoding="utf-8")

    def validator(args):
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="config ok", stderr="")

    result = save_xray_config(
        MiGateConfig(),
        target,
        yes=True,
        allow_system_changes=True,
        validator_runner=validator,
        backup_suffix=".bak-test",
    )

    assert result.status == "saved"
    assert result.backup_path == target.with_name("config.json.bak-test")
    assert result.rollback_performed is False
    assert result.backup_path.read_text(encoding="utf-8") == '{"old": true}\n'
    assert json.loads(target.read_text(encoding="utf-8"))["outbounds"][0]["protocol"] == "socks"


def test_save_xray_config_restores_existing_config_when_validation_fails(tmp_path):
    target = tmp_path / "config.json"
    old_content = '{"old": true}\n'
    target.write_text(old_content, encoding="utf-8")

    def validator(args):
        return subprocess.CompletedProcess(args=args, returncode=23, stdout="", stderr="invalid config")

    result = save_xray_config(
        MiGateConfig(),
        target,
        yes=True,
        allow_system_changes=True,
        validator_runner=validator,
        backup_suffix=".bak-test",
    )

    assert result.status == "invalid"
    assert result.message == "config validation failed; restored previous config"
    assert result.validation_status == "invalid"
    assert result.rollback_performed is True
    assert result.backup_path == target.with_name("config.json.bak-test")
    assert target.read_text(encoding="utf-8") == old_content


def test_save_xray_config_removes_new_config_when_validation_fails_without_existing_file(tmp_path):
    target = tmp_path / "config.json"

    def validator(args):
        return subprocess.CompletedProcess(args=args, returncode=23, stdout="", stderr="invalid config")

    result = save_xray_config(
        MiGateConfig(),
        target,
        yes=True,
        allow_system_changes=True,
        validator_runner=validator,
    )

    assert result.status == "invalid"
    assert result.message == "config validation failed; removed invalid new config"
    assert result.rollback_performed is True
    assert result.backup_path is None
    assert not target.exists()


def test_save_xray_config_reports_validation_failure_after_write(tmp_path):
    def validator(args):
        return subprocess.CompletedProcess(args=args, returncode=23, stdout="", stderr="invalid config")

    target = tmp_path / "config.json"
    result = save_xray_config(
        MiGateConfig(),
        target,
        yes=True,
        allow_system_changes=True,
        validator_runner=validator,
    )

    assert result.status == "invalid"
    assert result.message == "config validation failed; removed invalid new config"
    assert result.validation_status == "invalid"
    assert result.performed_side_effects is True
    assert result.rollback_performed is True
    assert not target.exists()
