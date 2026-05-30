import json

from migate.xray.writer import write_xray_config


def test_write_xray_config_creates_parent_dir_and_formats_json(tmp_path):
    target = tmp_path / "etc" / "migate" / "xray" / "config.json"
    config = {
        "outbounds": [
            {"protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": 34501}]}}
        ]
    }

    written = write_xray_config(config, target)

    assert written == target
    assert target.exists()
    content = target.read_text(encoding="utf-8")
    assert content.endswith("\n")
    assert '  "outbounds": [' in content
    assert json.loads(content) == config
