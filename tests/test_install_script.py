from pathlib import Path


INSTALL_SCRIPT = Path("scripts/install.sh")


def test_one_click_install_script_supports_curl_pipe_style_interactive_setup():
    script = INSTALL_SCRIPT.read_text(encoding="utf-8")

    assert script.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in script
    assert "MIGATE_REPO" in script
    assert "https://github.com/imzyb/MiGate.git" in script
    assert "prompt_with_default" in script
    assert "read -r -p" in script
    assert "read -r -s -p" in script
    assert "MIGATE_PANEL_PORT" in script
    assert "MIGATE_PANEL_USER" in script
    assert "MIGATE_PANEL_PASSWORD" in script
    assert "MIGATE_PANEL_BASE_PATH" in script
    assert "MIGATE_PUBLIC_HOST" in script
    assert ' setup \\\n' in script or ' setup\\n' in script or ' setup ' in script
    assert '--no-dry-run' in script
    assert '--yes' in script
    assert '--allow-system-changes' in script
    assert "panel --host" not in script
    assert "Web UI:" in script


def test_one_click_install_script_is_executable():
    assert INSTALL_SCRIPT.stat().st_mode & 0o111


def test_one_click_install_script_has_preflight_and_secret_hygiene_guards():
    script = INSTALL_SCRIPT.read_text(encoding="utf-8")

    assert "require_root" in script
    assert "require_command" in script
    assert "apt-get" in script
    assert "sshpass" not in script
    assert "StrictHostKeyChecking=accept-new" not in script
    assert "printf '%s' \"$MIGATE_PANEL_PASSWORD\"" not in script
    assert "token" not in script.lower()


def test_one_click_install_script_verifies_webui_after_starting_services():
    script = INSTALL_SCRIPT.read_text(encoding="utf-8")

    assert "verify_webui" in script
    assert "curl -fsS" in script
    assert "http://127.0.0.1:${MIGATE_PANEL_PORT}" in script
    assert script.index("start_panel_service") < script.index("verify_webui") < script.index("print_next_steps")


def test_one_click_install_script_writes_services_and_prints_next_steps():
    script = INSTALL_SCRIPT.read_text(encoding="utf-8")

    assert "xray service save --yes --allow-system-changes" in script
    assert "proxy service save --yes --allow-system-changes" in script
    assert "systemctl enable --now migate-panel.service" in script
    assert "systemctl enable --now migate-xray.service" in script
    assert "migate remote acceptance --backend xray-tun" in script
