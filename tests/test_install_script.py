from pathlib import Path


INSTALL_SCRIPT = Path("scripts/install.sh")


def _read_script() -> str:
    return INSTALL_SCRIPT.read_text(encoding="utf-8")


# ── basic structure ───────────────────────────────────────────────────────

def test_one_click_install_script_supports_curl_pipe_style_interactive_setup():
    script = _read_script()

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
    assert ' setup \\\n' in script or ' setup\n' in script or ' setup ' in script
    assert '--no-dry-run' in script
    assert '--yes' in script
    assert '--allow-system-changes' in script
    assert "Web UI:" in script


def test_one_click_install_script_is_executable():
    assert INSTALL_SCRIPT.stat().st_mode & 0o111


# ── #1: port preflight regex must be precise ──────────────────────────────

def test_port_preflight_regex_matches_port_as_complete_token():
    """Issue #1: regex must not match port 80 inside port 8080."""
    script = _read_script()
    # must use end-of-field anchor, not just end-of-line
    assert "(\\s|$)" in script or "(\\s|\\$)" in script
    # must NOT use bare $ as only anchor (allows partial matches like 80 in 8080)
    assert 'grep -Eq "(^|:)${MIGATE_PANEL_PORT}$"' not in script


# ── #2: default port must match config default ────────────────────────────

def test_default_panel_port_is_8787():
    """Issue #2: default port should match MiGateConfig().security.web_port."""
    script = _read_script()
    assert "'8787'" in script or '"8787"' in script


# ── #4: proxy service must be started ─────────────────────────────────────

def test_proxy_service_is_enabled_and_started():
    """Issue #4: save_runtime_units saves proxy unit but start must also enable it."""
    script = _read_script()
    assert "systemctl enable --now migate-proxy.service" in script


# ── #5: git update must use reset --hard not checkout FETCH_HEAD ──────────

def test_git_update_uses_reset_hard_not_checkout_fetch_head():
    """Issue #5: reset --hard origin/$REF is safer than checkout --force FETCH_HEAD."""
    script = _read_script()
    assert "reset --hard" in script
    assert "FETCH_HEAD" not in script


# ── #6: rm -rf must have install-dir guard ─────────────────────────────────

def test_rm_rf_has_install_dir_guard():
    """Issue #6: validate_install_dir prevents rm -rf /."""
    script = _read_script()
    assert "validate_install_dir" in script
    assert 'MIGATE_INSTALL_DIR = "/"' in script or 'MIGATE_INSTALL_DIR" = "/"' in script
    # validate_install_dir must be called before fetch_source (which does rm -rf)
    assert script.index("validate_install_dir") < script.index("fetch_source")


# ── #7: WebUI verification must wait long enough ──────────────────────────

def test_webui_verification_waits_long_enough_for_slow_vps():
    """Issue #7: 10 attempts × 2s = 20s is enough for Python cold start."""
    script = _read_script()
    # must have at least 10 attempts
    assert "seq 1 10" in script or "{1..10}" in script
    # must sleep at least 2s between attempts
    assert "sleep 2" in script


# ── #8: no duplicate require_command before install_os_packages ────────────

def test_no_duplicate_require_command_checks():
    """Issue #8: require_command git/python3 should appear once before install_os_packages."""
    script = _read_script()
    # Count occurrences of "require_command git" and "require_command python3"
    git_count = script.count("require_command git")
    python_count = script.count("require_command python3")
    assert git_count == 1, f"require_command git appears {git_count} times (expected 1)"
    assert python_count == 1, f"require_command python3 appears {python_count} times (expected 1)"


# ── #9: no pip self-upgrade ───────────────────────────────────────────────

def test_no_pip_self_upgrade():
    """Issue #9: pip install --upgrade pip is unnecessary and risky."""
    script = _read_script()
    assert "pip install --upgrade pip" not in script
    assert "pip install --upgrade --force-reinstall" in script


# ── #11: uninstall mode ──────────────────────────────────────────────────

def test_uninstall_mode_exists():
    """Issue #11: script must support --uninstall."""
    script = _read_script()
    assert "--uninstall" in script
    assert "do_uninstall" in script
    # must stop and disable services
    assert "systemctl disable --now migate-panel" in script
    assert "systemctl disable --now migate-xray" in script
    assert "systemctl disable --now migate-proxy" in script
    # must remove unit files
    assert "rm -f /etc/systemd/system/migate-panel.service" in script
    assert "rm -f /etc/systemd/system/migate-xray.service" in script
    assert "rm -f /etc/systemd/system/migate-proxy.service" in script
    # must remove config and data
    assert "rm -rf /etc/migate" in script
    assert "rm -rf /var/lib/migate" in script
    # must daemon-reload after removing units (within do_uninstall function)
    uninstall_start = script.index("do_uninstall()")
    uninstall_body = script[uninstall_start:]
    assert uninstall_body.index("rm -f /etc/systemd/system/migate-panel") < \
           uninstall_body.index("systemctl daemon-reload")


# ── #12: upgrade mode ────────────────────────────────────────────────────

def test_upgrade_mode_exists():
    """Issue #12: script must support --upgrade."""
    script = _read_script()
    assert "--upgrade" in script
    assert "do_upgrade" in script
    # upgrade must fetch, reinstall, and restart
    assert "fetch_source" in script
    assert "install_python_package" in script
    assert "systemctl restart migate-panel" in script
    assert "systemctl restart migate-xray" in script
    assert "systemctl restart migate-proxy" in script


# ── preflight & security hygiene ──────────────────────────────────────────

def test_one_click_install_script_has_preflight_and_secret_hygiene_guards():
    script = _read_script()

    assert "require_root" in script
    assert "require_command" in script
    assert "apt-get" in script
    assert "sshpass" not in script
    assert "StrictHostKeyChecking=accept-new" not in script


# ── service management ────────────────────────────────────────────────────

def test_one_click_install_script_writes_services_and_prints_next_steps():
    script = _read_script()

    assert "panel-service save --yes --allow-system-changes" in script
    assert "xray service save --yes --allow-system-changes" in script
    assert "proxy service save --yes --allow-system-changes" in script
    assert "systemctl enable --now migate-panel.service" in script
    assert "systemctl enable --now migate-xray.service" in script
    assert "systemctl enable --now migate-proxy.service" in script
    assert "migate remote acceptance --backend xray-tun" in script


# ── WebUI verification ───────────────────────────────────────────────────

def test_one_click_install_script_verifies_webui_after_starting_services():
    script = _read_script()

    assert "verify_webui" in script
    assert "curl -fsS" in script
    assert "http://127.0.0.1:${MIGATE_PANEL_PORT}" in script
    # verify_webui must come after start_services
    assert script.index("start_services") < script.index("verify_webui") < script.index("print_next_steps")


# ── failure diagnostics ──────────────────────────────────────────────────

def test_one_click_install_script_enhances_failure_diagnostics_and_service_summary():
    script = _read_script()

    # failure diagnostics: show journalctl on WebUI verify failure
    assert "install_failure_diagnostics" in script
    assert "journalctl" in script
    assert "migate-panel.service" in script

    # success summary: show service status in final output
    assert "systemctl is-active migate-panel.service" in script
    assert "Service status" in script
    # must show all three services in output
    assert "Panel:" in script
    assert "Xray:" in script
    assert "Proxy:" in script


# ── venv-free install ────────────────────────────────────────────────────

def test_one_click_install_script_installs_without_venv_like_binary_style_installer():
    script = _read_script()

    assert "python3 -m venv" not in script
    assert "python3-venv" not in script
    assert ".venv" not in script
    assert "--break-system-packages" in script
    assert "python3 -m pip install" in script
    assert "ln -sfn" in script
    assert "/usr/local/bin/migate" in script


# ── install dir safety ───────────────────────────────────────────────────

def test_validate_install_dir_prevents_destructive_operations():
    """validate_install_dir must guard both fetch_source (rm -rf) and do_uninstall."""
    script = _read_script()
    assert "validate_install_dir" in script
    # fetch_source calls validate_install_dir
    assert script.index("validate_install_dir") < script.index("fetch_source")


# ── main flow ordering ───────────────────────────────────────────────────

def test_main_flow_ordering():
    """Ensure the main install flow has the correct step ordering."""
    script = _read_script()
    steps = [
        "require_root",
        "collect_panel_inputs",
        "ensure_panel_port_available",
        "install_os_packages",
        "fetch_source",
        "install_python_package",
        "run_setup",
        "save_runtime_units",
        "start_services",
        "verify_webui",
        "print_next_steps",
    ]
    for i in range(len(steps) - 1):
        a, b = steps[i], steps[i + 1]
        assert script.index(a) < script.index(b), \
            f"Expected '{a}' before '{b}' in main flow"
