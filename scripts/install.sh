#!/usr/bin/env bash
set -euo pipefail

MIGATE_REPO="${MIGATE_REPO:-https://github.com/imzyb/MiGate.git}"
MIGATE_REF="${MIGATE_REF:-main}"
MIGATE_INSTALL_DIR="${MIGATE_INSTALL_DIR:-/opt/migate}"
MIGATE_BIN="${MIGATE_BIN:-/usr/local/bin/migate}"
MIGATE_PANEL_PORT="${MIGATE_PANEL_PORT:-}"
MIGATE_PANEL_USER="${MIGATE_PANEL_USER:-}"
MIGATE_PANEL_PASSWORD="${MIGATE_PANEL_PASSWORD:-}"
MIGATE_PANEL_BASE_PATH="${MIGATE_PANEL_BASE_PATH:-}"
MIGATE_PUBLIC_HOST="${MIGATE_PUBLIC_HOST:-}"
MIGATE_SETUP_CONFIG_TARGET="${MIGATE_SETUP_CONFIG_TARGET:-/etc/migate/setup-panel.json}"

# ── helpers ──────────────────────────────────────────────────────────────

log() {
  printf '[migate-install] %s\n' "$*"
}

die() {
  printf '[migate-install] FATAL: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [ "$(id -u)" -eq 0 ] || die "MiGate installer must run as root."
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

prompt_with_default() {
  local prompt="$1" default_value="$2" value=""
  read -r -p "$prompt [$default_value]: " value
  printf '%s' "${value:-$default_value}"
}

prompt_secret() {
  local prompt="$1" value=""
  while true; do
    read -r -s -p "$prompt: " value
    printf '\n' >/dev/tty
    if [ -n "$value" ]; then
      printf '%s' "$value"
      return 0
    fi
    printf 'Password cannot be empty.\n' >&2
  done
}

detect_public_host() {
  if [ -n "${MIGATE_PUBLIC_HOST:-}" ]; then
    printf '%s' "$MIGATE_PUBLIC_HOST"
    return 0
  fi

  local candidate=""
  candidate="$(curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  if [ -n "$candidate" ]; then
    printf '%s' "$candidate"
    return 0
  fi

  candidate="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  if [ -n "$candidate" ]; then
    printf '%s' "$candidate"
    return 0
  fi

  printf '127.0.0.1'
}

# ── input collection ─────────────────────────────────────────────────────

collect_panel_inputs() {
  if [ -z "$MIGATE_PANEL_PORT" ]; then
    MIGATE_PANEL_PORT="$(prompt_with_default 'Custom panel port' '8787')"
  fi
  if [ -z "$MIGATE_PANEL_USER" ]; then
    MIGATE_PANEL_USER="$(prompt_with_default 'Admin username' 'admin')"
  fi
  if [ -z "$MIGATE_PANEL_PASSWORD" ]; then
    MIGATE_PANEL_PASSWORD="$(prompt_secret 'Admin password')"
  fi
  if [ -z "$MIGATE_PANEL_BASE_PATH" ]; then
    MIGATE_PANEL_BASE_PATH="$(prompt_with_default 'Custom web path' '/migate')"
  fi
  MIGATE_PUBLIC_HOST="$(detect_public_host)"
}

# ── preflight checks ─────────────────────────────────────────────────────

validate_install_dir() {
  if [ -z "$MIGATE_INSTALL_DIR" ] || [ "$MIGATE_INSTALL_DIR" = "/" ]; then
    die "MIGATE_INSTALL_DIR is empty or '/' — refusing to proceed."
  fi
}

ensure_panel_port_available() {
  require_command ss
  # match port as a complete token at end-of-field (handles IPv4/IPv6)
  if ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${MIGATE_PANEL_PORT}(\s|$)"; then
    die "Panel port $MIGATE_PANEL_PORT is already in use. Choose another or stop the service."
  fi
}

# ── OS packages ───────────────────────────────────────────────────────────

install_os_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      iproute2 \
      openvpn \
      python3 \
      python3-pip \
      rsync \
      unzip
  else
    log 'apt-get not found; skipping OS package installation'
  fi
}

# ── source management ─────────────────────────────────────────────────────

fetch_source() {
  validate_install_dir
  if [ -d "$MIGATE_INSTALL_DIR/.git" ]; then
    log "updating MiGate source in $MIGATE_INSTALL_DIR"
    git -C "$MIGATE_INSTALL_DIR" fetch --depth 1 origin "$MIGATE_REF"
    git -C "$MIGATE_INSTALL_DIR" reset --hard "origin/$MIGATE_REF"
  else
    log "cloning MiGate source into $MIGATE_INSTALL_DIR"
    rm -rf "$MIGATE_INSTALL_DIR"
    git clone --depth 1 --branch "$MIGATE_REF" "$MIGATE_REPO" "$MIGATE_INSTALL_DIR"
  fi
}

# ── Python package install ────────────────────────────────────────────────

install_python_package() {
  log 'installing MiGate Python package system-wide'
  if [ -L "$MIGATE_BIN" ]; then
    local link_target
    link_target="$(readlink -f "$MIGATE_BIN" 2>/dev/null || true)"
    if [ -z "$link_target" ] || [ "$link_target" = "$MIGATE_BIN" ]; then
      log "removing broken symlink at $MIGATE_BIN"
      rm -f "$MIGATE_BIN"
    fi
  fi
  python3 -m pip install --upgrade --force-reinstall "$MIGATE_INSTALL_DIR" \
    --break-system-packages --root-user-action=ignore
  local installed_bin
  installed_bin="$(command -v migate 2>/dev/null || true)"
  if [ -n "$installed_bin" ] && [ "$installed_bin" != "$MIGATE_BIN" ]; then
    ln -sfn "$installed_bin" "$MIGATE_BIN"
  fi
}

# ── setup & service management ────────────────────────────────────────────

run_setup() {
  log 'running MiGate setup'
  "$MIGATE_BIN" setup \
    --setup-config-target "$MIGATE_SETUP_CONFIG_TARGET" \
    --panel-host 0.0.0.0 \
    --panel-port "$MIGATE_PANEL_PORT" \
    --admin-user "$MIGATE_PANEL_USER" \
    --admin-password "$MIGATE_PANEL_PASSWORD" \
    --base-path "$MIGATE_PANEL_BASE_PATH" \
    --public-host "$MIGATE_PUBLIC_HOST" \
    --no-dry-run \
    --yes \
    --allow-system-changes
}

save_runtime_units() {
  log 'saving MiGate runtime service units'
  "$MIGATE_BIN" panel-service save --yes --allow-system-changes
  "$MIGATE_BIN" xray service save --yes --allow-system-changes
  "$MIGATE_BIN" proxy service save --yes --allow-system-changes
}

start_services() {
  log 'enabling MiGate services'
  systemctl daemon-reload
  systemctl enable --now migate-panel.service
  systemctl enable --now migate-xray.service
  systemctl enable --now migate-proxy.service
}

# ── verification ──────────────────────────────────────────────────────────

normalized_panel_path() {
  local p="${MIGATE_PANEL_BASE_PATH:-/}"
  [[ "$p" != /* ]] && p="/$p"
  p="${p%/}"
  printf '%s' "${p:-/}"
}

verify_webui() {
  local normalized_path url
  normalized_path="$(normalized_panel_path)"
  url="http://127.0.0.1:${MIGATE_PANEL_PORT}${normalized_path}/"
  log "verifying WebUI at $url"

  local attempt
  for attempt in $(seq 1 10); do
    if curl -fsS --max-time 5 "$url" >/dev/null 2>&1; then
      log 'WebUI is reachable locally'
      return 0
    fi
    sleep 2
  done

  printf 'MiGate WebUI did not become reachable at %s after 10 attempts\n' "$url" >&2
  install_failure_diagnostics
  exit 1
}

install_failure_diagnostics() {
  printf '\nMiGate install failure diagnostics:\n' >&2
  printf '  Panel service status:\n' >&2
  systemctl is-active migate-panel.service 2>/dev/null || true
  systemctl status migate-panel.service --no-pager -n 20 >&2 || true
  printf '  Recent panel logs:\n' >&2
  journalctl -u migate-panel.service -n 30 --no-pager >&2 || true
  printf '  Xray service status:\n' >&2
  systemctl is-active migate-xray.service 2>/dev/null || true
  systemctl status migate-xray.service --no-pager -n 20 >&2 || true
  printf '  Recent xray logs:\n' >&2
  journalctl -u migate-xray.service -n 30 --no-pager >&2 || true
}

# ── uninstall ─────────────────────────────────────────────────────────────

do_uninstall() {
  require_root

  log 'stopping MiGate processes'
  # Kill any running openvpn/migate processes
  pkill -f 'openvpn.*migate' 2>/dev/null || true
  pkill -f 'xray.*migate' 2>/dev/null || true

  log 'stopping MiGate services'
  systemctl disable --now migate-panel.service 2>/dev/null || true
  systemctl disable --now migate-xray.service 2>/dev/null || true
  systemctl disable --now migate-xray-tun.service 2>/dev/null || true
  systemctl disable --now migate-proxy.service 2>/dev/null || true

  log 'removing service unit files'
  rm -f /etc/systemd/system/migate-panel.service
  rm -f /etc/systemd/system/migate-xray.service
  rm -f /etc/systemd/system/migate-xray-tun.service
  rm -f /etc/systemd/system/migate-proxy.service
  systemctl daemon-reload

  log 'removing config and data'
  rm -rf /etc/migate
  rm -rf /var/lib/migate

  log 'removing logs'
  rm -rf /var/log/migate

  log 'removing binary'
  rm -f "$MIGATE_BIN"

  log 'removing pip package'
  python3 -m pip uninstall -y migate 2>/dev/null || true

  log 'removing source directory'
  if [ -n "$MIGATE_INSTALL_DIR" ] && [ "$MIGATE_INSTALL_DIR" != "/" ]; then
    rm -rf "$MIGATE_INSTALL_DIR"
  fi

  log 'uninstall complete'
}

# ── upgrade (re-install in place) ─────────────────────────────────────────

do_upgrade() {
  log 'upgrading MiGate (fetching latest source + reinstalling package)'
  validate_install_dir
  fetch_source
  install_python_package
  save_runtime_units
  systemctl daemon-reload
  systemctl restart migate-panel.service || true
  systemctl restart migate-xray.service || true
  systemctl restart migate-proxy.service || true
  verify_webui
  print_next_steps
}

# ── output ────────────────────────────────────────────────────────────────

print_next_steps() {
  local normalized_path panel_status xray_status proxy_status
  normalized_path="$(normalized_panel_path)"
  panel_status="$(systemctl is-active migate-panel.service 2>/dev/null || echo 'unknown')"
  xray_status="$(systemctl is-active migate-xray.service 2>/dev/null || echo 'unknown')"
  proxy_status="$(systemctl is-active migate-proxy.service 2>/dev/null || echo 'unknown')"

  printf '\nMiGate install finished.\n\n'
  printf 'Service status:\n'
  printf '  Panel: %s (%s)\n' "$panel_status" "migate-panel.service"
  printf '  Xray:  %s (%s)\n' "$xray_status" "migate-xray.service"
  printf '  Proxy: %s (%s)\n' "$proxy_status" "migate-proxy.service"
  printf '\n'
  printf 'Web UI: http://%s:%s%s/\n' "$MIGATE_PUBLIC_HOST" "$MIGATE_PANEL_PORT" "$normalized_path"
  printf 'Username: %s\n' "$MIGATE_PANEL_USER"
  printf 'Config saved to: %s\n\n' "$MIGATE_SETUP_CONFIG_TARGET"
  printf 'Next steps for xray-tun remote rollout:\n'
  printf '  migate remote acceptance --backend xray-tun\n'
}

# ── main ──────────────────────────────────────────────────────────────────

main() {
  # Handle --uninstall / --upgrade before any interactive prompts
  case "${1:-}" in
    --uninstall) do_uninstall; exit 0 ;;
    --upgrade)   do_upgrade;   exit 0 ;;
  esac

  require_root
  require_command git
  require_command python3
  require_command curl
  collect_panel_inputs
  ensure_panel_port_available
  install_os_packages
  require_command systemctl
  fetch_source
  install_python_package
  run_setup
  save_runtime_units
  start_services
  verify_webui
  print_next_steps
}

main "$@"
