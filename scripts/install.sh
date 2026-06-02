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

log() {
  printf '[migate-install] %s\n' "$*"
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    printf 'MiGate installer must run as root.\n' >&2
    exit 1
  fi
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

prompt_with_default() {
  local prompt="$1"
  local default_value="$2"
  local value=""
  read -r -p "$prompt [$default_value]: " value
  if [ -z "$value" ]; then
    value="$default_value"
  fi
  printf '%s' "$value"
}

prompt_secret() {
  local prompt="$1"
  local value=""
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
  if [ -n "$MIGATE_PUBLIC_HOST" ]; then
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

collect_panel_inputs() {
  if [ -z "$MIGATE_PANEL_PORT" ]; then
    MIGATE_PANEL_PORT="$(prompt_with_default 'Custom panel port' '8080')"
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

ensure_panel_port_available() {
  require_command ss
  if ss -ltn | awk '{print $4}' | grep -Eq "(^|:)${MIGATE_PANEL_PORT}$"; then
    printf 'MiGate panel port %s is already in use. Choose another port or stop the existing service.\n' "$MIGATE_PANEL_PORT" >&2
    exit 1
  fi
}

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

fetch_source() {
  if [ -d "$MIGATE_INSTALL_DIR/.git" ]; then
    log "updating MiGate source in $MIGATE_INSTALL_DIR"
    git -C "$MIGATE_INSTALL_DIR" fetch --depth 1 origin "$MIGATE_REF"
    git -C "$MIGATE_INSTALL_DIR" checkout --force FETCH_HEAD
  else
    log "cloning MiGate source into $MIGATE_INSTALL_DIR"
    rm -rf "$MIGATE_INSTALL_DIR"
    git clone --depth 1 --branch "$MIGATE_REF" "$MIGATE_REPO" "$MIGATE_INSTALL_DIR"
  fi
}

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
  python3 -m pip install --upgrade pip --break-system-packages --root-user-action=ignore
  python3 -m pip install --upgrade --force-reinstall "$MIGATE_INSTALL_DIR" --break-system-packages --root-user-action=ignore
  local installed_bin
  installed_bin="$(command -v migate 2>/dev/null || true)"
  if [ -n "$installed_bin" ] && [ "$installed_bin" != "$MIGATE_BIN" ]; then
    ln -sfn "$installed_bin" "$MIGATE_BIN"
  fi
}

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

start_panel_service() {
  log 'enabling MiGate panel service'
  systemctl daemon-reload
  systemctl enable --now migate-panel.service
  systemctl enable --now migate-xray.service
}

normalized_panel_path() {
  local normalized_path="$MIGATE_PANEL_BASE_PATH"
  if [ -z "$normalized_path" ]; then
    normalized_path='/'
  fi
  if [[ "$normalized_path" != /* ]]; then
    normalized_path="/$normalized_path"
  fi
  normalized_path="${normalized_path%/}"
  if [ -z "$normalized_path" ]; then
    normalized_path='/'
  fi
  printf '%s' "$normalized_path"
}

verify_webui() {
  local normalized_path
  normalized_path="$(normalized_panel_path)"
  local local_url="http://127.0.0.1:${MIGATE_PANEL_PORT}${normalized_path}/"
  log "verifying WebUI at $local_url"

  local attempt
  for attempt in 1 2 3 4 5; do
    if curl -fsS --max-time 5 "$local_url" >/dev/null; then
      log 'WebUI is reachable locally'
      return 0
    fi
    sleep 1
  done

  printf 'MiGate WebUI did not become reachable at %s\n' "$local_url" >&2
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

print_next_steps() {
  local normalized_path
  normalized_path="$(normalized_panel_path)"

  local panel_status xray_status
  panel_status="$(systemctl is-active migate-panel.service 2>/dev/null || echo 'unknown')"
  xray_status="$(systemctl is-active migate-xray.service 2>/dev/null || echo 'unknown')"

  printf '\nMiGate install finished.\n\n'
  printf 'Service status:\n'
  printf '  Panel: %s (%s)\n' "$panel_status" "migate-panel.service"
  printf '  Xray:  %s (%s)\n' "$xray_status" "migate-xray.service"
  printf '\n'
  printf 'Web UI: http://%s:%s%s/\n' "$MIGATE_PUBLIC_HOST" "$MIGATE_PANEL_PORT" "$normalized_path"
  printf 'Username: %s\n' "$MIGATE_PANEL_USER"
  printf 'Config saved to: %s\n\n' "$MIGATE_SETUP_CONFIG_TARGET"
  printf 'Next steps for xray-tun remote rollout:\n'
  printf '  migate remote acceptance --backend xray-tun\n'
}

main() {
  require_root
  require_command git
  require_command python3
  require_command curl
  collect_panel_inputs
  ensure_panel_port_available
  install_os_packages
  require_command git
  require_command python3
  require_command systemctl
  fetch_source
  install_python_package
  run_setup
  save_runtime_units
  start_panel_service
  verify_webui
  print_next_steps
}

main "$@"
