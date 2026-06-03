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

has_tty() {
  [ -t 0 ] || [ -e /dev/tty ]
}

prompt_with_default() {
  local prompt="$1" default_value="$2" value=""
  if has_tty; then
    read -r -p "$prompt [$default_value]: " value </dev/tty 2>/dev/null || read -r -p "$prompt [$default_value]: " value
  else
    # Non-interactive: use default
    log "(non-interactive) $prompt = $default_value"
    value="$default_value"
  fi
  printf '%s' "${value:-$default_value}"
}

prompt_secret() {
  local prompt="$1" value=""
  if ! has_tty; then
    die "No TTY available and MIGATE_PANEL_PASSWORD is not set. Export MIGATE_PANEL_PASSWORD before running."
  fi
  while true; do
    read -r -s -p "$prompt: " value </dev/tty 2>/dev/null || read -r -s -p "$prompt: " value
    printf '\n' >/dev/tty 2>/dev/null || true
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

stop_conflicting_services() {
  # Stop official xray.service if it exists (MiGate manages its own migate-xray.service)
  if systemctl is-active xray.service >/dev/null 2>&1; then
    log 'stopping conflicting xray.service (MiGate uses migate-xray.service)'
    systemctl stop xray.service 2>/dev/null || true
    systemctl disable xray.service 2>/dev/null || true
  fi

  # Stop Caddy or other webservers that may bind :443
  local svc
  for svc in caddy nginx apache2 httpd; do
    if systemctl is-active "${svc}.service" >/dev/null 2>&1; then
      log "stopping conflicting ${svc}.service (may bind ports needed by xray)"
      systemctl stop "${svc}.service" 2>/dev/null || true
      systemctl disable "${svc}.service" 2>/dev/null || true
    fi
  done
}

# ── low-memory helpers ───────────────────────────────────────────────────

get_total_ram_mb() {
  awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 512
}

ensure_swap_if_low_ram() {
  local ram_mb
  ram_mb="$(get_total_ram_mb)"

  # Already have swap?
  local swap_total
  swap_total="$(awk '/SwapTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  if [ "$swap_total" -gt 0 ]; then
    log "swap already active (${swap_total}kB)"
    return 0
  fi

  # Create swap for low-memory machines (< 1.5GB RAM)
  if [ "$ram_mb" -lt 1536 ]; then
    local swap_size=512
    [ "$ram_mb" -lt 768 ] && swap_size=1024
    log "low RAM detected (${ram_mb}MB) — creating ${swap_size}MB swap"
    if [ ! -f /swapfile ]; then
      fallocate -l "${swap_size}M" /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count="$swap_size" status=none
      chmod 600 /swapfile
      mkswap /swapfile >/dev/null 2>&1
      swapon /swapfile
    fi
    log "swap active: $(swapon --show --noheadings | awk '{print $3, $4}')"
  fi
}

cleanup_swap_if_temp() {
  # Only remove swap we created (file-based, not partition)
  if [ -f /swapfile ] && swapon --show --noheadings | grep -q '/swapfile'; then
    log 'cleaning up temporary swap'
    swapoff /swapfile 2>/dev/null || true
    rm -f /swapfile
  fi
}

install_uv() {
  # uv is a fast, low-memory Python package installer (10-100x faster than pip)
  if command -v uv >/dev/null 2>&1; then
    log "uv already installed ($(uv --version 2>/dev/null || echo 'unknown'))"
    return 0
  fi
  log 'installing uv (fast Python package manager)'
  if curl -LsSf https://astral.sh/uv/install.sh | sh 2>&1 | tail -2; then
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
  fi
  if command -v uv >/dev/null 2>&1; then
    log "uv installed: $(uv --version)"
  else
    log 'uv not available, will use pip'
  fi
}

# ── OS packages ───────────────────────────────────────────────────────────

install_os_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
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
  elif command -v yum >/dev/null 2>&1; then
    log 'detected yum-based system'
    yum install -y -q curl git python3 iproute openvpn rsync unzip ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    log 'detected dnf-based system'
    dnf install -y -q curl git python3 iproute openvpn rsync unzip ca-certificates
  else
    log 'unknown package manager; skipping OS package installation'
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
  log 'installing MiGate Python package'
  if [ -L "$MIGATE_BIN" ]; then
    local link_target
    link_target="$(readlink -f "$MIGATE_BIN" 2>/dev/null || true)"
    if [ -z "$link_target" ] || [ "$link_target" = "$MIGATE_BIN" ]; then
      log "removing broken symlink at $MIGATE_BIN"
      rm -f "$MIGATE_BIN"
    fi
  fi

  # Prefer uv (fast, low memory), fall back to pip
  if command -v uv >/dev/null 2>&1; then
    log 'using uv for package installation'
    uv pip install --system --upgrade "$MIGATE_INSTALL_DIR" 2>&1 | tail -3
  else
    log 'using pip for package installation'
    python3 -m pip install --upgrade "$MIGATE_INSTALL_DIR" \
      --only-binary :all: --break-system-packages --root-user-action=ignore --no-cache-dir 2>&1 | tail -3 || {
      log 'binary-only install failed, retrying with source build...'
      python3 -m pip install --upgrade "$MIGATE_INSTALL_DIR" \
        --break-system-packages --root-user-action=ignore --no-cache-dir 2>&1 | tail -3
    }
  fi

  local installed_bin
  installed_bin="$(command -v migate 2>/dev/null || true)"
  if [ -n "$installed_bin" ] && [ "$installed_bin" != "$MIGATE_BIN" ]; then
    ln -sfn "$installed_bin" "$MIGATE_BIN"
  fi
  log "migate binary: $(command -v migate || echo 'NOT FOUND')"
}

# ── setup & service management ────────────────────────────────────────────

run_setup() {
  log 'running MiGate setup'
  local setup_output
  setup_output=$("$MIGATE_BIN" setup \
    --setup-config-target "$MIGATE_SETUP_CONFIG_TARGET" \
    --panel-host 0.0.0.0 \
    --panel-port "$MIGATE_PANEL_PORT" \
    --admin-user "$MIGATE_PANEL_USER" \
    --admin-password "$MIGATE_PANEL_PASSWORD" \
    --base-path "$MIGATE_PANEL_BASE_PATH" \
    --public-host "$MIGATE_PUBLIC_HOST" \
    --no-dry-run \
    --yes \
    --allow-system-changes 2>&1) || {
    log "setup output (may contain non-fatal warnings):"
    printf '%s\n' "$setup_output" | head -40
    # Check if critical config was saved even if service start failed
    if [ -f "$MIGATE_SETUP_CONFIG_TARGET" ]; then
      log "panel config saved at $MIGATE_SETUP_CONFIG_TARGET (service start may have failed — will retry)"
    else
      die "setup failed and no panel config was saved"
    fi
  }
}

save_runtime_units() {
  log 'saving MiGate runtime service units'
  "$MIGATE_BIN" panel-service save --yes --allow-system-changes 2>&1 | tail -2
  "$MIGATE_BIN" xray service save --yes --allow-system-changes 2>&1 | tail -2
  "$MIGATE_BIN" proxy service save --yes --allow-system-changes 2>&1 | tail -2
}

start_services() {
  log 'enabling and starting MiGate services'
  systemctl daemon-reload

  # Start xray first (panel depends on it)
  systemctl enable --now migate-xray.service 2>/dev/null || {
    log 'WARNING: migate-xray.service failed to start, checking...'
    journalctl -u migate-xray.service -n 5 --no-pager 2>/dev/null || true
  }

  sleep 1

  # Verify xray is actually running before starting panel
  if systemctl is-active migate-xray.service >/dev/null 2>&1; then
    log 'migate-xray.service is active ✓'
  else
    log 'WARNING: migate-xray.service is not active — panel will start but xray features will be degraded'
  fi

  systemctl enable --now migate-panel.service 2>/dev/null || {
    log 'WARNING: migate-panel.service failed to start'
    journalctl -u migate-panel.service -n 5 --no-pager 2>/dev/null || true
  }

  # Proxy service is optional (only needed for egress tunnel mode)
  # Enable it but don't fail if it can't start
  if systemctl enable --now migate-proxy.service 2>/dev/null; then
    log 'migate-proxy.service is active ✓'
  else
    log 'migate-proxy.service inactive (optional — only needed for egress tunnel mode)'
  fi
}

# ── verification ──────────────────────────────────────────────────────────

normalized_panel_path() {
  local p="${MIGATE_PANEL_BASE_PATH:-/}"
  [[ "$p" != /* ]] && p="/$p"
  p="${p%/}"
  # "/" is the default — return empty to avoid double-slash in URLs
  [ "$p" = "/" ] && p=""
  printf '%s' "$p"
}

verify_webui() {
  local normalized_path url
  normalized_path="$(normalized_panel_path)"
  url="http://127.0.0.1:${MIGATE_PANEL_PORT}${normalized_path}/spa/"
  log "verifying WebUI at $url"

  local attempt
  for attempt in $(seq 1 10); do
    if curl -fsS --max-time 5 "$url" >/dev/null 2>&1; then
      log 'WebUI is reachable locally ✓'
      return 0
    fi
    sleep 2
  done

  printf 'MiGate WebUI did not become reachable at %s after 10 attempts\n' "$url" >&2
  install_failure_diagnostics
  return 1
}

install_failure_diagnostics() {
  printf '\n[migate-install] Failure diagnostics:\n' >&2
  printf '  Panel service: ' >&2
  systemctl is-active migate-panel.service 2>/dev/null >&2 || echo 'inactive' >&2
  systemctl status migate-panel.service --no-pager -n 10 2>/dev/null >&2 || true
  printf '  Xray service: ' >&2
  systemctl is-active migate-xray.service 2>/dev/null >&2 || echo 'inactive' >&2
  systemctl status migate-xray.service --no-pager -n 10 2>/dev/null >&2 || true
  printf '  Recent xray logs:\n' >&2
  journalctl -u migate-xray.service -n 10 --no-pager 2>/dev/null >&2 || true
}

# ── uninstall ─────────────────────────────────────────────────────────────

do_uninstall() {
  require_root

  # Confirm unless --yes
  if [ "${2:-}" != "--yes" ] && has_tty; then
    local answer=""
    printf 'This will remove MiGate, all configs, and services.\n'
    read -r -p "Continue? [y/N]: " answer </dev/tty 2>/dev/null || answer="y"
    [[ "$answer" =~ ^[Yy]$ ]] || { log 'aborted'; exit 0; }
  fi

  log 'stopping MiGate processes'
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

  cleanup_swap_if_temp

  log 'uninstall complete ✓'
}

# ── upgrade (re-install in place) ─────────────────────────────────────────

do_upgrade() {
  log 'upgrading MiGate (fetching latest source + reinstalling package)'
  validate_install_dir
  stop_conflicting_services
  ensure_swap_if_low_ram
  fetch_source
  install_python_package
  save_runtime_units
  systemctl daemon-reload
  systemctl restart migate-xray.service 2>/dev/null || true
  sleep 1
  systemctl restart migate-panel.service 2>/dev/null || true
  systemctl restart migate-proxy.service 2>/dev/null || true
  cleanup_swap_if_temp
  verify_webui || true
  print_next_steps
}

# ── output ────────────────────────────────────────────────────────────────

print_next_steps() {
  local normalized_path panel_status xray_status proxy_status
  normalized_path="$(normalized_panel_path)"
  panel_status="$(systemctl is-active migate-panel.service 2>/dev/null || echo 'unknown')"
  xray_status="$(systemctl is-active migate-xray.service 2>/dev/null || echo 'unknown')"
  proxy_status="$(systemctl is-active migate-proxy.service 2>/dev/null || echo 'unknown')"

  printf '\n'
  printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
  printf '  MiGate Install Complete ✓\n'
  printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
  printf '\n'
  printf '  Services:\n'
  printf '    Panel  → %-10s  (migate-panel.service)\n' "$panel_status"
  printf '    Xray   → %-10s  (migate-xray.service)\n' "$xray_status"
  printf '    Proxy  → %-10s  (migate-proxy.service)\n' "$proxy_status"
  printf '\n'
  printf '  Web UI:   http://%s:%s%s/spa/\n' "$MIGATE_PUBLIC_HOST" "$MIGATE_PANEL_PORT" "$normalized_path"
  printf '  Username: %s\n' "$MIGATE_PANEL_USER"
  printf '  Config:   %s\n' "$MIGATE_SETUP_CONFIG_TARGET"
  printf '\n'
  printf '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
  printf '\n'
  printf 'Uninstall:  bash <(curl -Ls %s) --uninstall\n' "$MIGATE_REPO/raw/$MIGATE_REF/scripts/install.sh"
  printf 'Upgrade:    bash <(curl -Ls %s) --upgrade\n' "$MIGATE_REPO/raw/$MIGATE_REF/scripts/install.sh"
  printf '\n'
}

# ── main ──────────────────────────────────────────────────────────────────

main() {
  # Handle --uninstall / --upgrade before any interactive prompts
  case "${1:-}" in
    --uninstall) do_uninstall "$@"; exit 0 ;;
    --upgrade)   do_upgrade;   exit 0 ;;
  esac

  require_root

  local ram_mb
  ram_mb="$(get_total_ram_mb)"
  log "system: $(uname -srm) | RAM: ${ram_mb}MB | Disk: $(df -h / | awk 'NR==2{print $4}') free"

  collect_panel_inputs
  ensure_panel_port_available
  stop_conflicting_services
  ensure_swap_if_low_ram
  install_os_packages
  install_uv

  # Now verify required commands exist (after OS packages installed)
  require_command git
  require_command python3
  require_command curl
  require_command systemctl
  fetch_source
  install_python_package
  run_setup
  save_runtime_units
  start_services
  cleanup_swap_if_temp
  verify_webui || true   # non-fatal: diagnostics already printed
  print_next_steps
}

main "$@"
