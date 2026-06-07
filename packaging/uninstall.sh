#!/usr/bin/env bash
set -euo pipefail

MIGATE_SERVICE="migate"
SINGBOX_SERVICE="migate-singbox"
MIGATE_BINARY="/usr/local/bin/migate"
MIGATE_SERVICE_PATH="/etc/systemd/system/migate.service"
SINGBOX_SERVICE_PATH="/etc/systemd/system/migate-singbox.service"
MIGATE_CONFIG_DIR="/etc/migate"
MIGATE_INSTALL_DIR="/usr/local/migate"
SINGBOX_CONFIG_DIR="/etc/sing-box"
XRAY_CONFIG_LINK="/usr/local/etc/xray/config.json"
XRAY_DEFAULT_CONFIG_LINK="/usr/local/etc/xray/xray.json"

PURGE=0
ASSUME_YES=0

usage() {
  cat <<'EOF'
MiGate uninstaller

Usage:
  uninstall.sh [--purge] [--yes]

Options:
  --purge   Also remove MiGate config/data and MiGate-managed generated configs.
  --yes     Do not ask for confirmation when --purge is used.
  -h,--help Show this help.

Default uninstall keeps data:
  - /etc/migate/panel.json
  - /usr/local/migate/migate.db
  - /usr/local/migate/xray.json

Purge removes:
  - /etc/migate
  - /usr/local/migate
  - /etc/sing-box
  - /usr/local/etc/xray/config.json symlink/file

Third-party Xray itself is not removed.
EOF
}

require_root() {
  [ "$(id -u)" -eq 0 ] || { echo "MiGate uninstaller must run as root" >&2; exit 1; }
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --purge) PURGE=1 ;;
      --yes|-y) ASSUME_YES=1 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
    shift
  done
}

confirm_purge() {
  if [ "$PURGE" -ne 1 ] || [ "$ASSUME_YES" -eq 1 ]; then
    return
  fi
  echo "--purge will permanently remove MiGate configuration and data."
  read -r -p "Type 'PURGE' to continue: " answer
  if [ "$answer" != "PURGE" ]; then
    echo "Purge cancelled. Re-run without --purge for service-only uninstall."
    exit 1
  fi
}

remove_migate_xray_link() {
  # MiGate installer points Xray's default config to /usr/local/migate/xray.json.
  # Remove only that managed link/file path; do not uninstall third-party Xray.
  if [ -L "$XRAY_CONFIG_LINK" ]; then
    rm -f "$XRAY_CONFIG_LINK"
  elif [ "$PURGE" -eq 1 ] && [ -f "$XRAY_CONFIG_LINK" ]; then
    rm -f "$XRAY_CONFIG_LINK"
  fi
  if [ -L "$XRAY_DEFAULT_CONFIG_LINK" ]; then
    rm -f "$XRAY_DEFAULT_CONFIG_LINK"
  elif [ "$PURGE" -eq 1 ] && [ -f "$XRAY_DEFAULT_CONFIG_LINK" ]; then
    rm -f "$XRAY_DEFAULT_CONFIG_LINK"
  fi
}

main() {
  parse_args "$@"
  require_root
  confirm_purge

  echo "Stopping MiGate services..."
  systemctl stop migate 2>/dev/null || true
  systemctl disable migate 2>/dev/null || true
  rm -f /etc/systemd/system/migate.service
  systemctl stop migate-singbox 2>/dev/null || true
  systemctl disable migate-singbox 2>/dev/null || true
  rm -f /etc/systemd/system/migate-singbox.service

  echo "Removing MiGate binary..."
  rm -f /usr/local/bin/migate
  rm -f /usr/local/bin/mg

  if [ "$PURGE" -eq 1 ]; then
    echo "Purging MiGate config/data and managed runtime files..."
    rm -rf /etc/migate
    rm -rf /usr/local/migate
    rm -rf /etc/sing-box
    rm -f /usr/local/etc/xray/config.json
    rm -f /usr/local/etc/xray/xray.json
  else
    remove_migate_xray_link
    echo "Keeping MiGate config/data. Use --purge --yes to remove them."
  fi

  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed "$MIGATE_SERVICE" 2>/dev/null || true
  systemctl reset-failed "$SINGBOX_SERVICE" 2>/dev/null || true
  systemctl reset-failed 2>/dev/null || true

  echo "MiGate uninstalled."
}

main "$@"
