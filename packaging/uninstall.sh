#!/usr/bin/env bash
set -euo pipefail

MIGATE_SERVICE="migate"
XRAY_SERVICE="migate-xray"
SINGBOX_SERVICE="migate-sing-box"
MIGATE_BINARY="${MIGATE_BINARY:-/usr/local/bin/migate}"
MIGATE_LINK="${MIGATE_LINK:-/usr/local/bin/mg}"
INSTALLER_BINARY="${INSTALLER_BINARY:-/usr/local/bin/migate-install}"
UNINSTALLER_BINARY="${UNINSTALLER_BINARY:-/usr/local/bin/migate-uninstall}"
XRAY_BINARY="${XRAY_BINARY:-/usr/local/bin/xray}"
SINGBOX_BINARY="${SINGBOX_BINARY:-/usr/local/bin/sing-box}"
MIGATE_SERVICE_PATH="${MIGATE_SERVICE_PATH:-/etc/systemd/system/migate.service}"
XRAY_SERVICE_PATH="${XRAY_SERVICE_PATH:-/etc/systemd/system/migate-xray.service}"
SINGBOX_SERVICE_PATH="${SINGBOX_SERVICE_PATH:-/etc/systemd/system/migate-sing-box.service}"
MIGATE_CONFIG_DIR="${MIGATE_CONFIG_DIR:-/etc/migate}"
MIGATE_DATA_DIR="${MIGATE_DATA_DIR:-/var/lib/migate}"
MIGATE_LOG_DIR="${MIGATE_LOG_DIR:-/var/log/migate}"
MIGATE_RUN_DIR="${MIGATE_RUN_DIR:-/run/migate}"
MIGATE_MANAGED_DIR="${MIGATE_MANAGED_DIR:-${MIGATE_DATA_DIR}/managed}"

UNINSTALL_MODE=""
ASSUME_YES=0
DRY_RUN=0

usage() {
  cat <<'EOF'
MiGate uninstaller

Usage:
  uninstall.sh [--panel-only|--with-cores|--purge] [--yes] [--dry-run]

Options:
  --panel-only   Remove only the MiGate panel service and MiGate command binaries.
  --with-cores   Remove MiGate panel plus managed Xray/sing-box services and binaries; keep config/data/logs.
  --purge        Remove MiGate panel, managed cores, and all MiGate config/data/log/runtime files.
  --yes, -y      Do not ask for the uninstall mode; requires one mode option.
  --dry-run      Print planned commands without changing the system.
  -h,--help      Show this help.

Interactive uninstall asks which mode to use:
  1) 只卸载 MiGate 面板
  2) 卸载 MiGate 面板和核心
  3) 彻底卸载 MiGate 面板、核心和配置文件
EOF
}

require_root() {
  [ "$(id -u)" -eq 0 ] || [ "$DRY_RUN" -eq 1 ] || { echo "MiGate uninstaller must run as root" >&2; exit 1; }
}

run_cmd() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] %s\n' "$*"
    return 0
  fi
  "$@"
}

set_mode() {
  local mode="$1"
  if [ -n "$UNINSTALL_MODE" ] && [ "$UNINSTALL_MODE" != "$mode" ]; then
    echo "Conflicting uninstall modes: $UNINSTALL_MODE and $mode" >&2
    usage >&2
    exit 1
  fi
  UNINSTALL_MODE="$mode"
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --panel-only) set_mode panel-only ;;
      --with-cores|--cores) set_mode with-cores ;;
      --purge) set_mode purge ;;
      --yes|-y) ASSUME_YES=1 ;;
      --dry-run) DRY_RUN=1 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
    shift
  done
}

ask_uninstall_mode() {
  if [ -n "$UNINSTALL_MODE" ]; then
    return
  fi
  if [ "$ASSUME_YES" -eq 1 ]; then
    echo "--yes requires an explicit uninstall mode: --panel-only, --with-cores, or --purge" >&2
    usage >&2
    exit 1
  fi
  cat <<'EOF'
请选择卸载方式：
  1) 只卸载 MiGate 面板（保留 Xray/sing-box 核心和所有配置）
  2) 卸载 MiGate 面板和核心（保留配置、数据和日志）
  3) 彻底卸载 MiGate 面板、核心和配置文件
EOF
  local answer=""
  read -r -p "请输入 1/2/3: " answer
  case "$answer" in
    1) UNINSTALL_MODE="panel-only" ;;
    2) UNINSTALL_MODE="with-cores" ;;
    3) UNINSTALL_MODE="purge" ;;
    *) echo "卸载已取消：无效选择。" >&2; exit 1 ;;
  esac
}

mode_label() {
  case "$UNINSTALL_MODE" in
    panel-only) printf '只卸载 MiGate 面板' ;;
    with-cores) printf '卸载 MiGate 面板和核心' ;;
    purge) printf '彻底卸载 MiGate 面板、核心和配置文件' ;;
    *) printf '未知模式' ;;
  esac
}

stop_disable_remove_service() {
  local service="$1"
  local unit_path="$2"
  run_cmd systemctl stop "$service" 2>/dev/null || true
  run_cmd systemctl disable "$service" 2>/dev/null || true
  run_cmd rm -f "$unit_path"
}

remove_panel() {
  echo "Stopping MiGate panel service..."
  stop_disable_remove_service "$MIGATE_SERVICE" "$MIGATE_SERVICE_PATH"

  echo "Removing MiGate command binaries..."
  run_cmd rm -f "$MIGATE_BINARY"
  run_cmd rm -f "$MIGATE_LINK"
  run_cmd rm -f "$INSTALLER_BINARY"
  run_cmd rm -f "$UNINSTALLER_BINARY"
}

core_binary_is_migate_managed() {
  local name="$1"
  local binary="$2"
  local marker="${MIGATE_MANAGED_DIR}/${name}.binary"
  [ -f "$marker" ] || return 1
  grep -Fxq 'installed_by=MiGate' "$marker" || return 1
  grep -Fxq "binary=${binary}" "$marker" || return 1
}

remove_core_binary_if_migate_managed() {
  local label="$1"
  local name="$2"
  local binary="$3"
  local marker="${MIGATE_MANAGED_DIR}/${name}.binary"
  if core_binary_is_migate_managed "$name" "$binary"; then
    run_cmd rm -f "$binary"
    run_cmd rm -f "$marker"
  else
    echo "Keeping non-MiGate-managed ${label} binary: ${binary}"
  fi
}

legacy_xray_service_is_migate_managed() {
  local unit=""
  local old_config_marker="/usr/local/""migate/xray.json"
  unit="$(systemctl cat xray 2>/dev/null || true)"
  printf '%s\n' "$unit" | grep -Eq "MiGate|${old_config_marker}|/etc/migate/cores/xray\.json"
}

stop_disable_legacy_migate_xray_service() {
  if [ "$DRY_RUN" -eq 1 ] && [ "${MIGATE_ALLOW_LEGACY_XRAY_DRY_RUN:-0}" != "1" ]; then
    printf '[DRY-RUN] inspect xray.service for MiGate-managed legacy config\n'
    return 0
  fi
  if legacy_xray_service_is_migate_managed; then
    echo "Stopping legacy MiGate-managed xray.service..."
    run_cmd systemctl stop xray 2>/dev/null || true
    run_cmd systemctl disable xray 2>/dev/null || true
  fi
}

remove_cores() {
  echo "Stopping MiGate managed core services..."
  stop_disable_remove_service "$XRAY_SERVICE" "$XRAY_SERVICE_PATH"
  stop_disable_remove_service "$SINGBOX_SERVICE" "$SINGBOX_SERVICE_PATH"
  stop_disable_legacy_migate_xray_service
  echo "Removing MiGate managed core binaries..."
  remove_core_binary_if_migate_managed "Xray" "xray" "$XRAY_BINARY"
  remove_core_binary_if_migate_managed "sing-box" "sing-box" "$SINGBOX_BINARY"
}

remove_state() {
  echo "Purging MiGate config, data, logs, and runtime files..."
  run_cmd rm -rf "$MIGATE_CONFIG_DIR"
  run_cmd rm -rf "$MIGATE_DATA_DIR"
  run_cmd rm -rf "$MIGATE_LOG_DIR"
  run_cmd rm -rf "$MIGATE_RUN_DIR"
}

reload_systemd_state() {
  run_cmd systemctl daemon-reload 2>/dev/null || true
  run_cmd systemctl reset-failed "$MIGATE_SERVICE" 2>/dev/null || true
  if [ "$UNINSTALL_MODE" != "panel-only" ]; then
    run_cmd systemctl reset-failed "$XRAY_SERVICE" 2>/dev/null || true
    run_cmd systemctl reset-failed "$SINGBOX_SERVICE" 2>/dev/null || true
    if { [ "$DRY_RUN" -eq 0 ] || [ "${MIGATE_ALLOW_LEGACY_XRAY_DRY_RUN:-0}" = "1" ]; } && legacy_xray_service_is_migate_managed; then
      run_cmd systemctl reset-failed xray 2>/dev/null || true
    fi
  fi
  run_cmd systemctl reset-failed 2>/dev/null || true
}

main() {
  parse_args "$@"
  require_root
  ask_uninstall_mode

  echo "卸载模式: $(mode_label)"
  remove_panel

  if [ "$UNINSTALL_MODE" = "panel-only" ]; then
    echo "Keeping MiGate cores and config/data/logs."
  else
    remove_cores
    if [ "$UNINSTALL_MODE" = "purge" ]; then
      remove_state
    else
      echo "Keeping MiGate config/data/logs."
    fi
  fi

  reload_systemd_state
  echo "MiGate uninstalled."
}

main "$@"
