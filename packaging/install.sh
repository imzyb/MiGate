#!/usr/bin/env bash
set -euo pipefail

REPO="${MIGATE_REPO:-imzyb/MiGate}"
VERSION="${MIGATE_VERSION:-latest}"
REQUESTED_VERSION="$VERSION"
INSTALL_DIR="${MIGATE_DATA_DIR:-${MIGATE_INSTALL_DIR:-/var/lib/migate}}"
DATA_DIR="$INSTALL_DIR"
VERSIONS_PATH="${MIGATE_VERSIONS_PATH:-/var/lib/migate/versions.json}"
UPDATE_STATUS_PATH="${MIGATE_UPDATE_STATUS_PATH:-/var/lib/migate/update-status.json}"
CORE_CONFIG_DIR="${MIGATE_CORE_CONFIG_DIR:-/etc/migate/cores}"
XRAY_CONFIG_PATH="${MIGATE_XRAY_CONFIG_PATH:-/etc/migate/cores/xray.json}"
SINGBOX_CONFIG_PATH="${MIGATE_SINGBOX_CONFIG_PATH:-/etc/migate/cores/sing-box.json}"
BACKUP_DIR="${MIGATE_BACKUP_DIR:-/var/lib/migate/backups}"
LOG_DIR="${MIGATE_LOG_DIR:-/var/log/migate}"
RUN_DIR="${MIGATE_RUN_DIR:-/run/migate}"
INSTALL_LOCK="${MIGATE_INSTALL_LOCK:-/run/migate/install.lock}"
SYSTEMD_RUNTIME_DIR="${MIGATE_SYSTEMD_RUNTIME_DIR:-/run/systemd/system}"
CONFIG_DIR="${MIGATE_CONFIG_DIR:-/etc/migate}"
CONFIG_PATH="${MIGATE_CONFIG_PATH:-/etc/migate/panel.json}"
SERVICE_PATH="${MIGATE_SERVICE_PATH:-/etc/systemd/system/migate.service}"
MIGATE_BIN="${MIGATE_BIN:-/usr/local/bin/migate}"
MIGATE_LINK="${MIGATE_LINK:-/usr/local/bin/mg}"
INSTALLER_BIN="${INSTALLER_BIN:-/usr/local/bin/migate-install}"
UNINSTALLER_BIN="${UNINSTALLER_BIN:-/usr/local/bin/migate-uninstall}"
XRAY_SERVICE_PATH="${XRAY_SERVICE_PATH:-/etc/systemd/system/migate-xray.service}"
SINGBOX_SERVICE_PATH="${SINGBOX_SERVICE_PATH:-/etc/systemd/system/migate-sing-box.service}"
XRAY_SHARE_DIR="${MIGATE_XRAY_SHARE_DIR:-/usr/local/share/xray}"
JOURNALD_CONF_DIR="${JOURNALD_CONF_DIR:-/etc/systemd/journald.conf.d}"
JOURNALD_MIGATE_CONF="${JOURNALD_MIGATE_CONF:-${JOURNALD_CONF_DIR}/migate.conf}"
LOGROTATE_CONF_DIR="${LOGROTATE_CONF_DIR:-/etc/logrotate.d}"
LOGROTATE_MIGATE_CONF="${LOGROTATE_MIGATE_CONF:-${LOGROTATE_CONF_DIR}/migate}"

ACTION="auto"
ASSUME_YES=0
DRY_RUN=0
REGENERATE_CONFIG=0
INSTALL_XRAY=0
INSTALL_SINGBOX=0
EXPLICIT_INSTALL_XRAY=0
EXPLICIT_INSTALL_SINGBOX=0
SKIP_CORE_PROMPTS=0
EXTRA_ARGS_COUNT=0
XRAY_FOUND=0
SINGBOX_FOUND=0
CORE_PROMPTS_CONFIRMED=0

OS_NAME="unknown"
ARCH="unknown"
SYSTEMD_AVAILABLE=0
IS_ROOT=0
PANEL_PORT=9999
PANEL_USERNAME="admin"
PANEL_PASSWORD=""
WEB_BASE_PATH="/panel"
PANEL_BIND_HOST="${MIGATE_PANEL_BIND_HOST:-0.0.0.0}"
GENERATED_PASSWORD=0

on_error() {
  local code="$?"
  section "安装未完成"
  log_error "脚本在执行过程中失败，退出码：${code}"
  log_info "如 MiGate 服务启动失败，请查看：journalctl -u migate -n 80 --no-pager"
  log_info "如下载失败，请检查服务器网络、DNS 和 GitHub 访问。"
  log_info "可以使用 --dry-run 预览安装步骤。"
  exit "$code"
}
trap on_error ERR

line() { printf '%s\n' '----------------------------------------------------------------'; }
log_info() { printf '  [INFO] %s\n' "$*"; }
log_ok() { printf '  [ OK ] %s\n' "$*"; }
log_warn() { printf '  [WARN] %s\n' "$*"; }
log_error() { printf '  [ERR ] %s\n' "$*" >&2; }

with_install_lock() {
  local code=0
  local lock_dir=""
  if [ "$DRY_RUN" -eq 1 ] && [ "$INSTALL_LOCK" = "/run/migate/install.lock" ]; then
    INSTALL_LOCK="${TMPDIR:-/tmp}/migate-install.$$.lock"
  fi
  mkdir -p "$(dirname "$INSTALL_LOCK")"
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$INSTALL_LOCK"
    if ! flock -n 9; then
      log_error "另一个安装/修复流程正在运行：$INSTALL_LOCK"
      exit 1
    fi
    set +e
    ( set -e; "$@" )
    code="$?"
    set -e
    flock -u 9 || true
    return "$code"
  fi

  lock_dir="${INSTALL_LOCK}.d"
  if ! mkdir "$lock_dir" 2>/dev/null; then
    log_error "另一个安装/修复流程正在运行：$INSTALL_LOCK"
    exit 1
  fi
  set +e
  ( set -e; "$@" )
  code="$?"
  set -e
  rmdir "$lock_dir" 2>/dev/null || true
  return "$code"
}

section() {
  printf '\n'
  line
  printf '%s\n' "$*"
  line
}
kv() {
  printf '  %-22s %s\n' "$1:" "$2"
}
prompt_line() {
  printf '  ? %s' "$1"
}
confirm_yes() {
  local prompt="$1"
  local answer
  prompt_line "${prompt} [Y/n]: "
  read -r answer
  case "$answer" in n|N|no|NO) return 1 ;; *) return 0 ;; esac
}
confirm_no() {
  local prompt="$1"
  local answer
  prompt_line "${prompt} [y/N]: "
  read -r answer
  case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}
is_valid_port() {
  local port="$1"
  case "$port" in ''|*[!0-9]*) return 1 ;; esac
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}
print_banner() {
  section "MiGate 一键安装器"
  kv "仓库" "$REPO"
  kv "版本" "$VERSION"
  kv "数据目录" "$DATA_DIR"
  kv "配置文件" "$CONFIG_PATH"
  if [ "$DRY_RUN" -eq 1 ]; then
    log_warn "当前为 dry-run 模式，只打印计划执行的操作。"
  fi
}

usage() {
  cat <<'EOF'
MiGate installer

Usage:
  install.sh [--install|--upgrade|--uninstall|--repair-service|--install-xray|--install-singbox] [options]

Options:
  --yes, -y             Run non-interactively for MiGate operations.
  --install            Install MiGate. If already installed, upgrade/reinstall binary and keep config.
  --upgrade, --update   Upgrade MiGate and keep existing config.
  --reinstall          Reinstall MiGate binary and keep existing config.
  --fresh-config       Regenerate panel.json during install/reinstall.
  --uninstall          Run MiGate uninstaller. Keeps config/data unless --purge is passed after --.
  --repair-service     Rewrite/repair migate.service only.
  --install-xray       Install/repair Xray only, or include Xray when used with --install.
  --install-singbox    Install/repair sing-box only, or include sing-box when used with --install.
  --dry-run            Print planned commands without changing the system.
  --check              Check latest MiGate release only.
  --version vX.Y.Z     Install or upgrade to a specific release tag.
  -h, --help           Show this help.

Environment:
  MIGATE_VERSION=vX.Y.Z
  MIGATE_REPO=owner/repo
  MIGATE_PANEL_BIND_HOST=0.0.0.0
  SINGBOX_VERSION=1.13.13
EOF
}

run_cmd() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] %s\n' "$*"
    return 0
  fi
  "$@"
}

enable_systemd_service() {
  local service="$1"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] systemctl enable %s\n' "$service"
    return 0
  fi
  if systemctl enable "$service" >/dev/null; then
    log_ok "${service}.service 已启用"
    return 0
  fi
  log_error "${service}.service 启用失败"
  return 1
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

detect_os() {
  case "$(uname -s 2>/dev/null || true)" in
    Linux) OS_NAME="linux" ;;
    Darwin) OS_NAME="macos" ;;
    *) OS_NAME="other" ;;
  esac
}

detect_arch() {
  case "$(uname -m 2>/dev/null || true)" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) ARCH="unsupported" ;;
  esac
}

arch() {
  detect_arch
  if [ "$ARCH" = "unsupported" ]; then
    log_error "unsupported architecture: $(uname -m). MiGate release assets support linux/amd64 and linux/arm64."
    exit 1
  fi
  printf '%s' "$ARCH"
}

detect_systemd() {
  if command_exists systemctl && [ -d "$SYSTEMD_RUNTIME_DIR" ]; then
    SYSTEMD_AVAILABLE=1
  else
    SYSTEMD_AVAILABLE=0
  fi
}

detect_root() {
  if [ "$(id -u)" -eq 0 ]; then
    IS_ROOT=1
  else
    IS_ROOT=0
  fi
}

require_root() {
  detect_root
  if [ "$IS_ROOT" -ne 1 ] && [ "$DRY_RUN" -ne 1 ]; then
    log_error "MiGate installer must run as root. Re-run with sudo or root."
    exit 1
  fi
}

require_linux_for_release() {
  detect_os
  if [ "$OS_NAME" != "linux" ] && [ "$DRY_RUN" -ne 1 ]; then
    log_error "One-click release install supports Linux VPS only. macOS can run MiGate manually with a local build."
    exit 1
  fi
}

dependency_status() {
  local missing=0
  for dep in curl tar openssl; do
    if command_exists "$dep"; then
      log_ok "依赖 ${dep}: 已找到 ($(command -v "$dep"))"
    else
      log_warn "依赖 ${dep}: 未找到"
      missing=1
    fi
  done
  if command_exists sha256sum || command_exists shasum; then
    log_ok "依赖 checksum: 已找到"
  else
    log_warn "依赖 checksum: 未找到 sha256sum/shasum"
    missing=1
  fi
  if command_exists wget; then
    log_ok "可选依赖 wget: 已找到 ($(command -v wget))"
  else
    log_info "可选依赖 wget: 未找到"
  fi
  if command_exists unzip; then
    log_ok "依赖 unzip: 已找到 ($(command -v unzip))"
  else
    log_warn "依赖 unzip: 未找到"
    missing=1
  fi
  return "$missing"
}

require_dependencies() {
  local missing=0
  for dep in curl tar unzip; do
    if ! command_exists "$dep"; then
      log_error "required dependency missing: ${dep}"
      missing=1
    fi
  done
  if ! command_exists sha256sum && ! command_exists shasum; then
    log_error "required dependency missing: sha256sum or shasum"
    missing=1
  fi
  if [ "$missing" -ne 0 ] && [ "$DRY_RUN" -ne 1 ]; then
    exit 1
  fi
}

ensure_migate_user_group() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] ensure group/user migate:migate\n'
    return 0
  fi
  if ! getent group migate >/dev/null 2>&1; then
    groupadd --system migate
  fi
  if ! id -u migate >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA_DIR" --no-create-home --gid migate --shell /usr/sbin/nologin migate
  fi
}

ensure_runtime_dirs() {
  run_cmd mkdir -p "$CONFIG_DIR" "$CORE_CONFIG_DIR" "$DATA_DIR" "$BACKUP_DIR" "$LOG_DIR" "$RUN_DIR" "$(dirname "$MIGATE_BIN")" "$(dirname "$INSTALLER_BIN")" "$(dirname "$UNINSTALLER_BIN")" "$XRAY_SHARE_DIR" "$(dirname "$SERVICE_PATH")"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] set runtime ownership and permissions under /etc/migate, /var/lib/migate, /var/log/migate, /run/migate\n'
    return 0
  fi
  chown root:migate "$CONFIG_DIR" "$CORE_CONFIG_DIR"
  chmod 0750 "$CONFIG_DIR" "$CORE_CONFIG_DIR"
  chown root:migate "$DATA_DIR" "$BACKUP_DIR" "$LOG_DIR" "$RUN_DIR"
  chmod 0770 "$DATA_DIR" "$BACKUP_DIR" "$LOG_DIR" "$RUN_DIR"
}

set_core_config_permissions() {
  local path="$1"
  chown root:migate "$path"
  chmod 0640 "$path"
}

atomic_write_file() {
  local path="$1"
  local mode="$2"
  local owner="${3:-}"
  local dir
  local base
  local tmp
  dir="$(dirname "$path")"
  base="$(basename "$path")"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] atomic write %q via %q with mode %s%s\n' "$path" "${dir}/.${base}.tmp.XXXXXX" "$mode" "${owner:+ owner ${owner}}"
    return 0
  fi
  mkdir -p "$dir"
  tmp="$(mktemp "${dir}/.${base}.tmp.XXXXXX")"
  if ! cat > "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if [ -n "$owner" ]; then
    chown "$owner" "$tmp"
  fi
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$path"
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

sanitize_update_health_check() {
  local max_len=2000
  (
    LC_ALL=C
    export LC_ALL
    printf '%s' "$1" |
      tr '\r\t\n' '   ' |
      tr -cd ' -~' |
      sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//' |
      cut -b 1-"$max_len"
  )
}

record_health_check() {
  LAST_HEALTH_CHECK="$(sanitize_update_health_check "$1")"
  [ -n "${MIGATE_HEALTH_RESULT_PATH:-}" ] && printf '%s\n' "$LAST_HEALTH_CHECK" > "$MIGATE_HEALTH_RESULT_PATH"
}

generate_password() {
  if command_exists openssl; then
    openssl rand -base64 24 | tr -d '\n'
  else
    LC_ALL=C tr -dc 'A-Za-z0-9_@%+=:,.-' < /dev/urandom | head -c 32
  fi
}

normalize_web_base_path() {
  local path="$1"
  if [ -z "$path" ] || [ "$path" = "/" ]; then
    printf ''
    return
  fi
  path="/${path#/}"
  path="${path%/}"
  printf '%s' "$path"
}

web_url_path() {
  local path
  path="$(normalize_web_base_path "${1:-}")"
  if [ -z "$path" ]; then
    printf '/'
    return
  fi
  printf '%s' "$path"
}

json_number_value() {
  local key="$1"
  local file="$2"
  sed -nE "s/.*\"${key}\"[[:space:]]*:[[:space:]]*([0-9]+).*/\\1/p" "$file" 2>/dev/null | head -1
}

json_string_value() {
  local key="$1"
  local file="$2"
  sed -nE "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\\1/p" "$file" 2>/dev/null | head -1
}

read_existing_config_defaults() {
  if [ ! -f "$CONFIG_PATH" ]; then
    return
  fi
  PANEL_PORT="$(json_number_value panel_port "$CONFIG_PATH")"
  PANEL_PORT="${PANEL_PORT:-9999}"
  PANEL_USERNAME="$(json_string_value panel_username "$CONFIG_PATH")"
  PANEL_USERNAME="${PANEL_USERNAME:-admin}"
  WEB_BASE_PATH="$(json_string_value web_base_path "$CONFIG_PATH")"
  WEB_BASE_PATH="${WEB_BASE_PATH:-/panel}"
}

detect_ssh_port() {
  local file="${SSHD_CONFIG_PATH:-/etc/ssh/sshd_config}"
  local port=""
  if [ -f "$file" ]; then
    port="$(sed -nE 's/^[[:space:]]*Port[[:space:]]+([0-9]+).*/\1/p' "$file" 2>/dev/null | tail -1)"
  fi
  if is_valid_port "${port:-}"; then
    printf '%s' "$port"
  else
    printf '22'
  fi
}

detect_public_ip() {
  local ip=""
  if command_exists curl; then
    ip="$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
    if [ -z "$ip" ]; then
      ip="$(curl -fsS --max-time 4 https://ifconfig.me/ip 2>/dev/null || true)"
    fi
  fi
  if is_valid_public_ip "$ip"; then
    printf '%s' "$ip"
  fi
}

is_valid_public_ip() {
  local ip="$1"
  case "$ip" in
    ''|*[!0-9a-fA-F:.]*) return 1 ;;
  esac
  if printf '%s' "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    local IFS=. octet
    for octet in $ip; do
      [ "$octet" -le 255 ] || return 1
    done
    return 0
  fi
  case "$ip" in
    *:*) is_valid_ipv6_literal "$ip" ;;
    *) return 1 ;;
  esac
}

is_valid_ipv6_literal() {
  local ip="$1" IFS=: part count explicit_count double_colon_count colon_count
  case "$ip" in
    ''|*[!0-9a-fA-F:]*|*:::*) return 1 ;;
  esac
  case "$ip" in
    :*) case "$ip" in ::*) ;; *) return 1 ;; esac ;;
  esac
  case "$ip" in
    *:) case "$ip" in *::) ;; *) return 1 ;; esac ;;
  esac
  double_colon_count="$(printf '%s' "$ip" | awk -F'::' '{print NF-1}')"
  colon_count="$(printf '%s' "$ip" | awk -F: '{print NF-1}')"
  [ "$double_colon_count" -le 1 ] || return 1
  if [ "$double_colon_count" -eq 0 ]; then
    [ "$colon_count" -eq 7 ] || return 1
  else
    [ "$colon_count" -ge 2 ] || return 1
  fi
  count=0
  explicit_count=0
  for part in $ip; do
    count=$((count + 1))
    [ -z "$part" ] && continue
    explicit_count=$((explicit_count + 1))
    [ "${#part}" -le 4 ] || return 1
    printf '%s' "$part" | grep -Eq '^[0-9A-Fa-f]+$' || return 1
  done
  if [ "$double_colon_count" -eq 1 ]; then
    [ "$explicit_count" -lt 8 ] || return 1
  fi
  [ "$count" -le 8 ] || return 1
  return 0
}

ensure_management_direct_defaults() {
  if [ ! -f "$CONFIG_PATH" ] || [ "$DRY_RUN" -eq 1 ]; then
    return 0
  fi
  local ssh_port public_ip args
  ssh_port="$(detect_ssh_port)"
  public_ip="$(detect_public_ip)"
  args=(ensure-management-direct --config "$CONFIG_PATH" --port "$ssh_port")
  if [ -n "$public_ip" ]; then
    args+=(--host "$public_ip")
  fi
  if "$MIGATE_BIN" "${args[@]}" >/dev/null 2>&1; then
    log_ok "管理直连保护默认配置已确认。"
  else
    log_warn "管理直连保护默认配置补齐失败，请安装后在设置页检查。"
  fi
}

port_in_use() {
  local port="$1"
  if command_exists ss; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${port}$"
  elif command_exists lsof; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
  elif command_exists netstat; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${port}$"
  else
    return 1
  fi
}

service_exists() {
  [ -f "$SERVICE_PATH" ] || { [ "$SYSTEMD_AVAILABLE" -eq 1 ] && systemctl list-unit-files migate.service >/dev/null 2>&1; }
}

service_status() {
  if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
    systemctl is-active migate 2>/dev/null || printf 'unknown'
  else
    printf 'systemd_unavailable'
  fi
}

binary_version() {
  local bin="$1"
  if [ -x "$bin" ]; then
    "$bin" version 2>/dev/null | head -1 || true
  elif command_exists "$bin"; then
    "$bin" version 2>/dev/null | head -1 || true
  fi
}

detect_existing_install() {
  local found=0
  section "已安装检测"
  if [ -x "$MIGATE_BIN" ]; then
    found=1
    log_ok "MiGate 二进制：$MIGATE_BIN ($(binary_version "$MIGATE_BIN"))"
  else
    log_info "MiGate 二进制：未找到 ($MIGATE_BIN)"
  fi
  if [ -L "$MIGATE_LINK" ] || [ -e "$MIGATE_LINK" ]; then
    found=1
    log_ok "MiGate CLI 链接：$MIGATE_LINK"
  else
    log_info "MiGate CLI 链接：未找到"
  fi
  if service_exists; then
    found=1
    log_ok "systemd 服务：migate.service ($(service_status))"
  else
    log_info "systemd 服务：未找到"
  fi
  if [ -d "$CONFIG_DIR" ]; then
    found=1
    log_ok "配置目录：$CONFIG_DIR"
  else
    log_info "配置目录：未找到"
  fi
  if [ -f "$CONFIG_PATH" ]; then
    found=1
    read_existing_config_defaults
    log_ok "面板配置：$CONFIG_PATH"
  else
    log_info "面板配置：未找到"
  fi
  if [ -f "${DATA_DIR}/migate.db" ]; then
    found=1
    log_ok "数据库：${DATA_DIR}/migate.db"
  else
    log_info "数据库：未找到 (${DATA_DIR}/migate.db)"
  fi
  if pgrep -x migate >/dev/null 2>&1; then
    found=1
    log_ok "进程：migate 正在运行"
  else
    log_info "进程：migate 未运行"
  fi
  if [ -n "${PANEL_PORT:-}" ] && port_in_use "$PANEL_PORT"; then
    log_warn "端口 ${PANEL_PORT}: 已被监听"
  else
    log_info "端口 ${PANEL_PORT:-9999}: 未检测到监听"
  fi
  log_info "WebUI：Release 二进制已内嵌前端静态资源，无需在服务器上安装 Node。"
  [ "$found" -eq 1 ]
}

core_version() {
  local core="$1"
  local name
  name="$(basename "$core")"
  case "$name" in
    xray) "$core" version 2>/dev/null | head -1 || true ;;
    sing-box) "$core" version 2>/dev/null | head -1 || true ;;
  esac
}

core_binary_path() {
  local command_name="$1"
  for path in "/usr/local/bin/${command_name}" "/usr/bin/${command_name}"; do
    if [ -x "$path" ]; then
      printf '%s' "$path"
      return 0
    fi
  done
  command -v "$command_name" 2>/dev/null || true
}

core_service_status() {
  local svc="$1"
  if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
    systemctl is-active "$svc" 2>/dev/null || printf 'unknown'
  else
    printf 'systemd_unavailable'
  fi
}

detect_core() {
  local label="$1"
  local command_name="$2"
  local service_name="$3"
  local found=0
  log_info "${label}: 检测二进制路径"
  for path in "/usr/local/bin/${command_name}" "/usr/bin/${command_name}"; do
    if [ -x "$path" ]; then
      found=1
      log_ok "${label} binary: ${path} ($(core_version "$path"))"
    else
      log_info "${label} binary: not found at ${path}"
    fi
  done
  if command_exists "$command_name"; then
    found=1
    log_ok "${label} command: $(command -v "$command_name") ($(core_version "$command_name"))"
  fi
  if [ "$SYSTEMD_AVAILABLE" -eq 1 ] && systemctl list-unit-files "${service_name}.service" >/dev/null 2>&1; then
    log_ok "${label} service: ${service_name}.service ($(core_service_status "$service_name"))"
  else
    log_info "${label} service: ${service_name}.service not found"
  fi
  [ "$found" -eq 1 ]
}

environment_report() {
  section "环境检测"
  detect_os
  detect_arch
  detect_root
  detect_systemd
  kv "系统" "${OS_NAME}"
  kv "架构" "${ARCH}"
  if [ "$IS_ROOT" -eq 1 ]; then log_ok "权限：root"; else log_warn "权限：非 root，实际安装需要 sudo/root。"; fi
  if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then log_ok "systemd：可用"; else log_warn "systemd：不可用，将跳过服务写入。"; fi
  dependency_status || true
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --install) ACTION="install"; shift ;;
      --upgrade|--update) ACTION="upgrade"; SKIP_CORE_PROMPTS=1; shift ;;
      --reinstall) ACTION="reinstall"; shift ;;
      --fresh-config) REGENERATE_CONFIG=1; shift ;;
      --uninstall) ACTION="uninstall"; shift ;;
      --repair-service) ACTION="repair-service"; shift ;;
      --install-xray) INSTALL_XRAY=1; EXPLICIT_INSTALL_XRAY=1; ACTION="${ACTION:-auto}"; shift ;;
      --install-singbox) INSTALL_SINGBOX=1; EXPLICIT_INSTALL_SINGBOX=1; ACTION="${ACTION:-auto}"; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --yes|-y) ASSUME_YES=1; SKIP_CORE_PROMPTS=1; shift ;;
      --check) ACTION="check"; shift ;;
      --version)
        [ "$#" -ge 2 ] || { log_error "--version requires a value"; exit 2; }
        VERSION="$2"
        REQUESTED_VERSION="$2"
        shift 2
        ;;
      -h|--help) usage; exit 0 ;;
      --)
        shift
        EXTRA_ARGS=("$@")
        EXTRA_ARGS_COUNT="$#"
        break
        ;;
      *)
        log_error "unknown argument: $1"
        usage >&2
        exit 2
        ;;
    esac
  done
}

release_base_url() {
  if [ "$VERSION" = "latest" ]; then
    printf 'https://github.com/%s/releases/latest/download' "$REPO"
  else
    printf 'https://github.com/%s/releases/download/%s' "$REPO" "$VERSION"
  fi
}

latest_release_tag() {
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' || true
}

current_migate_version() {
  "$MIGATE_BIN" version 2>/dev/null | awk '{print $NF}' || true
}

normalize_version() {
  printf '%s' "$1" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/^MiGate version:[[:space:]]*//; s/^v//'
}

parse_semver() {
  local normalized
  normalized="$(normalize_version "$1")"
  if printf '%s' "$normalized" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    printf '%s\n' "$normalized"
    return 0
  fi
  return 1
}

compare_versions() {
  local current latest
  current="$(parse_semver "$1")" || return 2
  latest="$(parse_semver "$2")" || return 2
  awk -v current="$current" -v latest="$latest" '
    BEGIN {
      split(current, c, ".")
      split(latest, l, ".")
      for (i = 1; i <= 3; i++) {
        if (l[i] + 0 > c[i] + 0) { print -1; exit }
        if (l[i] + 0 < c[i] + 0) { print 1; exit }
      }
      print 0
    }'
}

ensure_latest_release_version() {
  if [ "$VERSION" != "latest" ]; then
    return 0
  fi
  local latest
  latest="$(latest_release_tag)"
  if [ -z "$latest" ]; then
    log_warn "无法解析最新 Release 版本，将继续使用 releases/latest/download。"
    return 0
  fi
  VERSION="$latest"
  log_info "解析最新 Release：${VERSION}"
}

guard_default_latest_upgrade() {
  if [ "$ACTION" != "upgrade" ] || [ "$REQUESTED_VERSION" != "latest" ]; then
    return 0
  fi
  local current latest cmp
  current="$(current_migate_version)"
  if [ -z "$current" ] || [ "$current" = "unknown" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      log_warn "无法解析当前 MiGate 版本，dry-run 跳过默认 latest 升级保护预览。"
      return 0
    fi
    log_warn "无法解析当前 MiGate 版本，已停止默认 latest 升级以避免误降级。"
    return 1
  fi
  ensure_latest_release_version
  latest="$VERSION"
  if [ -z "$latest" ] || [ "$latest" = "unknown" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      log_warn "无法解析最新 Release 版本，dry-run 跳过默认 latest 升级保护预览。"
      return 0
    fi
    log_warn "无法解析最新 Release 版本，已停止默认 latest 升级以避免误降级。"
    return 1
  fi
  cmp="$(compare_versions "$current" "$latest")" || {
    log_warn "无法比较当前版本 ${current} 与最新发布版本 ${latest}，已停止默认 latest 升级。"
    return 11
  }
  if [ "$cmp" -eq 0 ]; then
    log_ok "MiGate 已是最新版本：${current}，不执行默认 latest 升级。"
    return 10
  fi
  if [ "$cmp" -gt 0 ]; then
    log_warn "当前版本 ${current} 高于最新发布版本 ${latest}，不可执行默认 latest 升级。"
    return 11
  fi
  return 0
}

note_explicit_version_direction() {
  if [ "$ACTION" != "upgrade" ] || [ "$REQUESTED_VERSION" = "latest" ]; then
    return 0
  fi
  local current cmp
  current="$(current_migate_version)"
  if [ -z "$current" ] || [ "$current" = "unknown" ]; then
    return 0
  fi
  cmp="$(compare_versions "$current" "$VERSION")" || return 0
  if [ "$cmp" -gt 0 ]; then
    log_warn "显式指定版本 ${VERSION} 低于当前版本 ${current}，将按用户指定执行降级。"
  elif [ "$cmp" -eq 0 ]; then
    log_ok "显式指定版本与当前版本一致：${current}，将刷新安装器和服务配置。"
  fi
}

note_current_release_state() {
  if [ "$ACTION" != "upgrade" ] || [ "$DRY_RUN" -eq 1 ]; then
    return 0
  fi
  local current latest cmp
  current="$(current_migate_version)"
  if [ -z "$current" ] || [ "$current" = "unknown" ]; then
    return 0
  fi
  ensure_latest_release_version
  latest="$VERSION"
  cmp="$(compare_versions "$current" "$latest")" || return 0
  if [ "$cmp" -eq 0 ]; then
    log_ok "MiGate 已是最新版本：${current}，将刷新安装器和服务配置。"
  elif [ "$REQUESTED_VERSION" != "latest" ] && [ "$cmp" -gt 0 ]; then
    log_warn "显式指定版本 ${latest} 低于当前版本 ${current}，将按用户指定执行降级。"
  fi
}

download_file() {
  local url="$1"
  local dest="$2"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] curl -fL %q -o %q\n' "$url" "$dest"
    return 0
  fi
  curl -fL "$url" -o "$dest"
}

verify_sha256() {
  local sha_file="$1"
  local work_dir="$2"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] verify sha256 with %s in %s\n' "$sha_file" "$work_dir"
    return 0
  fi
  if command_exists sha256sum; then
    (cd "$work_dir" && sha256sum -c "$sha_file")
  else
    (cd "$work_dir" && shasum -a 256 -c "$sha_file")
  fi
}

download_release_asset() {
  ensure_latest_release_version
  BASE_URL="$(release_base_url)"
  URL="${BASE_URL}/${ARTIFACT}"
  CHECKSUM_URL="${BASE_URL}/checksums.txt"

  log_info "下载 Release 包：${URL}"
  download_file "$URL" "$TMP/${ARTIFACT}"
  log_info "下载校验文件：${CHECKSUM_URL}"
  download_file "$CHECKSUM_URL" "$TMP/checksums.txt"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] grep "migate-linux-${ARCH}.tar.gz" %q > %q\n' "$TMP/checksums.txt" "$TMP/${ARTIFACT}.sha256"
    printf '[DRY-RUN] tar --no-same-owner -xzf %q -C %q\n' "$TMP/migate-linux-${ARCH}.tar.gz" "$TMP"
    return 0
  fi
  grep "migate-linux-${ARCH}.tar.gz" "$TMP/checksums.txt" > "$TMP/${ARTIFACT}.sha256"
  log_info "校验 Release 包 sha256"
  verify_sha256 "${ARTIFACT}.sha256" "$TMP"
  log_info "解压 Release 包"
  tar --no-same-owner -xzf "$TMP/migate-linux-${ARCH}.tar.gz" -C "$TMP"
}

install_migate_binary_from_tmp() {
  run_cmd mkdir -p "$DATA_DIR"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] install %q to %q using atomic temp file in target directory\n' "$TMP/migate" "$MIGATE_BIN"
    printf '[DRY-RUN] ln -sf %q %q\n' "$MIGATE_BIN" "$MIGATE_LINK"
    printf '[DRY-RUN] install packaged installer/uninstaller when present\n'
    return 0
  fi
  local migate_tmp
  migate_tmp="$(mktemp "$(dirname "$MIGATE_BIN")/.migate.XXXXXX")"
  cat "$TMP/migate" > "$migate_tmp"
  chmod +x "$migate_tmp"
  mv -f "$migate_tmp" "$MIGATE_BIN"
  ln -sf "$MIGATE_BIN" "$MIGATE_LINK"
  log_ok "MiGate 二进制已安装：$MIGATE_BIN"
  log_ok "CLI 快捷命令已安装：$MIGATE_LINK"
  if [ -f "$TMP/packaging/install.sh" ]; then
    local installer_tmp
    installer_tmp="$(mktemp "$(dirname "$INSTALLER_BIN")/.migate-install.XXXXXX")"
    cat "$TMP/packaging/install.sh" > "$installer_tmp"
    chmod +x "$installer_tmp"
    mv -f "$installer_tmp" "$INSTALLER_BIN"
    log_ok "安装器已安装：$INSTALLER_BIN"
  fi
  if [ -f "$TMP/packaging/uninstall.sh" ]; then
    local uninstaller_tmp
    uninstaller_tmp="$(mktemp "$(dirname "$UNINSTALLER_BIN")/.migate-uninstall.XXXXXX")"
    cat "$TMP/packaging/uninstall.sh" > "$uninstaller_tmp"
    chmod +x "$uninstaller_tmp"
    mv -f "$uninstaller_tmp" "$UNINSTALLER_BIN"
    log_ok "卸载器已安装：$UNINSTALLER_BIN"
  fi
}

check_update() {
  local current latest cmp
  latest="$(latest_release_tag)"
  current="$(current_migate_version)"
  [ -n "$current" ] || current="unknown"
  [ -n "$latest" ] || latest="unknown"
  echo "Current version: ${current}"
  echo "Latest version: ${latest}"
  cmp="$(compare_versions "$current" "$latest")" || cmp="unknown"
  if [ "$cmp" = "-1" ]; then
    echo "Update available: yes"
    echo "Run: mg update"
  elif [ "$cmp" = "1" ]; then
    echo "Update available: no"
    echo "Current version is higher than the latest release; default latest update is disabled."
  elif [ "$cmp" = "0" ]; then
    echo "Update available: no"
  else
    echo "Update available: no"
    echo "Unable to parse current or latest release version; update check is conservative."
  fi
}

write_versions_state() {
  local installed_at
  local xray_version
  local singbox_version
  installed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  xray_version="$(core_version "$(core_binary_path xray)")"
  singbox_version="$(core_version "$(core_binary_path sing-box)")"
  xray_version="${xray_version:-configured ${XRAY_VERSION:-26.3.27}}"
  singbox_version="${singbox_version:-configured ${SINGBOX_VERSION:-1.13.13}}"
  atomic_write_file "$VERSIONS_PATH" 0640 root:migate <<JSON
{
  "migate": {
    "version": "$(json_escape "$VERSION")"
  },
  "xray": {
    "version": "$(json_escape "$xray_version")",
    "configured_version": "$(json_escape "${XRAY_VERSION:-26.3.27}")"
  },
  "sing_box": {
    "version": "$(json_escape "$singbox_version")",
    "configured_version": "$(json_escape "${SINGBOX_VERSION:-1.13.13}")"
  },
  "installed_at": "$(json_escape "$installed_at")",
  "installer_version": "$(json_escape "$VERSION")"
}
JSON
  log_ok "版本状态已写入：$VERSIONS_PATH"
}

write_update_status() {
  local status="$1"
  local current_version="${2:-}"
  local target_version="${3:-}"
  local message="${4:-}"
  local health_check="${5:-}"
  local rolled_back="${6:-false}"
  local rollback_status="${7:-}"
  local updated_at
  health_check="$(sanitize_update_health_check "$health_check")"
  updated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] write update status %q status=%q target=%q rollback=%q\n' "$UPDATE_STATUS_PATH" "$status" "$target_version" "$rolled_back"
    return 0
  fi
  atomic_write_file "$UPDATE_STATUS_PATH" 0640 root:migate <<JSON
{
  "status": "$(json_escape "$status")",
  "current_version": "$(json_escape "$current_version")",
  "target_version": "$(json_escape "$target_version")",
  "message": "$(json_escape "$message")",
  "health_check": "$(json_escape "$health_check")",
  "rolled_back": ${rolled_back},
  "rollback_status": "$(json_escape "$rollback_status")",
  "updated_at": "$(json_escape "$updated_at")"
}
JSON
  log_ok "更新状态已写入：$UPDATE_STATUS_PATH"
}

copy_if_exists() {
  local src="$1"
  local dest="$2"
  if [ -e "$src" ] || [ -L "$src" ]; then
    cp -a "$src" "$dest"
  fi
}

backup_upgrade_state() {
  local backup_root="$1"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] backup %q %q %q %q %q %q under %q\n' "$MIGATE_BIN" "$INSTALLER_BIN" "$UNINSTALLER_BIN" "$SERVICE_PATH" "$VERSIONS_PATH" "$UPDATE_STATUS_PATH" "$backup_root"
    return 0
  fi
  mkdir -p "$backup_root/bin" "$backup_root/systemd" "$backup_root/state"
  copy_if_exists "$MIGATE_BIN" "$backup_root/bin/migate"
  copy_if_exists "$INSTALLER_BIN" "$backup_root/bin/migate-install"
  copy_if_exists "$UNINSTALLER_BIN" "$backup_root/bin/migate-uninstall"
  copy_if_exists "$SERVICE_PATH" "$backup_root/systemd/migate.service"
  copy_if_exists "$VERSIONS_PATH" "$backup_root/state/versions.json"
  copy_if_exists "$UPDATE_STATUS_PATH" "$backup_root/state/update-status.json"
  log_ok "升级前状态已备份：$backup_root"
}

restore_file_if_backed_up() {
  local backup_file="$1"
  local dest="$2"
  if [ -e "$backup_file" ] || [ -L "$backup_file" ]; then
    mkdir -p "$(dirname "$dest")"
    cp -a "$backup_file" "$dest"
  elif [ -d "$dest" ] && [ ! -L "$dest" ]; then
    log_error "回滚目标是目录，未自动删除：$dest"
    return 1
  else
    rm -f "$dest"
  fi
}

restore_upgrade_state() {
  local backup_root="$1"
  local ok=1
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] restore old migate binaries, installer, uninstaller, service, and version state from %q\n' "$backup_root"
    printf '[DRY-RUN] systemctl daemon-reload && systemctl restart migate && systemctl is-active migate\n'
    return 0
  fi
  restore_file_if_backed_up "$backup_root/bin/migate" "$MIGATE_BIN" || ok=0
  restore_file_if_backed_up "$backup_root/bin/migate-install" "$INSTALLER_BIN" || ok=0
  restore_file_if_backed_up "$backup_root/bin/migate-uninstall" "$UNINSTALLER_BIN" || ok=0
  restore_file_if_backed_up "$backup_root/systemd/migate.service" "$SERVICE_PATH" || ok=0
  restore_file_if_backed_up "$backup_root/state/versions.json" "$VERSIONS_PATH" || ok=0
  restore_file_if_backed_up "$backup_root/state/update-status.json" "$UPDATE_STATUS_PATH" || ok=0
  [ "$ok" -eq 1 ] || return 1
  chmod +x "$MIGATE_BIN" "$INSTALLER_BIN" "$UNINSTALLER_BIN" 2>/dev/null || true
  if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
    systemctl daemon-reload || return 1
    systemctl restart migate || return 1
  fi
}

migate_health_url_from_config() {
  local endpoint="$1"
  local port
  local web_path
  port="$(json_number_value panel_port "$CONFIG_PATH")"
  [ -n "$port" ] || return 1
  web_path="$(json_string_value web_base_path "$CONFIG_PATH")"
  web_path="$(normalize_web_base_path "${web_path:-/}")"
  printf 'http://127.0.0.1:%s%s%s' "$port" "$web_path" "$endpoint"
}

check_migate_health() {
  local health=""
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] systemctl is-active migate\n'
    printf '[DRY-RUN] retry curl -fsS local /api/health or /api/version until healthy or timeout\n'
    record_health_check "dry-run health check planned"
    return 0
  fi
  local timeout="${MIGATE_HEALTH_TIMEOUT:-45}"
  local interval="${MIGATE_HEALTH_INTERVAL:-2}"
  case "$timeout" in ''|*[!0-9]*) timeout=45 ;; esac
  case "$interval" in ''|*[!0-9]*) interval=2 ;; esac
  [ "$timeout" -ge 1 ] || timeout=45
  [ "$interval" -ge 1 ] || interval=2

  local deadline
  local active_streak=0
  local checked_http=0
  local last_systemd=""
  local last_http=""
  local now
  deadline="$(($(date +%s) + timeout))"
  while true; do
    if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
      if systemctl is-active --quiet migate; then
        active_streak=$((active_streak + 1))
        last_systemd="systemctl is-active migate: active"
      else
        active_streak=0
        last_systemd="systemctl is-active migate: not active"
      fi
    else
      record_health_check "systemd unavailable; skipped systemctl health check"
      return 0
    fi

    if [ "$active_streak" -gt 0 ]; then
      health="$last_systemd"
      if [ -f "$CONFIG_PATH" ] && command_exists curl; then
        local url
        local endpoint
        checked_http=0
        last_http=""
        for endpoint in /api/health /api/version; do
          url="$(migate_health_url_from_config "$endpoint" || true)"
          if [ -n "$url" ]; then
            checked_http=1
            if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
              record_health_check "${health}; ${url}: ok"
              return 0
            fi
            last_http="${last_http}; ${url}: failed"
          fi
        done
        if [ "$checked_http" -eq 0 ] && [ "$active_streak" -ge 2 ]; then
          record_health_check "${health}; local HTTP health check skipped: panel_port unavailable"
          return 0
        fi
        health="${health}${last_http}"
      elif [ "$active_streak" -ge 2 ]; then
        record_health_check "${health}; local HTTP health check skipped"
        return 0
      fi
    fi

    now="$(date +%s)"
    if [ "$now" -ge "$deadline" ]; then
      if [ -n "$health" ]; then
        record_health_check "health check timed out after ${timeout}s: ${health}"
      else
        record_health_check "health check timed out after ${timeout}s: ${last_systemd:-unknown}"
      fi
      return 1
    fi
    sleep "$interval"
  done
}

restart_and_healthcheck_migate_service() {
  restart_migate_service
  check_migate_health
}

rollback_failed_upgrade() {
  local backup_root="$1"
  local old_version="$2"
  local target_version="$3"
  local reason="${4:-upgrade failed}"
  log_error "$reason"
  log_warn "升级失败，开始自动回滚。"
  if restore_upgrade_state "$backup_root" && check_migate_health; then
    log_warn "升级失败，已回滚，服务已恢复。"
    write_update_status "failed" "${old_version:-unknown}" "$target_version" "升级失败，已回滚，服务已恢复" "${LAST_HEALTH_CHECK:-rollback health passed}" true "restored"
  else
    log_error "回滚失败，需要人工处理。"
    write_update_status "failed" "${old_version:-unknown}" "$target_version" "回滚失败，需要人工处理" "${LAST_HEALTH_CHECK:-rollback health failed}" true "failed"
  fi
}

apply_upgrade_release_from_backup() {
  local old_version="$1"
  if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
    run_cmd systemctl stop migate 2>/dev/null || true
  fi
  install_migate_binary_from_tmp
  write_config "$PANEL_PORT" "$PANEL_USERNAME" "$PANEL_PASSWORD" "$WEB_BASE_PATH"
  configure_log_retention
  write_systemd_service

  section "核心检测"
  if detect_core "Xray" "xray" "migate-xray"; then XRAY_FOUND=1; else XRAY_FOUND=0; fi
  if detect_core "sing-box" "sing-box" "migate-sing-box"; then SINGBOX_FOUND=1; else SINGBOX_FOUND=0; fi
  if [ "$INSTALL_XRAY" -eq 1 ] || [ "$INSTALL_SINGBOX" -eq 1 ]; then
    log_warn "MiGate 升级事务不同时安装/修复核心；请在升级完成后单独运行 migate-install --install-xray/--install-singbox。"
  fi

  section "服务启动"
  write_update_status "restarting" "${old_version:-unknown}" "$VERSION" "正在重启 MiGate 并执行健康检查" "" false ""
  restart_and_healthcheck_migate_service
}

print_config_summary() {
  section "安装配置摘要"
  kv "面板监听" "${PANEL_BIND_HOST}:${PANEL_PORT}"
  kv "Web base path" "${WEB_BASE_PATH:-/}"
  kv "管理员用户" "${PANEL_USERNAME}"
  if [ -f "$CONFIG_PATH" ] && [ "$REGENERATE_CONFIG" -ne 1 ]; then
    kv "管理员密码" "保留已有配置"
  elif [ "$GENERATED_PASSWORD" -eq 1 ]; then
    kv "管理员密码" "随机生成，完成后仅显示一次"
  else
    kv "管理员密码" "使用刚才输入的密码"
  fi
  kv "配置文件" "$CONFIG_PATH"
  kv "数据库" "${DATA_DIR}/migate.db"
  kv "Xray 配置" "${XRAY_CONFIG_PATH}"
  kv "sing-box 配置" "${SINGBOX_CONFIG_PATH}"
}

configure_log_retention() {
  if [ "$SYSTEMD_AVAILABLE" -ne 1 ]; then
    log_warn "systemd 不可用，跳过 journald 日志保留策略。"
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] write %q with SystemMaxUse=128M and RuntimeMaxUse=64M\n' "$JOURNALD_MIGATE_CONF"
    printf '[DRY-RUN] write %q for /var/log/migate-update.log rotation\n' "$LOGROTATE_MIGATE_CONF"
    return 0
  fi
  mkdir -p "$JOURNALD_CONF_DIR"
  atomic_write_file "$JOURNALD_MIGATE_CONF" 0644 root:root <<'CONF'
[Journal]
SystemMaxUse=128M
SystemKeepFree=512M
RuntimeMaxUse=64M
MaxRetentionSec=14day
RateLimitIntervalSec=30s
RateLimitBurst=1000
CONF
  log_ok "journald 日志保留策略已写入：$JOURNALD_MIGATE_CONF"
  if command_exists logrotate; then
    mkdir -p "$LOGROTATE_CONF_DIR"
    atomic_write_file "$LOGROTATE_MIGATE_CONF" 0644 root:root <<'CONF'
/var/log/migate-update.log {
  size 5M
  rotate 3
  compress
  missingok
  notifempty
  copytruncate
  create 0640 root root
}
CONF
    log_ok "更新日志轮转策略已写入：$LOGROTATE_MIGATE_CONF"
  else
    log_warn "未检测到 logrotate，跳过 /var/log/migate-update.log 轮转配置。"
  fi
  systemctl restart systemd-journald 2>/dev/null || true
  journalctl --vacuum-size=128M >/dev/null 2>&1 || true
}

write_config() {
  local panel_port="$1"
  local panel_username="$2"
  local panel_password="$3"
  local web_base_path="$4"
  local panel_password_hash
  if [ -f "$CONFIG_PATH" ] && [ "$REGENERATE_CONFIG" -ne 1 ]; then
    log_ok "保留已有配置：$CONFIG_PATH"
    ensure_management_direct_defaults
    return 0
  fi
  ensure_runtime_dirs
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] write panel config %q with mode 640\n' "$CONFIG_PATH"
    return 0
  fi
  panel_password_hash="$("$MIGATE_BIN" hash-password "$panel_password")"
  atomic_write_file "$CONFIG_PATH" 0640 root:migate <<JSON
{
  "panel_port": ${panel_port},
  "panel_username": "$(json_escape "$panel_username")",
  "panel_password": "$(json_escape "$panel_password_hash")",
  "web_base_path": "$(json_escape "$web_base_path")",
  "database_path": "$(json_escape "$DATA_DIR")/migate.db",
  "management_direct_enabled": true,
  "management_direct_auto_detect": true,
  "management_direct_hosts": [],
  "management_direct_ports": [$(detect_ssh_port)]
}
JSON
  ensure_management_direct_defaults
  log_ok "配置已写入：$CONFIG_PATH"
}

prompt_config() {
  if [ -f "$CONFIG_PATH" ] && [ "$REGENERATE_CONFIG" -ne 1 ]; then
    read_existing_config_defaults
    log_ok "使用已有配置，不重新生成 panel.json"
    print_config_summary
    return 0
  fi
  if [ "$ASSUME_YES" -eq 1 ]; then
    PANEL_PORT="${PANEL_PORT:-9999}"
    PANEL_USERNAME="${PANEL_USERNAME:-admin}"
    WEB_BASE_PATH="$(normalize_web_base_path "${WEB_BASE_PATH:-/panel}")"
    PANEL_PASSWORD="$(generate_password)"
    GENERATED_PASSWORD=1
    print_config_summary
    return 0
  fi

  section "面板配置"
  log_info "直接回车会使用方括号中的默认值。"
  while true; do
    prompt_line "面板端口 [${PANEL_PORT:-9999}]: "
    read -r input_panel_port
    PANEL_PORT="${input_panel_port:-${PANEL_PORT:-9999}}"
    if is_valid_port "$PANEL_PORT"; then
      break
    fi
    log_warn "端口必须是 1-65535 之间的数字，请重新输入。"
  done

  prompt_line "管理员用户名 [${PANEL_USERNAME:-admin}]: "
  read -r input_panel_username
  PANEL_USERNAME="${input_panel_username:-${PANEL_USERNAME:-admin}}"

  prompt_line "管理员密码 [留空则随机生成]: "
  read -r -s PANEL_PASSWORD
  printf '\n'
  if [ -z "$PANEL_PASSWORD" ]; then
    PANEL_PASSWORD="$(generate_password)"
    GENERATED_PASSWORD=1
    log_warn "未输入密码，已生成随机密码。安装完成时只显示一次，请保存。"
  fi

  prompt_line "Web base path [${WEB_BASE_PATH:-/panel}]: "
  read -r input_web_base_path
  WEB_BASE_PATH="${input_web_base_path:-${WEB_BASE_PATH:-/panel}}"
  WEB_BASE_PATH="$(normalize_web_base_path "$WEB_BASE_PATH")"

  print_config_summary
  if ! confirm_yes "确认使用以上配置继续安装？"; then
    log_error "用户取消安装。"
    exit 1
  fi
}

write_systemd_service() {
  if [ "$SYSTEMD_AVAILABLE" -ne 1 ]; then
    log_warn "systemd 不可用，跳过 migate.service 写入。"
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] write %q\n' "$SERVICE_PATH"
    return 0
  fi
  ensure_runtime_dirs
  atomic_write_file "$SERVICE_PATH" 0644 root:root <<UNIT
[Unit]
Description=MiGate Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# MiGate still runs as root because this service manages systemd units, writes
# root-owned core configs, and binds/administers system resources during install
# and repair flows.
User=root
WorkingDirectory=${DATA_DIR}
ExecStart=${MIGATE_BIN} serve --host ${PANEL_BIND_HOST} --config ${CONFIG_PATH}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${CONFIG_DIR} ${DATA_DIR} ${LOG_DIR} ${RUN_DIR} $(dirname "$MIGATE_BIN") ${XRAY_SHARE_DIR} $(dirname "$SERVICE_PATH")
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
StandardOutput=journal
StandardError=journal
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200

[Install]
WantedBy=multi-user.target
UNIT
  log_ok "systemd service written: $SERVICE_PATH"
}

restart_migate_service() {
  if [ "$SYSTEMD_AVAILABLE" -ne 1 ]; then
    log_warn "systemd 不可用，手动运行：${MIGATE_BIN} serve --config ${CONFIG_PATH}"
    return 0
  fi
  run_cmd systemctl daemon-reload
  enable_systemd_service migate
  run_cmd systemctl restart migate
  if [ "$DRY_RUN" -eq 0 ]; then
    if systemctl is-active migate >/dev/null 2>&1; then
      log_ok "MiGate service: running"
    else
      log_warn "MiGate service: waiting for health check"
    fi
  fi
}

write_default_xray_config() {
  local path="$1"
  atomic_write_file "$path" 0640 root:migate <<'JSON'
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "api",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      }
    }
  ],
  "outbounds": [
    {
      "tag": "xray-out-1",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "xray-out-2",
      "protocol": "blackhole",
      "settings": {}
    },
    {
      "tag": "xray-out-3",
      "protocol": "dns",
      "settings": {}
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api"
      }
    ]
  },
  "stats": {},
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    }
  },
  "api": {
    "tag": "api",
    "services": [
      "StatsService"
    ]
  }
}
JSON
}

write_default_singbox_config() {
  local path="$1"
  atomic_write_file "$path" 0640 root:migate <<'JSON'
{
  "log": {
    "level": "warn"
  },
  "inbounds": [],
  "outbounds": [
    {
      "type": "direct",
      "tag": "singbox-out-1"
    },
    {
      "type": "block",
      "tag": "singbox-out-2"
    }
  ]
}
JSON
}

backup_invalid_core_config() {
  local path="$1"
  local core="$2"
  if [ ! -e "$path" ]; then
    return 0
  fi
  ensure_runtime_dirs
  local backup="${BACKUP_DIR}/${core}-config-invalid-$(date +%Y%m%d-%H%M%S).json"
  mv -f "$path" "$backup"
  log_warn "已备份不可用配置：${backup}"
}

check_xray_config_silent() {
  /usr/local/bin/xray run -test -c "$1" >/dev/null 2>&1
}

check_singbox_config_silent() {
  /usr/local/bin/sing-box check -c "$1" >/dev/null 2>&1
}

validate_xray_config() {
  local path="$1"
  local success_message="${2:-}"
  local output
  if output="$(/usr/local/bin/xray run -test -c "$path" 2>&1)"; then
    if [ -n "$success_message" ]; then
      log_ok "$success_message"
    fi
    return 0
  fi
  printf '%s\n' "$output" >&2
  return 1
}

validate_singbox_config() {
  local path="$1"
  local success_message="${2:-}"
  local output
  if output="$(/usr/local/bin/sing-box check -c "$path" 2>&1)"; then
    if [ -n "$success_message" ]; then
      log_ok "$success_message"
    fi
    return 0
  fi
  printf '%s\n' "$output" >&2
  return 1
}

install_default_xray_config() {
  local tmp
  tmp="$(mktemp "${CORE_CONFIG_DIR}/.xray-default.XXXXXX.json")"
  write_default_xray_config "$tmp"
  validate_xray_config "$tmp"
  mv -f "$tmp" "$XRAY_CONFIG_PATH"
  set_core_config_permissions "$XRAY_CONFIG_PATH"
}

install_default_singbox_config() {
  local tmp
  tmp="$(mktemp "${CORE_CONFIG_DIR}/.sing-box-default.XXXXXX.json")"
  write_default_singbox_config "$tmp"
  validate_singbox_config "$tmp"
  mv -f "$tmp" "$SINGBOX_CONFIG_PATH"
  set_core_config_permissions "$SINGBOX_CONFIG_PATH"
}

ensure_valid_xray_config() {
  if check_xray_config_silent "$XRAY_CONFIG_PATH"; then
    log_ok "Xray 配置校验通过：${XRAY_CONFIG_PATH}"
    return 0
  fi
  log_warn "现有 Xray 配置校验失败，将备份并写入 MiGate 默认配置。"
  backup_invalid_core_config "${XRAY_CONFIG_PATH}" "xray"
  install_default_xray_config
  validate_xray_config "$XRAY_CONFIG_PATH" "Xray 配置校验通过：${XRAY_CONFIG_PATH}"
}

ensure_valid_singbox_config() {
  if check_singbox_config_silent "$SINGBOX_CONFIG_PATH"; then
    log_ok "sing-box 配置校验通过：${SINGBOX_CONFIG_PATH}"
    return 0
  fi
  log_warn "现有 sing-box 配置校验失败，将备份并写入 MiGate 默认配置。"
  backup_invalid_core_config "$SINGBOX_CONFIG_PATH" "sing-box"
  install_default_singbox_config
  validate_singbox_config "$SINGBOX_CONFIG_PATH" "sing-box 配置校验通过：${SINGBOX_CONFIG_PATH}"
}

install_xray() {
  section "安装/修复 Xray"
  local xray_version="${XRAY_VERSION:-26.3.27}"
  local xray_asset_arch
  case "$(arch)" in
    amd64) xray_asset_arch="64" ;;
    arm64) xray_asset_arch="arm64-v8a" ;;
    *) log_error "unsupported Xray architecture"; return 1 ;;
  esac
  local xray_artifact="Xray-linux-${xray_asset_arch}.zip"
  local xray_url="https://github.com/XTLS/Xray-core/releases/download/v${xray_version}/${xray_artifact}"
  local xray_dgst_url="${xray_url}.dgst"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] curl -fL %q -o "$tmp_xray/%s"\n' "$xray_url" "$xray_artifact"
    printf '[DRY-RUN] curl -fL %q -o "$tmp_xray/%s.dgst"\n' "$xray_dgst_url" "$xray_artifact"
    printf '[DRY-RUN] extract SHA2-256 to "$tmp_xray/%s.sha256"\n' "$xray_artifact"
    printf '[DRY-RUN] verify sha256 with "%s.sha256"\n' "$xray_artifact"
    if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
      printf '[DRY-RUN] systemctl stop migate-xray\n'
      printf '[DRY-RUN] atomic install /usr/local/bin/xray via /usr/local/bin/.xray.new.$$\n'
      printf '[DRY-RUN] write /etc/systemd/system/migate-xray.service, validate config, and restart migate-xray\n'
    else
      printf '[DRY-RUN] atomic install /usr/local/bin/xray via /usr/local/bin/.xray.new.$$\n'
      printf '[DRY-RUN] skip /etc/systemd/system/migate-xray.service because systemd is unavailable\n'
    fi
    return 0
  fi
  if [ "$ASSUME_YES" -ne 1 ] && [ "$CORE_PROMPTS_CONFIRMED" -ne 1 ]; then
    if ! confirm_no "确认安装/修复 Xray ${xray_version}？"; then
      log_warn "跳过 Xray 安装。"
      return 0
    fi
  fi
  log_info "下载 Xray ${xray_version}: ${xray_url}"
  local tmp_xray
  tmp_xray="$(mktemp -d)"
  curl -fL "$xray_url" -o "$tmp_xray/$xray_artifact"
  log_info "下载 Xray 校验文件"
  curl -fL "$xray_dgst_url" -o "$tmp_xray/$xray_artifact.dgst"
  awk -F'= ' -v asset="$xray_artifact" '/^SHA2-256=/{print $2 "  " asset}' "$tmp_xray/$xray_artifact.dgst" > "$tmp_xray/$xray_artifact.sha256"
  if ! grep -Eq '^[0-9a-fA-F]{64}[[:space:]]+' "$tmp_xray/$xray_artifact.sha256"; then
    log_error "invalid Xray checksum file"
    rm -rf "$tmp_xray"
    return 1
  fi
  log_info "校验 Xray sha256"
  verify_sha256 "$xray_artifact.sha256" "$tmp_xray"
  log_info "解压并安装 Xray"
  unzip -oq "$tmp_xray/$xray_artifact" -d "$tmp_xray/xray"
  if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
    systemctl stop migate-xray 2>/dev/null || true
  fi
  local xray_install_tmp="/usr/local/bin/.xray.new.$$"
  rm -f "$xray_install_tmp"
  if ! { cp "$tmp_xray/xray/xray" "$xray_install_tmp" && chmod +x "$xray_install_tmp" && mv -f "$xray_install_tmp" /usr/local/bin/xray; }; then
    rm -f "$xray_install_tmp"
    rm -rf "$tmp_xray"
    return 1
  fi
  ensure_runtime_dirs
  mkdir -p "$XRAY_SHARE_DIR"
  [ -f "$tmp_xray/xray/geosite.dat" ] && cp "$tmp_xray/xray/geosite.dat" "$XRAY_SHARE_DIR/geosite.dat"
  [ -f "$tmp_xray/xray/geoip.dat" ] && cp "$tmp_xray/xray/geoip.dat" "$XRAY_SHARE_DIR/geoip.dat"
  rm -rf "$tmp_xray"
  if [ ! -f "${XRAY_CONFIG_PATH}" ]; then
    install_default_xray_config
  fi
  set_core_config_permissions "$XRAY_CONFIG_PATH"
  if ! ensure_valid_xray_config; then
    log_error "Xray 默认配置校验失败：/etc/migate/cores/xray.json"
    return 1
  fi
  if [ "$SYSTEMD_AVAILABLE" -ne 1 ]; then
    log_warn "systemd 不可用，跳过 migate-xray.service 写入。"
    log_info "Manual run: /usr/local/bin/xray run -c ${XRAY_CONFIG_PATH}"
    log_ok "Xray 安装/修复完成"
    return 0
  fi
  atomic_write_file "$XRAY_SERVICE_PATH" 0644 root:root <<UNIT
[Unit]
Description=MiGate managed Xray service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -c ${XRAY_CONFIG_PATH}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  enable_systemd_service migate-xray
  if ! systemctl restart migate-xray; then
    log_error "Xray 服务启动失败。查看：journalctl -u migate-xray -n 80 --no-pager"
    return 1
  fi
  if ! systemctl is-active --quiet migate-xray; then
    log_error "Xray 服务未处于 active 状态。查看：systemctl status migate-xray"
    return 1
  fi
  log_ok "Xray 安装/修复完成"
}

install_singbox() {
  section "安装/修复 sing-box"
  local sb_version="${SINGBOX_VERSION:-1.13.13}"
  local sb_asset_arch
  case "$(arch)" in
    amd64) sb_asset_arch="amd64" ;;
    arm64) sb_asset_arch="arm64" ;;
    *) log_error "unsupported sing-box architecture"; return 1 ;;
  esac
  local sb_artifact="sing-box-${sb_version}-linux-${sb_asset_arch}.tar.gz"
  local sb_url="https://github.com/SagerNet/sing-box/releases/download/v${sb_version}/sing-box-${sb_version}-linux-${sb_asset_arch}.tar.gz"
  local sb_release_api_url="https://api.github.com/repos/SagerNet/sing-box/releases/tags/v${sb_version}"
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[DRY-RUN] curl -fL %q -o "$tmp_sb/%s"\n' "$sb_url" "$sb_artifact"
    printf '[DRY-RUN] curl -fsSL %q -o "$tmp_sb/release.json"\n' "$sb_release_api_url"
    printf '[DRY-RUN] extract GitHub asset digest for %q > "$tmp_sb/%s.sha256"\n' "$sb_artifact" "$sb_artifact"
    printf '[DRY-RUN] sha256sum -c "%s.sha256"\n' "$sb_artifact"
    if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
      printf '[DRY-RUN] systemctl stop migate-sing-box\n'
      printf '[DRY-RUN] atomic install /usr/local/bin/sing-box via /usr/local/bin/.sing-box.new.$$\n'
      printf '[DRY-RUN] write %q and restart migate-sing-box\n' "$SINGBOX_SERVICE_PATH"
    else
      printf '[DRY-RUN] atomic install /usr/local/bin/sing-box via /usr/local/bin/.sing-box.new.$$\n'
      printf '[DRY-RUN] skip %q because systemd is unavailable\n' "$SINGBOX_SERVICE_PATH"
    fi
    return 0
  fi
  if [ "$ASSUME_YES" -ne 1 ] && [ "$CORE_PROMPTS_CONFIRMED" -ne 1 ]; then
    if ! confirm_no "确认安装/修复 sing-box ${sb_version}？"; then
      log_warn "跳过 sing-box 安装。"
      return 0
    fi
  fi
  log_info "下载 sing-box ${sb_version}: ${sb_url}"
  local tmp_sb
  tmp_sb="$(mktemp -d)"
  curl -fL "$sb_url" -o "$tmp_sb/$sb_artifact"
  log_info "读取 sing-box Release 资产校验值"
  curl -fsSL "$sb_release_api_url" -o "$tmp_sb/release.json"
  local sb_digest
  sb_digest="$(awk -v asset="$sb_artifact" '
    /"name": "/ { in_asset=0 }
    index($0, "\"name\": \"" asset "\"") { in_asset=1 }
    in_asset && index($0, "\"digest\": \"sha256:") {
      line=$0
      sub(/^.*"digest": "sha256:/, "", line)
      sub(/".*$/, "", line)
      print line
      exit
    }
  ' "$tmp_sb/release.json")"
  if ! printf '%s\n' "$sb_digest" | grep -Eq '^[0-9a-fA-F]{64}$'; then
    log_error "无法从 sing-box Release API 获取 ${sb_artifact} 的 sha256 digest"
    rm -rf "$tmp_sb"
    return 1
  fi
  printf '%s  %s\n' "$sb_digest" "$sb_artifact" > "$tmp_sb/$sb_artifact.sha256"
  log_info "校验 sing-box sha256"
  verify_sha256 "$sb_artifact.sha256" "$tmp_sb"
  log_info "解压并安装 sing-box"
  tar --no-same-owner -xzf "$tmp_sb/$sb_artifact" -C "$tmp_sb"
  if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
    systemctl stop migate-sing-box 2>/dev/null || true
  fi
  local sb_install_tmp="/usr/local/bin/.sing-box.new.$$"
  rm -f "$sb_install_tmp"
  if ! { cp "$tmp_sb"/sing-box-*/sing-box "$sb_install_tmp" && chmod +x "$sb_install_tmp" && mv -f "$sb_install_tmp" /usr/local/bin/sing-box; }; then
    rm -f "$sb_install_tmp"
    rm -rf "$tmp_sb"
    return 1
  fi
  rm -rf "$tmp_sb"
  ensure_runtime_dirs
  if [ ! -f "$SINGBOX_CONFIG_PATH" ]; then
    install_default_singbox_config
  fi
  set_core_config_permissions "$SINGBOX_CONFIG_PATH"
  if ! ensure_valid_singbox_config; then
    log_error "sing-box 默认配置校验失败：${SINGBOX_CONFIG_PATH}"
    return 1
  fi
  if [ "$SYSTEMD_AVAILABLE" -ne 1 ]; then
    log_warn "systemd 不可用，跳过 migate-sing-box.service 写入。"
    log_info "Manual run: /usr/local/bin/sing-box run -c ${SINGBOX_CONFIG_PATH}"
    log_ok "sing-box 安装/修复完成"
    return 0
  fi
  atomic_write_file "$SINGBOX_SERVICE_PATH" 0644 root:root <<UNIT
[Unit]
Description=MiGate managed sing-box service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c ${SINGBOX_CONFIG_PATH}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
StandardOutput=journal
StandardError=journal
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  enable_systemd_service migate-sing-box
  if ! systemctl restart migate-sing-box; then
    log_error "sing-box 服务启动失败。查看：journalctl -u migate-sing-box -n 80 --no-pager"
    return 1
  fi
  if ! systemctl is-active --quiet migate-sing-box; then
    log_error "sing-box 服务未处于 active 状态。查看：systemctl status migate-sing-box"
    return 1
  fi
  log_ok "sing-box 安装/修复完成"
}

maybe_install_core() {
  local label="$1"
  local installer="$2"
  set +e
  ( set -e; "$installer" )
  local code="$?"
  set -e
  if [ "$code" -eq 0 ]; then
    return 0
  fi
  log_warn "${label} 安装/修复失败（退出码：${code}），MiGate 安装/升级将继续。"
  log_warn "稍后可运行对应的 migate-install --install-xray/--install-singbox --yes，或在 WebUI 核心页面重试。"
  return 0
}

prompt_core_installs() {
  if [ "$SKIP_CORE_PROMPTS" -eq 1 ]; then
    if [ "$INSTALL_XRAY" -ne 1 ]; then log_warn "未指定 --install-xray，跳过 Xray 安装。"; fi
    if [ "$INSTALL_SINGBOX" -ne 1 ]; then log_warn "未指定 --install-singbox，跳过 sing-box 安装。"; fi
    return 0
  fi
  CORE_PROMPTS_CONFIRMED=1
  if [ "$INSTALL_XRAY" -ne 1 ]; then
    if [ "$XRAY_FOUND" -eq 1 ]; then
      if confirm_no "检测到 Xray 已安装，是否重新安装/修复 Xray？"; then
        INSTALL_XRAY=1
      else
        log_info "保留现有 Xray 安装。"
      fi
    else
      if confirm_yes "未检测到 Xray，是否安装 Xray？"; then
        INSTALL_XRAY=1
      else
        log_warn "跳过 Xray。核心代理功能可能不可用。"
      fi
    fi
  fi
  if [ "$INSTALL_SINGBOX" -ne 1 ]; then
    if [ "$SINGBOX_FOUND" -eq 1 ]; then
      if confirm_no "检测到 sing-box 已安装，是否重新安装/修复 sing-box？"; then
        INSTALL_SINGBOX=1
      else
        log_info "保留现有 sing-box 安装。"
      fi
    else
      if confirm_yes "未检测到 sing-box，是否安装 sing-box？"; then
        INSTALL_SINGBOX=1
      else
        log_warn "跳过 sing-box。Hysteria2/TUIC/ShadowTLS 可能不可用。"
      fi
    fi
  fi
}

install_release_flow() {
  local mode="$1"
  local upgrade_backup_root=""
  local old_version=""
  require_linux_for_release
  require_root
  require_dependencies
  ARCH="$(arch)"
  ARTIFACT="migate-linux-${ARCH}.tar.gz"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  section "配置确认"
  if [ "$mode" = "fresh" ]; then
    REGENERATE_CONFIG=1
  fi
  prompt_config
  if [ -n "${PANEL_PORT:-}" ] && port_in_use "$PANEL_PORT" && ! pgrep -x migate >/dev/null 2>&1; then
    log_warn "端口 ${PANEL_PORT} 已被占用，服务启动可能失败。"
  fi
  section "安装计划"
  kv "动作" "$mode"
  kv "Release 资产" "$ARTIFACT"
  kv "安装 MiGate" "$MIGATE_BIN"
  kv "写入配置" "$CONFIG_PATH"
  if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
    kv "写入服务" "$SERVICE_PATH"
  else
    kv "写入服务" "跳过，systemd 不可用"
  fi

  section "安装 MiGate"
  if [ "$ACTION" = "upgrade" ]; then
    set +e
    guard_default_latest_upgrade
    local guard_code="$?"
    set -e
    if [ "$guard_code" -eq 10 ]; then
      if [ "$DRY_RUN" -eq 1 ]; then
        return 0
      fi
      write_update_status "completed" "$(current_migate_version)" "$VERSION" "当前版本已是最新发布版本，未执行升级" "" false ""
      return 0
    fi
    if [ "$guard_code" -ne 0 ]; then
      if [ "$DRY_RUN" -eq 1 ]; then
        return 0
      fi
      write_update_status "failed" "$(current_migate_version)" "$VERSION" "当前版本不可执行默认 latest 升级" "" false ""
      return 1
    fi
    note_explicit_version_direction
  fi
  note_current_release_state
  ensure_migate_user_group
  ensure_runtime_dirs
  old_version="$(current_migate_version)"
  if [ "$ACTION" = "upgrade" ]; then
    write_update_status "downloading" "${old_version:-unknown}" "$VERSION" "正在下载并校验升级包" "" false ""
  fi
  download_release_asset
  if [ "$ACTION" = "upgrade" ]; then
    upgrade_backup_root="${BACKUP_DIR}/upgrade-$(date +%Y%m%d-%H%M%S)"
    backup_upgrade_state "$upgrade_backup_root"
    write_update_status "installing" "${old_version:-unknown}" "$VERSION" "升级包校验完成，正在替换二进制和服务文件" "" false ""
    MIGATE_HEALTH_RESULT_PATH="$TMP/health-check-result"
    rm -f "$MIGATE_HEALTH_RESULT_PATH"
    export MIGATE_HEALTH_RESULT_PATH
    set +e
    ( set -e; apply_upgrade_release_from_backup "$old_version" )
    local upgrade_code="$?"
    set -e
    if [ -f "$MIGATE_HEALTH_RESULT_PATH" ]; then
      LAST_HEALTH_CHECK="$(cat "$MIGATE_HEALTH_RESULT_PATH")"
    fi
    if [ "$upgrade_code" -eq 0 ]; then
      write_versions_state
      log_ok "升级成功，目标版本：${VERSION}，当前版本：$(current_migate_version)"
      log_ok "健康检查结果：${LAST_HEALTH_CHECK:-passed}"
      write_update_status "completed" "$(current_migate_version)" "$VERSION" "升级成功，服务已恢复可用" "${LAST_HEALTH_CHECK:-passed}" false ""
    else
      rollback_failed_upgrade "$upgrade_backup_root" "$old_version" "$VERSION" "升级过程失败或健康检查失败：${LAST_HEALTH_CHECK:-exit code ${upgrade_code}}"
      return 1
    fi
  else
    if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
      run_cmd systemctl stop migate 2>/dev/null || true
    fi
    install_migate_binary_from_tmp
    write_config "$PANEL_PORT" "$PANEL_USERNAME" "$PANEL_PASSWORD" "$WEB_BASE_PATH"
    configure_log_retention
    write_systemd_service

    section "核心检测"
    if detect_core "Xray" "xray" "migate-xray"; then XRAY_FOUND=1; else XRAY_FOUND=0; fi
    if detect_core "sing-box" "sing-box" "migate-sing-box"; then SINGBOX_FOUND=1; else SINGBOX_FOUND=0; fi
    prompt_core_installs
    if [ "$INSTALL_XRAY" -eq 1 ]; then
      if [ "$EXPLICIT_INSTALL_XRAY" -eq 1 ]; then install_xray; else maybe_install_core "Xray" install_xray; fi
    fi
    if [ "$INSTALL_SINGBOX" -eq 1 ]; then
      if [ "$EXPLICIT_INSTALL_SINGBOX" -eq 1 ]; then install_singbox; else maybe_install_core "sing-box" install_singbox; fi
    fi

    section "服务启动"
    restart_migate_service
    write_versions_state
  fi
  finish_message
}

repair_service_flow() {
  require_root
  detect_systemd
  ensure_migate_user_group
  section "修复 systemd 服务"
  configure_log_retention
  write_systemd_service
  restart_migate_service
  log_ok "服务修复完成"
}

uninstall_flow() {
  require_root
  local args=()
  local args_count=0
  if [ "${EXTRA_ARGS_COUNT:-0}" -gt 0 ]; then
    args=("${EXTRA_ARGS[@]}")
    args_count="${EXTRA_ARGS_COUNT:-0}"
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    args[args_count]="--dry-run"
    args_count=$((args_count + 1))
  fi
  if [ "$ASSUME_YES" -eq 1 ]; then
    args[args_count]="--yes"
    args_count=$((args_count + 1))
  fi
  if [ -x "$UNINSTALLER_BIN" ]; then
    if [ "$args_count" -gt 0 ]; then
      "$UNINSTALLER_BIN" "${args[@]}"
    else
      "$UNINSTALLER_BIN"
    fi
  else
    if [ "$args_count" -gt 0 ]; then
      bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/uninstall.sh" "${args[@]}"
    else
      bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/uninstall.sh"
    fi
  fi
}

interactive_menu() {
  local installed=0
  detect_existing_install && installed=1 || installed=0
  if [ "$installed" -eq 0 ]; then
    ACTION="install"
    return
  fi
  section "操作选择"
  cat <<'EOF'
  1) 升级 MiGate，并保留现有配置
  2) 重装 MiGate，并保留现有配置
  3) 重装 MiGate，并重新生成面板配置
  4) 只修复 migate systemd 服务
  5) 只安装/修复 Xray
  6) 只安装/修复 sing-box
  7) 卸载 MiGate
  8) 退出
EOF
  prompt_line "请选择操作 [1-8]: "
  read -r choice
  case "$choice" in
    1) ACTION="upgrade" ;;
    2) ACTION="reinstall" ;;
    3) ACTION="reinstall"; REGENERATE_CONFIG=1 ;;
    4) ACTION="repair-service" ;;
    5) ACTION="install-xray-only"; INSTALL_XRAY=1 ;;
    6) ACTION="install-singbox-only"; INSTALL_SINGBOX=1 ;;
    7) ACTION="uninstall" ;;
    8) ACTION="exit" ;;
    *) log_error "无效选择"; exit 2 ;;
  esac
}

finish_message() {
  local host_ip
  local xray_bin
  local singbox_bin
  local web_path
  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  [ -n "$host_ip" ] || host_ip="SERVER_IP"
  xray_bin="$(core_binary_path xray)"
  singbox_bin="$(core_binary_path sing-box)"
  web_path="$(web_url_path "${WEB_BASE_PATH:-/}")"
  section "安装完成，请保存以下信息"
  kv "MiGate 二进制" "$MIGATE_BIN"
  kv "CLI 命令" "mg"
  kv "数据目录" "${DATA_DIR}"
  kv "面板监听" "${PANEL_BIND_HOST}:${PANEL_PORT}"
  kv "Web base path" "$web_path"
  kv "WebUI 地址" "http://${host_ip}:${PANEL_PORT}${web_path}"
  log_warn "默认仅监听 ${PANEL_BIND_HOST}。公网访问请通过 Nginx/Caddy 等反向代理并启用 HTTPS。"
  kv "管理员用户" "${PANEL_USERNAME}"
  if [ "$GENERATED_PASSWORD" -eq 1 ] || [ -n "$PANEL_PASSWORD" ]; then
    kv "管理员密码" "${PANEL_PASSWORD}"
    log_warn "密码仅在终端显示一次，请立即保存。"
  else
    kv "管理员密码" "保留已有配置中的密码"
  fi
  kv "面板配置" "${CONFIG_PATH}"
  kv "数据库" "${DATA_DIR}/migate.db"
  kv "Xray 配置" "${XRAY_CONFIG_PATH}"
  if [ -n "$xray_bin" ]; then
    kv "Xray 二进制" "${xray_bin} ($(core_version "$xray_bin"))"
    if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then kv "Xray 服务" "systemctl status migate-xray"; fi
  else
    log_warn "Xray 二进制：未找到"
  fi
  kv "sing-box 配置" "${SINGBOX_CONFIG_PATH}"
  if [ -n "$singbox_bin" ]; then
    kv "sing-box 二进制" "${singbox_bin} ($(core_version "$singbox_bin"))"
    if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then kv "sing-box 服务" "systemctl status migate-sing-box"; fi
  else
    log_warn "sing-box 二进制：未找到"
  fi
  kv "安装器" "${INSTALLER_BIN}"
  kv "卸载器" "${UNINSTALLER_BIN}"
  if [ "$SYSTEMD_AVAILABLE" -eq 1 ]; then
    kv "MiGate 服务文件" "${SERVICE_PATH}"
    kv "MiGate 服务状态" "systemctl status migate"
    kv "MiGate 实时日志" "journalctl -u migate -f"
  else
    kv "手动启动" "${MIGATE_BIN} serve --config ${CONFIG_PATH}"
  fi
  kv "常用命令" "mg status | mg doctor | mg logs -f | mg restart | mg update | mg uninstall"
  section "下一步"
  log_info "如果你需要公网访问面板，请用 Nginx/Caddy 反向代理到 ${PANEL_BIND_HOST}:${PANEL_PORT}${web_path}，并启用 HTTPS。"
  log_info "如果服务启动失败，请运行：journalctl -u migate -n 80 --no-pager"
  log_info "如果核心不可用，请运行：mg doctor"
}

run_action() {
  case "$ACTION" in
    install|upgrade|reinstall)
      install_release_flow "$([ "$REGENERATE_CONFIG" -eq 1 ] && printf 'fresh' || printf 'preserve')"
      ;;
    repair-service)
      repair_service_flow
      ;;
    install-xray-only)
      require_linux_for_release
      require_root
      detect_systemd
      ensure_migate_user_group
      install_xray
      ;;
    install-singbox-only)
      require_linux_for_release
      require_root
      detect_systemd
      ensure_migate_user_group
      install_singbox
      ;;
    install-cores-only)
      require_linux_for_release
      require_root
      detect_systemd
      ensure_migate_user_group
      install_xray
      install_singbox
      ;;
    uninstall)
      uninstall_flow
      ;;
    exit)
      log_info "退出。"
      ;;
    *)
      log_error "unknown action: ${ACTION}"
      exit 2
      ;;
  esac
}

main() {
  EXTRA_ARGS=()
  EXTRA_ARGS_COUNT=0
  parse_args "$@"
  print_banner
  environment_report
  if [ "$ACTION" = "check" ]; then
    check_update
    return
  fi
  if [ "$ACTION" = "auto" ] && [ "$ASSUME_YES" -eq 0 ] && [ "$INSTALL_XRAY" -eq 0 ] && [ "$INSTALL_SINGBOX" -eq 0 ]; then
    interactive_menu
  else
    detect_existing_install || true
    if [ "$ACTION" = "auto" ]; then
      if [ "$INSTALL_XRAY" -eq 1 ] && [ "$INSTALL_SINGBOX" -eq 0 ]; then
        ACTION="install-xray-only"
      elif [ "$INSTALL_SINGBOX" -eq 1 ] && [ "$INSTALL_XRAY" -eq 0 ]; then
        ACTION="install-singbox-only"
      elif [ "$INSTALL_XRAY" -eq 1 ] && [ "$INSTALL_SINGBOX" -eq 1 ]; then
        ACTION="install-cores-only"
      else
        ACTION="install"
      fi
    fi
  fi

  case "$ACTION" in
    install|upgrade|reinstall|repair-service|install-xray-only|install-singbox-only|install-cores-only|uninstall)
      require_root
      with_install_lock run_action
      ;;
    *)
      run_action
      ;;
  esac
}

main "$@"
