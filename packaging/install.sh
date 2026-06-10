#!/usr/bin/env bash
set -euo pipefail

REPO="${MIGATE_REPO:-imzyb/MiGate}"
VERSION="${MIGATE_VERSION:-latest}"
UPDATE_ONLY=0
INSTALL_DIR="${MIGATE_INSTALL_DIR:-/usr/local/migate}"
CONFIG_DIR="${MIGATE_CONFIG_DIR:-/etc/migate}"
CONFIG_PATH="${MIGATE_CONFIG_PATH:-/etc/migate/panel.json}"
SERVICE_PATH="/etc/systemd/system/migate.service"

arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    *) echo "unsupported architecture: $(uname -m). MiGate release assets support linux/amd64 and linux/arm64." >&2; exit 1 ;;
  esac
}

require_root() {
  [ "$(id -u)" -eq 0 ] || { echo "MiGate installer must run as root" >&2; exit 1; }
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

generate_password() {
  if command -v openssl >/dev/null 2>&1; then
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

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --update)
        UPDATE_ONLY=1
        shift
        ;;
      --version)
        [ "$#" -ge 2 ] || { echo "--version requires a value" >&2; exit 2; }
        VERSION="$2"
        shift 2
        ;;
      -h|--help)
        echo "Usage: install.sh [--update] [--version vX.Y.Z]"
        exit 0
        ;;
      *)
        echo "unknown argument: $1" >&2
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

download_release_asset() {
  BASE_URL="$(release_base_url)"
  URL="${BASE_URL}/${ARTIFACT}"
  CHECKSUM_URL="${BASE_URL}/checksums.txt"

  echo "Downloading ${URL}"
  curl -fL "$URL" -o "$TMP/${ARTIFACT}"
  curl -fL "$CHECKSUM_URL" -o "$TMP/checksums.txt"
  grep "migate-linux-${ARCH}.tar.gz" "$TMP/checksums.txt" > "$TMP/${ARTIFACT}.sha256"
  (cd "$TMP" && sha256sum -c "${ARTIFACT}.sha256")
  tar -xzf "$TMP/migate-linux-${ARCH}.tar.gz" -C "$TMP"
}

install_migate_binary_from_tmp() {
  mkdir -p "$INSTALL_DIR"
  cp "$TMP/migate" /usr/local/bin/migate
  chmod +x /usr/local/bin/migate
  ln -sf /usr/local/bin/migate /usr/local/bin/mg
  if [ -f "$TMP/packaging/install.sh" ]; then
    cp "$TMP/packaging/install.sh" /usr/local/bin/migate-install
    chmod +x /usr/local/bin/migate-install
  fi
  if [ -f "$TMP/packaging/uninstall.sh" ]; then
    cp "$TMP/packaging/uninstall.sh" /usr/local/bin/migate-uninstall
    chmod +x /usr/local/bin/migate-uninstall
  fi
}

update_migate() {
  require_root
  ARCH="$(arch)"
  ARTIFACT="migate-linux-${ARCH}.tar.gz"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  echo "MiGate updater"
  download_release_asset
  systemctl stop migate 2>/dev/null || true
  install_migate_binary_from_tmp
  systemctl daemon-reload 2>/dev/null || true
  systemctl restart migate
  echo "MiGate updated"
}

write_config() {
  local panel_port="$1"
  local panel_username="$2"
  local panel_password="$3"
  local web_base_path="$4"
  mkdir -p "$CONFIG_DIR"
  cat > "$CONFIG_PATH" <<JSON
{
  "panel_port": ${panel_port},
  "panel_username": "$(json_escape "$panel_username")",
  "panel_password": "$(json_escape "$panel_password")",
  "web_base_path": "$(json_escape "$web_base_path")",
  "database_path": "/usr/local/migate/migate.db",
  "xray_config_path": "/usr/local/migate"
}
JSON
  chmod 600 "$CONFIG_PATH"
}

install_xray() {
  echo ""
  echo "Xray 是 MiGate 代理协议（VLESS / VMess / Trojan / Shadowsocks）的运行时引擎。"
  echo "未安装 Xray 时，面板仍可管理入站和客户端，但无法实际提供代理服务。"
  read -r -p "是否安装 Xray？[Y/n]: " install_xray_choice
  install_xray_choice="${install_xray_choice:-Y}"
  if [ "$install_xray_choice" != "Y" ] && [ "$install_xray_choice" != "y" ] && [ "$install_xray_choice" != "" ]; then
    echo "跳过 Xray 安装。可通过后续手动安装："
    echo "  bash -c \"\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\""
    return
  fi

  if command -v xray &>/dev/null; then
    echo "Xray 已安装 ($(xray --version 2>/dev/null | head -1))"
  else
    echo "正在安装 Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" 2>&1
    echo "Xray 安装完成"
  fi

  # Symlink MiGate's xray.json to Xray's default config path.
  # MiGate Apply() writes to /usr/local/migate/xray.json.
  # Xray's official installer starts with /usr/local/etc/xray/xray.json.
  # Keep config.json too for compatibility with older MiGate installs and docs.
  mkdir -p /usr/local/etc/xray
  ln -sf /usr/local/migate/xray.json /usr/local/etc/xray/xray.json
  ln -sf /usr/local/migate/xray.json /usr/local/etc/xray/config.json
  echo "Xray 配置已关联到 MiGate: /usr/local/etc/xray/xray.json → /usr/local/migate/xray.json"

  systemctl enable xray 2>/dev/null || true
  systemctl restart xray 2>/dev/null || true
  echo "Xray 服务已启动"
}

install_singbox() {
  echo ""
  echo "sing-box 是 MiGate Hysteria2 / TUIC / ShadowTLS 等协议的运行时引擎。"
  echo "未安装 sing-box 时，这些协议可创建但不会实际监听。"
  read -r -p "是否安装 sing-box？[Y/n]: " install_singbox_choice
  install_singbox_choice="${install_singbox_choice:-Y}"
  if [ "$install_singbox_choice" != "Y" ] && [ "$install_singbox_choice" != "y" ] && [ "$install_singbox_choice" != "" ]; then
    echo "跳过 sing-box 安装。"
    return
  fi

  if command -v sing-box >/dev/null 2>&1; then
    echo "sing-box 已安装 ($(sing-box version 2>/dev/null | head -1))"
  else
    echo "正在安装 sing-box..."
    tmp_sb="$(mktemp -d)"
    sb_arch="$(arch)"
    case "$sb_arch" in
      amd64) sb_asset_arch="amd64" ;;
      arm64) sb_asset_arch="arm64" ;;
      *) echo "unsupported sing-box architecture: $sb_arch" >&2; return 1 ;;
    esac
    sb_version="${SINGBOX_VERSION:-1.13.13}"
    sb_url="https://github.com/SagerNet/sing-box/releases/download/v${sb_version}/sing-box-${sb_version}-linux-${sb_asset_arch}.tar.gz"
    curl -fL "$sb_url" -o "$tmp_sb/sing-box.tar.gz"
    tar -xzf "$tmp_sb/sing-box.tar.gz" -C "$tmp_sb"
    cp "$tmp_sb"/sing-box-*/sing-box /usr/local/bin/sing-box
    chmod +x /usr/local/bin/sing-box
    rm -rf "$tmp_sb"
    echo "sing-box 安装完成"
  fi

  mkdir -p /etc/sing-box
  if [ ! -f /etc/sing-box/config.json ]; then
    cat > /etc/sing-box/config.json <<'JSON'
{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}
JSON
  fi
  cat > /etc/systemd/system/migate-singbox.service <<'UNIT'
[Unit]
Description=MiGate managed sing-box service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable migate-singbox
  systemctl restart migate-singbox 2>/dev/null || true
  echo "sing-box 服务已配置：migate-singbox.service"
}

main() {
  parse_args "$@"
  if [ "$UPDATE_ONLY" = "1" ]; then
    update_migate
    return
  fi

  require_root
  ARCH="$(arch)"
  ARTIFACT="migate-linux-${ARCH}.tar.gz"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  echo "MiGate installer"
  read -r -p "Panel port [9999]: " panel_port
  panel_port="${panel_port:-9999}"
  read -r -p "Panel username [admin]: " panel_username
  panel_username="${panel_username:-admin}"
  read -r -s -p "Panel password [leave blank to generate]: " panel_password
  printf '\n'
  if [ -z "$panel_password" ]; then
    panel_password="$(generate_password)"
    echo "No password entered; generated a random panel password."
  fi
  read -r -p "Web base path [/panel]: " web_base_path
  web_base_path="${web_base_path:-/panel}"
  web_base_path="$(normalize_web_base_path "$web_base_path")"

  download_release_asset

  systemctl stop migate 2>/dev/null || true
  install_migate_binary_from_tmp
  write_config "$panel_port" "$panel_username" "$panel_password" "$web_base_path"

  cp "$TMP/packaging/migate.service" "$SERVICE_PATH"
  systemctl daemon-reload
  systemctl enable migate
  systemctl start migate

  install_xray
  install_singbox

  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [ -z "$host_ip" ]; then
    host_ip="SERVER_IP"
  fi
  echo ""
  echo "MiGate installed: /usr/local/bin/migate"
  echo "CLI: mg"
  echo "Useful commands: mg status | mg logs | mg restart | mg uninstall"
  echo "WebUI: http://${host_ip}:${panel_port}${web_base_path}"
  echo "Username: ${panel_username}"
  echo "Password: ${panel_password}"
  if command -v xray &>/dev/null; then
    echo "Xray: $(xray --version 2>/dev/null | head -1)"
  fi
  if command -v sing-box &>/dev/null; then
    echo "Sing-box: $(sing-box version 2>/dev/null | head -1)"
  fi
}

main "$@"