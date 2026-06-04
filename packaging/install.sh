#!/usr/bin/env bash
set -euo pipefail

REPO="${MIGATE_REPO:-imzyb/MiGate}"
VERSION="${MIGATE_VERSION:-latest}"
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
  "xray_config_path": "/usr/local/migate/xray.json"
}
JSON
  chmod 600 "$CONFIG_PATH"
}

main() {
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
  read -r -s -p "Panel password [hidden default]: " panel_password
  printf '\n'
  panel_password="${panel_password:-super-secret-password}"
  read -r -p "Web base path [/]: " web_base_path
  web_base_path="${web_base_path:-/}"

  if [ "$VERSION" = "latest" ]; then
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
  else
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
  fi
  URL="${BASE_URL}/${ARTIFACT}"
  CHECKSUM_URL="${BASE_URL}/checksums.txt"

  echo "Downloading ${URL}"
  curl -fL "$URL" -o "$TMP/${ARTIFACT}"
  curl -fL "$CHECKSUM_URL" -o "$TMP/checksums.txt"
  grep "migate-linux-${ARCH}.tar.gz" "$TMP/checksums.txt" > "$TMP/${ARTIFACT}.sha256"
  (cd "$TMP" && sha256sum -c "${ARTIFACT}.sha256")

  systemctl stop migate 2>/dev/null || true
  mkdir -p "$INSTALL_DIR"
  tar -xzf "$TMP/migate-linux-${ARCH}.tar.gz" -C "$TMP"
  cp "$TMP/migate" /usr/local/bin/migate
  chmod +x /usr/local/bin/migate
  write_config "$panel_port" "$panel_username" "$panel_password" "$web_base_path"

  cp "$TMP/packaging/migate.service" "$SERVICE_PATH"
  systemctl daemon-reload
  systemctl enable migate
  systemctl start migate

  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [ -z "$host_ip" ]; then
    host_ip="SERVER_IP"
  fi
  echo "MiGate installed: /usr/local/bin/migate"
  echo "WebUI: http://${host_ip}:${panel_port}${web_base_path}"
  echo "Username: ${panel_username}"
}

main "$@"
