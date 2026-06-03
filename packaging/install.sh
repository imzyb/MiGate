#!/usr/bin/env bash
set -euo pipefail

REPO="${MIGATE_REPO:-imzyb/MiGate}"
VERSION="${MIGATE_VERSION:-latest}"
INSTALL_DIR="${MIGATE_INSTALL_DIR:-/usr/local/migate}"
SERVICE_PATH="/etc/systemd/system/migate.service"

arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    armv7l) printf 'armv7' ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac
}

require_root() {
  [ "$(id -u)" -eq 0 ] || { echo "MiGate installer must run as root" >&2; exit 1; }
}

main() {
  require_root
  ARCH="$(arch)"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  if [ "$VERSION" = "latest" ]; then
    URL="https://github.com/${REPO}/releases/latest/download/migate-linux-${ARCH}.tar.gz"
  else
    URL="https://github.com/${REPO}/releases/download/${VERSION}/migate-linux-${ARCH}.tar.gz"
  fi

  echo "Downloading ${URL}"
  curl -fL "$URL" -o "$TMP/migate-linux-${ARCH}.tar.gz"

  systemctl stop migate 2>/dev/null || true
  rm -rf "$INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
  tar -xzf "$TMP/migate-linux-${ARCH}.tar.gz" -C "$INSTALL_DIR"
  chmod +x "$INSTALL_DIR/migate"

  cp "$INSTALL_DIR/packaging/migate.service" "$SERVICE_PATH"
  systemctl daemon-reload
  systemctl enable migate
  systemctl start migate

  echo "MiGate installed: /usr/local/migate/migate"
}

main "$@"
