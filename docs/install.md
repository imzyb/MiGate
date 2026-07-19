# MiGate Install Guide

MiGate ships as a Go single binary with the WebUI embedded. The installer is
intended for Linux VPS hosts and focuses on repeatable install, upgrade, repair,
core detection, and safe config handling.

## One-Click Install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/packaging/install.sh)
```

Install a specific release:

```bash
MIGATE_VERSION=v1.0.21 bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/packaging/install.sh)
```

The interactive flow prints these stages:

- `环境检测`: OS, architecture, root, systemd, and command dependencies.
- `已安装检测`: binary, CLI link, systemd service, config dir, `panel.json`, database, running process, and panel port.
- `配置确认`: first install creates `panel.json`; existing config is kept unless you choose fresh config.
- `核心检测`: Xray and sing-box binary paths, versions, and services.
- `安装 MiGate`: release asset download, checksum verification, binary replacement, config, and service unit.
- `服务启动`: daemon reload, enable, restart, and status check when systemd exists.
- `完成`: WebUI URL, username, password behavior, paths, service commands, and logs.

## Existing Installs

When MiGate is already detected, the installer shows:

```text
1) 升级并保留配置
2) 重装并保留配置
3) 重装并重新生成配置
4) 只修复 systemd 服务
5) 只安装/修复 Xray
6) 只安装/修复 sing-box
7) 卸载
8) 退出
```

By default, existing `/etc/migate/panel.json` is preserved. Choose fresh config
only when you explicitly want a new panel password, port, username, and paths.

## Non-Interactive Mode

```bash
migate-install --install --yes
migate-install --upgrade --yes
migate-install --reinstall --yes
migate-install --reinstall --fresh-config --yes
migate-install --repair-service --yes
migate-install --install-xray --yes
migate-install --install-singbox --yes
migate-install --uninstall --yes                         # panel only
migate-install --uninstall -- --with-cores --yes         # panel + cores
migate-install --uninstall -- --purge --yes              # panel + cores + config/data/logs
```

`--install-xray` and `--install-singbox` by themselves are core-only repair
modes. They do not install or upgrade the MiGate panel unless they are combined
with `--install`, `--upgrade`, or `--reinstall`.

Preview without changing the system:

```bash
migate-install --install --yes --dry-run
migate-install --upgrade --yes --dry-run
migate-install --uninstall --yes --dry-run
migate-install --uninstall --dry-run                     # asks for 1/2/3
migate-install --uninstall -- --with-cores --yes --dry-run
migate-install --install-xray --yes --dry-run
migate-install --install-singbox --yes --dry-run
```

`--dry-run` prints the commands that would be run and does not install binaries,
write config, stop services, or remove files.

## Config Paths

The MiGate Runtime Contract and MiGate Ops Contract use these default paths:

```text
Binary:        /usr/local/bin/migate
CLI alias:     /usr/local/bin/mg
Installer:     /usr/local/bin/migate-install
Uninstaller:   /usr/local/bin/migate-uninstall
Config:        /etc/migate/panel.json
Database:      /var/lib/migate/migate.db
Versions:      /var/lib/migate/versions.json
Backups:       /var/lib/migate/backups
Certificates:  /etc/migate/certs
Xray config:   /etc/migate/cores/xray.json
sing-box config: /etc/migate/cores/sing-box.json
Web base path: /panel
```

First install writes a random password when the password prompt is left blank.
The generated password is printed once at the end of installation and is not
stored anywhere except `panel.json`.

The installer writes `/var/lib/migate/versions.json` after a completed install or
upgrade. It records the MiGate version, configured core versions, install time,
and installer version. Invalid core configs repaired during install are moved to
`/var/lib/migate/backups` with names such as
`xray-config-invalid-YYYYMMDD-HHMMSS.json`; `mg backup` still writes archives as
`migate-backup-YYYYMMDD-HHMMSS.tar.gz`.

## systemd

The installer writes or repairs:

```text
/etc/systemd/system/migate.service
```

The generated systemd service listens on `0.0.0.0:9999` by default for VPS panel-style
access, and the default web base path is `/panel` (for example,
`http://<your-server-ip>:9999/panel`; from the server itself,
`http://127.0.0.1:9999/panel`). For production use, set a strong password and prefer publishing through a
reverse proxy with HTTPS. Use
`public_host` in `/etc/migate/panel.json` to control the host embedded in
subscription share links. If the proxy terminates HTTPS, set `trust_proxy` to
`true` only when MiGate is reachable exclusively through that trusted proxy, so
the service can honor `X-Forwarded-Proto` for Secure cookies and HSTS. Passing
`migate serve --host 0.0.0.0` is still supported for explicit deployments that
accept that exposure.

Useful commands:

```bash
systemctl status migate
systemctl restart migate
journalctl -u migate -f
mg status
mg doctor
mg info
mg ports
mg logs -f
mg restart
mg restart all
```

If systemd is unavailable, the installer skips service creation and prints a
manual command:

```bash
/usr/local/bin/migate serve --config /etc/migate/panel.json
```

## Xray and sing-box

The installer checks:

```text
/usr/local/bin/xray
/usr/bin/xray
/usr/local/bin/sing-box
/usr/bin/sing-box
migate-xray.service
migate-sing-box.service
```

Version commands:

```bash
xray version
sing-box version
```

Xray installation downloads the configured official XTLS release ZIP, downloads
the corresponding `.dgst` checksum file, verifies the archive, installs
`/usr/local/bin/xray`, writes the dedicated `migate-xray.service`, and records a
MiGate ownership marker under `/var/lib/migate/managed`. It does not execute the
upstream Xray install script.

sing-box installation downloads the configured release archive, reads the GitHub
Release asset digest, verifies the archive before extracting, installs
`/usr/local/bin/sing-box`, writes `migate-sing-box.service`, and records the same
kind of MiGate ownership marker.

MiGate, Xray, and sing-box release archives are installed only after checksum
verification. Certificate issuance no longer depends on `acme.sh`; the WebUI
uses MiGate's Go native ACME HTTP-01 issuer and stores managed certificate
assets under `/etc/migate/certs`. HTTP-01 still requires public DNS resolution
for the requested domain and temporary access to TCP port 80 on the host.

Skipping core installation does not block the panel installation. Xray-backed
protocols or sing-box-backed protocols may not listen until the relevant core is
installed and configuration is applied.

## Uninstall

Default uninstall removes MiGate services and binaries while keeping config and
data:

```bash
mg uninstall --yes
# or
migate-install --uninstall --yes
```

Purge config/data only when you explicitly intend to delete them:

```bash
migate-uninstall --purge --yes
```

`--with-cores` and `--purge` remove only core binaries that have MiGate ownership markers. Existing third-party or manually installed `xray`/`sing-box` binaries are left in place even when MiGate removes `migate-xray.service` and `migate-sing-box.service`.

## Update, Backup, and Restore

The CLI update commands delegate to the installer entrypoint:

```bash
mg update          # migate-install --update
mg update vX.Y.Z   # migate-install --update --version vX.Y.Z
mg update --check  # migate-install --check, read-only
```

The WebUI update action uses the same installer entrypoint through the update
service. HTTP handlers only validate and accept the request; update planning and
execution stay in the service layer.

Backups default to `/var/lib/migate/backups`:

```bash
mg backup
mg backup /tmp/migate-backup.tar.gz
mg restore /tmp/migate-backup.tar.gz
```

Default backup scope is exactly:

```text
/etc/migate
/var/lib/migate/migate.db
/var/lib/migate/versions.json
```

`/run/migate` and unrelated system files are not included. Restore extracts the
archive to `/` and restarts the standard `migate` service. Use
`mg restart all` if restored core configs should be reloaded immediately.

## Troubleshooting

Check local diagnostics:

```bash
mg doctor
```

Check service logs:

```bash
journalctl -u migate -n 80 --no-pager
journalctl -u migate -f
```

Common issues:

- Port already in use: choose a different `panel_port` or stop the conflicting service.
- systemd unavailable: run MiGate manually or configure your platform's service manager.
- Core skipped or missing: install Xray or sing-box and apply config from the WebUI Core page.
- Lost generated password: run `mg reset-password` on the server.
