# MiGate

MiGate is a **Go single-binary** lightweight VPS panel that uses local SQLite
and embedded WebUI to manage Xray and sing-box inbounds, clients, shared
outbound profiles, routing, and generated core configs.

Currently suitable for users familiar with VPS/Xray for testing.

## Features

- Single binary deployment, no Python/Node runtime required
- React WebUI for inbounds, clients, outbounds, SOCKS5 pool import, routing, Xray/sing-box core config, TLS certificates, settings, sessions, and updates
- Local SQLite database
- Generate and apply Xray and sing-box configuration from shared panel resources
- Supported inbound protocols: VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, ShadowTLS
- systemd service management

## One-Click Install

Run as root on Linux VPS:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/packaging/install.sh)
```

Install specific version:

```bash
MIGATE_VERSION=v1.0.21 bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/packaging/install.sh)
```

The installer runs an environment check, detects existing MiGate installs, keeps
`/etc/migate/panel.json` by default, checks Xray and sing-box, and then asks what
to do. On an existing host it can upgrade, reinstall, regenerate config, repair
systemd, install/repair cores, uninstall, or exit.

Common non-interactive commands:

```bash
# Install or upgrade while keeping existing config.
bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/packaging/install.sh) --install --yes

# Preview install actions without changing the system.
bash <(curl -Ls https://raw.githubusercontent.com/imzyb/MiGate/main/packaging/install.sh) --install --yes --dry-run

# Upgrade to latest release and keep config.
migate-install --upgrade --yes

# Repair the systemd unit only.
migate-install --repair-service --yes

# Install or repair runtime cores only. This does not install MiGate itself.
migate-install --install-xray --yes
migate-install --install-singbox --yes

# Uninstall service and binaries while keeping config/data.
migate-install --uninstall --yes
```

During first installation, you will be prompted for:

- Panel port, default `9999`
- Username, default `admin`
- Password, leave empty for auto-generated random password
- Web path, default `/panel`
- Whether to install/repair Xray and sing-box

After installation, access:

```text
http://127.0.0.1:9999/panel
```

The panel service binds to `0.0.0.0` by default for direct VPS panel access. For
production use, set a strong password and prefer a reverse proxy such as Nginx or
Caddy with HTTPS. Set
`public_host` in `/etc/migate/panel.json` so subscription share links use your
public domain or address. If MiGate is behind a trusted HTTPS reverse proxy, set
`trust_proxy` to `true` so Secure cookies and HSTS can use `X-Forwarded-Proto`.
`migate serve --host 0.0.0.0` remains available only when you intentionally
override the safer default.
Management direct protection is documented in `docs/config-contract.md`.

## Common Commands

Check status and diagnostics:

```bash
mg status
mg doctor
mg info
mg ports
systemctl status migate
```

Restart panel:

```bash
mg restart
mg restart all
systemctl restart migate
```

View logs:

```bash
mg logs -f
journalctl -u migate -f
```

Update, backup, and restore:

```bash
mg update
mg update --check
mg backup
mg restore /var/lib/migate/backups/migate-backup-YYYYMMDD-HHMMSS.tar.gz
```

`mg backup` includes `/etc/migate`, `/var/lib/migate/migate.db`, and
`/var/lib/migate/versions.json` by default, and writes archives under
`/var/lib/migate/backups`. `mg uninstall` removes services and binaries while
keeping config/data/logs unless the uninstaller is run with `--purge`.

These paths and services are the MiGate Runtime Contract and MiGate Ops
Contract. Standard systemd services are `migate`, `migate-xray`, and
`migate-sing-box`.

Config file:

```text
/etc/migate/panel.json
```

Database:

```text
/var/lib/migate/migate.db
```

Install state:

```text
/var/lib/migate/versions.json
```

Backups:

```text
/var/lib/migate/backups
```

Xray config:

```text
/etc/migate/cores/xray.json
```

sing-box config:

```text
/etc/migate/cores/sing-box.json
```

More details: `docs/install.md`.

## Development

The WebUI source lives in `web/` and builds into `internal/web/static/dist`, which is embedded into the Go binary.

```bash
npm run dev        # start local Go API and Vite WebUI for manual testing
make web-install   # install frontend dependencies
make web-dev       # start Vite dev server
make web-build     # build embedded frontend dist
make go-build      # build final migate binary
make test          # run frontend and Go tests
```

`npm run dev` creates a local `.dev/panel.json` and `.dev/migate-dev.db`, starts
the backend on `http://127.0.0.1:9999`, and starts the WebUI on
`http://127.0.0.1:5173/panel/`. The default local login is
`admin` / `admin123`.

Node/npm are only build-time tools for contributors and release automation. The one-click installer and VPS runtime continue to use the Go single binary only.

See `docs/frontend-refactor.md` for the split frontend/backend architecture and
`docs/dual-core-outbound-model.md` for the dual-core inbound and shared outbound
model.

## Note

MiGate currently focuses on single-machine VPS scenarios and is still under rapid iteration. It is recommended to test on a test VPS before using it for long-term services.
