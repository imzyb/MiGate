# MiGate

MiGate is a **Go single-binary** lightweight VPS panel that uses local SQLite and embedded WebUI to manage Xray inbounds and clients.

Currently suitable for users familiar with VPS/Xray for testing.

## Features

- Single binary deployment, no Python/Node runtime required
- WebUI management for inbounds, clients, and basic settings
- Local SQLite database
- Generate and apply Xray configuration
- Supported protocols: VLESS, VMess, Trojan, Shadowsocks, Hysteria2
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

During installation, you will be prompted for:

- Panel port, default `9999`
- Username, default `admin`
- Password, leave empty for auto-generated random password
- Web path, default `/panel`
- Whether to install Xray

After installation, access:

```text
http://SERVER_IP:9999/panel
```

## Common Commands

Check status:

```bash
systemctl status migate
```

Restart panel:

```bash
systemctl restart migate
```

View logs:

```bash
journalctl -u migate -f
```

Config file:

```text
/etc/migate/panel.json
```

Database:

```text
/usr/local/migate/migate.db
```

Xray config:

```text
/usr/local/migate/xray.json
```

## Note

MiGate currently focuses on single-machine VPS scenarios and is still under rapid iteration. It is recommended to test on a test VPS before using it for long-term services.
