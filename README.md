# MiGate

MiGate is being rewritten as a **Go single-binary** VPS panel with a **轻量面板-style** architecture.

## Scope

Core protocols:

- VLESS
- VMess
- Trojan
- Shadowsocks

Core features:

- Single Go binary: `/usr/local/migate/migate`
- Embedded/static web UI
- SQLite local database
- Xray config generation and process control
- Subscription endpoints
- Lightweight install from release tarball

## Explicitly not included in Lite rewrite

- Not included: OpenVPN
- Not included: TUN
- Not included: egress tunnel
- Not included: remote readiness
- Not included: leak check
- Not included: rollout plan
- Not included: proxy service
- Not included: multi-node remote checks

The installer must not clone source or install Python/Node dependencies on small VPSes.
