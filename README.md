# MiGate

MiGate is an integrated Xray + VPNGate + OpenVPN smart egress gateway.

See `docs/plans/2026-05-30-migate-xray-gateway-v0.1.md` for the v0.1 implementation plan.

## Development and test hosts

- This repository host is for development and unit tests only.
- Do not run real install/uninstall, OpenVPN, Xray, systemd, policy routing, firewall, or traffic-leak tests on the development host.
- Full-system lifecycle tests must run on the dedicated test VPS environment.
- Never commit or document test VPS passwords, private keys, tokens, or connection strings. Use `[REDACTED]` in docs and reports.
