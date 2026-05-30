# MiGate

MiGate is an integrated Xray + VPNGate + OpenVPN smart egress gateway.

See `docs/plans/2026-05-30-migate-xray-gateway-v0.1.md` for the v0.1 implementation plan.

## Development and test hosts

- This repository host is for development and unit tests only.
- Do not run real install/uninstall, OpenVPN, Xray, systemd, policy routing, firewall, or traffic-leak tests on the development host.
- Full-system lifecycle tests must run on the dedicated test VPS environment.
- Never commit or document test VPS passwords, private keys, tokens, or connection strings. Use `[REDACTED]` in docs and reports.

### Remote lifecycle dry-run

Preview the dedicated test VPS lifecycle without opening SSH or changing either host:

```bash
migate remote lifecycle
```

The command prints a side-effect-free plan with `commands_executed: []` and `performed_side_effects: False`. It redacts credential hints and rejects embedded credentials such as `user:password@host`.

Before any real remote lifecycle work, run the read-only doctor/preflight probe:

```bash
migate remote doctor
```

`remote doctor` uses SSH batch mode with a short connect timeout to inspect hostname, kernel, UID, and required command paths (`python3`, `systemctl`, `ip`, `openvpn`). It does not pass passwords, does not use `sshpass`, and reports `performed_side_effects: False`.

Custom target preview:

```bash
migate remote lifecycle --host 203.0.113.10 --port 62422 --user ubuntu
```

Real remote execution is intentionally not implemented in this layer. Keep actual install/uninstall, OpenVPN, Xray, systemd, policy routing, and leak tests off the development host and behind a later explicit double-gated remote executor.
