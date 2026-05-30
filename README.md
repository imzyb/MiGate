# MiGate

MiGate is an integrated Xray + VPNGate + OpenVPN smart egress gateway.

See `docs/plans/2026-05-30-migate-xray-gateway-v0.1.md` for the v0.1 implementation plan.

## Development and test hosts

- This repository host is for development and unit tests only.
- Do not run real install/uninstall, OpenVPN, Xray, systemd, policy routing, firewall, or traffic-leak tests on the development host.
- Full-system lifecycle tests must run on the dedicated test VPS environment.
- Never commit or document test VPS passwords, private keys, tokens, or connection strings. Use `[REDACTED]` in docs and reports.

### Remote install dry-run

Preview the future remote installer on the dedicated test VPS without SSHing or making changes:

```bash
migate remote install
```

The command prints a side-effect-free plan with `commands_executed: []` and `performed_side_effects: False`. It redacts credential hints, rejects embedded credentials such as `user:password@host`, and keeps the staging directory under `/tmp/`.

The first gated runner shell is available only with all remote-change gates:

```bash
migate remote install --no-dry-run --yes --allow-remote-changes
```

This path executes the planned command previews in order through the runner layer and stops on the first failed step. Treat it as a test-VPS-only orchestration shell, not a production installer. It still does not implement rollback, ownership cleanup, firewall changes, policy routing, OpenVPN startup, or leak tests.

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

Real remote execution is intentionally limited in this layer. The only non-dry-run lifecycle action currently allowed is the read-only doctor phase, and it requires both gates:

```bash
migate remote lifecycle --no-dry-run --yes --allow-remote-changes
```

This command still does not install, uninstall, start Xray, start OpenVPN, edit systemd, change routes, or modify firewall state. Those phases remain behind later explicit implementations.
