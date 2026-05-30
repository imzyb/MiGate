# MiGate

MiGate is an integrated Xray + VPNGate + OpenVPN smart egress gateway.

See `docs/plans/2026-05-30-migate-xray-gateway-v0.1.md` for the v0.1 implementation plan.

## Development and test hosts

- This repository host is for development and unit tests only.
- Do not run real install/uninstall, OpenVPN, Xray, systemd, policy routing, firewall, or traffic-leak tests on the development host.
- Full-system lifecycle tests must run on the dedicated test VPS environment.
- Never commit or document test VPS passwords, private keys, tokens, or connection strings. Use `[REDACTED]` in docs and reports.

### Egress lifecycle orchestration

The egress lifecycle layer now composes already-tested lower-level phases:

- `bring_up_egress`: OpenVPN start -> policy routing apply
- `bring_down_egress`: policy routing cleanup -> OpenVPN stop

The layer requires `allow_side_effects=True`, stops on the first failed phase, aggregates `commands_executed` from phase results, and keeps phase result objects attached for later CLI/panel rendering. It supports separate injected runners for OpenVPN vs routing phases while preserving the older shared `runner=` path. It does not build raw commands, arm firewall rules, invent leak-guard state, or talk to systemd/panels directly.

### Remote rollout dry-run

Preview the full remote promotion flow without SSHing or changing the test VPS:

```bash
migate remote rollout
```

The dry-run rollout orders the currently available building blocks as `remote install -> remote readiness -> remote egress up`. It renders planned read-only vs planned side-effect phases, keeps `commands_executed: []`, and reports `performed_side_effects: False`. Real rollout execution is intentionally rejected until a dedicated runner layer is implemented.

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

### Remote egress dry-run

Preview remote egress operations after installation without opening SSH or changing the test VPS:

```bash
migate remote egress up
migate remote egress down
```

These commands print side-effect-free plans with `commands_executed: []` and `performed_side_effects: False`. They preview the future remote calls to gated local commands such as `migate egress up --no-dry-run --yes --allow-system-changes`, but the remote planning layer itself never SSHs, starts OpenVPN, changes policy routing, or performs leak tests.

A gated remote egress runner shell is available only with all remote-change gates:

```bash
migate remote egress up --no-dry-run --yes --allow-remote-changes
migate remote egress down --no-dry-run --yes --allow-remote-changes
```

This path executes the planned command previews in order through the runner layer and stops on the first failed step. Treat it as a test-VPS-only shell for the already-gated local `migate egress` commands. It still does not own credentials, implement rollback, verify traffic leaks, or bypass the local `--yes --allow-system-changes` gates.

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

For post-install readiness, run the read-only promotion probe:

```bash
migate remote readiness
```

`remote readiness` checks whether the test VPS can see the MiGate CLI, Xray, OpenVPN, systemd, `ip`, service previews, and local egress status. It still uses SSH batch mode, performs no install/start/route/firewall changes, and reports `performed_side_effects: False`.

Custom target preview:

```bash
migate remote lifecycle --host 203.0.113.10 --port 62422 --user ubuntu
```

Real remote execution is intentionally limited in this layer. The only non-dry-run lifecycle action currently allowed is the read-only doctor phase, and it requires both gates:

```bash
migate remote lifecycle --no-dry-run --yes --allow-remote-changes
```

This command still does not install, uninstall, start Xray, start OpenVPN, edit systemd, change routes, or modify firewall state. Those phases remain behind later explicit implementations.
