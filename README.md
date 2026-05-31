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

The dry-run rollout orders the currently available building blocks as `remote install -> remote readiness -> remote egress up -> remote leak-check`. It renders planned read-only vs planned side-effect phases, keeps `commands_executed: []`, and reports `performed_side_effects: False`.

The gated rollout runner shell is available only with all remote-change gates:

```bash
migate remote rollout --no-dry-run --yes --allow-remote-changes
```

This orchestration calls the already-gated remote install phase, then the read-only readiness probe, then the already-gated remote egress up phase, then the read-only public-IP leak check. It stops on the first failed phase and reports aggregated `commands_executed` plus `performed_side_effects`.

Run the gated smoke wrapper when you want a structured verification report that the rollout reached all four expected phases:

```bash
migate remote rollout-smoke
migate remote rollout-smoke --no-dry-run --yes --allow-remote-changes
```

`remote rollout-smoke` defaults to dry-run and calls no remote runner. The real path uses the same remote-change gates, delegates to the rollout runner, and fails unless the rollout completes exactly `install -> readiness -> egress_up -> leak_check`. It is a verification wrapper, not a separate SSH or credential-owning implementation.

Use the top-level acceptance workflow as the operator-facing test-VPS verification entrypoint:

```bash
migate remote acceptance
migate remote acceptance --no-dry-run --yes --allow-remote-changes
```

`remote acceptance` defaults to dry-run and calls no remote commands. The real path first runs the read-only remote doctor, stops before rollout if doctor fails, then delegates to `remote rollout-smoke`. Its report aggregates `doctor -> rollout_smoke` phases, `commands_executed`, and `performed_side_effects` so one command can be used as the current remote acceptance gate.

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

This path executes the planned command previews in order through the runner layer and stops on the first failed step. Treat it as a test-VPS-only orchestration shell, not a production installer. It still does not implement rollback, ownership cleanup, firewall changes, policy routing, or OpenVPN startup.

### VPN runtime config save

Before real egress startup, render an explicit OpenVPN `.ovpn` source into MiGate's managed runtime path:

```bash
migate vpn config save --source /tmp/vpngate.ovpn
migate vpn config save --source /tmp/vpngate.ovpn --yes --allow-system-changes
```

The command defaults to a side-effect-free preview and writes only with both gates. Rendering forces `dev tun-migate`, strips caller-supplied log/status paths, injects MiGate log/status paths, adds OpenVPN 2.5+ compatible `data-ciphers`, and adds `route-nopull` plus `pull-filter ignore redirect-gateway` so VPNGate pushed default routes cannot steal the VPS management route. `migate egress up` fails closed before OpenVPN startup if `/var/lib/migate/runtime/active.ovpn` is missing.

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

This path executes the planned command previews in order through the runner layer and stops on the first failed step. Treat it as a test-VPS-only shell for the already-gated local `migate egress` commands. It still does not own credentials, implement rollback, or bypass the local `--yes --allow-system-changes` gates.

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

Run the read-only remote leak check after egress is up:

```bash
migate remote leak-check
```

`remote leak-check` uses SSH batch mode to compare the VPS native public IP with the public IP observed through the remote local SOCKS listener. It performs no systemd, OpenVPN, routing, firewall, or file changes. If the egress IP matches the native IP, or if the egress IP cannot be verified, the check fails closed and reports `performed_side_effects: False`.

Custom target preview:

```bash
migate remote lifecycle --host 203.0.113.10 --port 62422 --user ubuntu
```

Real remote execution is intentionally limited in this layer. The only non-dry-run lifecycle action currently allowed is the read-only doctor phase, and it requires both gates:

```bash
migate remote lifecycle --no-dry-run --yes --allow-remote-changes
```

This command still does not install, uninstall, start Xray, start OpenVPN, edit systemd, change routes, or modify firewall state. Those phases remain behind later explicit implementations.
