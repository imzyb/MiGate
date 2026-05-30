# MiGate Xray Integrated Gateway v0.1 Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build MiGate as an all-in-one Xray + VPNGate + OpenVPN + policy-routing smart egress gateway, so users can create inbound nodes, bind them to VPNGate exits, and generate share/subscription links without separately installing 3x-ui.

**Architecture:** MiGate manages xray-core for client-facing inbound nodes, manages OpenVPN tunnels for VPNGate exits, and connects both through a local leak-safe SOCKS5/HTTP egress gateway. Xray outbounds point to MiGate's local SOCKS5 proxy, and MiGate ensures proxy traffic only leaves through the OpenVPN tun interface.

**Tech Stack:** Python 3.11+, FastAPI, Typer, SQLite, pytest, pydantic, xray-core, OpenVPN, iproute2 policy routing, nftables/iptables fallback, systemd.

---

## Product Scope

MiGate v0.1 is not a full 3x-ui clone. It is a focused one-stop gateway:

1. Create Xray inbound nodes.
2. Create/manage Xray users.
3. Automatically route Xray traffic through MiGate VPNGate egress.
4. Automatically collect/test/select VPNGate OpenVPN exits.
5. Prevent fallback leaks to the VPS native IP.
6. Generate share links and subscription links.
7. Provide CLI and minimal Web API/Web UI.

## Primary Data Path

```text
[Client]
   │ VLESS / Trojan / Shadowsocks
   ▼
[xray-core inbound]
   │ outbound: socks -> 127.0.0.1:7929
   ▼
[MiGate local SOCKS5/HTTP egress proxy]
   │ bound/guarded to tun-migate
   ▼
[OpenVPN tunnel]
   ▼
[VPNGate exit]
   ▼
[Internet]
```

## Security Invariants

These are non-negotiable:

1. If OpenVPN is down, MiGate egress proxy must reject traffic.
2. If `tun-migate` does not exist, MiGate egress proxy must reject traffic.
3. If detected egress IP equals VPS native public IP, MiGate must mark this as leak and stop egress.
4. Xray must not have a direct `freedom` fallback for user traffic by default.
5. System default route must not be replaced by the VPN tunnel.
6. SSH and server management traffic must continue using the original VPS route.

## Recommended Repository Layout

```text
MiGate/
├── migate/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── paths.py
│   ├── logging.py
│   ├── models.py
│   │
│   ├── database/
│   │   ├── db.py
│   │   ├── schema.sql
│   │   └── repository.py
│   │
│   ├── vpngate/
│   │   ├── collector.py
│   │   ├── parser.py
│   │   ├── probe.py
│   │   ├── scorer.py
│   │   └── manager.py
│   │
│   ├── vpn/
│   │   ├── openvpn.py
│   │   ├── config_render.py
│   │   └── process.py
│   │
│   ├── routing/
│   │   ├── policy.py
│   │   ├── firewall.py
│   │   └── leak_guard.py
│   │
│   ├── egress/
│   │   ├── socks5.py
│   │   ├── http.py
│   │   ├── bind.py
│   │   └── service.py
│   │
│   ├── xray/
│   │   ├── core.py
│   │   ├── config_builder.py
│   │   ├── inbounds.py
│   │   ├── outbounds.py
│   │   ├── users.py
│   │   ├── links.py
│   │   ├── subscription.py
│   │   └── stats.py
│   │
│   ├── api/
│   │   ├── app.py
│   │   ├── auth.py
│   │   ├── routes_nodes.py
│   │   ├── routes_users.py
│   │   ├── routes_exits.py
│   │   └── routes_status.py
│   │
│   └── cli/
│       └── commands.py
│
├── systemd/
│   ├── migate.service
│   ├── migate-xray.service
│   └── migate-egress.service
│
├── scripts/
│   ├── install.sh
│   ├── uninstall.sh
│   └── doctor.sh
│
├── tests/
│   ├── test_vpngate_parser.py
│   ├── test_xray_config_builder.py
│   ├── test_xray_links.py
│   ├── test_subscription.py
│   ├── test_policy_routing.py
│   └── test_leak_guard.py
│
├── docs/
│   └── plans/
├── pyproject.toml
├── README.md
└── LICENSE
```

## Runtime Paths

```text
/etc/migate/config.yaml
/etc/migate/xray/config.json
/var/lib/migate/migate.db
/var/lib/migate/runtime/active.ovpn
/var/lib/migate/runtime/openvpn.pid
/var/lib/migate/runtime/status.json
/var/log/migate/migate.log
/var/log/migate/xray.log
```

## Initial Configuration

```yaml
proxy:
  http_host: "127.0.0.1"
  http_port: 7928
  socks_host: "127.0.0.1"
  socks_port: 7929

xray:
  enabled: true
  bin_path: "/usr/local/bin/xray"
  config_path: "/etc/migate/xray/config.json"
  api_host: "127.0.0.1"
  api_port: 10085
  default_outbound_tag: "migate-vpngate"
  block_direct_fallback: true

vpn:
  interface: "tun-migate"
  route_table: 100
  fwmark: "0x66"
  reconnect_interval: 30
  max_failures_per_node: 3

collector:
  source: "https://www.vpngate.net/api/iphone/"
  refresh_interval: 600
  max_nodes: 300

probe:
  concurrency: 32
  connect_timeout: 5
  handshake_timeout: 20
  max_latency_ms: 500

security:
  leak_guard: true
  fail_policy: "block"
  web_bind: "127.0.0.1"
  web_port: 8787
  secret_path: "auto"
```

## Database Schema Draft

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  traffic_limit_bytes INTEGER,
  traffic_used_bytes INTEGER NOT NULL DEFAULT 0,
  expire_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE xray_inbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tag TEXT NOT NULL UNIQUE,
  protocol TEXT NOT NULL,
  listen TEXT NOT NULL DEFAULT '0.0.0.0',
  port INTEGER NOT NULL,
  transport TEXT NOT NULL DEFAULT 'tcp',
  tls_mode TEXT NOT NULL DEFAULT 'none',
  settings_json TEXT NOT NULL DEFAULT '{}',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE xray_clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  inbound_id INTEGER NOT NULL REFERENCES xray_inbounds(id),
  user_id INTEGER REFERENCES users(id),
  email TEXT NOT NULL,
  credential TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  traffic_limit_bytes INTEGER,
  expire_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE vpngate_nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  country TEXT,
  ip TEXT,
  hostname TEXT,
  score REAL NOT NULL DEFAULT 0,
  latency_ms INTEGER,
  ovpn_config TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  failure_count INTEGER NOT NULL DEFAULT 0,
  last_seen_at TEXT,
  last_tested_at TEXT
);

CREATE TABLE egress_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  mode TEXT NOT NULL DEFAULT 'auto',
  country_filter TEXT,
  current_vpngate_node_id INTEGER REFERENCES vpngate_nodes(id),
  fail_policy TEXT NOT NULL DEFAULT 'block',
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE routing_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  inbound_tag TEXT,
  user_id INTEGER REFERENCES users(id),
  outbound_tag TEXT NOT NULL,
  egress_profile_id INTEGER REFERENCES egress_profiles(id),
  enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  token TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
```

---

# Implementation Tasks

## Phase 0: Project Bootstrap

### Task 1: Create Python project skeleton

**Objective:** Create the initial package, test layout, and development tooling.

**Files:**
- Create: `pyproject.toml`
- Create: `migate/__init__.py`
- Create: `migate/main.py`
- Create: `tests/test_import.py`

**Step 1: Write failing test**

```python
# tests/test_import.py

def test_migate_package_imports():
    import migate

    assert migate.__version__
```

**Step 2: Run test to verify failure**

Run:

```bash
pytest tests/test_import.py::test_migate_package_imports -v
```

Expected: FAIL because package/version does not exist.

**Step 3: Write minimal implementation**

```python
# migate/__init__.py
__version__ = "0.1.0"
```

**Step 4: Run test to verify pass**

```bash
pytest tests/test_import.py::test_migate_package_imports -v
```

Expected: PASS.

---

### Task 2: Add typed configuration model

**Objective:** Define validated config defaults for proxy, xray, vpn, collector, probe, and security sections.

**Files:**
- Create: `migate/config.py`
- Test: `tests/test_config.py`

**Step 1: Write failing test**

```python
from migate.config import MiGateConfig


def test_default_config_routes_xray_to_migate_socks():
    cfg = MiGateConfig()

    assert cfg.xray.default_outbound_tag == "migate-vpngate"
    assert cfg.proxy.socks_host == "127.0.0.1"
    assert cfg.proxy.socks_port == 7929
    assert cfg.security.fail_policy == "block"
```

**Step 2: Verify RED**

```bash
pytest tests/test_config.py::test_default_config_routes_xray_to_migate_socks -v
```

Expected: FAIL because `MiGateConfig` does not exist.

**Step 3: Implement minimal pydantic config classes**

Use `pydantic.BaseModel` and defaults matching the YAML above.

**Step 4: Verify GREEN**

```bash
pytest tests/test_config.py -v
```

Expected: PASS.

---

## Phase 1: VPNGate Collection and Node Model

### Task 3: Parse VPNGate CSV response

**Objective:** Convert VPNGate API CSV text into normalized node objects with decoded OpenVPN config.

**Files:**
- Create: `migate/vpngate/parser.py`
- Test: `tests/test_vpngate_parser.py`

**Step 1: Write failing test**

```python
from base64 import b64encode
from migate.vpngate.parser import parse_vpngate_csv


def test_parse_vpngate_csv_decodes_openvpn_config():
    ovpn = "client\ndev tun\nremote 1.2.3.4 1194 udp\n"
    encoded = b64encode(ovpn.encode()).decode()
    csv_text = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
    csv_text += f"vpn.example,1.2.3.4,123,45,999,Japan,JP,1,1000,10,1000,2,op,msg,{encoded}\n"
    csv_text += "*\n"

    nodes = parse_vpngate_csv(csv_text)

    assert len(nodes) == 1
    assert nodes[0].ip == "1.2.3.4"
    assert nodes[0].country == "Japan"
    assert "remote 1.2.3.4" in nodes[0].ovpn_config
```

**Step 2: Verify RED**

```bash
pytest tests/test_vpngate_parser.py::test_parse_vpngate_csv_decodes_openvpn_config -v
```

Expected: FAIL because parser does not exist.

**Step 3: Implement parser**

Create a small dataclass or pydantic model `VPNGateNodeCandidate` and parse rows until `*`.

**Step 4: Verify GREEN**

```bash
pytest tests/test_vpngate_parser.py -v
```

Expected: PASS.

---

### Task 4: Score VPNGate candidates

**Objective:** Rank nodes by latency, speed, uptime, and failure count.

**Files:**
- Create: `migate/vpngate/scorer.py`
- Test: `tests/test_vpngate_scorer.py`

**Step 1: Write failing test**

```python
from migate.vpngate.scorer import score_node


def test_score_penalizes_high_latency_and_failures():
    fast = score_node(latency_ms=80, speed=1000000, uptime=100000, failure_count=0)
    slow_failed = score_node(latency_ms=900, speed=1000000, uptime=100000, failure_count=3)

    assert fast > slow_failed
```

**Step 2:** Verify RED.

**Step 3:** Implement simple deterministic scoring.

**Step 4:** Verify GREEN.

---

## Phase 2: Xray Configuration and Links

### Task 5: Generate Xray outbound to MiGate SOCKS5

**Objective:** Build a valid Xray outbound object that routes through MiGate local SOCKS5.

**Files:**
- Create: `migate/xray/config_builder.py`
- Test: `tests/test_xray_config_builder.py`

**Step 1: Write failing test**

```python
from migate.config import MiGateConfig
from migate.xray.config_builder import build_migate_socks_outbound


def test_build_migate_socks_outbound_uses_local_socks_proxy():
    cfg = MiGateConfig()

    outbound = build_migate_socks_outbound(cfg)

    assert outbound["tag"] == "migate-vpngate"
    assert outbound["protocol"] == "socks"
    assert outbound["settings"]["servers"][0]["address"] == "127.0.0.1"
    assert outbound["settings"]["servers"][0]["port"] == 7929
```

**Step 2:** Verify RED.

**Step 3:** Implement outbound builder.

**Step 4:** Verify GREEN.

---

### Task 6: Generate minimal VLESS TCP inbound

**Objective:** Create a VLESS inbound with one client and no direct fallback.

**Files:**
- Modify: `migate/xray/config_builder.py`
- Test: `tests/test_xray_config_builder.py`

**Step 1: Write failing test**

```python
from migate.xray.config_builder import build_vless_tcp_inbound


def test_build_vless_tcp_inbound_contains_client_uuid_and_tag():
    inbound = build_vless_tcp_inbound(
        tag="vless-main",
        port=443,
        client_uuid="00000000-0000-4000-8000-000000000001",
        email="sam@example.com",
    )

    assert inbound["tag"] == "vless-main"
    assert inbound["protocol"] == "vless"
    assert inbound["port"] == 443
    assert inbound["settings"]["decryption"] == "none"
    assert inbound["settings"]["clients"][0]["id"] == "00000000-0000-4000-8000-000000000001"
```

**Step 2:** Verify RED.

**Step 3:** Implement minimal VLESS inbound builder.

**Step 4:** Verify GREEN.

---

### Task 7: Build full Xray config with blocked fallback

**Objective:** Ensure user traffic only routes to `migate-vpngate` and includes blackhole for blocking.

**Files:**
- Modify: `migate/xray/config_builder.py`
- Test: `tests/test_xray_config_builder.py`

**Step 1: Write failing test**

```python
from migate.config import MiGateConfig
from migate.xray.config_builder import build_full_config, build_vless_tcp_inbound


def test_full_xray_config_routes_inbound_to_migate_and_has_no_freedom():
    cfg = MiGateConfig()
    inbound = build_vless_tcp_inbound(
        tag="vless-main",
        port=443,
        client_uuid="00000000-0000-4000-8000-000000000001",
        email="sam@example.com",
    )

    config = build_full_config(cfg, inbounds=[inbound])

    protocols = {outbound["protocol"] for outbound in config["outbounds"]}
    assert "freedom" not in protocols
    assert "blackhole" in protocols
    assert config["routing"]["rules"][0]["outboundTag"] == "migate-vpngate"
```

**Step 2:** Verify RED.

**Step 3:** Implement full config builder.

**Step 4:** Verify GREEN.

---

### Task 8: Generate VLESS share links

**Objective:** Generate client-consumable VLESS links for created nodes.

**Files:**
- Create: `migate/xray/links.py`
- Test: `tests/test_xray_links.py`

**Step 1: Write failing test**

```python
from migate.xray.links import build_vless_link


def test_build_vless_link_contains_uuid_host_port_and_name():
    link = build_vless_link(
        uuid="00000000-0000-4000-8000-000000000001",
        host="example.com",
        port=443,
        name="MiGate-JP",
        security="none",
        network="tcp",
    )

    assert link.startswith("vless://00000000-0000-4000-8000-000000000001@example.com:443")
    assert "type=tcp" in link
    assert "security=none" in link
    assert link.endswith("#MiGate-JP")
```

**Step 2:** Verify RED.

**Step 3:** Implement URL builder with URL-encoded query/name.

**Step 4:** Verify GREEN.

---

### Task 9: Generate base64 subscription response

**Objective:** Combine user links into a subscription document compatible with common clients.

**Files:**
- Create: `migate/xray/subscription.py`
- Test: `tests/test_subscription.py`

**Step 1: Write failing test**

```python
import base64
from migate.xray.subscription import build_base64_subscription


def test_build_base64_subscription_encodes_links_line_by_line():
    result = build_base64_subscription(["vless://a", "trojan://b"])

    decoded = base64.b64decode(result).decode()
    assert decoded == "vless://a\ntrojan://b"
```

**Step 2:** Verify RED.

**Step 3:** Implement base64 subscription builder.

**Step 4:** Verify GREEN.

---

## Phase 3: Policy Routing and Leak Guard

### Task 10: Build policy routing commands without applying them

**Objective:** Generate deterministic `ip rule` and `ip route` commands for table 100.

**Files:**
- Create: `migate/routing/policy.py`
- Test: `tests/test_policy_routing.py`

**Step 1: Write failing test**

```python
from migate.routing.policy import build_policy_commands


def test_build_policy_commands_uses_dedicated_table_and_tun_interface():
    commands = build_policy_commands(interface="tun-migate", table=100, fwmark="0x66")

    joined = "\n".join(commands)
    assert "ip rule add fwmark 0x66 table 100" in joined
    assert "ip route replace default dev tun-migate table 100" in joined
```

**Step 2:** Verify RED.

**Step 3:** Implement pure command builder.

**Step 4:** Verify GREEN.

---

### Task 11: Define leak guard decision logic

**Objective:** Decide whether egress is allowed based on tunnel state and IP checks.

**Files:**
- Create: `migate/routing/leak_guard.py`
- Test: `tests/test_leak_guard.py`

**Step 1: Write failing test**

```python
from migate.routing.leak_guard import LeakState, should_allow_egress


def test_leak_guard_blocks_when_tunnel_down():
    state = LeakState(tun_exists=False, openvpn_running=False, native_ip="1.1.1.1", egress_ip=None)

    decision = should_allow_egress(state)

    assert decision.allowed is False
    assert "tun" in decision.reason.lower()


def test_leak_guard_blocks_when_egress_equals_native_ip():
    state = LeakState(tun_exists=True, openvpn_running=True, native_ip="1.1.1.1", egress_ip="1.1.1.1")

    decision = should_allow_egress(state)

    assert decision.allowed is False
    assert "leak" in decision.reason.lower()
```

**Step 2:** Verify RED.

**Step 3:** Implement dataclasses and decision logic.

**Step 4:** Verify GREEN.

---

## Phase 4: Process Management

### Task 12: Render OpenVPN config to stable runtime path

**Objective:** Write selected VPNGate OVPN config to MiGate runtime file while forcing tun interface name.

**Files:**
- Create: `migate/vpn/config_render.py`
- Test: `tests/test_openvpn_render.py`

**Step 1: Write failing test**

```python
from migate.vpn.config_render import render_openvpn_config


def test_render_openvpn_config_forces_named_tun_interface():
    raw = "client\ndev tun\nremote 1.2.3.4 1194 udp\n"

    rendered = render_openvpn_config(raw, interface="tun-migate")

    assert "dev tun-migate" in rendered
    assert "remote 1.2.3.4 1194 udp" in rendered
```

**Step 2:** Verify RED.

**Step 3:** Implement renderer that replaces `dev tun` or injects `dev tun-migate`.

**Step 4:** Verify GREEN.

---

### Task 13: Add xray config validation command wrapper

**Objective:** Build a safe command for `xray test -config` before reload.

**Files:**
- Create: `migate/xray/core.py`
- Test: `tests/test_xray_core.py`

**Step 1: Write failing test**

```python
from migate.xray.core import build_xray_test_command


def test_build_xray_test_command_quotes_config_path():
    cmd = build_xray_test_command("/etc/migate/xray/config.json")

    assert cmd == ["/usr/local/bin/xray", "test", "-config", "/etc/migate/xray/config.json"]
```

**Step 2:** Verify RED.

**Step 3:** Implement list-based subprocess command builder.

**Step 4:** Verify GREEN.

---

## Phase 5: CLI MVP

### Task 14: Add `migate status` command contract

**Objective:** Provide a CLI status command that prints Xray, VPN, egress, and leak guard state.

**Files:**
- Create: `migate/cli/commands.py`
- Modify: `migate/main.py`
- Test: `tests/test_cli_status.py`

**Step 1: Write failing test**

```python
from typer.testing import CliRunner
from migate.main import app


def test_status_command_outputs_core_sections():
    runner = CliRunner()

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 0
    assert "Xray" in result.stdout
    assert "VPN" in result.stdout
    assert "Egress" in result.stdout
    assert "Leak Guard" in result.stdout
```

**Step 2:** Verify RED.

**Step 3:** Implement minimal Typer app with status command.

**Step 4:** Verify GREEN.

---

### Task 15: Add `migate node create` command contract

**Objective:** Create an Xray inbound/client record and print a share link.

**Files:**
- Modify: `migate/cli/commands.py`
- Test: `tests/test_cli_node_create.py`

**Step 1: Write failing test**

```python
from typer.testing import CliRunner
from migate.main import app


def test_node_create_prints_vless_link():
    runner = CliRunner()

    result = runner.invoke(app, ["node", "create", "--type", "vless", "--port", "443", "--host", "example.com"])

    assert result.exit_code == 0
    assert "vless://" in result.stdout
    assert "example.com:443" in result.stdout
```

**Step 2:** Verify RED.

**Step 3:** Implement minimal command using `build_vless_link`.

**Step 4:** Verify GREEN.

---

## Phase 6: Web API MVP

### Task 16: Add `/api/status` endpoint

**Objective:** Expose machine-readable status for UI and monitoring.

**Files:**
- Create: `migate/api/app.py`
- Create: `migate/api/routes_status.py`
- Test: `tests/test_api_status.py`

**Step 1: Write failing test**

```python
from fastapi.testclient import TestClient
from migate.api.app import create_app


def test_status_endpoint_returns_core_status_keys():
    client = TestClient(create_app())

    response = client.get("/api/status")

    assert response.status_code == 200
    data = response.json()
    assert "xray" in data
    assert "vpn" in data
    assert "egress" in data
    assert "leak_guard" in data
```

**Step 2:** Verify RED.

**Step 3:** Implement FastAPI app and endpoint.

**Step 4:** Verify GREEN.

---

## Phase 7: Install and Systemd

### Task 17: Add systemd unit templates

**Objective:** Define separate services for MiGate API/manager, xray-core, and egress proxy.

**Files:**
- Create: `systemd/migate.service`
- Create: `systemd/migate-xray.service`
- Create: `systemd/migate-egress.service`

**Verification:**

Run:

```bash
systemd-analyze verify systemd/migate.service systemd/migate-xray.service systemd/migate-egress.service
```

Expected: no syntax errors.

---

### Task 18: Add installer preflight checks

**Objective:** Check OS, root privileges, dependencies, and ports before installation.

**Files:**
- Create: `scripts/install.sh`
- Test: `scripts/doctor.sh`

**Verification:**

Run:

```bash
bash -n scripts/install.sh
bash -n scripts/doctor.sh
```

Expected: no shell syntax errors.

---

## v0.1 Acceptance Criteria

MiGate v0.1 is done when:

1. `pytest tests/ -q` passes.
2. `migate status` prints Xray/VPN/Egress/Leak Guard sections.
3. `migate node create --type vless --port 443 --host example.com` prints a valid `vless://` link.
4. Generated Xray config contains no default direct `freedom` outbound for user traffic.
5. Generated Xray outbound points to MiGate SOCKS5 at `127.0.0.1:7929`.
6. VPNGate CSV parser can decode candidate OpenVPN configs.
7. Leak guard blocks when tun is missing, OpenVPN is down, or egress IP equals native IP.
8. Policy routing commands use table 100 and do not replace the system default route.
9. Systemd unit files pass `systemd-analyze verify`.
10. Installer scripts pass `bash -n`.

## v0.2 Roadmap

1. Web UI dashboard.
2. Trojan TCP node creation.
3. Shadowsocks node creation.
4. VLESS WebSocket node creation.
5. Reality support.
6. Xray Stats API traffic accounting.
7. User expiration and traffic limits.
8. Country-based VPNGate exit selection.
9. Multiple egress profiles.
10. Subscription token auth and reset.

## v0.3 Roadmap

1. Network namespace egress isolation.
2. nftables-first firewall backend.
3. Multi-exit pools and routing strategies.
4. Prometheus metrics.
5. Import/export compatible with 3x-ui-style node/user data.
6. Optional external 3x-ui interop mode.
7. Automated TLS certificate management.
8. CDN/WebSocket templates.

## Implementation Notes

- Do not fork 3x-ui for v0.1. Use it as UX inspiration only.
- Do not expose Web UI publicly by default.
- Do not permit direct fallback by default.
- Keep all command builders testable as pure functions before adding privileged execution.
- Apply privileged network changes only through explicit manager methods with dry-run support.
- Use strict TDD for production Python code.
