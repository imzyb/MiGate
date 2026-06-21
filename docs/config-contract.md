# MiGate Config Contract

Panel configuration lives at `/etc/migate/panel.json`, is owned by
`internal/config.Config`, and is part of the MiGate Runtime Contract.

## Schema Compatibility

MiGate has not shipped a stable public config API yet, so writes are typed and
conservative, while reads stay upgrade-compatible:

Configuration writes follow a strict schema: only fields defined by
`internal/config.Config` are persisted, and unknown JSON fields are never
round-tripped by the settings service.

- `panel.json` writes follow a strict schema: only known `Config` fields are emitted.
- `internal/config.Config` is the only field source.
- `Load(path)` ignores unknown JSON fields so older or user-extended
  `panel.json` files do not block service startup during an online upgrade.
- `Save(path, cfg)` writes only known `Config` fields.
- `Update(path, mutate)` loads typed `Config`, validates it, normalizes write defaults, and saves typed JSON.
- Settings APIs must not preserve, pass through, or create unknown fields with arbitrary maps.
- `cert_domain` and `cert_email` are compatibility settings for the legacy
  `/api/cert/*` UI flow. Managed certificate assets live in SQLite, not
  `panel.json`.

## Fields

| JSON field | Go field | Default on Save | Validation |
| --- | --- | --- | --- |
| `panel_port` | `PanelPort` | `9999` | `1..65535`; explicit `0` in existing config is invalid |
| `panel_username` | `PanelUsername` | empty | trimmed |
| `panel_password` | `PanelPassword` | empty | stored as an Argon2id MiGate hash when updated through settings |
| `web_base_path` | `WebPath` | `/panel` | trimmed, leading slash added, trailing slash removed except `/` |
| `public_host` | `PublicHost` | empty | trimmed |
| `trust_proxy` | `TrustProxy` | `false` | boolean |
| `database_path` | `DatabasePath` | `/var/lib/migate/migate.db` | required on save, absolute path, no NUL byte |
| `cert_domain` | `CertDomain` | empty | compatibility field; trimmed |
| `cert_email` | `CertEmail` | empty | compatibility field; trimmed |
| `management_direct_enabled` | `ManagementDirectEnabled` | `true` | boolean |
| `management_direct_auto_detect` | `ManagementDirectAutoDetect` | `true` | boolean |
| `management_direct_hosts` | `ManagementDirectHosts` | empty | normalized Host/IP list |
| `management_direct_ports` | `ManagementDirectPorts` | empty | normalized `1..65535` port list |

## Management Direct

Management direct protects the MiGate panel and SSH-style management entrypoints
from being routed through user proxy rules. When enabled, generated Xray and
sing-box configs add an internal direct outbound plus system route rules before
user routing rules.

The match is precise: only the configured management Host/IP values plus the
configured management ports are forced direct. By default MiGate uses the panel
port and auto-detected management hosts from `public_host` and `cert_domain`,
then appends `management_direct_hosts` and `management_direct_ports`.

This does not change normal SOCKS/VLESS inbound traffic to proxy outbounds.
User catch-all routing rules are still emitted after the system management
rules, and they continue to target the configured proxy outbound for ordinary
destinations.

Do not add `80` or `443` to `management_direct_ports` unless those ports are
also management entrypoints on the same management Host/IP. Adding a common
business port means traffic to that Host/IP and port will also be direct.

To disable the protection, set `management_direct_enabled` to `false` or turn it
off in Settings. To keep the protection but remove auto-detected targets, set
`management_direct_auto_detect` to `false` and manage the host and port lists
manually.

## Certificate Assets

Managed TLS certificates are stored in the application database with file
assets under `/etc/migate/certs`.

The certificate asset model records:

- domains / SANs
- status: `issued`, `pending`, `failed`, `expired`, `expiring_soon`
- certificate and private key paths
- `not_before`, `not_after`
- SHA-256 fingerprint and serial number
- last error
- usage count and TLS inbound references

Certificate operation records store issue, import, renew, apply, delete, and
failure diagnostics. These records are exposed through
`GET /api/certificates/{id}/operations` so UI and API clients can surface
actionable errors instead of raw command output.

## Read Versus Write Defaults

`Load(path)` normalizes existing string fields and ignores unknown fields, but
does not inject omitted write defaults. This lets callers distinguish an old
partial config from a newly saved full config.

`Normalize(cfg)` and `Save(path, cfg)` apply write defaults before persisting. A saved config should not contain unknown fields and should include normalized paths and defaults.

## Password Handling

The settings service never returns `panel_password`. Settings `GET` returns `has_password` only. Settings `PUT` hashes a non-empty plaintext password before saving; if a valid MiGate hash is supplied, it is preserved as a hash.
