from __future__ import annotations

import base64
import csv
from dataclasses import dataclass
from io import StringIO


@dataclass(frozen=True)
class VPNGateNodeCandidate:
    hostname: str
    ip: str
    score: int
    ping_ms: int
    speed: int
    country: str
    country_code: str
    sessions: int
    uptime: int
    total_users: int
    total_traffic: int
    ovpn_config: str


def _to_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _decode_ovpn(value: str) -> str | None:
    try:
        return base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
    except Exception:
        return None


def parse_vpngate_csv(csv_text: str) -> list[VPNGateNodeCandidate]:
    lines = []
    for raw_line in csv_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line == "*":
            break
        lines.append(raw_line)

    if not lines:
        return []

    header = lines[0]
    if header.startswith("#"):
        lines[0] = header[1:]

    reader = csv.DictReader(StringIO("\n".join(lines)))
    nodes: list[VPNGateNodeCandidate] = []
    for row in reader:
        encoded = row.get("OpenVPN_ConfigData_Base64", "")
        ovpn_config = _decode_ovpn(encoded)
        if not ovpn_config:
            continue

        nodes.append(
            VPNGateNodeCandidate(
                hostname=row.get("HostName", ""),
                ip=row.get("IP", ""),
                score=_to_int(row.get("Score", "0")),
                ping_ms=_to_int(row.get("Ping", "0")),
                speed=_to_int(row.get("Speed", "0")),
                country=row.get("CountryLong", ""),
                country_code=row.get("CountryShort", ""),
                sessions=_to_int(row.get("NumVpnSessions", "0")),
                uptime=_to_int(row.get("Uptime", "0")),
                total_users=_to_int(row.get("TotalUsers", "0")),
                total_traffic=_to_int(row.get("TotalTraffic", "0")),
                ovpn_config=ovpn_config,
            )
        )
    return nodes
