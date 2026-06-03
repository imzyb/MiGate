"""Query xray traffic stats via the xray CLI gRPC API."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class XrayStatEntry:
    name: str
    value: int


@dataclass(frozen=True)
class XrayTrafficStats:
    entries: list[XrayStatEntry]

    def inbound_traffic(self, tag: str) -> tuple[int, int]:
        """Return (up_bytes, down_bytes) for the given inbound tag."""
        up = 0
        down = 0
        for entry in self.entries:
            if f"inbound>>>{tag}>>>" in entry.name:
                if "uplink" in entry.name:
                    up += entry.value
                elif "downlink" in entry.name:
                    down += entry.value
        return up, down

    def user_traffic(self, email: str) -> tuple[int, int]:
        """Return (up_bytes, down_bytes) for the given user email."""
        up = 0
        down = 0
        prefix = f"user>>>{email}>>>"
        for entry in self.entries:
            if prefix in entry.name:
                if "uplink" in entry.name:
                    up += entry.value
                elif "downlink" in entry.name:
                    down += entry.value
        return up, down

    def all_user_traffic(self) -> dict[str, tuple[int, int]]:
        """Return traffic for all users grouped by email.

        Returns a dict mapping email -> (up_bytes, down_bytes).
        """
        users: dict[str, tuple[int, int]] = {}
        for entry in self.entries:
            if not entry.name.startswith("user>>>"):
                continue
            parts = entry.name.split(">>>", 2)
            if len(parts) < 3:
                continue
            email = parts[1]
            if email not in users:
                users[email] = (0, 0)
            up, down = users[email]
            if "uplink" in entry.name:
                up += entry.value
            elif "downlink" in entry.name:
                down += entry.value
            users[email] = (up, down)
        return users


def query_xray_stats(
    *,
    server: str = "127.0.0.1:10085",
    pattern: str = "",
    reset: bool = False,
) -> XrayTrafficStats:
    """Query xray stats via gRPC API using the xray CLI."""
    cmd = ["xray", "api", "statsquery", "--server", server]
    if pattern:
        cmd.extend(["-pattern", pattern])
    if reset:
        cmd.append("-reset")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return XrayTrafficStats(entries=[])
        data = json.loads(result.stdout)
        stats = data.get("stat", [])
        entries = []
        for s in stats:
            name = s.get("name", "")
            value = int(s.get("value", 0))
            entries.append(XrayStatEntry(name=name, value=value))
        return XrayTrafficStats(entries=entries)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return XrayTrafficStats(entries=[])
