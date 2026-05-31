"""Pure OpenVPN config rendering for MiGate-managed VPNGate exits."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OpenVPNRenderPlan:
    source_profile: str
    tun_interface: str
    runtime_dir: str
    config_text: str
    performed_side_effects: bool = False


def _is_drop_runtime_line(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("status ") or stripped.startswith("log ") or stripped.startswith("log-append ")


def render_openvpn_config_preview(
    raw_config: str,
    *,
    tun_interface: str,
    runtime_dir: str,
    log_path: str,
    status_path: str,
) -> OpenVPNRenderPlan:
    rendered_lines: list[str] = []
    dev_written = False
    for line in raw_config.splitlines():
        stripped = line.strip()
        if stripped.startswith("dev "):
            if not dev_written:
                rendered_lines.append(f"dev {tun_interface}")
                dev_written = True
            continue
        if _is_drop_runtime_line(line):
            continue
        rendered_lines.append(line)

    if not dev_written:
        rendered_lines.append(f"dev {tun_interface}")
    if not any(line.strip() == "route-nopull" for line in rendered_lines):
        rendered_lines.append("route-nopull")
    if not any(line.strip() == "pull-filter ignore redirect-gateway" for line in rendered_lines):
        rendered_lines.append("pull-filter ignore redirect-gateway")
    if not any(line.strip().startswith("data-ciphers ") for line in rendered_lines):
        rendered_lines.append("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC")
    rendered_lines.append(f"status {status_path}")
    rendered_lines.append(f"log-append {log_path}")

    return OpenVPNRenderPlan(
        source_profile="vpnGate",
        tun_interface=tun_interface,
        runtime_dir=runtime_dir,
        config_text="\n".join(rendered_lines) + "\n",
        performed_side_effects=False,
    )
