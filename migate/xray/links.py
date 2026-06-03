from __future__ import annotations

import base64
from urllib.parse import quote, urlencode


def _fragment(name: str) -> str:
    return quote(name, safe="")


def _base64_urlsafe_no_padding(value: str) -> str:
    encoded = base64.urlsafe_b64encode(value.encode()).decode()
    return encoded.rstrip("=")


def _build_query(params: dict[str, str]) -> str:
    """Build a URL query string, excluding empty values."""
    filtered = {k: v for k, v in params.items() if v}
    return urlencode(filtered)


def build_vless_link(uuid: str, host: str, port: int, name: str = "",
                     *, network: str = "tcp", security: str = "none",
                     sni: str = "", alpn: str = "", fp: str = "",
                     flow: str = "", path: str = "", host_header: str = "",
                     header_type: str = "", pbk: str = "", sid: str = "",
                     spx: str = "") -> str:
    query = _build_query({
        "type": network,
        "security": security,
        "sni": sni,
        "fp": fp,
        "flow": flow,
        "alpn": alpn,
        "path": path,
        "host": host_header,
        "headerType": header_type,
        "pbk": pbk,
        "sid": sid,
        "spx": spx,
    })
    return f"vless://{quote(uuid, safe='')}@{host}:{port}?{query}#{_fragment(name)}"


def build_trojan_link(password: str, host: str, port: int, name: str = "",
                      *, network: str = "tcp", security: str = "none",
                      sni: str = "", alpn: str = "", fp: str = "",
                      path: str = "", host_header: str = "",
                      header_type: str = "") -> str:
    query = _build_query({
        "type": network,
        "security": security,
        "sni": sni,
        "fp": fp,
        "alpn": alpn,
        "path": path,
        "host": host_header,
        "headerType": header_type,
    })
    return f"trojan://{quote(password, safe='')}@{host}:{port}?{query}#{_fragment(name)}"


def build_shadowsocks_link(method: str, password: str, host: str, port: int,
                           name: str = "") -> str:
    userinfo = _base64_urlsafe_no_padding(f"{method}:{password}")
    return f"ss://{userinfo}@{host}:{port}#{_fragment(name)}"


def build_vmess_link(uuid: str, host: str, port: int, name: str = "",
                     *, network: str = "tcp", security: str = "none",
                     alter_id: int = 0) -> str:
    """Build VMess link (V2RayN format, base64-encoded JSON)."""
    import json
    vmess_obj = {
        "v": "2",
        "ps": name,
        "add": host,
        "port": str(port),
        "id": uuid,
        "aid": str(alter_id),
        "net": network,
        "type": "none",
        "host": "",
        "path": "",
        "tls": security if security != "none" else "",
    }
    raw = json.dumps(vmess_obj, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    return f"vmess://{encoded}"
