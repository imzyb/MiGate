from __future__ import annotations

import base64
from urllib.parse import quote, urlencode


def _fragment(name: str) -> str:
    return quote(name, safe="")


def _query(params: dict[str, str]) -> str:
    return urlencode(params)


def _base64_urlsafe_no_padding(value: str) -> str:
    encoded = base64.urlsafe_b64encode(value.encode()).decode()
    return encoded.rstrip("=")


def build_vless_link(*, uuid: str, host: str, port: int, name: str, security: str = "none", network: str = "tcp") -> str:
    query = _query({"type": network, "security": security})
    return f"vless://{quote(uuid, safe='')}@{host}:{port}?{query}#{_fragment(name)}"


def build_trojan_link(*, password: str, host: str, port: int, name: str, security: str = "none", network: str = "tcp") -> str:
    query = _query({"type": network, "security": security})
    return f"trojan://{quote(password, safe='')}@{host}:{port}?{query}#{_fragment(name)}"


def build_shadowsocks_link(*, method: str, password: str, host: str, port: int, name: str) -> str:
    userinfo = _base64_urlsafe_no_padding(f"{method}:{password}")
    return f"ss://{userinfo}@{host}:{port}#{_fragment(name)}"
