from __future__ import annotations

import base64
from collections.abc import Iterable


def normalize_subscription_links(links: Iterable[str]) -> list[str]:
    return [link.strip() for link in links if link and link.strip()]


def build_base64_subscription(links: Iterable[str]) -> str:
    normalized = normalize_subscription_links(links)
    if not normalized:
        return ""
    body = "\n".join(normalized)
    return base64.b64encode(body.encode()).decode()
