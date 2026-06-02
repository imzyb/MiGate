"""Client management for inbound rules.

Parses and modifies the ``settings`` JSON field of inbound records,
which stores ``{"clients": [{...}, ...]}`` per xray convention.
"""

from __future__ import annotations

import json
import uuid
from typing import Any


def parse_clients(settings_json: str) -> list[dict[str, Any]]:
    """Return the clients list from an inbound settings JSON string."""
    try:
        data = json.loads(settings_json)
    except (json.JSONDecodeError, TypeError):
        return []
    clients = data.get("clients")
    if not isinstance(clients, list):
        return []
    return list(clients)


def _dump_settings(clients: list[dict[str, Any]]) -> str:
    return json.dumps({"clients": clients}, ensure_ascii=False)


def add_client(
    settings_json: str,
    *,
    email: str = "",
    flow: str = "",
    extra: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Add a new client with a generated UUID. Returns (new_settings_json, client_dict)."""
    clients = parse_clients(settings_json)
    client: dict[str, Any] = {"id": str(uuid.uuid4())}
    if email:
        client["email"] = email
    if flow:
        client["flow"] = flow
    if extra:
        client.update(extra)
    clients.append(client)
    return _dump_settings(clients), client


def remove_client(settings_json: str, client_id: str) -> tuple[str, bool]:
    """Remove a client by id. Returns (new_settings_json, removed)."""
    clients = parse_clients(settings_json)
    original_len = len(clients)
    clients = [c for c in clients if c.get("id") != client_id]
    return _dump_settings(clients), len(clients) < original_len


def update_client(
    settings_json: str,
    client_id: str,
    **fields: Any,
) -> tuple[str, bool]:
    """Update fields on an existing client. Returns (new_settings_json, updated)."""
    clients = parse_clients(settings_json)
    updated = False
    for client in clients:
        if client.get("id") == client_id:
            client.update(fields)
            updated = True
            break
    return _dump_settings(clients), updated


# --- Repository integration helpers ---

def list_clients(repo: Any, inbound_id: int) -> list[dict[str, Any]]:
    """List clients for an inbound rule via the repository."""
    ib = repo.get_inbound(inbound_id)
    if ib is None:
        return []
    return parse_clients(ib.settings)


def add_client_to_inbound(
    repo: Any,
    inbound_id: int,
    *,
    email: str = "",
    flow: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Add a client to an inbound rule. Returns the new client dict or None if inbound not found."""
    ib = repo.get_inbound(inbound_id)
    if ib is None:
        return None
    new_settings, client = add_client(ib.settings, email=email, flow=flow, extra=extra)
    repo.update_inbound(
        inbound_id,
        remark=ib.remark,
        protocol=ib.protocol,
        port=ib.port,
        listen=ib.listen,
        settings=new_settings,
        stream_settings=ib.stream_settings,
    )
    return client


def remove_client_from_inbound(
    repo: Any,
    inbound_id: int,
    client_id: str,
) -> bool:
    """Remove a client from an inbound rule. Returns True if removed."""
    ib = repo.get_inbound(inbound_id)
    if ib is None:
        return False
    new_settings, removed = remove_client(ib.settings, client_id)
    if not removed:
        return False
    repo.update_inbound(
        inbound_id,
        remark=ib.remark,
        protocol=ib.protocol,
        port=ib.port,
        listen=ib.listen,
        settings=new_settings,
        stream_settings=ib.stream_settings,
    )
    return True


def update_client_in_inbound(
    repo: Any,
    inbound_id: int,
    client_id: str,
    **fields: Any,
) -> bool:
    """Update a client in an inbound rule. Returns True if updated."""
    ib = repo.get_inbound(inbound_id)
    if ib is None:
        return False
    new_settings, updated = update_client(ib.settings, client_id, **fields)
    if not updated:
        return False
    repo.update_inbound(
        inbound_id,
        remark=ib.remark,
        protocol=ib.protocol,
        port=ib.port,
        listen=ib.listen,
        settings=new_settings,
        stream_settings=ib.stream_settings,
    )
    return True
