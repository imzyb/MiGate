"""Minimal asyncio SOCKS5 server without upstream forwarding.

This server is intentionally constrained for test-driven development:
- bind on caller-provided host/port
- accept a single client connection
- process SOCKS5 greeting and one CONNECT request
- write SOCKS5 replies and close
- never connect to upstream destinations
"""

from __future__ import annotations

import asyncio
from typing import Any

from migate.proxy.socks5_connection import Socks5Connection
from migate.proxy.socks5_listener import Socks5ServeResult

_current_server: asyncio.AbstractServer | None = None


async def _read_socks5_request(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(4)
    atyp = header[3]
    if atyp == 0x01:
        rest = await reader.readexactly(4 + 2)
    elif atyp == 0x03:
        length_byte = await reader.readexactly(1)
        domain_length = length_byte[0]
        rest = length_byte + await reader.readexactly(domain_length + 2)
    elif atyp == 0x04:
        rest = await reader.readexactly(16 + 2)
    else:
        rest = await reader.read(2)
    return header + rest


async def _handle_socks5_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    stats: dict[str, int],
) -> None:
    connection = Socks5Connection()
    try:
        greeting_header = await reader.readexactly(2)
        methods_count = greeting_header[1]
        greeting_payload = greeting_header + await reader.readexactly(methods_count)
        greeting_event = connection.receive_greeting(greeting_payload)
        if greeting_event.response is not None:
            writer.write(greeting_event.response)
            await writer.drain()
        if greeting_event.status != "accepted":
            return

        request_payload = await _read_socks5_request(reader)
        connect_event = connection.receive_request(request_payload)
        if connect_event.response is not None:
            writer.write(connect_event.response)
            await writer.drain()
        stats["upstream_connections"] += 0
    except (asyncio.IncompleteReadError, ConnectionResetError):
        return
    finally:
        stats["accepted_connections"] += 1
        writer.close()
        await writer.wait_closed()


async def serve_socks5_once(bind_host: str, bind_port: int) -> Socks5ServeResult:
    """Serve exactly one SOCKS5 client and then stop.

    This opens a local listening socket, but never opens upstream sockets.
    """
    global _current_server
    stats = {"accepted_connections": 0, "upstream_connections": 0}
    client_done = asyncio.Event()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await _handle_socks5_client(reader, writer, stats)
        finally:
            client_done.set()

    server = await asyncio.start_server(handler, bind_host, bind_port)
    _current_server = server
    try:
        await client_done.wait()
    finally:
        server.close()
        await server.wait_closed()
        _current_server = None

    sockname: Any = server.sockets[0].getsockname() if server.sockets else (bind_host, bind_port)
    return Socks5ServeResult(
        status="stopped",
        message="SOCKS5 listener handled one client without upstream forwarding",
        bind_host=str(sockname[0]),
        bind_port=int(sockname[1]),
        listener_started=True,
        accepted_connections=stats["accepted_connections"],
        upstream_connections=stats["upstream_connections"],
        performed_side_effects=True,
    )


async def _current_server_waiter() -> asyncio.AbstractServer:
    for _ in range(100):
        if _current_server is not None:
            return _current_server
        await asyncio.sleep(0.01)
    raise RuntimeError("SOCKS5 server did not start")


serve_socks5_once.current_server = _current_server_waiter  # type: ignore[attr-defined]
