"""Minimal asyncio SOCKS5 server with bounded upstream forwarding.

This server is intentionally constrained for test-driven development:
- bind on caller-provided host/port
- accept a bounded number of client connections
- process SOCKS5 greeting and one CONNECT request per client
- connect accepted CONNECT requests to upstream destinations
- relay bytes until either side closes
"""

from __future__ import annotations

import asyncio
from typing import Any

from migate.proxy.socks5_connection import Socks5Connection
from migate.proxy.socks5_listener import Socks5ServeEvent, Socks5ServeResult
from migate.proxy.socks5_session import SOCKS5_GENERAL_FAILURE_REPLY

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


async def _pipe_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> int:
    bytes_forwarded = 0
    try:
        while data := await reader.read(65536):
            bytes_forwarded += len(data)
            writer.write(data)
            await writer.drain()
    except asyncio.CancelledError:
        return bytes_forwarded
    except (ConnectionResetError, BrokenPipeError):
        return bytes_forwarded
    finally:
        try:
            writer.write_eof()
        except (AttributeError, OSError, RuntimeError):
            writer.close()
    return bytes_forwarded


async def _relay_until_closed(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> tuple[int, int]:
    client_to_upstream = asyncio.create_task(_pipe_stream(client_reader, upstream_writer))
    upstream_to_client = asyncio.create_task(_pipe_stream(upstream_reader, client_writer))
    done, pending = await asyncio.wait({client_to_upstream, upstream_to_client}, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    results = await asyncio.gather(client_to_upstream, upstream_to_client, return_exceptions=True)
    upstream_writer.close()
    await upstream_writer.wait_closed()
    byte_counts = [result if isinstance(result, int) else 0 for result in results]
    return byte_counts[0], byte_counts[1]


async def _handle_socks5_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    stats: dict[str, int],
    events: list[Socks5ServeEvent],
    *,
    client_id: int,
    client_timeout: float,
) -> None:
    connection = Socks5Connection()
    try:
        greeting_header = await asyncio.wait_for(reader.readexactly(2), timeout=client_timeout)
        methods_count = greeting_header[1]
        greeting_payload = greeting_header + await asyncio.wait_for(reader.readexactly(methods_count), timeout=client_timeout)
        greeting_event = connection.receive_greeting(greeting_payload)
        if greeting_event.response is not None:
            writer.write(greeting_event.response)
            await asyncio.wait_for(writer.drain(), timeout=client_timeout)
        if greeting_event.status != "accepted":
            events.append(
                Socks5ServeEvent(
                    client_id=client_id,
                    phase="greeting",
                    status=greeting_event.status,
                    target_host=None,
                    target_port=None,
                    upstream_connected=False,
                )
            )
            return

        request_payload = await asyncio.wait_for(_read_socks5_request(reader), timeout=client_timeout)
        connect_event = connection.receive_request(request_payload)
        target_host = connect_event.request_address.host if connect_event.request_address is not None else None
        target_port = connect_event.request_address.port if connect_event.request_address is not None else None
        upstream_connected = False
        if connect_event.should_connect and target_host is not None and target_port is not None:
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port),
                    timeout=client_timeout,
                )
            except OSError:
                connect_event = type(connect_event)(
                    phase=connect_event.phase,
                    status="rejected",
                    response=SOCKS5_GENERAL_FAILURE_REPLY,
                    message="upstream connection failed",
                    request_address=connect_event.request_address,
                    should_connect=False,
                    performed_side_effects=connect_event.performed_side_effects,
                )
            else:
                stats["upstream_connections"] += 1
                upstream_connected = True
                if connect_event.response is not None:
                    writer.write(connect_event.response)
                    await asyncio.wait_for(writer.drain(), timeout=client_timeout)
                bytes_from_client, bytes_from_upstream = await _relay_until_closed(reader, writer, upstream_reader, upstream_writer)
                events.append(
                    Socks5ServeEvent(
                        client_id=client_id,
                        phase="connect",
                        status=connect_event.status,
                        target_host=target_host,
                        target_port=target_port,
                        upstream_connected=True,
                        bytes_from_client=bytes_from_client,
                        bytes_from_upstream=bytes_from_upstream,
                    )
                )
                return
        if connect_event.response is not None:
            writer.write(connect_event.response)
            await asyncio.wait_for(writer.drain(), timeout=client_timeout)
        events.append(
            Socks5ServeEvent(
                client_id=client_id,
                phase="connect",
                status=connect_event.status,
                target_host=target_host,
                target_port=target_port,
                upstream_connected=upstream_connected,
            )
        )
    except TimeoutError:
        stats["timed_out_connections"] += 1
        events.append(
            Socks5ServeEvent(
                client_id=client_id,
                phase="greeting",
                status="timed_out",
                target_host=None,
                target_port=None,
                upstream_connected=False,
            )
        )
        return
    except (asyncio.IncompleteReadError, ConnectionResetError):
        return
    finally:
        stats["accepted_connections"] += 1
        writer.close()
        await writer.wait_closed()


async def serve_socks5_bounded(
    bind_host: str,
    bind_port: int,
    *,
    max_clients: int = 1,
    client_timeout: float = 5.0,
) -> Socks5ServeResult:
    """Serve SOCKS5 clients; max_clients=0 keeps serving until cancelled.

    This opens a local listening socket and relays accepted CONNECT requests upstream.
    """
    global _current_server
    stats = {"accepted_connections": 0, "upstream_connections": 0, "timed_out_connections": 0}
    events: list[Socks5ServeEvent] = []
    all_clients_done = asyncio.Event()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_id = stats["accepted_connections"] + 1
        try:
            await _handle_socks5_client(reader, writer, stats, events, client_id=client_id, client_timeout=client_timeout)
        finally:
            if max_clients > 0 and stats["accepted_connections"] >= max_clients:
                all_clients_done.set()

    server = await asyncio.start_server(handler, bind_host, bind_port)
    _current_server = server
    try:
        await all_clients_done.wait()
    finally:
        sockname: Any = server.sockets[0].getsockname() if server.sockets else (bind_host, bind_port)
        server.close()
        await server.wait_closed()
        _current_server = None

    return Socks5ServeResult(
        status="stopped",
        message=f"SOCKS5 listener handled {stats['accepted_connections']} client(s) with direct upstream relay",
        bind_host=str(sockname[0]),
        bind_port=int(sockname[1]),
        listener_started=True,
        accepted_connections=stats["accepted_connections"],
        upstream_connections=stats["upstream_connections"],
        timed_out_connections=stats["timed_out_connections"],
        max_clients=max_clients,
        client_timeout=client_timeout,
        events=events,
        performed_side_effects=True,
    )


async def serve_socks5_once(bind_host: str, bind_port: int) -> Socks5ServeResult:
    """Serve exactly one SOCKS5 client and then stop.

    This opens a local listening socket and relays accepted CONNECT requests upstream.
    """
    return await serve_socks5_bounded(bind_host, bind_port, max_clients=1)


async def _current_server_waiter() -> asyncio.AbstractServer:
    for _ in range(100):
        if _current_server is not None:
            return _current_server
        await asyncio.sleep(0.01)
    raise RuntimeError("SOCKS5 server did not start")


serve_socks5_bounded.current_server = _current_server_waiter  # type: ignore[attr-defined]
serve_socks5_once.current_server = _current_server_waiter  # type: ignore[attr-defined]
