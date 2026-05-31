import asyncio

import pytest

from migate.proxy.socks5_session import SOCKS5_GENERAL_FAILURE_REPLY, SOCKS5_SUCCESS_REPLY
from migate.proxy.socks5_server import serve_socks5_bounded, serve_socks5_once


async def unused_local_tcp_port() -> int:
    server = await asyncio.start_server(lambda _reader, _writer: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    return port


def ipv4_connect_request(host: str, port: int) -> bytes:
    return b"\x05\x01\x00\x01" + bytes(int(part) for part in host.split(".")) + port.to_bytes(2, "big")


@pytest.mark.asyncio
async def test_serve_socks5_bounded_relays_bytes_to_connected_upstream():
    upstream_payloads: list[bytes] = []

    async def handle_upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        payload = await reader.readexactly(4)
        upstream_payloads.append(payload)
        writer.write(b"pong")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    upstream_server = await asyncio.start_server(handle_upstream, "127.0.0.1", 0)
    upstream_host, upstream_port = upstream_server.sockets[0].getsockname()[:2]
    server_task = asyncio.create_task(serve_socks5_bounded("127.0.0.1", 0, max_clients=1))
    await asyncio.sleep(0)
    server = await asyncio.wait_for(serve_socks5_bounded.current_server(), timeout=1)
    bound_host, bound_port = server.sockets[0].getsockname()[:2]

    reader, writer = await asyncio.open_connection(bound_host, bound_port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    method_response = await reader.readexactly(2)
    writer.write(ipv4_connect_request(upstream_host, upstream_port))
    await writer.drain()
    connect_response = await reader.readexactly(10)
    writer.write(b"ping")
    await writer.drain()
    relayed_response = await reader.readexactly(4)
    remaining = await reader.read()
    writer.close()
    await writer.wait_closed()

    result = await asyncio.wait_for(server_task, timeout=1)
    upstream_server.close()
    await upstream_server.wait_closed()

    assert method_response == b"\x05\x00"
    assert connect_response == SOCKS5_SUCCESS_REPLY
    assert relayed_response == b"pong"
    assert remaining == b""
    assert upstream_payloads == [b"ping"]
    assert result.upstream_connections == 1
    assert "with direct upstream relay" in result.message
    assert len(result.events) == 1
    assert result.events[0].client_id == 1
    assert result.events[0].phase == "connect"
    assert result.events[0].status == "accepted"
    assert result.events[0].target_host == upstream_host
    assert result.events[0].target_port == upstream_port
    assert result.events[0].upstream_connected is True


@pytest.mark.asyncio
async def test_serve_socks5_bounded_records_rejected_greeting_and_connect_events():
    server_task = asyncio.create_task(serve_socks5_bounded("127.0.0.1", 0, max_clients=2))
    await asyncio.sleep(0)
    server = await asyncio.wait_for(serve_socks5_bounded.current_server(), timeout=1)
    bound_host, bound_port = server.sockets[0].getsockname()[:2]

    reader1, writer1 = await asyncio.open_connection(bound_host, bound_port)
    writer1.write(b"\x05\x01\x02")
    await writer1.drain()
    method_response1 = await reader1.readexactly(2)
    await reader1.read()
    writer1.close()
    await writer1.wait_closed()

    reader2, writer2 = await asyncio.open_connection(bound_host, bound_port)
    writer2.write(b"\x05\x01\x00")
    await writer2.drain()
    method_response2 = await reader2.readexactly(2)
    writer2.write(b"\x05\x02\x00\x03\x0bexample.com\x01\xbb")
    await writer2.drain()
    connect_response2 = await reader2.readexactly(10)
    await reader2.read()
    writer2.close()
    await writer2.wait_closed()

    result = await asyncio.wait_for(server_task, timeout=1)

    assert method_response1 == b"\x05\xff"
    assert method_response2 == b"\x05\x00"
    assert connect_response2 == bytes([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
    assert result.upstream_connections == 0
    assert len(result.events) == 2
    assert result.events[0].client_id == 1
    assert result.events[0].phase == "greeting"
    assert result.events[0].status == "rejected"
    assert result.events[0].target_host is None
    assert result.events[0].target_port is None
    assert result.events[0].upstream_connected is False
    assert result.events[1].client_id == 2
    assert result.events[1].phase == "connect"
    assert result.events[1].status == "rejected"
    assert result.events[1].target_host is None
    assert result.events[1].target_port is None
    assert result.events[1].upstream_connected is False


@pytest.mark.asyncio
async def test_serve_socks5_bounded_records_connect_and_timeout_events():
    server_task = asyncio.create_task(serve_socks5_bounded("127.0.0.1", 0, max_clients=2, client_timeout=0.05))
    await asyncio.sleep(0)
    server = await asyncio.wait_for(serve_socks5_bounded.current_server(), timeout=1)
    bound_host, bound_port = server.sockets[0].getsockname()[:2]

    upstream_port = await unused_local_tcp_port()

    reader1, writer1 = await asyncio.open_connection(bound_host, bound_port)
    writer1.write(b"\x05\x01\x00")
    await writer1.drain()
    await reader1.readexactly(2)
    writer1.write(ipv4_connect_request("127.0.0.1", upstream_port))
    await writer1.drain()
    connect_response1 = await reader1.readexactly(10)
    await reader1.read()
    writer1.close()
    await writer1.wait_closed()

    reader2, writer2 = await asyncio.open_connection(bound_host, bound_port)
    await asyncio.wait_for(reader2.read(), timeout=1)
    writer2.close()
    await writer2.wait_closed()

    result = await asyncio.wait_for(server_task, timeout=1)

    assert connect_response1 == SOCKS5_GENERAL_FAILURE_REPLY
    assert result.upstream_connections == 0
    assert len(result.events) == 2
    assert result.events[0].client_id == 1
    assert result.events[0].phase == "connect"
    assert result.events[0].status == "rejected"
    assert result.events[0].target_host == "127.0.0.1"
    assert result.events[0].target_port == upstream_port
    assert result.events[0].upstream_connected is False
    assert result.events[1].client_id == 2
    assert result.events[1].phase == "greeting"
    assert result.events[1].status == "timed_out"
    assert result.events[1].target_host is None
    assert result.events[1].target_port is None
    assert result.events[1].upstream_connected is False


@pytest.mark.asyncio
async def test_serve_socks5_bounded_zero_max_clients_keeps_serving_until_cancelled():
    server_task = asyncio.create_task(serve_socks5_bounded("127.0.0.1", 0, max_clients=0, client_timeout=0.05))
    await asyncio.sleep(0)
    server = await asyncio.wait_for(serve_socks5_bounded.current_server(), timeout=1)
    bound_host, bound_port = server.sockets[0].getsockname()[:2]

    reader, writer = await asyncio.open_connection(bound_host, bound_port)
    writer.write(b"\x05\x01\x02")
    await writer.drain()
    method_response = await reader.readexactly(2)
    remaining = await reader.read()
    writer.close()
    await writer.wait_closed()

    assert method_response == b"\x05\xff"
    assert remaining == b""
    assert server_task.done() is False

    server_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await server_task


@pytest.mark.asyncio
async def test_serve_socks5_bounded_times_out_idle_client_and_stops():
    server_task = asyncio.create_task(serve_socks5_bounded("127.0.0.1", 0, max_clients=1, client_timeout=0.05))
    await asyncio.sleep(0)
    server = await asyncio.wait_for(serve_socks5_bounded.current_server(), timeout=1)
    bound_host, bound_port = server.sockets[0].getsockname()[:2]

    reader, writer = await asyncio.open_connection(bound_host, bound_port)
    remaining = await asyncio.wait_for(reader.read(), timeout=1)
    writer.close()
    await writer.wait_closed()

    result = await asyncio.wait_for(server_task, timeout=1)

    assert remaining == b""
    assert result.status == "stopped"
    assert result.listener_started is True
    assert result.accepted_connections == 1
    assert result.timed_out_connections == 1
    assert result.upstream_connections == 0
    assert result.performed_side_effects is True


@pytest.mark.asyncio
async def test_serve_socks5_bounded_handles_two_clients_then_stops():
    server_task = asyncio.create_task(serve_socks5_bounded("127.0.0.1", 0, max_clients=2))
    await asyncio.sleep(0)
    server = await asyncio.wait_for(serve_socks5_bounded.current_server(), timeout=1)
    bound_host, bound_port = server.sockets[0].getsockname()[:2]

    upstream_port = await unused_local_tcp_port()

    reader1, writer1 = await asyncio.open_connection(bound_host, bound_port)
    writer1.write(b"\x05\x01\x00")
    await writer1.drain()
    method_response1 = await reader1.readexactly(2)
    writer1.write(ipv4_connect_request("127.0.0.1", upstream_port))
    await writer1.drain()
    connect_response1 = await reader1.readexactly(10)
    remaining1 = await reader1.read()
    writer1.close()
    await writer1.wait_closed()

    reader2, writer2 = await asyncio.open_connection(bound_host, bound_port)
    writer2.write(b"\x05\x01\x02")
    await writer2.drain()
    method_response2 = await reader2.readexactly(2)
    remaining2 = await reader2.read()
    writer2.close()
    await writer2.wait_closed()

    result = await asyncio.wait_for(server_task, timeout=1)

    assert method_response1 == b"\x05\x00"
    assert connect_response1 == SOCKS5_GENERAL_FAILURE_REPLY
    assert remaining1 == b""
    assert method_response2 == b"\x05\xff"
    assert remaining2 == b""
    assert result.status == "stopped"
    assert result.listener_started is True
    assert result.accepted_connections == 2
    assert result.upstream_connections == 0
    assert result.performed_side_effects is True


@pytest.mark.asyncio
async def test_serve_socks5_once_rejects_connect_when_upstream_connection_fails():
    server_task = asyncio.create_task(serve_socks5_once("127.0.0.1", 0))
    await asyncio.sleep(0)
    server = await asyncio.wait_for(serve_socks5_once.current_server(), timeout=1)
    bound_host, bound_port = server.sockets[0].getsockname()[:2]

    upstream_port = await unused_local_tcp_port()

    reader, writer = await asyncio.open_connection(bound_host, bound_port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    method_response = await reader.readexactly(2)

    writer.write(ipv4_connect_request("127.0.0.1", upstream_port))
    await writer.drain()
    connect_response = await reader.readexactly(10)
    remaining = await reader.read()
    writer.close()
    await writer.wait_closed()

    result = await asyncio.wait_for(server_task, timeout=1)

    assert method_response == b"\x05\x00"
    assert connect_response == SOCKS5_GENERAL_FAILURE_REPLY
    assert remaining == b""
    assert result.status == "stopped"
    assert result.listener_started is True
    assert result.accepted_connections == 1
    assert result.upstream_connections == 0
    assert result.performed_side_effects is True


@pytest.mark.asyncio
async def test_serve_socks5_once_rejects_unsupported_auth_and_closes():
    server_task = asyncio.create_task(serve_socks5_once("127.0.0.1", 0))
    await asyncio.sleep(0)
    server = await asyncio.wait_for(serve_socks5_once.current_server(), timeout=1)
    bound_host, bound_port = server.sockets[0].getsockname()[:2]

    reader, writer = await asyncio.open_connection(bound_host, bound_port)
    writer.write(b"\x05\x01\x02")
    await writer.drain()
    method_response = await reader.readexactly(2)
    remaining = await reader.read()
    writer.close()
    await writer.wait_closed()

    result = await asyncio.wait_for(server_task, timeout=1)

    assert method_response == b"\x05\xff"
    assert remaining == b""
    assert result.status == "stopped"
    assert result.accepted_connections == 1
    assert result.upstream_connections == 0
