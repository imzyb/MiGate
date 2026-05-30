import asyncio

import pytest

from migate.proxy.socks5_session import SOCKS5_SUCCESS_REPLY
from migate.proxy.socks5_server import serve_socks5_bounded, serve_socks5_once


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

    reader1, writer1 = await asyncio.open_connection(bound_host, bound_port)
    writer1.write(b"\x05\x01\x00")
    await writer1.drain()
    method_response1 = await reader1.readexactly(2)
    writer1.write(b"\x05\x01\x00\x03\x0bexample.com\x01\xbb")
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
    assert connect_response1 == SOCKS5_SUCCESS_REPLY
    assert remaining1 == b""
    assert method_response2 == b"\x05\xff"
    assert remaining2 == b""
    assert result.status == "stopped"
    assert result.listener_started is True
    assert result.accepted_connections == 2
    assert result.upstream_connections == 0
    assert result.performed_side_effects is True


@pytest.mark.asyncio
async def test_serve_socks5_once_handles_connect_without_upstream_connection():
    server_task = asyncio.create_task(serve_socks5_once("127.0.0.1", 0))
    await asyncio.sleep(0)
    server = await asyncio.wait_for(serve_socks5_once.current_server(), timeout=1)
    bound_host, bound_port = server.sockets[0].getsockname()[:2]

    reader, writer = await asyncio.open_connection(bound_host, bound_port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    method_response = await reader.readexactly(2)

    writer.write(b"\x05\x01\x00\x03\x0bexample.com\x01\xbb")
    await writer.drain()
    connect_response = await reader.readexactly(10)
    remaining = await reader.read()
    writer.close()
    await writer.wait_closed()

    result = await asyncio.wait_for(server_task, timeout=1)

    assert method_response == b"\x05\x00"
    assert connect_response == SOCKS5_SUCCESS_REPLY
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
