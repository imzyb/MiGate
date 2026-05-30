import asyncio

import pytest

from migate.proxy.socks5_session import SOCKS5_SUCCESS_REPLY
from migate.proxy.socks5_server import serve_socks5_once


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
