"""Pure SOCKS5 session decisions for the future proxy runtime.

This module turns already-received SOCKS5 frames into deterministic responses
and connection decisions. It intentionally does not listen on sockets, connect
to upstream hosts, or forward traffic.
"""

from __future__ import annotations

from dataclasses import dataclass

from migate.proxy.socks5 import (
    SOCKS5_NO_ACCEPTABLE_METHODS_RESPONSE,
    SOCKS5_NO_AUTH,
    SOCKS5_NO_AUTH_RESPONSE,
    Socks5Address,
    Socks5Error,
    build_method_selection_response,
    parse_socks5_greeting,
    parse_socks5_request,
)

SOCKS5_SUCCESS_REPLY = bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
SOCKS5_GENERAL_FAILURE_REPLY = bytes([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
SOCKS5_COMMAND_NOT_SUPPORTED_REPLY = bytes([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])


@dataclass(frozen=True)
class Socks5HandshakeResult:
    status: str
    response: bytes
    selected_method: int | None
    message: str
    performed_side_effects: bool = False


@dataclass(frozen=True)
class Socks5ConnectDecision:
    status: str
    request_address: Socks5Address | None
    reply: bytes
    should_connect: bool
    message: str
    performed_side_effects: bool = False


def handle_socks5_greeting(payload: bytes) -> Socks5HandshakeResult:
    try:
        greeting = parse_socks5_greeting(payload)
    except Socks5Error as exc:
        return Socks5HandshakeResult(
            status="rejected",
            response=SOCKS5_NO_ACCEPTABLE_METHODS_RESPONSE,
            selected_method=None,
            message=str(exc),
            performed_side_effects=False,
        )

    response = build_method_selection_response(greeting)
    if greeting.selected_method == SOCKS5_NO_AUTH:
        return Socks5HandshakeResult(
            status="accepted",
            response=response,
            selected_method=greeting.selected_method,
            message="no-auth method selected",
            performed_side_effects=False,
        )
    return Socks5HandshakeResult(
        status="rejected",
        response=response,
        selected_method=None,
        message="no acceptable authentication methods",
        performed_side_effects=False,
    )


def handle_socks5_connect_request(payload: bytes) -> Socks5ConnectDecision:
    try:
        request = parse_socks5_request(payload)
    except Socks5Error as exc:
        message = str(exc)
        reply = SOCKS5_COMMAND_NOT_SUPPORTED_REPLY if "unsupported SOCKS command" in message else SOCKS5_GENERAL_FAILURE_REPLY
        return Socks5ConnectDecision(
            status="rejected",
            request_address=None,
            reply=reply,
            should_connect=False,
            message=message,
            performed_side_effects=False,
        )

    return Socks5ConnectDecision(
        status="accepted",
        request_address=request.address,
        reply=SOCKS5_SUCCESS_REPLY,
        should_connect=True,
        message="CONNECT request accepted; connect to upstream",
        performed_side_effects=False,
    )
