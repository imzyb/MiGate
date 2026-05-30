"""Pure SOCKS5 protocol parsing helpers.

This module intentionally does not open sockets, listen on ports, or connect to
remote destinations. It only parses already-received bytes into structured
objects that the future proxy runtime can consume.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import ipaddress


SOCKS5_VERSION = 0x05
SOCKS5_NO_AUTH = 0x00
SOCKS5_NO_ACCEPTABLE_METHODS = 0xFF
SOCKS5_NO_AUTH_RESPONSE = bytes([SOCKS5_VERSION, SOCKS5_NO_AUTH])
SOCKS5_NO_ACCEPTABLE_METHODS_RESPONSE = bytes([SOCKS5_VERSION, SOCKS5_NO_ACCEPTABLE_METHODS])


class Socks5Error(ValueError):
    """Raised when a SOCKS5 frame is malformed or unsupported."""


class Socks5Command(IntEnum):
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03


@dataclass(frozen=True)
class Socks5Greeting:
    version: int
    methods: list[int]
    selected_method: int | None


@dataclass(frozen=True)
class Socks5Address:
    address_type: str
    host: str
    port: int


@dataclass(frozen=True)
class Socks5Request:
    version: int
    command: Socks5Command
    address: Socks5Address


def parse_socks5_greeting(payload: bytes) -> Socks5Greeting:
    if len(payload) < 2:
        raise Socks5Error("truncated greeting")
    version = payload[0]
    if version != SOCKS5_VERSION:
        raise Socks5Error(f"unsupported SOCKS version: {version}")
    method_count = payload[1]
    expected_len = 2 + method_count
    if len(payload) < expected_len:
        raise Socks5Error("truncated greeting")
    methods = list(payload[2:expected_len])
    selected = SOCKS5_NO_AUTH if SOCKS5_NO_AUTH in methods else None
    return Socks5Greeting(version=version, methods=methods, selected_method=selected)


def build_method_selection_response(greeting: Socks5Greeting) -> bytes:
    if greeting.selected_method == SOCKS5_NO_AUTH:
        return SOCKS5_NO_AUTH_RESPONSE
    return SOCKS5_NO_ACCEPTABLE_METHODS_RESPONSE


def parse_socks5_request(payload: bytes) -> Socks5Request:
    if len(payload) < 4:
        raise Socks5Error("truncated request header")
    version, command_byte, reserved, address_type = payload[:4]
    if version != SOCKS5_VERSION:
        raise Socks5Error(f"unsupported SOCKS version: {version}")
    if reserved != 0x00:
        raise Socks5Error("invalid reserved byte")
    try:
        command = Socks5Command(command_byte)
    except ValueError as exc:
        raise Socks5Error(f"unsupported SOCKS command: {command_byte}") from exc
    if command is not Socks5Command.CONNECT:
        raise Socks5Error(f"unsupported SOCKS command: {command.name.lower()}")

    address, consumed = _parse_address(payload[4:], address_type)
    if len(payload[4:]) < consumed + 2:
        raise Socks5Error("truncated port")
    port_start = 4 + consumed
    port = int.from_bytes(payload[port_start : port_start + 2], "big")
    return Socks5Request(version=version, command=command, address=Socks5Address(address.address_type, address.host, port))


def _parse_address(payload: bytes, address_type: int) -> tuple[Socks5Address, int]:
    if address_type == 0x01:
        if len(payload) < 4:
            raise Socks5Error("truncated IPv4 address")
        return Socks5Address("ipv4", str(ipaddress.IPv4Address(payload[:4])), 0), 4
    if address_type == 0x03:
        if len(payload) < 1:
            raise Socks5Error("truncated domain address")
        domain_len = payload[0]
        if len(payload) < 1 + domain_len:
            raise Socks5Error("truncated domain address")
        try:
            host = payload[1 : 1 + domain_len].decode("idna")
        except UnicodeError as exc:
            raise Socks5Error("invalid domain address") from exc
        return Socks5Address("domain", host, 0), 1 + domain_len
    if address_type == 0x04:
        if len(payload) < 16:
            raise Socks5Error("truncated IPv6 address")
        return Socks5Address("ipv6", str(ipaddress.IPv6Address(payload[:16])), 0), 16
    raise Socks5Error(f"unsupported address type: {address_type}")
