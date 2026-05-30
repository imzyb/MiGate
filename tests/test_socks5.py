import pytest

from migate.proxy.socks5 import (
    SOCKS5_NO_ACCEPTABLE_METHODS_RESPONSE,
    SOCKS5_NO_AUTH_RESPONSE,
    Socks5Address,
    Socks5Command,
    Socks5Error,
    Socks5Greeting,
    Socks5Request,
    build_method_selection_response,
    parse_socks5_greeting,
    parse_socks5_request,
)


def test_parse_socks5_greeting_accepts_no_auth_method():
    greeting = parse_socks5_greeting(bytes([0x05, 0x02, 0x00, 0x02]))

    assert greeting == Socks5Greeting(version=5, methods=[0x00, 0x02], selected_method=0x00)
    assert build_method_selection_response(greeting) == SOCKS5_NO_AUTH_RESPONSE


def test_parse_socks5_greeting_rejects_unsupported_version():
    with pytest.raises(Socks5Error, match="unsupported SOCKS version"):
        parse_socks5_greeting(bytes([0x04, 0x01, 0x00]))


def test_parse_socks5_greeting_rejects_truncated_payload():
    with pytest.raises(Socks5Error, match="truncated greeting"):
        parse_socks5_greeting(bytes([0x05, 0x02, 0x00]))


def test_method_selection_returns_no_acceptable_methods_when_no_auth_missing():
    greeting = parse_socks5_greeting(bytes([0x05, 0x01, 0x02]))

    assert greeting.selected_method is None
    assert build_method_selection_response(greeting) == SOCKS5_NO_ACCEPTABLE_METHODS_RESPONSE


def test_parse_socks5_connect_request_with_ipv4_address():
    request = parse_socks5_request(bytes([0x05, 0x01, 0x00, 0x01, 192, 0, 2, 10, 0x01, 0xBB]))

    assert request == Socks5Request(
        version=5,
        command=Socks5Command.CONNECT,
        address=Socks5Address(address_type="ipv4", host="192.0.2.10", port=443),
    )


def test_parse_socks5_connect_request_with_domain_name():
    domain = b"example.com"
    request = parse_socks5_request(bytes([0x05, 0x01, 0x00, 0x03, len(domain)]) + domain + bytes([0x00, 0x50]))

    assert request.command is Socks5Command.CONNECT
    assert request.address == Socks5Address(address_type="domain", host="example.com", port=80)


def test_parse_socks5_connect_request_with_ipv6_address():
    ipv6 = bytes.fromhex("20010db8000000000000000000000001")
    request = parse_socks5_request(bytes([0x05, 0x01, 0x00, 0x04]) + ipv6 + bytes([0x20, 0xFB]))

    assert request.address == Socks5Address(address_type="ipv6", host="2001:db8::1", port=8443)


def test_parse_socks5_request_rejects_bind_and_udp_associate():
    bind_request = bytes([0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])
    udp_request = bytes([0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50])

    with pytest.raises(Socks5Error, match="unsupported SOCKS command"):
        parse_socks5_request(bind_request)
    with pytest.raises(Socks5Error, match="unsupported SOCKS command"):
        parse_socks5_request(udp_request)


def test_parse_socks5_request_rejects_unknown_address_type():
    with pytest.raises(Socks5Error, match="unsupported address type"):
        parse_socks5_request(bytes([0x05, 0x01, 0x00, 0x09, 0x00, 0x50]))


def test_parse_socks5_request_rejects_truncated_domain():
    with pytest.raises(Socks5Error, match="truncated domain address"):
        parse_socks5_request(bytes([0x05, 0x01, 0x00, 0x03, 11]) + b"example")
