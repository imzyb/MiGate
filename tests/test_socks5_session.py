from migate.proxy.socks5 import SOCKS5_NO_ACCEPTABLE_METHODS_RESPONSE, SOCKS5_NO_AUTH_RESPONSE, Socks5Address
from migate.proxy.socks5_session import (
    SOCKS5_COMMAND_NOT_SUPPORTED_REPLY,
    SOCKS5_GENERAL_FAILURE_REPLY,
    SOCKS5_SUCCESS_REPLY,
    Socks5ConnectDecision,
    Socks5HandshakeResult,
    handle_socks5_connect_request,
    handle_socks5_greeting,
)


def test_handle_socks5_greeting_accepts_no_auth_without_side_effects():
    result = handle_socks5_greeting(bytes([0x05, 0x01, 0x00]))

    assert result == Socks5HandshakeResult(
        status="accepted",
        response=SOCKS5_NO_AUTH_RESPONSE,
        selected_method=0x00,
        message="no-auth method selected",
        performed_side_effects=False,
    )


def test_handle_socks5_greeting_rejects_when_no_auth_missing():
    result = handle_socks5_greeting(bytes([0x05, 0x01, 0x02]))

    assert result.status == "rejected"
    assert result.response == SOCKS5_NO_ACCEPTABLE_METHODS_RESPONSE
    assert result.selected_method is None
    assert result.performed_side_effects is False


def test_handle_socks5_greeting_rejects_malformed_payload_with_no_acceptable_methods_response():
    result = handle_socks5_greeting(bytes([0x04, 0x01, 0x00]))

    assert result.status == "rejected"
    assert result.response == SOCKS5_NO_ACCEPTABLE_METHODS_RESPONSE
    assert "unsupported SOCKS version" in result.message
    assert result.performed_side_effects is False


def test_handle_socks5_connect_request_accepts_domain_and_requests_upstream_connect():
    domain = b"example.com"
    result = handle_socks5_connect_request(bytes([0x05, 0x01, 0x00, 0x03, len(domain)]) + domain + bytes([0x01, 0xBB]))

    assert result == Socks5ConnectDecision(
        status="accepted",
        request_address=Socks5Address(address_type="domain", host="example.com", port=443),
        reply=SOCKS5_SUCCESS_REPLY,
        should_connect=True,
        message="CONNECT request accepted; connect to upstream",
        performed_side_effects=False,
    )


def test_handle_socks5_connect_request_accepts_ipv4_and_requests_upstream_connect():
    result = handle_socks5_connect_request(bytes([0x05, 0x01, 0x00, 0x01, 192, 0, 2, 20, 0x00, 0x50]))

    assert result.status == "accepted"
    assert result.request_address == Socks5Address(address_type="ipv4", host="192.0.2.20", port=80)
    assert result.reply == SOCKS5_SUCCESS_REPLY
    assert result.should_connect is True
    assert result.performed_side_effects is False


def test_handle_socks5_connect_request_rejects_bind_with_command_not_supported_reply():
    result = handle_socks5_connect_request(bytes([0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]))

    assert result.status == "rejected"
    assert result.request_address is None
    assert result.reply == SOCKS5_COMMAND_NOT_SUPPORTED_REPLY
    assert result.should_connect is False
    assert "unsupported SOCKS command" in result.message
    assert result.performed_side_effects is False


def test_handle_socks5_connect_request_rejects_malformed_payload_with_general_failure_reply():
    result = handle_socks5_connect_request(bytes([0x05, 0x01, 0x00, 0x03, 11]) + b"example")

    assert result.status == "rejected"
    assert result.request_address is None
    assert result.reply == SOCKS5_GENERAL_FAILURE_REPLY
    assert result.should_connect is False
    assert "truncated domain address" in result.message
    assert result.performed_side_effects is False
