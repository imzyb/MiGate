from migate.proxy.socks5 import SOCKS5_NO_ACCEPTABLE_METHODS_RESPONSE, SOCKS5_NO_AUTH_RESPONSE, Socks5Address
from migate.proxy.socks5_connection import Socks5Connection, Socks5ConnectionEvent
from migate.proxy.socks5_session import SOCKS5_COMMAND_NOT_SUPPORTED_REPLY, SOCKS5_SUCCESS_REPLY


def test_socks5_connection_starts_waiting_for_greeting_without_side_effects():
    connection = Socks5Connection()

    assert connection.state == "waiting_greeting"
    assert connection.final_status is None
    assert connection.performed_side_effects is False
    assert connection.events == []


def test_socks5_connection_accepts_greeting_and_waits_for_request():
    connection = Socks5Connection()

    event = connection.receive_greeting(bytes([0x05, 0x01, 0x00]))

    assert event == Socks5ConnectionEvent(
        phase="greeting",
        status="accepted",
        response=SOCKS5_NO_AUTH_RESPONSE,
        message="no-auth method selected",
        performed_side_effects=False,
    )
    assert connection.state == "waiting_request"
    assert connection.final_status is None
    assert connection.events == [event]


def test_socks5_connection_rejects_greeting_and_closes_session():
    connection = Socks5Connection()

    event = connection.receive_greeting(bytes([0x05, 0x01, 0x02]))

    assert event.status == "rejected"
    assert event.response == SOCKS5_NO_ACCEPTABLE_METHODS_RESPONSE
    assert connection.state == "closed"
    assert connection.final_status == "rejected"
    assert connection.performed_side_effects is False


def test_socks5_connection_accepts_connect_request_after_greeting_and_requests_upstream_connect():
    connection = Socks5Connection()
    connection.receive_greeting(bytes([0x05, 0x01, 0x00]))
    domain = b"example.com"

    event = connection.receive_request(bytes([0x05, 0x01, 0x00, 0x03, len(domain)]) + domain + bytes([0x01, 0xBB]))

    assert event == Socks5ConnectionEvent(
        phase="connect",
        status="accepted",
        response=SOCKS5_SUCCESS_REPLY,
        message="CONNECT request accepted; connect to upstream",
        request_address=Socks5Address(address_type="domain", host="example.com", port=443),
        should_connect=True,
        performed_side_effects=False,
    )
    assert connection.state == "accepted"
    assert connection.final_status == "accepted"
    assert connection.request_address == Socks5Address(address_type="domain", host="example.com", port=443)
    assert connection.should_connect is True
    assert connection.performed_side_effects is False


def test_socks5_connection_rejects_request_before_greeting():
    connection = Socks5Connection()

    event = connection.receive_request(bytes([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]))

    assert event.phase == "connect"
    assert event.status == "rejected"
    assert event.response is None
    assert event.message == "SOCKS5 request received before accepted greeting"
    assert connection.state == "closed"
    assert connection.final_status == "rejected"


def test_socks5_connection_rejects_unsupported_command_and_closes():
    connection = Socks5Connection()
    connection.receive_greeting(bytes([0x05, 0x01, 0x00]))

    event = connection.receive_request(bytes([0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]))

    assert event.status == "rejected"
    assert event.response == SOCKS5_COMMAND_NOT_SUPPORTED_REPLY
    assert event.should_connect is False
    assert connection.state == "closed"
    assert connection.final_status == "rejected"


def test_socks5_connection_rejects_frames_after_closed_without_new_side_effects():
    connection = Socks5Connection()
    connection.receive_greeting(bytes([0x05, 0x01, 0x02]))

    event = connection.receive_greeting(bytes([0x05, 0x01, 0x00]))

    assert event.phase == "closed"
    assert event.status == "rejected"
    assert event.response is None
    assert event.message == "SOCKS5 connection is already closed"
    assert event.performed_side_effects is False
    assert connection.state == "closed"
    assert connection.final_status == "rejected"
