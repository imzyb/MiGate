"""In-memory SOCKS5 single-connection driver.

This module sequences greeting and CONNECT decisions for a single logical
client connection. It intentionally does not own sockets, listen on ports,
connect to upstream hosts, or forward traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from migate.proxy.socks5 import Socks5Address
from migate.proxy.socks5_session import handle_socks5_connect_request, handle_socks5_greeting


@dataclass(frozen=True)
class Socks5ConnectionEvent:
    phase: str
    status: str
    response: bytes | None
    message: str
    request_address: Socks5Address | None = None
    should_connect: bool = False
    performed_side_effects: bool = False


@dataclass
class Socks5Connection:
    state: str = "waiting_greeting"
    final_status: str | None = None
    request_address: Socks5Address | None = None
    should_connect: bool = False
    performed_side_effects: bool = False
    events: list[Socks5ConnectionEvent] = field(default_factory=list)

    def receive_greeting(self, payload: bytes) -> Socks5ConnectionEvent:
        if self.state == "closed":
            return self._closed_event()
        if self.state != "waiting_greeting":
            event = Socks5ConnectionEvent(
                phase="greeting",
                status="rejected",
                response=None,
                message="SOCKS5 greeting received after greeting phase",
                performed_side_effects=False,
            )
            self._close_rejected(event)
            return event

        result = handle_socks5_greeting(payload)
        event = Socks5ConnectionEvent(
            phase="greeting",
            status=result.status,
            response=result.response,
            message=result.message,
            performed_side_effects=result.performed_side_effects,
        )
        self.events.append(event)
        if result.status == "accepted":
            self.state = "waiting_request"
        else:
            self.state = "closed"
            self.final_status = "rejected"
        return event

    def receive_request(self, payload: bytes) -> Socks5ConnectionEvent:
        if self.state == "closed":
            return self._closed_event(phase="connect")
        if self.state != "waiting_request":
            event = Socks5ConnectionEvent(
                phase="connect",
                status="rejected",
                response=None,
                message="SOCKS5 request received before accepted greeting",
                performed_side_effects=False,
            )
            self._close_rejected(event)
            return event

        decision = handle_socks5_connect_request(payload)
        event = Socks5ConnectionEvent(
            phase="connect",
            status=decision.status,
            response=decision.reply,
            message=decision.message,
            request_address=decision.request_address,
            should_connect=decision.should_connect,
            performed_side_effects=decision.performed_side_effects,
        )
        self.events.append(event)
        self.request_address = decision.request_address
        self.should_connect = decision.should_connect
        if decision.status == "accepted":
            self.state = "accepted"
            self.final_status = "accepted"
        else:
            self.state = "closed"
            self.final_status = "rejected"
        return event

    def _closed_event(self, *, phase: str = "closed") -> Socks5ConnectionEvent:
        event = Socks5ConnectionEvent(
            phase=phase if phase == "connect" else "closed",
            status="rejected",
            response=None,
            message="SOCKS5 connection is already closed",
            performed_side_effects=False,
        )
        self.events.append(event)
        return event

    def _close_rejected(self, event: Socks5ConnectionEvent) -> None:
        self.events.append(event)
        self.state = "closed"
        self.final_status = "rejected"
