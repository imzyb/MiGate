"""Tests for client traffic repository and xray user traffic stats."""

from __future__ import annotations

import pytest

from migate.database.repository import (
    ClientTrafficRecord,
    ClientTrafficRepository,
    InboundRepository,
)
from migate.xray.stats import XrayStatEntry, XrayTrafficStats


# --- Fixtures ---


@pytest.fixture()
def db(tmp_path):
    return tmp_path / "test.db"


@pytest.fixture()
def inbound_repo(db):
    r = InboundRepository(db)
    r.initialize()
    return r


@pytest.fixture()
def traffic_repo(db, inbound_repo):
    """Create a ClientTrafficRepository; inbound_repo ensures inbounds table exists."""
    r = ClientTrafficRepository(db)
    r.initialize()
    return r


@pytest.fixture()
def inbound(inbound_repo):
    return inbound_repo.create_inbound(
        remark="test",
        protocol="vless",
        port=443,
        listen="0.0.0.0",
        settings="{}",
        stream_settings="{}",
    )


# --- Table creation ---


def test_table_creation(traffic_repo, db):
    """Table should exist after initialize()."""
    import sqlite3

    conn = sqlite3.connect(db)
    tables = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    conn.close()
    assert "client_traffic" in tables


def test_table_created_via_inbound_initialize(db):
    """InboundRepository.initialize() should also create client_traffic table."""
    import sqlite3

    ir = InboundRepository(db)
    ir.initialize()

    conn = sqlite3.connect(db)
    tables = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    conn.close()
    assert "client_traffic" in tables


# --- upsert_traffic ---


def test_upsert_insert(traffic_repo, inbound):
    record = traffic_repo.upsert_traffic("alice@example.com", inbound.id, 100, 200)

    assert isinstance(record, ClientTrafficRecord)
    assert record.email == "alice@example.com"
    assert record.inbound_id == inbound.id
    assert record.up_bytes == 100
    assert record.down_bytes == 200
    assert record.id > 0
    assert record.created_at is not None


def test_upsert_update(traffic_repo, inbound):
    traffic_repo.upsert_traffic("bob@example.com", inbound.id, 100, 200)
    record = traffic_repo.upsert_traffic("bob@example.com", inbound.id, 500, 800)

    assert record.up_bytes == 500
    assert record.down_bytes == 800


# --- get_by_email ---


def test_get_by_email_found(traffic_repo, inbound):
    traffic_repo.upsert_traffic("carol@example.com", inbound.id, 10, 20)

    record = traffic_repo.get_by_email("carol@example.com")

    assert record is not None
    assert record.email == "carol@example.com"
    assert record.up_bytes == 10
    assert record.down_bytes == 20


def test_get_by_email_not_found(traffic_repo):
    assert traffic_repo.get_by_email("nobody@example.com") is None


# --- get_by_inbound ---


def test_get_by_inbound(traffic_repo, inbound):
    traffic_repo.upsert_traffic("u1@example.com", inbound.id, 1, 2)
    traffic_repo.upsert_traffic("u2@example.com", inbound.id, 3, 4)

    records = traffic_repo.get_by_inbound(inbound.id)

    assert len(records) == 2
    emails = {r.email for r in records}
    assert emails == {"u1@example.com", "u2@example.com"}


def test_get_by_inbound_empty(traffic_repo, inbound):
    assert traffic_repo.get_by_inbound(inbound.id) == []


# --- update_limits ---


def test_update_limits(traffic_repo, inbound):
    traffic_repo.upsert_traffic("dave@example.com", inbound.id, 0, 0)

    updated = traffic_repo.update_limits(
        "dave@example.com",
        traffic_limit_bytes=1_000_000,
        expire_at="2026-12-31",
    )

    assert updated is not None
    assert updated.traffic_limit_bytes == 1_000_000
    assert updated.expire_at == "2026-12-31"


def test_update_limits_not_found(traffic_repo):
    result = traffic_repo.update_limits("ghost@example.com", traffic_limit_bytes=100)
    assert result is None


def test_update_limits_partial(traffic_repo, inbound):
    traffic_repo.upsert_traffic("eve@example.com", inbound.id, 0, 0)

    updated = traffic_repo.update_limits("eve@example.com", traffic_limit_bytes=500)
    assert updated is not None
    assert updated.traffic_limit_bytes == 500
    assert updated.expire_at is None


# --- reset_traffic ---


def test_reset_traffic(traffic_repo, inbound):
    traffic_repo.upsert_traffic("frank@example.com", inbound.id, 999, 888)

    reset = traffic_repo.reset_traffic("frank@example.com")

    assert reset is not None
    assert reset.up_bytes == 0
    assert reset.down_bytes == 0


def test_reset_traffic_not_found(traffic_repo):
    assert traffic_repo.reset_traffic("ghost@example.com") is None


# --- Stats: user_traffic ---


def test_user_traffic():
    stats = XrayTrafficStats(entries=[
        XrayStatEntry(name="user>>>alice>>>traffic>>>uplink", value=1024),
        XrayStatEntry(name="user>>>alice>>>traffic>>>downlink", value=2048),
        XrayStatEntry(name="user>>>bob>>>traffic>>>uplink", value=512),
        XrayStatEntry(name="inbound>>>vless>>>traffic>>>uplink", value=999),
    ])
    up, down = stats.user_traffic("alice")
    assert up == 1024
    assert down == 2048


def test_user_traffic_no_match():
    stats = XrayTrafficStats(entries=[
        XrayStatEntry(name="user>>>alice>>>traffic>>>uplink", value=100),
    ])
    up, down = stats.user_traffic("bob")
    assert up == 0
    assert down == 0


def test_user_traffic_empty():
    stats = XrayTrafficStats(entries=[])
    up, down = stats.user_traffic("alice")
    assert up == 0
    assert down == 0


# --- Stats: all_user_traffic ---


def test_all_user_traffic():
    stats = XrayTrafficStats(entries=[
        XrayStatEntry(name="user>>>alice>>>traffic>>>uplink", value=100),
        XrayStatEntry(name="user>>>alice>>>traffic>>>downlink", value=200),
        XrayStatEntry(name="user>>>bob>>>traffic>>>uplink", value=300),
        XrayStatEntry(name="user>>>bob>>>traffic>>>downlink", value=400),
        XrayStatEntry(name="inbound>>>vless>>>traffic>>>uplink", value=999),
        XrayStatEntry(name="outbound>>>proxy>>>traffic>>>uplink", value=888),
    ])
    result = stats.all_user_traffic()
    assert len(result) == 2
    assert result["alice"] == (100, 200)
    assert result["bob"] == (300, 400)


def test_all_user_traffic_empty():
    stats = XrayTrafficStats(entries=[])
    assert stats.all_user_traffic() == {}


def test_all_user_traffic_ignores_non_user_entries():
    stats = XrayTrafficStats(entries=[
        XrayStatEntry(name="inbound>>>main>>>traffic>>>uplink", value=100),
        XrayStatEntry(name="outbound>>>proxy>>>traffic>>>downlink", value=200),
    ])
    assert stats.all_user_traffic() == {}
