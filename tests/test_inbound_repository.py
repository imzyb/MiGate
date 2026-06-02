"""Tests for inbound rule repository — 3x-ui style inbound management."""

from __future__ import annotations

import pytest

from migate.database.repository import InboundRecord, InboundRepository


@pytest.fixture()
def repo(tmp_path):
    db = tmp_path / "test.db"
    r = InboundRepository(db)
    r.initialize()
    return r


def test_create_inbound_record(repo):
    record = repo.create_inbound(
        remark="HK VLESS",
        protocol="vless",
        port=443,
        listen="0.0.0.0",
        settings='{"clients":[{"id":"abc"}]}',
        stream_settings='{"network":"tcp","security":"tls"}',
    )

    assert record.id > 0
    assert record.remark == "HK VLESS"
    assert record.protocol == "vless"
    assert record.port == 443
    assert record.listen == "0.0.0.0"
    assert record.enabled is True
    assert record.up_bytes == 0
    assert record.down_bytes == 0


def test_list_inbounds_returns_all(repo):
    repo.create_inbound(remark="A", protocol="vless", port=443, listen="0.0.0.0", settings="{}", stream_settings="{}")
    repo.create_inbound(remark="B", protocol="trojan", port=8443, listen="0.0.0.0", settings="{}", stream_settings="{}")

    result = repo.list_inbounds()

    assert len(result) == 2
    assert {r.remark for r in result} == {"A", "B"}


def test_get_inbound_by_id(repo):
    created = repo.create_inbound(remark="Test", protocol="vmess", port=10001, listen="0.0.0.0", settings="{}", stream_settings="{}")

    found = repo.get_inbound(created.id)

    assert found is not None
    assert found.id == created.id
    assert found.remark == "Test"


def test_get_inbound_returns_none_for_missing(repo):
    assert repo.get_inbound(9999) is None


def test_update_inbound(repo):
    created = repo.create_inbound(remark="Old", protocol="vless", port=443, listen="0.0.0.0", settings="{}", stream_settings="{}")

    updated = repo.update_inbound(
        created.id,
        remark="New",
        protocol="trojan",
        port=8443,
        listen="127.0.0.1",
        settings='{"password":"test"}',
        stream_settings='{"network":"ws"}',
    )

    assert updated is not None
    assert updated.remark == "New"
    assert updated.protocol == "trojan"
    assert updated.port == 8443
    assert updated.listen == "127.0.0.1"


def test_update_inbound_returns_none_for_missing(repo):
    assert repo.update_inbound(9999, remark="X", protocol="vless", port=443, listen="0.0.0.0", settings="{}", stream_settings="{}") is None


def test_delete_inbound(repo):
    created = repo.create_inbound(remark="Del", protocol="vless", port=443, listen="0.0.0.0", settings="{}", stream_settings="{}")

    assert repo.delete_inbound(created.id) is True
    assert repo.get_inbound(created.id) is None


def test_delete_inbound_returns_false_for_missing(repo):
    assert repo.delete_inbound(9999) is False


def test_set_inbound_enabled(repo):
    created = repo.create_inbound(remark="Toggle", protocol="vless", port=443, listen="0.0.0.0", settings="{}", stream_settings="{}")

    updated = repo.set_inbound_enabled(created.id, enabled=False)

    assert updated is not None
    assert updated.enabled is False

    updated2 = repo.set_inbound_enabled(created.id, enabled=True)

    assert updated2 is not None
    assert updated2.enabled is True


def test_update_traffic_stats(repo):
    created = repo.create_inbound(remark="Stats", protocol="vless", port=443, listen="0.0.0.0", settings="{}", stream_settings="{}")

    updated = repo.update_traffic(created.id, up_bytes=1024, down_bytes=2048)

    assert updated is not None
    assert updated.up_bytes == 1024
    assert updated.down_bytes == 2048

    updated2 = repo.update_traffic(created.id, up_bytes=512, down_bytes=512)

    assert updated2 is not None
    assert updated2.up_bytes == 1536
    assert updated2.down_bytes == 2560
