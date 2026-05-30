import json

from migate.config import MiGateConfig
from migate.proxy.socks5_listener import (
    Socks5ServeEvent,
    Socks5ServeEventSummary,
    Socks5ServeResult,
    Socks5ServeOutputWriteResult,
    render_socks5_serve_json,
    render_socks5_serve_jsonl,
    render_socks5_serve_output,
    render_socks5_serve_output_write_result,
    render_socks5_serve_result,
    write_socks5_serve_output,
    socks5_serve_result_to_dict,
    run_socks5_serve_placeholder,
    start_socks5_placeholder_server,
)


def test_summarize_socks5_serve_events_counts_statuses_without_side_effects():
    from migate.proxy.socks5_listener import summarize_socks5_serve_events

    events = [
        Socks5ServeEvent(1, "connect", "accepted", "example.com", 443, False),
        Socks5ServeEvent(2, "greeting", "rejected", None, None, False),
        Socks5ServeEvent(3, "greeting", "timed_out", None, None, False),
    ]

    summary = summarize_socks5_serve_events(events)

    assert summary == Socks5ServeEventSummary(
        total_events=3,
        accepted_events=1,
        rejected_events=1,
        timed_out_events=1,
        upstream_connected_events=0,
        performed_side_effects=False,
    )


def test_socks5_serve_result_to_dict_includes_summary_and_events():
    result = Socks5ServeResult(
        status="dry_run",
        message="SOCKS5 listener dry-run; no socket opened",
        bind_host="127.0.0.1",
        bind_port=34501,
        listener_started=False,
        accepted_connections=0,
        upstream_connections=0,
        timed_out_connections=0,
        max_clients=1,
        client_timeout=5.0,
        events=[
            Socks5ServeEvent(
                client_id=1,
                phase="connect",
                status="accepted",
                target_host="example.com",
                target_port=443,
                upstream_connected=False,
            )
        ],
        performed_side_effects=False,
    )

    payload = socks5_serve_result_to_dict(result)

    assert payload == {
        "status": "dry_run",
        "message": "SOCKS5 listener dry-run; no socket opened",
        "bind_host": "127.0.0.1",
        "bind_port": 34501,
        "listener_started": False,
        "accepted_connections": 0,
        "upstream_connections": 0,
        "timed_out_connections": 0,
        "max_clients": 1,
        "client_timeout": 5.0,
        "event_summary": {
            "total_events": 1,
            "accepted_events": 1,
            "rejected_events": 0,
            "timed_out_events": 0,
            "upstream_connected_events": 0,
            "performed_side_effects": False,
        },
        "events": [
            {
                "client_id": 1,
                "phase": "connect",
                "status": "accepted",
                "target_host": "example.com",
                "target_port": 443,
                "upstream_connected": False,
            }
        ],
        "performed_side_effects": False,
    }


def test_render_socks5_serve_json_matches_result_dict_contract():
    result = Socks5ServeResult(
        status="rejected",
        message="SOCKS5 listener requires yes=True and allow_network_listen=True",
        bind_host="127.0.0.1",
        bind_port=34501,
        listener_started=False,
        accepted_connections=0,
        upstream_connections=0,
        timed_out_connections=0,
        max_clients=1,
        client_timeout=5.0,
        events=[Socks5ServeEvent(1, "greeting", "rejected", None, None, False)],
        performed_side_effects=False,
    )

    text = render_socks5_serve_json(result)
    payload = json.loads(text)

    assert payload == socks5_serve_result_to_dict(result)
    assert payload["status"] == "rejected"
    assert payload["event_summary"]["rejected_events"] == 1
    assert payload["events"][0]["phase"] == "greeting"
    assert text.endswith("\n")


def test_render_socks5_serve_jsonl_emits_summary_then_event_rows():
    result = Socks5ServeResult(
        status="stopped",
        message="handled two clients",
        bind_host="127.0.0.1",
        bind_port=34501,
        listener_started=True,
        accepted_connections=2,
        upstream_connections=0,
        timed_out_connections=1,
        max_clients=2,
        client_timeout=0.5,
        events=[
            Socks5ServeEvent(1, "connect", "accepted", "example.com", 443, False),
            Socks5ServeEvent(2, "greeting", "timed_out", None, None, False),
        ],
        performed_side_effects=True,
    )

    lines = [json.loads(line) for line in render_socks5_serve_jsonl(result).splitlines()]

    assert lines == [
        {
            "type": "summary",
            "status": "stopped",
            "message": "handled two clients",
            "bind_host": "127.0.0.1",
            "bind_port": 34501,
            "listener_started": True,
            "accepted_connections": 2,
            "upstream_connections": 0,
            "timed_out_connections": 1,
            "max_clients": 2,
            "client_timeout": 0.5,
            "total_events": 2,
            "accepted_events": 1,
            "rejected_events": 0,
            "timed_out_events": 1,
            "upstream_connected_events": 0,
            "performed_side_effects": True,
        },
        {
            "type": "event",
            "client_id": 1,
            "phase": "connect",
            "status": "accepted",
            "target_host": "example.com",
            "target_port": 443,
            "upstream_connected": False,
        },
        {
            "type": "event",
            "client_id": 2,
            "phase": "greeting",
            "status": "timed_out",
            "target_host": None,
            "target_port": None,
            "upstream_connected": False,
        },
    ]
    assert render_socks5_serve_jsonl(result).endswith("\n")


def test_render_socks5_serve_output_dispatches_text_json_and_jsonl_formats():
    result = Socks5ServeResult(
        status="dry_run",
        message="SOCKS5 listener dry-run; no socket opened",
        bind_host="127.0.0.1",
        bind_port=34501,
        listener_started=False,
        accepted_connections=0,
        upstream_connections=0,
        timed_out_connections=0,
        max_clients=1,
        client_timeout=5.0,
        events=[],
        performed_side_effects=False,
    )

    assert render_socks5_serve_output(result, output_format="text") == render_socks5_serve_result(result) + "\n"
    assert render_socks5_serve_output(result, output_format="json") == render_socks5_serve_json(result)
    assert render_socks5_serve_output(result, output_format="jsonl") == render_socks5_serve_jsonl(result)


def test_render_socks5_serve_output_rejects_unknown_format_without_side_effects():
    result = Socks5ServeResult(
        status="dry_run",
        message="SOCKS5 listener dry-run; no socket opened",
        bind_host="127.0.0.1",
        bind_port=34501,
        listener_started=False,
        accepted_connections=0,
        upstream_connections=0,
        timed_out_connections=0,
        max_clients=1,
        client_timeout=5.0,
        events=[],
        performed_side_effects=False,
    )

    try:
        render_socks5_serve_output(result, output_format="yaml")
    except ValueError as exc:
        assert str(exc) == "unsupported format: yaml; supported formats: text, json, jsonl"
    else:
        raise AssertionError("expected ValueError for unsupported format")


def test_write_socks5_serve_output_rejects_without_double_file_write_gate(tmp_path):
    target = tmp_path / "serve.jsonl"
    result = Socks5ServeResult(
        status="dry_run",
        message="SOCKS5 listener dry-run; no socket opened",
        bind_host="127.0.0.1",
        bind_port=34501,
        listener_started=False,
        accepted_connections=0,
        upstream_connections=0,
        timed_out_connections=0,
        max_clients=1,
        client_timeout=5.0,
        events=[],
        performed_side_effects=False,
    )

    write_result = write_socks5_serve_output(
        result,
        output_format="jsonl",
        target=str(target),
        yes=True,
        allow_file_write=False,
    )

    assert write_result == Socks5ServeOutputWriteResult(
        status="rejected",
        message="SOCKS5 serve output write requires yes=True and allow_file_write=True",
        target=str(target),
        bytes_written=0,
        performed_side_effects=False,
    )
    assert not target.exists()


def test_write_socks5_serve_output_writes_rendered_output_when_double_gated(tmp_path):
    target = tmp_path / "nested" / "serve.jsonl"
    result = Socks5ServeResult(
        status="dry_run",
        message="SOCKS5 listener dry-run; no socket opened",
        bind_host="127.0.0.1",
        bind_port=34501,
        listener_started=False,
        accepted_connections=0,
        upstream_connections=0,
        timed_out_connections=0,
        max_clients=1,
        client_timeout=5.0,
        events=[],
        performed_side_effects=False,
    )

    write_result = write_socks5_serve_output(
        result,
        output_format="jsonl",
        target=str(target),
        yes=True,
        allow_file_write=True,
    )

    expected = render_socks5_serve_output(result, output_format="jsonl")
    assert target.read_text(encoding="utf-8") == expected
    assert write_result == Socks5ServeOutputWriteResult(
        status="written",
        message="SOCKS5 serve output written",
        target=str(target),
        bytes_written=len(expected.encode("utf-8")),
        performed_side_effects=True,
    )


def test_render_socks5_serve_output_write_result_is_structured():
    result = Socks5ServeOutputWriteResult(
        status="written",
        message="SOCKS5 serve output written",
        target="/tmp/serve.jsonl",
        bytes_written=123,
        performed_side_effects=True,
    )

    text = render_socks5_serve_output_write_result(result)

    assert "SOCKS5 serve output write result" in text
    assert "status: written" in text
    assert "target: /tmp/serve.jsonl" in text
    assert "bytes_written: 123" in text
    assert "performed_side_effects: True" in text


def test_run_socks5_serve_placeholder_defaults_to_dry_run_without_listening():
    calls = []

    result = run_socks5_serve_placeholder(MiGateConfig(), server_starter=lambda *_args, **_kwargs: calls.append("called"))

    assert result == Socks5ServeResult(
        status="dry_run",
        message="SOCKS5 listener dry-run; no socket opened",
        bind_host="127.0.0.1",
        bind_port=34501,
        listener_started=False,
        accepted_connections=0,
        upstream_connections=0,
        timed_out_connections=0,
        max_clients=1,
        client_timeout=5.0,
        events=[],
        performed_side_effects=False,
    )
    assert calls == []


def test_run_socks5_serve_placeholder_rejects_real_listen_without_double_gate():
    calls = []

    result = run_socks5_serve_placeholder(
        MiGateConfig(),
        dry_run=False,
        yes=True,
        allow_network_listen=False,
        server_starter=lambda *_args, **_kwargs: calls.append("called"),
    )

    assert result.status == "rejected"
    assert result.listener_started is False
    assert result.performed_side_effects is False
    assert "requires yes=True and allow_network_listen=True" in result.message
    assert calls == []


def test_run_socks5_serve_placeholder_calls_injected_server_starter_only_when_double_gated():
    calls = []

    def fake_server_starter(host: str, port: int, max_clients: int, client_timeout: float):
        calls.append((host, port, max_clients, client_timeout))
        return Socks5ServeResult(
            status="listening_placeholder",
            message="SOCKS5 listener placeholder handled zero clients",
            bind_host=host,
            bind_port=port,
            listener_started=True,
            accepted_connections=0,
            upstream_connections=0,
            timed_out_connections=0,
            max_clients=max_clients,
            client_timeout=client_timeout,
            events=[],
            performed_side_effects=True,
        )

    result = run_socks5_serve_placeholder(
        MiGateConfig(),
        dry_run=False,
        yes=True,
        allow_network_listen=True,
        server_starter=fake_server_starter,
    )

    assert result.status == "listening_placeholder"
    assert result.listener_started is True
    assert result.upstream_connections == 0
    assert result.performed_side_effects is True
    assert calls == [("127.0.0.1", 34501, 1, 5.0)]


def test_start_socks5_placeholder_server_delegates_to_asyncio_server(monkeypatch):
    calls = []

    async def fake_serve_once(host: str, port: int, max_clients: int, client_timeout: float):
        calls.append((host, port, max_clients, client_timeout))
        return Socks5ServeResult(
            status="stopped",
            message="handled one client",
            bind_host=host,
            bind_port=port,
            listener_started=True,
            accepted_connections=1,
            upstream_connections=0,
            timed_out_connections=0,
            max_clients=max_clients,
            client_timeout=client_timeout,
            events=[],
            performed_side_effects=True,
        )

    import migate.proxy.socks5_listener as listener_module

    monkeypatch.setattr(listener_module, "_serve_socks5_once", fake_serve_once)

    result = start_socks5_placeholder_server("127.0.0.1", 0, 1, 5.0)

    assert result.status == "stopped"
    assert result.listener_started is True
    assert result.accepted_connections == 1
    assert result.upstream_connections == 0
    assert result.performed_side_effects is True
    assert calls == [("127.0.0.1", 0, 1, 5.0)]


def test_render_socks5_serve_result_is_structured_and_mentions_no_upstream_connections():
    result = Socks5ServeResult(
        status="dry_run",
        message="SOCKS5 listener dry-run; no socket opened",
        bind_host="127.0.0.1",
        bind_port=34501,
        listener_started=False,
        accepted_connections=0,
        upstream_connections=0,
        timed_out_connections=0,
        max_clients=1,
        client_timeout=5.0,
        events=[
            Socks5ServeEvent(
                client_id=1,
                phase="connect",
                status="accepted",
                target_host="example.com",
                target_port=443,
                upstream_connected=False,
            )
        ],
        performed_side_effects=False,
    )

    text = render_socks5_serve_result(result)

    assert "SOCKS5 serve result" in text
    assert "status: dry_run" in text
    assert "listener_started: False" in text
    assert "accepted_connections: 0" in text
    assert "upstream_connections: 0" in text
    assert "timed_out_connections: 0" in text
    assert "max_clients: 1" in text
    assert "client_timeout: 5.0" in text
    assert "events: 1" in text
    assert "accepted_events: 1" in text
    assert "rejected_events: 0" in text
    assert "timed_out_events: 0" in text
    assert "upstream_connected_events: 0" in text
    assert "event[1]: client_id=1 phase=connect status=accepted target=example.com:443 upstream_connected=False" in text
    assert "performed_side_effects: False" in text
