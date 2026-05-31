"""SOCKS5 listener planning and bounded runtime helpers.

The plan remains side-effect-free, while the gated serve helpers can open a
local listener and relay accepted SOCKS5 CONNECT sessions upstream.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
import asyncio
import json

from migate.config import MiGateConfig

SOCKS5_LISTENER_BIND_HOST = "127.0.0.1"
SOCKS5_LISTENER_BIND_PORT = 34501


@dataclass(frozen=True)
class Socks5ListenerPlan:
    bind_host: str
    bind_port: int
    protocol: str
    connection_driver: str
    upstream_mode: str
    will_listen: bool
    will_connect_upstream: bool
    performed_side_effects: bool


@dataclass(frozen=True)
class Socks5ServeEvent:
    client_id: int
    phase: str
    status: str
    target_host: str | None
    target_port: int | None
    upstream_connected: bool


@dataclass(frozen=True)
class Socks5ServeEventSummary:
    total_events: int
    accepted_events: int
    rejected_events: int
    timed_out_events: int
    upstream_connected_events: int
    performed_side_effects: bool


@dataclass(frozen=True)
class Socks5ServeResult:
    status: str
    message: str
    bind_host: str
    bind_port: int
    listener_started: bool
    accepted_connections: int
    upstream_connections: int
    timed_out_connections: int
    max_clients: int
    client_timeout: float
    events: list[Socks5ServeEvent]
    performed_side_effects: bool


@dataclass(frozen=True)
class Socks5ServeOutputWriteResult:
    status: str
    message: str
    target: str
    bytes_written: int
    path_policy_reason: str
    serve_performed_side_effects: bool
    file_performed_side_effects: bool
    performed_side_effects: bool


@dataclass(frozen=True)
class Socks5ServeOutputPathPolicy:
    project_root: Path = field(default_factory=Path.cwd)
    tmp_root: Path = Path("/tmp")


Socks5ServerStarter = Callable[[str, int, int, float], Socks5ServeResult]


def build_socks5_listener_plan(config: MiGateConfig) -> Socks5ListenerPlan:
    return Socks5ListenerPlan(
        bind_host=config.proxy.socks_host,
        bind_port=config.proxy.socks_port,
        protocol="socks5",
        connection_driver="Socks5Connection",
        upstream_mode="direct_tcp_relay",
        will_listen=True,
        will_connect_upstream=True,
        performed_side_effects=False,
    )


def summarize_socks5_serve_events(events: list[Socks5ServeEvent]) -> Socks5ServeEventSummary:
    return Socks5ServeEventSummary(
        total_events=len(events),
        accepted_events=sum(1 for event in events if event.status == "accepted"),
        rejected_events=sum(1 for event in events if event.status == "rejected"),
        timed_out_events=sum(1 for event in events if event.status == "timed_out"),
        upstream_connected_events=sum(1 for event in events if event.upstream_connected),
        performed_side_effects=False,
    )


def socks5_serve_result_to_dict(result: Socks5ServeResult) -> dict[str, object]:
    summary = summarize_socks5_serve_events(result.events)
    return {
        "status": result.status,
        "message": result.message,
        "bind_host": result.bind_host,
        "bind_port": result.bind_port,
        "listener_started": result.listener_started,
        "accepted_connections": result.accepted_connections,
        "upstream_connections": result.upstream_connections,
        "timed_out_connections": result.timed_out_connections,
        "max_clients": result.max_clients,
        "client_timeout": result.client_timeout,
        "event_summary": {
            "total_events": summary.total_events,
            "accepted_events": summary.accepted_events,
            "rejected_events": summary.rejected_events,
            "timed_out_events": summary.timed_out_events,
            "upstream_connected_events": summary.upstream_connected_events,
            "performed_side_effects": summary.performed_side_effects,
        },
        "events": [
            {
                "client_id": event.client_id,
                "phase": event.phase,
                "status": event.status,
                "target_host": event.target_host,
                "target_port": event.target_port,
                "upstream_connected": event.upstream_connected,
            }
            for event in result.events
        ],
        "performed_side_effects": result.performed_side_effects,
    }


def render_socks5_serve_json(result: Socks5ServeResult) -> str:
    return json.dumps(socks5_serve_result_to_dict(result), sort_keys=True) + "\n"


def render_socks5_serve_jsonl(result: Socks5ServeResult) -> str:
    summary = summarize_socks5_serve_events(result.events)
    rows: list[dict[str, object]] = [
        {
            "type": "summary",
            "status": result.status,
            "message": result.message,
            "bind_host": result.bind_host,
            "bind_port": result.bind_port,
            "listener_started": result.listener_started,
            "accepted_connections": result.accepted_connections,
            "upstream_connections": result.upstream_connections,
            "timed_out_connections": result.timed_out_connections,
            "max_clients": result.max_clients,
            "client_timeout": result.client_timeout,
            "total_events": summary.total_events,
            "accepted_events": summary.accepted_events,
            "rejected_events": summary.rejected_events,
            "timed_out_events": summary.timed_out_events,
            "upstream_connected_events": summary.upstream_connected_events,
            "performed_side_effects": result.performed_side_effects,
        }
    ]
    rows.extend(
        {
            "type": "event",
            "client_id": event.client_id,
            "phase": event.phase,
            "status": event.status,
            "target_host": event.target_host,
            "target_port": event.target_port,
            "upstream_connected": event.upstream_connected,
        }
        for event in result.events
    )
    return "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)


def render_socks5_listener_plan(plan: Socks5ListenerPlan) -> str:
    return "\n".join(
        [
            "SOCKS5 listener plan",
            f"bind_host: {plan.bind_host}",
            f"bind_port: {plan.bind_port}",
            f"protocol: {plan.protocol}",
            f"connection_driver: {plan.connection_driver}",
            f"upstream_mode: {plan.upstream_mode}",
            f"will_listen: {plan.will_listen}",
            f"will_connect_upstream: {plan.will_connect_upstream}",
            f"performed_side_effects: {plan.performed_side_effects}",
        ]
    )


def run_socks5_serve_placeholder(
    config: MiGateConfig,
    *,
    dry_run: bool = True,
    yes: bool = False,
    allow_network_listen: bool = False,
    max_clients: int = 1,
    client_timeout: float = 5.0,
    server_starter: Socks5ServerStarter | None = None,
) -> Socks5ServeResult:
    bind_host = config.proxy.socks_host
    bind_port = config.proxy.socks_port
    if dry_run:
        return Socks5ServeResult(
            status="dry_run",
            message="SOCKS5 listener dry-run; no socket opened",
            bind_host=bind_host,
            bind_port=bind_port,
            listener_started=False,
            accepted_connections=0,
            upstream_connections=0,
            timed_out_connections=0,
            max_clients=max_clients,
            client_timeout=client_timeout,
            events=[],
            performed_side_effects=False,
        )
    if not yes or not allow_network_listen:
        return Socks5ServeResult(
            status="rejected",
            message="SOCKS5 listener requires yes=True and allow_network_listen=True",
            bind_host=bind_host,
            bind_port=bind_port,
            listener_started=False,
            accepted_connections=0,
            upstream_connections=0,
            timed_out_connections=0,
            max_clients=max_clients,
            client_timeout=client_timeout,
            events=[],
            performed_side_effects=False,
        )
    starter = server_starter or start_socks5_placeholder_server
    return starter(bind_host, bind_port, max_clients, client_timeout)


async def _serve_socks5_once(bind_host: str, bind_port: int, max_clients: int, client_timeout: float) -> Socks5ServeResult:
    from migate.proxy.socks5_server import serve_socks5_bounded

    return await serve_socks5_bounded(bind_host, bind_port, max_clients=max_clients, client_timeout=client_timeout)


def start_socks5_placeholder_server(bind_host: str, bind_port: int, max_clients: int, client_timeout: float) -> Socks5ServeResult:
    return asyncio.run(_serve_socks5_once(bind_host, bind_port, max_clients, client_timeout))


def render_socks5_serve_output(result: Socks5ServeResult, *, output_format: str) -> str:
    if output_format == "text":
        return render_socks5_serve_result(result) + "\n"
    if output_format == "json":
        return render_socks5_serve_json(result)
    if output_format == "jsonl":
        return render_socks5_serve_jsonl(result)
    raise ValueError(f"unsupported format: {output_format}; supported formats: text, json, jsonl")


def _path_is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _resolve_socks5_serve_output_target(target: str, policy: Socks5ServeOutputPathPolicy) -> tuple[Path | None, str]:
    target_path = Path(target)
    project_root = policy.project_root.resolve()
    tmp_root = policy.tmp_root.resolve()
    if target_path.is_absolute():
        resolved = target_path.resolve()
        if _path_is_relative_to(resolved, tmp_root):
            return resolved, "tmp_allowed"
        if _path_is_relative_to(resolved, project_root):
            return resolved, "project_absolute_allowed"
        return None, "sensitive_absolute_path_denied"
    resolved = (project_root / target_path).resolve()
    if _path_is_relative_to(resolved, project_root):
        return resolved, "project_relative_allowed"
    return None, "outside_project_root"


def _reject_socks5_serve_output_write(
    result: Socks5ServeResult,
    *,
    target: str,
    message: str,
    path_policy_reason: str,
) -> Socks5ServeOutputWriteResult:
    return Socks5ServeOutputWriteResult(
        status="rejected",
        message=message,
        target=target,
        bytes_written=0,
        path_policy_reason=path_policy_reason,
        serve_performed_side_effects=result.performed_side_effects,
        file_performed_side_effects=False,
        performed_side_effects=result.performed_side_effects,
    )


def write_socks5_serve_output(
    result: Socks5ServeResult,
    *,
    output_format: str,
    target: str,
    yes: bool = False,
    allow_file_write: bool = False,
    allow_system_output_path: bool = False,
    path_policy: Socks5ServeOutputPathPolicy | None = None,
) -> Socks5ServeOutputWriteResult:
    if not yes or not allow_file_write:
        return _reject_socks5_serve_output_write(
            result,
            target=target,
            message="SOCKS5 serve output write requires yes=True and allow_file_write=True",
            path_policy_reason="missing_file_write_gate",
        )
    resolved_target, path_policy_reason = _resolve_socks5_serve_output_target(target, path_policy or Socks5ServeOutputPathPolicy())
    if resolved_target is None:
        if allow_system_output_path and Path(target).is_absolute():
            return _reject_socks5_serve_output_write(
                result,
                target=target,
                message="SOCKS5 serve system output paths are intentionally unsupported until log rotation and ownership policy exist",
                path_policy_reason="system_path_reserved",
            )
        return _reject_socks5_serve_output_write(
            result,
            target=target,
            message="SOCKS5 serve output target path is not allowed",
            path_policy_reason=path_policy_reason,
        )
    rendered = render_socks5_serve_output(result, output_format=output_format)
    resolved_target.parent.mkdir(parents=True, exist_ok=True)
    resolved_target.write_text(rendered, encoding="utf-8")
    return Socks5ServeOutputWriteResult(
        status="written",
        message="SOCKS5 serve output written",
        target=str(resolved_target),
        bytes_written=len(rendered.encode("utf-8")),
        path_policy_reason=path_policy_reason,
        serve_performed_side_effects=result.performed_side_effects,
        file_performed_side_effects=True,
        performed_side_effects=True,
    )


def socks5_serve_output_write_result_to_dict(result: Socks5ServeOutputWriteResult) -> dict[str, object]:
    return {
        "status": result.status,
        "message": result.message,
        "target": result.target,
        "bytes_written": result.bytes_written,
        "path_policy_reason": result.path_policy_reason,
        "serve_performed_side_effects": result.serve_performed_side_effects,
        "file_performed_side_effects": result.file_performed_side_effects,
        "performed_side_effects": result.performed_side_effects,
    }


def render_socks5_serve_output_write_json(result: Socks5ServeOutputWriteResult) -> str:
    return json.dumps(socks5_serve_output_write_result_to_dict(result), sort_keys=True) + "\n"


def render_socks5_serve_output_write_result(result: Socks5ServeOutputWriteResult) -> str:
    return "\n".join(
        [
            "SOCKS5 serve output write result",
            f"status: {result.status}",
            f"message: {result.message}",
            f"target: {result.target}",
            f"bytes_written: {result.bytes_written}",
            f"path_policy_reason: {result.path_policy_reason}",
            f"serve_performed_side_effects: {result.serve_performed_side_effects}",
            f"file_performed_side_effects: {result.file_performed_side_effects}",
            f"performed_side_effects: {result.performed_side_effects}",
        ]
    )


def render_socks5_serve_result(result: Socks5ServeResult) -> str:
    lines = [
        "SOCKS5 serve result",
        f"status: {result.status}",
        f"message: {result.message}",
        f"bind_host: {result.bind_host}",
        f"bind_port: {result.bind_port}",
        f"listener_started: {result.listener_started}",
        f"accepted_connections: {result.accepted_connections}",
        f"upstream_connections: {result.upstream_connections}",
        f"timed_out_connections: {result.timed_out_connections}",
        f"max_clients: {result.max_clients}",
        f"client_timeout: {result.client_timeout}",
        f"events: {len(result.events)}",
    ]
    summary = summarize_socks5_serve_events(result.events)
    lines.extend(
        [
            f"accepted_events: {summary.accepted_events}",
            f"rejected_events: {summary.rejected_events}",
            f"timed_out_events: {summary.timed_out_events}",
            f"upstream_connected_events: {summary.upstream_connected_events}",
        ]
    )
    for index, event in enumerate(result.events, start=1):
        target = f"{event.target_host}:{event.target_port}" if event.target_host is not None else "none"
        lines.append(
            f"event[{index}]: client_id={event.client_id} phase={event.phase} status={event.status} "
            f"target={target} upstream_connected={event.upstream_connected}"
        )
    lines.append(f"performed_side_effects: {result.performed_side_effects}")
    return "\n".join(lines)
