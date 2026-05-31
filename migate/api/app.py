from __future__ import annotations

import json
from collections.abc import Callable, Sized
from html import escape
import platform
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse

from migate.database.repository import NodeRecord, NodeRepository
from migate.config import MiGateConfig
from migate.egress.lifecycle import EgressLifecycleResult
from migate.egress.status import EgressStatusReport, run_egress_status
from migate.routing.policy_cleanup import build_policy_routing_cleanup_plan
from migate.routing.policy_plan import build_policy_routing_plan
from migate.systemd.manager import SystemdResult, daemon_reload, restart_service, service_status
from migate.systemd.units import build_panel_unit, build_xray_unit, write_unit_file
from migate.xray.install_executor import XrayInstallDryRunResult, dry_run_xray_install_plan
from migate.vpn.process_plan import build_openvpn_start_plan
from migate.vpn.process_stop import build_openvpn_stop_plan
from migate.xray.install_plan import XrayInstallPlan, build_xray_install_plan
from migate.xray.links import build_shadowsocks_link, build_trojan_link, build_vless_link
from migate.xray.node_adapter import build_config_from_nodes
from migate.xray.subscription import build_base64_subscription
from migate.xray.runtime import XrayRuntimeStatus, detect_xray_runtime
from migate.xray.validator import XrayValidationResult, validate_xray_config
from migate.xray.writer import write_xray_config

DEFAULT_DB_PATH = Path("/var/lib/migate/migate.db")
DEFAULT_XRAY_CONFIG_PATH = Path("/etc/migate/xray/config.json")
DEFAULT_SYSTEMD_UNIT_DIR = Path("/etc/systemd/system")
DEFAULT_RUNTIME_DIR = Path("/var/lib/migate/runtime")
DEFAULT_OPENVPN_CONFIG_PATH = DEFAULT_RUNTIME_DIR / "active.ovpn"
DEFAULT_OPENVPN_PID_PATH = DEFAULT_RUNTIME_DIR / "openvpn.pid"
DEFAULT_OPENVPN_STATUS_PATH = DEFAULT_RUNTIME_DIR / "openvpn.status"
DEFAULT_OPENVPN_LOG_PATH = DEFAULT_RUNTIME_DIR / "openvpn.log"


def _page_shell(body: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MiGate 面板</title>
  <style>
    :root {{ color-scheme: dark; --bg:#0b1020; --card:#121a33; --muted:#8fa3c8; --text:#edf3ff; --accent:#65d6ad; --danger:#ff7a90; }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: radial-gradient(circle at top, #18264d, var(--bg)); color:var(--text); }}
    main {{ max-width: 1080px; margin: 0 auto; padding: 32px 20px 56px; }}
    .hero {{ display:flex; justify-content:space-between; gap:16px; align-items:flex-start; margin-bottom:24px; }}
    h1 {{ margin:0 0 8px; font-size:36px; }}
    p {{ color:var(--muted); line-height:1.6; }}
    .grid {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap:16px; margin: 20px 0; }}
    .card {{ background:rgba(18,26,51,.88); border:1px solid rgba(143,163,200,.18); border-radius:18px; padding:18px; box-shadow: 0 20px 60px rgba(0,0,0,.22); }}
    .label {{ color:var(--muted); font-size:14px; }}
    .value {{ font-size:22px; margin-top:6px; }}
    .ok {{ color:var(--accent); }}
    .warn {{ color:#ffd166; }}
    form {{ display:grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap:14px; }}
    label {{ display:flex; flex-direction:column; gap:6px; color:var(--muted); font-size:14px; }}
    input, select {{ width:100%; border:1px solid rgba(143,163,200,.25); border-radius:12px; padding:12px 14px; background:#0d1429; color:var(--text); font-size:15px; }}
    button {{ grid-column:1/-1; border:0; border-radius:14px; padding:14px 18px; background:linear-gradient(135deg,#65d6ad,#63a4ff); color:#06111f; font-weight:800; cursor:pointer; }}
    pre {{ white-space:pre-wrap; word-break:break-all; background:#080d1c; border-radius:14px; padding:14px; border:1px solid rgba(143,163,200,.16); }}
    .wide {{ grid-column: 1/-1; }}
    .node {{ display:grid; grid-template-columns: 1fr; gap:8px; margin-top:12px; padding:14px; background:#0d1429; border-radius:14px; border:1px solid rgba(143,163,200,.16); }}
    .node-title {{ font-weight:800; }}
    @media (max-width: 720px) {{ form {{ grid-template-columns: 1fr; }} .hero {{ flex-direction:column; }} }}
  </style>
</head>
<body>
<main>
{body}
</main>
</body>
</html>"""


def _nodes_html(nodes: list[NodeRecord]) -> str:
    if not nodes:
        return """
  <section class="card">
    <h2>已创建节点</h2>
    <p>还没有节点。请先使用上面的表单生成第一个节点。</p>
  </section>
"""

    items = []
    for node in nodes:
        address = f"{escape(node.host)}:{node.port}"
        items.append(
            f"""
    <article class="node">
      <div class="node-title">{escape(node.name)} <span class="label">#{node.id}</span></div>
      <div class="label">协议：{escape(node.protocol)} ｜ 地址：{address} ｜ 状态：{'启用' if node.enabled else '禁用'}</div>
      <div class="label">分享链接</div>
      <pre>{escape(node.share_link)}</pre>
      <div class="label">订阅内容</div>
      <pre>{escape(node.subscription)}</pre>
    </article>
"""
        )
    return f"""
  <section class="card">
    <h2>已创建节点</h2>
    {''.join(items)}
  </section>
"""


def _xray_config_for_nodes(nodes: list[NodeRecord]) -> dict[str, object]:
    return build_config_from_nodes(MiGateConfig(), [node for node in nodes if node.enabled])


def _xray_preview_html(nodes: list[NodeRecord]) -> str:
    enabled_nodes = [node for node in nodes if node.enabled]
    restart_form = """
    <form method="post" action="/xray/restart">
      <button type="submit">校验并重启 Xray</button>
    </form>
"""
    if not enabled_nodes:
        return f"""
  <section class="card">
    <h2>Xray 配置预览</h2>
    <p>暂无启用节点。创建节点后这里会显示即将写入 Xray 的配置。</p>
    {restart_form}
  </section>
"""
    preview = json.dumps(_xray_config_for_nodes(enabled_nodes), ensure_ascii=False, indent=2)
    return f"""
  <section class="card">
    <h2>Xray 配置预览</h2>
    <p>当前仅预览，不会重载 Xray。安全约束：不生成 freedom 出站，默认路由到 MiGate SOCKS5。</p>
    <form method="post" action="/xray/config/save">
      <button type="submit">保存 Xray 配置</button>
    </form>
    <form method="post" action="/xray/config/validate">
      <button type="submit">校验 Xray 配置</button>
    </form>
    {restart_form}
    <pre>{escape(preview)}</pre>
  </section>
"""


def _home_body(
    *,
    nodes: list[NodeRecord] | None = None,
    result_html: str = "",
    systemd_html: str = "",
    service_status_html: str = "",
    xray_runtime_html: str = "",
    xray_install_plan_html: str = "",
    xray_install_dry_run_html: str = "",
    egress_status_html: str = "",
    egress_dry_run_html: str = "",
) -> str:
    current_nodes = nodes or []
    nodes_html = _nodes_html(current_nodes)
    preview_html = _xray_preview_html(current_nodes)
    return f"""
  <section class="hero">
    <div>
      <h1>MiGate</h1>
      <p>一体化 Xray + VPNGate + OpenVPN 智能出站网关。面板面向小白用户：选择协议、填写域名和端口，即可生成节点链接和订阅内容。</p>
    </div>
  </section>

  <section class="grid" aria-label="状态概览">
    <div class="card"><div class="label">Xray 状态</div><div class="value warn">待接入</div></div>
    <div class="card"><div class="label">VPNGate 出口</div><div class="value warn">待连接</div></div>
    <div class="card"><div class="label">SOCKS5 出站</div><div class="value ok">127.0.0.1:34501</div></div>
    <div class="card"><div class="label">HTTP 出站</div><div class="value ok">127.0.0.1:34502</div></div>
  </section>

  <section class="card">
    <h2>创建节点</h2>
    <p>推荐新手先使用 VLESS TCP；Trojan 和 Shadowsocks 也已支持链接生成。</p>
    <form method="post" action="/nodes/create">
      <label>节点协议
        <select name="protocol">
          <option value="vless">VLESS</option>
          <option value="trojan">Trojan</option>
          <option value="shadowsocks">Shadowsocks</option>
        </select>
      </label>
      <label>节点名称
        <input name="name" value="MiGate Node" placeholder="MiGate JP">
      </label>
      <label>服务器域名/IP
        <input name="host" placeholder="example.com" required>
      </label>
      <label>端口
        <input name="port" type="number" value="443" min="1" max="65535" required>
      </label>
      <label class="wide">UUID / 密码（留空自动生成）
        <input name="credential" placeholder="VLESS 填 UUID；Trojan/SS 填密码；留空自动生成">
      </label>
      <button type="submit">生成并保存节点</button>
    </form>
  </section>

  {result_html}
  {xray_runtime_html}
  {xray_install_plan_html}
  {xray_install_dry_run_html}
  {egress_status_html}
  {egress_dry_run_html}
  {service_status_html}
  {nodes_html}
  {preview_html}
  {systemd_html}
"""


def _credential_for_protocol(protocol: str, credential: str) -> str:
    if credential:
        return credential
    if protocol == "vless":
        return str(uuid4())
    return uuid4().hex


def _build_link(protocol: str, host: str, port: int, name: str, credential: str) -> str:
    if protocol == "vless":
        return build_vless_link(uuid=credential, host=host, port=port, name=name)
    if protocol == "trojan":
        return build_trojan_link(password=credential, host=host, port=port, name=name)
    if protocol == "shadowsocks":
        return build_shadowsocks_link(method="aes-128-gcm", password=credential, host=host, port=port, name=name)
    raise ValueError(f"unsupported protocol: {protocol}")


def _systemd_preview_html(config: MiGateConfig) -> str:
    xray_unit = build_xray_unit(config)
    panel_unit = build_panel_unit(config)
    return f"""
  <section class="card">
    <h2>Systemd 服务文件预览</h2>
    <p>当前仅生成并保存服务文件，不会执行服务重载、开机启用、重启或其他服务控制操作。</p>
    <form method="post" action="/systemd/units/save">
      <button type="submit">保存 systemd 服务文件</button>
    </form>
    <div class="label">{escape(xray_unit.name)}</div>
    <pre>{escape(xray_unit.content)}</pre>
    <div class="label">{escape(panel_unit.name)}</div>
    <pre>{escape(panel_unit.content)}</pre>
  </section>
"""


def _service_status_row(service_name: str, result: SystemdResult) -> str:
    output = "\n".join(part for part in [result.stdout, result.stderr] if part)
    return f"""
    <article class="node">
      <div class="node-title">{escape(service_name)}</div>
      <div class="label">状态：{escape(result.status)} ｜ 返回码：{escape(str(result.returncode))}</div>
      <pre>{escape(output)}</pre>
    </article>
"""


def _service_status_html(status_loader: Callable[[str], SystemdResult], *, refreshed: bool = False) -> str:
    xray_result = status_loader("migate-xray.service")
    panel_result = status_loader("migate-panel.service")
    heading = "服务状态已刷新" if refreshed else "服务状态"
    return f"""
  <section class="card">
    <h2>{heading}</h2>
    <p>这里只读取 MiGate 自有服务状态，不会执行重启、重载或开机启用。</p>
    <form method="post" action="/systemd/status/refresh">
      <button type="submit">刷新服务状态</button>
    </form>
    {_service_status_row("migate-xray.service", xray_result)}
    {_service_status_row("migate-panel.service", panel_result)}
  </section>
"""


def _xray_runtime_html(runtime_loader: Callable[[], XrayRuntimeStatus], *, refreshed: bool = False) -> str:
    status = runtime_loader()
    heading = "Xray 运行时已刷新" if refreshed else "Xray 运行时"
    version = status.version or "未识别 / 未安装"
    guidance = ""
    if status.status == "not_installed":
        guidance = "<p>请先安装 xray-core，或修改 MiGate Xray bin_path。</p>"
    output = "\n".join(part for part in [status.stdout, status.stderr] if part)
    return f"""
  <section class="card">
    <h2>{heading}</h2>
    <p>这里只检测本机 Xray 二进制和版本，不会下载、安装或修改系统。</p>
    <form method="post" action="/xray/runtime/refresh">
      <button type="submit">刷新 Xray 运行时</button>
    </form>
    <div class="label">状态：{escape(status.status)} ｜ 返回码：{escape(str(status.returncode))}</div>
    <div class="label">路径：{escape(status.bin_path)}</div>
    <div class="label">版本：{escape(version)}</div>
    <p>{escape(status.message)}</p>
    {guidance}
    <pre>{escape(output)}</pre>
  </section>
"""


def _xray_install_plan_json(plan: XrayInstallPlan) -> dict[str, object]:
    return {
        "version": plan.version,
        "system": plan.system,
        "arch": plan.arch,
        "bin_path": plan.bin_path,
        "config_dir": plan.config_dir,
        "archive_name": plan.archive_name,
        "download_url": plan.download_url,
        "steps": [
            {"action": step.action, "description": step.description}
            for step in plan.steps
        ],
        "commands": plan.commands,
        "performs_side_effects": plan.performs_side_effects,
    }


def _xray_install_dry_run_json(result: XrayInstallDryRunResult) -> dict[str, object]:
    return {
        "status": result.status,
        "message": result.message,
        "steps": [
            {
                "action": step.action,
                "description": step.description,
                "status": step.status,
                "command_preview": step.command_preview,
            }
            for step in result.steps
        ],
        "commands_executed": result.commands_executed,
        "performed_side_effects": result.performed_side_effects,
    }


def _xray_install_plan_html(plan_loader: Callable[[], XrayInstallPlan], *, refreshed: bool = False) -> str:
    plan = plan_loader()
    heading = "Xray 安装计划已刷新" if refreshed else "Xray 安装计划预览"
    steps = "\n".join(f"- {step.description}" for step in plan.steps)
    preview = "\n".join(
        [
            f"版本：{plan.version}",
            f"架构：{plan.system}-{plan.arch}",
            f"目标路径：{plan.bin_path}",
            f"配置目录：{plan.config_dir}",
            f"压缩包：{plan.archive_name}",
            f"下载地址：{plan.download_url}",
            f"commands: {plan.commands}",
            f"performs_side_effects: {plan.performs_side_effects}",
            "操作步骤：",
            steps,
        ]
    )
    return f"""
  <section class="card">
    <h2>{heading}</h2>
    <p>当前不会执行安装，只展示将来安装器会执行的计划。</p>
    <form method="post" action="/xray/install-plan/refresh">
      <button type="submit">刷新 Xray 安装计划</button>
    </form>
    <form method="post" action="/xray/install/dry-run">
      <button type="submit">Dry-run Xray 安装</button>
    </form>
    <pre>{escape(preview)}</pre>
  </section>
"""


def _xray_install_dry_run_html(dry_run_loader: Callable[[], XrayInstallDryRunResult]) -> str:
    result = dry_run_loader()
    steps = "\n".join(
        f"- {step.action}: {step.status} -> {step.command_preview}" for step in result.steps
    )
    preview = "\n".join(
        [
            f"status: {result.status}",
            f"message: {result.message}",
            f"commands_executed: {result.commands_executed}",
            f"performed_side_effects: {result.performed_side_effects}",
            "steps:",
            steps,
        ]
    )
    return f"""
  <section class="card">
    <h2>Xray 安装 dry-run 结果</h2>
    <p>这里只展示如果将来执行安装时会跑哪些命令预览；当前不会执行命令，也不会写文件。</p>
    <pre>{escape(preview)}</pre>
  </section>
"""


def _egress_status_html(status_loader: Callable[[], EgressStatusReport], *, refreshed: bool = False) -> str:
    report = status_loader()
    heading = "Egress 出口状态已刷新" if refreshed else "Egress 出口状态"
    checks = "\n".join(f"{check.name}: {check.status} - {check.message}" for check in report.checks)
    preview = "\n".join(
        [
            f"status: {report.status}",
            checks,
            f"performed_side_effects: {report.performed_side_effects}",
        ]
    )
    return f"""
  <section class="card">
    <h2>{heading}</h2>
    <p>这里只读取隧道、OpenVPN 进程、策略路由计划和防泄漏判断；不会启动/停止 OpenVPN，也不会修改路由或防火墙。</p>
    <form method="post" action="/egress/status/refresh">
      <button type="submit">刷新 Egress 状态</button>
    </form>
    <pre>{escape(preview)}</pre>
  </section>
"""


def _egress_dry_run_controls_html() -> str:
    return """
  <section class="card">
    <h2>Egress Dry-run 预览</h2>
    <p>这里只预览将来 Egress Up/Down 会涉及的 OpenVPN 与策略路由命令，不会执行命令，也不会修改系统。</p>
    <form method="post" action="/egress/up/dry-run">
      <button type="submit">Dry-run Egress Up</button>
    </form>
    <form method="post" action="/egress/down/dry-run">
      <button type="submit">Dry-run Egress Down</button>
    </form>
  </section>
"""


def _egress_lifecycle_result_json(result: EgressLifecycleResult) -> dict[str, object]:
    return {
        "status": result.status,
        "message": result.message,
        "commands_executed": result.commands_executed,
        "phases": [
            {
                "name": phase.name,
                "status": phase.status,
                "result": phase.result,
            }
            for phase in result.phases
        ],
        "performed_side_effects": result.performed_side_effects,
    }


def _egress_dry_run_result_html(title: str, result_loader: Callable[[], EgressLifecycleResult]) -> str:
    result = result_loader()
    commands = "\n".join(result.commands_executed)
    preview = "\n".join(
        [
            f"status: {result.status}",
            f"message: {result.message}",
            "commands:",
            commands,
            f"performed_side_effects: {result.performed_side_effects}",
        ]
    )
    return f"""
  <section class="card">
    <h2>{escape(title)}</h2>
    <p>Dry-run 只展示计划，不执行 OpenVPN、ip rule、ip route 或 kill 命令。</p>
    <pre>{escape(preview)}</pre>
  </section>
"""


def _default_egress_up_dry_run(config: MiGateConfig) -> EgressLifecycleResult:
    start_plan = build_openvpn_start_plan(
        config,
        config_path=str(DEFAULT_OPENVPN_CONFIG_PATH),
        pid_path=str(DEFAULT_OPENVPN_PID_PATH),
        status_path=str(DEFAULT_OPENVPN_STATUS_PATH),
        log_path=str(DEFAULT_OPENVPN_LOG_PATH),
    )
    routing_plan = build_policy_routing_plan(config)
    return EgressLifecycleResult(
        status="dry_run",
        message="planned only; no egress up commands executed",
        phases=[],
        commands_executed=[" ".join(start_plan.command), *(" ".join(command) for command in routing_plan.commands)],
        performed_side_effects=False,
    )


def _default_egress_down_dry_run(config: MiGateConfig) -> EgressLifecycleResult:
    cleanup_plan = build_policy_routing_cleanup_plan(config)
    stop_plan = build_openvpn_stop_plan(pid_file=DEFAULT_OPENVPN_PID_PATH)
    return EgressLifecycleResult(
        status="dry_run",
        message="planned only; no egress down commands executed",
        phases=[],
        commands_executed=[
            *(" ".join(command) for command in cleanup_plan.commands),
            f"kill -{stop_plan.kill_signal} <pid from {stop_plan.pid_file}>",
        ],
        performed_side_effects=False,
    )


def _result_output(*parts: object) -> str:
    values = []
    for part in parts:
        if isinstance(part, XrayValidationResult | SystemdResult):
            values.extend([part.stdout, part.stderr])
        elif part:
            values.append(str(part))
    return "\n".join(value for value in values if value)


def create_app(
    node_repository: NodeRepository | None = None,
    xray_config_path: str | Path | None = None,
    xray_validator: Callable[[Path], XrayValidationResult] | None = None,
    systemd_unit_dir: str | Path | None = None,
    systemd_status_loader: Callable[[str], SystemdResult] | None = None,
    systemd_daemon_reloader: Callable[[], SystemdResult] | None = None,
    systemd_restarter: Callable[[str], SystemdResult] | None = None,
    xray_runtime_loader: Callable[[], XrayRuntimeStatus] | None = None,
    xray_install_plan_loader: Callable[[], XrayInstallPlan] | None = None,
    xray_install_dry_run_loader: Callable[[], XrayInstallDryRunResult] | None = None,
    egress_status_loader: Callable[[], EgressStatusReport] | None = None,
    egress_up_dry_run_loader: Callable[[], EgressLifecycleResult] | None = None,
    egress_down_dry_run_loader: Callable[[], EgressLifecycleResult] | None = None,
) -> FastAPI:
    repo = node_repository or NodeRepository(DEFAULT_DB_PATH)
    config_path = Path(xray_config_path) if xray_config_path is not None else DEFAULT_XRAY_CONFIG_PATH
    unit_dir = Path(systemd_unit_dir) if systemd_unit_dir is not None else DEFAULT_SYSTEMD_UNIT_DIR
    validator = xray_validator or validate_xray_config
    status_loader = systemd_status_loader or service_status
    daemon_reloader = systemd_daemon_reloader or daemon_reload
    restarter = systemd_restarter or restart_service
    migate_config = MiGateConfig()
    runtime_loader = xray_runtime_loader or (lambda: detect_xray_runtime(migate_config.xray.bin_path))
    plan_loader = xray_install_plan_loader or (
        lambda: build_xray_install_plan(
            migate_config,
            system=platform.system(),
            machine=platform.machine(),
        )
    )
    dry_run_loader = xray_install_dry_run_loader or (lambda: dry_run_xray_install_plan(plan_loader()))
    egress_loader = egress_status_loader or (lambda: run_egress_status(migate_config))
    egress_up_loader = egress_up_dry_run_loader or (lambda: _default_egress_up_dry_run(migate_config))
    egress_down_loader = egress_down_dry_run_loader or (lambda: _default_egress_down_dry_run(migate_config))
    repo.initialize()
    app = FastAPI(title="MiGate Panel")

    @app.get("/api/nodes")
    def api_nodes() -> dict[str, object]:
        nodes = repo.list_nodes()
        return {
            "nodes": [
                {
                    "id": node.id,
                    "protocol": node.protocol,
                    "name": node.name,
                    "host": node.host,
                    "port": node.port,
                    "enabled": node.enabled,
                    "created_at": node.created_at,
                }
                for node in nodes
            ],
            "counts": {
                "total": len(nodes),
                "enabled": sum(1 for node in nodes if node.enabled),
            },
            "performed_side_effects": False,
        }

    @app.get("/api/xray/config/preview")
    def api_xray_config_preview() -> dict[str, object]:
        nodes = repo.list_nodes()
        enabled_nodes = [node for node in nodes if node.enabled]
        config = _xray_config_for_nodes(nodes)
        inbounds = config.get("inbounds", [])
        inbound_count = len(inbounds) if isinstance(inbounds, Sized) else 0
        return {
            "status": "preview",
            "target_path": str(config_path),
            "counts": {
                "total_nodes": len(nodes),
                "enabled_nodes": len(enabled_nodes),
                "inbounds": inbound_count,
            },
            "config": config,
            "performed_side_effects": False,
        }

    @app.get("/api/xray/runtime")
    def api_xray_runtime() -> dict[str, object]:
        runtime = runtime_loader()
        return {
            "status": runtime.status,
            "bin_path": runtime.bin_path,
            "version": runtime.version,
            "message": runtime.message,
            "returncode": runtime.returncode,
            "stdout": runtime.stdout,
            "stderr": runtime.stderr,
            "performed_side_effects": False,
        }

    @app.get("/api/xray/install-plan")
    def api_xray_install_plan() -> dict[str, object]:
        return _xray_install_plan_json(plan_loader())

    @app.get("/api/xray/install/dry-run")
    def api_xray_install_dry_run() -> dict[str, object]:
        return _xray_install_dry_run_json(dry_run_loader())

    @app.get("/api/systemd/units/preview")
    def api_systemd_units_preview() -> dict[str, object]:
        units = [build_xray_unit(migate_config), build_panel_unit(migate_config)]
        return {
            "status": "preview",
            "target_dir": str(unit_dir),
            "units": [
                {
                    "name": unit.name,
                    "target_path": str(unit_dir / unit.name),
                    "content": unit.content,
                }
                for unit in units
            ],
            "systemctl_commands_executed": [],
            "performed_side_effects": False,
        }

    @app.get("/api/systemd/status")
    def api_systemd_status() -> dict[str, object]:
        services = {
            "migate-xray.service": status_loader("migate-xray.service"),
            "migate-panel.service": status_loader("migate-panel.service"),
        }
        return {
            "services": {
                name: {
                    "status": result.status,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
                for name, result in services.items()
            },
            "systemctl_commands_executed": [],
            "performed_side_effects": False,
        }

    @app.get("/api/status/summary")
    def status_summary() -> dict[str, object]:
        nodes = repo.list_nodes()
        runtime = runtime_loader()
        egress = egress_loader()
        services = {
            "migate-xray.service": status_loader("migate-xray.service"),
            "migate-panel.service": status_loader("migate-panel.service"),
        }
        healthy = (
            runtime.status == "installed"
            and all(check.status == "ok" for check in egress.checks)
            and all(service.status == "success" for service in services.values())
        )
        return {
            "status": "ok" if healthy else "degraded",
            "nodes": {
                "total": len(nodes),
                "enabled": sum(1 for node in nodes if node.enabled),
            },
            "xray": {
                "status": runtime.status,
                "bin_path": runtime.bin_path,
                "version": runtime.version,
                "message": runtime.message,
                "returncode": runtime.returncode,
            },
            "egress": {
                "status": egress.status,
                "performed_side_effects": egress.performed_side_effects,
                "checks": [
                    {"name": check.name, "status": check.status, "message": check.message}
                    for check in egress.checks
                ],
            },
            "services": {
                name: {
                    "status": result.status,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
                for name, result in services.items()
            },
            "performed_side_effects": False,
        }

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return _page_shell(
            _home_body(
                nodes=repo.list_nodes(),
                xray_runtime_html=_xray_runtime_html(runtime_loader),
                xray_install_plan_html=_xray_install_plan_html(plan_loader),
                egress_status_html=_egress_status_html(egress_loader),
                egress_dry_run_html=_egress_dry_run_controls_html(),
                service_status_html=_service_status_html(status_loader),
                systemd_html=_systemd_preview_html(migate_config),
            )
        )

    @app.post("/nodes/create", response_class=HTMLResponse)
    def create_node(
        protocol: str = Form(...),
        host: str = Form(...),
        port: int = Form(...),
        name: str = Form("MiGate Node"),
        credential: str = Form(""),
    ) -> str:
        cleaned_name = name.strip() or "MiGate Node"
        cleaned_host = host.strip()
        cleaned_credential = _credential_for_protocol(protocol, credential.strip())
        link = _build_link(protocol=protocol, host=cleaned_host, port=port, name=cleaned_name, credential=cleaned_credential)
        subscription = build_base64_subscription([link])
        node = repo.create_node(
            protocol=protocol,
            name=cleaned_name,
            host=cleaned_host,
            port=port,
            credential=cleaned_credential,
            share_link=link,
            subscription=subscription,
        )
        result = f"""
  <section class="card">
    <h2>节点已生成</h2>
    <p>节点 #{node.id} 已保存。复制下面的分享链接，或复制订阅内容导入客户端。</p>
    <div class="label">分享链接</div>
    <pre>{escape(link)}</pre>
    <div class="label">订阅内容</div>
    <pre>{escape(subscription)}</pre>
  </section>
"""
        return _page_shell(_home_body(nodes=repo.list_nodes(), result_html=result))

    @app.post("/xray/config/save", response_class=HTMLResponse)
    def save_xray_config() -> str:
        nodes = repo.list_nodes()
        written = write_xray_config(_xray_config_for_nodes(nodes), config_path)
        result = f"""
  <section class="card">
    <h2>Xray 配置已保存</h2>
    <p>配置已写入：{escape(str(written))}</p>
    <p>当前步骤仅写盘，不会自动重载 Xray 服务。</p>
  </section>
"""
        return _page_shell(_home_body(nodes=nodes, result_html=result))

    @app.post("/xray/config/validate", response_class=HTMLResponse)
    def validate_saved_xray_config() -> str:
        result_value = validator(config_path)
        output = _result_output(result_value)
        result = f"""
  <section class="card">
    <h2>Xray 配置校验结果</h2>
    <p>状态：{escape(result_value.status)}</p>
    <p>返回码：{escape(str(result_value.returncode))}</p>
    <pre>{escape(output)}</pre>
  </section>
"""
        return _page_shell(_home_body(nodes=repo.list_nodes(), result_html=result, systemd_html=_systemd_preview_html(migate_config)))

    @app.post("/xray/restart", response_class=HTMLResponse)
    def restart_xray_after_validation() -> str:
        validation = validator(config_path)
        if validation.status != "valid":
            result = f"""
  <section class="card">
    <h2>Xray 未重启</h2>
    <p>配置校验失败，未执行服务重载或重启。</p>
    <p>校验状态：{escape(validation.status)}</p>
    <pre>{escape(_result_output(validation))}</pre>
  </section>
"""
            return _page_shell(
                _home_body(
                    nodes=repo.list_nodes(),
                    result_html=result,
                    service_status_html=_service_status_html(status_loader),
                    systemd_html=_systemd_preview_html(migate_config),
                )
            )

        reload_result = daemon_reloader()
        restart_result = restarter("migate-xray.service")
        result = f"""
  <section class="card">
    <h2>Xray 重启已执行</h2>
    <p>配置校验通过后，已执行服务重载并重启 migate-xray.service。</p>
    <div class="label">配置校验</div>
    <pre>{escape(_result_output(validation))}</pre>
    <div class="label">服务重载：{escape(reload_result.status)}</div>
    <pre>{escape(_result_output(reload_result))}</pre>
    <div class="label">Xray 重启：{escape(restart_result.status)}</div>
    <pre>{escape(_result_output(restart_result))}</pre>
  </section>
"""
        return _page_shell(
            _home_body(
                nodes=repo.list_nodes(),
                result_html=result,
                service_status_html=_service_status_html(status_loader),
                systemd_html=_systemd_preview_html(migate_config),
            )
        )

    @app.post("/systemd/units/save", response_class=HTMLResponse)
    def save_systemd_units() -> str:
        written_xray = write_unit_file(build_xray_unit(migate_config), unit_dir)
        written_panel = write_unit_file(build_panel_unit(migate_config), unit_dir)
        result = f"""
  <section class="card">
    <h2>Systemd 服务文件已保存</h2>
    <p>已写入：{escape(str(written_xray))}</p>
    <p>已写入：{escape(str(written_panel))}</p>
    <p>当前步骤仅写服务文件，不会执行服务重载或启动。</p>
  </section>
"""
        return _page_shell(
            _home_body(
                nodes=repo.list_nodes(),
                result_html=result,
                service_status_html=_service_status_html(status_loader),
                systemd_html=_systemd_preview_html(migate_config),
            )
        )

    @app.post("/systemd/status/refresh", response_class=HTMLResponse)
    def refresh_systemd_status() -> str:
        return _page_shell(
            _home_body(
                nodes=repo.list_nodes(),
                xray_runtime_html=_xray_runtime_html(runtime_loader),
                egress_status_html=_egress_status_html(egress_loader),
                service_status_html=_service_status_html(status_loader, refreshed=True),
                systemd_html=_systemd_preview_html(migate_config),
            )
        )

    @app.post("/egress/status/refresh", response_class=HTMLResponse)
    def refresh_egress_status() -> str:
        return _page_shell(
            _home_body(
                nodes=repo.list_nodes(),
                xray_runtime_html=_xray_runtime_html(runtime_loader),
                xray_install_plan_html=_xray_install_plan_html(plan_loader),
                egress_status_html=_egress_status_html(egress_loader, refreshed=True),
                egress_dry_run_html=_egress_dry_run_controls_html(),
                service_status_html=_service_status_html(status_loader),
                systemd_html=_systemd_preview_html(migate_config),
            )
        )

    @app.get("/api/egress/up/dry-run")
    def api_egress_up_dry_run() -> dict[str, object]:
        return _egress_lifecycle_result_json(egress_up_loader())

    @app.get("/api/egress/down/dry-run")
    def api_egress_down_dry_run() -> dict[str, object]:
        return _egress_lifecycle_result_json(egress_down_loader())

    @app.post("/egress/up/dry-run", response_class=HTMLResponse)
    def dry_run_egress_up() -> str:
        return _page_shell(
            _home_body(
                nodes=repo.list_nodes(),
                xray_runtime_html=_xray_runtime_html(runtime_loader),
                xray_install_plan_html=_xray_install_plan_html(plan_loader),
                egress_status_html=_egress_status_html(egress_loader),
                egress_dry_run_html=_egress_dry_run_result_html("Egress Up dry-run 结果", egress_up_loader),
                service_status_html=_service_status_html(status_loader),
                systemd_html=_systemd_preview_html(migate_config),
            )
        )

    @app.post("/egress/down/dry-run", response_class=HTMLResponse)
    def dry_run_egress_down() -> str:
        return _page_shell(
            _home_body(
                nodes=repo.list_nodes(),
                xray_runtime_html=_xray_runtime_html(runtime_loader),
                xray_install_plan_html=_xray_install_plan_html(plan_loader),
                egress_status_html=_egress_status_html(egress_loader),
                egress_dry_run_html=_egress_dry_run_result_html("Egress Down dry-run 结果", egress_down_loader),
                service_status_html=_service_status_html(status_loader),
                systemd_html=_systemd_preview_html(migate_config),
            )
        )

    @app.post("/xray/runtime/refresh", response_class=HTMLResponse)
    def refresh_xray_runtime() -> str:
        return _page_shell(
            _home_body(
                nodes=repo.list_nodes(),
                xray_runtime_html=_xray_runtime_html(runtime_loader, refreshed=True),
                xray_install_plan_html=_xray_install_plan_html(plan_loader),
                service_status_html=_service_status_html(status_loader),
                systemd_html=_systemd_preview_html(migate_config),
            )
        )

    @app.post("/xray/install-plan/refresh", response_class=HTMLResponse)
    def refresh_xray_install_plan() -> str:
        return _page_shell(
            _home_body(
                nodes=repo.list_nodes(),
                xray_runtime_html=_xray_runtime_html(runtime_loader),
                xray_install_plan_html=_xray_install_plan_html(plan_loader, refreshed=True),
                service_status_html=_service_status_html(status_loader),
                systemd_html=_systemd_preview_html(migate_config),
            )
        )

    @app.post("/xray/install/dry-run", response_class=HTMLResponse)
    def dry_run_xray_install() -> str:
        return _page_shell(
            _home_body(
                nodes=repo.list_nodes(),
                xray_runtime_html=_xray_runtime_html(runtime_loader),
                xray_install_plan_html=_xray_install_plan_html(plan_loader),
                xray_install_dry_run_html=_xray_install_dry_run_html(dry_run_loader),
                service_status_html=_service_status_html(status_loader),
                systemd_html=_systemd_preview_html(migate_config),
            )
        )

    return app
