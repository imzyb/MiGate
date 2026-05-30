from __future__ import annotations

import json
from collections.abc import Callable
from html import escape
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse

from migate.database.repository import NodeRecord, NodeRepository
from migate.config import MiGateConfig
from migate.systemd.manager import SystemdResult, daemon_reload, restart_service, service_status
from migate.systemd.units import build_panel_unit, build_xray_unit, write_unit_file
from migate.xray.links import build_shadowsocks_link, build_trojan_link, build_vless_link
from migate.xray.node_adapter import build_config_from_nodes
from migate.xray.subscription import build_base64_subscription
from migate.xray.validator import XrayValidationResult, validate_xray_config
from migate.xray.writer import write_xray_config

DEFAULT_DB_PATH = Path("/var/lib/migate/migate.db")
DEFAULT_XRAY_CONFIG_PATH = Path("/etc/migate/xray/config.json")
DEFAULT_SYSTEMD_UNIT_DIR = Path("/etc/systemd/system")


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
) -> FastAPI:
    repo = node_repository or NodeRepository(DEFAULT_DB_PATH)
    config_path = Path(xray_config_path) if xray_config_path is not None else DEFAULT_XRAY_CONFIG_PATH
    unit_dir = Path(systemd_unit_dir) if systemd_unit_dir is not None else DEFAULT_SYSTEMD_UNIT_DIR
    validator = xray_validator or validate_xray_config
    status_loader = systemd_status_loader or service_status
    daemon_reloader = systemd_daemon_reloader or daemon_reload
    restarter = systemd_restarter or restart_service
    migate_config = MiGateConfig()
    repo.initialize()
    app = FastAPI(title="MiGate Panel")

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return _page_shell(
            _home_body(
                nodes=repo.list_nodes(),
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
                service_status_html=_service_status_html(status_loader, refreshed=True),
                systemd_html=_systemd_preview_html(migate_config),
            )
        )

    return app
