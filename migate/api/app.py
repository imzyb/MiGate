from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sized
from html import escape
import platform
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from migate.database.repository import InboundRecord, InboundRepository, NodeRecord, NodeRepository
from migate.config import MiGateConfig
from migate.egress.lifecycle import EgressLifecycleResult
from migate.egress.status import EgressStatusReport, run_egress_status
from migate.systemd.manager import SystemdResult, daemon_reload, restart_service, service_status
from migate.systemd.units import build_panel_unit, build_xray_unit, write_unit_file
from migate.xray.runtime import XrayRuntimeStatus, detect_xray_runtime


# ---------------------------------------------------------------------------
# Lazy import helper — avoids loading heavy modules at module import time.
# Modules are cached on first call, so subsequent access is O(1).
# ---------------------------------------------------------------------------
_LAZY_IMPORT_CACHE: dict[str, object] = {}


def _lazy_import(module_name: str, symbol_name: str | None = None) -> object:
    """Import a module/symbol lazily and cache it."""
    cache_key = f"{module_name}.{symbol_name}" if symbol_name else module_name
    if cache_key not in _LAZY_IMPORT_CACHE:
        import importlib
        mod = importlib.import_module(module_name)
        _LAZY_IMPORT_CACHE[cache_key] = getattr(mod, symbol_name) if symbol_name else mod
    return _LAZY_IMPORT_CACHE[cache_key]

DEFAULT_DB_PATH = Path("/var/lib/migate/migate.db")
DEFAULT_XRAY_CONFIG_PATH = Path("/etc/migate/xray/config.json")
DEFAULT_SYSTEMD_UNIT_DIR = Path("/etc/systemd/system")
DEFAULT_RUNTIME_DIR = Path("/var/lib/migate/runtime")
DEFAULT_OPENVPN_CONFIG_PATH = DEFAULT_RUNTIME_DIR / "active.ovpn"
DEFAULT_OPENVPN_PID_PATH = DEFAULT_RUNTIME_DIR / "openvpn.pid"
DEFAULT_OPENVPN_STATUS_PATH = DEFAULT_RUNTIME_DIR / "openvpn.status"
DEFAULT_OPENVPN_LOG_PATH = DEFAULT_RUNTIME_DIR / "openvpn.log"
MIGATE_SYSTEMD_SERVICES = ("migate-xray.service", "migate-panel.service", "migate-proxy.service")


def _load_migate_systemd_services(status_loader: Callable[[str], SystemdResult]) -> dict[str, SystemdResult]:
    return {service_name: status_loader(service_name) for service_name in MIGATE_SYSTEMD_SERVICES}


def _hash_panel_password(password: str) -> str:
    return "sha256:" + hashlib.sha256(password.encode()).hexdigest()


def _normalize_panel_base_path(base_path: object | None) -> str:
    value = str(base_path or "/").strip() or "/"
    if not value.startswith("/"):
        value = f"/{value}"
    return value.rstrip("/") or "/"


def load_panel_auth_config(path: str | Path | None) -> dict[str, object] | None:
    if path is None:
        return None
    config_path = Path(path)
    if not config_path.exists():
        return None
    data = json.loads(config_path.read_text())
    if not isinstance(data, dict):
        return None
    required = {"admin_user", "password_hash", "base_path"}
    if not required.issubset(data):
        return None
    if not str(data.get("password_hash", "")).startswith("sha256:"):
        return None
    data["base_path"] = _normalize_panel_base_path(data.get("base_path"))
    return data


def _panel_auth_enabled(panel_auth_config: dict[str, object] | None) -> bool:
    if panel_auth_config is None:
        return False
    return bool(panel_auth_config.get("admin_user")) and str(panel_auth_config.get("password_hash", "")).startswith("sha256:")


def _dangerous_actions_enabled(panel_auth_config: dict[str, object] | None) -> bool:
    return bool((panel_auth_config or {}).get("dangerous_actions_enabled", False))


def _dangerous_action_rejected_json() -> dict[str, object]:
    return {
        "status": "rejected",
        "message": "dangerous actions are disabled in panel config",
        "performed_side_effects": False,
    }


def _dangerous_action_confirmation_required_json(required_confirm: str) -> dict[str, object]:
    return {
        "status": "confirmation_required",
        "message": "dangerous action confirmation is required",
        "required_confirm": required_confirm,
        "performed_side_effects": False,
    }


def _dangerous_action_rejected_html() -> str:
    return """
  <section class="card">
    <h2>危险动作已禁用</h2>
    <p>panel.json 未启用 dangerous_actions_enabled，因此不会写配置、校验或控制 systemd。</p>
  </section>
"""


def _dangerous_action_confirmation_required_html(required_confirm: str) -> str:
    return f"""
  <section class="card">
    <h2>危险动作需要确认</h2>
    <p>需要确认：{escape(required_confirm)}。未匹配确认字段时，不会写配置、校验或控制 systemd。</p>
  </section>
"""


def _confirm_dangerous_action(confirm: str | None, required_confirm: str) -> JSONResponse | None:
    if confirm == required_confirm:
        return None
    return JSONResponse(_dangerous_action_confirmation_required_json(required_confirm), status_code=403)


def _session_token_for_auth_config(panel_auth_config: dict[str, object]) -> str:
    admin_user = str(panel_auth_config.get("admin_user", ""))
    password_hash = str(panel_auth_config.get("password_hash", ""))
    return hashlib.sha256(f"{admin_user}:{password_hash}".encode()).hexdigest()


def _is_authenticated(request: Request, panel_auth_config: dict[str, object] | None) -> bool:
    if not _panel_auth_enabled(panel_auth_config):
        return True
    return request.cookies.get("migate_session") == _session_token_for_auth_config(panel_auth_config or {})


def _panel_url(base_path: str, path: str = "/") -> str:
    normalized_base = _normalize_panel_base_path(base_path)
    normalized_path = path if path.startswith("/") else f"/{path}"
    if normalized_base == "/":
        return normalized_path
    if normalized_path == "/":
        return f"{normalized_base}/"
    return f"{normalized_base}{normalized_path}"


def _login_html(message: str = "", *, base_path: str = "/") -> str:
    message_html = f'<div class="toast toast-error">{escape(message)}</div>' if message else ""
    login_action = _panel_url(base_path, "/login")
    return _page_shell(
        f"""
  <section class="card">
    <h2 style="margin-bottom:8px;">MiGate 登录</h2>
    <p class="text-muted text-sm" style="margin-bottom:16px;">请输入 setup 配置中的管理员账号和密码。</p>
    {message_html}
    <form method="post" action="{escape(login_action)}" style="display:grid;gap:14px;">
      <div class="form-group"><label>用户名<input name="username" required></label></div>
      <div class="form-group"><label>密码<input name="password" type="password" required></label></div>
      <button class="btn btn-primary btn-block" type="submit">登录</button>
    </form>
  </section>
""",
        show_sidebar=False, title="登录", base_path=base_path,
    )


def _logout_html(*, base_path: str = "/") -> str:
    logout_action = _panel_url(base_path, "/logout")
    return f"""
  <form method="post" action="{escape(logout_action)}">
    <button type="submit">退出登录</button>
  </form>
"""


def _page_shell(body: str, *, active: str = "dashboard", title: str = "MiGate 面板", subtitle: str = "", base_path: str = "/", show_sidebar: bool = True, user: str = "", flash: str = "", flash_type: str = "ok") -> str:
    if not show_sidebar:
        return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)} - MiGate</title>
  <link rel="stylesheet" href="{escape(base_path.rstrip('/'))}/static/style.css">
</head>
<body>
<main class="main-content" style="margin-left:0;max-width:520px;display:flex;align-items:center;justify-content:center;min-height:100vh;">
  {body}
</main>
</body>
</html>"""
    from migate.panel.layout import layout
    return layout(
        active=active, title=title, subtitle=subtitle, content=body,
        base_path=base_path, flash=flash, flash_type=flash_type, user=user,
    )


def _node_create_form_html(base_path: str = "/") -> str:
    return f"""
  <section class="card">
    <h3>创建节点</h3>
    <p class="text-muted text-sm">推荐新手先使用 VLESS TCP；Trojan 和 Shadowsocks 也已支持链接生成。</p>
    <form method="post" action="{escape(_panel_url(base_path, '/nodes/create'))}" class="form-grid">
      <div class="form-group"><label>节点协议<select name="protocol"><option value="vless">VLESS</option><option value="trojan">Trojan</option><option value="shadowsocks">Shadowsocks</option></select></label></div>
      <div class="form-group"><label>节点名称<input name="name" value="MiGate Node" placeholder="MiGate JP"></label></div>
      <div class="form-group"><label>服务器域名/IP<input name="host" placeholder="example.com" required></label></div>
      <div class="form-group"><label>端口<input name="port" type="number" value="443" min="1" max="65535" required></label></div>
      <div class="form-group"><label>UUID / 密码（留空自动生成）<input name="credential" placeholder="VLESS 填 UUID；Trojan/SS 填密码"></label></div>
      <details style="grid-column:1/-1;">
        <summary style="cursor:pointer;color:var(--text-muted);margin-bottom:8px;">⚙️ 高级选项（SOCKS5 出口）</summary>
        <div class="form-group"><label>SOCKS5 出口主机<input name="socks5_host" placeholder="127.0.0.1"></label></div>
        <div class="form-group"><label>SOCKS5 出口端口<input name="socks5_port" type="number" min="1" max="65535" placeholder="34501"></label></div>
      </details>
      <button class="btn btn-primary btn-block" type="submit">生成并保存节点</button>
    </form>
  </section>
"""


def _inbound_create_form_html(base_path: str = "/") -> str:
    return f"""
  <section class="card">
    <h3>创建入站规则</h3>
    <p class="text-muted text-sm">创建 Xray 入站代理。支持 VLESS、VMess、Trojan、Shadowsocks 协议。</p>
    <form method="post" action="{escape(_panel_url(base_path, '/inbounds/create'))}" class="form-grid">
      <div class="form-group"><label>备注<input name="remark" placeholder="例如：HK-VLESS-443" required></label></div>
      <div class="form-group"><label>协议<select name="protocol"><option value="vless">VLESS</option><option value="vmess">VMess</option><option value="trojan">Trojan</option><option value="shadowsocks">Shadowsocks</option></select></label></div>
      <div class="form-group"><label>端口<input name="port" type="number" value="443" min="1" max="65535" required></label></div>
      <input type="hidden" name="listen" value="0.0.0.0">
      <input type="hidden" name="settings" value="{{}}">
      <input type="hidden" name="stream_settings" value="{{}}">
      <button class="btn btn-primary btn-block" type="submit">创建入站</button>
    </form>
  </section>
"""


def _nodes_html(nodes: list[NodeRecord], *, base_path: str = "/") -> str:
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
        socks5 = f"<div class=\"label\">SOCKS5 出口：{escape(node.socks5_host)}:{node.socks5_port}</div>" if node.socks5_host and node.socks5_port else "<div class=\"label\">SOCKS5 出口：默认 MiGate 本地出口</div>"
        toggle_action = _panel_url(base_path, f"/nodes/{node.id}/disable" if node.enabled else f"/nodes/{node.id}/enable")
        toggle_label = "禁用节点" if node.enabled else "启用节点"
        delete_action = _panel_url(base_path, f"/nodes/{node.id}/delete")
        edit_action = _panel_url(base_path, f"/nodes/{node.id}/edit")
        vless_selected = " selected" if node.protocol == "vless" else ""
        trojan_selected = " selected" if node.protocol == "trojan" else ""
        ss_selected = " selected" if node.protocol == "shadowsocks" else ""
        socks5_port_value = "" if node.socks5_port is None else str(node.socks5_port)
        items.append(
            f"""
    <article class="node">
      <div class="node-title">{escape(node.name)} <span class="label">#{node.id}</span></div>
      <div class="label">协议：{escape(node.protocol)} ｜ 地址：{address} ｜ 状态：{'启用' if node.enabled else '禁用'} <span class="badge badge-traffic">↑ {_format_bytes(node.up_bytes if hasattr(node,'up_bytes') else 0)} ↓ {_format_bytes(node.down_bytes if hasattr(node,'down_bytes') else 0)}</span></div>
      {socks5}
      <div class="label">分享链接</div>
      <div class="code-block"><code>{escape(node.share_link)}</code><button class="copy-btn" onclick="copyText(this)" data-text="{escape(node.share_link)}" data-orig="复制">复制</button><button class="copy-btn" onclick="showQR(this.dataset.text)" data-text="{escape(node.share_link)}">QR 码</button></div>
      <div class="label">订阅内容</div>
      <div class="code-block"><code>{escape(node.subscription)}</code><button class="copy-btn" onclick="copyText(this)" data-text="{escape(node.subscription)}" data-orig="复制">复制</button><button class="copy-btn" onclick="showQR(this.dataset.text)" data-text="{escape(node.subscription)}">QR 码</button></div>
      <div class="actions">
        <div class="toggle-wrap">
          <input type="checkbox" id="node-toggle-{node.id}" class="toggle-checkbox"{' checked' if node.enabled else ''} data-url="{escape(toggle_action)}">
          <label for="node-toggle-{node.id}" class="toggle-btn"></label>
        </div>
        <form method="post" action="{escape(delete_action)}">
          <button type="submit">删除节点</button>
        </form>
      </div>
      <details>
        <summary>编辑节点</summary>
        <form method="post" action="{escape(edit_action)}">
          <label>节点协议
            <select name="protocol">
              <option value="vless"{vless_selected}>VLESS</option>
              <option value="trojan"{trojan_selected}>Trojan</option>
              <option value="shadowsocks"{ss_selected}>Shadowsocks</option>
            </select>
          </label>
          <label>节点名称
            <input name="name" value="{escape(node.name)}">
          </label>
          <label>服务器域名/IP
            <input name="host" value="{escape(node.host)}" required>
          </label>
          <label>端口
            <input name="port" type="number" value="{node.port}" min="1" max="65535" required>
          </label>
          <label class="wide">UUID / 密码
            <input name="credential" value="{escape(node.credential)}" required>
          </label>
          <label>SOCKS5 出口主机（可选）
            <input name="socks5_host" value="{escape(node.socks5_host)}">
          </label>
          <label>SOCKS5 出口端口（可选）
            <input name="socks5_port" type="number" min="1" max="65535" value="{escape(socks5_port_value)}">
          </label>
          <button type="submit">保存修改</button>
        </form>
      </details>
    </article>
"""
        )
    return f"""
  <section class="card">
    <h2>已创建节点</h2>
    {''.join(items)}
  </section>
"""


def _inbounds_html(inbounds: list[InboundRecord], *, base_path: str = "/") -> str:
    if not inbounds:
        return """
  <section class="card">
    <h2>入站规则</h2>
    <p>还没有入站规则。使用下方表单创建第一个入站。</p>
  </section>
"""

    items = []
    for ib in inbounds:
        toggle_action = _panel_url(base_path, f"/inbounds/{ib.id}/disable" if ib.enabled else f"/inbounds/{ib.id}/enable")
        toggle_label = "禁用" if ib.enabled else "启用"
        delete_action = _panel_url(base_path, f"/inbounds/{ib.id}/delete")
        edit_action = _panel_url(base_path, f"/inbounds/{ib.id}/edit")
        traffic_up = _format_bytes(ib.up_bytes)
        traffic_down = _format_bytes(ib.down_bytes)
        protocol_selected = {p: " selected" if ib.protocol == p else "" for p in ("vless", "vmess", "trojan", "shadowsocks")}
        # Parse clients from settings
        try:
            ib_clients = json.loads(ib.settings).get("clients", [])
        except (json.JSONDecodeError, TypeError):
            ib_clients = []

        clients_html = ""
        for cl in ib_clients:
            cl_id = cl.get("id", "")
            cl_email = cl.get("email", "") or cl_id[:8]
            clients_html += f'''
    <div class="client-row" style="display:flex;align-items:center;gap:8px;padding:4px 0;">
      <span style="font-family:monospace;font-size:13px;">{escape(cl_email)}</span>
      <span style="color:var(--text-muted);font-size:12px;">{escape(cl_id[:8])}...</span>
      <button class="btn btn-sm btn-danger" onclick="removeClient('{escape(str(ib.id))}','{escape(cl_id)}',this)">删除</button>
    </div>'''

        add_client_url = f"/api/inbounds/{ib.id}/clients/add"
        clients_section = f'''
<div style="margin-top:12px;border-top:1px solid var(--border);padding-top:8px;">
  <div style="font-weight:600;margin-bottom:6px;">👤 客户端管理</div>
  <div id="clients-{ib.id}">{clients_html if clients_html else '<div style="color:var(--text-muted);">暂无客户端</div>'}</div>
  <form onsubmit="addClient(event,'{escape(str(ib.id))}','{escape(add_client_url)}')" style="margin-top:8px;display:flex;gap:8px;">
    <input type="email" name="email" placeholder="客户端邮箱" required style="flex:1;">
    <button type="submit" class="btn btn-primary btn-sm">添加</button>
  </form>
</div>'''
        items.append(f"""
    <article class="node">
      <div class="node-title">{escape(ib.remark)} <span class="label">#{ib.id}</span></div>
      <div class="label">协议：{escape(ib.protocol)} ｜ 端口：{ib.port} ｜ 监听：{escape(ib.listen)} ｜ 状态：{'启用' if ib.enabled else '禁用'} <span class="badge badge-traffic">↑ {traffic_up} ↓ {traffic_down}</span></div>
      <div class="actions">
        <div class="toggle-wrap">
          <input type="checkbox" id="inbound-toggle-{ib.id}" class="toggle-checkbox"{' checked' if ib.enabled else ''} data-url="{escape(toggle_action)}">
          <label for="inbound-toggle-{ib.id}" class="toggle-btn"></label>
        </div>
        <form method="post" action="{escape(delete_action)}">
          <button type="submit">删除</button>
        </form>
      </div>
      <details>
        <summary>编辑入站</summary>
        <form method="post" action="{escape(edit_action)}">
          <label>备注
            <input name="remark" value="{escape(ib.remark)}" required>
          </label>
          <label>协议
            <select name="protocol">
              <option value="vless"{protocol_selected['vless']}>VLESS</option>
              <option value="vmess"{protocol_selected['vmess']}>VMess</option>
              <option value="trojan"{protocol_selected['trojan']}>Trojan</option>
              <option value="shadowsocks"{protocol_selected['shadowsocks']}>Shadowsocks</option>
            </select>
          </label>
          <label>端口
            <input name="port" type="number" value="{ib.port}" min="1" max="65535" required>
          </label>
          <input type="hidden" name="listen" value="{escape(ib.listen)}">
          <input type="hidden" name="settings" value="{escape(ib.settings)}">
          <input type="hidden" name="stream_settings" value="{escape(ib.stream_settings)}">
          <button type="submit">保存修改</button>
        </form>
      </details>
      {clients_section}
    </article>
""")
    return f"""
  <section class="card">
    <h2>入站规则</h2>
    {''.join(items)}
  </section>
"""


def _format_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def _xray_config_for_nodes(nodes: list[NodeRecord], *, inbounds: list[InboundRecord] | None = None) -> dict[str, object]:
    build_combined = _lazy_import('migate.xray.node_adapter', 'build_config_from_nodes_and_inbounds')
    return build_combined(MiGateConfig(), nodes=[n for n in nodes if n.enabled], inbounds=inbounds or [])


def _xray_preview_html(nodes: list[NodeRecord], *, base_path: str = "/", inbounds: list[InboundRecord] | None = None) -> str:
    enabled_nodes = [node for node in nodes if node.enabled]
    if not enabled_nodes and not inbounds:
        return f"""
  <section class="card">
    <h2>Xray 配置</h2>
    <p>暂无启用节点。创建节点后这里会显示配置。</p>
  </section>
"""
    preview = json.dumps(_xray_config_for_nodes(enabled_nodes, inbounds=inbounds), indent=2, ensure_ascii=False)
    return f"""
  <section class="card">
    <h2>Xray 配置</h2>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">
      <form method="post" action="{escape(_panel_url(base_path, '/xray/config/save'))}">
        <button type="submit" class="btn btn-primary btn-sm">💾 保存配置</button>
      </form>
      <form method="post" action="{escape(_panel_url(base_path, '/xray/config/validate'))}">
        <button type="submit" class="btn btn-sm">✅ 校验配置</button>
      </form>
      <form method="post" action="{escape(_panel_url(base_path, '/xray/apply'))}">
        <button type="submit" class="btn btn-sm">🚀 应用配置</button>
      </form>
      <form method="post" action="{escape(_panel_url(base_path, '/xray/restart'))}">
        <button type="submit" class="btn btn-sm">🔄 重启 Xray</button>
      </form>
    </div>
    <details>
      <summary style="cursor:pointer;color:var(--text-muted);margin-bottom:8px;">📄 查看配置 JSON（{len(preview)} 字符）</summary>
      <pre style="max-height:400px;overflow:auto;">{escape(preview)}</pre>
    </details>
  </section>
"""


def _rewrite_panel_actions(html: str, *, base_path: str) -> str:
    normalized_base = _normalize_panel_base_path(base_path)
    if normalized_base == "/":
        return html
    protected_prefixes = (
        "/nodes/",
        "/xray/",
        "/systemd/",
        "/remote/",
        "/egress/",
    )
    rewritten = html
    for prefix in protected_prefixes:
        rewritten = rewritten.replace(f'action="{prefix}', f'action="{normalized_base}{prefix}')
    return rewritten


def _action_page(
    result_html: str,
    *,
    active: str = "dashboard",
    title: str = "操作结果",
    subtitle: str = "",
    base_path: str = "/",
    user: str = "",
) -> str:
    """Wrap an action result in the sidebar layout."""
    from migate.panel.layout import layout
    return layout(
        active=active, title=title, subtitle=subtitle,
        content=result_html, base_path=base_path, user=user,
    )


def _home_body(
    *,
    nodes: list[NodeRecord] | None = None,
    inbounds: list[InboundRecord] | None = None,
    result_html: str = "",
    auth_html: str = "",
    base_path: str = "/",
    systemd_html: str = "",
    service_status_html: str = "",
    xray_runtime_html: str = "",
    xray_install_plan_html: str = "",
    xray_install_dry_run_html: str = "",
    egress_status_html: str = "",
    egress_dry_run_html: str = "",
) -> str:
    current_nodes = nodes or []
    nodes_html = _nodes_html(current_nodes, base_path=base_path)
    inbounds_html = _inbounds_html(inbounds or [], base_path=base_path)
    preview_html = _xray_preview_html(current_nodes, base_path=base_path)
    html = f"""
  <section class="hero">
    <div>
      <h1>MiGate</h1>
      <p>一体化 Xray + VPNGate + OpenVPN 智能出站网关。面板面向小白用户：选择协议、填写域名和端口，即可生成节点链接和订阅内容。</p>
    </div>
    {auth_html}
  </section>


  <section class="card">
    <h2>创建节点</h2>
    <p>推荐新手先使用 VLESS TCP；Trojan 和 Shadowsocks 也已支持链接生成。</p>
    <form method="post" action="{escape(_panel_url(base_path, '/nodes/create'))}">
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
      <label>SOCKS5 出口主机（可选）
        <input name="socks5_host" placeholder="127.0.0.1">
      </label>
      <label>SOCKS5 出口端口（可选）
        <input name="socks5_port" type="number" min="1" max="65535" placeholder="34501">
      </label>
      <button type="submit">生成并保存节点</button>
    </form>
  </section>

  <section class="card">
    <h2>创建入站规则</h2>
    <p>创建 Xray 入站代理。支持 VLESS、VMess、Trojan、Shadowsocks 协议。</p>
    <form method="post" action="{escape(_panel_url(base_path, '/inbounds/create'))}">
      <label>备注
        <input name="remark" placeholder="HK VLESS TLS" required>
      </label>
      <label>协议
        <select name="protocol">
          <option value="vless">VLESS</option>
          <option value="vmess">VMess</option>
          <option value="trojan">Trojan</option>
          <option value="shadowsocks">Shadowsocks</option>
        </select>
      </label>
      <label>端口
        <input name="port" type="number" value="443" min="1" max="65535" required>
      </label>
      <label>监听地址
        <input name="listen" value="0.0.0.0" required>
      </label>
      <label class="wide">Settings (JSON)
        <input name="settings" placeholder='{{"clients":[{{"id":"uuid"}}]}}'>
      </label>
      <label class="wide">Stream Settings (JSON)
        <input name="stream_settings" placeholder='{{"network":"tcp","security":"tls"}}'>
      </label>
      <button type="submit">创建入站</button>
    </form>
  </section>

  {result_html}
  {xray_runtime_html}
  {xray_install_plan_html}
  {xray_install_dry_run_html}
  {egress_status_html}
  {egress_dry_run_html}
  {service_status_html}
  {inbounds_html}
  {nodes_html}
  {preview_html}
  {systemd_html}
"""
    return _rewrite_panel_actions(html, base_path=base_path)


def _credential_for_protocol(protocol: str, credential: str) -> str:
    if credential:
        return credential
    if protocol == "vless":
        return str(uuid4())
    return uuid4().hex


def _build_link(protocol: str, host: str, port: int, name: str, credential: str) -> str:
    build_shadowsocks_link = _lazy_import('migate.xray.links', 'build_shadowsocks_link')
    build_trojan_link = _lazy_import('migate.xray.links', 'build_trojan_link')
    build_vless_link = _lazy_import('migate.xray.links', 'build_vless_link')
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
    <h2>服务文件</h2>
    <form method="post" action="/systemd/units/save" style="margin-bottom:12px;">
      <button type="submit" class="btn btn-sm">💾 保存服务文件</button>
    </form>
    <details>
      <summary style="cursor:pointer;color:var(--text-muted);margin-bottom:8px;">📄 查看 {escape(xray_unit.name)}</summary>
      <pre>{escape(xray_unit.content)}</pre>
    </details>
    <details>
      <summary style="cursor:pointer;color:var(--text-muted);margin-bottom:8px;">📄 查看 {escape(panel_unit.name)}</summary>
      <pre>{escape(panel_unit.content)}</pre>
    </details>
  </section>
"""


def _service_status_row(service_name: str, result: SystemdResult) -> str:
    is_active = result.status.lower() in ("active", "running")
    icon = "🟢" if is_active else "🔴"
    label = "运行中" if is_active else "已停止"
    friendly_name = service_name.replace("migate-", "").replace(".service", "")
    return f"""
    <div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--border);">
      <span style="font-size:20px;">{icon}</span>
      <div style="flex:1;">
        <div style="font-weight:600;">{escape(friendly_name)}</div>
        <div class="label">{label}</div>
      </div>
    </div>
"""


def _service_statuses_html(services: dict[str, SystemdResult], *, refreshed: bool = False) -> str:
    heading = "服务状态已刷新" if refreshed else "服务状态"
    rows = "\n".join(_service_status_row(name, result) for name, result in services.items())
    return f"""
  <section class="card">
    <h2>{heading}</h2>
    {rows}
    <form method="post" action="/systemd/status/refresh" style="margin-top:12px;">
      <button type="submit" class="btn btn-sm">🔄 刷新状态</button>
    </form>
  </section>
"""


def _service_status_html(status_loader: Callable[[str], SystemdResult], *, refreshed: bool = False) -> str:
    return _service_statuses_html(_load_migate_systemd_services(status_loader), refreshed=refreshed)


def _xray_runtime_status_html(status: XrayRuntimeStatus, *, refreshed: bool = False) -> str:
    heading = "Xray 运行时已刷新" if refreshed else "Xray 运行时"
    is_ok = status.status in ("running", "ok", "installed")
    icon = "🟢" if is_ok else "🔴"
    version = status.version or "未安装"
    return f"""
  <section class="card">
    <h2>{heading}</h2>
    <div style="display:flex;align-items:center;gap:8px;">
      <span style="font-size:20px;">{icon}</span>
      <span style="font-weight:600;">{escape(version)}</span>
    </div>
    <div class="label">路径：{escape(status.bin_path)}</div>
    <form method="post" action="/xray/runtime/refresh" style="margin-top:8px;">
      <button type="submit" class="btn btn-sm">🔄 刷新</button>
    </form>
  </section>
"""


def _xray_runtime_html(runtime_loader: Callable[[], XrayRuntimeStatus], *, refreshed: bool = False) -> str:
    return _xray_runtime_status_html(runtime_loader(), refreshed=refreshed)


def _xray_install_plan_json(plan: XrayInstallPlan) -> dict[str, object]:
    XrayInstallPlan = _lazy_import('migate.xray.install_plan', 'XrayInstallPlan')
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
    XrayInstallDryRunResult = _lazy_import('migate.xray.install_executor', 'XrayInstallDryRunResult')
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
    XrayInstallPlan = _lazy_import('migate.xray.install_plan', 'XrayInstallPlan')
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
    XrayInstallDryRunResult = _lazy_import('migate.xray.install_executor', 'XrayInstallDryRunResult')
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


def _remote_check_rows_html(checks: object) -> str:
    rows = []
    if isinstance(checks, list):
        for check in checks:
            name = getattr(check, "name", "")
            status = getattr(check, "status", "")
            message = getattr(check, "message", "")
            if name == "systemctl_bin":
                continue
            rows.append(f"{name}: {status} - {message}")
    return "\n".join(rows)


def _remote_rollout_steps_html(steps: list[RemoteRolloutStep]) -> str:
    RemoteRolloutStep = _lazy_import('migate.remote.rollout_plan', 'RemoteRolloutStep')
    return "\n".join(
        f"{step.action}: {'side_effect' if step.performs_side_effects else 'read_only'} - {step.description}"
        for step in steps
    )


def _remote_commands_preview(commands: list[str]) -> list[str]:
    hidden_terms = ("systemctl", "daemon-reload", "restart", "start ", " stop ")
    return ["[REDACTED_COMMAND]" if any(term in command for term in hidden_terms) else command for command in commands]


def _remote_status_detail_html(
    *,
    readiness: "RemoteReadinessReport",
    leak_check: "RemoteLeakCheckReport",
    rollout: "RemoteRolloutPlan",
) -> str:
    RemoteReadinessReport = _lazy_import('migate.remote.readiness', 'RemoteReadinessReport')
    RemoteLeakCheckReport = _lazy_import('migate.remote.leak_check', 'RemoteLeakCheckReport')
    RemoteRolloutPlan = _lazy_import('migate.remote.rollout_plan', 'RemoteRolloutPlan')
    readiness_checks = _remote_check_rows_html(readiness.checks)
    leak_checks = _remote_check_rows_html(leak_check.checks)
    rollout_steps = _remote_rollout_steps_html(rollout.steps)
    preview = "\n".join(
        [
            "readiness:",
            f"readiness: {readiness.status}",
            f"target: {readiness.target}",
            readiness_checks,
            f"commands_executed: {_remote_commands_preview(readiness.commands_executed)}",
            f"performed_side_effects: {readiness.performed_side_effects}",
            "",
            "leak-check:",
            f"leak-check: {leak_check.status}",
            f"target: {leak_check.target}",
            f"native_public_ip: {leak_check.native_public_ip}",
            f"egress_public_ip: {leak_check.egress_public_ip}",
            leak_checks,
            f"commands_executed: {_remote_commands_preview(leak_check.commands_executed)}",
            f"performed_side_effects: {leak_check.performed_side_effects}",
            "",
            "rollout dry-run:",
            f"rollout dry-run: {rollout.status}",
            f"message: {rollout.message}",
            f"target: {rollout.target}",
            f"credential_hint: {rollout.credential_hint}",
            f"staging_dir: {rollout.staging_dir}",
            rollout_steps,
            f"commands_executed: {_remote_commands_preview(rollout.commands_executed)}",
            f"performed_side_effects: {rollout.performed_side_effects}",
        ]
    )
    return f"""
  <section class="card">
    <h2>远端状态详情</h2>
    <p>这里只展示 readiness、leak-check 与 rollout dry-run 的只读诊断；不会 SSH apply，不会写远端，也不会启动或停止远端服务。</p>
    <form method="post" action="/remote/status/refresh">
      <button type="submit">刷新远端状态</button>
    </form>
    <div class="label">危险动作：禁用</div>
    <pre>{escape(preview)}</pre>
  </section>
"""


def _egress_status_report_html(report: EgressStatusReport, *, refreshed: bool = False) -> str:
    heading = "出口状态已刷新" if refreshed else "出口状态"
    is_ok = report.status.lower() in ("ok", "healthy", "active")
    icon = "🟢" if is_ok else "🔴"
    status_text = "正常" if is_ok else "异常"
    checks_html = ""
    for check in report.checks:
        check_icon = "✅" if check.status.lower() in ("ok", "pass") else "⚠️"
        checks_html += f'<div style="padding:4px 0;">{check_icon} {escape(check.name)}: {escape(check.message)}</div>'
    return f"""
  <section class="card">
    <h2>{heading}</h2>
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
      <span style="font-size:20px;">{icon}</span>
      <span style="font-weight:600;">{status_text}</span>
    </div>
    {checks_html}
    <form method="post" action="/egress/status/refresh" style="margin-top:8px;">
      <button type="submit" class="btn btn-sm">🔄 刷新状态</button>
    </form>
  </section>
"""


def _egress_status_html(status_loader: Callable[[], EgressStatusReport], *, refreshed: bool = False) -> str:
    return _egress_status_report_html(status_loader(), refreshed=refreshed)


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


def _xray_runtime_status_json(runtime: XrayRuntimeStatus, *, include_output: bool = True) -> dict[str, object]:
    result: dict[str, object] = {
        "status": runtime.status,
        "bin_path": runtime.bin_path,
        "version": runtime.version,
        "message": runtime.message,
        "returncode": runtime.returncode,
    }
    if include_output:
        result["stdout"] = runtime.stdout
        result["stderr"] = runtime.stderr
        result["performed_side_effects"] = False
    return result


def _xray_validation_result_json(result: XrayValidationResult, *, target_path: Path) -> dict[str, object]:
    XrayValidationResult = _lazy_import('migate.xray.validator', 'XrayValidationResult')
    return {
        "status": result.status,
        "target_path": str(target_path),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "systemctl_commands_executed": [],
        "performed_side_effects": False,
    }


def _systemd_result_json(result: SystemdResult) -> dict[str, object]:
    return {
        "status": result.status,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _systemd_services_status_json(services: dict[str, SystemdResult]) -> dict[str, object]:
    return {name: _systemd_result_json(result) for name, result in services.items()}


def _xray_validation_summary_json(result: XrayValidationResult) -> dict[str, object]:
    XrayValidationResult = _lazy_import('migate.xray.validator', 'XrayValidationResult')
    return {
        "status": result.status,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def build_xray_apply_dry_run_plan(*, nodes: Sized, enabled_nodes: Sized, config_path: Path) -> dict[str, object]:
    return {
        "status": "dry_run",
        "message": "planned only; no config write, validation, or service control executed",
        "target_path": str(config_path),
        "counts": {"total_nodes": len(nodes), "enabled_nodes": len(enabled_nodes)},
        "steps": [
            {"action": "generate_config", "status": "planned", "performs_side_effects": False},
            {"action": "write_config", "status": "planned", "target_path": str(config_path), "performs_side_effects": True},
            {"action": "validate_config", "status": "planned", "target_path": str(config_path), "performs_side_effects": False},
            {"action": "daemon_reload", "status": "planned", "service": None, "performs_side_effects": True},
            {"action": "restart_service", "status": "planned", "service": "migate-xray.service", "performs_side_effects": True},
        ],
        "commands_executed": [],
        "systemctl_commands_executed": [],
        "performed_side_effects": False,
    }


def build_xray_restart_dry_run_plan(*, config_path: Path) -> dict[str, object]:
    return {
        "status": "dry_run",
        "message": "planned only; no validation or service control executed",
        "target_path": str(config_path),
        "steps": [
            {"action": "validate_config", "status": "planned", "target_path": str(config_path), "performs_side_effects": False},
            {"action": "daemon_reload", "status": "planned", "service": None, "performs_side_effects": True},
            {"action": "restart_service", "status": "planned", "service": "migate-xray.service", "performs_side_effects": True},
            {"action": "refresh_service_status", "status": "planned", "service": "migate-xray.service", "performs_side_effects": False},
        ],
        "commands_executed": [],
        "systemctl_commands_executed": [],
        "performed_side_effects": False,
    }


def _safe_preview_actions_json() -> list[dict[str, str]]:
    return [
        {"name": "dashboard", "method": "GET", "path": "/api/dashboard"},
        {"name": "xray_install_plan", "method": "GET", "path": "/api/xray/install-plan"},
        {"name": "xray_install_dry_run", "method": "GET", "path": "/api/xray/install/dry-run"},
        {"name": "xray_config_preview", "method": "GET", "path": "/api/xray/config/preview"},
        {"name": "xray_config_validate", "method": "GET", "path": "/api/xray/config/validate"},
        {"name": "xray_apply_dry_run", "method": "GET", "path": "/api/xray/apply/dry-run"},
        {"name": "xray_restart_dry_run", "method": "GET", "path": "/api/xray/restart/dry-run"},
        {"name": "egress_up_dry_run", "method": "GET", "path": "/api/egress/up/dry-run"},
        {"name": "egress_down_dry_run", "method": "GET", "path": "/api/egress/down/dry-run"},
        {"name": "remote_rollout_dry_run", "method": "GET", "path": "/api/remote/rollout/dry-run"},
        {"name": "systemd_units_preview", "method": "GET", "path": "/api/systemd/units/preview"},
        {"name": "proxy_service_preview", "method": "GET", "path": "/api/proxy/service/preview"},
    ]


def _dangerous_actions_json(*, enabled: bool = False) -> list[dict[str, object]]:
    return [
        {"name": "xray_apply", "method": "POST", "path": "/api/xray/apply", "enabled": enabled},
        {"name": "xray_restart", "method": "POST", "path": "/api/xray/restart", "enabled": enabled},
    ]


def _egress_status_report_json(report: EgressStatusReport) -> dict[str, object]:
    return {
        "status": report.status,
        "checks": [
            {
                "name": check.name,
                "status": check.status,
                "message": check.message,
            }
            for check in report.checks
        ],
        "performed_side_effects": report.performed_side_effects,
    }


def _proxy_run_result_json(result: ProxyRunResult) -> dict[str, object]:
    ProxyRunResult = _lazy_import('migate.proxy.run', 'ProxyRunResult')
    return {
        "status": result.status,
        "message": result.message,
        "listener_started": result.listener_started,
        "forwarding_started": result.forwarding_started,
        "accepted_connections": result.accepted_connections,
        "upstream_connections": result.upstream_connections,
        "timed_out_connections": result.timed_out_connections,
        "max_clients": result.max_clients,
        "serve_mode": result.serve_mode,
        "client_timeout": result.client_timeout,
        "checks": [
            {
                "name": check.name,
                "status": check.status,
                "message": check.message,
            }
            for check in result.checks
        ],
        "performed_side_effects": result.performed_side_effects,
    }


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


def _remote_readiness_report_json(report: RemoteReadinessReport) -> dict[str, object]:
    RemoteReadinessReport = _lazy_import('migate.remote.readiness', 'RemoteReadinessReport')
    return {
        "status": report.status,
        "target": report.target,
        "checks": [
            {"name": check.name, "status": check.status, "message": check.message}
            for check in report.checks
        ],
        "commands_executed": report.commands_executed,
        "performed_side_effects": report.performed_side_effects,
    }


def _remote_leak_check_report_json(report: RemoteLeakCheckReport) -> dict[str, object]:
    RemoteLeakCheckReport = _lazy_import('migate.remote.leak_check', 'RemoteLeakCheckReport')
    return {
        "status": report.status,
        "target": report.target,
        "native_public_ip": report.native_public_ip,
        "egress_public_ip": report.egress_public_ip,
        "checks": [
            {"name": check.name, "status": check.status, "message": check.message}
            for check in report.checks
        ],
        "commands_executed": report.commands_executed,
        "performed_side_effects": report.performed_side_effects,
    }


def _remote_rollout_plan_json(plan: RemoteRolloutPlan) -> dict[str, object]:
    RemoteRolloutPlan = _lazy_import('migate.remote.rollout_plan', 'RemoteRolloutPlan')
    return {
        "status": plan.status,
        "message": plan.message,
        "target": plan.target,
        "credential_hint": plan.credential_hint,
        "staging_dir": plan.staging_dir,
        "steps": [
            {
                "action": step.action,
                "description": step.description,
                "command_preview": step.command_preview,
                "performs_side_effects": step.performs_side_effects,
            }
            for step in plan.steps
        ],
        "commands_executed": plan.commands_executed,
        "performed_side_effects": plan.performed_side_effects,
    }


def _dashboard_snapshot_json(
    *,
    nodes: list[NodeRecord],
    runtime: XrayRuntimeStatus,
    egress: EgressStatusReport,
    proxy: ProxyRunResult,
    services: dict[str, SystemdResult],
    readiness: RemoteReadinessReport,
    leak_check: RemoteLeakCheckReport,
    rollout: RemoteRolloutPlan,
    dangerous_actions_enabled: bool = False,
) -> dict[str, object]:
    healthy = (
        runtime.status == "installed"
        and all(check.status == "ok" for check in egress.checks)
        and all(service.status == "success" for service in services.values())
        and readiness.status == "ok"
        and leak_check.status == "ok"
    )
    return {
        "status": "ok" if healthy else "degraded",
        "nodes": {
            "total": len(nodes),
            "enabled": sum(1 for node in nodes if node.enabled),
        },
        "cards": {
            "xray": _xray_runtime_status_json(runtime, include_output=False),
            "egress": _egress_status_report_json(egress),
            "proxy": _proxy_run_result_json(proxy),
            "systemd": {
                "services": _systemd_services_status_json(services),
                "systemctl_commands_executed": [],
                "performed_side_effects": False,
            },
            "remote": {
                "readiness": _remote_readiness_report_json(readiness),
                "leak_check": _remote_leak_check_report_json(leak_check),
                "rollout_dry_run": _remote_rollout_plan_json(rollout),
            },
        },
        "actions": {
            "safe_previews": _safe_preview_actions_json(),
            "dangerous_actions_enabled": dangerous_actions_enabled,
            "dangerous_actions": _dangerous_actions_json(enabled=dangerous_actions_enabled),
        },
        "performed_side_effects": False,
    }


def _card_status_class(status: object) -> str:
    return "ok" if str(status) in {"ok", "installed", "observed", "running", "dry_run", "success"} else "warn"


def _dashboard_card_html(label: str, value: object, detail: object = "") -> str:
    value_text = str(value)
    detail_html = f'<div class="label">{escape(str(detail))}</div>' if detail else ""
    return f"""
    <div class="card">
      <div class="label">{escape(label)}</div>
      <div class="value {_card_status_class(value_text)}">{escape(value_text)}</div>
      {detail_html}
    </div>
"""


def _dashboard_html(snapshot: dict[str, object]) -> str:
    cards = snapshot["cards"]
    assert isinstance(cards, dict)
    xray = cards["xray"]
    egress = cards["egress"]
    proxy = cards["proxy"]
    systemd = cards["systemd"]
    assert isinstance(xray, dict)
    assert isinstance(egress, dict)
    assert isinstance(proxy, dict)
    assert isinstance(systemd, dict)
    nodes = snapshot["nodes"]
    assert isinstance(nodes, dict)

    xray_ok = str(xray.get("status", "")).lower() in ("running", "ok", "active")
    xray_icon = "🟢" if xray_ok else "🔴"
    xray_text = "运行中" if xray_ok else "未运行"
    xray_ver = xray.get("version") or ""

    nodes_text = f"{nodes['enabled']}/{nodes['total']} 已启用"

    services = systemd.get("services", {})
    svc_ok = sum(1 for v in services.values() if isinstance(v, dict) and str(v.get("status", "")).lower() in ("active", "running"))
    svc_total = len(services)

    return f"""
  <section class="card">
    <h2>系统状态</h2>
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin:16px 0;">
      <div class="card" style="text-align:center;">
        <div style="font-size:32px;">{xray_icon}</div>
        <div style="font-weight:600;margin:8px 0 4px;">Xray</div>
        <div class="label">{xray_text} {escape(xray_ver)}</div>
      </div>
      <div class="card" style="text-align:center;">
        <div style="font-size:32px;">🔗</div>
        <div style="font-weight:600;margin:8px 0 4px;">节点</div>
        <div class="label">{nodes_text}</div>
      </div>
      <div class="card" style="text-align:center;">
        <div style="font-size:32px;">⚙️</div>
        <div style="font-weight:600;margin:8px 0 4px;">服务</div>
        <div class="label">{svc_ok}/{svc_total} 正常</div>
      </div>
    </div>
    <h3 style="margin-top:24px;">📊 流量统计</h3>
    <div class="grid" id="traffic-stats">
      <div class="card"><div class="label">加载中...</div></div>
    </div>
    <script>
    (function(){{
      function fmt(v){{if(v>1073741824)return(v/1073741824).toFixed(2)+' GB';if(v>1048576)return(v/1048576).toFixed(2)+' MB';if(v>1024)return(v/1024).toFixed(2)+' KB';return v+' B';}}
  fetch('/api/stats/traffic').then(r=>r.json()).then(data=>{{
    const el=document.getElementById('traffic-stats');
    if(!data.inbounds||data.inbounds.length===0){{el.innerHTML='<div class="card"><div class="label">暂无流量数据</div></div>';return;}}
    el.innerHTML=data.inbounds.map(s=>`<div class="card"><div class="label">${{s.remark}} (${{s.protocol}}:${{s.port}})</div><div class="value">↑ ${{fmt(s.up_bytes)}} ↓ ${{fmt(s.down_bytes)}}</div><div class="label">总计 ${{fmt(s.total_bytes)}}</div></div>`).join('');
  }}).catch(()=>{{document.getElementById('traffic-stats').innerHTML='<div class="card"><div class="label">流量数据获取失败</div></div>';}});
    }})();
    </script>
  </section>
{_dangerous_actions_html(snapshot)}
"""


def _dangerous_actions_html(snapshot: dict[str, object]) -> str:
    actions = snapshot.get("actions", {})
    assert isinstance(actions, dict)
    enabled = actions.get("dangerous_actions_enabled", False)
    if not enabled:
        return ""
    return """
  <section class="card">
    <div class="label">危险动作：启用</div>
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:12px;">
      <form method="post" action="/api/xray/apply">
        <input type="hidden" name="confirm" value="APPLY">
        <button type="submit">应用 Xray 配置</button>
      </form>
      <form method="post" action="/api/xray/restart">
        <input type="hidden" name="confirm" value="RESTART">
        <button type="submit">重启 Xray</button>
      </form>
    </div>
  </section>
"""


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
    build_openvpn_start_plan = _lazy_import('migate.vpn.process_plan', 'build_openvpn_start_plan')
    build_policy_routing_plan = _lazy_import('migate.routing.policy_plan', 'build_policy_routing_plan')
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
    build_openvpn_stop_plan = _lazy_import('migate.vpn.process_stop', 'build_openvpn_stop_plan')
    build_policy_routing_cleanup_plan = _lazy_import('migate.routing.policy_cleanup', 'build_policy_routing_cleanup_plan')
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
    XrayValidationResult = _lazy_import('migate.xray.validator', 'XrayValidationResult')
    values = []
    for part in parts:
        if isinstance(part, XrayValidationResult | SystemdResult):
            values.extend([part.stdout, part.stderr])
        elif part:
            values.append(str(part))
    return "\n".join(value for value in values if value)


def _xray_control_diagnostics_html(
    *,
    validation: "XrayValidationResult",
    reload_result: SystemdResult | None = None,
    restart_result: SystemdResult | None = None,
    restart_label: str = "Xray 重启",
) -> str:
    XrayValidationResult = _lazy_import('migate.xray.validator', 'XrayValidationResult')
    html = f"""
    <div class="label">配置校验</div>
    <pre>{escape(_result_output(validation))}</pre>"""
    if reload_result is not None:
        html += f"""
    <div class="label">服务重载：{escape(reload_result.status)}</div>
    <pre>{escape(_result_output(reload_result))}</pre>"""
    if restart_result is not None:
        html += f"""
    <div class="label">{escape(restart_label)}：{escape(restart_result.status)}</div>
    <pre>{escape(_result_output(restart_result))}</pre>"""
    return html


def create_app(
    node_repository: NodeRepository | None = None,
    inbound_repository: InboundRepository | None = None,
    xray_config_path: str | Path | None = None,
    xray_validator: Callable[[Path], "XrayValidationResult"] | None = None,
    systemd_unit_dir: str | Path | None = None,
    systemd_status_loader: Callable[[str], SystemdResult] | None = None,
    systemd_daemon_reloader: Callable[[], SystemdResult] | None = None,
    systemd_restarter: Callable[[str], SystemdResult] | None = None,
    xray_runtime_loader: Callable[[], XrayRuntimeStatus] | None = None,
    xray_install_plan_loader: Callable[[], "XrayInstallPlan"] | None = None,
    xray_install_dry_run_loader: Callable[[], "XrayInstallDryRunResult"] | None = None,
    egress_status_loader: Callable[[], EgressStatusReport] | None = None,
    proxy_runtime_loader: Callable[[], "ProxyRunResult"] | None = None,
    egress_up_dry_run_loader: Callable[[], EgressLifecycleResult] | None = None,
    egress_down_dry_run_loader: Callable[[], EgressLifecycleResult] | None = None,
    remote_readiness_loader: Callable[..., "RemoteReadinessReport"] | None = None,
    remote_leak_check_loader: Callable[..., "RemoteLeakCheckReport"] | None = None,
    remote_rollout_plan_loader: Callable[..., "RemoteRolloutPlan"] | None = None,
    panel_auth_config: dict[str, object] | None = None,
    panel_config_path: str | Path | None = None,
) -> FastAPI:
    # Lazy imports — loaded once when the app starts, not at module import time
    ProxyRunResult = _lazy_import('migate.proxy.run', 'ProxyRunResult')
    run_proxy = _lazy_import('migate.proxy.run', 'run_proxy')
    preview_proxy_service_unit = _lazy_import('migate.proxy.service_cli', 'preview_proxy_service_unit')
    RemoteLeakCheckReport = _lazy_import('migate.remote.leak_check', 'RemoteLeakCheckReport')
    run_remote_leak_check = _lazy_import('migate.remote.leak_check', 'run_remote_leak_check')
    RemoteReadinessReport = _lazy_import('migate.remote.readiness', 'RemoteReadinessReport')
    run_remote_readiness = _lazy_import('migate.remote.readiness', 'run_remote_readiness')
    RemoteRolloutPlan = _lazy_import('migate.remote.rollout_plan', 'RemoteRolloutPlan')
    RemoteRolloutStep = _lazy_import('migate.remote.rollout_plan', 'RemoteRolloutStep')
    build_remote_rollout_dry_run_plan = _lazy_import('migate.remote.rollout_plan', 'build_remote_rollout_dry_run_plan')
    build_policy_routing_cleanup_plan = _lazy_import('migate.routing.policy_cleanup', 'build_policy_routing_cleanup_plan')
    build_policy_routing_plan = _lazy_import('migate.routing.policy_plan', 'build_policy_routing_plan')
    XrayInstallDryRunResult = _lazy_import('migate.xray.install_executor', 'XrayInstallDryRunResult')
    dry_run_xray_install_plan = _lazy_import('migate.xray.install_executor', 'dry_run_xray_install_plan')
    build_openvpn_start_plan = _lazy_import('migate.vpn.process_plan', 'build_openvpn_start_plan')
    build_openvpn_stop_plan = _lazy_import('migate.vpn.process_stop', 'build_openvpn_stop_plan')
    XrayInstallPlan = _lazy_import('migate.xray.install_plan', 'XrayInstallPlan')
    build_xray_install_plan = _lazy_import('migate.xray.install_plan', 'build_xray_install_plan')
    build_shadowsocks_link = _lazy_import('migate.xray.links', 'build_shadowsocks_link')
    build_trojan_link = _lazy_import('migate.xray.links', 'build_trojan_link')
    build_vless_link = _lazy_import('migate.xray.links', 'build_vless_link')
    build_config_from_nodes = _lazy_import('migate.xray.node_adapter', 'build_config_from_nodes')
    build_base64_subscription = _lazy_import('migate.xray.subscription', 'build_base64_subscription')
    XrayValidationResult = _lazy_import('migate.xray.validator', 'XrayValidationResult')
    validate_xray_config = _lazy_import('migate.xray.validator', 'validate_xray_config')
    write_xray_config = _lazy_import('migate.xray.writer', 'write_xray_config')
    query_xray_stats = _lazy_import('migate.xray.stats', 'query_xray_stats')
    loaded_panel_auth_config = panel_auth_config if panel_auth_config is not None else load_panel_auth_config(panel_config_path)
    panel_base_path = (
        _normalize_panel_base_path((loaded_panel_auth_config or {}).get("base_path"))
        if panel_auth_config is None and loaded_panel_auth_config
        else "/"
    )
    repo = node_repository or NodeRepository(DEFAULT_DB_PATH)
    inbound_repo = inbound_repository or InboundRepository(DEFAULT_DB_PATH)
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
    proxy_loader = proxy_runtime_loader or (lambda: run_proxy(migate_config))
    egress_up_loader = egress_up_dry_run_loader or (lambda: _default_egress_up_dry_run(migate_config))
    egress_down_loader = egress_down_dry_run_loader or (lambda: _default_egress_down_dry_run(migate_config))
    readiness_loader = remote_readiness_loader or run_remote_readiness
    leak_check_loader = remote_leak_check_loader or run_remote_leak_check
    remote_rollout_loader = remote_rollout_plan_loader or build_remote_rollout_dry_run_plan
    repo.initialize()
    inbound_repo.initialize()
    app = FastAPI(title="MiGate Panel")

    # Static files
    _static_dir = Path(__file__).resolve().parent.parent / "panel" / "static"

    @app.get(_panel_url(panel_base_path, "/static/{filename}"))
    def serve_static(filename: str):
        from fastapi.responses import FileResponse
        file_path = _static_dir / filename
        if not file_path.exists() or not file_path.is_file():
            return JSONResponse({"detail": "not found"}, status_code=404)
        return FileResponse(file_path, media_type="text/css" if filename.endswith(".css") else "application/octet-stream")

    @app.middleware("http")
    async def protect_panel_routes(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/") and not _is_authenticated(request, loaded_panel_auth_config):
            return JSONResponse({"detail": "authentication required", "performed_side_effects": False}, status_code=401)
        if (
            request.method == "POST"
            and _panel_auth_enabled(loaded_panel_auth_config)
            and path not in {_panel_url(panel_base_path, "/login"), _panel_url(panel_base_path, "/logout")}
            and (path.startswith(_panel_url(panel_base_path, "/")) if panel_base_path != "/" else path.startswith("/"))
            and not _is_authenticated(request, loaded_panel_auth_config)
        ):
            return RedirectResponse(_panel_url(panel_base_path, "/login"), status_code=303)
        return await call_next(request)

    @app.middleware("http")
    async def catch_exceptions_middleware(request: Request, call_next):
        try:
            return await call_next(request)
        except Exception as exc:
            import traceback

            trace = traceback.format_exc()
            path = request.url.path
            is_api = path.startswith("/api/")
            if is_api:
                return JSONResponse(
                    {"detail": "internal server error", "error": str(exc)},
                    status_code=500,
                )
            # HTML 页面：返回友好错误页
            html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MiGate - 出错了</title>
<style>
body {{ background:#0e1621; color:#e0e0e0; font-family:sans-serif; display:flex;
       justify-content:center; align-items:center; min-height:100vh; margin:0; }}
.box {{ background:#182533; padding:2rem 3rem; border-radius:12px; max-width:700px; }}
h1 {{ color:#e74c3c; }} pre {{ background:#0b1926; padding:1rem; border-radius:8px;
overflow-x:auto; font-size:0.85rem; }}
a {{ color:#4ecdc4; }}
</style></head><body>
<div class="box">
<h1>⚠️ 出错了</h1>
<p>请求 <code>{path}</code> 时发生内部错误。</p>
<p><strong>错误信息：</strong> {exc}</p>
<p><a href="{_panel_url(panel_base_path, '/')}">← 返回首页</a></p>
<details><summary>技术详情（仅供调试）</summary><pre>{trace}</pre></details>
</div></body></html>"""
            return HTMLResponse(html, status_code=500)

    def require_panel_auth(request: Request) -> RedirectResponse | None:
        if _is_authenticated(request, loaded_panel_auth_config):
            return None
        return RedirectResponse(_panel_url(panel_base_path, "/login"), status_code=303)

    @app.get(_panel_url(panel_base_path, "/login"), response_class=HTMLResponse)
    def login_page() -> str:
        return _login_html(base_path=panel_base_path)

    @app.post(_panel_url(panel_base_path, "/login"), response_class=HTMLResponse)
    def login(username: str = Form(...), password: str = Form(...)):
        if not _panel_auth_enabled(loaded_panel_auth_config):
            return RedirectResponse(_panel_url(panel_base_path, "/"), status_code=303)
        expected_user = str((loaded_panel_auth_config or {}).get("admin_user", ""))
        expected_hash = str((loaded_panel_auth_config or {}).get("password_hash", ""))
        if username != expected_user or _hash_panel_password(password) != expected_hash:
            return HTMLResponse(_login_html("登录失败", base_path=panel_base_path), status_code=401)
        response = RedirectResponse(_panel_url(panel_base_path, "/"), status_code=303)
        response.set_cookie("migate_session", _session_token_for_auth_config(loaded_panel_auth_config or {}), httponly=True, samesite="lax")
        return response

    @app.post(_panel_url(panel_base_path, "/logout"))
    def logout() -> RedirectResponse:
        response = RedirectResponse(_panel_url(panel_base_path, "/login"), status_code=303)
        response.delete_cookie("migate_session")
        return response

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
                    "socks5": {"host": node.socks5_host, "port": node.socks5_port} if node.socks5_host and node.socks5_port else None,
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

    @app.get("/api/nodes/export")
    def api_nodes_export() -> dict[str, object]:
        nodes = repo.list_nodes()
        enabled_nodes = [node for node in nodes if node.enabled]
        links = [node.share_link for node in enabled_nodes]
        return {
            "links": links,
            "subscription": build_base64_subscription(links),
            "counts": {
                "total": len(nodes),
                "enabled": len(enabled_nodes),
            },
            "performed_side_effects": False,
        }

    @app.get("/api/inbounds")
    def api_inbounds_list() -> dict[str, object]:
        inbounds = inbound_repo.list_inbounds()
        return {
            "inbounds": [
                {
                    "id": ib.id,
                    "remark": ib.remark,
                    "protocol": ib.protocol,
                    "port": ib.port,
                    "listen": ib.listen,
                    "settings": ib.settings,
                    "stream_settings": ib.stream_settings,
                    "enabled": ib.enabled,
                    "up_bytes": ib.up_bytes,
                    "down_bytes": ib.down_bytes,
                    "created_at": ib.created_at,
                }
                for ib in inbounds
            ],
            "performed_side_effects": False,
        }

    @app.get("/api/inbounds/{inbound_id}")
    def api_inbound_get(inbound_id: int) -> dict[str, object]:
        ib = inbound_repo.get_inbound(inbound_id)
        if ib is None:
            return {"status": "not_found", "performed_side_effects": False}
        return {
            "id": ib.id,
            "remark": ib.remark,
            "protocol": ib.protocol,
            "port": ib.port,
            "listen": ib.listen,
            "settings": ib.settings,
            "stream_settings": ib.stream_settings,
            "enabled": ib.enabled,
            "up_bytes": ib.up_bytes,
            "down_bytes": ib.down_bytes,
            "created_at": ib.created_at,
            "performed_side_effects": False,
        }

    @app.post("/api/inbounds")
    def api_inbound_create(
        remark: str = Form(...),
        protocol: str = Form(...),
        port: int = Form(...),
        listen: str = Form("0.0.0.0"),
        settings: str = Form("{}"),
        stream_settings: str = Form("{}"),
    ) -> dict[str, object]:
        ib = inbound_repo.create_inbound(
            remark=remark, protocol=protocol, port=port, listen=listen,
            settings=settings, stream_settings=stream_settings,
        )
        return {"status": "created", "id": ib.id, "performed_side_effects": True}

    @app.post("/api/inbounds/{inbound_id}/update")
    def api_inbound_update(
        inbound_id: int,
        remark: str = Form(...),
        protocol: str = Form(...),
        port: int = Form(...),
        listen: str = Form("0.0.0.0"),
        settings: str = Form("{}"),
        stream_settings: str = Form("{}"),
    ) -> dict[str, object]:
        ib = inbound_repo.update_inbound(
            inbound_id, remark=remark, protocol=protocol, port=port, listen=listen,
            settings=settings, stream_settings=stream_settings,
        )
        if ib is None:
            return {"status": "not_found", "performed_side_effects": False}
        return {"status": "updated", "id": ib.id, "performed_side_effects": True}

    @app.post("/api/inbounds/{inbound_id}/delete")
    def api_inbound_delete(inbound_id: int) -> dict[str, object]:
        deleted = inbound_repo.delete_inbound(inbound_id)
        if not deleted:
            return {"status": "not_found", "performed_side_effects": False}
        return {"status": "deleted", "performed_side_effects": True}

    @app.post("/api/inbounds/{inbound_id}/enable")
    def api_inbound_enable(inbound_id: int) -> dict[str, object]:
        ib = inbound_repo.set_inbound_enabled(inbound_id, enabled=True)
        if ib is None:
            return {"status": "not_found", "performed_side_effects": False}
        return {"status": "enabled", "id": ib.id, "performed_side_effects": True}

    @app.post("/api/inbounds/{inbound_id}/disable")
    def api_inbound_disable(inbound_id: int) -> dict[str, object]:
        ib = inbound_repo.set_inbound_enabled(inbound_id, enabled=False)
        if ib is None:
            return {"status": "not_found", "performed_side_effects": False}
        return {"status": "disabled", "id": ib.id, "performed_side_effects": True}

    # --- Client management within inbounds ---
    @app.get("/api/inbounds/{inbound_id}/clients")
    def api_inbound_clients_list(inbound_id: int) -> dict[str, object]:
        from migate.client_manager import list_clients
        clients = list_clients(inbound_repo, inbound_id)
        return {"clients": clients, "performed_side_effects": False}

    @app.post("/api/inbounds/{inbound_id}/clients/add")
    def api_inbound_client_add(
        inbound_id: int,
        email: str = Form(""),
        flow: str = Form(""),
    ) -> dict[str, object]:
        from migate.client_manager import add_client_to_inbound
        client = add_client_to_inbound(inbound_repo, inbound_id, email=email, flow=flow)
        if client is None:
            return {"status": "not_found", "performed_side_effects": False}
        return {"status": "created", "client": client, "performed_side_effects": True}

    @app.post("/api/inbounds/{inbound_id}/clients/{client_id}/remove")
    def api_inbound_client_remove(inbound_id: int, client_id: str) -> dict[str, object]:
        from migate.client_manager import remove_client_from_inbound
        removed = remove_client_from_inbound(inbound_repo, inbound_id, client_id)
        if not removed:
            return {"status": "not_found", "performed_side_effects": False}
        return {"status": "removed", "performed_side_effects": True}

    @app.post("/api/inbounds/{inbound_id}/clients/{client_id}/update")
    def api_inbound_client_update(
        inbound_id: int,
        client_id: str,
        email: str = Form(""),
    ) -> dict[str, object]:
        from migate.client_manager import update_client_in_inbound
        updated = update_client_in_inbound(inbound_repo, inbound_id, client_id, email=email)
        if not updated:
            return {"status": "not_found", "performed_side_effects": False}
        return {"status": "updated", "performed_side_effects": True}

    @app.get("/api/stats/traffic")
    def api_stats_traffic() -> dict[str, object]:
        stats = query_xray_stats(pattern="inbound>>>", reset=False)
        inbounds = inbound_repo.list_inbounds()
        result = []
        for ib in inbounds:
            up, down = stats.inbound_traffic(ib.remark)
            result.append({
                "id": ib.id,
                "remark": ib.remark,
                "protocol": ib.protocol,
                "port": ib.port,
                "enabled": ib.enabled,
                "up_bytes": up,
                "down_bytes": down,
                "total_bytes": up + down,
            })
        return {
            "inbounds": result,
            "performed_side_effects": False,
        }

    @app.get("/api/stats/traffic/reset")
    def api_stats_traffic_reset() -> dict[str, object]:
        query_xray_stats(pattern="inbound>>>", reset=True)
        return {"status": "reset", "performed_side_effects": True}

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
        return _xray_runtime_status_json(runtime_loader())

    @app.get("/api/xray/install-plan")
    def api_xray_install_plan() -> dict[str, object]:
        return _xray_install_plan_json(plan_loader())

    @app.get("/api/xray/install/dry-run")
    def api_xray_install_dry_run() -> dict[str, object]:
        return _xray_install_dry_run_json(dry_run_loader())

    @app.get("/api/xray/config/validate")
    def api_xray_config_validate() -> dict[str, object]:
        return _xray_validation_result_json(validator(config_path), target_path=config_path)

    @app.get("/api/xray/apply/dry-run")
    def api_xray_apply_dry_run() -> dict[str, object]:
        nodes = repo.list_nodes()
        enabled_nodes = [node for node in nodes if node.enabled]
        return build_xray_apply_dry_run_plan(nodes=nodes, enabled_nodes=enabled_nodes, config_path=config_path)

    @app.post("/api/xray/apply")
    def api_xray_apply(confirm: str = Form("")):
        if not _dangerous_actions_enabled(loaded_panel_auth_config):
            return JSONResponse(_dangerous_action_rejected_json(), status_code=403)
        confirmation_failure = _confirm_dangerous_action(confirm, "APPLY")
        if confirmation_failure is not None:
            return confirmation_failure
        nodes = repo.list_nodes()
        enabled_nodes = [node for node in nodes if node.enabled]
        write_xray_config(_xray_config_for_nodes(nodes), config_path)
        validation = validator(config_path)
        if validation.status != "valid":
            return {
                "status": "validation_failed",
                "target_path": str(config_path),
                "counts": {"total_nodes": len(nodes), "enabled_nodes": len(enabled_nodes)},
                "validation": _xray_validation_summary_json(validation),
                "daemon_reload": None,
                "restart": None,
                "services": None,
                "performed_side_effects": True,
            }
        reload_result = daemon_reloader()
        if reload_result.status != "success":
            return {
                "status": "daemon_reload_failed",
                "target_path": str(config_path),
                "counts": {"total_nodes": len(nodes), "enabled_nodes": len(enabled_nodes)},
                "validation": _xray_validation_summary_json(validation),
                "daemon_reload": _systemd_result_json(reload_result),
                "restart": None,
                "services": None,
                "performed_side_effects": True,
            }
        restart_result = restarter("migate-xray.service")
        services = _load_migate_systemd_services(status_loader)
        return {
            "status": "success" if restart_result.status == "success" else "restart_failed",
            "target_path": str(config_path),
            "counts": {"total_nodes": len(nodes), "enabled_nodes": len(enabled_nodes)},
            "validation": _xray_validation_summary_json(validation),
            "daemon_reload": _systemd_result_json(reload_result),
            "restart": {"service": "migate-xray.service", **_systemd_result_json(restart_result)},
            "services": _systemd_services_status_json(services),
            "performed_side_effects": True,
        }

    @app.get("/api/xray/restart/dry-run")
    def api_xray_restart_dry_run() -> dict[str, object]:
        return build_xray_restart_dry_run_plan(config_path=config_path)

    @app.post("/api/xray/restart")
    def api_xray_restart(confirm: str = Form("")):
        if not _dangerous_actions_enabled(loaded_panel_auth_config):
            return JSONResponse(_dangerous_action_rejected_json(), status_code=403)
        confirmation_failure = _confirm_dangerous_action(confirm, "RESTART")
        if confirmation_failure is not None:
            return confirmation_failure
        validation = validator(config_path)
        if validation.status != "valid":
            return {
                "status": "validation_failed",
                "target_path": str(config_path),
                "validation": _xray_validation_summary_json(validation),
                "daemon_reload": None,
                "restart": None,
                "services": None,
                "performed_side_effects": True,
            }
        reload_result = daemon_reloader()
        if reload_result.status != "success":
            return {
                "status": "daemon_reload_failed",
                "target_path": str(config_path),
                "validation": _xray_validation_summary_json(validation),
                "daemon_reload": _systemd_result_json(reload_result),
                "restart": None,
                "services": None,
                "performed_side_effects": True,
            }
        restart_result = restarter("migate-xray.service")
        services = _load_migate_systemd_services(status_loader)
        return {
            "status": "success" if restart_result.status == "success" else "restart_failed",
            "target_path": str(config_path),
            "validation": _xray_validation_summary_json(validation),
            "daemon_reload": _systemd_result_json(reload_result),
            "restart": {"service": "migate-xray.service", **_systemd_result_json(restart_result)},
            "services": _systemd_services_status_json(services),
            "performed_side_effects": True,
        }

    @app.get("/api/proxy/runtime")
    def api_proxy_runtime() -> dict[str, object]:
        return _proxy_run_result_json(proxy_loader())

    @app.get("/api/remote/readiness")
    def api_remote_readiness(
        host: str = "166.88.232.2",
        port: int = 22,
        user: str = "root",
    ) -> dict[str, object]:
        return _remote_readiness_report_json(readiness_loader(host=host, port=port, user=user))

    @app.get("/api/remote/leak-check")
    def api_remote_leak_check(
        host: str = "166.88.232.2",
        port: int = 22,
        user: str = "root",
        socks_port: int = 34501,
    ) -> dict[str, object]:
        return _remote_leak_check_report_json(
            leak_check_loader(host=host, port=port, user=user, socks_port=socks_port)
        )

    @app.get("/api/remote/rollout/dry-run")
    def api_remote_rollout_dry_run(
        host: str = "166.88.232.2",
        port: int = 22,
        user: str = "root",
        staging_dir: str = "/tmp/migate-install",
        backend: str | None = None,
    ) -> dict[str, object]:
        return _remote_rollout_plan_json(
            remote_rollout_loader(host=host, port=port, user=user, staging_dir=staging_dir, backend=backend)
        )

    @app.get("/api/proxy/service/preview")
    def api_proxy_service_preview() -> dict[str, object]:
        name = "migate-proxy.service"
        return {
            "status": "preview",
            "name": name,
            "target_path": str(unit_dir / name),
            "content": preview_proxy_service_unit(),
            "systemctl_commands_executed": [],
            "performed_side_effects": False,
        }

    @app.get("/api/systemd/units/preview")
    def api_systemd_units_preview() -> dict[str, object]:
        units = [
            {
                "name": unit.name,
                "target_path": str(unit_dir / unit.name),
                "content": unit.content,
            }
            for unit in [build_xray_unit(migate_config), build_panel_unit(migate_config)]
        ]
        units.append(
            {
                "name": "migate-proxy.service",
                "target_path": str(unit_dir / "migate-proxy.service"),
                "content": preview_proxy_service_unit(),
            }
        )
        return {
            "status": "preview",
            "target_dir": str(unit_dir),
            "units": units,
            "systemctl_commands_executed": [],
            "performed_side_effects": False,
        }

    @app.get("/api/systemd/status")
    def api_systemd_status() -> dict[str, object]:
        services = _load_migate_systemd_services(status_loader)
        return {
            "services": _systemd_services_status_json(services),
            "systemctl_commands_executed": [],
            "performed_side_effects": False,
        }

    @app.get("/api/status/summary")
    def status_summary() -> dict[str, object]:
        nodes = repo.list_nodes()
        runtime = runtime_loader()
        egress = egress_loader()
        proxy = proxy_loader()
        services = _load_migate_systemd_services(status_loader)
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
            "xray": _xray_runtime_status_json(runtime, include_output=False),
            "egress": _egress_status_report_json(egress),
            "proxy": _proxy_run_result_json(proxy),
            "services": _systemd_services_status_json(services),
            "performed_side_effects": False,
        }

    def collect_dashboard_parts() -> tuple[
        list[NodeRecord],
        XrayRuntimeStatus,
        EgressStatusReport,
        "ProxyRunResult",
        dict[str, SystemdResult],
        "RemoteReadinessReport",
        "RemoteLeakCheckReport",
        "RemoteRolloutPlan",
    ]:
        return (
            repo.list_nodes(),
            runtime_loader(),
            egress_loader(),
            proxy_loader(),
            _load_migate_systemd_services(status_loader),
            readiness_loader(host="166.88.232.2", port=22, user="root"),
            leak_check_loader(host="166.88.232.2", port=22, user="root", socks_port=34501),
            remote_rollout_loader(
                host="166.88.232.2",
                port=22,
                user="root",
                staging_dir="/tmp/migate-install",
                backend=None,
            ),
        )

    def dashboard_snapshot_from_parts(
        parts: tuple[
            list[NodeRecord],
            XrayRuntimeStatus,
            EgressStatusReport,
            ProxyRunResult,
            dict[str, SystemdResult],
            RemoteReadinessReport,
            RemoteLeakCheckReport,
            RemoteRolloutPlan,
        ]
    ) -> dict[str, object]:
        nodes, runtime, egress, proxy, services, readiness, leak_check, rollout = parts
        return _dashboard_snapshot_json(
            nodes=nodes,
            runtime=runtime,
            egress=egress,
            proxy=proxy,
            services=services,
            readiness=readiness,
            leak_check=leak_check,
            rollout=rollout,
            dangerous_actions_enabled=_dangerous_actions_enabled(loaded_panel_auth_config),
        )

    def dashboard_snapshot() -> dict[str, object]:
        return dashboard_snapshot_from_parts(collect_dashboard_parts())

    @app.get("/api/dashboard")
    def api_dashboard() -> dict[str, object]:
        return dashboard_snapshot()

    if panel_base_path != "/":
        @app.get("/")
        def root_redirect() -> RedirectResponse:
            return RedirectResponse(_panel_url(panel_base_path, "/login"), status_code=303)

    @app.get(_panel_url(panel_base_path, "/"), response_class=HTMLResponse)
    def home(request: Request):
        auth_redirect = require_panel_auth(request)
        if auth_redirect is not None:
            return auth_redirect
        parts = collect_dashboard_parts()
        snapshot = dashboard_snapshot_from_parts(parts)
        return _page_shell(
            _node_create_form_html(panel_base_path) + _dashboard_html(snapshot),
            active="dashboard", title="Dashboard", subtitle="系统状态总览",
            base_path=panel_base_path,
            user=str((loaded_panel_auth_config or {}).get("admin_user", "")),
        )

    _panel_user = str((loaded_panel_auth_config or {}).get("admin_user", ""))

    @app.get(_panel_url(panel_base_path, "/nodes"), response_class=HTMLResponse)
    def nodes_page(request: Request):
        auth_redirect = require_panel_auth(request)
        if auth_redirect is not None:
            return auth_redirect
        nodes = repo.list_nodes()
        return _page_shell(
            _node_create_form_html(panel_base_path) + _nodes_html(nodes, base_path=panel_base_path),
            active="nodes", title="节点管理", subtitle="创建和管理代理节点",
            base_path=panel_base_path, user=_panel_user,
        )

    @app.get(_panel_url(panel_base_path, "/inbounds"), response_class=HTMLResponse)
    def inbounds_page(request: Request):
        auth_redirect = require_panel_auth(request)
        if auth_redirect is not None:
            return auth_redirect
        return _page_shell(
            _inbound_create_form_html(panel_base_path) + _inbounds_html(inbound_repo.list_inbounds(), base_path=panel_base_path),
            active="inbounds", title="入站规则", subtitle="管理 Xray 入站代理规则",
            base_path=panel_base_path, user=_panel_user,
        )

    @app.get(_panel_url(panel_base_path, "/xray"), response_class=HTMLResponse)
    def xray_page(request: Request):
        auth_redirect = require_panel_auth(request)
        if auth_redirect is not None:
            return auth_redirect
        nodes = repo.list_nodes()
        runtime = runtime_loader()
        return _page_shell(
            _xray_preview_html(nodes, base_path=panel_base_path, inbounds=inbound_repo.list_inbounds())
            + _xray_runtime_status_html(runtime)
            + _xray_install_plan_html(plan_loader),
            active="xray", title="Xray 配置", subtitle="预览、校验和管理 Xray 配置",
            base_path=panel_base_path, user=_panel_user,
        )

    @app.get(_panel_url(panel_base_path, "/system"), response_class=HTMLResponse)
    def system_page(request: Request):
        auth_redirect = require_panel_auth(request)
        if auth_redirect is not None:
            return auth_redirect
        services = {n: status_loader(n) for n in MIGATE_SYSTEMD_SERVICES}
        egress = egress_loader()
        return _page_shell(
            _service_statuses_html(services) + _egress_status_report_html(egress) + _egress_dry_run_controls_html() + _systemd_preview_html(migate_config),
            active="system", title="系统设置", subtitle="服务管理、Egress 状态和系统配置",
            base_path=panel_base_path, user=_panel_user,
        )

    def remote_status_detail() -> str:
        return _remote_status_detail_html(
            readiness=readiness_loader(host="166.88.232.2", port=22, user="root"),
            leak_check=leak_check_loader(host="166.88.232.2", port=22, user="root", socks_port=34501),
            rollout=remote_rollout_loader(
                host="166.88.232.2",
                port=22,
                user="root",
                staging_dir="/tmp/migate-install",
                backend=None,
            ),
        )

    @app.post(_panel_url(panel_base_path, "/remote/status/refresh"), response_class=HTMLResponse)
    def refresh_remote_status() -> str:
        result = remote_status_detail().replace("远端状态详情", "远端状态详情已刷新", 1)
        return _action_page(result, active="system", title="远端状态", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/nodes/create"), response_class=HTMLResponse)
    def create_node(
        request: Request,
        protocol: str = Form(...),
        host: str = Form(...),
        port: int = Form(...),
        name: str = Form("MiGate Node"),
        credential: str = Form(""),
        socks5_host: str = Form(""),
        socks5_port: int | None = Form(None),
    ):
        auth_redirect = require_panel_auth(request)
        if auth_redirect is not None:
            return auth_redirect
        cleaned_name = name.strip() or "MiGate Node"
        cleaned_host = host.strip()
        cleaned_socks5_host = socks5_host.strip()
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
            socks5_host=cleaned_socks5_host,
            socks5_port=socks5_port if cleaned_socks5_host else None,
        )
        socks5_html = f"<div class=\"label\">SOCKS5 出口：{escape(node.socks5_host)}:{node.socks5_port}</div>" if node.socks5_host and node.socks5_port else "<div class=\"label\">SOCKS5 出口：默认 MiGate 本地出口</div>"
        result = f"""
  <section class="card">
    <h2>节点已生成</h2>
    <p>节点 #{node.id} 已保存。复制下面的分享链接，或复制订阅内容导入客户端。</p>
    {socks5_html}
    <div class="label">分享链接</div>
    <pre>{escape(link)}</pre>
    <div class="label">订阅内容</div>
    <pre>{escape(subscription)}</pre>
  </section>
"""
        return _action_page(result, active="nodes", title="创建节点", base_path=panel_base_path, user=_panel_user)

    def _node_action_result(title: str, message: str) -> str:
        result = f"""
  <section class="card">
    <h2>{escape(title)}</h2>
    <p>{escape(message)}</p>
  </section>
"""
        return _action_page(result, active="nodes", title="节点管理", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/nodes/{node_id}/edit"), response_class=HTMLResponse)
    def edit_node(
        node_id: int,
        protocol: str = Form(...),
        host: str = Form(...),
        port: int = Form(...),
        name: str = Form("MiGate Node"),
        credential: str = Form(""),
        socks5_host: str = Form(""),
        socks5_port: str = Form(""),
    ) -> str:
        existing = repo.get_node(node_id)
        if existing is None:
            return _node_action_result("节点不存在", f"节点 #{node_id} 不存在。")
        cleaned_name = name.strip() or "MiGate Node"
        cleaned_host = host.strip()
        cleaned_credential = _credential_for_protocol(protocol, credential.strip())
        cleaned_socks5_host = socks5_host.strip()
        cleaned_socks5_port = int(socks5_port) if cleaned_socks5_host and socks5_port.strip() else None
        link = _build_link(protocol=protocol, host=cleaned_host, port=port, name=cleaned_name, credential=cleaned_credential)
        subscription = build_base64_subscription([link])
        node = repo.update_node(
            node_id,
            protocol=protocol,
            name=cleaned_name,
            host=cleaned_host,
            port=port,
            credential=cleaned_credential,
            share_link=link,
            subscription=subscription,
            socks5_host=cleaned_socks5_host,
            socks5_port=cleaned_socks5_port,
        )
        if node is None:
            return _node_action_result("节点不存在", f"节点 #{node_id} 不存在。")
        return _node_action_result("节点已更新", f"节点 {node.name} 已更新。")

    @app.post(_panel_url(panel_base_path, "/nodes/{node_id}/enable"), response_class=HTMLResponse)
    def enable_node(node_id: int) -> str:
        node = repo.set_node_enabled(node_id, True)
        if node is None:
            return _node_action_result("节点不存在", f"节点 #{node_id} 不存在。")
        return _node_action_result("节点已启用", f"节点 {node.name} 已启用。")

    @app.post(_panel_url(panel_base_path, "/nodes/{node_id}/disable"), response_class=HTMLResponse)
    def disable_node(node_id: int) -> str:
        node = repo.set_node_enabled(node_id, False)
        if node is None:
            return _node_action_result("节点不存在", f"节点 #{node_id} 不存在。")
        return _node_action_result("节点已禁用", f"节点 {node.name} 已禁用。")

    @app.post(_panel_url(panel_base_path, "/nodes/{node_id}/delete"), response_class=HTMLResponse)
    def delete_node(node_id: int) -> str:
        node = repo.delete_node(node_id)
        if node is None:
            return _node_action_result("节点不存在", f"节点 #{node_id} 不存在。")
        return _node_action_result("节点已删除", f"节点 {node.name} 已删除。")

    def _inbound_action_result(title: str, message: str) -> str:
        result = f"""
  <section class="card">
    <h2>{escape(title)}</h2>
    <p>{escape(message)}</p>
  </section>
"""
        return _action_page(result, active="inbounds", title="入站规则", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/inbounds/create"), response_class=HTMLResponse)
    def create_inbound(
        remark: str = Form(...),
        protocol: str = Form(...),
        port: int = Form(...),
        listen: str = Form("0.0.0.0"),
        settings: str = Form("{}"),
        stream_settings: str = Form("{}"),
    ) -> str:
        ib = inbound_repo.create_inbound(
            remark=remark, protocol=protocol, port=port, listen=listen,
            settings=settings, stream_settings=stream_settings,
        )
        return _inbound_action_result("入站已创建", f"入站 #{ib.id} ({ib.remark}) 已创建，端口 {ib.port}。")

    @app.post(_panel_url(panel_base_path, "/inbounds/{inbound_id}/edit"), response_class=HTMLResponse)
    def edit_inbound(
        inbound_id: int,
        remark: str = Form(...),
        protocol: str = Form(...),
        port: int = Form(...),
        listen: str = Form("0.0.0.0"),
        settings: str = Form("{}"),
        stream_settings: str = Form("{}"),
    ) -> str:
        ib = inbound_repo.update_inbound(
            inbound_id, remark=remark, protocol=protocol, port=port, listen=listen,
            settings=settings, stream_settings=stream_settings,
        )
        if ib is None:
            return _inbound_action_result("入站不存在", f"入站 #{inbound_id} 不存在。")
        return _inbound_action_result("入站已更新", f"入站 #{ib.id} ({ib.remark}) 已更新。")

    @app.post(_panel_url(panel_base_path, "/inbounds/{inbound_id}/enable"), response_class=HTMLResponse)
    def enable_inbound(inbound_id: int) -> str:
        ib = inbound_repo.set_inbound_enabled(inbound_id, enabled=True)
        if ib is None:
            return _inbound_action_result("入站不存在", f"入站 #{inbound_id} 不存在。")
        return _inbound_action_result("入站已启用", f"入站 #{ib.id} ({ib.remark}) 已启用。")

    @app.post(_panel_url(panel_base_path, "/inbounds/{inbound_id}/disable"), response_class=HTMLResponse)
    def disable_inbound(inbound_id: int) -> str:
        ib = inbound_repo.set_inbound_enabled(inbound_id, enabled=False)
        if ib is None:
            return _inbound_action_result("入站不存在", f"入站 #{inbound_id} 不存在。")
        return _inbound_action_result("入站已禁用", f"入站 #{ib.id} ({ib.remark}) 已禁用。")

    @app.post(_panel_url(panel_base_path, "/inbounds/{inbound_id}/delete"), response_class=HTMLResponse)
    def delete_inbound(inbound_id: int) -> str:
        ib = inbound_repo.get_inbound(inbound_id)
        if ib is None:
            return _inbound_action_result("入站不存在", f"入站 #{inbound_id} 不存在。")
        inbound_repo.delete_inbound(inbound_id)
        return _inbound_action_result("入站已删除", f"入站 #{ib.id} ({ib.remark}) 已删除。")

    @app.post(_panel_url(panel_base_path, "/xray/config/save"), response_class=HTMLResponse)
    def save_xray_config() -> str:
        nodes = repo.list_nodes()
        written = write_xray_config(_xray_config_for_nodes(nodes, inbounds=inbound_repo.list_inbounds()), config_path)
        result = f"""
  <section class="card">
    <h2>Xray 配置已保存</h2>
    <p>配置已写入：{escape(str(written))}</p>
    <p>当前步骤仅写盘，不会自动重载 Xray 服务。</p>
  </section>
"""
        return _action_page(result, active="xray", title="Xray 配置", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/xray/config/validate"), response_class=HTMLResponse)
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
        return _action_page(result, active="xray", title="Xray 配置", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/xray/apply"), response_class=HTMLResponse)
    def apply_current_nodes_to_xray(confirm: str = Form("")):
        if not _dangerous_actions_enabled(loaded_panel_auth_config):
            return HTMLResponse(
                _action_page(_dangerous_action_rejected_html(), active="xray", title="Xray 配置", base_path=panel_base_path, user=_panel_user),
                status_code=403,
            )
        if confirm != "APPLY":
            return HTMLResponse(
                _action_page(_dangerous_action_confirmation_required_html("APPLY"), active="xray", title="Xray 配置", base_path=panel_base_path, user=_panel_user),
                status_code=403,
            )
        nodes = repo.list_nodes()
        written = write_xray_config(_xray_config_for_nodes(nodes, inbounds=inbound_repo.list_inbounds()), config_path)
        validation = validator(config_path)
        if validation.status != "valid":
            result = f"""
  <section class="card">
    <h2>当前节点配置未应用</h2>
    <p>已生成并保存 Xray 配置：{escape(str(written))}</p>
    <p>配置校验失败，未执行服务重载或重启。</p>
    <p>校验状态：{escape(validation.status)}</p>
    <pre>{escape(_result_output(validation))}</pre>
  </section>
"""
            return _action_page(result, active="xray", title="Xray 配置", base_path=panel_base_path, user=_panel_user)
        reload_result = daemon_reloader()
        if reload_result.status != "success":
            result = f"""
  <section class="card">
    <h2>当前节点配置未完全应用</h2>
    <p>已生成并保存 Xray 配置：{escape(str(written))}</p>
    <p>配置校验通过，但 systemd daemon-reload 失败，Xray 重启已跳过。</p>
{_xray_control_diagnostics_html(validation=validation, reload_result=reload_result)}
  </section>
"""
            return _action_page(result, active="xray", title="Xray 配置", base_path=panel_base_path, user=_panel_user)
        restart_result = restarter("migate-xray.service")
        if restart_result.status != "success":
            result = f"""
  <section class="card">
    <h2>当前节点配置未完全应用</h2>
    <p>已生成并保存 Xray 配置：{escape(str(written))}</p>
    <p>配置校验和 systemd daemon-reload 已通过，但 Xray 重启失败。</p>
{_xray_control_diagnostics_html(validation=validation, reload_result=reload_result, restart_result=restart_result, restart_label="Xray 重启失败")}
  </section>
"""
            return _action_page(result, active="xray", title="操作结果", base_path=panel_base_path, user=_panel_user)
        result = f"""
  <section class="card">
    <h2>当前节点配置已应用</h2>
    <p>生成并保存 Xray 配置：{escape(str(written))}</p>
{_xray_control_diagnostics_html(validation=validation, reload_result=reload_result, restart_result=restart_result)}
  </section>
"""
        return _action_page(result, active="xray", title="操作结果", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/xray/restart"), response_class=HTMLResponse)
    def restart_xray_after_validation(confirm: str = Form("")):
        if not _dangerous_actions_enabled(loaded_panel_auth_config):
            return HTMLResponse(
                _action_page(_dangerous_action_rejected_html(), active="xray", title="Xray 配置", base_path=panel_base_path, user=_panel_user),
                status_code=403,
            )
        if confirm != "RESTART":
            return HTMLResponse(
                _action_page(_dangerous_action_confirmation_required_html("RESTART"), active="xray", title="Xray 配置", base_path=panel_base_path, user=_panel_user),
                status_code=403,
            )
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
            return _action_page(result, active="xray", title="操作结果", base_path=panel_base_path, user=_panel_user)

        reload_result = daemon_reloader()
        if reload_result.status != "success":
            result = f"""
  <section class="card">
    <h2>Xray 未重启</h2>
    <p>配置校验通过，但 daemon-reload 失败，未执行 Xray 重启。</p>
{_xray_control_diagnostics_html(validation=validation, reload_result=reload_result)}
  </section>
"""
            return _action_page(result, active="xray", title="操作结果", base_path=panel_base_path, user=_panel_user)
        restart_result = restarter("migate-xray.service")
        if restart_result.status != "success":
            result = f"""
  <section class="card">
    <h2>Xray 未重启</h2>
    <p>配置校验和 systemd daemon-reload 已通过，但 Xray 重启失败。</p>
{_xray_control_diagnostics_html(validation=validation, reload_result=reload_result, restart_result=restart_result, restart_label="Xray 重启失败")}
  </section>
"""
            return _action_page(result, active="xray", title="操作结果", base_path=panel_base_path, user=_panel_user)
        result = f"""
  <section class="card">
    <h2>Xray 重启已执行</h2>
    <p>配置校验通过后，已执行服务重载并重启 migate-xray.service。</p>
{_xray_control_diagnostics_html(validation=validation, reload_result=reload_result, restart_result=restart_result)}
  </section>
"""
        return _action_page(result, active="xray", title="操作结果", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/systemd/units/save"), response_class=HTMLResponse)
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
        return _action_page(result, active="xray", title="操作结果", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/systemd/status/refresh"), response_class=HTMLResponse)
    def refresh_systemd_status() -> str:
        services = {n: status_loader(n) for n in MIGATE_SYSTEMD_SERVICES}
        result = _service_statuses_html(services, refreshed=True) + _systemd_preview_html(migate_config)
        return _action_page(result, active="system", title="系统设置", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/egress/status/refresh"), response_class=HTMLResponse)
    def refresh_egress_status() -> str:
        egress = egress_loader()
        result = _egress_status_report_html(egress, refreshed=True) + _systemd_preview_html(migate_config)
        return _action_page(result, active="system", title="系统设置", base_path=panel_base_path, user=_panel_user)

    @app.get("/api/egress/status")
    def api_egress_status() -> dict[str, object]:
        return _egress_status_report_json(egress_loader())

    @app.get("/api/egress/up/dry-run")
    def api_egress_up_dry_run() -> dict[str, object]:
        return _egress_lifecycle_result_json(egress_up_loader())

    @app.get("/api/egress/down/dry-run")
    def api_egress_down_dry_run() -> dict[str, object]:
        return _egress_lifecycle_result_json(egress_down_loader())

    @app.post(_panel_url(panel_base_path, "/egress/up/dry-run"), response_class=HTMLResponse)
    def dry_run_egress_up() -> str:
        result = _egress_status_report_html(egress_loader()) + _egress_dry_run_result_html("Egress Up dry-run 结果", egress_up_loader)
        return _action_page(result, active="system", title="系统设置", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/egress/down/dry-run"), response_class=HTMLResponse)
    def dry_run_egress_down() -> str:
        result = _egress_status_report_html(egress_loader()) + _egress_dry_run_result_html("Egress Down dry-run 结果", egress_down_loader)
        return _action_page(result, active="system", title="系统设置", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/xray/runtime/refresh"), response_class=HTMLResponse)
    def refresh_xray_runtime() -> str:
        result = _xray_runtime_status_html(runtime_loader(), refreshed=True)
        return _action_page(result, active="xray", title="Xray 配置", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/xray/install-plan/refresh"), response_class=HTMLResponse)
    def refresh_xray_install_plan() -> str:
        result = _xray_install_plan_html(plan_loader, refreshed=True)
        return _action_page(result, active="xray", title="Xray 配置", base_path=panel_base_path, user=_panel_user)

    @app.post(_panel_url(panel_base_path, "/xray/install/dry-run"), response_class=HTMLResponse)
    def dry_run_xray_install() -> str:
        result = _xray_install_dry_run_html(dry_run_loader)
        return _action_page(result, active="xray", title="Xray 配置", base_path=panel_base_path, user=_panel_user)

    return app
