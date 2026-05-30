from __future__ import annotations

from html import escape
from uuid import uuid4

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse

from migate.xray.links import build_shadowsocks_link, build_trojan_link, build_vless_link
from migate.xray.subscription import build_base64_subscription


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
    @media (max-width: 720px) {{ form {{ grid-template-columns: 1fr; }} .hero {{ flex-direction:column; }} }}
  </style>
</head>
<body>
<main>
{body}
</main>
</body>
</html>"""


def _home_body(result_html: str = "") -> str:
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
      <button type="submit">生成节点</button>
    </form>
  </section>

  {result_html}
"""


def _build_link(protocol: str, host: str, port: int, name: str, credential: str) -> str:
    if protocol == "vless":
        return build_vless_link(uuid=credential or str(uuid4()), host=host, port=port, name=name)
    if protocol == "trojan":
        return build_trojan_link(password=credential or uuid4().hex, host=host, port=port, name=name)
    if protocol == "shadowsocks":
        return build_shadowsocks_link(method="aes-128-gcm", password=credential or uuid4().hex, host=host, port=port, name=name)
    raise ValueError(f"unsupported protocol: {protocol}")


def create_app() -> FastAPI:
    app = FastAPI(title="MiGate Panel")

    @app.get("/", response_class=HTMLResponse)
    def home() -> str:
        return _page_shell(_home_body())

    @app.post("/nodes/create", response_class=HTMLResponse)
    def create_node(
        protocol: str = Form(...),
        host: str = Form(...),
        port: int = Form(...),
        name: str = Form("MiGate Node"),
        credential: str = Form(""),
    ) -> str:
        link = _build_link(protocol=protocol, host=host.strip(), port=port, name=name.strip() or "MiGate Node", credential=credential.strip())
        subscription = build_base64_subscription([link])
        result = f"""
  <section class="card">
    <h2>节点已生成</h2>
    <p>复制下面的分享链接，或复制订阅内容导入客户端。</p>
    <div class="label">分享链接</div>
    <pre>{escape(link)}</pre>
    <div class="label">订阅内容</div>
    <pre>{escape(subscription)}</pre>
  </section>
"""
        return _page_shell(_home_body(result))

    return app
