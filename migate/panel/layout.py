"""Shared layout template for MiGate panel pages."""

from __future__ import annotations

from html import escape


NAV_ITEMS = [
    ("/migate/", "dashboard", "📊", "Dashboard"),
    ("/migate/nodes", "nodes", "🔗", "节点管理"),
    ("/migate/inbounds", "inbounds", "📡", "入站规则"),
    ("/migate/xray", "xray", "⚙️", "Xray 配置"),
    ("/migate/system", "system", "🛠️", "系统设置"),
]


def _nav_html(active: str, base_path: str = "/migate") -> str:
    items = []
    for href, key, icon, label in NAV_ITEMS:
        full_href = f"{base_path.rstrip('/')}{href[len('/migate'):]}".rstrip("/") or "/"
        cls = " active" if key == active else ""
        items.append(
            f'<a href="{escape(full_href)}" class="{cls}">'
            f'<span class="icon">{icon}</span>{escape(label)}</a>'
        )
    return "\n".join(items)


def layout(
    *,
    active: str,
    title: str,
    subtitle: str,
    content: str,
    base_path: str = "/migate",
    flash: str = "",
    flash_type: str = "ok",
    user: str = "",
) -> str:
    """Wrap page content in the shared sidebar layout."""
    bp = base_path.rstrip("/") or "/"
    logout_href = f"{bp}/logout"
    static_css = f"{bp}/static/style.css"

    flash_html = ""
    if flash:
        flash_html = f'<div class="toast toast-{escape(flash_type)}">{escape(flash)}</div>'

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)} - MiGate</title>
  <link rel="stylesheet" href="{escape(static_css)}">
</head>
<body>
<button class="sidebar-toggle" onclick="document.querySelector('.sidebar').classList.toggle('open')">☰</button>
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-brand">
      <h1>MiGate</h1>
      <small>Xray 智能出站网关</small>
    </div>
    <nav class="sidebar-nav">
      {_nav_html(active, bp)}
    </nav>
    <div class="sidebar-footer">
      {"<span>" + escape(user) + "</span> · " if user else ""}
      <a href="{escape(logout_href)}">退出登录</a>
    </div>
  </aside>
  <main class="main-content">
    <div class="page-header">
      <h2>{escape(title)}</h2>
      <p>{escape(subtitle)}</p>
    </div>
    {flash_html}
    {content}
  </main>
</div>
<script>
// Close sidebar on outside click (mobile)
document.addEventListener('click', function(e) {{
  var sb = document.querySelector('.sidebar');
  var btn = document.querySelector('.sidebar-toggle');
  if (sb.classList.contains('open') && !sb.contains(e.target) && !btn.contains(e.target)) {{
    sb.classList.remove('open');
  }}
}});
</script>
<script>
function copyText(el){{ navigator.clipboard.writeText(el.dataset.text || el.textContent); el.textContent='已复制 ✓'; setTimeout(()=>el.textContent=el.dataset.orig||'复制',1500); }}
document.addEventListener('submit', function(e) {{
  var form = e.target;
  if (form.action && form.action.indexOf('/delete') !== -1) {{
    if (!confirm('确定要删除吗？')) {{ e.preventDefault(); }}
  }}
}});
document.addEventListener('change', function(e) {{
  if (e.target.classList.contains('toggle-checkbox')) {{
    var url = e.target.dataset.url;
    if (url) {{ fetch(url, {{method:'POST',credentials:'same-origin'}}).then(function(){{ location.reload(); }}); }}
  }}
}});
</script>
</body>
</html>"""
