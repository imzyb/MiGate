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
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="stylesheet" href="{escape(static_css)}">
</head>
<body data-base-path="{escape(bp)}">
<button class="sidebar-toggle" onclick="document.querySelector('.sidebar').classList.toggle('open')" aria-label="Toggle menu">
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="5" x2="17" y2="5"/><line x1="3" y1="10" x2="17" y2="10"/><line x1="3" y1="15" x2="17" y2="15"/></svg>
</button>
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
      <form method="post" action="{escape(logout_href)}" style="display:inline;"><button type="submit" style="background:none;border:none;color:inherit;cursor:pointer;padding:0;font:inherit;">退出登录</button></form>
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
<!-- Loading overlay -->
<div class="loading-overlay" id="loading-overlay">
  <div class="spinner"></div>
</div>
<!-- Toast container (JS-driven notifications) -->
<div class="toast-container" id="toast-container"></div>
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
function showToast(msg, type) {{
  var container = document.getElementById('toast-container');
  var t = document.createElement('div');
  t.className = 'toast ' + (type === 'toast-err' || type === 'toast-error' ? 'toast-error' : 'toast-ok');
  t.textContent = msg;
  container.appendChild(t);
  setTimeout(function() {{
    t.classList.add('removing');
    setTimeout(function() {{ t.remove(); }}, 300);
  }}, 2500);
}}
function copyText(el){{ navigator.clipboard.writeText(el.dataset.text || el.textContent); showToast('已复制'); setTimeout(function(){{el.textContent=el.dataset.orig||'复制';}},1500); }}
document.addEventListener('submit', function(e) {{
  var form = e.target;
  if (form.action && form.action.indexOf('/delete') !== -1) {{
    if (!confirm('确定要删除吗？')) {{ e.preventDefault(); return; }}
    var fd = new FormData(form);
    fetch(form.action, {{method:'POST', body:fd, credentials:'same-origin'}}).then(function(r) {{
      if (r.ok) {{ showToast('已删除'); setTimeout(function(){{location.reload();}},800); }}
      else {{ showToast('删除失败','toast-err'); }}
    }}).catch(function(){{ showToast('删除失败','toast-err'); }});
    e.preventDefault();
  }}
}});
document.addEventListener('change', function(e) {{
  if (e.target.classList.contains('toggle-checkbox')) {{
    var url = e.target.dataset.url;
    if (url) {{ fetch(url, {{method:'POST',credentials:'same-origin'}}).then(function(r){{ if(r.ok) showToast('状态已更新'); else showToast('操作失败','toast-err'); }}).catch(function(){{ showToast('操作失败','toast-err'); }}); }}
  }}
}});
async function addClient(e,inboundId,url){{
  e.preventDefault();
  const form=e.target;const data=new FormData(form);
  try{{
    const r=await fetch(url,{{method:'POST',body:data}});
    const j=await r.json();
    if(j.status==='created'){{showToast('客户端已添加');setTimeout(function(){{location.reload();}},500);}}
    else showToast(j.status||'添加失败','toast-err');
  }}catch(err){{showToast('网络错误','toast-err');}}
}}
async function removeClient(inboundId,clientId,btn){{
  if(!confirm('确定删除此客户端？'))return;
  const bp=document.body.dataset.basePath||'/';
  try{{
    const r=await fetch(bp+'api/inbounds/'+inboundId+'/clients/'+clientId+'/remove',{{method:'POST'}});
    const j=await r.json();
    if(j.status==='removed'){{showToast('客户端已删除');btn.closest('.client-row').remove();}}
    else showToast('删除失败','toast-err');
  }}catch(err){{showToast('网络错误','toast-err');}}
}}
async function saveClientLimits(e,inboundId,email){{
  e.preventDefault();
  const form=e.target;const data=new FormData(form);
  const bp=document.body.dataset.basePath||'/';
  try{{
    const r=await fetch(bp+'api/inbounds/'+inboundId+'/clients/'+encodeURIComponent(email)+'/limits',{{method:'POST',body:data}});
    const j=await r.json();
    if(j.status==='ok'){{showToast('限额已保存');setTimeout(function(){{location.reload();}},500);}}
    else showToast(j.detail||'保存失败','toast-err');
  }}catch(err){{showToast('网络错误','toast-err');}}
}}
</script>
<div id="qr-modal" style="display:none;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.7);align-items:center;justify-content:center;" onclick="if(event.target===this)this.style.display='none'">
  <div style="background:#161b22;padding:24px;border-radius:12px;text-align:center;max-width:320px;border:1px solid #30363d;">
    <div style="margin-bottom:12px;font-weight:600;">扫码导入</div>
    <img id="qr-img" src="" alt="QR Code" style="width:200px;height:200px;background:#fff;padding:8px;border-radius:8px;">
    <div style="margin-top:12px;"><button class="btn btn-sm" onclick="document.getElementById('qr-modal').style.display='none'">关闭</button></div>
  </div>
</div>
<script>
function showQR(text){{var m=document.getElementById('qr-modal');var img=document.getElementById('qr-img');img.src='https://api.qrserver.com/v1/create-qr-code/?size=200x200&data='+encodeURIComponent(text);m.style.display='flex';}}
</script>
</body>
</html>"""
