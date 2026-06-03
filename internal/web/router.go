package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/xray"
)

type Store interface {
	ListInbounds(ctx context.Context) ([]db.Inbound, error)
	CreateInbound(ctx context.Context, params db.CreateInboundParams) (db.Inbound, error)
	CreateClient(ctx context.Context, params db.CreateClientParams) (db.Client, error)
}

type XrayController interface {
	Status(ctx context.Context) XrayStatus
	Apply(ctx context.Context) XrayApplyResult
}

type XrayStatus struct {
	Service          string   `json:"service"`
	Status           string   `json:"status"`
	Managed          bool     `json:"managed"`
	CommandsExecuted []string `json:"commands_executed"`
}

type XrayApplyResult struct {
	Status           string   `json:"status"`
	Service          string   `json:"service"`
	CommandsExecuted []string `json:"commands_executed"`
}

type defaultXrayController struct{}

func (defaultXrayController) Status(ctx context.Context) XrayStatus {
	return XrayStatus{Service: "xray", Status: "unknown", Managed: false, CommandsExecuted: []string{}}
}

func (defaultXrayController) Apply(ctx context.Context) XrayApplyResult {
	return XrayApplyResult{Status: "unavailable", Service: "xray", CommandsExecuted: []string{}}
}

type routerConfig struct {
	store          Store
	xrayController XrayController
}

type Option func(*routerConfig)

func WithStore(store Store) Option {
	return func(cfg *routerConfig) {
		cfg.store = store
	}
}

func WithXrayController(controller XrayController) Option {
	return func(cfg *routerConfig) {
		cfg.xrayController = controller
	}
}

func NewRouter(options ...Option) http.Handler {
	cfg := routerConfig{xrayController: defaultXrayController{}}
	for _, option := range options {
		option(&cfg)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", panelHandler)
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/inbounds", inboundsHandler(cfg.store))
	mux.HandleFunc("/api/inbounds/", inboundChildrenHandler(cfg.store))
	mux.HandleFunc("/api/xray/config", xrayConfigHandler(cfg.store))
	mux.HandleFunc("/api/xray/status", xrayStatusHandler(cfg.xrayController))
	mux.HandleFunc("/api/xray/apply", xrayApplyHandler(cfg.xrayController))
	mux.HandleFunc("/sub/", subscriptionHandler(cfg.store))
	return mux
}

func panelHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(panelHTML))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok","mode":"go-lite"}`))
}

func inboundsHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listInbounds(w, r, store)
		case http.MethodPost:
			createInbound(w, r, store)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func listInbounds(w http.ResponseWriter, r *http.Request, store Store) {
	inbounds := []db.Inbound{}
	if store != nil {
		loaded, err := store.ListInbounds(r.Context())
		if err != nil {
			http.Error(w, `{"error":"list_inbounds_failed"}`, http.StatusInternalServerError)
			return
		}
		inbounds = loaded
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"inbounds": inbounds})
}

func createInbound(w http.ResponseWriter, r *http.Request, store Store) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var payload db.CreateInboundParams
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	created, err := store.CreateInbound(r.Context(), payload)
	if err != nil {
		http.Error(w, `{"error":"unsupported_protocol"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func inboundChildrenHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/inbounds/")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) != 2 || parts[1] != "clients" {
			http.NotFound(w, r)
			return
		}
		inboundID, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || inboundID <= 0 {
			http.NotFound(w, r)
			return
		}
		createClient(w, r, store, inboundID)
	}
}

func createClient(w http.ResponseWriter, r *http.Request, store Store, inboundID int64) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	if !inboundExists(r.Context(), store, inboundID) {
		http.Error(w, `{"error":"inbound_not_found"}`, http.StatusNotFound)
		return
	}
	var payload struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	created, err := store.CreateClient(r.Context(), db.CreateClientParams{InboundID: inboundID, Email: payload.Email})
	if err != nil {
		http.Error(w, `{"error":"create_client_failed"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func inboundExists(ctx context.Context, store Store, inboundID int64) bool {
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		return false
	}
	for _, inbound := range inbounds {
		if inbound.ID == inboundID {
			return true
		}
	}
	return false
}

func xrayConfigHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		inbounds := []db.Inbound{}
		if store != nil {
			loaded, err := store.ListInbounds(r.Context())
			if err != nil {
				http.Error(w, `{"error":"list_inbounds_failed"}`, http.StatusInternalServerError)
				return
			}
			inbounds = loaded
		}
		config, err := xray.BuildConfig(inbounds)
		if err != nil {
			http.Error(w, `{"error":"build_xray_config_failed"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(config)
	}
}

func xrayStatusHandler(controller XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if controller == nil {
			controller = defaultXrayController{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controller.Status(r.Context()))
	}
}

func xrayApplyHandler(controller XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			Confirm            bool `json:"confirm"`
			AllowSystemChanges bool `json:"allow_system_changes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
			return
		}
		if !payload.Confirm || !payload.AllowSystemChanges {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "confirmation_required", "commands_executed": []string{}})
			return
		}
		if controller == nil {
			controller = defaultXrayController{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controller.Apply(r.Context()))
	}
}

func subscriptionHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if store == nil {
			http.NotFound(w, r)
			return
		}
		token := strings.Trim(strings.TrimPrefix(r.URL.Path, "/sub/"), "/")
		if token == "" {
			http.NotFound(w, r)
			return
		}
		inbounds, err := store.ListInbounds(r.Context())
		if err != nil {
			http.Error(w, `{"error":"list_inbounds_failed"}`, http.StatusInternalServerError)
			return
		}
		for _, inbound := range inbounds {
			if !inbound.Enabled {
				continue
			}
			for _, client := range inbound.Clients {
				if !client.Enabled || client.UUID != token {
					continue
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = w.Write([]byte(shareLink(r.Host, inbound, client)))
				return
			}
		}
		http.NotFound(w, r)
	}
}

func shareLink(host string, inbound db.Inbound, client db.Client) string {
	if host == "" {
		host = "SERVER_IP"
	}
	return inbound.Protocol + "://" + client.UUID + "@" + host + ":" + strconv.Itoa(inbound.Port) + "?type=" + inbound.Network + "&security=" + inbound.Security + "#" + client.Email
}

const panelHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MiGate Go Lite</title>
  <style>
    :root { color-scheme: dark; --bg:#070b14; --card:#101827; --muted:#94a3b8; --text:#e5eefb; --line:#223047; --accent:#4f8cff; --accent2:#22c55e; --danger:#ef4444; }
    * { box-sizing: border-box; }
    body { margin:0; min-height:100vh; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: radial-gradient(circle at 20% 10%, rgba(79,140,255,.24), transparent 36%), radial-gradient(circle at 80% 0%, rgba(34,197,94,.14), transparent 30%), var(--bg); color:var(--text); }
    .shell { display:grid; grid-template-columns: 240px 1fr; min-height:100vh; }
    aside { border-right:1px solid var(--line); padding:24px 18px; background:rgba(7,11,20,.74); backdrop-filter: blur(18px); }
    .brand { font-size:24px; font-weight:800; letter-spacing:.4px; margin-bottom:4px; }
    .brand span { color:var(--accent); }
    .subtitle { color:var(--muted); font-size:13px; margin-bottom:28px; }
    nav a { display:block; color:var(--text); text-decoration:none; padding:11px 12px; border-radius:12px; margin:6px 0; border:1px solid transparent; }
    nav a.active, nav a:hover { background:rgba(79,140,255,.13); border-color:rgba(79,140,255,.25); }
    main { padding:28px; }
    .hero { display:flex; justify-content:space-between; gap:20px; align-items:flex-start; margin-bottom:22px; }
    h1 { margin:0 0 8px; font-size:32px; }
    p { color:var(--muted); line-height:1.6; }
    .badge { display:inline-flex; align-items:center; gap:8px; padding:8px 12px; border-radius:999px; background:rgba(34,197,94,.12); color:#bbf7d0; border:1px solid rgba(34,197,94,.24); font-size:13px; }
    .grid { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:16px; margin-bottom:18px; }
    .card { background:linear-gradient(180deg, rgba(16,24,39,.92), rgba(12,18,30,.92)); border:1px solid var(--line); border-radius:18px; padding:18px; box-shadow:0 18px 60px rgba(0,0,0,.22); }
    .metric { font-size:26px; font-weight:800; margin-top:10px; }
    .section-title { font-size:18px; font-weight:750; margin:0 0 12px; }
    .protocols { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }
    .protocol { padding:14px; border-radius:16px; background:rgba(148,163,184,.08); border:1px solid rgba(148,163,184,.14); }
    .protocol strong { display:block; margin-bottom:6px; }
    .actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:14px; }
    button { background:linear-gradient(135deg,var(--accent),#7c3aed); border:none; color:white; padding:10px 14px; border-radius:12px; font-weight:700; cursor:pointer; }
    button.secondary { background:rgba(148,163,184,.12); border:1px solid var(--line); }
    form { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:10px; margin:16px 0; }
    input, select { width:100%; border:1px solid var(--line); background:rgba(7,11,20,.72); color:var(--text); border-radius:12px; padding:10px 12px; }
    .list { display:grid; gap:10px; margin-top:14px; }
    .row { display:grid; grid-template-columns:1.2fr .8fr .8fr .8fr .8fr; gap:10px; align-items:center; padding:12px; border:1px solid rgba(148,163,184,.14); border-radius:14px; background:rgba(148,163,184,.07); }
    .muted { color:var(--muted); }
    .error { color:#fecaca; }
    @media (max-width: 900px) { .shell { grid-template-columns:1fr; } aside { border-right:0; border-bottom:1px solid var(--line); } .grid,.protocols { grid-template-columns:1fr 1fr; } }
    @media (max-width: 560px) { .grid,.protocols { grid-template-columns:1fr; } main { padding:18px; } }
  </style>
</head>
<body>
  <div class="shell">
    <aside>
      <div class="brand">MiGate <span>Go Lite</span></div>
      <div class="subtitle">轻量面板风格单二进制面板</div>
      <nav>
        <a class="active" href="/">概览</a>
        <a href="/#inbounds">入站</a>
        <a href="/#clients">客户端</a>
        <a href="/#subscriptions">订阅</a>
        <a href="/#xray">Xray</a>
      </nav>
    </aside>
    <main>
      <section class="hero">
        <div>
          <h1>MiGate Go Lite</h1>
          <p>从零重写为轻量 Go 单二进制：SQLite、本地 Xray 配置、订阅链接与核心面板能力。</p>
        </div>
        <div class="badge">● 服务在线</div>
      </section>
      <section class="grid" aria-label="概览指标">
        <div class="card"><div>入站</div><div id="inbound-count" class="metric">0</div><p>VLESS / VMess / Trojan / Shadowsocks</p></div>
        <div class="card"><div>客户端</div><div id="client-count" class="metric">0</div><p>按 inbound 管理账号</p></div>
        <div class="card"><div>订阅</div><div class="metric">Ready</div><p>Clash / 通用链接规划中</p></div>
        <div class="card"><div>Xray</div><div class="metric">Direct</div><p>默认 freedom 出站</p></div>
      </section>
      <section id="inbounds" class="card">
        <h2 class="section-title">核心协议</h2>
        <div class="protocols">
          <div class="protocol"><strong>VLESS</strong><span>Reality / TLS 入站</span></div>
          <div class="protocol"><strong>VMess</strong><span>WebSocket / TLS 兼容</span></div>
          <div class="protocol"><strong>Trojan</strong><span>TLS 节点支持</span></div>
          <div class="protocol"><strong>Shadowsocks</strong><span>轻量转发协议</span></div>
        </div>
        <div class="actions">
          <button>新增入站</button>
          <button class="secondary">生成 Xray 配置</button>
          <button class="secondary">查看订阅</button>
        </div>
        <form id="inbound-form">
          <input name="remark" placeholder="备注，例如 主入口" required>
          <select name="protocol">
            <option value="vless">VLESS</option>
            <option value="vmess">VMess</option>
            <option value="trojan">Trojan</option>
            <option value="shadowsocks">Shadowsocks</option>
          </select>
          <input name="port" type="number" min="1" max="65535" placeholder="端口" required>
          <input name="network" value="tcp" placeholder="network">
          <select name="security">
            <option value="none">none</option>
            <option value="tls">tls</option>
            <option value="reality">reality</option>
          </select>
          <button type="submit">保存入站</button>
        </form>
        <div id="inbound-list" class="list muted">正在加载入站...</div>
      </section>
    </main>
  </div>
  <script>
    const inboundList = document.getElementById('inbound-list');
    const inboundCount = document.getElementById('inbound-count');
    const clientCount = document.getElementById('client-count');

    function renderInbounds(inbounds) {
      inboundCount.textContent = String(inbounds.length);
      clientCount.textContent = String(inbounds.reduce((total, inbound) => total + (inbound.clients || []).length, 0));
      if (inbounds.length === 0) {
        inboundList.className = 'list muted';
        inboundList.textContent = '暂无入站，先创建一个 VLESS / VMess / Trojan / Shadowsocks 节点。';
        return;
      }
      inboundList.className = 'list';
      inboundList.innerHTML = inbounds.map((inbound) => '<div class="row"><strong>' + escapeHtml(inbound.remark || '-') + '</strong><span>' + escapeHtml(inbound.protocol) + '</span><span>:' + inbound.port + '</span><span>' + escapeHtml(inbound.network || 'tcp') + '/' + escapeHtml(inbound.security || 'none') + '</span><span>' + ((inbound.clients || []).length) + ' 客户端</span></div>').join('');
    }

    function escapeHtml(value) {
      return String(value || '').replace(/[&<>"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[char]));
    }

    async function loadInbounds() {
      const response = await fetch('/api/inbounds');
      const data = await response.json();
      renderInbounds(data.inbounds || []);
    }

    document.getElementById('inbound-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      const payload = Object.fromEntries(form.entries());
      payload.port = Number(payload.port);
      const response = await fetch('/api/inbounds', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
      if (!response.ok) {
        inboundList.className = 'list error';
        inboundList.textContent = '创建失败：' + await response.text();
        return;
      }
      event.currentTarget.reset();
      await loadInbounds();
    });

    loadInbounds();
  </script>
</body>
</html>`
