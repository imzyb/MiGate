package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/xray"
)

type Store interface {
	ListInbounds(ctx context.Context) ([]db.Inbound, error)
	CreateInbound(ctx context.Context, params db.CreateInboundParams) (db.Inbound, error)
	CreateClient(ctx context.Context, params db.CreateClientParams) (db.Client, error)
	DeleteInbound(ctx context.Context, id int64) error
	DeleteClient(ctx context.Context, id int64) error
	UpdateInbound(ctx context.Context, id int64, params db.UpdateInboundParams) (db.Inbound, error)
	UpdateClient(ctx context.Context, id int64, params db.UpdateClientParams) (db.Client, error)
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
	authEnabled    bool
	authUsername   string
	authPassword   string
	sessionSecret  []byte
	configDir      string
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

func WithConfigDir(dir string) Option {
	return func(cfg *routerConfig) {
		cfg.configDir = dir
	}
}

func NewRouter(options ...Option) http.Handler {
	cfg := routerConfig{xrayController: defaultXrayController{}}
	for _, option := range options {
		option(&cfg)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", panelHandler)
	mux.HandleFunc("/login", loginHandler(&cfg))
	mux.HandleFunc("/api/login", loginHandler(&cfg))
	mux.HandleFunc("/api/logout", logoutHandler())
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/inbounds", inboundsHandler(cfg.store))
	mux.HandleFunc("/api/inbounds/", inboundChildrenHandler(cfg.store))
	mux.HandleFunc("/api/xray/config", xrayConfigHandler(cfg.store))
	mux.HandleFunc("/api/xray/status", xrayStatusHandler(cfg.xrayController))
	mux.HandleFunc("/api/xray/apply", xrayApplyHandler(cfg.xrayController))
	mux.HandleFunc("/api/settings", settingsHandler(&cfg))
	mux.HandleFunc("/sub/", subscriptionHandler(cfg.store))
	return authMiddleware(mux, &cfg)
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
	_, _ = w.Write([]byte(`{"status":"ok","mode":"single-binary"}`))
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
		path := strings.TrimPrefix(r.URL.Path, "/api/inbounds/")
		parts := strings.Split(strings.Trim(path, "/"), "/")

		switch r.Method {
		case http.MethodPost:
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
		case http.MethodPut:
			if len(parts) == 1 {
				// PUT /api/inbounds/{id}
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				updateInbound(w, r, store, inboundID)
			} else if len(parts) == 3 && parts[1] == "clients" {
				// PUT /api/inbounds/{id}/clients/{clientId}
				clientID, err := strconv.ParseInt(parts[2], 10, 64)
				if err != nil || clientID <= 0 {
					http.NotFound(w, r)
					return
				}
				updateClient(w, r, store, clientID)
			} else {
				http.NotFound(w, r)
			}
		case http.MethodDelete:
			if len(parts) == 1 {
				// DELETE /api/inbounds/{id}
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				if store == nil {
					http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
					return
				}
				if err := store.DeleteInbound(r.Context(), inboundID); err != nil {
					http.Error(w, `{"error":"inbound_not_found"}`, http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			} else if len(parts) == 3 && parts[1] == "clients" {
				// DELETE /api/inbounds/{id}/clients/{clientId}
				clientID, err := strconv.ParseInt(parts[2], 10, 64)
				if err != nil || clientID <= 0 {
					http.NotFound(w, r)
					return
				}
				if store == nil {
					http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
					return
				}
				if err := store.DeleteClient(r.Context(), clientID); err != nil {
					http.Error(w, `{"error":"client_not_found"}`, http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
			} else {
				http.NotFound(w, r)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
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
		Email        string `json:"email"`
		TrafficLimit int64  `json:"traffic_limit"`
		ExpiryAt     int64  `json:"expiry_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	created, err := store.CreateClient(r.Context(), db.CreateClientParams{InboundID: inboundID, Email: payload.Email, TrafficLimit: payload.TrafficLimit, ExpiryAt: payload.ExpiryAt})
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

func updateInbound(w http.ResponseWriter, r *http.Request, store Store, inboundID int64) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var payload db.UpdateInboundParams
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	updated, err := store.UpdateInbound(r.Context(), inboundID, payload)
	if err != nil {
		http.Error(w, `{"error":"update_inbound_failed"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

func updateClient(w http.ResponseWriter, r *http.Request, store Store, clientID int64) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var payload db.UpdateClientParams
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	updated, err := store.UpdateClient(r.Context(), clientID, payload)
	if err != nil {
		http.Error(w, `{"error":"update_client_failed"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
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

func settingsHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.configDir == "" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"settings_not_available"}`))
			return
		}
		configPath := cfg.configDir + "/panel.json"
		switch r.Method {
		case http.MethodGet:
			data, err := os.ReadFile(configPath)
			if err != nil {
				http.Error(w, `{"error":"read_config_failed"}`, http.StatusInternalServerError)
				return
			}
			// Mask password for GET
			var raw map[string]interface{}
			if err := json.Unmarshal(data, &raw); err != nil {
				http.Error(w, `{"error":"parse_config_failed"}`, http.StatusInternalServerError)
				return
			}
			if _, exists := raw["panel_password"]; exists {
				raw["has_password"] = true
				delete(raw, "panel_password")
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(raw)
		case http.MethodPut:
			var updated map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
				return
			}
			// Read existing to preserve password if not provided
			existing, err := os.ReadFile(configPath)
			if err == nil {
				var existingMap map[string]interface{}
				if err := json.Unmarshal(existing, &existingMap); err == nil {
					if pw, has := updated["panel_password"]; !has || pw == "" {
						if oldPW, ok := existingMap["panel_password"]; ok {
							updated["panel_password"] = oldPW
						}
					}
				}
			}
			data, err := json.MarshalIndent(updated, "", "  ")
			if err != nil {
				http.Error(w, `{"error":"serialize_failed"}`, http.StatusInternalServerError)
				return
			}
			if err := os.WriteFile(configPath, data, 0o600); err != nil {
				http.Error(w, `{"error":"write_config_failed"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
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
			now := time.Now().Unix()
			for _, client := range inbound.Clients {
				if !client.Enabled || client.UUID != token {
					continue
				}
				// Skip expired or over-limit clients
				if client.ExpiryAt > 0 && client.ExpiryAt <= now {
					continue
				}
				if client.TrafficLimit > 0 && (client.Up+client.Down) >= client.TrafficLimit {
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
	host = subscriptionHost(host)
	switch inbound.Protocol {
	case "vmess":
		return vmessShareLink(host, inbound, client)
	case "shadowsocks":
		return ssShareLink(host, inbound, client)
	default:
		// vless, trojan, etc. use universal link format
		return inbound.Protocol + "://" + client.UUID + "@" + host + ":" + strconv.Itoa(inbound.Port) + "?type=" + inbound.Network + "&security=" + inbound.Security + "#" + client.Email
	}
}

func vmessShareLink(host string, inbound db.Inbound, client db.Client) string {
	inboundPort := inbound.Port
	portStr := strconv.Itoa(inboundPort)
	tls := ""
	if inbound.Security == "tls" || inbound.Security == "reality" {
		tls = "tls"
	}
	vmessData := map[string]interface{}{
		"v":    "2",
		"ps":   client.Email,
		"add":  host,
		"port": portStr,
		"id":   client.UUID,
		"aid":  "0",
		"scy":  "auto",
		"net":  inbound.Network,
		"type": "none",
		"host": "",
		"path": "",
		"tls":  tls,
	}
	b, _ := json.Marshal(vmessData)
	encoded := base64.StdEncoding.EncodeToString(b)
	return "vmess://" + encoded
}

func ssShareLink(host string, inbound db.Inbound, client db.Client) string {
	// Default method used by Xray config builder: 2022-blake3-aes-128-gcm
	method := "2022-blake3-aes-128-gcm"
	userPass := method + ":" + client.UUID
	encoded := base64.StdEncoding.EncodeToString([]byte(userPass))
	return "ss://" + encoded + "@" + host + ":" + strconv.Itoa(inbound.Port) + "#" + client.Email
}

func subscriptionHost(host string) string {
	if host == "" {
		return "SERVER_IP"
	}
	name, _, err := net.SplitHostPort(host)
	if err == nil && name != "" {
		return name
	}
	return strings.Trim(host, "[]")
}

const panelHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MiGate</title>
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
    .row { display:grid; grid-template-columns:1.2fr .8fr .8fr .8fr .8fr .6fr; gap:10px; align-items:center; padding:12px; border:1px solid rgba(148,163,184,.14); border-radius:14px; background:rgba(148,163,184,.07); }
    .muted { color:var(--muted); }
    .error { color:#fecaca; }
    .btn-del { background:var(--danger); border:none; color:white; padding:4px 10px; border-radius:8px; font-size:12px; cursor:pointer; }
    .bar-low { background:var(--accent2); }
    .bar-mid { background:#fbbf24; }
    .bar-high { background:var(--danger); }
    .copy-link { font-size:11px;cursor:pointer; }
    .btn-sm { border:none; color:white; padding:4px 8px; border-radius:8px; font-size:11px; cursor:pointer; }
    .hidden { display:none; }
    #toast-container { position:fixed; top:20px; right:20px; z-index:9999; display:flex; flex-direction:column; gap:10px; }
    .toast { background:var(--card); border:1px solid var(--accent); color:var(--text); padding:12px 18px; border-radius:12px; box-shadow:0 8px 30px rgba(0,0,0,.4); animation: toastIn .3s ease, toastOut .3s ease 2.7s forwards; }
    .toast.error { border-color:var(--danger); }
    .toast.success { border-color:var(--accent2); }
    @keyframes toastIn { from { opacity:0; transform:translateX(40px); } to { opacity:1; transform:translateX(0); } }
    @keyframes toastOut { from { opacity:1; } to { opacity:0; transform:translateX(40px); } }
    #confirm-overlay.hidden { display:none; }
  #edit-inbound-overlay.hidden { display:none; }
  #edit-client-overlay.hidden { display:none; }
#confirm-overlay { position:fixed; inset:0; z-index:10000; background:rgba(0,0,0,.65); display:flex; align-items:center; justify-content:center; animation:fadeIn .2s; }
  #confirm-dialog p { margin:0 0 20px; font-size:15px; line-height:1.6; }
  #confirm-dialog .actions { display:flex; gap:10px; justify-content:flex-end; }
  #confirm-dialog .btn-cancel { background:rgba(148,163,184,.12); border:1px solid var(--line); color:var(--text); padding:10px 18px; border-radius:12px; cursor:pointer; font-weight:600; }
  #confirm-dialog .btn-confirm { background:var(--danger); border:none; color:white; padding:10px 18px; border-radius:12px; cursor:pointer; font-weight:700; }
  #edit-inbound-overlay, #edit-client-overlay { position:fixed; inset:0; z-index:10000; background:rgba(0,0,0,.65); display:flex; align-items:center; justify-content:center; animation:fadeIn .2s; }
  #edit-inbound-dialog, #edit-client-dialog { background:var(--bg); border:1px solid var(--line); border-radius:18px; padding:24px; min-width:360px; max-width:480px; max-height:80vh; overflow-y:auto; }
  #edit-inbound-dialog input, #edit-inbound-dialog select { width:100%; box-sizing:border-box; margin-bottom:10px; }
    @keyframes fadeIn { from { opacity:0; } to { opacity:1; } }
    @media (max-width: 900px) { .shell { grid-template-columns:1fr; } aside { border-right:0; border-bottom:1px solid var(--line); } .grid,.protocols { grid-template-columns:1fr 1fr; } }
    @media (max-width: 560px) { .grid,.protocols { grid-template-columns:1fr; } main { padding:18px; } }
  </style>
</head>
<body>
  <div id="toast-container"></div>
  <div id="confirm-overlay" class="hidden" onclick="if(event.target===this)rejectConfirm()">
    <div id="confirm-dialog">
      <p id="confirm-msg"></p>
      <div class="actions">
        <button class="btn-cancel" onclick="rejectConfirm()">取消</button>
        <button class="btn-confirm" onclick="resolveConfirm()">确认</button>
      </div>
    </div>
  </div>

  <!-- Edit Inbound Modal -->
  <div id="edit-inbound-overlay" class="hidden" onclick="if(event.target===this)closeEditInbound()">
    <div id="edit-inbound-dialog">
      <h3 style="margin:0 0 16px">编辑入站</h3>
      <form id="edit-inbound-form" onsubmit="return false">
        <input id="ei-remark" placeholder="备注" required>
        <select id="ei-protocol">
          <option value="vless">VLESS</option>
          <option value="vmess">VMess</option>
          <option value="trojan">Trojan</option>
          <option value="shadowsocks">Shadowsocks</option>
        </select>
        <input id="ei-port" type="number" min="1" max="65535" placeholder="端口" required>
        <select id="ei-network">
          <option value="tcp">TCP</option>
          <option value="ws">WebSocket</option>
          <option value="kcp">mKCP</option>
          <option value="grpc">gRPC</option>
          <option value="quic">QUIC</option>
          <option value="h2">HTTP/2</option>
        </select>
        <select id="ei-security">
          <option value="none">none</option>
          <option value="tls">tls</option>
          <option value="reality">reality</option>
        </select>
        <div id="ei-dynamic-fields">
          <div id="ei-ws-settings" class="hidden">
            <input id="ei-ws-path" placeholder="WS Path (默认 /)">
            <input id="ei-ws-host" placeholder="WS Host (可选)">
          </div>
          <div id="ei-reality-settings" class="hidden">
            <input id="ei-reality-dest" value="www.cloudflare.com:443" placeholder="目标 (dest)">
            <input id="ei-reality-server-names" value="www.cloudflare.com" placeholder="ServerNames (逗号分隔)">
            <input id="ei-reality-short-id" placeholder="ShortId (可选)">
          </div>
          <div id="ei-ss-settings" class="hidden">
            <select id="ei-ss-method">
              <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
              <option value="aes-256-gcm">aes-256-gcm</option>
              <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
            </select>
          </div>
        </div>
        <div class="actions" style="margin-top:12px">
          <button type="button" class="btn-cancel" onclick="closeEditInbound()">取消</button>
          <button type="submit" class="btn-confirm" style="background:var(--accent)" onclick="saveEditInbound()">保存</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Edit Client Modal -->
  <div id="edit-client-overlay" class="hidden" onclick="if(event.target===this)closeEditClient()">
    <div id="edit-client-dialog">
      <h3 style="margin:0 0 16px">编辑客户端</h3>
      <div class="actions" style="flex-direction:column;gap:10px">
        <input id="ec-email" placeholder="客户端标识，例如 user01" required style="width:100%;box-sizing:border-box">
        <input id="ec-traffic-limit" type="number" min="0" placeholder="流量限额（字节，0=不限）" style="width:100%;box-sizing:border-box">
        <input id="ec-expiry-at" type="datetime-local" style="width:100%;box-sizing:border-box">
      </div>
      <div class="actions" style="margin-top:12px">
        <button class="btn-cancel" onclick="closeEditClient()">取消</button>
        <button class="btn-confirm" style="background:var(--accent)" onclick="saveEditClient()">保存</button>
      </div>
    </div>
  </div>

  <div class="shell">
    <aside>
      <div class="brand">MiGate</div>
      <div class="subtitle">轻量面板风格单二进制面板</div>
      <nav>
        <a class="active" href="/">概览</a>
        <a href="/#inbounds">入站</a>
        <a href="/#clients">客户端</a>
        <a href="/#subscriptions">订阅</a>
        <a href="/#xray">Xray</a>
        <a href="/#settings">设置</a>
      </nav>
    </aside>
    <main>
      <section id="overview" class="grid" aria-label="概览指标">
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
          <select name="network">
            <option value="tcp">TCP</option>
            <option value="ws">WebSocket</option>
            <option value="kcp">mKCP</option>
            <option value="grpc">gRPC</option>
            <option value="quic">QUIC</option>
            <option value="h2">HTTP/2</option>
          </select>
          <select name="security">
            <option value="none">none</option>
            <option value="tls">tls</option>
            <option value="reality">reality</option>
          </select>
          <div id="dynamic-fields">
            <div id="ws-settings" class="hidden">
              <input name="ws_path" placeholder="WS Path (默认 /)">
              <input name="ws_host" placeholder="WS Host (可选)">
            </div>
            <div id="reality-settings" class="hidden">
              <input name="reality_dest" value="www.cloudflare.com:443" placeholder="目标 (dest)">
              <input name="reality_server_names" value="www.cloudflare.com" placeholder="ServerNames (逗号分隔)">
              <input name="reality_short_id" placeholder="ShortId (可选)">
            </div>
            <div id="ss-settings" class="hidden">
              <select name="ss_method">
                <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
                <option value="aes-256-gcm">aes-256-gcm</option>
                <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
              </select>
            </div>
          </div>
          <button type="submit">保存入站</button>
        </form>
        <div id="inbound-list" class="list muted">正在加载入站...</div>
      </section>
      <section id="clients" class="card">
        <h2 class="section-title">客户端管理</h2>
        <p class="muted">选择入站 → 创建客户端 → 获取订阅链接</p>
        <div class="actions">
          <select id="client-inbound-select" onchange="loadClients()">
            <option value="">--选择入站--</option>
          </select>
        </div>
        <form id="client-form" style="display:flex;flex-wrap:wrap;gap:8px;align-items:end">
          <input name="email" placeholder="客户端标识，例如 user01" required style="flex:1;min-width:140px">
          <input name="traffic_limit" type="number" min="0" placeholder="流量限额（字节，0=不限）" style="width:180px">
          <input name="expiry_at" type="datetime-local" id="client-expiry" placeholder="到期时间" style="width:180px">
          <button type="submit">创建客户端</button>
        </form>
        <div id="client-list" class="list muted">选择一个入站以查看客户端...</div>
      </section>
      <section id="subscriptions" class="card">
        <h2 class="section-title">订阅管理</h2>
        <p class="muted" style="margin-bottom:16px">每个客户端自动生成订阅链接和分享链接，可在客户端列表中查看和复制。</p>
        <div id="subscription-info" style="background:rgba(148,163,184,.06); border-radius:16px; padding:20px; line-height:2">
          <div><strong>订阅格式</strong>：<code>/sub/{uuid}</code> — 返回对应协议的分享链接</div>
          <div><strong>支持协议</strong>：VLESS / VMess / Trojan / Shadowsocks</div>
          <div><strong>使用方式</strong>：将订阅链接填入 V2Ray / Clash Meta / Nekoray 等客户端</div>
        </div>
        <div class="list" style="margin-top:16px">
          <div id="sub-inbound-summary">正在加载入站订阅概况...</div>
        </div>
      </section>
      <section id="xray" class="card">
        <h2 class="section-title">Xray 管理</h2>
        <p class="muted" style="margin-bottom:16px">查看 Xray 服务状态，应用配置变更。</p>
        <div style="background:rgba(148,163,184,.06); border-radius:16px; padding:20px; margin-bottom:16px">
          <div><strong>状态</strong>：<span id="xray-status">未知</span></div>
          <div><strong>托管</strong>：<span id="xray-managed">-</span></div>
          <div><strong>服务</strong>：<span id="xray-service">xray</span></div>
        </div>
        <div class="actions" style="gap:10px">
          <button onclick="fetchXrayStatus()">刷新状态</button>
          <button class="secondary" onclick="applyXrayConfig()">应用配置</button>
        </div>
        <div id="xray-result" class="list muted" style="margin-top:12px"></div>
        <div style="margin-top:16px">
          <button class="secondary" onclick="previewXrayConfig()">预览配置</button>
        </div>
        <div id="xray-config-preview" class="list muted" style="margin-top:12px;display:none"><pre id="xray-config-json" style="background:rgba(148,163,184,.06);border-radius:12px;padding:16px;font-size:12px;overflow-x:auto;white-space:pre-wrap;max-height:400px;overflow-y:auto"></pre></div>
      </section>
      <section id="settings" class="card">
        <h2 class="section-title">面板设置</h2>
        <p class="muted" style="margin-bottom:16px">编辑 panel.json 配置。修改面板端口或认证后需重启服务生效。</p>
        <form id="settings-form" onsubmit="return false">
          <input id="set-panel-port" type="number" min="1" max="65535" placeholder="面板端口" required>
          <input id="set-username" placeholder="登录用户名">
          <input id="set-password" type="password" placeholder="登录密码（留空不修改）">
          <input id="set-xray-config-path" placeholder="Xray 配置路径（如 /etc/migate/xray.json）">
          <input id="set-web-path" placeholder="Web 基础路径（如 /）">
          <div class="actions" style="margin-top:8px">
            <button type="submit" onclick="saveSettings()">保存设置</button>
            <button type="button" class="secondary" onclick="loadSettings()">刷新</button>
          </div>
        </form>
        <div id="settings-status" class="list muted" style="margin-top:12px"></div>
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
      inboundList.innerHTML = inbounds.map((inbound) => '<div class="row"><strong>' + escapeHtml(inbound.remark || '-') + '</strong><span>' + escapeHtml(inbound.protocol) + '</span><span>:' + inbound.port + '</span><span>' + escapeHtml(inbound.network || 'tcp') + '/' + escapeHtml(inbound.security || 'none') + '</span><span>' + ((inbound.clients || []).length) + ' 客户端</span><span style="display:flex;gap:4px"><button class="btn-sm" style="background:var(--accent)" onclick="editInbound(' + inbound.id + ')" title="EDIT">\u270f\ufe0f</button><button class="btn-sm" style="background:' + (inbound.enabled ? 'var(--accent2)' : 'var(--muted)') + '" onclick="toggleInbound(' + inbound.id + ')" title="TOGGLE">' + (inbound.enabled ? 'ON' : 'OFF') + '</button><button class="btn-del" onclick="deleteInbound(' + inbound.id + ')">DEL</button></span></div>').join('');
    }

    function escapeHtml(value) {
      return String(value || '').replace(/[&<>"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[char]));
    }

    async function loadInbounds() {
      const response = await fetch('/api/inbounds');
      const data = await response.json();
      renderInbounds(data.inbounds || []);
    }

    loadInbounds();

    // === Navigation section switching ===
    function navigateTo(sectionId) {
      const validSections = ['overview', 'inbounds', 'clients', 'subscriptions', 'xray', 'settings'];
      if (!validSections.includes(sectionId)) sectionId = 'overview';
      document.querySelectorAll('main > section').forEach((el) => {
        el.style.display = (el.id === sectionId) ? '' : 'none';
      });
      document.querySelectorAll('nav a').forEach((a) => {
        const href = a.getAttribute('href');
        a.classList.toggle('active', (sectionId === 'overview' && href === '/') || href === '/#' + sectionId);
      });
    }
    document.querySelectorAll('nav a').forEach((a) => {
      a.addEventListener('click', (e) => {
        e.preventDefault();
        const href = a.getAttribute('href');
        if (href === '/') { navigateTo('overview'); return; }
        const id = href.replace('/#', '');
        navigateTo(id);
      });
    });
    // Start on overview
    navigateTo('overview');

    async function loadClients() {
      const sel = document.getElementById('client-inbound-select');
      const list = document.getElementById('client-list');
      if (!sel.value) {
        list.className = 'list muted';
        list.textContent = '选择一个入站以查看客户端...';
        return;
      }
      const response = await fetch('/api/inbounds');
      const data = await response.json();
      const inbound = (data.inbounds || []).find(i => i.id === parseInt(sel.value));
      if (!inbound) {
        list.className = 'list muted';
        list.textContent = '入站未找到。';
        return;
      }
      renderClients(inbound, list);
    }

    function renderClients(inbound, list) {
      const subscriptionHost = window.location.host;
      const clients = inbound.clients || [];
      if (clients.length === 0) {
        list.className = 'list muted';
        list.textContent = '暂无客户端，在该入站下创建一个。';
        return;
      }
      list.className = 'list';
      list.innerHTML = clients.map(c => {
        const subUrl = window.location.protocol + '//' + subscriptionHost + '/sub/' + c.uuid;
        const shareLink = inbound.protocol + '://' + c.uuid + '@' + subscriptionHost + ':' + inbound.port + '?type=' + (inbound.network||'tcp') + '&security=' + (inbound.security||'none') + '#' + escapeHtml(c.email);
        return '<div class="row" style="grid-template-columns:1.2fr .8fr .8fr 1.5fr .4fr .7fr">' +
          '<strong>' + escapeHtml(c.email) + '</strong>' +
          '<span class="muted" style="font-size:11px;word-break:break-all">' + c.uuid + '</span>' +
          '<span class="muted" style="font-size:11px">订阅链接</span>' +
          '<span class="copy-link" style="font-size:11px;cursor:pointer;color:var(--accent);word-break:break-all" onclick="copySubUrl(\'' + subUrl + '\')" title="点击复制订阅链接">' + subUrl + '</span>' +
          '<span class="copy-link" style="font-size:11px;cursor:pointer;color:var(--accent2)" onclick="copySubUrl(\'' + shareLink + '\')" title="点击复制分享链接">🔗</span>' +
          '<span style="display:flex;gap:4px">' +
          '<button class="btn-sm" style="background:var(--accent)" onclick="editClient(' + c.id + ',' + inbound.id + ')" title="EDIT">\u270f\ufe0f</button>' +
          '<button class="btn-sm" style="background:' + (c.enabled ? 'var(--accent2)' : 'var(--muted)') + '" onclick="toggleClient(' + c.id + ')" title="TOGGLE">' + (c.enabled ? 'ON' : 'OFF') + '</button>' +
          '<button class="btn-del" style="padding:4px 8px;font-size:11px" onclick="deleteClient(' + inbound.id + ',' + c.id + ')">DEL</button></span></div>';
      }).join('');
    }

    function formatBytes(bytes) {
      if (!bytes || bytes === 0) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(1024));
      return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
    }

    function copySubUrl(text) {
      navigator.clipboard.writeText(text).then(() => {
      }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      });
    }

    async function deleteInbound(id) {
      if (!await showConfirm('确认删除入站 ' + id + '？此操作不可撤销，其下的客户端也将被删除。')) return;
      const response = await fetch('/api/inbounds/' + id, {method: 'DELETE'});
      if (!response.ok) {
        showToast('删除失败：' + await response.text(), 'error');
        return;
      }
      await loadInbounds();
      populateInboundSelect();
    }

    async function deleteClient(inboundId, clientId) {
      if (!await showConfirm('确认删除客户端 ' + clientId + '？')) return;
      const response = await fetch('/api/inbounds/' + inboundId + '/clients/' + clientId, {method: 'DELETE'});
      if (!response.ok) {
        showToast('删除失败：' + await response.text(), 'error');
        return;
      }
      await loadClients();
      const inboundResponse = await fetch('/api/inbounds');
      const data = await inboundResponse.json();
      renderInbounds(data.inbounds || []);
    }

    function populateInboundSelect() {
      const sel = document.getElementById('client-inbound-select');
      fetch('/api/inbounds').then(r => r.json()).then(data => {
        const inbounds = data.inbounds || [];
        sel.innerHTML = '<option value="">--选择入站--</option>' +
          inbounds.map(i => '<option value="' + i.id + '">' + escapeHtml(i.remark) + ' (' + i.protocol + ' :' + i.port + ')</option>').join('');
      });
    }

    // === Edit & toggle functions ===
    let _editingInboundId = null;
    let _editingClientData = null;

    function eiUpdateDynamicFields() {
      const proto = document.getElementById('ei-protocol').value;
      const net = document.getElementById('ei-network').value;
      const sec = document.getElementById('ei-security').value;
      document.getElementById('ei-ws-settings').classList.toggle('hidden', net !== 'ws' && net !== 'h2');
      document.getElementById('ei-reality-settings').classList.toggle('hidden', sec !== 'reality');
      document.getElementById('ei-ss-settings').classList.toggle('hidden', proto !== 'shadowsocks');
    }

    async function editInbound(id) {
      const res = await fetch('/api/inbounds');
      const data = await res.json();
      const inbound = (data.inbounds || []).find(i => i.id === id);
      if (!inbound) { showToast('入站未找到', 'error'); return; }
      _editingInboundId = id;
      document.getElementById('ei-remark').value = inbound.remark || '';
      document.getElementById('ei-protocol').value = inbound.protocol || 'vless';
      document.getElementById('ei-port').value = inbound.port || '';
      document.getElementById('ei-network').value = inbound.network || 'tcp';
      document.getElementById('ei-security').value = inbound.security || 'none';
      document.getElementById('ei-ws-path').value = inbound.ws_path || '';
      document.getElementById('ei-ws-host').value = inbound.ws_host || '';
      document.getElementById('ei-reality-dest').value = inbound.reality_dest || '';
      document.getElementById('ei-reality-server-names').value = inbound.reality_server_names || '';
      document.getElementById('ei-reality-short-id').value = inbound.reality_short_id || '';
      document.getElementById('ei-ss-method').value = inbound.ss_method || '2022-blake3-aes-128-gcm';
      eiUpdateDynamicFields();
      document.getElementById('edit-inbound-overlay').classList.remove('hidden');
    }
    function closeEditInbound() {
      _editingInboundId = null;
      document.getElementById('edit-inbound-overlay').classList.add('hidden');
    }
    async function saveEditInbound() {
      const id = _editingInboundId;
      if (id === null) return;
      const data = {
        remark: document.getElementById('ei-remark').value.trim() || '-',
        protocol: document.getElementById('ei-protocol').value,
        port: parseInt(document.getElementById('ei-port').value) || 0,
        network: document.getElementById('ei-network').value,
        security: document.getElementById('ei-security').value,
        ws_path: document.getElementById('ei-ws-path').value,
        ws_host: document.getElementById('ei-ws-host').value,
        reality_dest: document.getElementById('ei-reality-dest').value,
        reality_server_names: document.getElementById('ei-reality-server-names').value,
        reality_short_id: document.getElementById('ei-reality-short-id').value,
        ss_method: document.getElementById('ei-ss-method').value,
      };
      if (!data.remark || !data.port) { showToast('请填写备注和端口', 'error'); return; }
      const res = await fetch('/api/inbounds/' + id, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
      });
      if (!res.ok) { showToast('编辑入站失败', 'error'); return; }
      showToast('入站已更新', 'success');
      closeEditInbound();
      await loadInbounds();
    }
    document.getElementById('ei-protocol').addEventListener('change', eiUpdateDynamicFields);
    document.getElementById('ei-network').addEventListener('change', eiUpdateDynamicFields);
    document.getElementById('ei-security').addEventListener('change', eiUpdateDynamicFields);

    async function toggleInbound(id) {
      const response = await fetch('/api/inbounds');
      const data = await response.json();
      const inbound = (data.inbounds || []).find(i => i.id === id);
      if (!inbound) return;
      const newEnabled = !inbound.enabled;
      const res = await fetch('/api/inbounds/' + id, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: newEnabled})
      });
      if (!res.ok) {
        showToast('开关入站失败', 'error');
        return;
      }
      showToast('入站 ' + (newEnabled ? '已启用' : '已禁用'), 'success');
      await loadInbounds();
    }

    async function editClient(id, inboundId) {
      const res = await fetch('/api/inbounds');
      const data = await res.json();
      const inbound = (data.inbounds || []).find(i => inboundId ? i.id === inboundId : true);
      const allClients = (inbound && inbound.clients) || [];
      // Search across all inbounds for the client
      let client = allClients.find(c => c.id === id);
      if (!client) {
        for (const ib of (data.inbounds || [])) {
          client = (ib.clients || []).find(c => c.id === id);
          if (client) break;
        }
      }
      if (!client) { showToast('客户端未找到', 'error'); return; }
      _editingClientData = {id: id, inboundId: client.inbound_id};
      document.getElementById('ec-email').value = client.email || '';
      document.getElementById('ec-traffic-limit').value = client.traffic_limit || '';
      if (client.expiry_at && client.expiry_at > 0) {
        const d = new Date(client.expiry_at * 1000);
        document.getElementById('ec-expiry-at').value = d.toISOString().slice(0,16);
      } else {
        document.getElementById('ec-expiry-at').value = '';
      }
      document.getElementById('edit-client-overlay').classList.remove('hidden');
    }
    function closeEditClient() {
      _editingClientData = null;
      document.getElementById('edit-client-overlay').classList.add('hidden');
    }
    async function saveEditClient() {
      const d = _editingClientData;
      if (!d) return;
      const email = document.getElementById('ec-email').value.trim();
      if (!email) { showToast('请输入客户端标识', 'error'); return; }
      const tl = parseInt(document.getElementById('ec-traffic-limit').value) || 0;
      const eaStr = document.getElementById('ec-expiry-at').value;
      let ea = 0;
      if (eaStr) { ea = Math.floor(new Date(eaStr).getTime() / 1000); }
      const res = await fetch('/api/inbounds/' + d.inboundId + '/clients/' + d.id, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: email, traffic_limit: tl, expiry_at: ea})
      });
      if (!res.ok) { showToast('编辑客户端失败', 'error'); return; }
      showToast('客户端已更新', 'success');
      closeEditClient();
      await loadClients();
    }

    async function toggleClient(id) {
      const sel = document.getElementById('client-inbound-select');
      const inboundRes = await fetch('/api/inbounds');
      const data = await inboundRes.json();
      const inbound = (data.inbounds || []).find(i => i.id === parseInt(sel.value));
      if (!inbound) return;
      const client = (inbound.clients || []).find(c => c.id === id);
      if (!client) return;
      const newEnabled = !client.enabled;
      const res = await fetch('/api/inbounds/1/clients/' + id, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: newEnabled})
      });
      if (!res.ok) {
        showToast('开关客户端失败', 'error');
        return;
      }
      showToast('客户端 ' + (newEnabled ? '已启用' : '已禁用'), 'success');
      await loadClients();
      const inboundResponse = await fetch('/api/inbounds');
      const inboundData = await inboundResponse.json();
      renderInbounds(inboundData.inbounds || []);
    }

    document.getElementById('client-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const sel = document.getElementById('client-inbound-select');
      if (!sel.value) {
        showToast('请先选择一个入站', 'error');
        return;
      }
      const form = new FormData(event.currentTarget);
      const email = form.get('email');
      const tl = parseInt(form.get('traffic_limit')) || 0;
      const eaStr = document.getElementById('client-expiry').value;
      let ea = 0;
      if (eaStr) { ea = Math.floor(new Date(eaStr).getTime() / 1000); }
      const response = await fetch('/api/inbounds/' + sel.value + '/clients', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: email, traffic_limit: tl, expiry_at: ea})
      });
      if (!response.ok) {
        showToast('创建客户端失败：' + await response.text(), 'error');
        return;
      }
      event.currentTarget.reset();
      showToast('客户端创建成功', 'success');
      await loadClients();
      const inboundResponse = await fetch('/api/inbounds');
      const data = await inboundResponse.json();
      renderInbounds(data.inbounds || []);
    });

    populateInboundSelect();

    // === Toast notification ===
    function showToast(msg, type) {
      const container = document.getElementById('toast-container');
      const el = document.createElement('div');
      el.className = 'toast' + (type === 'error' ? ' error' : type === 'success' ? ' success' : '');
      el.textContent = msg;
      container.appendChild(el);
      setTimeout(() => el.remove(), 3000);
    }

    // === Modal confirm (replaces native confirm()) ===
    let _confirmResolve = null;
    function showConfirm(msg) {
      return new Promise((resolve) => {
        _confirmResolve = resolve;
        document.getElementById('confirm-msg').textContent = msg;
        document.getElementById('confirm-overlay').classList.remove('hidden');
      });
    }
    function resolveConfirm() {
      document.getElementById('confirm-overlay').classList.add('hidden');
      if (_confirmResolve) { _confirmResolve(true); _confirmResolve = null; }
    }
    function rejectConfirm() {
      document.getElementById('confirm-overlay').classList.add('hidden');
      if (_confirmResolve) { _confirmResolve(false); _confirmResolve = null; }
    }

    // === Dynamic transport/security fields ===
    function updateDynamicFields() {
      const proto = document.querySelector('[name=protocol]').value;
      const net = document.querySelector('[name=network]').value;
      const sec = document.querySelector('[name=security]').value;
      document.getElementById('ws-settings').classList.toggle('hidden', net !== 'ws' && net !== 'h2');
      document.getElementById('reality-settings').classList.toggle('hidden', sec !== 'reality');
      document.getElementById('ss-settings').classList.toggle('hidden', proto !== 'shadowsocks');
    }

    document.querySelector('[name=protocol]').addEventListener('change', updateDynamicFields);
    document.querySelector('[name=network]').addEventListener('change', updateDynamicFields);
    document.querySelector('[name=security]').addEventListener('change', updateDynamicFields);
    updateDynamicFields();

    // Replace inbound creation alert with toast
    const origSubmit = document.getElementById('inbound-form').onsubmit;
    document.getElementById('inbound-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      const payload = Object.fromEntries(form.entries());
      payload.port = Number(payload.port);
      const response = await fetch('/api/inbounds', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
      if (!response.ok) {
        showToast('创建入站失败', 'error');
        return;
      }
      event.currentTarget.reset();
      showToast('入站创建成功', 'success');
      await loadInbounds();
    });

    // === Xray status & apply ===
    async function fetchXrayStatus() {
      try {
        const res = await fetch('/api/xray/status');
        const data = await res.json();
        document.getElementById('xray-status').textContent = data.status || '未知';
        document.getElementById('xray-managed').textContent = data.managed ? '是' : '否';
        document.getElementById('xray-service').textContent = data.service || 'xray';
      } catch (e) {
        document.getElementById('xray-status').textContent = '连接失败';
      }
    }
    async function applyXrayConfig() {
      document.getElementById('xray-result').textContent = '正在应用...';
      try {
        const res = await fetch('/api/xray/apply', {method: 'POST'});
        const data = await res.json();
        document.getElementById('xray-result').innerHTML = '<div>状态：' + (data.status || '完成') + '</div>' +
          (data.commands_executed && data.commands_executed.length
            ? '<div style="margin-top:8px;font-size:12px">' + data.commands_executed.join('<br>') + '</div>'
            : '');
        showToast('配置已应用', 'success');
        await fetchXrayStatus();
      } catch (e) {
        document.getElementById('xray-result').textContent = '应用失败';
        showToast('应用配置失败', 'error');
      }
    }

    // === Subscription summary ===
    async function loadSubSummary() {
      try {
        const res = await fetch('/api/inbounds');
        const data = await res.json();
        const inbounds = data.inbounds || [];
        const host = window.location.host;
        const el = document.getElementById('sub-inbound-summary');
        if (inbounds.length === 0) {
          el.innerHTML = '<span class="muted">暂无入站，请先在「入站」页面创建。</span>';
          return;
        }
        el.innerHTML = inbounds.map(inb => {
          const count = (inb.clients || []).length;
          return '<div style="background:rgba(148,163,184,.06); border-radius:12px; padding:14px; margin-bottom:10px">' +
            '<strong>' + escapeHtml(inb.remark || inb.protocol) + '</strong> ' +
            '<span class="muted">' + inb.protocol.toUpperCase() + ' / ' + (inb.port||'') + '</span>' +
            ' <span class="muted">(' + count + ' 个客户端)</span>' +
            '</div>';
        }).join('');
      } catch (e) {
        document.getElementById('sub-inbound-summary').textContent = '加载失败';
      }
    }

    // === Xray config preview ===
    let _configVisible = false;
    async function previewXrayConfig() {
      const el = document.getElementById('xray-config-preview');
      const pre = document.getElementById('xray-config-json');
      if (_configVisible) {
        el.style.display = 'none';
        _configVisible = false;
        return;
      }
      try {
        const res = await fetch('/api/xray/config');
        const json = await res.json();
        pre.textContent = JSON.stringify(json, null, 2);
        el.style.display = '';
        _configVisible = true;
      } catch (e) {
        pre.textContent = '加载配置失败';
        el.style.display = '';
        _configVisible = true;
      }
    }

    // === Settings ===
    async function loadSettings() {
      try {
        const res = await fetch('/api/settings');
        if (!res.ok) { throw new Error('not available'); }
        const data = await res.json();
        document.getElementById('set-panel-port').value = data.panel_port || '';
        document.getElementById('set-username').value = data.panel_username || '';
        document.getElementById('set-password').value = '';
        document.getElementById('set-xray-config-path').value = data.xray_config_path || '';
        document.getElementById('set-web-path').value = data.web_base_path || '';
        if (data.database_path) {
          document.getElementById('settings-status').innerHTML = '<span class="muted">数据库：' + escapeHtml(data.database_path) + (data.has_password ? ' | 密码已设置' : ' | 无密码') + '</span>';
        }
      } catch (e) {
        document.getElementById('settings-status').textContent = '设置页面不可用：需要在 panel.json 配置文件下运行';
      }
    }
    async function saveSettings() {
      const data = {
        panel_port: parseInt(document.getElementById('set-panel-port').value) || 0,
        panel_username: document.getElementById('set-username').value.trim(),
        panel_password: document.getElementById('set-password').value,
        xray_config_path: document.getElementById('set-xray-config-path').value.trim(),
        web_base_path: document.getElementById('set-web-path').value.trim() || '/',
      };
      if (!data.panel_port) { showToast('请输入面板端口', 'error'); return; }
      try {
        const res = await fetch('/api/settings', {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(data)
        });
        if (!res.ok) { showToast('保存设置失败', 'error'); return; }
        showToast('设置已保存，重启服务后生效', 'success');
        document.getElementById('set-password').value = '';
        await loadSettings();
      } catch (e) {
        showToast('保存设置失败', 'error');
      }
    }

    fetchXrayStatus();
    loadSubSummary();
    loadSettings();
  </script>
</body>
</html>`
