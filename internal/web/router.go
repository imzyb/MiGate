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
	SetInboundEnabled(ctx context.Context, id int64, enabled bool) (db.Inbound, error)
	SetClientEnabled(ctx context.Context, inboundID int64, id int64, enabled bool) (db.Client, error)
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
	mux.HandleFunc("/api/session", sessionHandler(&cfg))
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/inbounds", inboundsHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/inbounds/", inboundChildrenHandler(cfg.store, cfg.xrayController))
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


func sessionHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		resp := map[string]interface{}{
			"auth_enabled":   cfg.authEnabled,
			"authenticated":  false,
			"username":       "",
		}
		if !cfg.authEnabled {
			resp["username"] = "未启用认证"
		} else if cookie, err := r.Cookie("migate_session"); err == nil && validateSessionToken(cookie.Value, cfg.sessionSecret) {
			resp["authenticated"] = true
			resp["username"] = cfg.authUsername
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok","mode":"single-binary"}`))
}

func inboundsHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listInbounds(w, r, store)
		case http.MethodPost:
			createInbound(w, r, store)
			go ctrl.Apply(context.Background())
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func deriveRealityPublicKeys(inbounds []db.Inbound) {
	for i := range inbounds {
		if inbounds[i].Security == "reality" && inbounds[i].RealityPublicKey == "" && inbounds[i].RealityPrivateKey != "" {
			if pubKey, err := xray.DeriveRealityPublicKey(inbounds[i].RealityPrivateKey); err == nil {
				inbounds[i].RealityPublicKey = pubKey
			}
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
		deriveRealityPublicKeys(loaded)
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
	// Auto-generate REALITY private key if missing
	if payload.Security == "reality" && payload.RealityPrivateKey == "" {
		if privKey, pubKey, err := xray.GenerateRealityKey(); err == nil {
			payload.RealityPrivateKey = privKey
			payload.RealityPublicKey = pubKey
		}
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

func inboundChildrenHandler(store Store, ctrl XrayController) http.HandlerFunc {
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
			go ctrl.Apply(context.Background())
		case http.MethodPatch:
			if len(parts) == 2 && parts[1] == "enabled" {
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				patchInboundEnabled(w, r, store, inboundID)
				go ctrl.Apply(context.Background())
			} else if len(parts) == 4 && parts[1] == "clients" && parts[3] == "enabled" {
				clientID, err := strconv.ParseInt(parts[2], 10, 64)
				if err != nil || clientID <= 0 {
					http.NotFound(w, r)
					return
				}
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				patchClientEnabled(w, r, store, inboundID, clientID)
				go ctrl.Apply(context.Background())
			} else {
				http.NotFound(w, r)
			}
		case http.MethodPut:
			if len(parts) == 1 {
				// PUT /api/inbounds/{id}
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				updateInbound(w, r, store, inboundID)
				go ctrl.Apply(context.Background())
			} else if len(parts) == 3 && parts[1] == "clients" {
				// PUT /api/inbounds/{id}/clients/{clientId}
				clientID, err := strconv.ParseInt(parts[2], 10, 64)
				if err != nil || clientID <= 0 {
					http.NotFound(w, r)
					return
				}
				updateClient(w, r, store, clientID)
				go ctrl.Apply(context.Background())
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
				go ctrl.Apply(context.Background())
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
				go ctrl.Apply(context.Background())
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

func patchInboundEnabled(w http.ResponseWriter, r *http.Request, store Store, inboundID int64) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var payload struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	updated, err := store.SetInboundEnabled(r.Context(), inboundID, payload.Enabled)
	if err != nil {
		http.Error(w, `{"error":"inbound_not_found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

func patchClientEnabled(w http.ResponseWriter, r *http.Request, store Store, inboundID int64, clientID int64) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var payload struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	updated, err := store.SetClientEnabled(r.Context(), inboundID, clientID, payload.Enabled)
	if err != nil {
		http.Error(w, `{"error":"client_not_found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
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
	// Auto-generate REALITY private key if switching to reality without one
	if payload.Security == "reality" && payload.RealityPrivateKey == "" {
		if key, _, err := xray.GenerateRealityKey(); err == nil {
			payload.RealityPrivateKey = key
		}
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
					// Preserve database_path if not in update
					if _, has := updated["database_path"]; !has {
						if oldDP, ok := existingMap["database_path"]; ok {
							updated["database_path"] = oldDP
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
		deriveRealityPublicKeys(inbounds)
		for _, inbound := range inbounds {
			if !inbound.Enabled {
				continue
			}
			now := time.Now().Unix()
			for _, client := range inbound.Clients {
				if client.UUID != token {
					continue
				}
				if !client.Enabled {
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = w.Write([]byte("// Subscription disabled"))
					return
				}
				// Check expired or over-limit
				if client.ExpiryAt > 0 && client.ExpiryAt <= now {
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = w.Write([]byte("// Subscription expired"))
					return
				}
				if client.TrafficLimit > 0 && (client.Up+client.Down) >= client.TrafficLimit {
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = w.Write([]byte("// Traffic limit exceeded"))
					return
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
		var params []string
		params = append(params, "type="+inbound.Network)
		params = append(params, "security="+inbound.Security)
		if inbound.Security == "reality" {
			params = append(params, "flow=xtls-rprx-vision")
			if inbound.RealityServerNames != "" {
				params = append(params, "sni="+inbound.RealityServerNames)
			}
			params = append(params, "fp=chrome")
			if inbound.RealityPublicKey != "" {
				params = append(params, "pbk="+inbound.RealityPublicKey)
			}
			if inbound.RealityShortID != "" {
				params = append(params, "sid="+inbound.RealityShortID)
			}
		} else if inbound.Security == "tls" {
			if inbound.RealityServerNames != "" {
				params = append(params, "sni="+inbound.RealityServerNames)
			}
			params = append(params, "allowInsecure=1")
		}
		// Transport-specific params
		if inbound.Network == "ws" {
			if inbound.WsPath != "" {
				params = append(params, "path="+inbound.WsPath)
			}
			if inbound.WsHost != "" {
				params = append(params, "host="+inbound.WsHost)
			}
		} else if inbound.Network == "grpc" {
			if inbound.GrpcServiceName != "" {
				params = append(params, "serviceName="+inbound.GrpcServiceName)
			}
		} else if inbound.Network == "xhttp" {
			if inbound.XHTTPPath != "" {
				params = append(params, "path="+inbound.XHTTPPath)
			}
			if inbound.XHTTPMode != "" {
				params = append(params, "mode="+inbound.XHTTPMode)
			}
		}
		query := strings.Join(params, "&")
		return inbound.Protocol + "://" + client.UUID + "@" + host + ":" + strconv.Itoa(inbound.Port) + "?" + query + "#" + client.Email
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
  <link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root, :root[data-theme="light"] {
      color-scheme: light;
      --bg: #ffffff;
      --fg: #171717;
      --surface: #ffffff;
      --surface-subtle: #fafafa;
      --muted: #666666;
      --line: rgba(0,0,0,.08);
      --line-strong: #ebebeb;
      --accent: #171717;
      --accent2: #16a34a;
      --danger: #dc2626;
      --focus: hsla(212, 100%, 48%, 1);
      --shadow-sm: 0 0 0 1px rgba(0,0,0,.08);
      --shadow-md: 0 0 0 1px rgba(0,0,0,.08), 0 2px 2px rgba(0,0,0,.04), 0 8px 8px -8px rgba(0,0,0,.04);
      --radius-sm: 6px;
      --radius-md: 8px;
      --radius-lg: 12px;
      --radius-xl: 16px;
      --sidebar-width: 248px;
      --space-1: 4px;
      --space-2: 8px;
      --space-3: 12px;
      --space-4: 16px;
      --space-5: 20px;
      --space-6: 24px;
      --control-height: 40px;
      --control-radius: var(--radius-sm);
      --text-xs: 12px;
      --text-sm: 13px;
      --text-md: 14px;
      --text-lg: 16px;
      --panel-padding: var(--space-5);
      --row-padding: var(--space-4);
    }
    :root[data-theme="dark"] {
      color-scheme: dark;
      --bg: #0a0a0a;
      --fg: #ededed;
      --surface: #111111;
      --surface-subtle: #18181b;
      --muted: #a1a1aa;
      --line: rgba(255,255,255,.10);
      --line-strong: rgba(255,255,255,.14);
      --accent: #ededed;
      --accent2: #22c55e;
      --danger: #ef4444;
      --focus: rgba(99,102,241,.36);
      --shadow-sm: 0 0 0 1px rgba(255,255,255,.10);
      --shadow-md: 0 0 0 1px rgba(255,255,255,.10), 0 12px 28px rgba(0,0,0,.35);
    }
    * { box-sizing: border-box; }
    html { background: var(--bg); }
    body { margin:0; min-height:100vh; font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--fg); }
    code, pre, .mono { font-family:'Geist Mono',ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace; }
    a { color:inherit; }
    p { color:var(--muted); line-height:1.6; }
    .app-shell { display:grid; grid-template-columns: var(--sidebar-width) 1fr; min-height:100vh; }
    .sidebar { border-right:1px solid var(--line-strong); padding:var(--space-6) 18px; background:var(--surface); display:flex; flex-direction:column; }
    .brand { font-size:24px; font-weight:600; letter-spacing:-0.96px; margin-bottom:var(--space-1); color:var(--fg); }
    .subtitle { color:var(--muted); font-size:var(--text-sm); line-height:1.5; margin-bottom:28px; }
    nav { flex:1; }
    #sidebar-toggle { display:none; align-items:center; justify-content:center; width:36px; height:36px; border:none; background:transparent; color:var(--fg); font-size:22px; cursor:pointer; border-radius:var(--radius-sm); margin-bottom:var(--space-3); }
    .account-panel { display:grid; gap:var(--space-2); padding:var(--space-3); margin-top:auto; margin-bottom:0; border-radius:var(--radius-lg); background:var(--surface-subtle); box-shadow:var(--shadow-sm); }
    .account-label { color:var(--muted); font-size:var(--text-xs); }
    .account-name { color:var(--fg); font-size:var(--text-sm); font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .account-actions { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
    .account-actions button { min-height:34px; padding:0 10px; font-size:var(--text-xs); }
    nav a { display:block; color:var(--fg); text-decoration:none; padding:10px var(--space-3); border-radius:var(--radius-md); margin:var(--space-1) 0; box-shadow:none; font-size:var(--text-md); font-weight:500; }
    nav a.active, nav a:hover { background:var(--surface-subtle); box-shadow:var(--shadow-sm); }
    main { padding:var(--space-6); background:var(--bg); }
    main > section{display:none}
    #overview.overview-grid{display:grid}
    .badge { display:inline-flex; align-items:center; gap:var(--space-2); padding:0 10px; height:28px; border-radius:9999px; background:#ebf5ff; color:#0068d6; box-shadow:var(--shadow-sm); font-size:var(--text-xs); font-weight:500; }
    .grid { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:var(--space-4); margin-bottom:18px; }
    .overview-grid { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:var(--space-4); margin-bottom:18px; }
    .overview-insights { display:grid; grid-template-columns:1.2fr 1fr 1fr; gap:var(--space-4); grid-column:1 / -1; }
    .overview-card { display:grid; gap:var(--space-3); align-content:start; background:var(--surface); border-radius:var(--radius-lg); box-shadow:var(--shadow-md); padding:var(--panel-padding); min-height:156px; }
    .overview-card-title { color:var(--fg); font-size:var(--text-lg); font-weight:600; letter-spacing:-0.24px; }
    .overview-pill { display:inline-flex; align-items:center; width:max-content; min-height:26px; padding:0 10px; border-radius:9999px; background:var(--surface-subtle); color:var(--fg); box-shadow:var(--shadow-sm); font-size:var(--text-xs); font-weight:500; }
    .protocol-breakdown { display:grid; gap:8px; }
    .protocol-breakdown-row { display:grid; grid-template-columns:1fr auto; gap:10px; align-items:center; color:var(--muted); font-size:var(--text-sm); }
    .panel, .card { background:var(--surface); border-radius:var(--radius-lg); box-shadow:var(--shadow-md); padding:var(--panel-padding); }
    .metric { font-size:30px; font-weight:600; line-height:1.05; letter-spacing:-0.96px; margin-top:10px; color:var(--fg); }
    .section-heading, .section-title { font-size:24px; line-height:1.2; letter-spacing:-0.96px; font-weight:600; margin:0 0 var(--space-3); color:var(--fg); }
    .protocols { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:var(--space-3); }
    .protocol { padding:14px; border-radius:var(--radius-lg); background:var(--surface); box-shadow:var(--shadow-sm); }
    .protocol strong { display:block; margin-bottom:6px; color:var(--fg); }
    .actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:14px; }
    button { appearance:none; border:none; background:var(--accent); color:var(--bg); min-height:var(--control-height); padding:0 14px; border-radius:var(--control-radius); font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; font-size:var(--text-md); font-weight:500; cursor:pointer; box-shadow:var(--shadow-sm); }
    button:hover { opacity:.96; }
    button.secondary, .btn-cancel { background:var(--surface); color:var(--fg); box-shadow:var(--shadow-sm); }
    .btn-confirm { background:var(--danger); color:#fff; }
    form { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:var(--space-3); margin:var(--space-4) 0; }
    .form-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:var(--space-4); margin:18px 0; }
    .field-group { display:grid; gap:var(--space-2); min-width:0; }
    .field-group.span-2 { grid-column:1 / -1; }
    .field-label { color:var(--fg); font-size:var(--text-sm); font-weight:500; line-height:1.3; }
    .field-help { color:var(--muted); font-size:var(--text-xs); line-height:1.45; margin:0; }
    .form-actions { grid-column:1 / -1; display:flex; justify-content:flex-end; align-items:center; gap:10px; padding-top:var(--space-1); margin-top:2px; }
    .action-toolbar { display:flex; align-items:center; justify-content:space-between; gap:var(--space-4); padding:var(--space-4); border-radius:var(--radius-lg); background:rgba(148,163,184,.06); box-shadow:var(--shadow-sm); margin:var(--space-4) 0; }
    .action-toolbar.span-2 { grid-column:1 / -1; }
    .toolbar-copy { display:grid; gap:var(--space-1); min-width:0; color:var(--muted); font-size:var(--text-sm); line-height:1.5; }
    .toolbar-copy strong { color:var(--fg); font-size:var(--text-md); font-weight:600; letter-spacing:-0.14px; }
    .toolbar-actions { display:flex; align-items:center; justify-content:flex-end; gap:10px; flex-wrap:wrap; }
    .ui-control, input, select, textarea { width:100%; min-height:var(--control-height); border:none; outline:none; background:var(--surface); color:var(--fg); border-radius:var(--control-radius); padding:0 var(--space-3); box-shadow:var(--shadow-sm); font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; font-size:var(--text-md); line-height:1.4; }
    textarea { padding-top:10px; padding-bottom:10px; }
    input:focus, select:focus, textarea:focus, button:focus { box-shadow:var(--shadow-sm), 0 0 0 2px var(--focus); }
    .list { display:grid; gap:10px; margin-top:14px; }
    .row { display:grid; grid-template-columns:1.2fr .8fr .8fr .8fr .8fr .6fr; gap:10px; align-items:center; padding:var(--row-padding); border-radius:var(--radius-lg); background:var(--surface); box-shadow:var(--shadow-sm); }
    .resource-row { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:var(--space-4); align-items:center; padding:var(--row-padding); border-radius:var(--radius-lg); background:var(--surface); box-shadow:var(--shadow-sm); transition:box-shadow .16s ease, transform .16s ease; }
    .resource-row:hover { box-shadow:var(--shadow-md); transform:translateY(-1px); }
    .resource-main { min-width:0; display:grid; gap:var(--space-2); }
    .resource-title { display:flex; align-items:center; gap:var(--space-2); min-width:0; font-size:15px; font-weight:600; color:var(--fg); }
    .resource-title strong { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .resource-meta { display:flex; flex-wrap:wrap; align-items:center; gap:var(--space-2); color:var(--muted); font-size:var(--text-xs); line-height:1.5; }
    .status-badge { display:inline-flex; align-items:center; height:22px; padding:0 var(--space-2); border-radius:9999px; font-size:var(--text-xs); font-weight:500; box-shadow:var(--shadow-sm); }
    .status-badge.enabled { color:#047857; background:#ecfdf5; }
    .status-badge.disabled { color:#6b7280; background:#f3f4f6; }
    .resource-actions { display:flex; align-items:center; justify-content:flex-end; gap:6px; }
    .icon-btn, .danger-icon-btn { display:inline-flex; align-items:center; justify-content:center; min-width:32px; min-height:32px; height:32px; padding:0 var(--space-2); border-radius:var(--control-radius); font-size:var(--text-xs); }
    .icon-btn { background:var(--surface); color:var(--fg); box-shadow:var(--shadow-sm); }
    .danger-icon-btn { background:#fff5f5; color:var(--danger); box-shadow:var(--shadow-sm); }
    .traffic-track { width:128px; height:4px; margin-top:5px; overflow:hidden; border-radius:9999px; background:#f3f4f6; }
    .traffic-fill { height:100%; border-radius:9999px; background:var(--accent2); }
    .empty-state { display:grid; gap:10px; justify-items:start; padding:22px; border-radius:var(--radius-xl); background:var(--surface); box-shadow:var(--shadow-sm), inset 0 0 0 1px rgba(250,250,250,.9); color:var(--muted); }
    .empty-state-title { color:var(--fg); font-size:16px; font-weight:600; letter-spacing:-0.32px; }
    .empty-state-copy { max-width:560px; color:var(--muted); font-size:13px; line-height:1.6; }
    .empty-state-actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:4px; }
    .notice-slot { margin-top:12px; }
    .notice { display:grid; gap:8px; padding:16px; border-radius:var(--radius-lg); background:var(--surface); box-shadow:var(--shadow-sm), inset 3px 0 0 var(--accent); }
    .notice-title { color:var(--fg); font-size:14px; font-weight:600; letter-spacing:-0.14px; }
    .notice-copy { color:var(--muted); font-size:13px; line-height:1.55; white-space:pre-wrap; }
    .notice.success { box-shadow:var(--shadow-sm), inset 3px 0 0 var(--accent2); }
    .notice.error { box-shadow:var(--shadow-sm), inset 3px 0 0 var(--danger); }
    .muted { color:var(--muted); }
    .error { color:#b91c1c; }
    .btn-del { background:var(--danger); border:none; color:white; padding:4px 10px; border-radius:var(--radius-sm); font-size:12px; cursor:pointer; }
    .bar-low { background:var(--accent2); }
    .bar-mid { background:#fbbf24; }
    .bar-high { background:var(--danger); }
    .copy-link { font-size:11px; cursor:pointer; }
    .btn-sm { border:none; color:var(--bg); padding:4px 8px; border-radius:var(--radius-sm); font-size:11px; cursor:pointer; }
    .hidden { display:none; }
    #toast-container { position:fixed; top:20px; right:20px; z-index:9999; display:flex; flex-direction:column; gap:10px; }
    .toast { background:var(--surface); border:none; color:var(--fg); padding:12px 18px; border-radius:var(--radius-lg); box-shadow:var(--shadow-md); animation: toastIn .3s ease, toastOut .3s ease 2.7s forwards; }
    .toast.error { box-shadow:var(--shadow-sm), inset 0 0 0 1px rgba(220,38,38,.18); }
    .toast.success { box-shadow:var(--shadow-sm), inset 0 0 0 1px rgba(22,163,74,.18); }
    @keyframes toastIn { from { opacity:0; transform:translateX(40px); } to { opacity:1; transform:translateX(0); } }
    @keyframes toastOut { from { opacity:1; } to { opacity:0; transform:translateX(40px); } }
    #confirm-overlay.hidden { display:none; }
    #create-inbound-overlay.hidden { display:none; }
    #create-client-overlay.hidden { display:none; }
    #edit-inbound-overlay.hidden { display:none; }
    #edit-client-overlay.hidden { display:none; }
    #confirm-overlay, #create-inbound-overlay, #create-client-overlay, #edit-inbound-overlay, #edit-client-overlay { position:fixed; inset:0; z-index:10000; background:rgba(23,23,23,.12); backdrop-filter: blur(6px); display:flex; align-items:center; justify-content:center; animation:fadeIn .2s; }
    #confirm-dialog, #create-inbound-dialog, #create-client-dialog, #edit-inbound-dialog, #edit-client-dialog { background:var(--surface); box-shadow:var(--shadow-md); border-radius:var(--radius-xl); padding:var(--space-6); min-width:360px; max-width:520px; max-height:80vh; overflow-y:auto; }
    #confirm-dialog p { margin:0 0 20px; font-size:15px; line-height:1.6; color:var(--fg); }
    #confirm-dialog .actions { display:flex; gap:10px; justify-content:flex-end; }
    .modal-title { margin:0 0 var(--space-4); font-size:var(--text-lg); line-height:1.3; font-weight:600; letter-spacing:-0.2px; color:var(--fg); }
    .modal-form { margin:0; grid-template-columns:repeat(2,minmax(0,1fr)); }
    #create-inbound-form.modal-form, #create-client-form.modal-form, #edit-inbound-form.modal-form, #edit-client-form.modal-form { gap:var(--space-4); }
    .modal-actions { margin-top:0; }
    .advanced-fieldset { padding:var(--space-4); border-radius:var(--radius-lg); background:rgba(250,250,250,.72); box-shadow:var(--shadow-sm), inset 0 0 0 1px var(--line); }
    .advanced-fieldset-title { color:var(--fg); font-size:var(--text-sm); font-weight:600; letter-spacing:-0.12px; }
    .advanced-fieldset-copy { color:var(--muted); font-size:var(--text-xs); line-height:1.55; }
    #dynamic-fields, #ei-dynamic-fields { display:contents; }
    #create-inbound-dialog input, #create-inbound-dialog select, #create-client-dialog input, #create-client-dialog select, #edit-inbound-dialog input, #edit-inbound-dialog select, #edit-client-dialog input, #edit-client-dialog select { width:100%; box-sizing:border-box; margin-bottom:0; }
    @keyframes fadeIn { from { opacity:0; } to { opacity:1; } }
    /* Mobile sidebar overlay */
    #sidebar-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,.4); z-index:99; }
    @media (max-width: 768px) {
      .app-shell { grid-template-columns:1fr; }
      .sidebar { position:fixed; top:0; left:0; bottom:0; width:var(--sidebar-width); z-index:100; transform:translateX(-100%); transition:transform .25s ease; border-right:1px solid var(--line-strong); }
      .sidebar-open .sidebar { transform:translateX(0); }
      #sidebar-overlay { display:block; opacity:0; pointer-events:none; transition:opacity .25s ease; }
      .sidebar-open #sidebar-overlay { opacity:1; pointer-events:auto; }
      #sidebar-toggle { display:flex; }
      .grid,.overview-grid,.protocols { grid-template-columns:1fr 1fr; }
      .overview-insights { grid-template-columns:1fr; }
      form { grid-template-columns:repeat(2,minmax(0,1fr)); }
    }
    @media (max-width: 560px) { .grid,.overview-grid,.protocols, form { grid-template-columns:1fr; } main { padding:18px; } }
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

  <!-- Create Inbound Modal -->
  <div id="create-inbound-overlay" class="hidden" onclick="if(event.target===this)closeCreateInbound()">
    <div id="create-inbound-dialog">
      <h3 class="modal-title">新增入站</h3>
      <form id="create-inbound-form" class="form-grid modal-form" onsubmit="return false">
        <div class="field-group">
          <label class="field-label" for="inbound-remark">入站备注</label>
          <input id="inbound-remark" name="remark" placeholder="例如 主入口" required>
          <p class="field-help">用于列表识别，不会写入客户端密钥。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="inbound-protocol">协议</label>
          <select id="inbound-protocol" name="protocol">
            <option value="vless">VLESS</option>
            <option value="vmess">VMess</option>
            <option value="trojan">Trojan</option>
            <option value="shadowsocks">Shadowsocks</option>
          </select>
          <p class="field-help">选择 Xray 入站协议。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="inbound-port">监听端口</label>
          <input id="inbound-port" name="port" type="number" min="1" max="65535" placeholder="例如 443" required>
          <p class="field-help">建议使用未被占用的公网端口。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="inbound-network">传输方式</label>
          <select name="network" id="inbound-network">
            <option value="tcp">TCP</option>
            <option value="ws">WebSocket</option>
            <option value="kcp">mKCP</option>
            <option value="grpc">gRPC</option>
            <option value="quic">QUIC</option>
            <option value="h2">HTTP/2</option>
            <option value="xhttp">XHTTP</option>
          </select>
          <p class="field-help">切换后会显示对应的高级字段。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="inbound-security">安全层</label>
          <select id="inbound-security" name="security">
            <option value="none">none</option>
            <option value="tls">tls</option>
            <option value="reality">reality</option>
          </select>
          <p class="field-help">REALITY/TLS 会展开证书或伪装目标字段。</p>
        </div>
        <div id="dynamic-fields">
          <div id="ws-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">WebSocket 设置</div>
            <div class="advanced-fieldset-copy">适合 CDN、反向代理或路径分流场景。</div>
            <input name="ws_path" placeholder="WS Path (默认 /)">
            <input name="ws_host" placeholder="WS Host (可选)">
            <p class="field-help">路径和 Host 用于 CDN 或反代场景。</p>
          </div>
          <div id="grpc-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">gRPC 设置</div>
            <div class="advanced-fieldset-copy">用于 gRPC 传输的服务名，客户端需保持一致。</div>
            <input name="grpc_service_name" value="migate" placeholder="gRPC ServiceName">
          </div>
          <div id="xhttp-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">XHTTP 设置</div>
            <div class="advanced-fieldset-copy">配置 XHTTP 路径与上传模式。</div>
            <input name="xhttp_path" value="/" placeholder="XHTTP Path (默认 /)">
            <select name="xhttp_mode">
              <option value="stream-one">stream-one</option>
              <option value="packet-up">packet-up</option>
              <option value="stream-up">stream-up</option>
            </select>
          </div>
          <div id="reality-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">REALITY 设置</div>
            <div class="advanced-fieldset-copy">填写伪装目标、SNI 与短 ID，避免与客户端参数不一致。</div>
            <input name="reality_dest" value="www.cloudflare.com:443" placeholder="目标 (dest)">
            <input name="reality_server_names" value="www.cloudflare.com" placeholder="ServerNames (逗号分隔)">
            <input name="reality_short_id" placeholder="ShortId (可选)">
          </div>
          <div id="ss-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">Shadowsocks 设置</div>
            <div class="advanced-fieldset-copy">选择客户端支持的加密方法。</div>
            <select name="ss_method">
              <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
              <option value="aes-256-gcm">aes-256-gcm</option>
              <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
            </select>
          </div>
          <div id="tls-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">TLS 设置</div>
            <div class="advanced-fieldset-copy">填写证书和私钥路径，应用前会交给 Xray 校验。</div>
            <input name="tls_cert_file" placeholder="TLS 证书路径 (如 /etc/.../fullchain.pem)">
            <input name="tls_key_file" placeholder="TLS 密钥路径 (如 /etc/.../privkey.key)">
          </div>
        </div>
        <div class="advanced-fieldset field-group span-2" style="border-left:2px solid var(--accent);padding-left:12px;margin-bottom:0">
          <div onclick="toggleInitClient(this)" style="cursor:pointer;color:var(--accent);user-select:none;font-size:13px">
            <span class="chevron">▶</span> 同时添加首个客户端
          </div>
          <div id="init-client-fields" class="hidden" style="margin-top:8px">
            <input id="init-client-email" placeholder="客户端邮箱 (必填，如 sam@example.com)">
            <input id="init-client-traffic" type="number" min="0" placeholder="流量上限 (字节, 0=无限)" value="0">
            <p class="field-help">创建入站后自动生成第一个客户端，省去后续再添加的步骤。</p>
          </div>
        </div>
        <div class="form-actions modal-actions">
          <button type="button" class="btn-cancel" onclick="closeCreateInbound()">取消</button>
          <button type="submit" class="btn-confirm" style="background:var(--accent)" onclick="saveCreateInbound()">保存入站</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Create Client Modal -->
  <div id="create-client-overlay" class="hidden" onclick="if(event.target===this)closeCreateClient()">
    <div id="create-client-dialog">
      <h3 class="modal-title">创建客户端</h3>
      <form id="create-client-form" class="form-grid modal-form" onsubmit="return false">
        <div class="field-group span-2">
          <label class="field-label" for="client-email">客户端标识</label>
          <input id="client-email" name="email" placeholder="例如 user01" required>
          <p class="field-help">用于区分设备或用户，也会出现在分享链接备注中。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="client-traffic-limit">流量限额</label>
          <input id="client-traffic-limit" name="traffic_limit" type="number" min="0" placeholder="0 = 不限">
          <p class="field-help">单位为字节；留空或 0 表示不限流量。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="client-expiry">到期时间</label>
          <input name="expiry_at" type="datetime-local" id="client-expiry" placeholder="到期时间">
          <p class="field-help">到期后订阅会返回明确的过期提示。</p>
        </div>
        <div class="form-actions modal-actions">
          <button type="button" class="btn-cancel" onclick="closeCreateClient()">取消</button>
          <button type="submit" class="btn-confirm" style="background:var(--accent)" onclick="saveCreateClient()">创建客户端</button>
        </div>
      </form>
    </div>
  </div>


  <!-- Edit Inbound Modal -->
  <div id="edit-inbound-overlay" class="hidden" onclick="if(event.target===this)closeEditInbound()">
    <div id="edit-inbound-dialog">
      <h3 class="modal-title">编辑入站</h3>
      <form id="edit-inbound-form" class="form-grid modal-form" onsubmit="return false">
        <div class="field-group">
          <label class="field-label" for="ei-remark">入站备注</label>
          <input id="ei-remark" placeholder="备注" required>
          <p class="field-help">用于列表识别，建议使用节点地区或用途。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="ei-protocol">协议</label>
          <select id="ei-protocol">
            <option value="vless">VLESS</option>
            <option value="vmess">VMess</option>
            <option value="trojan">Trojan</option>
            <option value="shadowsocks">Shadowsocks</option>
          </select>
          <p class="field-help">保存后会影响客户端链接格式。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="ei-port">监听端口</label>
          <input id="ei-port" type="number" min="1" max="65535" placeholder="端口" required>
          <p class="field-help">1-65535，需确保防火墙已放行。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="ei-network">传输</label>
          <select id="ei-network">
            <option value="tcp">TCP</option>
            <option value="ws">WebSocket</option>
            <option value="kcp">mKCP</option>
            <option value="grpc">gRPC</option>
            <option value="quic">QUIC</option>
            <option value="h2">HTTP/2</option>
            <option value="xhttp">XHTTP</option>
          </select>
          <p class="field-help">切换后会显示对应高级字段。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="ei-security">安全</label>
          <select id="ei-security">
            <option value="none">none</option>
            <option value="tls">tls</option>
            <option value="reality">reality</option>
          </select>
          <p class="field-help">TLS/REALITY 会显示证书或伪装参数。</p>
        </div>
        <div id="ei-dynamic-fields">
          <div id="ei-ws-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">WebSocket 设置</div>
            <div class="advanced-fieldset-copy">适合 CDN、反向代理或路径分流场景。</div>
            <label class="field-label" for="ei-ws-path">WebSocket</label>
            <input id="ei-ws-path" placeholder="WS Path (默认 /)">
            <input id="ei-ws-host" placeholder="WS Host (可选)">
            <p class="field-help">路径和 Host 用于 CDN 或反代场景。</p>
          </div>
          <div id="ei-grpc-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">gRPC 设置</div>
            <div class="advanced-fieldset-copy">用于 gRPC 传输的服务名，客户端需保持一致。</div>
            <label class="field-label" for="ei-grpc-service-name">gRPC ServiceName</label>
            <input id="ei-grpc-service-name" value="migate" placeholder="gRPC ServiceName">
            <p class="field-help">客户端需与服务端保持一致。</p>
          </div>
          <div id="ei-xhttp-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">XHTTP 设置</div>
            <div class="advanced-fieldset-copy">配置 XHTTP 路径与上传模式。</div>
            <label class="field-label" for="ei-xhttp-path">XHTTP</label>
            <input id="ei-xhttp-path" value="/" placeholder="XHTTP Path (默认 /)">
            <select id="ei-xhttp-mode">
              <option value="stream-one">stream-one</option>
              <option value="packet-up">packet-up</option>
              <option value="stream-up">stream-up</option>
            </select>
            <p class="field-help">选择 XHTTP 路径和上传模式。</p>
          </div>
          <div id="ei-reality-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">REALITY 设置</div>
            <div class="advanced-fieldset-copy">填写伪装目标、SNI 与短 ID，避免与客户端参数不一致。</div>
            <label class="field-label" for="ei-reality-dest">REALITY</label>
            <input id="ei-reality-dest" value="www.cloudflare.com:443" placeholder="目标 (dest)">
            <input id="ei-reality-server-names" value="www.cloudflare.com" placeholder="ServerNames (逗号分隔)">
            <input id="ei-reality-short-id" placeholder="ShortId (可选)">
            <input type="hidden" id="ei-reality-private-key">
            <p class="field-help">用于 REALITY 伪装目标、SNI 和短 ID。</p>
          </div>
          <div id="ei-ss-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">Shadowsocks 设置</div>
            <div class="advanced-fieldset-copy">选择客户端支持的加密方法。</div>
            <label class="field-label" for="ei-ss-method">Shadowsocks 加密</label>
            <select id="ei-ss-method">
              <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
              <option value="aes-256-gcm">aes-256-gcm</option>
              <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
            </select>
            <p class="field-help">选择与客户端兼容的加密方法。</p>
          </div>
          <div id="ei-tls-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">TLS 设置</div>
            <div class="advanced-fieldset-copy">填写证书和私钥路径，应用前会交给 Xray 校验。</div>
            <label class="field-label" for="ei-tls-cert-file">TLS 证书</label>
            <input id="ei-tls-cert-file" placeholder="TLS 证书路径 (如 /etc/.../fullchain.pem)">
            <input id="ei-tls-key-file" placeholder="TLS 密钥路径 (如 /etc/.../privkey.key)">
            <p class="field-help">保存后应用 Xray 前会由 Xray 校验证书路径。</p>
          </div>
        </div>
        <div class="form-actions modal-actions">
          <button type="button" class="btn-cancel" onclick="closeEditInbound()">取消</button>
          <button type="submit" class="btn-confirm" style="background:var(--accent)" onclick="saveEditInbound()">保存</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Edit Client Modal -->
  <div id="edit-client-overlay" class="hidden" onclick="if(event.target===this)closeEditClient()">
    <div id="edit-client-dialog">
      <h3 class="modal-title">编辑客户端</h3>
      <form id="edit-client-form" class="form-grid modal-form" onsubmit="return false">
        <div class="field-group span-2">
          <label class="field-label" for="ec-email">客户端标识</label>
          <input id="ec-email" placeholder="客户端标识，例如 user01" required>
          <p class="field-help">用于识别用户或设备，不影响 UUID。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="ec-traffic-limit">流量限额</label>
          <input id="ec-traffic-limit" type="number" min="0" placeholder="流量限额（字节，0=不限）">
          <p class="field-help">单位为字节，填 0 表示不限。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="ec-expiry-at">过期时间</label>
          <input id="ec-expiry-at" type="datetime-local">
          <p class="field-help">留空表示不过期。</p>
        </div>
        <div class="form-actions modal-actions">
          <button type="button" class="btn-cancel" onclick="closeEditClient()">取消</button>
          <button type="submit" class="btn-confirm" style="background:var(--accent)" onclick="saveEditClient()">保存</button>
        </div>
      </form>
    </div>
  </div>

  <div class="app-shell">
    <aside class="sidebar">
      <button id="sidebar-toggle" onclick="toggleSidebar()" aria-label="展开菜单">☰</button>
      <div class="brand">MiGate</div>
      <div class="subtitle">轻量单二进制面板，专注协议、客户端与 Xray 管理。</div>
      <nav>
        <a class="active" href="/">概览</a>
        <a href="/#inbounds">入站</a>
        <a href="/#clients">客户端</a>
        <a href="/#subscriptions">订阅</a>
        <a href="/#xray">Xray</a>
        <a href="/#settings">设置</a>
      </nav>
      <div class="account-panel" aria-label="当前账号">
        <div class="account-label">当前用户</div>
        <div id="current-username" class="account-name">加载中...</div>
        <div class="account-actions">
          <button id="login-button" class="secondary" onclick="window.location.href='/login'">登录</button>
          <button id="logout-button" class="secondary" onclick="logoutPanel()">登出</button>
          <button id="theme-toggle" class="secondary" onclick="toggleTheme()">深色模式</button>
        </div>
      </div>
    </aside>
    <div id="sidebar-overlay" onclick="closeSidebar()"></div>
    <main>
      <section id="overview" class="overview-grid" aria-label="概览指标">
        <div class="card panel"><div>入站</div><div id="inbound-count" class="metric">0</div><p>VLESS / VMess / Trojan / Shadowsocks</p></div>
        <div class="card panel"><div>客户端</div><div id="client-count" class="metric">0</div><p>活跃 / 总计</p></div>
        <div class="card panel"><div>总流量</div><div id="total-traffic" class="metric">0 B</div><p>所有客户端上行+下行累计</p></div>
        <div class="card panel"><div>Xray</div><div id="xray-status-metric" class="metric">检查中...</div><p>运行状态</p></div>
        <div class="overview-insights">
          <div class="overview-card">
            <div class="overview-card-title">运行概况</div>
            <div id="overview-health-summary" class="muted">正在读取入站、客户端与 Xray 状态...</div>
            <div id="overview-active-summary" class="overview-pill">活跃客户端 0 / 0</div>
          </div>
          <div class="overview-card">
            <div class="overview-card-title">协议分布</div>
            <div id="overview-protocol-breakdown" class="protocol-breakdown"></div>
          </div>
          <div class="overview-card">
            <div class="overview-card-title">快捷操作</div>
            <div id="overview-quick-actions" class="actions" style="margin-top:0">
              <button onclick="navigateTo('inbounds')">管理入站</button>
              <button class="secondary" onclick="navigateTo('clients')">管理客户端</button>
              <button class="secondary" onclick="navigateTo('xray')">查看 Xray</button>
            </div>
          </div>
        </div>
      </section>
      <section id="inbounds" class="card panel">
        <h2 class="section-heading">核心协议</h2>
        <div class="protocols">
          <div class="protocol"><strong>VLESS</strong><span>Reality / TLS 入站</span></div>
          <div class="protocol"><strong>VMess</strong><span>WebSocket / TLS 兼容</span></div>
          <div class="protocol"><strong>Trojan</strong><span>TLS 节点支持</span></div>
          <div class="protocol"><strong>Shadowsocks</strong><span>轻量转发协议</span></div>
        </div>
        <div class="actions">
          <button onclick="openCreateInbound()">新增入站</button>
          <button class="secondary" onclick="navigateTo('xray');setTimeout(previewXrayConfig,200)">生成 Xray 配置</button>
          <button class="secondary" onclick="navigateTo('subscriptions')">查看订阅</button>
        </div>
        <div id="inbound-list" class="list muted">正在加载入站...</div>
      </section>
      <section id="clients" class="card panel">
        <h2 class="section-title">客户端管理</h2>
        <p class="muted">选择入站 → 创建客户端 → 获取订阅链接</p>
        <div class="actions">
          <select id="client-inbound-select" onchange="loadClients()">
            <option value="">--选择入站--</option>
          </select>
          <button onclick="openCreateClient()">创建客户端</button>
        </div>
        <div id="client-list" class="list muted">选择一个入站以查看客户端...</div>
      </section>
      <section id="subscriptions" class="card panel">
        <h2 class="section-title">订阅管理</h2>
        <p class="muted" style="margin-bottom:16px">每个客户端自动生成订阅链接和分享链接，可在客户端列表中查看和复制。</p>
        <div id="subscription-info" style="background:rgba(148,163,184,.06); border-radius:16px; padding:20px; line-height:2">
          <div><strong>订阅格式</strong>：<code>/sub/{uuid}</code> — 返回对应协议的分享链接</div>
          <div><strong>支持协议</strong>：VLESS / VMess / Trojan / Shadowsocks</div>
          <div><strong>使用方式</strong>：将订阅链接填入 V2Ray / Clash Meta / Nekoray 等客户端</div>
        </div>
        <div class="list" style="margin-top:16px">
          <div id="sub-inbound-summary" class="empty-state"><div class="empty-state-title">正在加载订阅概况</div><div class="empty-state-copy">正在读取入站与客户端数据，用于生成订阅入口概览。</div></div>
        </div>
      </section>
      <section id="xray" class="card panel">
        <h2 class="section-title">Xray 管理</h2>
        <p class="muted" style="margin-bottom:16px">查看 Xray 服务状态，应用配置变更。</p>
        <div style="background:rgba(148,163,184,.06); border-radius:16px; padding:20px; margin-bottom:16px">
          <div><strong>状态</strong>：<span id="xray-status">未知</span></div>
          <div><strong>托管</strong>：<span id="xray-managed">-</span></div>
          <div><strong>服务</strong>：<span id="xray-service">xray</span></div>
        </div>
        <div class="action-toolbar xray-toolbar">
          <div class="toolbar-copy">
            <strong>配置操作</strong>
            <span>应用、预览与刷新统一集中在右侧操作区。</span>
          </div>
          <div class="toolbar-actions">
            <button onclick="fetchXrayStatus()">刷新状态</button>
            <button class="secondary" onclick="previewXrayConfig()">预览配置</button>
            <button class="secondary" onclick="applyXrayConfig()">应用配置</button>
          </div>
        </div>
        <div id="xray-result" class="notice-slot"></div>
        <div id="xray-config-preview" class="list muted" style="margin-top:12px;display:none"><pre id="xray-config-json" style="background:rgba(148,163,184,.06);border-radius:12px;padding:16px;font-size:12px;overflow-x:auto;white-space:pre-wrap;max-height:400px;overflow-y:auto"></pre></div>
      </section>
      <section id="settings" class="card panel">
        <h2 class="section-title">面板设置</h2>
        <p class="muted" style="margin-bottom:16px">编辑 panel.json 配置。修改面板端口或认证后需重启服务生效。</p>
        <form id="settings-form" class="form-grid" onsubmit="return false">
          <div class="field-group">
            <label class="field-label" for="set-panel-port">面板端口</label>
            <input id="set-panel-port" type="number" min="1" max="65535" placeholder="例如 9999" required>
            <p class="field-help">保存后需要重启 MiGate 服务才会切换监听端口。</p>
          </div>
          <div class="field-group">
            <label class="field-label" for="set-username">登录用户名</label>
            <input id="set-username" placeholder="admin">
            <p class="field-help">与密码同时配置时启用面板认证。</p>
          </div>
          <div class="field-group">
            <label class="field-label" for="set-password">登录密码</label>
            <input id="set-password" type="password" placeholder="留空不修改">
            <p class="field-help">留空会保留现有密码，不会清空配置。</p>
          </div>
          <div class="field-group">
            <label class="field-label" for="set-xray-config-path">Xray 配置目录</label>
            <input id="set-xray-config-path" placeholder="例如 /usr/local/migate">
            <p class="field-help">MiGate 会在该目录写入 xray.json。</p>
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="set-web-path">Web 基础路径</label>
            <input id="set-web-path" placeholder="例如 /">
            <p class="field-help">默认使用根路径；反代到子路径时再修改。</p>
          </div>
          <div class="action-toolbar settings-toolbar span-2">
            <div class="toolbar-copy">
              <strong>设置操作</strong>
              <span>保存配置后按需重启 MiGate 服务。</span>
            </div>
            <div class="toolbar-actions">
              <button type="button" class="secondary" onclick="loadSettings()">刷新</button>
              <button type="submit" onclick="saveSettings()">保存设置</button>
            </div>
          </div>
        </form>
        <div id="settings-status" class="notice-slot"></div>
      </section>
    </main>
  </div>
  <script>
    const inboundList = document.getElementById('inbound-list');
    const inboundCount = document.getElementById('inbound-count');
    const clientCount = document.getElementById('client-count');
    const totalTraffic = document.getElementById('total-traffic');
    const xrayStatusMetric = document.getElementById('xray-status-metric');

    function renderInbounds(inbounds) {
      inboundCount.textContent = String(inbounds.length);
      const allClients = inbounds.flatMap(i => i.clients || []);
      clientCount.textContent = String(allClients.length);
      // Compute total traffic
      const totalUp = allClients.reduce((s, c) => s + (c.up || 0), 0);
      const totalDown = allClients.reduce((s, c) => s + (c.down || 0), 0);
      totalTraffic.textContent = formatBytes(totalUp + totalDown);
      // Active clients (enabled + not expired + not over limit)
      const now = Math.floor(Date.now() / 1000);
      const active = allClients.filter(c => {
        if (!c.enabled) return false;
        if (c.expiry_at && c.expiry_at > 0 && c.expiry_at <= now) return false;
        if (c.traffic_limit && c.traffic_limit > 0 && (c.up||0)+(c.down||0) >= c.traffic_limit) return false;
        return true;
      }).length;
      // Show active/total in client count description
      const card = clientCount.closest('.card');
      const p = card ? card.querySelector('p') : null;
      if (p) p.textContent = active + ' / ' + allClients.length;
      renderOverviewInsights(inbounds, allClients, active);
      updateProtocolBreakdown(inbounds);
      if (inbounds.length === 0) {
        inboundList.className = 'list';
        inboundList.innerHTML = renderEmptyState('暂无入站', '先创建一个 VLESS / VMess / Trojan / Shadowsocks 节点；MiGate 会自动生成客户端与 Xray 配置。', [
          {label:'创建入站', onclick:"openCreateInbound()"},
          {label:'查看 Xray', onclick:"navigateTo('xray')", secondary:true}
        ]);
        return;
      }
      inboundList.className = 'list';
      inboundList.innerHTML = inbounds.map((inbound) => {
        const enabledClass = inbound.enabled ? 'enabled' : 'disabled';
        const enabledText = inbound.enabled ? 'Enabled' : 'Disabled';
        return '<div class="resource-row">' +
          '<div class="resource-main">' +
            '<div class="resource-title"><strong>' + escapeHtml(inbound.remark || '-') + '</strong><span class="status-badge ' + enabledClass + '">' + enabledText + '</span></div>' +
            '<div class="resource-meta"><span>' + escapeHtml(inbound.protocol) + '</span><span>:' + inbound.port + '</span><span>' + escapeHtml(inbound.network || 'tcp') + ' / ' + escapeHtml(inbound.security || 'none') + '</span><span>' + ((inbound.clients || []).length) + ' 客户端</span></div>' +
          '</div>' +
          '<div class="resource-actions">' +
            '<button class="icon-btn" onclick="editInbound(' + inbound.id + ')" title="编辑">Edit</button>' +
            '<button class="icon-btn" onclick="toggleInbound(' + inbound.id + ')" title="启用/禁用">' + (inbound.enabled ? 'ON' : 'OFF') + '</button>' +
            '<button class="danger-icon-btn" onclick="deleteInbound(' + inbound.id + ')" title="删除">DEL</button>' +
          '</div>' +
        '</div>';
      }).join('');
    }

    function renderOverviewInsights(inbounds, allClients, active) {
      const health = document.getElementById('overview-health-summary');
      const activeSummary = document.getElementById('overview-active-summary');
      const enabledInbounds = inbounds.filter(i => i.enabled).length;
      const disabledInbounds = inbounds.length - enabledInbounds;
      const limitedClients = allClients.filter(c => {
        const used = (c.up || 0) + (c.down || 0);
        return (c.traffic_limit || 0) > 0 && used >= c.traffic_limit;
      }).length;
      const expiredClients = allClients.filter(c => c.expiry_at && c.expiry_at > 0 && c.expiry_at <= Math.floor(Date.now() / 1000)).length;
      if (health) {
        health.textContent = inbounds.length === 0
          ? '还没有入站。建议先创建一个 VLESS/REALITY 或 TLS 入站，再添加客户端。'
          : '已启用 ' + enabledInbounds + ' 个入站，停用 ' + disabledInbounds + ' 个；受限客户端 ' + limitedClients + ' 个，过期客户端 ' + expiredClients + ' 个。';
      }
      if (activeSummary) {
        activeSummary.textContent = '活跃客户端 ' + active + ' / ' + allClients.length;
      }
    }

    function updateProtocolBreakdown(inbounds) {
      const el = document.getElementById('overview-protocol-breakdown');
      if (!el) return;
      const protocols = ['vless', 'vmess', 'trojan', 'shadowsocks'];
      const labels = {vless:'VLESS', vmess:'VMess', trojan:'Trojan', shadowsocks:'Shadowsocks'};
      const counts = protocols.reduce((acc, proto) => {
        acc[proto] = inbounds.filter(i => (i.protocol || '').toLowerCase() === proto).length;
        return acc;
      }, {});
      el.innerHTML = protocols.map(proto =>
        '<div class="protocol-breakdown-row"><span>' + labels[proto] + '</span><strong>' + counts[proto] + '</strong></div>'
      ).join('');
    }

    function escapeHtml(value) {
      return String(value || '').replace(/[&<>"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[char]));
    }

    function renderEmptyState(title, copy, actions) {
      const actionHtml = (actions || []).map((action) => {
        const cls = action.secondary ? ' class="secondary"' : '';
        return '<button' + cls + ' onclick="' + action.onclick + '">' + escapeHtml(action.label) + '</button>';
      }).join('');
      return '<div class="empty-state">' +
        '<div class="empty-state-title">' + escapeHtml(title) + '</div>' +
        '<div class="empty-state-copy">' + escapeHtml(copy) + '</div>' +
        (actionHtml ? '<div class="empty-state-actions">' + actionHtml + '</div>' : '') +
      '</div>';
    }

    function renderNotice(title, copy, type) {
      const cls = type ? ' ' + type : '';
      return '<div class="notice' + cls + '">' +
        '<div class="notice-title">' + escapeHtml(title) + '</div>' +
        '<div class="notice-copy">' + escapeHtml(copy || '') + '</div>' +
      '</div>';
    }

    async function loadInbounds() {
      const response = await fetch('/api/inbounds');
      const data = await response.json();
      renderInbounds(data.inbounds || []);
      // Fetch Xray status for overview
      try {
        const xr = await fetch('/api/xray/status');
        const xs = await xr.json();
        if (xs && xs.service !== undefined) {
          xrayStatusMetric.textContent = xs.service === 'running' ? '运行中' : (xs.service === 'stopped' ? '已停止' : xs.service);
        }
      } catch (e) {
        xrayStatusMetric.textContent = '无法连接';
      }
    }


    function preferredTheme() {
      const saved = localStorage.getItem('migate-theme');
      if (saved === 'dark' || saved === 'light') return saved;
      return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    function applyTheme(theme) {
      if (theme !== 'dark') theme = 'light';
      document.documentElement.dataset.theme = theme;
      localStorage.setItem('migate-theme', theme);
      const btn = document.getElementById('theme-toggle');
      if (btn) btn.textContent = theme === 'dark' ? '浅色模式' : '深色模式';
    }

    function toggleTheme() {
      applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    }

    async function loadSession() {
      try {
        const res = await fetch('/api/session');
        const session = await res.json();
        const name = document.getElementById('current-username');
        const loginBtn = document.getElementById('login-button');
        const logoutBtn = document.getElementById('logout-button');
        const authenticated = !!session.authenticated;
        if (name) name.textContent = session.username || (session.auth_enabled ? '未登录' : '未启用认证');
        if (loginBtn) loginBtn.style.display = authenticated ? 'none' : '';
        if (logoutBtn) logoutBtn.style.display = authenticated ? '' : 'none';
      } catch (e) {
        const name = document.getElementById('current-username');
        if (name) name.textContent = '无法读取用户';
      }
    }

    async function logoutPanel() {
      const res = await fetch('/api/logout', {method: 'POST'});
      if (!res.ok) { showToast('登出失败', 'error'); return; }
      showToast('已登出', 'success');
      window.location.href = '/login';
    }

    function toggleSidebar() {
      document.querySelector('.app-shell').classList.toggle('sidebar-open');
    }
    function closeSidebar() {
      document.querySelector('.app-shell').classList.remove('sidebar-open');
    }

    applyTheme(preferredTheme());
    loadSession();

    loadInbounds();

    // === Navigation section switching ===
    function currentSectionFromLocation() {
      const hash = window.location.hash.replace('#', '');
      return hash || 'overview';
    }

    function navigateTo(sectionId) {
      const validSections = ['overview', 'inbounds', 'clients', 'subscriptions', 'xray', 'settings'];
      if (!validSections.includes(sectionId)) sectionId = 'overview';
      document.querySelectorAll('main > section').forEach((el) => {
        const display = el.classList.contains('overview-grid') ? 'grid' : 'block';
        el.style.display = (el.id === sectionId) ? display : 'none';
      });
      document.querySelectorAll('nav a').forEach((a) => {
        const href = a.getAttribute('href');
        a.classList.toggle('active', (sectionId === 'overview' && href === '/') || href === '/#' + sectionId);
      });
      history.replaceState(null, '', sectionId === 'overview' ? '/' : '/#' + sectionId);
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
    window.addEventListener('hashchange', () => navigateTo(currentSectionFromLocation()));
    navigateTo(currentSectionFromLocation());

    async function loadClients() {
      const sel = document.getElementById('client-inbound-select');
      const list = document.getElementById('client-list');
      if (!sel.value) {
        list.className = 'list';
        list.innerHTML = renderEmptyState('选择入站', '先从上方下拉框选择一个入站，再查看、创建或编辑该入站下的客户端。');
        return;
      }
      const response = await fetch('/api/inbounds');
      const data = await response.json();
      const inbound = (data.inbounds || []).find(i => i.id === parseInt(sel.value));
      if (!inbound) {
        list.className = 'list';
        list.innerHTML = renderEmptyState('入站未找到', '这个入站可能已被删除，请刷新列表后重新选择。', [
          {label:'刷新入站', onclick:'populateInboundSelect();loadClients()'}
        ]);
        return;
      }
      renderClients(inbound, list);
    }

    function renderClients(inbound, list) {
      const subscriptionHost = window.location.host;
      const hostName = window.location.hostname;
      const clients = inbound.clients || [];
      if (clients.length === 0) {
        list.className = 'list';
        list.innerHTML = renderEmptyState('暂无客户端', '在当前入站下创建第一个客户端后，即可复制订阅或分享链接。', [
          {label:'创建客户端', onclick:"openCreateClient()"}
        ]);
        return;
      }
      list.className = 'list';
      list.innerHTML = clients.map(c => {
        const subUrl = window.location.protocol + '//' + subscriptionHost + '/sub/' + c.uuid;
        let shareLink;
        if (inbound.protocol === 'vmess') {
          var vmessData = {v:'2',ps:c.email,add:hostName,port:String(inbound.port),id:c.uuid,aid:'0',scy:'auto',net:inbound.network||'tcp',type:'none',host:'',path:'',tls:(inbound.security==='tls'||inbound.security==='reality')?'tls':''};
          try { shareLink = 'vmess://' + btoa(JSON.stringify(vmessData)); } catch(e) { shareLink = ''; }
        } else if (inbound.protocol === 'shadowsocks') {
          var userPass = '2022-blake3-aes-128-gcm:' + c.uuid;
          try { shareLink = 'ss://' + btoa(userPass) + '@' + hostName + ':' + inbound.port + '#' + escapeHtml(c.email); } catch(e) { shareLink = ''; }
        } else {
          var p = [];
          p.push('type=' + (inbound.network||'tcp'));
          p.push('security=' + (inbound.security||'none'));
          if (inbound.security === 'reality') {
            p.push('flow=xtls-rprx-vision');
            if (inbound.reality_server_names) p.push('sni=' + encodeURIComponent(inbound.reality_server_names));
            p.push('fp=chrome');
            if (inbound.reality_public_key) p.push('pbk=' + encodeURIComponent(inbound.reality_public_key));
            if (inbound.reality_short_id) p.push('sid=' + encodeURIComponent(inbound.reality_short_id));
          } else if (inbound.security === 'tls') {
            if (inbound.reality_server_names) p.push('sni=' + encodeURIComponent(inbound.reality_server_names));
            p.push('allowInsecure=1');
          }
          if (inbound.network === 'ws') {
            if (inbound.ws_path) p.push('path=' + encodeURIComponent(inbound.ws_path));
            if (inbound.ws_host) p.push('host=' + encodeURIComponent(inbound.ws_host));
          } else if (inbound.network === 'grpc') {
            if (inbound.grpc_service_name) p.push('serviceName=' + encodeURIComponent(inbound.grpc_service_name));
          } else if (inbound.network === 'xhttp') {
            if (inbound.xhttp_path) p.push('path=' + encodeURIComponent(inbound.xhttp_path));
            if (inbound.xhttp_mode) p.push('mode=' + encodeURIComponent(inbound.xhttp_mode));
          }
          shareLink = inbound.protocol + '://' + c.uuid + '@' + hostName + ':' + inbound.port + '?' + p.join('&') + '#' + escapeHtml(c.email);
        }
        const used = (c.up||0) + (c.down||0);
        const limit = c.traffic_limit || 0;
        const pct = limit > 0 ? Math.min(100, used / limit * 100) : 0;
        const isOverLimit = limit > 0 && used >= limit;
        const isExpired = c.expiry_at && c.expiry_at > 0 && c.expiry_at <= Math.floor(Date.now() / 1000);
        const expiredText = c.expiry_at && c.expiry_at > 0 ? new Date(c.expiry_at * 1000).toLocaleDateString() : '不限';
        const expireStyle = isExpired ? 'color:var(--danger);font-weight:500' : '';
        const trafficStyle = isOverLimit ? 'color:var(--danger)' : '';
        const badgeClass = c.enabled && !isExpired && !isOverLimit ? 'enabled' : 'disabled';
        const badgeText = c.enabled ? (isExpired ? 'Expired' : (isOverLimit ? 'Limited' : 'Enabled')) : 'Disabled';
        const fillClass = isOverLimit ? 'bar-high' : (pct >= 85 ? 'bar-mid' : 'bar-low');
        return '<div class="resource-row">' +
          '<div class="resource-main">' +
            '<div class="resource-title"><strong>' + escapeHtml(c.email) + '</strong><span class="status-badge ' + badgeClass + '">' + badgeText + '</span></div>' +
            '<div class="resource-meta">' +
              '<span class="mono">' + c.uuid.substring(0,8) + '…</span>' +
              '<span style="' + trafficStyle + '">' + formatBytes(used) + ' / ' + (limit > 0 ? formatBytes(limit) : '∞') + '</span>' +
              '<span style="' + expireStyle + '">到期 ' + expiredText + '</span>' +
              (limit > 0 ? '<span><div class="traffic-track"><div class="traffic-fill ' + fillClass + '" style="width:' + pct + '%"></div></div></span>' : '') +
            '</div>' +
          '</div>' +
          '<div class="resource-actions">' +
            '<button class="icon-btn" onclick="copySubUrl(' + htmlAttrString(subUrl) + ')" title="复制订阅链接">Sub</button>' +
            '<button class="icon-btn" onclick="copySubUrl(' + htmlAttrString(shareLink) + ')" title="复制分享链接">Link</button>' +
            '<button class="icon-btn" onclick="editClient(' + c.id + ',' + inbound.id + ')" title="编辑">Edit</button>' +
            '<button class="icon-btn" onclick="toggleClient(' + c.id + ')" title="启用/禁用">' + (c.enabled ? 'ON' : 'OFF') + '</button>' +
            '<button class="danger-icon-btn" onclick="deleteClient(' + inbound.id + ',' + c.id + ')" title="删除">DEL</button>' +
          '</div>' +
        '</div>';
      }).join('');
    }

    function formatBytes(bytes) {
      if (!bytes || bytes === 0) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(1024));
      return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
    }

    function jsString(value) {
      return JSON.stringify(String(value || ''));
    }

    function htmlAttrString(value) {
      return jsString(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function copyTextFallback(text) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      try {
        return document.execCommand('copy');
      } finally {
        document.body.removeChild(ta);
      }
    }

    async function copySubUrl(text) {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
        } else if (!copyTextFallback(text)) {
          throw new Error('copy fallback failed');
        }
        showToast('已复制链接', 'success');
      } catch (e) {
        try {
          if (copyTextFallback(text)) {
            showToast('已复制链接', 'success');
            return;
          }
        } catch (_) {}
        showToast('复制失败，请手动复制', 'error');
      }
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

    async function populateInboundSelect(selectedInboundId) {
      const sel = document.getElementById('client-inbound-select');
      const keep = selectedInboundId !== undefined && selectedInboundId !== null ? String(selectedInboundId) : sel.value;
      const response = await fetch('/api/inbounds');
      const data = await response.json();
      const inbounds = data.inbounds || [];
      sel.innerHTML = '<option value="">--选择入站--</option>' +
        inbounds.map(i => '<option value="' + i.id + '">' + escapeHtml(i.remark) + ' (' + i.protocol + ' :' + i.port + ')</option>').join('');
      if (keep && inbounds.some(i => String(i.id) === keep)) {
        sel.value = keep;
      }
    }

    async function refreshPanelData(selectedInboundId) {
      await loadInbounds();
      await populateInboundSelect(selectedInboundId);
      await loadClients();
      await loadSubSummary();
    }

    // === Edit & toggle functions ===
    let _editingInboundId = null;
    let _editingClientData = null;

    function eiUpdateDynamicFields() {
      const proto = document.getElementById('ei-protocol').value;
      const net = document.getElementById('ei-network').value;
      const sec = document.getElementById('ei-security').value;
      document.getElementById('ei-ws-settings').classList.toggle('hidden', net !== 'ws' && net !== 'h2');
      document.getElementById('ei-grpc-settings').classList.toggle('hidden', net !== 'grpc');
      document.getElementById('ei-xhttp-settings').classList.toggle('hidden', net !== 'xhttp');
      document.getElementById('ei-reality-settings').classList.toggle('hidden', sec !== 'reality');
      document.getElementById('ei-ss-settings').classList.toggle('hidden', proto !== 'shadowsocks');
      document.getElementById('ei-tls-settings').classList.toggle('hidden', sec !== 'tls');
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
      document.getElementById('ei-grpc-service-name').value = inbound.grpc_service_name || 'migate';
      document.getElementById('ei-xhttp-path').value = inbound.xhttp_path || '/';
      document.getElementById('ei-xhttp-mode').value = inbound.xhttp_mode || 'stream-one';
      document.getElementById('ei-reality-dest').value = inbound.reality_dest || '';
      document.getElementById('ei-reality-server-names').value = inbound.reality_server_names || '';
      document.getElementById('ei-reality-short-id').value = inbound.reality_short_id || '';
      document.getElementById('ei-reality-private-key').value = inbound.reality_private_key || '';
      document.getElementById('ei-ss-method').value = inbound.ss_method || '2022-blake3-aes-128-gcm';
      document.getElementById('ei-tls-cert-file').value = inbound.tls_cert_file || '';
      document.getElementById('ei-tls-key-file').value = inbound.tls_key_file || '';
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
        grpc_service_name: document.getElementById('ei-grpc-service-name').value,
        xhttp_path: document.getElementById('ei-xhttp-path').value,
        xhttp_mode: document.getElementById('ei-xhttp-mode').value,
        reality_dest: document.getElementById('ei-reality-dest').value,
        reality_server_names: document.getElementById('ei-reality-server-names').value,
        reality_short_id: document.getElementById('ei-reality-short-id').value,
        reality_private_key: document.getElementById('ei-reality-private-key').value,
        ss_method: document.getElementById('ei-ss-method').value,
        tls_cert_file: document.getElementById('ei-tls-cert-file').value,
        tls_key_file: document.getElementById('ei-tls-key-file').value,
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
      inbound.enabled = !inbound.enabled;
      const res = await fetch('/api/inbounds/' + id + '/enabled', {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: inbound.enabled})
      });
      if (!res.ok) {
        showToast('开关入站失败', 'error');
        return;
      }
      showToast('入站 ' + (inbound.enabled ? '已启用' : '已禁用'), 'success');
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
      client.enabled = !client.enabled;
      const res = await fetch('/api/inbounds/' + inbound.id + '/clients/' + id + '/enabled', {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: client.enabled})
      });
      if (!res.ok) {
        showToast('开关客户端失败', 'error');
        return;
      }
      showToast('客户端 ' + (client.enabled ? '已启用' : '已禁用'), 'success');
      await loadClients();
      const inboundResponse = await fetch('/api/inbounds');
      const inboundData = await inboundResponse.json();
      renderInbounds(inboundData.inbounds || []);
    }

    function openCreateClient() {
      const sel = document.getElementById('client-inbound-select');
      if (!sel.value) {
        showToast('请先选择一个入站', 'error');
        return;
      }
      const formEl = document.getElementById('create-client-form');
      formEl.reset();
      document.getElementById('create-client-overlay').classList.remove('hidden');
      document.getElementById('client-email').focus();
    }
    function closeCreateClient() {
      document.getElementById('create-client-overlay').classList.add('hidden');
    }
    async function saveCreateClient() {
      const formEl = document.getElementById('create-client-form');
      const sel = document.getElementById('client-inbound-select');
      if (!sel.value) {
        showToast('请先选择一个入站', 'error');
        closeCreateClient();
        return;
      }
      const selectedInboundId = sel.value;
      const form = new FormData(formEl);
      const email = form.get('email');
      if (!email) { showToast('请输入客户端标识', 'error'); return; }
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
      formEl.reset();
      closeCreateClient();
      showToast('客户端创建成功', 'success');
      await refreshPanelData(selectedInboundId);
    }

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
      const proto = document.getElementById('inbound-protocol').value;
      const net = document.getElementById('inbound-network').value;
      const sec = document.getElementById('inbound-security').value;
      document.getElementById('ws-settings').classList.toggle('hidden', net !== 'ws' && net !== 'h2');
      document.getElementById('grpc-settings').classList.toggle('hidden', net !== 'grpc');
      document.getElementById('xhttp-settings').classList.toggle('hidden', net !== 'xhttp');
      document.getElementById('reality-settings').classList.toggle('hidden', sec !== 'reality');
      document.getElementById('ss-settings').classList.toggle('hidden', proto !== 'shadowsocks');
      document.getElementById('tls-settings').classList.toggle('hidden', sec !== 'tls');
    }

    function openCreateInbound() {
      const formEl = document.getElementById('create-inbound-form');
      formEl.reset();
      document.getElementById('inbound-network').value = 'tcp';
      document.getElementById('inbound-security').value = 'none';
      updateDynamicFields();
      document.getElementById('create-inbound-overlay').classList.remove('hidden');
      document.getElementById('inbound-remark').focus();
    }
    function closeCreateInbound() {
      document.getElementById('create-inbound-overlay').classList.add('hidden');
      // Hide and reset initial client fields on close
      document.getElementById('init-client-fields').classList.add('hidden');
      document.querySelector('#create-inbound-dialog .chevron').textContent = '\u25B6';
    }
    function toggleInitClient(el) {
      const fields = document.getElementById('init-client-fields');
      const chevron = el.querySelector('.chevron');
      const isHidden = fields.classList.contains('hidden');
      fields.classList.toggle('hidden');
      chevron.textContent = isHidden ? '\u25BC' : '\u25B6';
    }
    async function saveCreateInbound() {
      const formEl = document.getElementById('create-inbound-form');
      const form = new FormData(formEl);
      const payload = Object.fromEntries(form.entries());
      payload.port = Number(payload.port);
      if (!payload.remark || !payload.port) { showToast('请填写备注和端口', 'error'); return; }
      // Pack initial client if email is provided
      const initEmail = document.getElementById('init-client-email').value.trim();
      if (initEmail) {
        payload.initial_client = {
          email: initEmail,
          traffic_limit: Number(document.getElementById('init-client-traffic').value || 0)
        };
      }
      delete payload.init_email;
      delete payload.init_traffic;
      const response = await fetch('/api/inbounds', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
      if (!response.ok) {
        showToast('创建入站失败', 'error');
        return;
      }
      formEl.reset();
      closeCreateInbound();
      showToast('入站创建成功', 'success');
      await refreshPanelData();
    }

    document.getElementById('inbound-protocol').addEventListener('change', updateDynamicFields);
    document.getElementById('inbound-network').addEventListener('change', updateDynamicFields);
    document.getElementById('inbound-security').addEventListener('change', updateDynamicFields);
    updateDynamicFields();

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
      document.getElementById('xray-result').innerHTML = renderNotice('正在应用', '正在写入 xray.json、执行配置校验并尝试重启 Xray。');
      try {
        const res = await fetch('/api/xray/apply', {method: 'POST'});
        const data = await res.json();
        const commands = data.commands_executed && data.commands_executed.length ? '\n' + data.commands_executed.join('\n') : '';
        document.getElementById('xray-result').innerHTML = renderNotice('应用完成', '状态：' + (data.status || '完成') + commands, 'success');
        showToast('配置已应用', 'success');
        await fetchXrayStatus();
      } catch (e) {
        document.getElementById('xray-result').innerHTML = renderNotice('应用失败', '请检查 Xray 配置目录、xray 命令和 systemd 服务状态。', 'error');
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
          el.innerHTML = renderEmptyState('正在加载订阅概况', '还没有可生成订阅的入站。请先创建入站和客户端，再回到这里查看订阅概览。', [
            {label:'去创建入站', onclick:"navigateTo('inbounds')"}
          ]);
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
          document.getElementById('settings-status').innerHTML = renderNotice('数据库', data.database_path + (data.has_password ? ' | 密码已设置' : ' | 无密码'), 'success');
        }
      } catch (e) {
        document.getElementById('settings-status').innerHTML = renderNotice('设置不可用', '需要在 panel.json 配置文件下运行，或检查配置目录是否已传入。', 'error');
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
