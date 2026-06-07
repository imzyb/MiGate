package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/scheduler"
	"github.com/imzyb/MiGate/internal/singbox"
	"github.com/imzyb/MiGate/internal/vpngate"
	"github.com/imzyb/MiGate/internal/xray"
)

var validDomain = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
var validEmail = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type Store interface {
	ListInbounds(ctx context.Context) ([]db.Inbound, error)
	CreateInbound(ctx context.Context, params db.CreateInboundParams) (db.Inbound, error)
	ListOutbounds(ctx context.Context) ([]db.Outbound, error)
	CreateOutbound(ctx context.Context, params db.CreateOutboundParams) (db.Outbound, error)
	UpdateOutbound(ctx context.Context, id int64, params db.UpdateOutboundParams) (db.Outbound, error)
	DeleteOutbound(ctx context.Context, id int64) error
	ReorderOutbounds(ctx context.Context, ids []int64) error
	ListRoutingRules(ctx context.Context) ([]db.RoutingRule, error)
	CreateRoutingRule(ctx context.Context, params db.CreateRoutingRuleParams) (db.RoutingRule, error)
	UpdateRoutingRule(ctx context.Context, id int64, params db.UpdateRoutingRuleParams) (db.RoutingRule, error)
	DeleteRoutingRule(ctx context.Context, id int64) error
	ReorderRoutingRules(ctx context.Context, ids []int64) error
	CreateClient(ctx context.Context, params db.CreateClientParams) (db.Client, error)
	DeleteInbound(ctx context.Context, id int64) error
	DeleteClient(ctx context.Context, id int64) error
	UpdateInbound(ctx context.Context, id int64, params db.UpdateInboundParams) (db.Inbound, error)
	UpdateClient(ctx context.Context, id int64, params db.UpdateClientParams) (db.Client, error)
	SetInboundEnabled(ctx context.Context, id int64, enabled bool) (db.Inbound, error)
	SetOutboundEnabled(ctx context.Context, id int64, enabled bool) (db.Outbound, error)
	SetClientEnabled(ctx context.Context, inboundID int64, id int64, enabled bool) (db.Client, error)
	ResetClientTraffic(ctx context.Context, id int64) (db.Client, error)
}

type XrayController interface {
	Status(ctx context.Context) XrayStatus
	Apply(ctx context.Context) XrayApplyResult
	Version(ctx context.Context) string
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
	ErrorOutput      string   `json:"error_output,omitempty"`
}

type defaultXrayController struct{}

func (defaultXrayController) Status(ctx context.Context) XrayStatus {
	return XrayStatus{Service: "xray", Status: "unknown", Managed: false, CommandsExecuted: []string{}}
}

func (defaultXrayController) Apply(ctx context.Context) XrayApplyResult {
	return XrayApplyResult{Status: "not_managed"}
}

// xrayApplyerAdapter adapts XrayController to scheduler.XrayApplyer.
type xrayApplyerAdapter struct {
	ctrl XrayController
}

func (a *xrayApplyerAdapter) Apply(ctx context.Context) error {
	res := a.ctrl.Apply(ctx)
	if res.Status == "applied" {
		return nil
	}
	if res.ErrorOutput != "" {
		return fmt.Errorf("apply failed: %s", res.ErrorOutput)
	}
	return fmt.Errorf("apply failed: status=%s", res.Status)
}

// NewXrayApplyer wraps an XrayController as a scheduler.XrayApplyer.
func NewXrayApplyer(ctrl XrayController) scheduler.XrayApplyer {
	return &xrayApplyerAdapter{ctrl: ctrl}
}

func (defaultXrayController) Version(ctx context.Context) string { return "" }

type routerConfig struct {
	store          Store
	xrayController XrayController
	authEnabled    bool
	authUsername   string
	authPassword   string
	sessionSecret  []byte
	configDir      string
	version        string
	basePath       string
	vpnGateFetcher VPNGateFetcher
	statsClient    xray.StatsClient
	healthScheduler *scheduler.VPNGateHealthScheduler
}

type VPNGateFetcher interface {
	FetchServers() ([]VPNGateServer, error)
}

// VPNGateServer is the public type exposed to the web package.
type VPNGateServer struct {
	HostName     string `json:"hostname"`
	IP           string `json:"ip"`
	Score        int    `json:"score"`
	Ping         int    `json:"ping"`
	Speed        int64  `json:"speed"`
	CountryLong  string `json:"country_long"`
	CountryShort string `json:"country_short"`
	NumSessions  int    `json:"num_sessions"`
	Uptime       int64  `json:"uptime"`
	TotalUsers   int64  `json:"total_users"`
	TotalTraffic int64  `json:"total_traffic"`
	LogType      string `json:"log_type"`
	Operator     string `json:"operator"`
	Message      string `json:"message"`
	ServerType   string `json:"server_type"`
}

// classifyVPNGateType derives a type label from the operator string.
func classifyVPNGateType(operator string) string {
	op := strings.ToLower(operator)
	bizKeywords := []string{"aws", "amazon", "digitalocean", "vultr", "hetzner",
		"contabo", "linode", "ovh", "scaleway", "netcup", "leaseweb",
		"microsoft", "azure", "google", "gcp", "oracle", "rackspace",
		"ionos", "upcloud", "alibaba", "tencent", "vps", "hosting",
		"dedicated", "cloud", "datacenter", "server", "colocation",
		"inc", "llc", "ltd", "gmbh", "sarl"}
	for _, kw := range bizKeywords {
		if strings.Contains(op, kw) {
			return "商宽"
		}
	}
	return "家宽"
}

type Option func(*routerConfig)

func WithStore(store Store) Option {
	return func(cfg *routerConfig) {
		cfg.store = store
	}
}

func WithVersion(version string) Option {
	return func(cfg *routerConfig) {
		cfg.version = version
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

func WithBasePath(basePath string) Option {
	return func(cfg *routerConfig) {
		cfg.basePath = normalizeBasePath(basePath)
	}
}

func WithVPNGateFetcher(fetcher VPNGateFetcher) Option {
	return func(cfg *routerConfig) {
		cfg.vpnGateFetcher = fetcher
	}
}

// WithHealthScheduler sets the VPN Gate auto-health scheduler for status reporting.
func WithHealthScheduler(scheduler *scheduler.VPNGateHealthScheduler) Option {
	return func(cfg *routerConfig) {
		cfg.healthScheduler = scheduler
	}
}

// WithStatsClient sets the stats client for traffic statistics.
func WithStatsClient(client xray.StatsClient) Option {
	return func(cfg *routerConfig) {
		cfg.statsClient = client
	}
}

func NewRouter(options ...Option) http.Handler {
	cfg := routerConfig{
		xrayController: defaultXrayController{},
	}
	for _, option := range options {
		option(&cfg)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", panelHandler)
	mux.HandleFunc("/login", loginHandler(&cfg))
	mux.HandleFunc("/api/login", loginHandler(&cfg))
	mux.HandleFunc("/api/logout", logoutHandler(&cfg))
	mux.HandleFunc("/api/session", sessionHandler(&cfg))
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/inbounds", inboundsHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/inbounds/", inboundChildrenHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/outbounds", outboundsHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/outbounds/", outboundChildrenHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/routing-rules", routingRulesHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/routing-rules/", routingRuleChildrenHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/stats", statsHandler(cfg.store, cfg.statsClient))
	mux.HandleFunc("/api/xray/config", xrayConfigHandler(cfg.store))
	mux.HandleFunc("/api/xray/status", xrayStatusHandler(cfg.xrayController))
	mux.HandleFunc("/api/xray/apply", xrayApplyHandler(cfg.xrayController, cfg.store))
	mux.HandleFunc("/api/xray/logs", xrayLogsHandler())
	mux.HandleFunc("/api/xray/version", xrayVersionHandler(cfg.xrayController))
	mux.HandleFunc("/api/cert/status", certStatusHandler(&cfg))
	mux.HandleFunc("/api/cert/issue", certIssueHandler(&cfg))
	mux.HandleFunc("/api/settings", settingsHandler(&cfg))
	mux.HandleFunc("/api/restart", restartHandler())
	mux.HandleFunc("/api/service/status", serviceStatusHandler())
	mux.HandleFunc("/api/version", versionHandler(cfg.version))
	mux.HandleFunc("/api/vpngate/servers", vpngateServersHandler(&cfg))
	mux.HandleFunc("/api/vpngate/import", vpngateImportHandler(&cfg))
	mux.HandleFunc("/api/vpngate/probe", vpngateProbeHandler())
	mux.HandleFunc("/api/vpngate/outbounds/health", vpngateOutboundHealthHandler(cfg.store))
	mux.HandleFunc("/api/vpngate/auto-health/status", vpngateAutoHealthStatusHandler(&cfg))
	mux.HandleFunc("/api/singbox/status", singboxStatusHandler())
	mux.HandleFunc("/api/singbox/apply", singboxApplyHandler(cfg.store))
	mux.HandleFunc("/sub/", subscriptionHandler(cfg.store))
	handler := authMiddleware(mux, &cfg)
	if cfg.basePath != "" {
		return basePathMiddleware(handler, cfg.basePath)
	}
	return handler
}

func normalizeBasePath(basePath string) string {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" || basePath == "/" {
		return ""
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	return strings.TrimRight(basePath, "/")
}

func basePathMiddleware(next http.Handler, basePath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != basePath && !strings.HasPrefix(r.URL.Path, basePath+"/") {
			http.NotFound(w, r)
			return
		}
		cloned := r.Clone(r.Context())
		cloned.URL.Path = strings.TrimPrefix(r.URL.Path, basePath)
		if cloned.URL.Path == "" {
			cloned.URL.Path = "/"
		}
		cloned.URL.RawPath = ""
		next.ServeHTTP(w, cloned)
	})
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
			"auth_enabled":  cfg.authEnabled,
			"authenticated": false,
			"username":      "",
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

func outboundsHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			outbounds, err := store.ListOutbounds(r.Context())
			if err != nil {
				http.Error(w, `{"error":"list_outbounds_failed"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(outbounds)
		case http.MethodPost:
			var params db.CreateOutboundParams
			if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
				http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
				return
			}
			outbound, err := store.CreateOutbound(r.Context(), params)
			if err != nil {
				http.Error(w, `{"error":"create_outbound_failed"}`, http.StatusBadRequest)
				return
			}
			applyResult := ctrl.Apply(r.Context())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"outbound": outbound, "xray": applyResult})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func pingOutbound(address string, port int) map[string]interface{} {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return map[string]interface{}{"latency": -1, "error": err.Error()}
	}
	start := time.Now()
	// Send a SOCKS5 handshake greeting to measure round-trip
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte{5, 1, 0})
	var buf [1]byte
	_, _ = conn.Read(buf[:])
	latency := time.Since(start).Milliseconds()
	_ = conn.Close()
	return map[string]interface{}{"latency": latency}
}

func outboundChildrenHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/outbounds/")
		// Handle /api/outbounds/reorder
		if path == "reorder" {
			// ...existing reorder handler...
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				IDs []int64 `json:"ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
				http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
				return
			}
			if err := store.ReorderOutbounds(r.Context(), req.IDs); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "reorder_failed")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"reordered"}`))
			return
		}
		// Handle /api/outbounds/speedtest-all
		if path == "speedtest-all" {
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			obs, err := store.ListOutbounds(r.Context())
			if err != nil {
				http.Error(w, `{"error":"load_failed"}`, http.StatusInternalServerError)
				return
			}
			results := make(map[int64]map[string]interface{})
			var mu sync.Mutex
			var wg sync.WaitGroup
			for _, ob := range obs {
				if ob.Protocol == "freedom" || ob.Protocol == "blackhole" || ob.Address == "" {
					continue
				}
				wg.Add(1)
				go func(o db.Outbound) {
					defer wg.Done()
					r := pingOutbound(o.Address, o.Port)
					mu.Lock()
					results[o.ID] = r
					mu.Unlock()
				}(ob)
			}
			wg.Wait()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(results)
			return
		}
		idStr := strings.TrimSuffix(path, "/")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error":"invalid_id"}`, http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var params db.UpdateOutboundParams
			if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
				http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
				return
			}
			outbound, err := store.UpdateOutbound(r.Context(), id, params)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
				} else {
					http.Error(w, `{"error":"update_failed"}`, http.StatusBadRequest)
				}
				return
			}
			applyResult := ctrl.Apply(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"outbound": outbound, "xray": applyResult})
		case http.MethodDelete:
			err := store.DeleteOutbound(r.Context(), id)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
				} else {
					http.Error(w, `{"error":"delete_failed"}`, http.StatusInternalServerError)
				}
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func routingRulesHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			rules, err := store.ListRoutingRules(r.Context())
			if err != nil {
				http.Error(w, `{"error":"list_failed"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rules)
		case http.MethodPost:
			var params db.CreateRoutingRuleParams
			if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
				http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
				return
			}
			rule, err := store.CreateRoutingRule(r.Context(), params)
			if err != nil {
				http.Error(w, `{"error":"create_failed"}`, http.StatusBadRequest)
				return
			}
			applyResult := ctrl.Apply(r.Context())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"rule": rule, "xray": applyResult})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func routingRuleChildrenHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/routing-rules/")
		if path == "reorder" {
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				IDs []int64 `json:"ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
				http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
				return
			}
			if err := store.ReorderRoutingRules(r.Context(), req.IDs); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "reorder_failed")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"reordered"}`))
			return
		}
		idStr := strings.TrimSuffix(path, "/")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error":"invalid_id"}`, http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var params db.UpdateRoutingRuleParams
			if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
				http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
				return
			}
			rule, err := store.UpdateRoutingRule(r.Context(), id, params)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
				} else {
					http.Error(w, `{"error":"update_failed"}`, http.StatusBadRequest)
				}
				return
			}
			applyResult := ctrl.Apply(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"rule": rule, "xray": applyResult})
		case http.MethodDelete:
			err := store.DeleteRoutingRule(r.Context(), id)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
				} else {
					http.Error(w, `{"error":"delete_failed"}`, http.StatusInternalServerError)
				}
				return
			}
			applyResult := ctrl.Apply(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "deleted", "xray": applyResult})
		case http.MethodGet:
			if strings.HasSuffix(r.URL.Path, "/ping") {
				idStr := strings.TrimSuffix(path, "/ping")
				obID, err := strconv.ParseInt(strings.TrimSpace(idStr), 10, 64)
				if err != nil {
					http.Error(w, `{"error":"invalid_id"}`, http.StatusBadRequest)
					return
				}
				// Re-fetch the outbound to get address:port
				outbounds, err := store.ListOutbounds(r.Context())
				if err != nil {
					http.Error(w, `{"error":"list_failed"}`, http.StatusInternalServerError)
					return
				}
				var target *db.Outbound
				for i := range outbounds {
					if outbounds[i].ID == obID {
						target = &outbounds[i]
						break
					}
				}
				if target == nil || !target.Enabled || target.Protocol == "freedom" || target.Protocol == "blackhole" {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"latency": -1, "error": "not_pingable"})
					return
				}
				result := pingOutbound(target.Address, target.Port)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(result)
				return
			}
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func statsHandler(store Store, statsClient xray.StatsClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		inb, _ := store.ListInbounds(ctx)
		obs, _ := store.ListOutbounds(ctx)
		rules, _ := store.ListRoutingRules(ctx)
		var clientCount int
		for _, in := range inb {
			clientCount += len(in.Clients)
		}
		totalObs := len(obs)
		enabledObs := 0
		for _, ob := range obs {
			if ob.Enabled {
				enabledObs++
			}
		}
		totalRules := len(rules)
		enabledRules := 0
		for _, r := range rules {
			if r.Enabled {
				enabledRules++
			}
		}

		// Get per-client traffic stats if statsClient is available
		clientStats := make(map[string]*xray.ClientStats)
		if statsClient != nil {
			stats, _ := statsClient.QueryAllStats(ctx)
			clientStats = stats
		}

		// Build client traffic list from DB + stats
		var clientList []map[string]interface{}
		for _, in := range inb {
			for _, c := range in.Clients {
				info := map[string]interface{}{
					"id":            c.ID,
					"inbound_id":    c.InboundID,
					"email":         c.Email,
					"enabled":       c.Enabled,
					"up":            c.Up,
					"down":          c.Down,
					"traffic_limit": c.TrafficLimit,
					"expiry_at":     c.ExpiryAt,
				}
				// Override with live stats if available
				if liveStats, ok := clientStats[c.Email]; ok {
					info["up"] = liveStats.Uplink
					info["down"] = liveStats.Downlink
				}
				clientList = append(clientList, info)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"inbounds":              len(inb),
			"clients":               clientCount,
			"client_details":        clientList,
			"outbounds":             totalObs,
			"outbounds_enabled":     enabledObs,
			"routing_rules":         totalRules,
			"routing_rules_enabled": enabledRules,
		})
	}
}

func inboundsHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listInbounds(w, r, store)
		case http.MethodPost:
			createInbound(w, r, store)
			applyXrayAsync(ctrl)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func applyXrayAsync(ctrl XrayController) {
	go func() {
		result := ctrl.Apply(context.Background())
		if strings.HasPrefix(result.Status, "failed") {
			log.Printf("xray apply failed: status=%s service=%s commands=%v error=%s", result.Status, result.Service, result.CommandsExecuted, result.ErrorOutput)
		}
	}()
}

func writeJSONError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
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
	// Port conflict check
	if payload.Port > 0 {
		existing, _ := store.ListInbounds(r.Context())
		for _, ib := range existing {
			if ib.Port == payload.Port {
				http.Error(w, `{"error":"port_conflict","message":"端口 `+strconv.FormatInt(int64(ib.Port), 10)+` 已被入站 `+strconv.FormatInt(ib.ID, 10)+` 使用"}`, http.StatusConflict)
				return
			}
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
			if len(parts) == 4 && parts[1] == "clients" && parts[3] == "reset-traffic" {
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
				resetClientTraffic(w, r, store, inboundID, clientID)
				applyXrayAsync(ctrl)
			} else if len(parts) != 2 || parts[1] != "clients" {
				http.NotFound(w, r)
				return
			} else {
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				createClient(w, r, store, inboundID)
				applyXrayAsync(ctrl)
			}
		case http.MethodPatch:
			if len(parts) == 2 && parts[1] == "enabled" {
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				patchInboundEnabled(w, r, store, inboundID)
				applyXrayAsync(ctrl)
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
				applyXrayAsync(ctrl)
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
				applyXrayAsync(ctrl)
			} else if len(parts) == 3 && parts[1] == "clients" {
				// PUT /api/inbounds/{id}/clients/{clientId}
				clientID, err := strconv.ParseInt(parts[2], 10, 64)
				if err != nil || clientID <= 0 {
					http.NotFound(w, r)
					return
				}
				updateClient(w, r, store, clientID)
				applyXrayAsync(ctrl)
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
				applyXrayAsync(ctrl)
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
				applyXrayAsync(ctrl)
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
	// Port conflict check (exclude current inbound)
	if payload.Port > 0 {
		existing, _ := store.ListInbounds(r.Context())
		for _, ib := range existing {
			if ib.ID != inboundID && ib.Port == payload.Port {
				http.Error(w, `{"error":"port_conflict","message":"端口 `+strconv.FormatInt(int64(ib.Port), 10)+` 已被入站 `+strconv.FormatInt(ib.ID, 10)+` 使用"}`, http.StatusConflict)
				return
			}
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

func resetClientTraffic(w http.ResponseWriter, r *http.Request, store Store, inboundID, clientID int64) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	updated, err := store.ResetClientTraffic(r.Context(), clientID)
	if err != nil {
		http.Error(w, `{"error":"reset_traffic_failed"}`, http.StatusNotFound)
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
		outbounds := []db.Outbound{}
		rules := []db.RoutingRule{}
		if store != nil {
			if loaded, err := store.ListInbounds(r.Context()); err == nil {
				inbounds = loaded
			}
			if loaded, err := store.ListOutbounds(r.Context()); err == nil {
				outbounds = loaded
			}
			if loaded, err := store.ListRoutingRules(r.Context()); err == nil {
				rules = loaded
			}
		}
		config, err := xray.BuildConfigWithOutbounds(inbounds, outbounds, rules)
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

func xrayApplyHandler(controller XrayController, store Store) http.HandlerFunc {
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

		// 1. Apply Xray config
		xrayResult := controller.Apply(r.Context())

		// 2. Apply sing-box config if sing-box supported inbounds exist
		singboxResult := map[string]interface{}{
			"applied": false,
			"reason":  "not_needed",
		}
		if store != nil && singbox.IsInstalled() {
			inbounds, err := store.ListInbounds(r.Context())
			if err == nil {
				hasSingboxInbound := false
				for _, ib := range inbounds {
					if ib.Enabled {
						switch ib.Protocol {
						case "hysteria2", "tuic", "wireguard", "shadowtls":
							hasSingboxInbound = true
							break
						}
					}
				}
				if hasSingboxInbound {
					cfg := singbox.BuildConfig(inbounds)
					if _, err := os.Stat(singbox.CertFile); os.IsNotExist(err) {
						_ = singbox.GenerateSelfSignedCert()
					}
					raw, mErr := json.MarshalIndent(cfg, "", "  ")
					if mErr == nil {
						_ = os.WriteFile(singbox.DefaultConfigPath, raw, 0644)
					}
					applyErr := singbox.Apply()
					if applyErr != nil {
						singboxResult = map[string]interface{}{
							"applied": false,
							"error":   applyErr.Error(),
						}
					} else {
						singboxResult = map[string]interface{}{
							"applied":  true,
							"inbounds": len(cfg.Inbounds),
						}
					}
				}
			}
		} else if store == nil {
			singboxResult["reason"] = "no_store"
		} else {
			singboxResult["reason"] = "singbox_not_installed"
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"xray":    xrayResult,
			"singbox": singboxResult,
		})
	}
}

func xrayLogsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		lines := r.URL.Query().Get("lines")
		if lines == "" {
			lines = "50"
		}
		if n, err := strconv.Atoi(lines); err != nil || n < 1 {
			lines = "50"
		}
		out, err := exec.Command("journalctl", "-u", "xray", "-n", lines, "--no-pager", "-o", "short-iso").CombinedOutput()
		if err != nil {
			// Fallback: try reading from syslog
			out, err = exec.Command("tail", "-n", lines, "/var/log/syslog").CombinedOutput()
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"logs": "无法读取 Xray 日志：journalctl 和 syslog 均不可用。"})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"logs": string(out)})
	}
}

func xrayVersionHandler(controller XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ver := controller.Version(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"version": ver})
	}
}

func certStatusHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		domain := ""
		email := ""
		certPath := ""
		keyPath := ""
		issued := false

		if cfg.configDir != "" {
			configPath := cfg.configDir + "/panel.json"
			data, err := os.ReadFile(configPath)
			if err == nil {
				var raw map[string]interface{}
				if err := json.Unmarshal(data, &raw); err == nil {
					if d, ok := raw["cert_domain"].(string); ok {
						domain = d
					}
					if e, ok := raw["cert_email"].(string); ok {
						email = e
					}
				}
			}
			if domain != "" {
				certDir := cfg.configDir + "/certs/" + domain
				certPath = certDir + "/fullchain.pem"
				keyPath = certDir + "/privkey.pem"
				if _, err := os.Stat(certPath); err == nil {
					if _, err := os.Stat(keyPath); err == nil {
						issued = true
					}
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"domain":    domain,
			"email":     email,
			"issued":    issued,
			"cert_path": certPath,
			"key_path":  keyPath,
		})
	}
}

func certIssueHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Domain string `json:"domain"`
			Email  string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_json"})
			return
		}
		if req.Domain == "" || req.Email == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "domain_and_email_required"})
			return
		}
		if !validDomain.MatchString(req.Domain) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_domain"})
			return
		}
		if !validEmail.MatchString(req.Email) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_email"})
			return
		}
		if cfg.configDir == "" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "cert_not_available"})
			return
		}

		// Issue cert via acme.sh
		certDir := cfg.configDir + "/certs/" + req.Domain
		if err := os.MkdirAll(certDir, 0755); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "mkdir_cert_dir_failed"})
			return
		}

		// Check if acme.sh is installed; if not, install it
		if _, err := exec.LookPath("acme.sh"); err != nil {
			// Email already validated by validEmail regex above
			installOut, err := exec.Command("bash", "-c",
				"curl -fsSL https://get.acme.sh | sh -s email="+req.Email).CombinedOutput()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":  "install_acme_failed",
					"detail": string(installOut),
				})
				return
			}
		}

		// Run acme.sh --issue --standalone
		out, err := exec.Command("acme.sh",
			"--issue", "--standalone", "-d", req.Domain,
			"--keylength", "ec-256",
			"--fullchain-file", certDir+"/fullchain.pem",
			"--key-file", certDir+"/privkey.pem",
			"--cert-file", certDir+"/cert.pem",
			"--reloadcmd", "systemctl restart xray || true",
		).CombinedOutput()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":  "issue_cert_failed",
				"detail": string(out),
			})
			return
		}

		// Update panel.json with cert domain/email
		configPath := cfg.configDir + "/panel.json"
		existing, err := os.ReadFile(configPath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "read_panel_config_failed"})
			return
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(existing, &raw); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse_panel_config_failed"})
			return
		}
		raw["cert_domain"] = req.Domain
		raw["cert_email"] = req.Email
		updated, err := json.MarshalIndent(raw, "", "  ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "serialize_failed"})
			return
		}
		if err := os.WriteFile(configPath, updated, 0o600); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "write_panel_config_failed"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "issued",
			"domain":    req.Domain,
			"cert_path": certDir + "/fullchain.pem",
			"key_path":  certDir + "/privkey.pem",
		})
	}
}

func versionHandler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if version == "" {
			version = "dev"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"version": version})
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

func restartHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"restarting"}`))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Fork a child that restarts after a brief delay so the response is sent first
		go func() {
			time.Sleep(500 * time.Millisecond)
			_ = exec.Command("systemctl", "restart", "migate").Run()
		}()
		go func() {
			time.Sleep(2 * time.Second)
			os.Exit(0)
		}()
	}
}

func serviceStatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		status, detail := "unknown", ""
		out, err := exec.Command("systemctl", "is-active", "migate").Output()
		if err == nil {
			status = strings.TrimSpace(string(out))
		}
		if status == "active" {
			out2, _ := exec.Command("systemctl", "show", "migate", "--property=ActiveEnterTimestamp", "--value").Output()
			if len(out2) > 0 {
				detail = "启动于 " + strings.TrimSpace(string(out2))
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service": "migate",
			"status":  status,
			"detail":  detail,
		})
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
	case "hysteria2":
		// hy2://password@host:port/?params#name
		var params []string
		addParam := func(k, v string) {
			if v != "" {
				params = append(params, k+"="+url.QueryEscape(v))
			}
		}
		if inbound.Hy2UpMbps > 0 {
			params = append(params, "up_mbps="+strconv.Itoa(inbound.Hy2UpMbps))
		}
		if inbound.Hy2DownMbps > 0 {
			params = append(params, "down_mbps="+strconv.Itoa(inbound.Hy2DownMbps))
		}
		addParam("obfs", inbound.Hy2Obfs)
		addParam("obfs-password", inbound.Hy2ObfsPassword)
		if inbound.Security == "tls" {
			params = append(params, "security=tls")
			addParam("sni", inbound.RealityServerNames)
			params = append(params, "allowInsecure=1")
		}
		query := strings.Join(params, "&")
		suffix := ""
		if query != "" {
			suffix = "?" + query
		}
		return "hy2://" + client.UUID + "@" + host + ":" + strconv.Itoa(inbound.Port) + suffix + "#" + url.QueryEscape(client.Email)
	default:
		// vless, trojan, etc. use universal link format
		var params []string
		addParam := func(k, v string) {
			if v != "" {
				params = append(params, k+"="+url.QueryEscape(v))
			}
		}
		addParam("type", inbound.Network)
		addParam("security", inbound.Security)
		if inbound.Security == "reality" {
			params = append(params, "flow=xtls-rprx-vision")
			addParam("sni", inbound.RealityServerNames)
			params = append(params, "fp=chrome")
			addParam("pbk", inbound.RealityPublicKey)
			addParam("sid", inbound.RealityShortID)
		} else if inbound.Security == "tls" {
			addParam("sni", inbound.RealityServerNames)
			params = append(params, "allowInsecure=1")
		}
		// Transport-specific params
		switch inbound.Network {
		case "ws":
			addParam("path", inbound.WsPath)
			addParam("host", inbound.WsHost)
		case "h2":
			addParam("path", inbound.WsPath)
			addParam("host", inbound.WsHost)
		case "grpc":
			addParam("serviceName", inbound.GrpcServiceName)
		case "xhttp":
			addParam("path", inbound.XHTTPPath)
			addParam("mode", inbound.XHTTPMode)
		case "kcp":
		case "quic":
		}
		query := strings.Join(params, "&")
		return inbound.Protocol + "://" + client.UUID + "@" + host + ":" + strconv.Itoa(inbound.Port) + "?" + query + "#" + url.QueryEscape(client.Email)
	}
}

func vmessShareLink(host string, inbound db.Inbound, client db.Client) string {
	inboundPort := inbound.Port
	portStr := strconv.Itoa(inboundPort)
	tls := ""
	if inbound.Security == "tls" || inbound.Security == "reality" {
		tls = "tls"
	}

	// Transport-specific host and path
	vHost, vPath := "", ""
	sni := ""
	switch inbound.Network {
	case "ws":
		vHost = inbound.WsHost
		vPath = inbound.WsPath
	case "grpc":
		vPath = inbound.GrpcServiceName
	case "xhttp":
		vPath = inbound.XHTTPPath
	case "h2":
		vHost = inbound.WsHost
		vPath = inbound.WsPath
	}
	if inbound.Security == "tls" || inbound.Security == "reality" {
		sni = inbound.RealityServerNames
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
		"host": vHost,
		"path": vPath,
		"tls":  tls,
		"sni":  sni,
	}
	b, _ := json.Marshal(vmessData)
	encoded := base64.StdEncoding.EncodeToString(b)
	return "vmess://" + encoded
}

func ssShareLink(host string, inbound db.Inbound, client db.Client) string {
	method := inbound.SSMethod
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}
	userPass := method + ":" + inbound.UUID
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

type vpngateFetcherImpl struct{}

func (vpngateFetcherImpl) FetchServers() ([]VPNGateServer, error) {
	f := &vpngate.Fetcher{}
	servers, err := f.FetchServers()
	if err != nil {
		return nil, err
	}
	result := make([]VPNGateServer, len(servers))
	for i, s := range servers {
		result[i] = VPNGateServer{
			HostName:     s.HostName,
			IP:           s.IP,
			Score:        s.Score,
			Ping:         s.Ping,
			Speed:        s.Speed,
			CountryLong:  s.CountryLong,
			CountryShort: s.CountryShort,
			NumSessions:  s.NumSessions,
			Uptime:       s.Uptime,
			TotalUsers:   s.TotalUsers,
			TotalTraffic: s.TotalTraffic,
			LogType:      s.LogType,
			Operator:     s.Operator,
			Message:      s.Message,
			ServerType:   classifyVPNGateType(s.Operator),
		}
	}
	return result, nil
}

func vpngateServersHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		fetcher := cfg.vpnGateFetcher
		if fetcher == nil {
			fetcher = vpngateFetcherImpl{}
		}
		servers, err := fetcher.FetchServers()
		if err != nil {
			log.Printf("VPN Gate fetch failed: %v", err)
			http.Error(w, `{"error":"fetch_failed","detail":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(servers)
	}
}

type importServerRequest struct {
	Servers []importServerItem `json:"servers"`
}

type importServerItem struct {
	HostName    string `json:"hostname"`
	IP          string `json:"ip"`
	CountryLong string `json:"country_long"`
	Ping        int    `json:"ping"`
	Port        int    `json:"port"`
}

type vpngateProbeRequest struct {
	Servers []importServerItem `json:"servers"`
}

type vpngateProbeResult struct {
	HostName  string `json:"hostname"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

func probeTCPAddress(address string, port int, timeout time.Duration) (bool, int64, string) {
	if port == 0 {
		port = 1080
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, strconv.Itoa(port)), timeout)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return false, latency, err.Error()
	}
	_ = conn.Close()
	return true, latency, ""
}

func vpngateProbeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var req vpngateProbeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
			return
		}
		if len(req.Servers) == 0 {
			http.Error(w, `{"error":"no_servers"}`, http.StatusBadRequest)
			return
		}
		if len(req.Servers) > 20 {
			req.Servers = req.Servers[:20]
		}
		results := make([]vpngateProbeResult, 0, len(req.Servers))
		for _, s := range req.Servers {
			port := s.Port
			if port == 0 {
				port = 1080
			}
			res := vpngateProbeResult{HostName: s.HostName, IP: s.IP, Port: port}
			res.OK, res.LatencyMS, res.Error = probeTCPAddress(s.IP, port, 1200*time.Millisecond)
			results = append(results, res)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(results)
	}
}

type vpngateOutboundHealthResult struct {
	ID        int64  `json:"id"`
	Tag       string `json:"tag"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Enabled   bool   `json:"enabled"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

type vpngateOutboundHealthResponse struct {
	Results []vpngateOutboundHealthResult `json:"results"`
	Summary struct {
		Total int `json:"total"`
		OK    int `json:"ok"`
		Fail  int `json:"fail"`
	} `json:"summary"`
}

func vpngateOutboundHealthHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if store == nil {
			http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		outbounds, err := store.ListOutbounds(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "list_outbounds_failed")
			return
		}
		var resp vpngateOutboundHealthResponse
		for _, ob := range outbounds {
			if !ob.Enabled || ob.Protocol != "socks" || !strings.HasPrefix(ob.Tag, "vpngate-") || ob.Address == "" {
				continue
			}
			res := vpngateOutboundHealthResult{ID: ob.ID, Tag: ob.Tag, Address: ob.Address, Port: ob.Port, Enabled: ob.Enabled}
			res.OK, res.LatencyMS, res.Error = probeTCPAddress(ob.Address, ob.Port, 1200*time.Millisecond)
			resp.Results = append(resp.Results, res)
			resp.Summary.Total++
			if res.OK {
				resp.Summary.OK++
			} else {
				resp.Summary.Fail++
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func vpngateAutoHealthStatusHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if cfg == nil || cfg.healthScheduler == nil {
			_, _ = w.Write([]byte(`{"status":"not_started","results":[],"disabled_total":0}`))
			return
		}
		results, disabled := cfg.healthScheduler.LastResult()
		type resultJSON struct {
			OutboundID int64  `json:"outbound_id"`
			Tag        string `json:"tag"`
			Address    string `json:"address"`
			Port       int    `json:"port"`
			OK         bool   `json:"ok"`
			LatencyMS  int64  `json:"latency_ms"`
			Error      string `json:"error,omitempty"`
			Disabled   bool   `json:"disabled"`
		}
		jres := make([]resultJSON, len(results))
		for i, r := range results {
			jres[i] = resultJSON{
				OutboundID: r.OutboundID,
				Tag:        r.Tag,
				Address:    r.Address,
				Port:       r.Port,
				OK:         r.OK,
				LatencyMS:  r.LatencyMS,
				Error:      r.Error,
				Disabled:   r.Disabled,
			}
		}
		out := struct {
			Status        string       `json:"status"`
			Results       []resultJSON `json:"results"`
			DisabledTotal int          `json:"disabled_total"`
		}{
			Status:        "running",
			Results:       jres,
			DisabledTotal: disabled,
		}
		b, _ := json.Marshal(out)
		_, _ = w.Write(b)
	}
}

func vpngateImportHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var req importServerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
			return
		}
		if len(req.Servers) == 0 {
			http.Error(w, `{"error":"no_servers"}`, http.StatusBadRequest)
			return
		}
		existing, err := cfg.store.ListOutbounds(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "list_outbounds_failed")
			return
		}
		seenTags := make(map[string]bool, len(existing)+len(req.Servers))
		seenAddr := make(map[string]bool, len(existing)+len(req.Servers))
		for _, ob := range existing {
			seenTags[ob.Tag] = true
			if ob.Protocol == "socks" && ob.Address != "" {
				seenAddr[ob.Address+":"+strconv.Itoa(ob.Port)] = true
			}
		}

		created := make([]db.Outbound, 0, len(req.Servers))
		for _, s := range req.Servers {
			if s.IP == "" {
				continue
			}
			remark := s.CountryLong
			if remark == "" {
				remark = s.IP
			}
			remark = "VPN Gate - " + remark
			tag := "vpngate-" + s.HostName
			if tag == "vpngate-" {
				tag = "vpngate-" + strings.ReplaceAll(s.IP, ".", "-")
			}
			if len(tag) > 40 {
				tag = tag[:40]
			}
			addrKey := s.IP + ":1080"
			if seenTags[tag] || seenAddr[addrKey] {
				continue
			}
			seenTags[tag] = true
			seenAddr[addrKey] = true
			ob, err := cfg.store.CreateOutbound(r.Context(), db.CreateOutboundParams{
				Tag:      tag,
				Remark:   remark,
				Protocol: "socks",
				Address:  s.IP,
				Port:     1080,
			})
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "create_failed")
				return
			}
			created = append(created, ob)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(created)
	}
}

// singboxStatusHandler returns the sing-box runtime status.
func singboxStatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		installed := singbox.IsInstalled()
		if !installed {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"installed": false,
				"status":    "not_installed",
			})
			return
		}
		status := singbox.Status()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"installed": true,
			"status":    status,
		})
	}
}

// singboxApplyHandler reads sing-box supported inbounds from the store, builds
// a sing-box config, generates a self-signed cert if missing, writes
// the config to disk and restarts the sing-box service.
func singboxApplyHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		if !singbox.IsInstalled() {
			http.Error(w, `{"error":"singbox_not_installed"}`, http.StatusBadRequest)
			return
		}

		// Read sing-box inbounds
		inbounds, err := store.ListInbounds(r.Context())
		if err != nil {
			http.Error(w, `{"error":"list_failed","detail":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		// Build config
		cfg := singbox.BuildConfig(inbounds)

		// Ensure self-signed cert exists
		if _, err := os.Stat(singbox.CertFile); os.IsNotExist(err) {
			if err := singbox.GenerateSelfSignedCert(); err != nil {
				http.Error(w, `{"error":"cert_failed","detail":"`+err.Error()+`"}`, http.StatusInternalServerError)
				return
			}
		}

		// Encode and write config
		raw, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			http.Error(w, `{"error":"marshal_failed","detail":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(singbox.DefaultConfigPath, raw, 0644); err != nil {
			http.Error(w, `{"error":"write_failed","detail":"`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		// Restart sing-box
		applyErr := singbox.Apply()

		result := map[string]interface{}{
			"applied":     applyErr == nil,
			"config_path": singbox.DefaultConfigPath,
			"inbounds":    len(cfg.Inbounds),
		}
		if applyErr != nil {
			result["error"] = applyErr.Error()
			w.WriteHeader(http.StatusInternalServerError)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}
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
      --surface-warning: #fffbeb;
      --muted: #666666;
      --line: rgba(0,0,0,.08);
      --line-strong: #ebebeb;
      --accent: #171717;
      --accent2: #16a34a;
      --danger: #dc2626;
      --amber: #f59e0b;
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
      --surface-warning: #27251c;  /* dark amber-tinted surface */
      --muted: #a1a1aa;
      --line: rgba(255,255,255,.10);
      --line-strong: rgba(255,255,255,.14);
      --accent: #ededed;
      --accent2: #22c55e;
      --danger: #ef4444;
      --amber: #fbbf24;
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
    main { padding:var(--space-6); background:var(--bg); }
    main > section{display:none}
    #overview.overview-grid{display:grid}
    .overview-grid { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:var(--space-4); margin-bottom:var(--space-4); }
    .sidebar { position:sticky; top:0; height:100vh; overflow:auto; box-shadow:inset -1px 0 0 var(--line-strong); padding:var(--space-6) 18px; background:var(--surface); display:flex; flex-direction:column; }
    .brand { font-size:24px; font-weight:600; letter-spacing:-0.96px; margin-bottom:var(--space-1); color:var(--fg); }
    .subtitle { color:var(--muted); font-size:var(--text-sm); line-height:1.5; margin-bottom:var(--space-4); }
    nav { flex:1; overflow:visible; }
    #sidebar-toggle { display:none; align-items:center; justify-content:center; width:36px; height:36px; border:none; background:var(--surface); color:var(--fg); font-size:22px; cursor:pointer; border-radius:var(--radius-sm); box-shadow:var(--shadow-md); z-index:101; position:fixed; top:12px; left:12px; }
    .account-panel { display:grid; gap:var(--space-2); padding:var(--space-3); margin-top:auto; border-radius:var(--radius-md); background:transparent; box-shadow:inset 0 1px 0 var(--line); }
    .account-label { color:var(--muted); font-size:var(--text-xs); text-transform:uppercase; letter-spacing:.08em; }
    .account-name { color:var(--fg); font-size:var(--text-sm); font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .account-actions { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
    .account-actions button { min-height:32px; padding:0 10px; font-size:var(--text-xs); border-radius:var(--radius-md); background:var(--surface-subtle); color:var(--fg); box-shadow:none; }
    nav a { display:block; color:var(--fg); text-decoration:none; padding:10px var(--space-3); border-radius:var(--radius-md); margin:var(--space-1) 0; box-shadow:none; font-size:var(--text-md); font-weight:500; }
    nav a.active, nav a:hover { background:var(--surface-subtle); box-shadow:var(--shadow-sm); }
    .grid { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:var(--space-4); margin-bottom:var(--space-4); }
    .version-banner { margin-bottom:var(--space-3); padding:14px 18px; border-radius:var(--radius-md); background:var(--surface-subtle); box-shadow:var(--shadow-sm), inset 3px 0 0 var(--accent); font-size:var(--text-sm); line-height:1.5; color:var(--fg); }
    .notice-slot { margin-top:12px; }
    .client-subsection { margin:8px 0 var(--space-3) var(--space-5); padding:var(--space-3) 0 0 var(--space-4); border-left:1px solid var(--line); box-shadow:none; }

    .overview-insights { display:grid; grid-template-columns:1.2fr 1fr 1fr; gap:var(--space-4); grid-column:1 / -1; }
    .overview-card { display:grid; gap:var(--space-3); align-content:start; background:var(--surface); border-radius:var(--radius-lg); box-shadow:var(--shadow-md); padding:var(--panel-padding); min-height:156px; }
    .overview-card-title { color:var(--fg); font-size:var(--text-lg); font-weight:600; letter-spacing:-0.24px; }
    .overview-pill { display:inline-flex; align-items:center; width:max-content; min-height:26px; padding:0 10px; border-radius:9999px; background:var(--surface-subtle); color:var(--fg); box-shadow:var(--shadow-sm); font-size:var(--text-xs); font-weight:500; }
    .type-pill { display:inline-flex; align-items:center; padding:2px 8px; border-radius:8px; font-size:11px; font-weight:600; line-height:1.4; }
    .type-pill.type-home { background:color-mix(in srgb, #2e7d32 15%, transparent); color:var(--green, #2e7d32); }
    .type-pill.type-biz { background:color-mix(in srgb, #1565c0 15%, transparent); color:var(--blue, #1565c0); }
    .panel, .card { background:var(--surface); border-radius:var(--radius-lg); box-shadow:var(--shadow-md); padding:var(--panel-padding); }
    .metric { font-size:30px; font-weight:600; line-height:1.05; letter-spacing:-0.96px; margin-top:10px; color:var(--fg); }
    .section-heading, .section-title { font-size:24px; line-height:1.2; letter-spacing:-0.96px; font-weight:600; margin:0 0 var(--space-3); color:var(--fg); }
    .protocols { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:var(--space-3); }
    .protocol-breakdown { display:grid; gap:8px; }
    .protocol-breakdown-row { display:grid; grid-template-columns:1fr auto; gap:10px; align-items:center; color:var(--muted); font-size:var(--text-sm); }
    .protocol { padding:14px; border-radius:var(--radius-lg); background:var(--surface); box-shadow:var(--shadow-sm); }
    .protocol strong { display:block; margin-bottom:6px; color:var(--fg); }
    .actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:14px; }
    button { appearance:none; border:none; background:var(--accent); color:var(--bg); min-height:var(--control-height); padding:0 14px; border-radius:var(--control-radius); font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; font-size:var(--text-md); font-weight:500; cursor:pointer; box-shadow:var(--shadow-sm); }
    button:hover { opacity:.96; }
    button.secondary, .btn-cancel { background:var(--surface); color:var(--fg); box-shadow:var(--shadow-sm); }
    button.danger { background:var(--danger); color:var(--bg); }
    .btn-confirm { background:var(--danger); color:var(--bg); }
    .btn-modal-primary { background:var(--accent); color:var(--bg); }
    form { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:var(--space-3); margin:var(--space-4) 0; }
    .form-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:var(--space-4); margin:var(--space-4) 0; }
    .field-group { display:grid; gap:var(--space-2); min-width:0; }
    .field-group.span-2 { grid-column:1 / -1; }
    .field-label { color:var(--fg); font-size:var(--text-sm); font-weight:500; line-height:1.3; }
    .field-help { color:var(--muted); font-size:var(--text-xs); line-height:1.45; margin:0; }
    .inline-field-tools { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .btn-mini { background:var(--surface); color:var(--accent); border:1px solid var(--border); border-radius:var(--control-radius); padding:4px 12px; font-size:var(--text-xs); cursor:pointer; white-space:nowrap; transition:all .15s; min-height:32px; }
    .btn-mini:hover { background:var(--accent-subtle, rgba(99,102,241,0.08)); border-color:var(--accent); }
    .form-actions { grid-column:1 / -1; display:flex; justify-content:flex-end; align-items:center; gap:10px; padding-top:var(--space-4); margin-top:var(--space-2); }
    .action-toolbar { display:flex; align-items:center; justify-content:space-between; gap:var(--space-4); padding:var(--space-4); border-radius:var(--radius-lg); background:var(--surface-subtle); box-shadow:var(--shadow-sm); margin:var(--space-4) 0; }
    .action-toolbar.span-2 { grid-column:1 / -1; }
    .toolbar-copy { display:grid; gap:var(--space-1); min-width:0; color:var(--muted); font-size:var(--text-sm); line-height:1.5; }
    .toolbar-copy strong { color:var(--fg); font-size:var(--text-md); font-weight:600; letter-spacing:-0.14px; }
    .toolbar-actions { display:flex; align-items:center; justify-content:flex-end; gap:10px; flex-wrap:wrap; }
    .ui-control, input, select, textarea { width:100%; min-height:var(--control-height); border:none; outline:none; background:var(--surface); color:var(--fg); border-radius:var(--control-radius); padding:0 var(--space-3); box-shadow:var(--shadow-sm); font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; font-size:var(--text-md); line-height:1.4; transition:box-shadow .15s; }
    textarea { padding-top:10px; padding-bottom:10px; }
    input:focus, select:focus, textarea:focus, button:focus { box-shadow:var(--shadow-sm), 0 0 0 2px var(--focus); }
    .list { display:grid; gap:10px; margin-top:14px; }
    .row { display:grid; grid-template-columns:1.2fr .8fr .8fr .8fr .8fr .6fr; gap:10px; align-items:center; padding:var(--row-padding); border-radius:var(--radius-lg); background:var(--surface); box-shadow:var(--shadow-sm); }
    .resource-row { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:var(--space-4); align-items:center; padding:var(--row-padding); border-radius:var(--radius-lg); background:var(--surface); box-shadow:var(--shadow-sm); transition:box-shadow .16s ease, transform .16s ease; }
    .client-resource-row { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:var(--space-3); align-items:center; padding:10px var(--space-3); border-radius:var(--radius-md); background:var(--surface-subtle); box-shadow:var(--shadow-sm); border-left:3px solid var(--accent2); font-size:var(--text-sm); }
    .client-subsection .list { margin-top:0; gap:8px; }
    .client-add-row { display:flex; justify-content:flex-start; padding-top:var(--space-2); }
    .client-add-row .btn-sm { background:var(--surface-subtle); color:var(--fg); box-shadow:var(--shadow-sm); }
    .resource-row:hover { box-shadow:var(--shadow-md); transform:translateY(-1px); }
    .resource-main { min-width:0; display:grid; gap:var(--space-2); }
    .resource-title { display:flex; align-items:center; gap:var(--space-2); min-width:0; font-size:15px; font-weight:600; color:var(--fg); }
    .resource-title strong { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .resource-meta { display:flex; flex-wrap:wrap; align-items:center; gap:var(--space-2); color:var(--muted); font-size:var(--text-xs); line-height:1.5; }
    .status-badge { display:inline-flex; align-items:center; height:22px; padding:0 var(--space-2); border-radius:9999px; font-size:var(--text-xs); font-weight:500; box-shadow:var(--shadow-sm); }
    .status-badge.enabled { color:var(--accent2); background:rgba(22,163,74,.14); }
    .status-badge.disabled { color:var(--muted); background:rgba(161,161,170,.14); }
    .resource-actions { display:flex; align-items:center; justify-content:flex-end; gap:6px; }
    .icon-btn, .danger-icon-btn { display:inline-flex; align-items:center; justify-content:center; min-width:32px; min-height:32px; height:32px; padding:0 var(--space-2); border-radius:var(--control-radius); font-size:var(--text-xs); }
    .icon-btn { background:var(--surface); color:var(--fg); box-shadow:var(--shadow-sm); }
    .danger-icon-btn { background:rgba(239,68,68,.12); color:var(--danger); box-shadow:var(--shadow-sm); }
    .traffic-track { width:128px; height:4px; margin-top:5px; overflow:hidden; border-radius:9999px; background:var(--line-strong); }
    .traffic-fill { height:100%; border-radius:9999px; background:var(--accent2); }
    .empty-state { display:grid; gap:10px; justify-items:start; padding:22px; border-radius:var(--radius-xl); background:var(--surface); box-shadow:var(--shadow-sm); color:var(--muted); }
    .empty-state-title { color:var(--fg); font-size:16px; font-weight:600; letter-spacing:-0.32px; }
    .empty-state-copy { max-width:560px; color:var(--muted); font-size:13px; line-height:1.6; }
    .empty-state-actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:4px; }
    .version-banner { margin-bottom:var(--space-3); padding:14px 18px; border-radius:var(--radius-md); background:var(--surface-subtle); box-shadow:var(--shadow-sm), inset 3px 0 0 var(--accent); font-size:var(--text-sm); line-height:1.5; color:var(--fg); }
    .version-banner a { color:var(--fg); text-decoration:underline; }
    .notice-slot { margin-top:12px; }
    .xray-status-panel { box-shadow:var(--shadow-sm); border-radius:var(--radius-xl); padding:var(--space-5); margin-bottom:var(--space-4); display:grid; gap:5px; font-size:var(--text-sm); line-height:1.7; }
    .search-input { height:36px; min-width:160px; border:none; border-radius:var(--radius-md); padding:0 12px; font-size:var(--text-sm); background:var(--surface); color:var(--fg); box-shadow:var(--shadow-sm); outline:none; font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; transition:box-shadow .15s; }
    .search-input:focus { box-shadow:var(--shadow-sm), 0 0 0 2px var(--focus); }
    .sort-select { height:36px; border:none; border-radius:var(--radius-md); padding:0 10px; font-size:var(--text-sm); background:var(--surface); color:var(--fg); box-shadow:var(--shadow-sm); cursor:pointer; outline:none; font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; transition:box-shadow .15s; }
    .xray-preview-pre { background:var(--surface-subtle); border-radius:var(--radius-lg); padding:16px; font-size:12px; overflow-x:auto; white-space:pre-wrap; max-height:400px; overflow-y:auto; box-shadow:var(--shadow-sm); margin:0; }
    .xray-preview-header { display:flex; align-items:center; justify-content:space-between; padding:8px 0 4px; }
    .notice { display:grid; gap:8px; padding:16px; border-radius:var(--radius-lg); background:var(--surface); box-shadow:var(--shadow-sm), inset 3px 0 0 var(--accent); }
    .notice-title { color:var(--fg); font-size:14px; font-weight:600; letter-spacing:-0.14px; }
    .notice-copy { color:var(--muted); font-size:13px; line-height:1.55; white-space:pre-wrap; }
    .notice.success { box-shadow:var(--shadow-sm), inset 3px 0 0 var(--accent2); }
    .notice.error { box-shadow:var(--shadow-sm), inset 3px 0 0 var(--danger); }
    .muted { color:var(--muted); }
    .error { color:var(--danger); }
    .btn-del { background:var(--danger); border:none; color:white; padding:4px 10px; border-radius:var(--radius-sm); font-size:12px; cursor:pointer; }
    .bar-low { background:var(--accent2); }
    .bar-mid { background:var(--amber); }
    .bar-high { background:var(--danger); }
    .copy-link { font-size:11px; cursor:pointer; }
    .btn-sm { border:none; color:var(--bg); padding:4px 8px; border-radius:var(--radius-sm); font-size:11px; cursor:pointer; }
    .hidden { display:none; }
    #toast-container { position:fixed; top:20px; right:20px; z-index:9999; display:flex; flex-direction:column; gap:10px; }
    .toast { background:var(--surface); border:none; color:var(--fg); padding:12px 18px; border-radius:var(--radius-md); box-shadow:var(--shadow-md); animation: toastIn .3s ease, toastOut .3s ease 2.7s forwards; }
    .toast.error { box-shadow:var(--shadow-md), inset 3px 0 0 rgba(220,38,38,.55); }
    .toast.success { box-shadow:var(--shadow-md), inset 3px 0 0 rgba(22,163,74,.55); }
    @keyframes toastIn { from { opacity:0; transform:translateX(40px); } to { opacity:1; transform:translateX(0); } }
    @keyframes toastOut { from { opacity:1; } to { opacity:0; transform:translateX(40px); } }
    #confirm-overlay.hidden { display:none; }
    #create-inbound-overlay.hidden { display:none; }
    #create-client-overlay.hidden { display:none; }
    #edit-inbound-overlay.hidden { display:none; }
    #edit-client-overlay.hidden { display:none; }
    #confirm-dialog { background:var(--surface); box-shadow:var(--shadow-md); border-radius:var(--radius-xl); padding:var(--space-6); min-width:360px; max-width:520px; max-height:80vh; overflow-y:auto; }
    #confirm-dialog p { margin:0 0 20px; font-size:15px; line-height:1.6; color:var(--fg); }
    #confirm-dialog .actions { display:flex; gap:10px; justify-content:flex-end; }
    .modal-title { margin:0 0 var(--space-4); font-size:var(--text-lg); line-height:1.3; font-weight:600; letter-spacing:-0.2px; color:var(--fg); }
    .modal-overlay { position:fixed; inset:0; z-index:10000; background:rgba(0,0,0,.12); backdrop-filter:blur(4px); display:flex; align-items:center; justify-content:center; animation:fadeIn .2s; }
    .modal-content { background:var(--surface); box-shadow:var(--shadow-md); border-radius:var(--radius-xl); padding:var(--space-6); min-width:360px; max-width:520px; max-height:80vh; overflow-y:auto; }
    .modal-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:var(--space-4); }
    .modal-header .modal-title { margin:0; }
    .modal-close { width:32px; height:32px; min-height:32px; padding:0; display:inline-flex; align-items:center; justify-content:center; border-radius:var(--radius-sm); background:var(--surface); color:var(--fg); box-shadow:var(--shadow-sm); font-size:16px; line-height:1; }
    .modal-footer { display:flex; gap:10px; justify-content:flex-end; margin-top:var(--space-4); }
    .modal-checkbox { display:flex; align-items:center; gap:8px; font-size:var(--text-sm); color:var(--fg); cursor:pointer; }
    .modal-checkbox input[type=checkbox] { width:16px; height:16px; accent-color:var(--accent); cursor:pointer; margin:0; }
    .modal-form { margin:0; grid-template-columns:repeat(2,minmax(0,1fr)); }
    #create-inbound-form.modal-form, #create-client-form.modal-form, #edit-inbound-form.modal-form, #edit-client-form.modal-form { gap:var(--space-4); }
    .modal-actions { margin-top: var(--space-4); }
    .advanced-fieldset { padding:var(--space-4); border-radius:var(--radius-lg); background:var(--surface-subtle); box-shadow:var(--shadow-sm), inset 0 0 0 1px var(--line); }
    .advanced-fieldset-title { color:var(--fg); font-size:var(--text-sm); font-weight:600; letter-spacing:-0.12px; }
    .advanced-fieldset-copy { color:var(--muted); font-size:var(--text-xs); line-height:1.55; }
    #dynamic-fields, #ei-dynamic-fields { display:contents; }
    #create-inbound-dialog input, #create-inbound-dialog select, #create-client-dialog input, #create-client-dialog select, #edit-inbound-dialog input, #edit-inbound-dialog select, #edit-client-dialog input, #edit-client-dialog select { width:100%; box-sizing:border-box; margin-bottom:0; }
    @keyframes fadeIn { from { opacity:0; } to { opacity:1; } }
    /* Mobile sidebar overlay */
    #sidebar-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,.12); backdrop-filter:blur(4px); z-index:99; }
    @media (max-width: 768px) {
      .app-shell { grid-template-columns:1fr; }
      .sidebar { position:fixed; top:0; left:0; bottom:0; width:var(--sidebar-width); z-index:100; transform:translateX(-100%); transition:transform .25s ease; box-shadow:inset -1px 0 0 var(--line-strong); }
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
  <div id="confirm-overlay" class="modal-overlay hidden" onclick="if(event.target===this)rejectConfirm()">
    <div id="confirm-dialog">
      <p id="confirm-msg"></p>
      <div class="actions">
        <button class="btn-cancel" onclick="rejectConfirm()">取消</button>
        <button class="btn-confirm" onclick="resolveConfirm()">确认</button>
      </div>
    </div>
  </div>

  <!-- Create Inbound Modal -->
<div id="create-inbound-overlay" class="modal-overlay hidden" onclick="if(event.target===this)closeCreateInbound()">
      <div id="create-inbound-dialog" class="modal-content">
        <div class="modal-header">
          <h3 class="modal-title">新增入站</h3>
          <button class="modal-close" onclick="closeCreateInbound()">✕</button>
        </div>
      <form id="create-inbound-form" class="form-grid modal-form" onsubmit="return false">
        <div class="field-group">
          <label class="field-label" for="inbound-remark">名称</label>
          <input id="inbound-remark" name="remark" placeholder="例如 主入口" required>
          <p class="field-help">只需要填写名称，其他参数会自动生成并可继续手动修改。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="inbound-protocol">协议类型</label>
          <select id="inbound-protocol" name="protocol" onchange="onProtocolChange()">
            <option value="vless">VLESS</option>
            <option value="vmess">VMess</option>
            <option value="trojan">Trojan</option>
            <option value="shadowsocks">Shadowsocks</option>
            <option value="hysteria2">Hysteria2</option>
            <option value="tuic">TUIC</option>
            <option value="wireguard">WireGuard ⚠️ (需升级 sing-box v1.14+)</option>
            <option value="shadowtls">ShadowTLS</option>
          </select>
          <p id="protocol-description" class="field-help" style="color:var(--accent);font-weight:500">选择核心入站协议，自动配置传输方式与安全层。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="inbound-port">监听端口</label>
          <input id="inbound-port" name="port" type="number" min="1" max="65535" placeholder="例如 443" required>
          <p class="field-help">建议使用未被占用的公网端口。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="inbound-network">参数类型 / 传输方式</label>
          <select name="network" id="inbound-network">
            <option value="tcp">TCP</option>
            <option value="ws">WebSocket</option>
            <option value="kcp">mKCP</option>
            <option value="grpc">gRPC</option>
            <option value="quic">QUIC</option>
            <option value="h2">HTTP/2</option>
            <option value="xhttp">XHTTP</option>
          </select>
          <p class="field-help">只要选定参数类型，其余如 UUID、密码、短 ID、证书路径等会随机填充并可手动修改。</p>
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
        <div class="field-group span-2">
          <label class="field-label" for="inbound-uuid">入站 UUID / Shadowsocks 密码</label>
          <div class="inline-field-tools"><input id="inbound-uuid" name="uuid" placeholder="自动生成；Shadowsocks 会作为单用户密码/密钥"><button type="button" class="btn-mini" onclick="regenerateField('inbound-uuid')">重新生成</button><button type="button" class="btn-mini" onclick="toggleSecretField('inbound-uuid')">显示/隐藏</button></div>
          <p class="field-help">普通协议可保持默认；Shadowsocks 单用户模式会使用这里的值作为密码/密钥。</p>
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
            <div class="inline-field-tools"><input id="inbound-reality-short-id" name="reality_short_id" placeholder="ShortId (可选)"><button type="button" class="btn-mini" onclick="regenerateField('inbound-reality-short-id')">重新生成</button></div>
          </div>
          <div id="ss-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">Shadowsocks 设置</div>
            <div class="advanced-fieldset-copy">选择客户端支持的加密方法。</div>
            <div class="inline-field-tools"><select id="inbound-ss-method" name="ss_method">
              <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
              <option value="aes-256-gcm">aes-256-gcm</option>
              <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
            </select><button type="button" class="btn-mini" onclick="regenerateField('inbound-ss-method')">重新生成</button></div>
          </div>
          <div id="hy2-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">Hysteria2 设置</div>
            <div class="advanced-fieldset-copy">Hysteria2 使用 QUIC 传输，以下为可选参数。</div>
            <input name="hy2_up_mbps" type="number" min="0" placeholder="上行速率 mbps (0=不限) 默认 0">
            <input name="hy2_down_mbps" type="number" min="0" placeholder="下行速率 mbps (0=不限) 默认 0">
            <input name="hy2_obfs" placeholder="混淆类型 (如 salamander, 可选)">
            <div class="inline-field-tools"><input id="inbound-hy2-obfs-password" name="hy2_obfs_password" type="password" placeholder="混淆密码 (可选)"><button type="button" class="btn-mini" onclick="regenerateField('inbound-hy2-obfs-password')">重新生成</button><button type="button" class="btn-mini" onclick="toggleSecretField('inbound-hy2-obfs-password')">显示/隐藏</button></div>
            <p class="field-help">速率限制为 0 表示不限制。混淆类型通常为 salamander。</p>
          </div>
          <div id="tuic-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">TUIC 设置</div>
            <div class="advanced-fieldset-copy">TUIC 基于 QUIC 的低延迟 UDP 代理。</div>
            <select name="tuic_congestion_control">
              <option value="bbr">BBR (推荐)</option>
              <option value="cubic">Cubic</option>
              <option value="new_reno">NewReno</option>
            </select>
            <label><input name="tuic_zero_rtt" type="checkbox" value="1"> 启用 0-RTT 握手</label>
            <p class="field-help">拥塞控制和 0-RTT 握手可优化延迟。</p>
          </div>
          <div id="wireguard-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">WireGuard 设置</div>
            <div class="advanced-fieldset-copy">WireGuard 简单高效的 VPN 协议。</div>
            <div class="inline-field-tools"><input name="wg_private_key" placeholder="私钥 (PrivateKey) 必填"><button type="button" class="btn-mini" onclick="regenerateFieldByName('wg_private_key')">生成密钥</button></div>
            <input name="wg_address" placeholder="本地地址 (如 10.0.0.1/24) 必填">
            <input name="wg_peer_public_key" placeholder="客户端公钥 (PublicKey) 必填">
            <input name="wg_allowed_ips" placeholder="允许的 IP (默认 0.0.0.0/0, ::/0)">
            <input name="wg_endpoint" placeholder="客户端 Endpoint (可选)">
            <div class="inline-field-tools"><input name="wg_preshared_key" placeholder="预共享密钥 (PreSharedKey, 可选)"><button type="button" class="btn-mini" onclick="regenerateFieldByName('wg_preshared_key')">生成密钥</button></div>
            <input name="wg_mtu" type="number" min="1280" placeholder="MTU (默认 1420)">
            <p class="field-help">WireGuard 需要服务器端生成私钥/公钥对。</p>
          </div>
          <div id="shadowtls-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">ShadowTLS 设置</div>
            <div class="advanced-fieldset-copy">ShadowTLS 将流量伪装成标准 TLS 连接。</div>
            <div class="inline-field-tools"><input name="shadowtls_password" placeholder="密码 (Password)"><button type="button" class="btn-mini" onclick="regenerateFieldByName('shadowtls_password')">重新生成</button></div>
            <select name="shadowtls_version">
              <option value="3">v3 (推荐)</option>
              <option value="2">v2</option>
              <option value="1">v1</option>
            </select>
            <p class="field-help">注意：ShadowTLS 复用 TLS 设置中的 SNI 作为 handshake_server_name。</p>
          </div>
          <div id="tls-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">TLS 设置</div>
            <div class="advanced-fieldset-copy">填写证书和私钥路径，应用前会交给 Xray 校验。</div>
            <input name="tls_cert_file" placeholder="TLS 证书路径 (如 /etc/.../fullchain.pem)">
            <div class="inline-field-tools"><input name="tls_key_file" placeholder="TLS 密钥路径 (如 /etc/.../privkey.key)"></div>
            <input name="tls_sni" placeholder="SNI / ServerName (可选，留空则自动匹配)">
            <select name="tls_fingerprint">
              <option value="">指纹 (默认不指定)</option>
              <option value="chrome">Chrome</option>
              <option value="firefox">Firefox</option>
              <option value="safari">Safari</option>
              <option value="random">Random</option>
              <option value="randomized">Randomized</option>
            </select>
            <input name="tls_alpn" placeholder="ALPN (逗号分隔，如 h2,http/1.1)">
            <p class="field-help">SNI 与指纹用于 TLS 握手指纹伪装；ALPN 用于协议协商，留空为默认。</p>
          </div>
        </div>
        <div class="advanced-fieldset field-group span-2" style="border-left:2px solid var(--accent);padding-left:12px;margin-bottom:0">
          <div onclick="toggleInitClient(this)" style="cursor:pointer;color:var(--accent);user-select:none;font-size:13px">
            <span class="chevron">▼</span> 同时添加首个客户端（推荐）
          </div>
          <div id="init-client-fields" style="margin-top:8px;display:grid;gap:10px">
            <div class="inline-field-tools" style="grid-column:1/-1"><input id="init-client-email" placeholder="客户端标识 (如 user01 或 sam@example.com)"><button type="button" class="btn-mini" onclick="regenerateField('init-client-email')">重新生成</button></div>
            <div class="inline-field-tools" style="grid-column:1/-1"><input id="init-client-uuid" placeholder="客户端 UUID / 密码 / 密钥（自动生成，可修改）"><button type="button" class="btn-mini" onclick="regenerateField('init-client-uuid')">重新生成</button><button type="button" class="btn-mini" onclick="toggleSecretField('init-client-uuid')">显示/隐藏</button></div>
            <input id="init-client-traffic" type="number" min="0" placeholder="流量上限，单位字节；0=无限" value="0">
            <input id="init-client-expiry" type="datetime-local">
            <p id="init-client-credential-help" class="field-help" style="grid-column:1/-1">客户端凭据会自动生成。VLESS/VMess 使用 UUID，Trojan/Shadowsocks/Hysteria2 使用密码或密钥；不懂时保持默认即可。</p>
          </div>
        </div>
        <div class="form-actions modal-actions">
          <button type="button" class="btn-cancel" onclick="closeCreateInbound()">取消</button>
          <button type="submit" class="btn-modal-primary" onclick="saveCreateInbound()">保存入站</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Create Client Modal -->
  <div id="create-client-overlay" class="modal-overlay hidden" onclick="if(event.target===this)closeCreateClient()">
    <div id="create-client-dialog" class="modal-content">
      <div class="modal-header">
        <h3 class="modal-title">创建客户端</h3>
        <button class="modal-close" onclick="closeCreateClient()">✕</button>
      </div>
      <form id="create-client-form" class="form-grid modal-form" onsubmit="return false">
        <input id="client-inbound-id" type="hidden" value="">
        <div class="field-group span-2">
          <label class="field-label" for="client-email">客户端标识</label>
          <input id="client-email" name="email" placeholder="例如 user01" required>
          <p class="field-help">用于区分设备或用户，也会出现在分享链接备注中。</p>
        </div>
        <div class="field-group span-2">
          <label class="field-label" for="client-uuid">客户端 UUID / 密码 / 密钥</label>
          <div class="inline-field-tools"><input id="client-uuid" name="uuid" placeholder="自动生成，可手动修改"><button type="button" class="btn-mini" onclick="regenerateField('client-uuid')">重新生成</button><button type="button" class="btn-mini" onclick="toggleSecretField('client-uuid')">显示/隐藏</button></div>
          <p class="field-help">VLESS/VMess 使用 UUID；Trojan、Shadowsocks、Hysteria2 可当作密码或密钥，不懂时保持默认即可。</p>
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
          <button type="submit" class="btn-modal-primary" onclick="saveCreateClient()">创建客户端</button>
        </div>
      </form>
    </div>
  </div>


  <!-- Edit Inbound Modal -->
  <div id="edit-inbound-overlay" class="modal-overlay hidden" onclick="if(event.target===this)closeEditInbound()">
    <div id="edit-inbound-dialog" class="modal-content">
      <div class="modal-header">
        <h3 class="modal-title">编辑入站</h3>
        <button class="modal-close" onclick="closeEditInbound()">✕</button>
      </div>
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
            <option value="hysteria2">Hysteria2</option>
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
          <div id="ei-hy2-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">Hysteria2 设置</div>
            <div class="advanced-fieldset-copy">Hysteria2 使用 QUIC 传输，以下为可选参数。</div>
            <label class="field-label" for="ei-hy2-up">Hysteria2 上行/下行</label>
            <input id="ei-hy2-up" type="number" min="0" placeholder="上行速率 mbps (0=不限) 默认 0">
            <input id="ei-hy2-down" type="number" min="0" placeholder="下行速率 mbps (0=不限) 默认 0">
            <input id="ei-hy2-obfs" placeholder="混淆类型 (如 salamander, 可选)">
            <input id="ei-hy2-obfs-password" placeholder="混淆密码 (可选)">
            <p class="field-help">速率限制为 0 表示不限制。混淆类型通常为 salamander。</p>
          </div>
          <div id="ei-tuic-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">TUIC 设置</div>
            <div class="advanced-fieldset-copy">TUIC 基于 QUIC 的低延迟 UDP 代理。</div>
            <label class="field-label" for="ei-tuic-cc">TUIC 拥塞控制</label>
            <select id="ei-tuic-cc">
              <option value="bbr">BBR (推荐)</option>
              <option value="cubic">Cubic</option>
              <option value="new_reno">NewReno</option>
            </select>
            <label><input id="ei-tuic-zero-rtt" type="checkbox" value="1"> 启用 0-RTT 握手</label>
            <p class="field-help">拥塞控制和 0-RTT 握手可优化延迟。</p>
          </div>
          <div id="ei-wireguard-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">WireGuard 设置</div>
            <div class="advanced-fieldset-copy">WireGuard 简单高效的 VPN 协议。</div>
            <label class="field-label" for="ei-wg-private-key">WireGuard 私钥</label>
            <input id="ei-wg-private-key" placeholder="私钥 (PrivateKey) 必填">
            <input id="ei-wg-address" placeholder="本地地址 (如 10.0.0.1/24) 必填">
            <input id="ei-wg-peer-public-key" placeholder="客户端公钥 (PublicKey) 必填">
            <input id="ei-wg-allowed-ips" placeholder="允许的 IP (默认 0.0.0.0/0, ::/0)">
            <input id="ei-wg-endpoint" placeholder="客户端 Endpoint (可选)">
            <input id="ei-wg-preshared-key" placeholder="预共享密钥 (PreSharedKey, 可选)">
            <input id="ei-wg-mtu" type="number" min="1280" placeholder="MTU (默认 1420)">
            <p class="field-help">WireGuard 需要服务器端生成私钥/公钥对。</p>
          </div>
          <div id="ei-shadowtls-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">ShadowTLS 设置</div>
            <div class="advanced-fieldset-copy">ShadowTLS 将流量伪装成标准 TLS 连接。</div>
            <label class="field-label" for="ei-shadowtls-password">ShadowTLS 密码</label>
            <input id="ei-shadowtls-password" placeholder="密码 (Password)">
            <select id="ei-shadowtls-version">
              <option value="3">v3 (推荐)</option>
              <option value="2">v2</option>
              <option value="1">v1</option>
            </select>
            <p class="field-help">注意：ShadowTLS 复用 TLS 设置中的 SNI 作为 handshake_server_name。</p>
          </div>
          <div id="ei-tls-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">TLS 设置</div>
            <div class="advanced-fieldset-copy">填写证书和私钥路径，应用前会交给 Xray 校验。</div>
            <label class="field-label" for="ei-tls-cert-file">TLS 证书</label>
            <input id="ei-tls-cert-file" placeholder="TLS 证书路径 (如 /etc/.../fullchain.pem)">
            <input id="ei-tls-key-file" placeholder="TLS 密钥路径 (如 /etc/.../privkey.key)">
            <input id="ei-tls-sni" placeholder="SNI / ServerName (可选，留空则自动匹配)">
            <select id="ei-tls-fingerprint">
              <option value="">指纹 (默认不指定)</option>
              <option value="chrome">Chrome</option>
              <option value="firefox">Firefox</option>
              <option value="safari">Safari</option>
              <option value="random">Random</option>
              <option value="randomized">Randomized</option>
            </select>
            <input id="ei-tls-alpn" placeholder="ALPN (逗号分隔，如 h2,http/1.1)">
            <p class="field-help">SNI 与指纹用于 TLS 握手指纹伪装；ALPN 用于协议协商，留空为默认。</p>
          </div>
        </div>
        <div class="form-actions modal-actions">
          <button type="button" class="btn-cancel" onclick="closeEditInbound()">取消</button>
          <button type="submit" class="btn-modal-primary" onclick="saveEditInbound()">保存</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Edit Client Modal -->
  <div id="edit-client-overlay" class="modal-overlay hidden" onclick="if(event.target===this)closeEditClient()">
    <div id="edit-client-dialog" class="modal-content">
      <div class="modal-header">
        <h3 class="modal-title">编辑客户端</h3>
        <button class="modal-close" onclick="closeEditClient()">✕</button>
      </div>
      <form id="edit-client-form" class="form-grid modal-form" onsubmit="return false">
        <div class="field-group span-2">
          <label class="field-label" for="ec-email">客户端标识</label>
          <input id="ec-email" placeholder="客户端标识，例如 user01" required>
          <p class="field-help">用于识别用户或设备，不影响 UUID。</p>
        </div>
        <div class="field-group">
          <label class="field-label">启用状态</label>
          <div style="display:flex;align-items:center;gap:12px;margin-top:4px">
            <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
              <input id="ec-enabled" type="checkbox" style="width:18px;height:18px;accent-color:var(--accent)">
              <span id="ec-enabled-label">已启用</span>
            </label>
          </div>
        </div>
        <div class="field-group">
          <label class="field-label" for="ec-traffic-limit">流量限额</label>
          <input id="ec-traffic-limit" type="number" min="0" placeholder="流量限额（字节，0=不限）">
          <p class="field-help">单位为字节，填 0 表示不限。</p>
        </div>
        <div class="field-group span-2" style="border:1px solid var(--line-strong);border-radius:8px;padding:12px;background:var(--surface)">
          <label class="field-label" style="margin-top:0">当前流量</label>
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
            <div>
              <span style="font-size:13px">↑ 上行: <strong id="ec-up-display">0 B</strong></span>
              <span style="font-size:13px;margin-left:16px">↓ 下行: <strong id="ec-down-display">0 B</strong></span>
              <span style="font-size:13px;margin-left:16px">总计: <strong id="ec-total-display">0 B</strong></span>
            </div>
            <button type="button" class="btn-confirm" onclick="resetClientTraffic()">重置流量</button>
          </div>
          <p class="field-help" style="margin-bottom:0">点击重置会将上下行数据清零，不可恢复。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="ec-expiry-at">过期时间</label>
          <input id="ec-expiry-at" type="datetime-local">
          <p class="field-help">留空表示不过期。</p>
        </div>
        <div class="form-actions modal-actions">
          <button type="button" class="btn-cancel" onclick="closeEditClient()">取消</button>
          <button type="submit" class="btn-modal-primary" onclick="saveEditClient()">保存</button>
        </div>
      </form>
    </div>
  </div>

  <div class="app-shell">
    <button id="sidebar-toggle" onclick="toggleSidebar()" aria-label="展开菜单">☰</button>
    <aside class="sidebar">
      <div class="brand">MiGate</div>
      <div class="subtitle">轻量单二进制面板，专注协议、客户端与 Xray 管理。</div>
      <nav>
        <a class="active" href="#">概览</a>
        <a href="#inbounds">入站</a>
        <a href="#outbound">出站</a>
        <a href="#routing">路由</a>
        <a href="#xray">核心</a>
        <a href="#settings">设置</a>
      </nav>
      <div class="account-panel" aria-label="当前账号">
        <div class="account-label">当前用户</div>
        <div id="current-username" class="account-name">加载中...</div>
        <div class="account-actions">
          <button id="logout-button" class="secondary" onclick="logoutPanel()">登出</button>
          <button id="theme-toggle" class="secondary" onclick="toggleTheme()">深色模式</button>
        </div>
      </div>
    </aside>
    <div id="sidebar-overlay" onclick="closeSidebar()"></div>
    <main>
      <section id="overview" class="overview-grid" aria-label="概览指标">
        <div id="version-banner" class="version-banner" style="display:none; grid-column:1 / -1"></div>
        <div class="card panel"><div>入站</div><div id="inbound-count" class="metric">0</div><p>VLESS / VMess / Trojan / Shadowsocks</p></div>
        <div class="card panel"><div>客户端</div><div id="client-count" class="metric">0</div><p>活跃 / 总计</p></div>
        <div class="card panel"><div>总流量</div><div id="total-traffic" class="metric">0 B</div><p>所有客户端上行+下行累计</p></div>
        <div class="card panel"><div>出站</div><div id="outbound-stats" class="metric">0</div><p>已启用 / 总计</p></div>
        <div class="card panel"><div>路由规则</div><div id="routing-stats" class="metric">0</div><p>已启用 / 总计</p></div>
        <div class="card panel"><div>Xray</div><div id="xray-status-metric" class="metric">检查中...</div><p>运行状态</p></div>
        <div class="card panel"><div>Sing-box</div><div id="singbox-status-metric" class="metric">检查中...</div><p>Hysteria2 运行状态</p></div>
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
          <button class="secondary" onclick="navigateTo('outbound')">出站</button>
          <input id="inbound-search" type="text" placeholder="搜索入站..." class="search-input" oninput="filterInbounds()">
          <select id="inbound-sort" class="sort-select" onchange="sortInbounds()">
            <option value="id">默认排序</option>
            <option value="port">按端口</option>
            <option value="protocol">按协议</option>
            <option value="clients">按客户端数</option>
          </select>
        </div>
        <div id="inbound-list" class="list muted">正在加载入站...</div>
      </section>
      <section id="outbound" class="card panel">
        <h2 class="section-title">出站管理</h2>
        <p class="muted" style="margin-bottom:16px">配置链式代理转发（SOCKS5 / HTTP），实现流量经外部代理链路中转。</p>
        <div class="actions">
          <button onclick="openCreateOutbound()">新建出站</button>
          <button class="secondary" onclick="batchSpeedTest()">一键测速</button>
          <button class="secondary" onclick="checkVPNGateOutboundHealth()">检测 VPN Gate</button>
          <button class="secondary" onclick="showVPNGateDialog()">VPN Gate</button>
        </div>
        <div id="outbound-list" class="list muted">正在加载出站...</div>
      </section>
      <section id="routing" class="card panel">
        <h2 class="section-title">路由规则</h2>
        <p class="muted" style="margin-bottom:16px">按域名、入站、协议将流量分配到指定出站。规则按顺序匹配，命中的规则立即生效。</p>
        <div class="actions">
          <button onclick="openCreateRoutingRule()">新建规则</button>
        </div>
        <div id="routing-rule-list" class="list muted">正在加载路由规则...</div>
        <div class="notice" style="margin-top:16px">
          <div class="notice-title">提示</div>
          <div class="notice-copy">启用规则后系统会自动重写 Xray 配置文件并重启服务。可用的域名格式包括 <code>google.com</code>（精确域名）、<code>geosite:netflix</code>（地理位置组）、<code>regex:.*\.youtube\.com$</code>（正则）。</div>
        </div>
      </section>
      <section id="xray" class="card panel">
        <h2 class="section-title">Xray 管理</h2>
        <p class="muted" style="margin-bottom:16px">查看 Xray 服务状态，应用配置变更。</p>
        <div class="xray-status-panel">
          <div><strong>状态</strong>：<span id="xray-status">未知</span></div>
          <div><strong>版本</strong>：<span id="xray-version">-</span></div>
          <div><strong>托管</strong>：<span id="xray-managed">-</span></div>
          <div><strong>服务</strong>：<span id="xray-service">xray</span></div>
        </div>
        <div id="xray-unsupported-warning" class="xray-warning muted" style="display:none;margin-top:12px;padding:12px 16px;border-radius:var(--radius-md);background:var(--surface-warning);color:var(--fg)">当前 Xray 版本不支持 Hysteria2 协议，需要使用 sing-box 等后端配合。</div>
        <div id="vpngate-auto-health-card" class="muted" style="display:none;margin-top:12px;padding:12px 16px;border-radius:var(--radius-md);background:var(--surface-subtle)">
          <span><strong>VPN Gate 自动检测</strong></span>
          <span id="vpngate-auto-health-status" style="margin-left:8px">检查中...</span>
          <button class="icon-btn" onclick="refreshAutoHealthStatus()" title="刷新" style="margin-left:8px;font-size:11px;float:right">⟳</button>
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
            <button class="secondary" onclick="loadXrayLogs()">查看日志</button>
          </div>
        </div>
        <div id="xray-result" class="notice-slot"></div>
        <div id="xray-config-preview" class="list muted" style="margin-top:12px;display:none"><div class="xray-preview-header"><span class="muted" style="font-weight:600">Xray 配置预览</span><button class="icon-btn" onclick="closeXrayConfig()" title="关闭" style="font-size:12px">✕</button></div><pre id="xray-config-json" class="xray-preview-pre"></pre></div>
        <div id="xray-logs-preview" class="list muted" style="margin-top:12px;display:none"><div class="xray-preview-header"><span class="muted" style="font-weight:600">Xray 运行日志</span><button class="icon-btn" onclick="closeXrayLogs()" title="关闭" style="font-size:12px">✕</button></div><pre id="xray-logs-text" class="xray-preview-pre mono"></pre></div>
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
          <div class="field-group span-2" style="border:1px solid var(--border);border-radius:8px;padding:12px;background:var(--surface-subtle)">
            <label class="field-label" style="margin-top:0">MiGate 服务状态</label>
            <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
              <div>
                <span id="svc-status-badge" style="display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:12px;font-size:13px;background:var(--surface-subtle)">检查中...</span>
                <span id="svc-status-detail" class="muted" style="margin-left:12px;font-size:13px"></span>
              </div>
              <button type="button" class="secondary" onclick="fetchServiceStatus()" style="font-size:12px">刷新状态</button>
            </div>
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="set-web-path">Web 基础路径</label>
            <input id="set-web-path" placeholder="例如 /">
            <p class="field-help">默认使用根路径；反代到子路径时再修改。</p>
          </div>
          <div class="field-group span-2" style="margin-top:var(--space-4);padding-top:var(--space-4);border-top:1px solid var(--line)">
            <h3 style="margin-bottom:var(--space-3);font-size:var(--text-md)">TLS 证书（Let's Encrypt）</h3>
            <p class="field-help">配置域名后可通过 acme.sh 自动获取 Let's Encrypt 证书，证书文件保存在面板配置目录下。</p>
          </div>
          <div class="field-group">
            <label class="field-label" for="set-cert-domain">域名</label>
            <input id="set-cert-domain" placeholder="例如 example.com">
          </div>
          <div class="field-group">
            <label class="field-label" for="set-cert-email">邮箱</label>
            <input id="set-cert-email" placeholder="admin@example.com">
          </div>
          <div class="field-group span-2" id="cert-status-area" style="display:none">
            <div class="cert-status-box" style="padding:var(--space-3) var(--space-4);border-radius:var(--radius-md);background:var(--surface-subtle);margin-bottom:var(--space-3)">
              <div><strong>证书状态</strong>：<span id="cert-status-label">未获取</span></div>
              <div id="cert-path-label" class="muted" style="font-size:var(--text-sm);margin-top:var(--space-1)"></div>
            </div>
            <button type="button" class="secondary" id="btn-issue-cert" onclick="issueCert()">获取证书</button>
          </div>
          <div class="action-toolbar settings-toolbar span-2">
            <div class="toolbar-copy">
              <strong>设置操作</strong>
              <span>保存配置后按需重启 MiGate 服务。</span>
            </div>
            <div class="toolbar-actions">
              <button type="button" class="secondary" onclick="loadSettings()">刷新</button>
              <button type="submit" onclick="saveSettings()">保存设置</button>
              <button type="button" class="danger" onclick="restartService()">重启服务</button>
            </div>
          </div>
        </form>
        <div id="settings-status" class="notice-slot"></div>
      </section>
    <!-- Create outbound dialog -->
    <div id="create-outbound-dialog" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeModal()">
      <div class="modal-content" style="max-width:480px">
        <div class="modal-header">
          <h3 class="modal-title">新建出站</h3>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <form id="create-outbound-form" class="form-grid modal-form" onsubmit="return false">
          <div class="field-group span-2">
            <label class="field-label" for="co-tag">出站标识</label>
            <input id="co-tag" placeholder="例如 my-socks-proxy" required>
            <p class="field-help">唯一标识，用于 Xray 路由规则中的 tag 引用。</p>
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="co-remark">备注</label>
            <input id="co-remark" placeholder="可选，留空使用标识">
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="co-protocol">协议</label>
            <select id="co-protocol">
              <option value="socks">SOCKS5</option>
              <option value="http">HTTP</option>
            </select>
          </div>
          <div class="field-group" id="co-address-row">
            <label class="field-label" for="co-address">地址</label>
            <input id="co-address" placeholder="IP 或域名">
          </div>
          <div class="field-group" id="co-port-row">
            <label class="field-label" for="co-port">端口</label>
            <input id="co-port" type="number" min="1" max="65535" placeholder="1080">
          </div>
          <div class="field-group span-2" id="co-cred-row">
            <label class="field-label">认证</label>
            <div style="display:flex;gap:8px">
              <input id="co-username" placeholder="用户名（可选）" style="flex:1">
              <input id="co-password" type="password" placeholder="密码（可选）" style="flex:1">
            </div>
          </div>
        </form>
        <div class="modal-footer">
          <button class="secondary" onclick="closeModal()">取消</button>
          <button onclick="submitCreateOutbound()" class="btn-modal-primary">创建</button>
        </div>
      </div>
    </div>

    <!-- Edit outbound dialog -->
    <div id="edit-outbound-dialog" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeModal()">
      <div class="modal-content" style="max-width:480px">
        <div class="modal-header">
          <h3 class="modal-title">编辑出站</h3>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <form id="edit-outbound-form" class="form-grid modal-form" onsubmit="return false">
          <input type="hidden" id="eo-id">
          <div class="field-group span-2">
            <label class="field-label" for="eo-tag">出站标识</label>
            <input id="eo-tag" placeholder="例如 my-socks-proxy" required>
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="eo-remark">备注</label>
            <input id="eo-remark" placeholder="可选，留空使用标识">
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="eo-protocol">协议</label>
            <select id="eo-protocol">
              <option value="socks">SOCKS5</option>
              <option value="http">HTTP</option>
            </select>
          </div>
          <div class="field-group" id="eo-address-row">
            <label class="field-label" for="eo-address">地址</label>
            <input id="eo-address" placeholder="IP 或域名">
          </div>
          <div class="field-group" id="eo-port-row">
            <label class="field-label" for="eo-port">端口</label>
            <input id="eo-port" type="number" min="1" max="65535" placeholder="1080">
          </div>
          <div class="field-group span-2" id="eo-cred-row">
            <label class="field-label">认证</label>
            <div style="display:flex;gap:8px">
              <input id="eo-username" placeholder="用户名（可选）" style="flex:1">
              <input id="eo-password" type="password" placeholder="密码（可选）" style="flex:1">
            </div>
          </div>
          <div class="field-group span-2">
            <label class="modal-checkbox">
              <input type="checkbox" id="eo-enabled" checked>
              已启用
            </label>
          </div>
        </form>
        <div class="modal-footer">
          <button class="secondary" onclick="closeModal()">取消</button>
          <button onclick="submitEditOutbound()" class="btn-modal-primary">保存</button>
        </div>
      </div>
    </div>
    <!-- Create routing rule dialog -->
    <div id="create-routing-rule-dialog" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeModal()">
      <div class="modal-content" style="max-width:480px">
        <div class="modal-header">
          <h3 class="modal-title">新建路由规则</h3>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <form id="create-routing-rule-form" class="form-grid modal-form" onsubmit="return false">
          <div class="field-group span-2">
            <label class="field-label" for="crr-outbound">目标出站 *</label>
            <select id="crr-outbound" required>
              <option value="">-- 选择出站 --</option>
            </select>
            <p class="field-help">匹配此条件时转发到哪个出站。</p>
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="crr-domain">域名匹配</label>
            <input id="crr-domain" placeholder="例如 geosite:netflix 或 google.com">
            <p class="field-help">留空表示匹配所有域名。支持 geosite: 和 regex: 前缀。</p>
          </div>
          <div class="field-group">
            <label class="field-label" for="crr-inbound">来源入站</label>
            <select id="crr-inbound">
              <option value="">留空 = 所有入站</option>
            </select>
          </div>
          <div class="field-group">
            <label class="field-label" for="crr-protocol">协议匹配</label>
            <input id="crr-protocol" placeholder="例如 dns, bittorrent">
          </div>
          <div class="field-group span-2">
            <label class="modal-checkbox">
              <input type="checkbox" id="crr-enabled" checked>
              已启用
            </label>
          </div>
        </form>
        <div class="modal-footer">
          <button class="secondary" onclick="closeModal()">取消</button>
          <button onclick="submitCreateRoutingRule()" class="btn-modal-primary">创建</button>
        </div>
      </div>
    </div>
    <!-- Edit routing rule dialog -->
    <div id="edit-routing-rule-dialog" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeModal()">
      <div class="modal-content" style="max-width:480px">
        <div class="modal-header">
          <h3 class="modal-title">编辑路由规则</h3>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <form id="edit-routing-rule-form" class="form-grid modal-form" onsubmit="return false">
          <div class="field-group span-2">
            <label class="field-label" for="err-outbound">目标出站 *</label>
            <select id="err-outbound" required>
              <option value="">-- 选择出站 --</option>
            </select>
            <p class="field-help">匹配此条件时转发到哪个出站。</p>
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="err-domain">域名匹配</label>
            <input id="err-domain" placeholder="例如 geosite:netflix 或 google.com">
            <p class="field-help">留空表示匹配所有域名。</p>
          </div>
          <div class="field-group">
            <label class="field-label" for="err-inbound">来源入站</label>
            <select id="err-inbound">
              <option value="">留空 = 所有入站</option>
            </select>
          </div>
          <div class="field-group">
            <label class="field-label" for="err-protocol">协议匹配</label>
            <input id="err-protocol" placeholder="例如 dns, bittorrent">
          </div>
          <div class="field-group span-2">
            <label class="modal-checkbox">
              <input type="checkbox" id="err-enabled" checked>
              已启用
            </label>
          </div>
          <input type="hidden" id="err-id">
        </form>
        <div class="modal-footer">
          <button class="secondary" onclick="closeModal()">取消</button>
          <button onclick="submitEditRoutingRule()" class="btn-modal-primary">保存</button>
        </div>
      </div>
    </div>

    <!-- VPN Gate dialog -->
    <div id="vpngate-dialog" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeModal()">
      <div class="modal-content" style="max-width:800px;max-height:80vh;overflow:hidden;display:flex;flex-direction:column">
        <div class="modal-header">
          <h3 class="modal-title">VPN Gate 公共服务器</h3>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <div style="flex:1;overflow-y:auto;padding:12px 16px">
          <div id="vpngate-loading" style="text-align:center;padding:40px;color:var(--muted)">
            <p style="font-size:18px;margin-bottom:8px">正在获取服务器列表...</p>
            <p>从 VPN Gate API 获取全球公共代理服务器</p>
          </div>
          <div id="vpngate-error" style="display:none;text-align:center;padding:40px">
            <p style="color:var(--danger);font-size:16px;margin-bottom:8px">获取失败</p>
            <p id="vpngate-error-msg" class="muted" style="margin-bottom:16px"></p>
            <button class="secondary" onclick="showVPNGateDialog()">重试</button>
          </div>
          <div id="vpngate-list" style="display:none">
            <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <span id="vpngate-count" class="muted"></span>
              <input id="vpngate-filter" type="text" placeholder="搜索国家/IP/运营商..." style="flex:1;min-width:180px;max-width:260px" oninput="renderVPNGateList()">
              <select id="vpngate-type-filter" style="width:110px" onchange="renderVPNGateList()">
                <option value="all">全部类型</option>
                <option value="家宽">家宽</option>
                <option value="商宽">商宽</option>
              </select>
              <input id="vpngate-country-filter" type="text" placeholder="国家 JP/US" style="width:110px" oninput="renderVPNGateList()">
              <input id="vpngate-max-ping" type="number" min="1" placeholder="延迟≤ms" style="width:110px" oninput="renderVPNGateList()">
              <select id="vpngate-topn" style="width:90px">
                <option value="5">Top 5</option>
                <option value="10" selected>Top 10</option>
                <option value="20">Top 20</option>
              </select>
              <button class="secondary" onclick="smartSelectVPNGate()">智能选择</button>
              <button onclick="importSelectedVPNGate()" id="vpngate-import-btn" disabled>导入选中</button>
            </div>
            <table style="width:100%;border-collapse:collapse;font-size:13px">
              <thead>
                <tr style="background:var(--surface-subtle)">
                  <th style="padding:6px 8px;text-align:left"><input type="checkbox" id="vpngate-select-all" onchange="toggleAllVPNGate()"></th>
                  <th style="padding:6px 8px;text-align:left">国家</th>
                  <th style="padding:6px 8px;text-align:left">IP</th>
                  <th style="padding:6px 8px;text-align:right">延迟</th>
                  <th style="padding:6px 8px;text-align:right">速度</th>
                  <th style="padding:6px 8px;text-align:left">类型</th>
                  <th style="padding:6px 8px;text-align:left">运营商</th>
                </tr>
              </thead>
              <tbody id="vpngate-tbody"></tbody>
            </table>
          </div>
        </div>
        <div class="modal-footer">
          <span class="muted" style="font-size:12px">导入为 SOCKS5 出站（端口 1080），来自 vpngate.net</span>
          <button class="secondary" onclick="closeModal()">关闭</button>
        </div>
      </div>
    </div>
    </main>
  </div>
  <script>
    function basePath() {
      const pathname = window.location.pathname || '/';
      const loginIndex = pathname.indexOf('/login');
      if (loginIndex >= 0) return pathname.slice(0, loginIndex);
      if (pathname === '/') return '';
      return pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
    }
    function apiPath(path) { return basePath() + path; }
    function panelPath(path) { return basePath() + path; }

    const inboundList = document.getElementById('inbound-list');
    const inboundCount = document.getElementById('inbound-count');
    const clientCount = document.getElementById('client-count');
    const totalTraffic = document.getElementById('total-traffic');
    const xrayStatusMetric = document.getElementById('xray-status-metric');

    function renderInbounds(inbounds) {
      window._cachedInbounds = inbounds;  // cache for port conflict check
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
            '<button class="icon-btn" onclick="toggleClientSection(' + inbound.id + ')" title="展开客户端">' + ((inbound.clients || []).length) + 'C</button>' +
            '<button class="icon-btn" onclick="editInbound(' + inbound.id + ')" title="编辑">Edit</button>' +
            '<button class="icon-btn" onclick="toggleInbound(' + inbound.id + ')" title="启用/禁用">' + (inbound.enabled ? 'ON' : 'OFF') + '</button>' +
            '<button class="danger-icon-btn" onclick="deleteInbound(' + inbound.id + ')" title="删除">DEL</button>' +
          '</div>' +
        '</div>' +
        '<div id="client-section-' + inbound.id + '" class="client-subsection" style="display:none"></div>';
      }).join('');
    }

    function filterInbounds() { applyInboundFilterSort(); }
    function sortInbounds() { applyInboundFilterSort(); }
    function applyInboundFilterSort() {
      const q = (document.getElementById('inbound-search').value || '').toLowerCase();
      const sortBy = (document.getElementById('inbound-sort').value || 'id');
      let list = (window._cachedInbounds || []).slice();
      if (q) {
        list = list.filter(ib =>
          (ib.remark || '').toLowerCase().includes(q) ||
          (ib.protocol || '').toLowerCase().includes(q) ||
          String(ib.port).includes(q) ||
          (ib.network || '').toLowerCase().includes(q)
        );
      }
      list.sort((a, b) => {
        if (sortBy === 'port') return a.port - b.port;
        if (sortBy === 'protocol') return (a.protocol || '').localeCompare(b.protocol || '');
        if (sortBy === 'clients') return (b.clients || []).length - (a.clients || []).length;
        return a.id - b.id;
      });
      renderInbounds(window._cachedInbounds);  // re-render full list (stats etc.)
      // Now filter the DOM rows
      const allowedIds = new Set(list.map(ib => ib.id));
      const rows = inboundList.querySelectorAll('.resource-row');
      if (rows.length > 0 && allowedIds.size === 0) {
        inboundList.innerHTML = '<div class="empty-state"><div class="empty-state-title">无匹配结果</div><div class="empty-state-copy">没有入站匹配当前的搜索或筛选条件。</div></div>';
        return;
      }
      rows.forEach(row => {
        const idMatch = row.querySelector('[onclick*="editInbound"]');
        if (idMatch) {
          const m = idMatch.getAttribute('onclick').match(/editInbound\((\d+)\)/);
          if (m) row.style.display = allowedIds.has(Number(m[1])) ? '' : 'none';
        }
      });
      // Also hide/show client subsections
      const subs = inboundList.querySelectorAll('.client-subsection');
      subs.forEach(el => {
        const m = el.id.match(/client-section-(\d+)/);
        if (m) el.style.display = (!allowedIds.has(Number(m[1])) || el.style.display === 'none') ? 'none' : el.style.display;
      });
      // Reorder rows to match sort order
      const allEls = Array.from(inboundList.children);
      const orderMap = {};
      list.forEach((ib, i) => orderMap[ib.id] = i);
      allEls.sort((a, b) => {
        const mA = a.id ? a.id.match(/client-section-(\d+)/) : null;
        const mB = b.id ? b.id.match(/client-section-(\d+)/) : null;
        const idA = mA ? Number(mA[1]) : (a.querySelector('[onclick*="editInbound"]')?.getAttribute('onclick')?.match(/editInbound\((\d+)\)/)?.[1] || 9999);
        const idB = mB ? Number(mB[1]) : (b.querySelector('[onclick*="editInbound"]')?.getAttribute('onclick')?.match(/editInbound\((\d+)\)/)?.[1] || 9999);
        return (orderMap[idA] ?? 9999) - (orderMap[idB] ?? 9999);
      });
      allEls.forEach(el => inboundList.appendChild(el));
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
    function escHtml(value) { return escapeHtml(value); }

    function escapeJsString(value) {
      return escapeHtml(String(value || '').replace(/\\/g, '\\\\').replace(/"/g, '\\&quot;').replace(/'/g, "\\&#39;").replace(/\n/g, '\\n').replace(/\r/g, ''));
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
      try {
        const response = await fetch(apiPath('/api/inbounds'));
        if (!response.ok) { console.error('loadInbounds: API error', response.status); return; }
        const data = await response.json();
        renderInbounds(data.inbounds || []);
        // Fetch Xray status for overview
        try {
          const xr = await fetch(apiPath('/api/xray/status'));
          const xs = await xr.json();
          if (xs && xs.service !== undefined) {
            xrayStatusMetric.textContent = xs.service === 'running' ? '运行中' : (xs.service === 'stopped' ? '已停止' : xs.service);
          }
        } catch (e) {
          xrayStatusMetric.textContent = '无法连接';
        }
        // Fetch sing-box status for overview
        try {
          const sr = await fetch(apiPath('/api/singbox/status'));
          const ss = await sr.json();
          if (ss && ss.installed !== undefined) {
            const el = document.getElementById('singbox-status-metric');
            if (!ss.installed) {
              el.textContent = '未安装';
            } else {
              el.textContent = ss.status === 'running' ? '运行中' : (ss.status === 'stopped' ? '已停止' : ss.status);
            }
          }
        } catch (e) {
          document.getElementById('singbox-status-metric').textContent = '无法连接';
        }
      } catch(e) {
        console.error('loadInbounds error:', e);
      }
    }

    async function loadOutbounds() {
      const el = document.getElementById('outbound-list');
      if (!el) return;
      try {
        const resp = await fetch(apiPath('/api/outbounds'));
        if (!resp.ok) { el.innerHTML = '<div class=\"muted\" style=\"padding:12px\">加载失败</div>'; return; }
        const data = await resp.json();
        const outbounds = Array.isArray(data) ? data : (data.outbounds || []);
        if (!outbounds.length) {
          el.innerHTML = renderEmptyState('暂无出站', '出站用于链式代理转发。点击上方"新建出站"添加 SOCKS5 / HTTP 代理。');
          return;
        }
        el.innerHTML = '<div style=\"display:grid;grid-template-columns:1fr;gap:8px\" id=\"outbound-drag-container\">' +
          outbounds.map(ob => renderOutboundCard(ob)).join('') +
          '</div>';
        setTimeout(attachOutboundDragHandlers, 0);
      } catch(e) {
        el.innerHTML = '<div class=\"muted\" style=\"padding:12px\">加载失败</div>';
      }
    }

    function renderOutboundCard(ob) {
      const protoLabel = ob.protocol === 'freedom' ? '直接连接' :
        ob.protocol === 'blackhole' ? '阻断' : ob.protocol.toUpperCase();
      const detail = ob.address ? ob.address + ':' + ob.port : '';
      const editable = ob.protocol !== 'freedom' && ob.protocol !== 'blackhole';
      const enabledColor = ob.enabled ? 'var(--green)' : 'var(--muted)';
      const pinned = ob.sort === 0 || ob.sort === 1;
      const isDraggable = editable && !pinned;
      return '<div class=\"card\" style=\"padding:12px 16px;display:flex;align-items:center;gap:12px\"' +
        (isDraggable ? ' draggable=\"true\" data-ob-id=\"' + ob.id + '\"' : '') + '>' +
        '<span style=\"color:' + enabledColor + ';font-size:18px\">' + (ob.enabled ? '&#9679;' : '&#9678;') + '</span>' +
        '<div style=\"flex:1;min-width:0\">' +
        '<div style=\"font-weight:600;font-size:var(--text-sm)\">' + escHtml(ob.remark||ob.tag) + '</div>' +
        '<div class=\"muted\" style=\"font-size:var(--text-xs)\">' + escHtml(ob.tag) + ' &middot; ' + protoLabel + (detail ? ' &middot; ' + escHtml(detail) : '') + ' <span id=\"ping-' + ob.id + '\"></span></div>' +
        '</div><div style=\"display:flex;gap:6px\">' +
        (editable ? '<button class=\"icon-btn\" onclick=\"speedTestOutbound(' + ob.id + ')\" title=\"测速\">&#9889;</button>' +
          '<button class=\"icon-btn\" onclick=\"openEditOutbound(' + ob.id + ')\" title=\"编辑\">&#9998;</button>' +
          '<button class=\"danger-icon-btn\" onclick=\"deleteOutbound(' + ob.id + ')\" title=\"删除\">&#10005;</button>' :
        '<span class=\"muted\" style=\"font-size:var(--text-xs);padding:4px 8px\">内置</span>') +
        '</div></div>';
    }

    function speedTestOutbound(id) {
      const el = document.getElementById('ping-' + id);
      if (!el) return;
      el.textContent = '测速中...';
      fetch(apiPath('/api/outbounds/' + id + '/ping')).then(function(r) { return r.json(); }).then(function(data) {
        if (data.latency >= 0) {
          el.textContent = ' ' + data.latency + 'ms';
          el.style.color = data.latency < 200 ? 'var(--green)' : data.latency < 500 ? 'var(--accent2)' : 'var(--danger)';
        } else {
          el.textContent = ' 超时';
          el.style.color = 'var(--danger)';
        }
      }).catch(function() {
        el.textContent = ' 失败';
        el.style.color = 'var(--danger)';
      });
    }

    async function batchSpeedTest() {
      var btn = document.querySelector('[onclick*=\"batchSpeedTest\"]');
      if (btn) btn.disabled = true;
      document.querySelectorAll('[id^=\"ping-\"]').forEach(function(el) {
        el.textContent = ' 测速中';
        el.style.color = 'var(--text)';
      });
      try {
        var resp = await fetch(apiPath('/api/outbounds/speedtest-all'), {method:'POST'});
        if (!resp.ok) { showToast('测速失败', 'error'); return; }
        var results = await resp.json();
        var okCount = 0, failCount = 0;
        Object.keys(results).forEach(function(id) {
          var r = results[id];
          var el = document.getElementById('ping-' + id);
          if (!el) return;
          if (r.latency >= 0) {
            var ms = Number(r.latency).toFixed(0);
            el.textContent = ' ' + ms + 'ms';
            el.style.color = ms < 200 ? 'var(--green)' : (ms < 500 ? 'orange' : 'var(--danger)');
            okCount++;
          } else {
            el.textContent = ' 失败';
            el.style.color = 'var(--danger)';
            failCount++;
          }
        });
        showToast('完成: ' + okCount + ' 成功, ' + failCount + ' 失败', okCount > 0 ? 'success' : 'error');
      } catch(e) {
        showToast('测速异常: ' + e.message, 'error');
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    async function checkVPNGateOutboundHealth() {
      var btn = document.querySelector('[onclick*=\"checkVPNGateOutboundHealth\"]');
      if (btn) { btn.disabled = true; btn.textContent = '检测中...'; }
      try {
        var resp = await fetch(apiPath('/api/vpngate/outbounds/health'), {method:'POST'});
        if (!resp.ok) { showToast('VPN Gate 健康检测失败', 'error'); return; }
        var data = await resp.json();
        var summary = data.summary || {total:0, ok:0, fail:0};
        (data.results || []).forEach(function(r) {
          var el = document.getElementById('ping-' + r.id);
          if (!el) return;
          if (r.ok) {
            el.textContent = ' VPN Gate: ' + r.latency_ms + 'ms';
            el.style.color = r.latency_ms < 300 ? 'var(--green)' : (r.latency_ms < 800 ? 'orange' : 'var(--danger)');
          } else {
            el.textContent = ' VPN Gate: 失败';
            el.style.color = 'var(--danger)';
          }
        });
        if (summary.total === 0) {
          showToast('没有已启用的 VPN Gate 出站', 'error');
        } else {
          showToast('VPN Gate 健康检测完成：' + summary.ok + '/' + summary.total + ' 可用', summary.ok > 0 ? 'success' : 'error');
        }
      } catch(e) {
        showToast('VPN Gate 健康检测异常: ' + e.message, 'error');
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = '检测 VPN Gate'; }
      }
    }

    function attachOutboundDragHandlers() {
      var container = document.getElementById('outbound-drag-container');
      if (!container) return;
      var draggedEl = null;
      container.addEventListener('dragstart', function(e) {
        var card = e.target.closest('[draggable]');
        if (!card) return;
        draggedEl = card;
        e.dataTransfer.effectAllowed = 'move';
        card.style.opacity = '0.4';
      });
      container.addEventListener('dragend', function(e) {
        var card = e.target.closest('[draggable]');
        if (card) card.style.opacity = '';
      });
      container.addEventListener('dragover', function(e) {
        var card = e.target.closest('[draggable]');
        if (!card || card === draggedEl || !draggedEl) return;
        e.preventDefault();
        var rect = card.getBoundingClientRect();
        var mid = rect.top + rect.height / 2;
        if (e.clientY < mid) {
          container.insertBefore(draggedEl, card);
        } else {
          container.insertBefore(draggedEl, card.nextSibling);
        }
      });
      container.addEventListener('drop', function(e) {
        e.preventDefault();
        if (!draggedEl) return;
        var ids = [];
        container.querySelectorAll('[data-ob-id]').forEach(function(el) {
          ids.push(parseInt(el.getAttribute('data-ob-id')));
        });
        if (!ids.length) return;
        fetch(apiPath('/api/outbounds/reorder'), {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ids: ids})
        }).then(async function(resp) {
          if (!resp.ok) { showToast('排序保存失败', 'error'); await loadOutbounds(); return; }
          showToast('排序已保存', 'success');
        }).catch(function() { showToast('排序保存失败', 'error'); loadOutbounds(); });
      });
    }

    function showModal(id) {
      document.getElementById(id).style.display = 'flex';
    }
    function closeModal() {
      document.querySelectorAll('.modal-overlay').forEach(function(el) {
        el.style.display = 'none';
      });
    }

    function openCreateOutbound() {
      ['co-tag','co-remark','co-address'].forEach(id => document.getElementById(id).value = '');
      document.getElementById('co-protocol').value = 'socks';
      document.getElementById('co-port').value = '1080';
      document.getElementById('co-username').value = '';
      document.getElementById('co-password').value = '';
      document.getElementById('co-address-row').style.display = '';
      document.getElementById('co-port-row').style.display = '';
      document.getElementById('co-cred-row').style.display = '';
      showModal('create-outbound-dialog');
    }

    document.addEventListener('change', function(e) {
      if (e.target.id === 'co-protocol') {
        const isRemote = e.target.value === 'socks' || e.target.value === 'http';
        ['address','port','cred'].forEach(pt => {
          const el = document.getElementById('co-' + pt + '-row');
          if (el) el.style.display = isRemote ? '' : 'none';
        });
      }
      if (e.target.id === 'eo-protocol') {
        const isRemote = e.target.value === 'socks' || e.target.value === 'http';
        ['address','port','cred'].forEach(pt => {
          const el = document.getElementById('eo-' + pt + '-row');
          if (el) el.style.display = isRemote ? '' : 'none';
        });
      }
    });

    async function submitCreateOutbound() {
      const tag = document.getElementById('co-tag').value.trim();
      if (!tag) { showToast('请输入出站标识', 'error'); return; }
      const remark = document.getElementById('co-remark').value.trim() || tag;
      const protocol = document.getElementById('co-protocol').value;
      const body = {tag: tag, remark: remark, protocol: protocol};
      if (protocol === 'socks' || protocol === 'http') {
        body.address = document.getElementById('co-address').value.trim();
        if (!body.address) { showToast('请输入代理地址', 'error'); return; }
        body.port = parseInt(document.getElementById('co-port').value) || 0;
        if (body.port <= 0 || body.port > 65535) { showToast('请输入有效端口(1-65535)', 'error'); return; }
        const user = document.getElementById('co-username').value.trim();
        if (user) { body.username = user; body.password = document.getElementById('co-password').value; }
      }
      try {
        const resp = await fetch(apiPath('/api/outbounds'), {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify(body)
        });
        if (!resp.ok) { showToast('创建失败', 'error'); return; }
        showToast('出站已创建', 'success');
        closeModal();
        await loadOutbounds();
      } catch(e) { showToast('创建失败: ' + e.message, 'error'); }
    }

    function openEditOutbound(id) {
      fetch(apiPath('/api/outbounds')).then(function(r) { return r.json(); }).then(function(data) {
        var obs = Array.isArray(data) ? data : (data.outbounds || []);
        var ob = obs.find(function(o) { return o.id === id; });
        if (!ob) { showToast('未找到出站', 'error'); return; }
        document.getElementById('eo-id').value = ob.id;
        document.getElementById('eo-tag').value = ob.tag;
        document.getElementById('eo-remark').value = ob.remark;
        document.getElementById('eo-protocol').value = ob.protocol;
        document.getElementById('eo-address').value = ob.address || '';
        document.getElementById('eo-port').value = ob.port || '';
        document.getElementById('eo-username').value = ob.username || '';
        document.getElementById('eo-password').value = ob.password || '';
        document.getElementById('eo-enabled').checked = ob.enabled !== false;
        var isRemote = ob.protocol === 'socks' || ob.protocol === 'http';
        ['address','port','cred'].forEach(function(pt) {
          document.getElementById('eo-' + pt + '-row').style.display = isRemote ? '' : 'none';
        });
        showModal('edit-outbound-dialog');
      }).catch(function() { showToast('加载失败','error'); });
    }

    async function submitEditOutbound() {
      var id = parseInt(document.getElementById('eo-id').value);
      var tag = document.getElementById('eo-tag').value.trim();
      if (!tag) { showToast('请输入出站标识', 'error'); return; }
      var body = {
        tag: tag, remark: document.getElementById('eo-remark').value.trim() || tag,
        protocol: document.getElementById('eo-protocol').value,
        enabled: document.getElementById('eo-enabled').checked,
      };
      if (body.protocol === 'socks' || body.protocol === 'http') {
        body.address = document.getElementById('eo-address').value.trim();
        body.port = parseInt(document.getElementById('eo-port').value) || 0;
        var user = document.getElementById('eo-username').value.trim();
        if (user) { body.username = user; body.password = document.getElementById('eo-password').value; }
      }
      try {
        var resp = await fetch(apiPath('/api/outbounds/' + id), {
          method: 'PUT', headers: {'Content-Type':'application/json'},
          body: JSON.stringify(body)
        });
        if (!resp.ok) { showToast('更新失败', 'error'); return; }
        showToast('出站已更新', 'success');
        closeModal();
        await loadOutbounds();
      } catch(e) { showToast('更新失败: ' + e.message, 'error'); }
    }

    function deleteOutbound(id) {
      showConfirm('确认删除此出站？').then(async function(confirmed) {
        if (!confirmed) return;
        try {
          const resp = await fetch(apiPath('/api/outbounds/' + id), {method:'DELETE'});
          if (!resp.ok) { const err = await resp.json(); throw new Error(err.error || '删除失败'); }
          showToast('出站已删除', 'success');
          await loadOutbounds();
        } catch(e) { showToast('删除失败: ' + e.message, 'error'); }
      });
    }

    async function loadRoutingRules() {
      const el = document.getElementById('routing-rule-list');
      if (!el) return;
      try {
        const resp = await fetch(apiPath('/api/routing-rules'));
        if (!resp.ok) { el.innerHTML = '<div class=\"muted\" style=\"padding:12px\">加载失败</div>'; return; }
        const rules = await resp.json();
        if (!rules || !rules.length) {
          el.innerHTML = '<div class=\"empty-state\"><div class=\"empty-state-title\">暂无路由规则</div><div class=\"empty-state-copy\">添加规则可将特定域名、入站或协议的流量转发到指定出站。点击上方"新建规则"开始。</div></div>';
          return;
        }
        el.innerHTML = '<div id=\"routing-rule-drag-container\" style=\"display:grid;grid-template-columns:1fr;gap:8px\">' +
          rules.map(function(r) { return renderRoutingRuleCard(r); }).join('') +
          '</div>';
        setTimeout(attachRoutingRuleDragHandlers, 0);
      } catch(e) {
        el.innerHTML = '<div class=\"muted\" style=\"padding:12px\">加载失败</div>';
      }
    }

    function renderRoutingRuleCard(r) {
      var parts = [];
      if (r.inbound_tag) parts.push('入站: ' + escHtml(r.inbound_tag));
      if (r.domain) parts.push('域名: ' + escHtml(r.domain));
      if (r.protocol) parts.push('协议: ' + escHtml(r.protocol));
      if (!parts.length) parts.push('所有流量');
      var detail = parts.join(' & ');
      var enabledColor = r.enabled ? 'var(--green)' : 'var(--muted)';
      return '<div class=\"card\" style=\"padding:12px 16px;display:flex;align-items:center;gap:12px\" draggable=\"true\" data-rule-id=\"' + r.id + '\">' +
        '<span style=\"color:' + enabledColor + ';font-size:18px\">' + (r.enabled ? '&#9679;' : '&#9678;') + '</span>' +
        '<div style=\"flex:1;min-width:0\">' +
        '<div style=\"font-weight:600;font-size:var(--text-sm)\">' + detail + '</div>' +
        '<div class=\"muted\" style=\"font-size:var(--text-xs)\">→ ' + escHtml(r.outbound_tag) + '</div>' +
        '</div>' +
        '<button class=\"icon-btn\" onclick=\"openEditRoutingRule(this,' + r.id + ')\" title=\"编辑\" data-rule-outbound=\"' + escapeHtml(r.outbound_tag) + '\" data-rule-domain=\"' + escapeHtml(r.domain || '') + '\" data-rule-inbound=\"' + escapeHtml(r.inbound_tag || '') + '\" data-rule-protocol=\"' + escapeHtml(r.protocol || '') + '\" data-rule-enabled=\"' + (r.enabled||false) + '\">&#9998;</button>' +
        '<button class=\"danger-icon-btn\" onclick=\"deleteRoutingRule(' + r.id + ')\" title=\"删除\">&#10005;</button>' +
        '</div>';
    }


    function attachRoutingRuleDragHandlers() {
      var container = document.getElementById('routing-rule-drag-container');
      if (!container) return;
      var draggedEl = null;
      container.addEventListener('dragstart', function(e) {
        var card = e.target.closest('[draggable]');
        if (!card) return;
        draggedEl = card;
        e.dataTransfer.effectAllowed = 'move';
        card.style.opacity = '0.4';
      });
      container.addEventListener('dragend', function(e) {
        var card = e.target.closest('[draggable]');
        if (card) card.style.opacity = '';
      });
      container.addEventListener('dragover', function(e) {
        var card = e.target.closest('[draggable]');
        if (!card || card === draggedEl || !draggedEl) return;
        e.preventDefault();
        var rect = card.getBoundingClientRect();
        var mid = rect.top + rect.height / 2;
        if (e.clientY < mid) {
          container.insertBefore(draggedEl, card);
        } else {
          container.insertBefore(draggedEl, card.nextSibling);
        }
      });
      container.addEventListener('drop', function(e) {
        e.preventDefault();
        if (!draggedEl) return;
        var ids = [];
        container.querySelectorAll('[data-rule-id]').forEach(function(el) {
          ids.push(parseInt(el.getAttribute('data-rule-id')));
        });
        if (!ids.length) return;
        fetch(apiPath('/api/routing-rules/reorder'), {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ids: ids})
        }).then(async function(resp) {
          if (!resp.ok) { showToast('排序保存失败', 'error'); await loadRoutingRules(); return; }
          showToast('排序已保存', 'success');
        }).catch(function() { showToast('排序保存失败', 'error'); loadRoutingRules(); });
      });
    }
function openCreateRoutingRule() {
      document.getElementById('crr-domain').value = '';
      document.getElementById('crr-inbound').innerHTML = '<option value="">留空 = 所有入站</option>';
      document.getElementById('crr-protocol').value = '';
      document.getElementById('crr-enabled').checked = true;
      var sel = document.getElementById('crr-outbound');
      sel.innerHTML = '<option value="">-- 选择出站 --</option><option value="vpngate-pool">VPN Gate 出口池（自动均衡）</option>';
      // Load outbounds for the dropdown
      fetch(apiPath('/api/outbounds')).then(function(r) { return r.json(); }).then(function(data) {
        var obs = Array.isArray(data) ? data : (data.outbounds || []);
        obs.forEach(function(ob) {
          var opt = document.createElement('option');
          opt.value = ob.tag;
          opt.textContent = (ob.remark || ob.tag) + ' (' + ob.protocol + ')';
          sel.appendChild(opt);
        });
        sel.value = '';
      }).catch(function() {});
      // Load inbounds for the inbound dropdown
      fetch(apiPath('/api/inbounds')).then(function(r) { return r.json(); }).then(function(data) {
        var ibs = Array.isArray(data) ? data : (data.inbounds || []);
        var ibSel = document.getElementById('crr-inbound');
        ibs.forEach(function(ib) {
          var opt = document.createElement('option');
          opt.value = ib.remark || '';
          opt.textContent = (ib.remark || '未命名') + ' (端口 ' + ib.port + ')';
          ibSel.appendChild(opt);
        });
      }).catch(function() {});
      showModal('create-routing-rule-dialog');
    }

    async function submitCreateRoutingRule() {
      var outboundTag = document.getElementById('crr-outbound').value;
      if (!outboundTag) { showToast('请选择目标出站', 'error'); return; }
      var body = {
        outbound_tag: outboundTag,
        domain: document.getElementById('crr-domain').value.trim(),
        inbound_tag: document.getElementById('crr-inbound').value.trim(),
        protocol: document.getElementById('crr-protocol').value.trim(),
        enabled: document.getElementById('crr-enabled').checked,
      };
      try {
        var resp = await fetch(apiPath('/api/routing-rules'), {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify(body)
        });
        if (!resp.ok) { showToast('创建失败', 'error'); return; }
        showToast('路由规则已创建', 'success');
        closeModal();
        await Promise.all([loadRoutingRules(), loadXrayStatus()]);
      } catch(e) { showToast('创建失败: ' + e.message, 'error'); }
    }

    function deleteRoutingRule(id) {
      showConfirm('确认删除此路由规则？').then(async function(confirmed) {
        if (!confirmed) return;
        try {
          await fetch(apiPath('/api/routing-rules/' + id), {method:'DELETE'});
          showToast('路由规则已删除', 'success');
          await Promise.all([loadRoutingRules(), loadXrayStatus()]);
        } catch(e) { showToast('删除失败: ' + e.message, 'error'); }
      });
    }

    function openEditRoutingRule(btn, id) {
      var outboundTag = btn.getAttribute('data-rule-outbound');
      var domain = btn.getAttribute('data-rule-domain');
      var inboundTag = btn.getAttribute('data-rule-inbound');
      var protocol = btn.getAttribute('data-rule-protocol');
      var enabled = btn.getAttribute('data-rule-enabled') !== 'false';
      document.getElementById('err-id').value = id;
      document.getElementById('err-domain').value = domain || '';
      document.getElementById('err-inbound').innerHTML = '<option value="">留空 = 所有入站</option>';
      document.getElementById('err-protocol').value = protocol || '';
      document.getElementById('err-enabled').checked = enabled !== false;
      var sel = document.getElementById('err-outbound');
      sel.innerHTML = '<option value="">-- 选择出站 --</option><option value="vpngate-pool">VPN Gate 出口池（自动均衡）</option>';
      fetch(apiPath('/api/outbounds')).then(function(r) { return r.json(); }).then(function(data) {
        var obs = Array.isArray(data) ? data : (data.outbounds || []);
        obs.forEach(function(ob) {
          var opt = document.createElement('option');
          opt.value = ob.tag;
          opt.textContent = (ob.remark || ob.tag) + ' (' + ob.protocol + ')';
          sel.appendChild(opt);
          if (ob.tag === outboundTag) opt.selected = true;
        });
      }).catch(function() {});
      // Load inbounds for the inbound dropdown
      fetch(apiPath('/api/inbounds')).then(function(r) { return r.json(); }).then(function(data) {
        var ibs = Array.isArray(data) ? data : (data.inbounds || []);
        var ibSel = document.getElementById('err-inbound');
        ibs.forEach(function(ib) {
          var opt = document.createElement('option');
          opt.value = ib.remark || '';
          opt.textContent = (ib.remark || '未命名') + ' (端口 ' + ib.port + ')';
          ibSel.appendChild(opt);
          if ((ib.remark || '') === (inboundTag || '')) opt.selected = true;
        });
      }).catch(function() {});
      showModal('edit-routing-rule-dialog');
    }

    async function submitEditRoutingRule() {
      var id = parseInt(document.getElementById('err-id').value);
      var outboundTag = document.getElementById('err-outbound').value;
      if (!outboundTag) { showToast('请选择目标出站', 'error'); return; }
      var body = {
        outbound_tag: outboundTag,
        domain: document.getElementById('err-domain').value.trim(),
        inbound_tag: document.getElementById('err-inbound').value.trim(),
        protocol: document.getElementById('err-protocol').value.trim(),
        enabled: document.getElementById('err-enabled').checked,
      };
      try {
        var resp = await fetch(apiPath('/api/routing-rules/' + id), {
          method: 'PUT', headers: {'Content-Type':'application/json'},
          body: JSON.stringify(body)
        });
        if (!resp.ok) { showToast('保存失败', 'error'); return; }
        showToast('路由规则已更新', 'success');
        closeModal();
        await Promise.all([loadRoutingRules(), loadXrayStatus()]);
      } catch(e) { showToast('保存失败: ' + e.message, 'error'); }
    }

    /* --- VPN Gate --- */
    var vpngateServers = [];
    var vpngateSelected = {};

    async function showVPNGateDialog() {
      document.getElementById('vpngate-loading').style.display = '';
      document.getElementById('vpngate-error').style.display = 'none';
      document.getElementById('vpngate-list').style.display = 'none';
      vpngateServers = [];
      vpngateSelected = {};
      showModal('vpngate-dialog');
      try {
        const resp = await fetch(apiPath('/api/vpngate/servers'));
        if (!resp.ok) throw new Error(await resp.text());
        vpngateServers = await resp.json();
        document.getElementById('vpngate-loading').style.display = 'none';
        document.getElementById('vpngate-list').style.display = '';
        renderVPNGateList();
      } catch (e) {
        document.getElementById('vpngate-loading').style.display = 'none';
        document.getElementById('vpngate-error').style.display = '';
        document.getElementById('vpngate-error-msg').textContent = e.message;
      }
    }

    function filteredVPNGateServers() {
      const filterText = (document.getElementById('vpngate-filter').value || '').toLowerCase();
      const typeFilter = document.getElementById('vpngate-type-filter').value || 'all';
      const countryFilter = (document.getElementById('vpngate-country-filter').value || '').toLowerCase();
      const maxPing = parseInt(document.getElementById('vpngate-max-ping').value || '0', 10);
      return vpngateServers.filter(function(s) {
        const type = s.server_type || '家宽';
        if (typeFilter !== 'all' && type !== typeFilter) return false;
        if (maxPing > 0 && Number(s.ping || 0) > maxPing) return false;
        if (countryFilter && !String(s.country_short || '').toLowerCase().includes(countryFilter) && !String(s.country_long || '').toLowerCase().includes(countryFilter)) return false;
        if (!filterText) return true;
        return (s.hostname && s.hostname.toLowerCase().indexOf(filterText) >= 0) ||
               (s.country_long && s.country_long.toLowerCase().indexOf(filterText) >= 0) ||
               (s.country_short && s.country_short.toLowerCase().indexOf(filterText) >= 0) ||
               (s.operator && s.operator.toLowerCase().indexOf(filterText) >= 0) ||
               (s.ip && s.ip.indexOf(filterText) >= 0);
      });
    }

    function vpnGateQualityScore(s) {
      const ping = Math.max(1, Number(s.ping || 9999));
      const speed = Math.max(0, Number(s.speed || 0));
      const typeBonus = (s.server_type || '家宽') === '家宽' ? 50000 : 0;
      return speed / ping + typeBonus;
    }

    function toggleAllVPNGate() {
      const checked = document.getElementById('vpngate-select-all').checked;
      filteredVPNGateServers().forEach(function(s) {
        var i = vpngateServers.indexOf(s);
        if (checked) vpngateSelected[i] = true;
        else delete vpngateSelected[i];
      });
      updateVPNGateImportBtn();
      renderVPNGateList();
    }

    function smartSelectVPNGate() {
      vpngateSelected = {};
      const topN = parseInt(document.getElementById('vpngate-topn').value || '10', 10);
      filteredVPNGateServers()
        .slice()
        .sort(function(a, b) { return vpnGateQualityScore(b) - vpnGateQualityScore(a); })
        .slice(0, topN)
        .forEach(function(s) { vpngateSelected[vpngateServers.indexOf(s)] = true; });
      updateVPNGateImportBtn();
      renderVPNGateList();
      showToast('已智能选择 ' + Object.keys(vpngateSelected).length + ' 个候选节点', 'success');
    }

    function renderVPNGateList() {
      const tbody = document.getElementById('vpngate-tbody');
      const filtered = filteredVPNGateServers();
      document.getElementById('vpngate-count').textContent = '共 ' + vpngateServers.length + ' 台服务器（显示 ' + filtered.length + ' 台）';

      var html = '';
      filtered.forEach(function(s, idx) {
        var realIndex = vpngateServers.indexOf(s);
        var checked = vpngateSelected[realIndex] ? 'checked' : '';
        var speedStr = s.speed > 1000000 ? (s.speed / 1000000).toFixed(1) + 'M' : s.speed > 1000 ? (s.speed / 1000).toFixed(0) + 'K' : s.speed;
        html += '<tr>' +
          '<td style="padding:4px 8px"><input type="checkbox" ' + checked + ' onchange="toggleVPNGateServer(' + realIndex + ')"></td>' +
          '<td style="padding:4px 8px"><span style="font-weight:600">' + escapeHtml(s.country_short || '') + '</span> ' + escapeHtml(s.country_long || '') + '</td>' +
          '<td style="padding:4px 8px;font-family:monospace">' + escapeHtml(s.ip || '') + '</td>' +
          '<td style="padding:4px 8px;text-align:right">' + s.ping + 'ms</td>' +
          '<td style="padding:4px 8px;text-align:right">' + speedStr + '</td>' +
          '<td style="padding:4px 8px"><span class="type-pill type-' + (s.server_type === '商宽' ? 'biz' : 'home') + '">' + (s.server_type || '家宽') + '</span></td>' +
          '<td style="padding:4px 8px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escapeHtml(s.operator || '') + '">' + escapeHtml(s.operator || '-') + '</td>' +
          '</tr>';
      });
      tbody.innerHTML = html;
      updateVPNGateImportBtn();
    }

    function toggleVPNGateServer(index) {
      if (vpngateSelected[index]) delete vpngateSelected[index];
      else vpngateSelected[index] = true;
      updateVPNGateImportBtn();
    }

    function updateVPNGateImportBtn() {
      var count = Object.keys(vpngateSelected).length;
      var btn = document.getElementById('vpngate-import-btn');
      btn.disabled = count === 0;
      btn.textContent = count > 0 ? '导入选中（' + count + '）' : '导入选中';
    }

    async function importSelectedVPNGate() {
      var selected = [];
      Object.keys(vpngateSelected).forEach(function(idx) {
        var s = vpngateServers[parseInt(idx)];
        if (s) selected.push({hostname: s.hostname, ip: s.ip, country_long: s.country_long, ping: s.ping});
      });
      if (selected.length === 0) return;
      var btn = document.getElementById('vpngate-import-btn');
      btn.disabled = true;
      btn.textContent = '导入中...';
      btn.textContent = '检测连通性...';
      try {
        var probeResp = await fetch(apiPath('/api/vpngate/probe'), {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({servers: selected})
        });
        if (probeResp.ok) {
          var probeResults = await probeResp.json();
          var reachable = {};
          probeResults.forEach(function(r) { if (r.ok) reachable[r.ip + ':' + (r.port || 1080)] = true; });
          var beforeProbe = selected.length;
          selected = selected.filter(function(s) { return reachable[s.ip + ':1080']; });
          if (selected.length === 0) {
            showToast('选中节点连通性检测全部失败，未导入', 'error');
            btn.textContent = '导入选中';
            btn.disabled = false;
            return;
          }
          if (selected.length < beforeProbe) showToast('已过滤不通节点 ' + (beforeProbe - selected.length) + ' 台', 'error');
        }
      } catch(e) {
        showToast('连通性检测失败，继续按原选择导入', 'error');
      }
      btn.textContent = '导入中...';
      try {
        var resp = await fetch(apiPath('/api/vpngate/import'), {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({servers: selected})
        });
        if (!resp.ok) {
          var errText = '导入失败';
          try { var errData = await resp.json(); errText = errData.error || errText; if (errData.detail) errText += ': ' + errData.detail; } catch(e) {}
          showToast(errText, 'error');
          btn.textContent = '导入选中';
          btn.disabled = false;
          return;
        }
        var created = await resp.json();
        showToast('已导入 ' + created.length + ' 台 VPN Gate 服务器' + (selected.length > created.length ? '，已跳过重复节点 ' + (selected.length - created.length) + ' 台' : ''), 'success');
        closeModal();
        await Promise.all([loadOutbounds(), loadXrayStatus()]);
      } catch(e) { showToast('导入失败: ' + e.message, 'error'); btn.textContent = '导入选中'; }
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
        const res = await fetch(apiPath('/api/session'));
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
      const res = await fetch(apiPath('/api/logout'), {method: 'POST'});
      if (!res.ok) { showToast('登出失败', 'error'); return; }
      showToast('已登出', 'success');
      window.location.href = panelPath('/login');
    }

    function toggleSidebar() {
      document.querySelector('.app-shell').classList.toggle('sidebar-open');
    }
    function closeSidebar() {
      document.querySelector('.app-shell').classList.remove('sidebar-open');
    }
    function toggleClientSection(inboundId) {
      const el = document.getElementById('client-section-' + inboundId);
      if (!el) return;
      if (el.style.display !== 'none') {
        el.style.display = 'none';
        return;
      }
      el.style.display = 'block';
      el.innerHTML = '<div class="list" style="margin:0">正在加载客户端...</div>';
      fetch(apiPath('/api/inbounds')).then(r => r.json()).then(data => {
        const inbound = (data.inbounds || []).find(i => i.id === inboundId);
        if (!inbound) { el.innerHTML = '<div class="muted" style="padding:12px">入站未找到</div>'; return; }
        renderClients(inbound, el.querySelector('.list') || el);
        // Append "新增客户端" button at bottom
        const btnWrap = document.createElement('div');
        btnWrap.className = 'client-add-row';
        btnWrap.innerHTML = '<button onclick="openCreateClient(' + inboundId + ')" class="btn-sm">新增客户端</button>';
        el.appendChild(btnWrap);
      }).catch(() => {
        el.innerHTML = '<div class="muted" style="padding:12px">加载失败</div>';
      });
    }

    async function loadStats() {
      try {
        const resp = await fetch(apiPath('/api/stats'));
        if (!resp.ok) return;
        const s = await resp.json();
        document.getElementById('inbound-count').textContent = s.inbounds;
        document.getElementById('client-count').textContent = s.clients;
        document.getElementById('outbound-stats').textContent = s.outbounds_enabled + ' / ' + s.outbounds;
        document.getElementById('routing-stats').textContent = s.routing_rules_enabled + ' / ' + s.routing_rules;
      } catch(e) {}
    }

    applyTheme(preferredTheme());
    loadSession();

    loadInbounds();
    loadOutbounds();
    loadRoutingRules();
    loadStats();
    setInterval(refreshAutoHealthStatus, 30000);

    // === Navigation section switching ===
    function currentSectionFromLocation() {
      const hash = window.location.hash.replace('#', '');
      return hash || 'overview';
    }

    function navigateTo(sectionId) {
      const validSections = ['overview', 'inbounds', 'clients', 'outbound', 'routing', 'xray', 'settings'];
      if (!validSections.includes(sectionId)) sectionId = 'overview';
      document.querySelectorAll('main > section').forEach((el) => {
        const display = el.classList.contains('overview-grid') ? 'grid' : 'block';
        el.style.display = (el.id === sectionId) ? display : 'none';
      });
      document.querySelectorAll('nav a').forEach((a) => {
        const href = a.getAttribute('href');
        a.classList.toggle('active', (sectionId === 'overview' && href === '#') || href === '#' + sectionId);
      });
      history.replaceState(null, '', sectionId === 'overview' ? panelPath('/') : panelPath('/#' + sectionId));
      if (sectionId === 'overview') loadStats();
      if (sectionId === 'xray') { fetchXrayStatus(); refreshAutoHealthStatus(); }
    }
    document.querySelectorAll('nav a').forEach((a) => {
      a.addEventListener('click', (e) => {
        e.preventDefault();
        closeSidebar();
        const href = a.getAttribute('href');
        if (href === '#') { navigateTo('overview'); return; }
        const id = href.replace('#', '');
        navigateTo(id);
      });
    });
    window.addEventListener('hashchange', () => navigateTo(currentSectionFromLocation()));
    navigateTo(currentSectionFromLocation());

    function renderClients(inbound, list) {
      const hostName = window.location.hostname;
      const clients = inbound.clients || [];
      if (clients.length === 0) {
        list.className = 'list';
        list.innerHTML = renderEmptyState('暂无客户端', '在当前入站下创建第一个客户端后，即可复制订阅或分享链接。', [
          {label:'创建客户端', onclick:"openCreateClient(" + inbound.id + ")"}
        ]);
        return;
      }
      list.className = 'list';
      list.innerHTML = clients.map(c => {
        let shareLink;
        if (inbound.protocol === 'vmess') {
          var vmessHost = '', vmessPath = '', vmessSni = '';
          if (inbound.network === 'ws' || inbound.network === 'h2') {
            vmessHost = inbound.ws_host || '';
            vmessPath = inbound.ws_path || '';
          } else if (inbound.network === 'grpc') {
            vmessPath = inbound.grpc_service_name || '';
          } else if (inbound.network === 'xhttp') {
            vmessPath = inbound.xhttp_path || '';
          }
          if (inbound.security === 'tls' || inbound.security === 'reality') {
            vmessSni = inbound.reality_server_names || '';
          }
          var vmessData = {v:'2',ps:c.email,add:hostName,port:String(inbound.port),id:c.uuid,aid:'0',scy:'auto',net:inbound.network||'tcp',type:'none',host:vmessHost,path:vmessPath,tls:(inbound.security==='tls'||inbound.security==='reality')?'tls':'',sni:vmessSni};
          try { shareLink = 'vmess://' + btoa(JSON.stringify(vmessData)); } catch(e) { shareLink = ''; }
        } else if (inbound.protocol === 'shadowsocks') {
          var ssMethod = inbound.ss_method || '2022-blake3-aes-128-gcm';
          var userPass = ssMethod + ':' + inbound.uuid;
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
          } else if (inbound.network === 'h2') {
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
        return '<div class="client-resource-row">' +
          '<div class="resource-main">' +
            '<div class="resource-title"><strong>' + escapeHtml(c.email) + '</strong><span class="status-badge ' + badgeClass + '">' + badgeText + '</span></div>' +
            '<div class="resource-meta">' +
              '<span class="mono">' + c.uuid.substring(0,8) + '…</span>' +
              '<span style="' + trafficStyle + '">↑' + formatBytes(c.up||0) + ' ↓' + formatBytes(c.down||0) + '</span>' +
              '<span>' + formatBytes(used) + ' / ' + (limit > 0 ? formatBytes(limit) : '∞') + '</span>' +
              '<span style="' + expireStyle + '">到期 ' + expiredText + '</span>' +
              (limit > 0 ? '<span><div class="traffic-track"><div class="traffic-fill ' + fillClass + '" style="width:' + pct + '%"></div></div></span>' : '') +
            '</div>' +
          '</div>' +
          '<div class="resource-actions">' +
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
      const response = await fetch(apiPath('/api/inbounds/') + id, {method: 'DELETE'});
      if (!response.ok) {
        showToast('删除失败：' + await response.text(), 'error');
        return;
      }
      await loadInbounds();
    }

    async function deleteClient(inboundId, clientId) {
      if (!await showConfirm('确认删除客户端 ' + clientId + '？')) return;
      const response = await fetch(apiPath('/api/inbounds/') + inboundId + '/clients/' + clientId, {method: 'DELETE'});
      if (!response.ok) {
        showToast('删除失败：' + await response.text(), 'error');
        return;
      }
      await loadInbounds();
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
      document.getElementById('ei-hy2-settings').classList.toggle('hidden', proto !== 'hysteria2');
      document.getElementById('ei-tuic-settings').classList.toggle('hidden', proto !== 'tuic');
      document.getElementById('ei-wireguard-settings').classList.toggle('hidden', proto !== 'wireguard');
      document.getElementById('ei-shadowtls-settings').classList.toggle('hidden', proto !== 'shadowtls');
    }

    async function editInbound(id) {
      const res = await fetch(apiPath('/api/inbounds'));
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
      document.getElementById('ei-tls-sni').value = inbound.tls_sni || '';
      document.getElementById('ei-tls-fingerprint').value = inbound.tls_fingerprint || '';
      document.getElementById('ei-tls-alpn').value = inbound.tls_alpn || '';
      document.getElementById('ei-hy2-up').value = inbound.hy2_up_mbps || 0;
      document.getElementById('ei-hy2-down').value = inbound.hy2_down_mbps || 0;
      document.getElementById('ei-hy2-obfs').value = inbound.hy2_obfs || '';
      document.getElementById('ei-hy2-obfs-password').value = inbound.hy2_obfs_password || '';
      document.getElementById('ei-tuic-cc').value = inbound.tuic_congestion_control || 'bbr';
      document.getElementById('ei-tuic-zero-rtt').checked = inbound.tuic_zero_rtt || false;
      document.getElementById('ei-wg-private-key').value = inbound.wg_private_key || '';
      document.getElementById('ei-wg-address').value = inbound.wg_address || '';
      document.getElementById('ei-wg-peer-public-key').value = inbound.wg_peer_public_key || '';
      document.getElementById('ei-wg-allowed-ips').value = inbound.wg_allowed_ips || '';
      document.getElementById('ei-wg-endpoint').value = inbound.wg_endpoint || '';
      document.getElementById('ei-wg-preshared-key').value = inbound.wg_preshared_key || '';
      document.getElementById('ei-wg-mtu').value = inbound.wg_mtu || 1420;
      document.getElementById('ei-shadowtls-password').value = inbound.shadowtls_password || '';
      document.getElementById('ei-shadowtls-version').value = inbound.shadowtls_version || 3;
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
        tls_sni: document.getElementById('ei-tls-sni').value,
        tls_fingerprint: document.getElementById('ei-tls-fingerprint').value,
        tls_alpn: document.getElementById('ei-tls-alpn').value,
        hy2_up_mbps: Number(document.getElementById('ei-hy2-up').value) || 0,
        hy2_down_mbps: Number(document.getElementById('ei-hy2-down').value) || 0,
        hy2_obfs: document.getElementById('ei-hy2-obfs').value,
        hy2_obfs_password: document.getElementById('ei-hy2-obfs-password').value,
        tuic_congestion_control: document.getElementById('ei-tuic-cc').value,
        tuic_zero_rtt: document.getElementById('ei-tuic-zero-rtt').checked,
        wg_private_key: document.getElementById('ei-wg-private-key').value,
        wg_address: document.getElementById('ei-wg-address').value,
        wg_peer_public_key: document.getElementById('ei-wg-peer-public-key').value,
        wg_allowed_ips: document.getElementById('ei-wg-allowed-ips').value,
        wg_endpoint: document.getElementById('ei-wg-endpoint').value,
        wg_preshared_key: document.getElementById('ei-wg-preshared-key').value,
        wg_mtu: Number(document.getElementById('ei-wg-mtu').value) || 1420,
        shadowtls_password: document.getElementById('ei-shadowtls-password').value,
        shadowtls_version: Number(document.getElementById('ei-shadowtls-version').value) || 3,
      };
      if (!data.remark || !data.port) { showToast('请填写备注和端口', 'error'); return; }
      // Port conflict check (client-side, exclude current inbound)
      const existingInbounds = window._cachedInbounds || [];
      const conflictInb = existingInbounds.find(ib => ib.id !== id && ib.port === data.port);
      if (conflictInb) { showToast('端口 ' + data.port + ' 已被入站 ' + (conflictInb.remark || conflictInb.id) + ' 使用', 'error'); return; }
      const res = await fetch(apiPath('/api/inbounds/') + id, {
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
      const response = await fetch(apiPath('/api/inbounds'));
      const data = await response.json();
      const inbound = (data.inbounds || []).find(i => i.id === id);
      if (!inbound) return;
      inbound.enabled = !inbound.enabled;
      const res = await fetch(apiPath('/api/inbounds/') + id + '/enabled', {
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
      const res = await fetch(apiPath('/api/inbounds'));
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
      document.getElementById('ec-enabled').checked = client.enabled;
      document.getElementById('ec-enabled-label').textContent = client.enabled ? '已启用' : '已禁用';
      document.getElementById('ec-enabled').onchange = function() {
        document.getElementById('ec-enabled-label').textContent = this.checked ? '已启用' : '已禁用';
      };
      document.getElementById('ec-traffic-limit').value = client.traffic_limit || '';
      document.getElementById('ec-up-display').textContent = formatBytes(client.up || 0);
      document.getElementById('ec-down-display').textContent = formatBytes(client.down || 0);
      document.getElementById('ec-total-display').textContent = formatBytes((client.up || 0) + (client.down || 0));
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
      const res = await fetch(apiPath('/api/inbounds/') + d.inboundId + '/clients/' + d.id, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          email: email,
          enabled: document.getElementById('ec-enabled').checked,
          traffic_limit: tl,
          expiry_at: ea
        })
      });
      if (!res.ok) { showToast('编辑客户端失败', 'error'); return; }
      showToast('客户端已更新', 'success');
      closeEditClient();
      await loadInbounds();
    }

    async function toggleClient(id) {
      const inboundRes = await fetch(apiPath('/api/inbounds'));
      const data = await inboundRes.json();
      const inbounds = data.inbounds || [];
      let foundInbound = null, foundClient = null;
      for (const ib of inbounds) {
        const c = (ib.clients || []).find(c => c.id === id);
        if (c) { foundInbound = ib; foundClient = c; break; }
      }
      if (!foundInbound || !foundClient) return;
      foundClient.enabled = !foundClient.enabled;
      const res = await fetch(apiPath('/api/inbounds/') + foundInbound.id + '/clients/' + id + '/enabled', {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: foundClient.enabled})
      });
      if (!res.ok) {
        showToast('开关客户端失败', 'error');
        return;
      }
      showToast('客户端 ' + (foundClient.enabled ? '已启用' : '已禁用'), 'success');
      await loadInbounds();
    }

    async function resetClientTraffic() {
      const d = _editingClientData;
      if (!d) return;
      const confirmed = await showConfirm('确定要重置此客户端的流量数据吗？此操作不可恢复。');
      if (!confirmed) return;
      const res = await fetch(apiPath('/api/inbounds/') + d.inboundId + '/clients/' + d.id + '/reset-traffic', {
        method: 'POST'
      });
      if (!res.ok) {
        showToast('重置流量失败', 'error');
        return;
      }
      const updated = await res.json();
      document.getElementById('ec-up-display').textContent = formatBytes(updated.up || 0);
      document.getElementById('ec-down-display').textContent = formatBytes(updated.down || 0);
      document.getElementById('ec-total-display').textContent = formatBytes((updated.up || 0) + (updated.down || 0));
      showToast('流量已重置', 'success');
      await loadInbounds();
    }

    function openCreateClient(inboundId) {
      document.getElementById('client-inbound-id').value = inboundId || '';
      const formEl = document.getElementById('create-client-form');
      formEl.reset();
      regenerateField('client-uuid');
      document.getElementById('create-client-overlay').classList.remove('hidden');
      document.getElementById('client-email').focus();
    }
    function closeCreateClient() {
      document.getElementById('create-client-overlay').classList.add('hidden');
    }
    async function saveCreateClient() {
      const formEl = document.getElementById('create-client-form');
      const inboundId = document.getElementById('client-inbound-id').value;
      if (!inboundId) {
        showToast('请先展开入站再创建客户端', 'error');
        closeCreateClient();
        return;
      }
      const form = new FormData(formEl);
      const email = form.get('email');
      if (!email) { showToast('请输入客户端标识', 'error'); return; }
      const tl = parseInt(form.get('traffic_limit')) || 0;
      const clientUUID = String(form.get('uuid') || '').trim();
      const eaStr = document.getElementById('client-expiry').value;
      let ea = 0;
      if (eaStr) { ea = Math.floor(new Date(eaStr).getTime() / 1000); }
      const response = await fetch(apiPath('/api/inbounds/') + inboundId + '/clients', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: email, uuid: clientUUID, traffic_limit: tl, expiry_at: ea})
      });
      if (!response.ok) {
        showToast('创建客户端失败：' + await response.text(), 'error');
        return;
      }
      formEl.reset();
      closeCreateClient();
      showToast('客户端创建成功', 'success');
      await loadInbounds();
    }

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
    const protocolPresets = {
      vless: {network: 'tcp', security: 'reality'},
      vmess: {network: 'ws', security: 'tls'},
      trojan: {network: 'tcp', security: 'tls'},
      shadowsocks: {network: 'tcp', security: 'none'},
      hysteria2: {network: 'quic', security: 'tls'},
      tuic: {network: 'quic', security: 'tls'},
      wireguard: {network: 'udp', security: 'none'},
      shadowtls: {network: 'tcp', security: 'tls'},
    };
    function applyProtocolPreset(proto) {
      const preset = protocolPresets[proto];
      if (!preset) return;
      document.getElementById('inbound-network').value = preset.network;
      document.getElementById('inbound-security').value = preset.security;
      const inboundCredential = document.getElementById('inbound-uuid');
      const initCredential = document.getElementById('init-client-uuid');
      if (inboundCredential) inboundCredential.value = '';
      if (initCredential) initCredential.value = '';
      onProtocolChange();
    }
    function onProtocolChange() {
      const proto = document.getElementById('inbound-protocol').value;
      const isSingbox = ['hysteria2','tuic','wireguard','shadowtls'].includes(proto);
      const desc = document.getElementById('protocol-description');

      // Protocol descriptions
      const labels = {
        vless: 'VLESS + Reality：高性能，推荐优先使用。',
        vmess: 'VMess + WebSocket + TLS：适合 CDN 反代场景。',
        trojan: 'Trojan + TLS：兼容性广泛的协议。',
        shadowsocks: 'Shadowsocks：轻量加密代理。',
        hysteria2: 'Hysteria2：基于 QUIC 的 UDP 加速协议，抗丢包。',
        tuic: 'TUIC：基于 QUIC 的低延迟 UDP 代理，适合弱网环境。',
        wireguard: 'WireGuard ⚠️ 当前需要升级 sing-box 至 v1.14+ 才能生效。',
        shadowtls: 'ShadowTLS：将流量伪装成标准 TLS 连接，可绕过深度包检测。',
      };
      desc.textContent = labels[proto] || '';

      // For sing-box protocols: hide Xray-specific fields
      const netGroup = document.getElementById('inbound-network').closest('.field-group');
      const secGroup = document.getElementById('inbound-security').closest('.field-group');
      const uuidGroup = document.getElementById('inbound-uuid').closest('.field-group');

      if (isSingbox) {
        netGroup.style.display = 'none';
        secGroup.style.display = 'none';
        if (proto === 'wireguard') {
          uuidGroup.style.display = 'none';
        } else {
          uuidGroup.style.display = '';
        }
      } else {
        netGroup.style.display = '';
        secGroup.style.display = '';
        uuidGroup.style.display = '';
      }
    }
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
      document.getElementById('hy2-settings').classList.toggle('hidden', proto !== 'hysteria2');
      document.getElementById('tuic-settings').classList.toggle('hidden', proto !== 'tuic');
      document.getElementById('wireguard-settings').classList.toggle('hidden', proto !== 'wireguard');
      document.getElementById('shadowtls-settings').classList.toggle('hidden', proto !== 'shadowtls');
      const formEl = document.getElementById('create-inbound-form');
      if (formEl) fillRandomDefaults(formEl);
    }

    function openCreateInbound() {
      const formEl = document.getElementById('create-inbound-form');
      formEl.reset();
      applyProtocolPreset(document.getElementById('inbound-protocol').value);
      document.getElementById('init-client-fields').classList.remove('hidden');
      document.querySelector('#create-inbound-dialog .chevron').textContent = '\u25BC';
      updateDynamicFields();
      onProtocolChange();
      fillRandomDefaults(formEl);
      document.getElementById('create-inbound-overlay').classList.remove('hidden');
      document.getElementById('inbound-remark').focus();
    }
    function closeCreateInbound() {
      document.getElementById('create-inbound-overlay').classList.add('hidden');
    }
    function toggleInitClient(el) {
      const fields = document.getElementById('init-client-fields');
      const chevron = el.querySelector('.chevron');
      const isHidden = fields.classList.contains('hidden');
      fields.classList.toggle('hidden');
      chevron.textContent = isHidden ? '\u25BC' : '\u25B6';
    }
    function randHex(n) {
      return Array.from(crypto.getRandomValues(new Uint8Array(Math.ceil(n / 2)))).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, n);
    }
    function randBase64(byteLen) {
      const bytes = crypto.getRandomValues(new Uint8Array(byteLen));
      let s = '';
      bytes.forEach((b) => { s += String.fromCharCode(b); });
      return btoa(s);
    }
    function randUUID() {
      if (crypto.randomUUID) return crypto.randomUUID();
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      bytes[6] = (bytes[6] & 0x0f) | 0x40;
      bytes[8] = (bytes[8] & 0x3f) | 0x80;
      const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
      return hex.slice(0,8) + '-' + hex.slice(8,12) + '-' + hex.slice(12,16) + '-' + hex.slice(16,20) + '-' + hex.slice(20);
    }
    function credentialForProtocol(proto) {
      if (proto === 'shadowsocks') return randBase64(16);
      if (proto === 'trojan' || proto === 'hysteria2') return randHex(16);
      return randUUID();
    }
    function protocolForClientModal() {
      const inboundId = Number(document.getElementById('client-inbound-id')?.value || 0);
      const inbound = (window._cachedInbounds || []).find((ib) => ib.id === inboundId);
      return inbound ? inbound.protocol : 'vless';
    }
    function makeFieldTools(id, secret) {
      const buttons = ['<button type="button" class="btn-mini" onclick="regenerateField(\'' + id + '\')">重新生成</button>'];
      if (secret) buttons.push('<button type="button" class="btn-mini" onclick="toggleSecretField(\'' + id + '\')">显示/隐藏</button>');
      return '<span style="display:inline-flex;gap:6px;align-items:center;margin-left:8px;flex-wrap:wrap">' + buttons.join('') + '</span>';
    }
    function regenerateField(id) {
      const el = document.getElementById(id);
      if (!el) return;
      if (id === 'inbound-reality-short-id' || id === 'ei-reality-short-id') el.value = randHex(8);
      else if (id === 'inbound-hy2-obfs-password' || id === 'ei-hy2-obfs-password') el.value = randHex(12);
      else if (id === 'inbound-uuid') el.value = credentialForProtocol(document.getElementById('inbound-protocol').value);
      else if (id === 'init-client-uuid') el.value = credentialForProtocol(document.getElementById('inbound-protocol').value);
      else if (id === 'client-uuid') el.value = credentialForProtocol(protocolForClientModal());
      else if (id === 'inbound-init-client-email' || id === 'init-client-email' || id === 'client-email') el.value = 'user@example.com';
      else if (id === 'inbound-ss-method' || id === 'ei-ss-method') el.value = '2022-blake3-aes-128-gcm';
      else el.value = randHex(8);
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }
    function regenerateFieldByName(name) {
      const el = document.querySelector('[name="'+name+'"]');
      if (el) { el.value = randCredential(); }
    }
    function toggleSecretField(id) {
      const el = document.getElementById(id);
      if (!el) return;
      el.type = el.type === 'password' ? 'text' : 'password';
    }
    function fillRandomDefaults(formEl) {
      const proto = document.getElementById('inbound-protocol').value;
      const sec = document.getElementById('inbound-security').value;
      const randHex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(Math.ceil(n/2)))).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, n);
      const randCredential = () => credentialForProtocol(proto);
      const setIfEmpty = (sel, val) => {
        const el = formEl.querySelector(sel);
        if (el && !el.value) el.value = val;
      };
      setIfEmpty('[name="uuid"]', randCredential());
      if (sec === 'reality') {
        setIfEmpty('[name="reality_dest"]', 'www.cloudflare.com:443');
        setIfEmpty('[name="reality_server_names"]', 'www.cloudflare.com');
        setIfEmpty('[name="reality_short_id"]', randHex(8));
      }
      if (sec === 'tls') {
        setIfEmpty('[name="tls_cert_file"]', '/etc/ssl/certs/fullchain.pem');
        setIfEmpty('[name="tls_key_file"]', '/etc/ssl/private/privkey.pem');
      }
      if (proto === 'hysteria2') {
        setIfEmpty('[name="hy2_obfs"]', 'salamander');
        setIfEmpty('[name="hy2_obfs_password"]', randHex(12));
      }
      if (proto === 'vless' || proto === 'trojan' || proto === 'vmess') {
        setIfEmpty('[name="reality_short_id"]', randHex(8));
      }
      if (proto === 'shadowsocks') {
        setIfEmpty('[name="ss_method"]', '2022-blake3-aes-128-gcm');
      }
      const initFields = document.getElementById('init-client-fields');
      if (initFields && !initFields.classList.contains('hidden')) {
        const emailEl = document.getElementById('init-client-email');
        if (emailEl && !emailEl.value) emailEl.value = 'user@example.com';
        const uuidEl = document.getElementById('init-client-uuid');
        if (uuidEl && !uuidEl.value) uuidEl.value = randCredential();
      }
      const credentialHelp = document.getElementById('init-client-credential-help');
      if (credentialHelp) {
        const label = proto === 'vless' || proto === 'vmess' ? 'UUID' : proto === 'shadowsocks' || proto === 'wireguard' ? '密码/密钥' : '密码';
        credentialHelp.textContent = '客户端凭据已自动生成为 ' + label + '，可以手动修改；不懂时保持默认即可。';
      }
    }

    async function saveCreateInbound() {
      const formEl = document.getElementById('create-inbound-form');
      const form = new FormData(formEl);
      const payload = Object.fromEntries(form.entries());
      payload.port = Number(payload.port);
      payload.hy2_up_mbps = Number(payload.hy2_up_mbps) || 0;
      payload.hy2_down_mbps = Number(payload.hy2_down_mbps) || 0;
      payload.tuic_zero_rtt = payload.tuic_zero_rtt === '1' || payload.tuic_zero_rtt === true;
      payload.hy2_up_mbps = Number(payload.hy2_up_mbps) || 0;
      payload.hy2_down_mbps = Number(payload.hy2_down_mbps) || 0;
      payload.wg_mtu = Number(payload.wg_mtu) || 0;
      payload.shadowtls_version = Number(payload.shadowtls_version) || 3;
      if (!payload.remark || !payload.port) { showToast('请填写备注和端口', 'error'); return; }
      // Port conflict check (client-side)
      const existingInbounds = window._cachedInbounds || [];
      const conflictInb = existingInbounds.find(ib => ib.port === payload.port);
      if (conflictInb) { showToast('端口 ' + payload.port + ' 已被入站 ' + (conflictInb.remark || conflictInb.id) + ' 使用', 'error'); return; }
      // Pack initial client if email is provided
      const initEmail = document.getElementById('init-client-email').value.trim();
      if (initEmail) {
        const initExpiryStr = document.getElementById('init-client-expiry').value;
        let initExpiry = 0;
        if (initExpiryStr) {
          initExpiry = Math.floor(new Date(initExpiryStr).getTime() / 1000);
        }
        payload.initial_client = {
          email: initEmail,
          uuid: document.getElementById('init-client-uuid').value.trim(),
          traffic_limit: Number(document.getElementById('init-client-traffic').value || 0),
          expiry_at: initExpiry
        };
      }
      delete payload.init_email;
      delete payload.init_traffic;
      const response = await fetch(apiPath('/api/inbounds'), {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
      if (!response.ok) {
        showToast('创建入站失败', 'error');
        return;
      }
      formEl.reset();
      closeCreateInbound();
      showToast('入站创建成功', 'success');
      await loadInbounds();
    }

    document.getElementById('inbound-protocol').addEventListener('change', () => { applyProtocolPreset(document.getElementById('inbound-protocol').value); updateDynamicFields(); });
    document.getElementById('inbound-network').addEventListener('change', updateDynamicFields);
    document.getElementById('inbound-security').addEventListener('change', updateDynamicFields);
    updateDynamicFields();

    // === Xray status & apply ===
    async function fetchXrayStatus() {
      try {
        const res = await fetch(apiPath('/api/xray/status'));
        const data = await res.json();
        document.getElementById('xray-status').textContent = data.status || '未知';
        document.getElementById('xray-managed').textContent = data.managed ? '是' : '否';
        document.getElementById('xray-service').textContent = data.service || 'xray';
      } catch (e) {
        document.getElementById('xray-status').textContent = '连接失败';
      }
      try {
        const vr = await fetch(apiPath('/api/xray/version'));
        const vdata = await vr.json();
        document.getElementById('xray-version').textContent = vdata.version || '-';
        // Hysteria2 is not supported by any current Xray version
        document.getElementById('xray-unsupported-warning').style.display = 'block';
      } catch (e) {
        document.getElementById('xray-version').textContent = '获取失败';
      }
    }
    async function applyXrayConfig() {
      document.getElementById('xray-result').innerHTML = renderNotice('正在应用', '正在写入 xray.json、执行配置校验并尝试重启 Xray 及 sing-box。');
      try {
        const res = await fetch(apiPath('/api/xray/apply'), {method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({confirm:true, allow_system_changes:true})});
        const data = await res.json();
        // New dual-kernel response: {xray: {...}, singbox: {...}}
        const xray = data.xray || data;
        const singboxResult = data.singbox;
        const commands = xray.commands_executed && xray.commands_executed.length ? '\n' + xray.commands_executed.join('\n') : '';
        const singboxLine = singboxResult ? (singboxResult.applied ? '\nSing-box: ✅ 已应用' + (singboxResult.inbounds ? '(' + singboxResult.inbounds + ' 个入站)' : '') : singboxResult.reason === 'not_needed' ? '\nSing-box: ⏭ 无 Hysteria2 入站' : '\nSing-box: ❌ ' + (singboxResult.error || singboxResult.reason || '失败')) : '';
        if (xray.status && xray.status.startsWith('failed')) {
          const errDetail = xray.error_output ? '\n\n' + xray.error_output : '';
          document.getElementById('xray-result').innerHTML = renderNotice('应用失败', 'Xray 状态：' + xray.status + errDetail + commands + singboxLine, 'error');
          showToast('应用配置失败', 'error');
        } else {
          document.getElementById('xray-result').innerHTML = renderNotice('应用完成', 'Xray 状态：' + (xray.status || '完成') + commands + singboxLine, 'success');
          showToast('配置已应用', 'success');
        }
        await fetchXrayStatus();
      } catch (e) {
        document.getElementById('xray-result').innerHTML = renderNotice('应用失败', '请检查 Xray 配置目录、xray 命令和 systemd 服务状态。', 'error');
        showToast('应用配置失败', 'error');
      }
    }



    // === Xray config preview ===
    let _configVisible = false;
    async function previewXrayConfig() {
      const el = document.getElementById('xray-config-preview');
      const pre = document.getElementById('xray-config-json');
      if (_configVisible) return;
      _configVisible = true;
      try {
        const res = await fetch(apiPath('/api/xray/config'));
        const json = await res.json();
        pre.textContent = JSON.stringify(json, null, 2);
        el.style.display = '';
      } catch (e) {
        pre.textContent = '加载配置失败';
        el.style.display = '';
      }
    }
    function closeXrayConfig() {
      document.getElementById('xray-config-preview').style.display = 'none';
      _configVisible = false;
    }
    var _logsVisible = false;
    async function loadXrayLogs() {
      const el = document.getElementById('xray-logs-preview');
      const pre = document.getElementById('xray-logs-text');
      if (_logsVisible) return;
      _logsVisible = true;
      pre.textContent = '加载中...';
      el.style.display = '';
      try {
        const res = await fetch(apiPath('/api/xray/logs?lines=80'));
        const data = await res.json();
        pre.textContent = data.logs || '暂无日志';
      } catch (e) {
        pre.textContent = '加载日志失败';
      }
    }
    function closeXrayLogs() {
      document.getElementById('xray-logs-preview').style.display = 'none';
      _logsVisible = false;
    }

    // === Settings ===
    async function loadSettings() {
      try {
        const res = await fetch(apiPath('/api/settings'));
        if (!res.ok) { throw new Error('not available'); }
        const data = await res.json();
        document.getElementById('set-panel-port').value = data.panel_port || '';
        document.getElementById('set-username').value = data.panel_username || '';
        document.getElementById('set-password').value = '';
        document.getElementById('set-xray-config-path').value = data.xray_config_path || '';
        document.getElementById('set-web-path').value = data.web_base_path || '';
        document.getElementById('set-cert-domain').value = data.cert_domain || '';
        document.getElementById('set-cert-email').value = data.cert_email || '';
        if (data.database_path) {
          document.getElementById('settings-status').innerHTML = renderNotice('数据库', data.database_path + (data.has_password ? ' | 密码已设置' : ' | 无密码'), 'success');
        }
        fetchCertStatus();
        fetchServiceStatus();
      } catch (e) {
        document.getElementById('settings-status').innerHTML = renderNotice('设置不可用', '需要在 panel.json 配置文件下运行，或检查配置目录是否已传入。', 'error');
      }
    }
    async function fetchCertStatus() {
      try {
        const res = await fetch(apiPath('/api/cert/status'));
        if (!res.ok) { return; }
        const data = await res.json();
        document.getElementById('cert-status-area').style.display = '';
        const label = document.getElementById('cert-status-label');
        const pathEl = document.getElementById('cert-path-label');
        if (data.issued) {
          label.textContent = '✓ 已签发';
          label.style.color = 'var(--accent2)';
          pathEl.textContent = '证书：' + (data.cert_path || '') + ' | 密钥：' + (data.key_path || '');
        } else if (data.domain) {
          label.textContent = '待获取（域名已配置）';
          label.style.color = 'var(--amber)';
          pathEl.textContent = '';
        } else {
          label.textContent = '未配置';
          label.style.color = '';
          pathEl.textContent = '';
        }
      } catch (e) {}
    }
    async function issueCert() {
      const domain = document.getElementById('set-cert-domain').value.trim();
      const email = document.getElementById('set-cert-email').value.trim();
      if (!domain || !email) {
        showToast('请先填写域名和邮箱', 'error');
        return;
      }
      const btn = document.getElementById('btn-issue-cert');
      btn.disabled = true;
      btn.textContent = '签发中…';
      document.getElementById('cert-status-label').textContent = '签发中，请等待…';
      try {
        const res = await fetch(apiPath('/api/cert/issue'), {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({domain, email})
        });
        const data = await res.json();
        if (res.ok && data.status === 'issued') {
          showToast('证书获取成功', 'success');
          fetchCertStatus();
        } else {
          showToast('签发失败：' + (data.detail || data.error || '未知错误'), 'error');
          document.getElementById('cert-status-label').textContent = '签发失败';
        }
      } catch (e) {
        showToast('签发失败：网络错误', 'error');
        document.getElementById('cert-status-label').textContent = '签发失败';
      }
      btn.disabled = false;
      btn.textContent = '获取证书';
    }
    async function saveSettings() {
      var btn = document.querySelector('[onclick*="saveSettings"]');
      if (btn.disabled) return;
      btn.disabled = true;
      btn.textContent = '保存中...';
      const data = {
        panel_port: parseInt(document.getElementById('set-panel-port').value) || 0,
        panel_username: document.getElementById('set-username').value.trim(),
        panel_password: document.getElementById('set-password').value,
        xray_config_path: document.getElementById('set-xray-config-path').value.trim(),
        web_base_path: document.getElementById('set-web-path').value.trim() || '/',
        cert_domain: document.getElementById('set-cert-domain').value.trim(),
        cert_email: document.getElementById('set-cert-email').value.trim(),
      };
      if (!data.panel_port) { showToast('请输入面板端口', 'error'); return; }
      try {
        const res = await fetch(apiPath('/api/settings'), {
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
      btn.disabled = false;
      btn.textContent = '保存设置';
    }
    async function restartService() {
      if (!await showConfirm('确认重启 MiGate 服务？页面将暂时无法访问，重启后自动重试恢复。')) return;
      const btn = document.querySelector('button.danger');
      btn.disabled = true;
      btn.textContent = '重启中…';
      try {
        const res = await fetch(apiPath('/api/restart'), { method: 'POST' });
        if (!res.ok) { showToast('重启失败', 'error'); btn.disabled = false; btn.textContent = '重启服务'; return; }
        showToast('正在重启 MiGate 服务…', 'success');
        // Retry reload until the page comes back up
        let retries = 0;
        const maxRetries = 30;
        const retryDelay = 1500;
        function tryReload() {
          retries++;
          if (retries >= maxRetries) {
            showToast('重启超时，请手动刷新', 'error');
            btn.disabled = false;
            btn.textContent = '重启服务';
            return;
          }
          setTimeout(function() { location.reload(true); }, retryDelay);
        }
        setTimeout(tryReload, 1000);
      } catch (e) {
        showToast('重启请求失败', 'error');
        btn.disabled = false;
        btn.textContent = '重启服务';
      }
    }

    async function fetchServiceStatus() {
      try {
        const res = await fetch(apiPath('/api/service/status'));
        if (!res.ok) { throw new Error('not available'); }
        const data = await res.json();
        const badge = document.getElementById('svc-status-badge');
        const detail = document.getElementById('svc-status-detail');
        if (data.status === 'active') {
          badge.innerHTML = '<span style="color:var(--accent2)">●</span> 运行中';
          badge.style.background = 'rgba(0,180,0,0.1)';
          detail.textContent = data.detail || '';
        } else if (data.status === 'inactive' || data.status === 'failed') {
          badge.innerHTML = '<span style="color:var(--danger)">●</span> ' + (data.status === 'failed' ? '异常' : '未运行');
          badge.style.background = 'rgba(220,40,40,0.1)';
          detail.textContent = '';
        } else {
          badge.textContent = '未知';
          badge.style.background = 'var(--surface-subtle)';
          detail.textContent = '非 systemd 环境或服务未安装';
        }
      } catch (e) {
        document.getElementById('svc-status-badge').textContent = '不可用';
        document.getElementById('svc-status-detail').textContent = '无法查询服务状态';
      }
    }

    async function refreshAutoHealthStatus() {
      try {
        const res = await fetch(apiPath('/api/vpngate/auto-health/status'));
        if (!res.ok) { document.getElementById('vpngate-auto-health-card').style.display = 'none'; return; }
        const data = await res.json();
        const card = document.getElementById('vpngate-auto-health-card');
        const status = document.getElementById('vpngate-auto-health-status');
        const ok = data.results.filter(r => r.ok).length;
        const total = data.results.length;
        const disabled = data.disabled_total || 0;
        if (total === 0) {
          card.style.display = 'none';
          return;
        }
        card.style.display = '';
        status.textContent = '可用 ' + ok + '/' + total + ' | 已自动禁用 ' + disabled + ' 个节点';
      } catch (e) {
        document.getElementById('vpngate-auto-health-card').style.display = 'none';
      }
    }

    // === Version check ===
    async function checkVersion() {
      try {
        const res = await fetch(apiPath('/api/version'));
        const data = await res.json();
        const current = data.version || 'dev';
        if (current === 'dev') return;
        // Check GitHub for latest release
        const ghRes = await fetch('https://api.github.com/repos/imzyb/MiGate/releases/latest');
        if (!ghRes.ok) return;
        const gh = await ghRes.json();
        const latest = (gh.tag_name || '').replace(/^v/, '');
        const cur = current.replace(/^v/, '');
        if (latest && latest !== cur) {
          const banner = document.getElementById('version-banner');
          banner.innerHTML = '🚀 新版本 <strong>v' + escapeHtml(latest) + '</strong> 已发布（当前 v' + escapeHtml(cur) + '）。查看 <a href="' + gh.html_url + '" target="_blank">更新日志</a>';
          banner.style.display = 'block';
        }
      } catch (e) { /* silent */ }
    }
    checkVersion();

    fetchXrayStatus();
    loadSettings();
  </script>
</body>
</html>`
