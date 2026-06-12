package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	"syscall"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/singbox"
	"github.com/imzyb/MiGate/internal/web/static"
	"github.com/imzyb/MiGate/internal/xray"
)

var validDomain = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
var validEmail = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

const maxXrayLogLines = 200
const defaultSocks5PoolURL = "https://github.cmliussss.net/raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/socks5.json"

type XrayStatusStore interface {
	ListInbounds(ctx context.Context) ([]db.Inbound, error)
}

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
	AddToBlacklist(ctx context.Context, tokenHash string, expiresAt time.Time, revoked bool) error
	IsBlacklisted(ctx context.Context, tokenHash string) (bool, error)
	RecordSessionTouch(ctx context.Context, tokenHash string) error
	ListActiveSessions(ctx context.Context) ([]db.BlacklistedSession, error)
	RevokeSession(ctx context.Context, id int64) error
}

type XrayController interface {
	Status(ctx context.Context) XrayStatus
	Apply(ctx context.Context) XrayApplyResult
	Version(ctx context.Context) string
}

type XrayStatus struct {
	Service           string   `json:"service"`
	Status            string   `json:"status"`
	Managed           bool     `json:"managed"`
	Installed         bool     `json:"installed"`
	Version           string   `json:"version"`
	MemoryRSSBytes    int64    `json:"memory_rss_bytes"`
	Uptime            string   `json:"uptime"`
	ActiveConnections int      `json:"active_connections"`
	ConfigPath        string   `json:"config_path"`
	CommandsExecuted  []string `json:"commands_executed"`
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
	statsClient    xray.StatsClient
	socks5PoolURL  string
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

func WithSocks5PoolURL(poolURL string) Option {
	return func(cfg *routerConfig) {
		cfg.socks5PoolURL = strings.TrimSpace(poolURL)
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
		socks5PoolURL:  defaultSocks5PoolURL,
	}
	for _, option := range options {
		option(&cfg)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", panelHandler)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(static.FS))))
	mux.HandleFunc("/login", loginHandler(&cfg))
	mux.HandleFunc("/api/login", loginHandler(&cfg))
	mux.HandleFunc("/api/logout", logoutHandler(&cfg))
	mux.HandleFunc("/api/session", sessionHandler(&cfg))
	mux.HandleFunc("/api/sessions", sessionsListHandler(&cfg))
	mux.HandleFunc("/api/sessions/", sessionRevokeHandler(&cfg))
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/inbounds", inboundsHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/inbounds/", inboundChildrenHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/outbounds", outboundsHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/outbounds/", outboundChildrenHandler(&cfg))
	mux.HandleFunc("/api/routing-rules", routingRulesHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/routing-rules/", routingRuleChildrenHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/stats", statsHandler(cfg.store, cfg.statsClient))
	mux.HandleFunc("/api/system/resources", systemResourcesHandler())
	mux.HandleFunc("/api/xray/config", xrayConfigHandler(cfg.store))
	mux.HandleFunc("/api/xray/status", xrayStatusHandler(cfg.xrayController))
	mux.HandleFunc("/api/xray/apply", xrayApplyHandler(cfg.xrayController, cfg.store))
	mux.HandleFunc("/api/xray/install", coreInstallHandler("xray"))
	mux.HandleFunc("/api/xray/uninstall", coreUninstallHandler("xray"))
	mux.HandleFunc("/api/xray/logs", xrayLogsHandler())
	mux.HandleFunc("/api/xray/version", xrayVersionHandler(cfg.xrayController))
	mux.HandleFunc("/api/cert/status", certStatusHandler(&cfg))
	mux.HandleFunc("/api/cert/issue", certIssueHandler(&cfg))
	mux.HandleFunc("/api/settings", settingsHandler(&cfg))
	mux.HandleFunc("/api/restart", restartHandler())
	mux.HandleFunc("/api/service/status", serviceStatusHandler())
	mux.HandleFunc("/api/version", versionHandler(cfg.version))
	mux.HandleFunc("/api/update", updateHandler())
	mux.HandleFunc("/api/singbox/status", singboxStatusHandler())
	mux.HandleFunc("/api/singbox/apply", singboxApplyHandler(cfg.store))
	mux.HandleFunc("/api/singbox/install", coreInstallHandler("singbox"))
	mux.HandleFunc("/api/singbox/uninstall", coreUninstallHandler("singbox"))
	mux.HandleFunc("/api/singbox/config", singboxConfigHandler())
	mux.HandleFunc("/api/singbox/version", singboxVersionHandler())
	mux.HandleFunc("/api/singbox/logs", singboxLogsHandler())
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
			_ = tryApplySingbox(r.Context(), store)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"outbound": outbound, "xray": applyResult})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func pingOutbound(address string, port int) map[string]interface{} {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return map[string]interface{}{"latency": -1, "method": "tcping", "error": err.Error()}
	}
	// tcping semantics: measure TCP connect latency only. Do not perform a SOCKS5 handshake.
	latency := time.Since(start).Milliseconds()
	_ = conn.Close()
	return map[string]interface{}{"latency": latency, "method": "tcping"}
}

type socks5PoolProxy struct {
	Address      string  `json:"address"`
	Port         int     `json:"port"`
	Username     string  `json:"username,omitempty"`
	Password     string  `json:"password,omitempty"`
	CountryCode  string  `json:"country_code"`
	Country      string  `json:"country"`
	City         string  `json:"city"`
	ASN          string  `json:"asn"`
	Organization string  `json:"organization"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	Latency      int64   `json:"latency"`
}

type socks5PoolRegion struct {
	Code  string `json:"code"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type socks5PoolCache struct {
	mu        sync.Mutex
	proxies   []socks5PoolProxy
	updatedAt time.Time
	err       string
}

var globalSocks5PoolCache = &socks5PoolCache{}

func nextSocks5PoolRefresh(now time.Time) time.Time {
	loc := now.Location()
	next := time.Date(now.Year(), now.Month(), now.Day(), 6, 0, 0, 0, loc)
	if !now.Before(next) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// StartSocks5PoolCacheScheduler refreshes the public SOCKS5 pool once a day at
// 06:00 local time (upstream updates around 05:30) and keeps an in-memory cache
// so opening the dialog does not block on the remote pool.
func StartSocks5PoolCacheScheduler(poolURL string) func() {
	cfg := &routerConfig{socks5PoolURL: poolURL}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_, _, _, _ = cachedSocks5Pool(ctx, cfg)
		for {
			delay := time.Until(nextSocks5PoolRefresh(time.Now()))
			if delay < time.Second {
				delay = time.Second
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				_, _, _, _ = cachedSocks5Pool(ctx, cfg)
			}
		}
	}()
	return cancel
}

func cachedSocks5Pool(ctx context.Context, cfg *routerConfig) ([]socks5PoolProxy, time.Time, string, error) {
	globalSocks5PoolCache.mu.Lock()
	cached := append([]socks5PoolProxy(nil), globalSocks5PoolCache.proxies...)
	updatedAt := globalSocks5PoolCache.updatedAt
	lastErr := globalSocks5PoolCache.err
	fresh := len(cached) > 0 && time.Now().Before(nextSocks5PoolRefresh(updatedAt))
	globalSocks5PoolCache.mu.Unlock()
	if fresh {
		return cached, updatedAt, "hit", nil
	}
	proxies, err := fetchSocks5Pool(ctx, cfg.socks5PoolURL)
	globalSocks5PoolCache.mu.Lock()
	defer globalSocks5PoolCache.mu.Unlock()
	if err != nil {
		globalSocks5PoolCache.err = err.Error()
		if len(globalSocks5PoolCache.proxies) > 0 {
			return append([]socks5PoolProxy(nil), globalSocks5PoolCache.proxies...), globalSocks5PoolCache.updatedAt, "stale", nil
		}
		return nil, time.Time{}, "miss", err
	}
	globalSocks5PoolCache.proxies = append([]socks5PoolProxy(nil), proxies...)
	globalSocks5PoolCache.updatedAt = time.Now()
	globalSocks5PoolCache.err = ""
	_ = lastErr
	return append([]socks5PoolProxy(nil), proxies...), globalSocks5PoolCache.updatedAt, "refresh", nil
}

func fetchSocks5Pool(ctx context.Context, poolURL string) ([]socks5PoolProxy, error) {
	if poolURL == "" {
		poolURL = defaultSocks5PoolURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, poolURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MiGate/1.0 socks5-pool")
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("pool upstream returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return parseSocks5Pool(body)
}

func parseSocks5Pool(body []byte) ([]socks5PoolProxy, error) {
	var raw interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	items := flattenSocks5PoolItems(raw)
	proxies := make([]socks5PoolProxy, 0, len(items))
	for _, item := range items {
		proxyURL := firstString(item, "proxy", "url", "uri")
		parsedAddress, parsedPort, parsedUser, parsedPass := parseSocks5ProxyURL(proxyURL)
		proxy := socks5PoolProxy{
			Address:      firstNonEmpty(firstString(item, "address", "addr", "ip", "host", "server"), parsedAddress),
			Port:         firstInt(item, "port"),
			Username:     parsedUser,
			Password:     parsedPass,
			CountryCode:  strings.ToUpper(firstString(item, "country_code", "countryCode", "cc", "code")),
			Country:      firstString(item, "country_cn", "country_en", "country_name", "countryName", "name", "country"),
			City:         firstString(item, "city", "region", "location"),
			ASN:          normalizeASN(firstString(item, "asn", "as", "AS")),
			Organization: firstString(item, "organization", "asOrganization", "org", "isp", "operator"),
			Latitude:     firstFloat(item, "latitude", "lat"),
			Longitude:    firstFloat(item, "longitude", "lon", "lng"),
			Latency:      -1,
		}
		if proxy.Port <= 0 && parsedPort > 0 {
			proxy.Port = parsedPort
		}
		if proxy.Address == "" || proxy.Port <= 0 || proxy.Port > 65535 {
			continue
		}
		if proxy.CountryCode == "" {
			country := firstString(item, "country")
			if len(country) == 2 {
				proxy.CountryCode = strings.ToUpper(country)
			}
		}
		proxies = append(proxies, proxy)
	}
	return proxies, nil
}

func flattenSocks5PoolItems(raw interface{}) []map[string]interface{} {
	switch v := raw.(type) {
	case []interface{}:
		items := make([]map[string]interface{}, 0, len(v))
		for _, entry := range v {
			if m, ok := entry.(map[string]interface{}); ok {
				items = append(items, m)
			}
		}
		return items
	case map[string]interface{}:
		for _, key := range []string{"proxies", "data", "items", "servers", "socks5"} {
			if nested, ok := v[key]; ok {
				return flattenSocks5PoolItems(nested)
			}
		}
		return []map[string]interface{}{v}
	default:
		return nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func parseSocks5ProxyURL(raw string) (string, int, string, string) {
	if raw == "" {
		return "", 0, "", ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return "", 0, "", ""
	}
	host := parsed.Hostname()
	port, _ := strconv.Atoi(parsed.Port())
	username := ""
	password := ""
	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
	}
	return host, port, username, password
}

func firstString(item map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := item[key]; ok {
			switch x := v.(type) {
			case string:
				return strings.TrimSpace(x)
			case float64:
				return strconv.FormatInt(int64(x), 10)
			}
		}
	}
	return ""
}

func firstInt(item map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		if v, ok := item[key]; ok {
			switch x := v.(type) {
			case float64:
				return int(x)
			case string:
				i, _ := strconv.Atoi(strings.TrimSpace(x))
				return i
			}
		}
	}
	return 0
}

func firstFloat(item map[string]interface{}, keys ...string) float64 {
	for _, key := range keys {
		if v, ok := item[key]; ok {
			switch x := v.(type) {
			case float64:
				return x
			case string:
				f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
				return f
			}
		}
	}
	return 0
}

func normalizeASN(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(strings.ToUpper(value), "AS") {
		return value
	}
	return "AS" + value
}

func socks5PoolRegions(proxies []socks5PoolProxy) []socks5PoolRegion {
	counts := map[string]*socks5PoolRegion{}
	for _, proxy := range proxies {
		code := proxy.CountryCode
		if code == "" {
			code = "UNKNOWN"
		}
		if counts[code] == nil {
			name := proxy.Country
			if name == "" {
				name = code
			}
			counts[code] = &socks5PoolRegion{Code: code, Name: name}
		}
		counts[code].Count++
	}
	regions := make([]socks5PoolRegion, 0, len(counts))
	for _, region := range counts {
		regions = append(regions, *region)
	}
	return regions
}

func socks5PoolListHandler(cfg *routerConfig, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	proxies, updatedAt, cacheStatus, err := cachedSocks5Pool(r.Context(), cfg)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "pool_fetch_failed", map[string]interface{}{"cache_status": cacheStatus, "detail": err.Error()})
		return
	}
	country := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("country")))
	filtered := make([]socks5PoolProxy, 0, len(proxies))
	for _, proxy := range proxies {
		if country == "" || proxy.CountryCode == country {
			filtered = append(filtered, proxy)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"regions": socks5PoolRegions(proxies), "proxies": filtered,
		"cache_status": cacheStatus, "cache_updated_at": updatedAt.Format(time.RFC3339),
		"next_refresh_at": nextSocks5PoolRefresh(time.Now()).Format(time.RFC3339),
	})
}

func socks5PoolPingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	address := strings.TrimSpace(req.Address)
	if address == "" || req.Port <= 0 || req.Port > 65535 {
		http.Error(w, `{"error":"invalid_proxy"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pingOutbound(address, req.Port))
}

func socks5PoolImportHandler(store Store, ctrl XrayController, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Address      string `json:"address"`
		Port         int    `json:"port"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		City         string `json:"city"`
		ASN          string `json:"asn"`
		Organization string `json:"organization"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	address := strings.TrimSpace(req.Address)
	if address == "" || req.Port <= 0 || req.Port > 65535 {
		http.Error(w, `{"error":"invalid_proxy"}`, http.StatusBadRequest)
		return
	}
	remarkParts := []string{}
	for _, part := range []string{req.City, normalizeASN(req.ASN), req.Organization} {
		part = strings.TrimSpace(part)
		if part != "" {
			remarkParts = append(remarkParts, part)
		}
	}
	remark := strings.Join(remarkParts, " ")
	if remark == "" {
		remark = address
	}
	outbound, err := store.CreateOutbound(r.Context(), db.CreateOutboundParams{
		Tag:      fmt.Sprintf("pool-socks-%s-%d", strings.NewReplacer(".", "-", ":", "-").Replace(address), req.Port),
		Remark:   remark,
		Protocol: "socks",
		Address:  address,
		Port:     req.Port,
		Username: strings.TrimSpace(req.Username),
		Password: req.Password,
	})
	if err != nil {
		http.Error(w, `{"error":"create_outbound_failed"}`, http.StatusBadRequest)
		return
	}
	applyResult := ctrl.Apply(r.Context())
	_ = tryApplySingbox(r.Context(), store)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"outbound": outbound, "xray": applyResult})
}

func outboundChildrenHandler(cfg *routerConfig) http.HandlerFunc {
	store := cfg.store
	ctrl := cfg.xrayController
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/outbounds/")
		if path == "socks5-pool" {
			socks5PoolListHandler(cfg, w, r)
			return
		}
		if path == "socks5-pool/ping" {
			socks5PoolPingHandler(w, r)
			return
		}
		if path == "socks5-pool/import" {
			socks5PoolImportHandler(store, ctrl, w, r)
			return
		}
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
					result := pingOutbound(o.Address, o.Port)
					mu.Lock()
					results[o.ID] = result
					mu.Unlock()
				}(ob)
			}
			wg.Wait()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(results)
			return
		}
		if strings.HasSuffix(path, "/ping") {
			if r.Method != http.MethodGet {
				http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			idStr := strings.TrimSuffix(path, "/ping")
			obID, err := strconv.ParseInt(strings.TrimSpace(idStr), 10, 64)
			if err != nil {
				http.Error(w, `{"error":"invalid_id"}`, http.StatusBadRequest)
				return
			}
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
			_ = tryApplySingbox(r.Context(), store)
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
			_ = tryApplySingbox(r.Context(), store)
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
			_ = tryApplySingbox(r.Context(), store)
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
			_ = tryApplySingbox(r.Context(), store)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "deleted", "xray": applyResult})
		case http.MethodGet:
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func isSingBoxProtocol(protocol string) bool {
	switch protocol {
	case "hysteria2", "tuic", "shadowtls":
		return true
	default:
		return false
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

		// Build client traffic list from DB + stats. Xray protocols can use the
		// live Xray stats API; sing-box protocols are not wired to a realtime
		// counter source yet, so label them explicitly instead of presenting DB
		// values as live traffic.
		var clientList []map[string]interface{}
		for _, in := range inb {
			for _, c := range in.Clients {
				info := map[string]interface{}{
					"id":                   c.ID,
					"inbound_id":           c.InboundID,
					"protocol":             in.Protocol,
					"email":                c.Email,
					"enabled":              c.Enabled,
					"up":                   c.Up,
					"down":                 c.Down,
					"traffic_limit":        c.TrafficLimit,
					"expiry_at":            c.ExpiryAt,
					"traffic_stats_source": "db",
				}
				if isSingBoxProtocol(in.Protocol) {
					info["traffic_stats_source"] = "unavailable"
					info["traffic_stats_note"] = "sing-box realtime traffic stats are not yet wired"
				} else if liveStats, ok := clientStats[c.Email]; ok {
					// Override with live stats if available.
					info["up"] = liveStats.Uplink
					info["down"] = liveStats.Downlink
					info["traffic_stats_source"] = "xray"
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

type cpuSample struct {
	Idle  uint64
	Total uint64
}

func systemResourcesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		memTotal, memUsed, memPercent := readMemoryUsage()
		diskTotal, diskUsed, diskPercent := readDiskUsage("/")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"cpu_percent":    sampleCPUPercent(),
			"memory_total":   memTotal,
			"memory_used":    memUsed,
			"memory_percent": memPercent,
			"disk_total":     diskTotal,
			"disk_used":      diskUsed,
			"disk_percent":   diskPercent,
			"uptime_seconds": readUptimeSeconds(),
		})
	}
}

func sampleCPUPercent() float64 {
	first, err := readCPUSample()
	if err != nil {
		return 0
	}
	time.Sleep(100 * time.Millisecond)
	second, err := readCPUSample()
	if err != nil || second.Total <= first.Total {
		return 0
	}
	totalDelta := second.Total - first.Total
	idleDelta := second.Idle - first.Idle
	if totalDelta == 0 || idleDelta > totalDelta {
		return 0
	}
	return clampPercent(round1(float64(totalDelta-idleDelta) * 100 / float64(totalDelta)))
}

func readCPUSample() (cpuSample, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}, fmt.Errorf("invalid cpu stat")
	}
	var total uint64
	var idle uint64
	for i, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuSample{}, err
		}
		total += value
		if i == 3 || i == 4 {
			idle += value
		}
	}
	return cpuSample{Idle: idle, Total: total}, nil
}

func readMemoryUsage() (totalBytes, usedBytes int64, percent float64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0
	}
	values := map[string]int64{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		values[strings.TrimSuffix(fields[0], ":")] = value * 1024
	}
	total := values["MemTotal"]
	available := values["MemAvailable"]
	if total <= 0 || available < 0 {
		return 0, 0, 0
	}
	used := total - available
	return total, used, clampPercent(round1(float64(used) * 100 / float64(total)))
}

func readDiskUsage(path string) (totalBytes, usedBytes int64, percent float64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, 0, 0
	}
	total := int64(stat.Blocks) * int64(stat.Bsize)
	free := int64(stat.Bavail) * int64(stat.Bsize)
	if total <= 0 || free < 0 {
		return 0, 0, 0
	}
	used := total - free
	return total, used, clampPercent(round1(float64(used) * 100 / float64(total)))
}

func readUptimeSeconds() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(seconds)
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

func clampPercent(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func inboundsHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listInbounds(w, r, store)
		case http.MethodPost:
			createInbound(w, r, store)
			applyXrayAsync(ctrl)
			applySingboxAsync(store)
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

func applySingboxAsync(store Store) {
	go func() {
		if err := tryApplySingbox(context.Background(), store); err != nil {
			log.Printf("sing-box auto apply: %v", err)
		}
	}()
}

func writeJSONError(w http.ResponseWriter, status int, code string, fields ...map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	payload := map[string]interface{}{"error": code}
	for _, extra := range fields {
		for k, v := range extra {
			payload[k] = v
		}
	}
	_ = json.NewEncoder(w).Encode(payload)
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
				writeJSONError(w, http.StatusConflict, "port_conflict", map[string]interface{}{
					"message": "端口 " + strconv.FormatInt(int64(ib.Port), 10) + " 已被入站 " + strconv.FormatInt(ib.ID, 10) + " 使用",
				})
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
				applySingboxAsync(store)
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
				applySingboxAsync(store)
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
				applySingboxAsync(store)
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
				applySingboxAsync(store)
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
				applySingboxAsync(store)
			} else if len(parts) == 3 && parts[1] == "clients" {
				// PUT /api/inbounds/{id}/clients/{clientId}
				clientID, err := strconv.ParseInt(parts[2], 10, 64)
				if err != nil || clientID <= 0 {
					http.NotFound(w, r)
					return
				}
				updateClient(w, r, store, clientID)
				applyXrayAsync(ctrl)
				applySingboxAsync(store)
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
				applySingboxAsync(store)
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
				applySingboxAsync(store)
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
		UUID         string `json:"uuid"`
		TrafficLimit int64  `json:"traffic_limit"`
		ExpiryAt     int64  `json:"expiry_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	created, err := store.CreateClient(r.Context(), db.CreateClientParams{InboundID: inboundID, Email: payload.Email, UUID: payload.UUID, TrafficLimit: payload.TrafficLimit, ExpiryAt: payload.ExpiryAt})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate client") {
			writeJSONError(w, http.StatusConflict, "duplicate_client", map[string]interface{}{
				"message": "同一入站下客户端邮箱或凭据已存在，请更换后重试",
			})
			return
		}
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
	// Port conflict check (excluding current inbound)
	if payload.Port > 0 {
		existing, _ := store.ListInbounds(r.Context())
		for _, ib := range existing {
			if ib.ID != inboundID && ib.Port == payload.Port {
				writeJSONError(w, http.StatusConflict, "port_conflict", map[string]interface{}{
					"message": "端口 " + strconv.FormatInt(int64(ib.Port), 10) + " 已被入站 " + strconv.FormatInt(ib.ID, 10) + " 使用",
				})
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
		if strings.Contains(err.Error(), "duplicate client") {
			writeJSONError(w, http.StatusConflict, "duplicate_client", map[string]interface{}{
				"message": "同一入站下客户端邮箱已存在，请更换后重试",
			})
			return
		}
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

type coreActionPayload struct {
	Confirm            bool `json:"confirm"`
	AllowSystemChanges bool `json:"allow_system_changes"`
}

func decodeCoreActionPayload(w http.ResponseWriter, r *http.Request) (coreActionPayload, bool) {
	var payload coreActionPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_json")
		return payload, false
	}
	if !payload.Confirm || !payload.AllowSystemChanges {
		writeJSONError(w, http.StatusForbidden, "confirmation_required", map[string]interface{}{"commands_executed": []string{}})
		return payload, false
	}
	return payload, true
}

func coreInstallHandler(core string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if _, ok := decodeCoreActionPayload(w, r); !ok {
			return
		}
		var script string
		var commands []string
		switch core {
		case "xray":
			commands = []string{"bash -c curl Xray-install", "mkdir -p /usr/local/etc/xray", "ln -sf /usr/local/migate/xray.json /usr/local/etc/xray/xray.json", "systemctl enable --now xray"}
			script = `set -euo pipefail
if ! command -v curl >/dev/null 2>&1; then echo 'curl is required' >&2; exit 1; fi
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"
mkdir -p /usr/local/etc/xray
ln -sf /usr/local/migate/xray.json /usr/local/etc/xray/xray.json
ln -sf /usr/local/migate/xray.json /usr/local/etc/xray/config.json
systemctl enable xray
systemctl restart xray || true
xray --version | head -1`
		case "singbox":
			commands = []string{"download sing-box release", "install /usr/local/bin/sing-box", "write /etc/systemd/system/migate-singbox.service", "systemctl enable --now migate-singbox"}
			script = `set -euo pipefail
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) asset_arch=amd64 ;;
  aarch64|arm64) asset_arch=arm64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
version="${SINGBOX_VERSION:-1.13.13}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${asset_arch}.tar.gz"
checksums_url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-checksums.txt"
curl -fL "$url" -o "$tmp/sing-box.tar.gz"
curl -fL "$checksums_url" -o "$tmp/checksums.txt"
grep "sing-box-${version}-linux-${asset_arch}.tar.gz" "$tmp/checksums.txt" > "$tmp/sing-box.tar.gz.sha256"
(cd "$tmp" && sha256sum -c "sing-box.tar.gz.sha256")
tar -xzf "$tmp/sing-box.tar.gz" -C "$tmp"
cp "$tmp"/sing-box-*/sing-box /usr/local/bin/sing-box
chmod +x /usr/local/bin/sing-box
mkdir -p /etc/sing-box
if [ ! -f /etc/sing-box/config.json ]; then
  printf '%s\n' '{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}' > /etc/sing-box/config.json
fi
cat > /etc/systemd/system/migate-singbox.service <<'UNIT'
[Unit]
Description=MiGate managed sing-box service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable migate-singbox
systemctl restart migate-singbox || true
sing-box version | head -1`
		default:
			writeJSONError(w, http.StatusBadRequest, "unknown_core")
			return
		}
		out, err := runCoreScript(script)
		status := "installed"
		if err != nil {
			status = "failed"
			w.WriteHeader(http.StatusInternalServerError)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"core": core, "status": status, "output": string(out), "commands_executed": commands})
	}
}

func runCoreScript(script string) ([]byte, error) {
	cmd := exec.Command("bash", "-s")
	cmd.Stdin = strings.NewReader(script)
	return cmd.CombinedOutput()
}

func coreUninstallHandler(core string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if _, ok := decodeCoreActionPayload(w, r); !ok {
			return
		}
		var script string
		var commands []string
		switch core {
		case "xray":
			commands = []string{"systemctl disable --now xray", "bash Xray-install remove", "remove MiGate xray symlinks"}
			script = `set -euo pipefail
systemctl disable --now xray 2>/dev/null || true
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" -- remove --purge 2>&1 || true
rm -f /usr/local/etc/xray/xray.json /usr/local/etc/xray/config.json
printf 'Xray removed or disabled\n'`
		case "singbox":
			commands = []string{"systemctl disable --now migate-singbox", "remove sing-box binary and service"}
			script = `set -euo pipefail
systemctl disable --now migate-singbox 2>/dev/null || true
rm -f /etc/systemd/system/migate-singbox.service /usr/local/bin/sing-box
systemctl daemon-reload 2>/dev/null || true
printf 'sing-box removed\n'`
		default:
			writeJSONError(w, http.StatusBadRequest, "unknown_core")
			return
		}
		out, err := runCoreScript(script)
		status := "uninstalled"
		if err != nil {
			status = "failed"
			w.WriteHeader(http.StatusInternalServerError)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"core": core, "status": status, "output": string(out), "commands_executed": commands})
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
		} else if n > maxXrayLogLines {
			lines = strconv.Itoa(maxXrayLogLines)
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
			// Check /etc/xray/certs/{domain}.pem and .key first
			certPath = "/etc/xray/certs/" + domain + ".pem"
			keyPath = "/etc/xray/certs/" + domain + ".key"
			if _, err := os.Stat(certPath); err == nil {
				if _, err := os.Stat(keyPath); err == nil {
					issued = true
				}
			}
			// Fallback to config dir for tests
			if !issued && cfg.configDir != "" {
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

func installACMESh(email string) (string, error) {
	resp, err := http.Get("https://get.acme.sh")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download acme.sh installer failed: status %d", resp.StatusCode)
	}
	script, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", err
	}
	cmd := exec.Command("sh", "-s", "email="+email)
	cmd.Stdin = bytes.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
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

	// Issue cert via acme.sh directly to /etc/xray/certs/
	certDir := "/etc/xray/certs"
	if err := os.MkdirAll(certDir, 0755); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "mkdir_cert_dir_failed"})
		return
	}

	certFile := certDir + "/" + req.Domain + ".pem"
	keyFile := certDir + "/" + req.Domain + ".key"

	// Check if acme.sh is installed; if not, install it without interpolating
	// request data into a shell command string.
	if _, err := exec.LookPath("acme.sh"); err != nil {
		installOut, err := installACMESh(req.Email)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":  "install_acme_failed",
				"detail": installOut,
			})
			return
		}
	}

	// Run acme.sh --issue --standalone
	out, err := exec.Command("acme.sh",
		"--issue", "--standalone", "-d", req.Domain,
		"--keylength", "ec-256",
		"--fullchain-file", certFile,
		"--key-file", keyFile,
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

	// Set permissions for xray user
	exec.Command("chmod", "644", certFile, keyFile).Run()

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
		"cert_path": certFile,
		"key_path":  keyFile,
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

func updateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		command := "/usr/local/bin/migate-install --update"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "updating", "command": command})
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if runningUnderGoTest() {
			return
		}
		go func() {
			time.Sleep(500 * time.Millisecond)
			_ = exec.Command("systemd-run", "--unit=migate-update", "--collect", "--same-dir", "--property=Type=oneshot", "--property=User=root", "--property=StandardOutput=append:/var/log/migate-update.log", "--property=StandardError=append:/var/log/migate-update.log", "/usr/local/bin/migate-install", "--update").Run()
		}()
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

func runningUnderGoTest() bool {
	return strings.HasSuffix(os.Args[0], ".test")
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
		if !runningUnderGoTest() {
			go func() {
				time.Sleep(2 * time.Second)
				os.Exit(0)
			}()
		}
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
		// hysteria2://password@host:port/?params#name
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
		// sing-box v1.13 requires TLS for Hysteria2 server inbounds.
		// MiGate uses generated self-signed certs by default, so share links must
		// include TLS + insecure even when the UI stores security=none.
		params = append(params, "security=tls")
		addParam("sni", inbound.RealityServerNames)
		params = append(params, "insecure=1")
		query := strings.Join(params, "&")
		suffix := ""
		if query != "" {
			suffix = "?" + query
		}
		return "hysteria2://" + client.UUID + "@" + host + ":" + strconv.Itoa(inbound.Port) + suffix + "#" + url.QueryEscape(client.Email)
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
			if inbound.Network != "xhttp" {
				params = append(params, "flow=xtls-rprx-vision")
			}
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
	return "ss://" + encoded + "@" + host + ":" + strconv.Itoa(inbound.Port) + "#" + url.QueryEscape(client.Email)
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
		ver, _ := singbox.Version()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"installed":          true,
			"status":             status,
			"version":            strings.TrimSpace(ver),
			"memory_rss_bytes":   singbox.MemoryRSS(),
			"uptime":             singbox.Uptime(),
			"active_connections": singbox.ActiveConnections(),
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
			writeJSONError(w, http.StatusInternalServerError, "list_failed", map[string]interface{}{"detail": err.Error()})
			return
		}

		// Build config
		cfg := singbox.BuildConfig(inbounds)

		// Ensure self-signed cert exists
		if _, err := os.Stat(singbox.CertFile); os.IsNotExist(err) {
			if err := singbox.GenerateSelfSignedCert(); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "cert_failed", map[string]interface{}{"detail": err.Error()})
				return
			}
		}

		// Encode and write config
		raw, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "marshal_failed", map[string]interface{}{"detail": err.Error()})
			return
		}
		if err := os.WriteFile(singbox.DefaultConfigPath, raw, 0644); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "write_failed", map[string]interface{}{"detail": err.Error()})
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

// tryApplySingbox reads sing-box supported inbounds from the store, builds
// a sing-box config, writes it to disk and restarts sing-box. Errors are
// silently returned (not panicked) to avoid blocking the caller.
func tryApplySingbox(ctx context.Context, store Store) error {
	if !singbox.IsInstalled() {
		return nil // sing-box not available, skip silently
	}
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		return fmt.Errorf("list inbounds: %w", err)
	}
	cfg := singbox.BuildConfig(inbounds)
	if _, err := os.Stat(singbox.CertFile); os.IsNotExist(err) {
		if err := singbox.GenerateSelfSignedCert(); err != nil {
			return fmt.Errorf("generate cert: %w", err)
		}
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(singbox.DefaultConfigPath, raw, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return singbox.Apply()
}

// singboxConfigHandler returns the current sing-box config JSON.
func singboxConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, err := os.ReadFile(singbox.DefaultConfigPath)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "read_failed", map[string]interface{}{"detail": err.Error()})
			return
		}
		// Parse and re-marshal so the client gets pretty-printed JSON
		var parsed interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			_, _ = w.Write(data)
			return
		}
		pretty, _ := json.MarshalIndent(parsed, "", "  ")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(pretty)
	}
}

// singboxVersionHandler returns the sing-box version.
func singboxVersionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if !singbox.IsInstalled() {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "not_installed"})
			return
		}
		ver, err := singbox.Version()
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "unknown", "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": strings.TrimSpace(ver)})
	}
}

// singboxLogsHandler returns recent sing-box service logs from journalctl.
func singboxLogsHandler() http.HandlerFunc {
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
		} else if n > maxXrayLogLines {
			lines = strconv.Itoa(maxXrayLogLines)
		}
		out, err := exec.Command("journalctl", "-u", singbox.ServiceName(), "-n", lines, "--no-pager", "-o", "short-iso").CombinedOutput()
		if err != nil {
			out, err = exec.Command("tail", "-n", lines, "/var/log/syslog").CombinedOutput()
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"logs": "无法读取 Sing-box 日志：journalctl 和 syslog 均不可用。"})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"logs": string(out)})
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
    .overview-grid { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:var(--space-4); margin-bottom:var(--space-4); align-items:stretch; }
    .overview-section { grid-column:1 / -1; display:grid; gap:var(--space-3); }
    .overview-section-title { color:var(--muted); font-size:var(--text-sm); font-weight:600; letter-spacing:.02em; }
    .sidebar { position:sticky; top:0; height:100vh; overflow:auto; box-shadow:inset -1px 0 0 var(--line-strong); padding:var(--space-6) 18px; background:var(--surface); display:flex; flex-direction:column; }
    .brand { font-size:24px; font-weight:600; letter-spacing:-0.96px; margin-bottom:var(--space-1); color:var(--fg); }
    .subtitle { color:var(--muted); font-size:var(--text-sm); line-height:1.5; margin-bottom:var(--space-4); }
    nav { flex:1; overflow:visible; }
    #sidebar-toggle { display:none; align-items:center; justify-content:center; width:36px; height:36px; border:none; background:var(--surface); color:var(--fg); font-size:22px; cursor:pointer; border-radius:var(--radius-sm); box-shadow:var(--shadow-md); z-index:101; position:fixed; top:12px; left:12px; touch-action:manipulation; }
    .mobile-topbar { display:none; position:sticky; top:0; z-index:90; align-items:center; gap:12px; min-height:56px; padding:calc(8px + env(safe-area-inset-top)) 18px 8px; margin:calc(-1 * var(--space-6)) calc(-1 * var(--space-6)) var(--space-4); background:color-mix(in srgb, var(--bg) 92%, transparent); backdrop-filter:blur(12px); box-shadow:inset 0 -1px 0 var(--line); }
    .mobile-menu-button { display:inline-flex; align-items:center; justify-content:center; width:40px; min-width:40px; min-height:40px; padding:0; background:var(--surface); color:var(--fg); border-radius:var(--radius-md); box-shadow:var(--shadow-sm); touch-action:manipulation; }
    .mobile-title { color:var(--fg); font-size:var(--text-lg); font-weight:600; letter-spacing:-.32px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
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
    .client-subsection { margin:8px 0 var(--space-3) var(--space-6); padding:var(--space-3) 0 0 var(--space-5); border-left:2px solid var(--line); box-shadow:none; }

    .overview-insights { display:grid; grid-template-columns:1.2fr 1fr 1fr; gap:var(--space-4); grid-column:1 / -1; }
    .overview-card { display:grid; gap:var(--space-3); align-content:start; background:var(--surface); border-radius:var(--radius-lg); box-shadow:var(--shadow-md); padding:var(--panel-padding); min-height:156px; }
    .overview-card-title { color:var(--fg); font-size:var(--text-lg); font-weight:600; letter-spacing:-0.24px; }
    .overview-pill { display:inline-flex; align-items:center; width:max-content; min-height:26px; padding:0 10px; border-radius:9999px; background:var(--surface-subtle); color:var(--fg); box-shadow:var(--shadow-sm); font-size:var(--text-xs); font-weight:500; }
    .type-pill { display:inline-flex; align-items:center; padding:2px 8px; border-radius:8px; font-size:11px; font-weight:600; line-height:1.4; }
    .type-pill.type-home { background:color-mix(in srgb, #2e7d32 15%, transparent); color:var(--green, #2e7d32); }
    .type-pill.type-biz { background:color-mix(in srgb, #1565c0 15%, transparent); color:var(--blue, #1565c0); }
    .panel, .card { background:var(--surface); border-radius:var(--radius-lg); box-shadow:var(--shadow-md); padding:var(--panel-padding); }
    .compact-metric-card { background:var(--surface); border-radius:var(--radius-md); box-shadow:var(--shadow-sm); padding:12px 14px; }
    .compact-metric-card .metric { font-size:22px; margin-top:6px; }
    .compact-metric-card p { font-size:12px; margin-top:4px; }
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
    .resource-actions { display:flex; align-items:center; justify-content:flex-end; gap:8px; }
    .client-resource-row .resource-actions { flex-wrap:nowrap; justify-content:flex-end; margin-left:auto; gap:6px; }
    .client-resource-row .icon-btn, .client-resource-row .danger-icon-btn { min-width:64px; padding:0 var(--space-2); white-space:nowrap; }
    .outbound-card { padding:12px 16px; display:flex; align-items:center; gap:12px; min-width:0; }
    .outbound-card.is-disabled { opacity:.68; }
    .outbound-status-dot { flex:0 0 auto; font-size:18px; line-height:1; }
    .outbound-main { flex:1; min-width:0; display:grid; gap:4px; }
    .outbound-meta { color:var(--muted); font-size:var(--text-xs); line-height:1.45; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .outbound-actions { display:flex; align-items:center; justify-content:flex-end; gap:6px; flex:0 0 auto; }
    .outbound-actions .icon-btn, .outbound-actions .danger-icon-btn { touch-action:manipulation; }
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
    .socks5-pool-layout { display:grid; grid-template-columns:minmax(220px,280px) minmax(360px,1fr); gap:16px; align-items:stretch; }
    .socks5-pool-detail-card { min-height:360px; border:1px solid var(--line); border-radius:var(--radius-lg); background:linear-gradient(135deg,var(--surface-subtle),var(--surface)); padding:14px; overflow:hidden; }
    .socks5-pool-list-panel { display:flex; flex-direction:column; gap:12px; min-height:360px; min-width:0; }
    .socks5-pool-list { height:260px; overflow-y:auto; overflow-x:hidden; padding:8px; }
    .socks5-pool-footer { position:sticky; bottom:0; padding-top:var(--space-3); background:linear-gradient(180deg, transparent, var(--surface) 28%); }
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
      main { padding:calc(var(--space-6) + 56px) var(--space-4) var(--space-4); }
      .mobile-topbar { display:flex; position:fixed; left:0; right:0; margin:0; }
      .sidebar { position:fixed; top:0; left:0; bottom:0; width:min(var(--sidebar-width), 86vw); z-index:100; transform:translateX(-100%); transition:transform .25s ease; box-shadow:inset -1px 0 0 var(--line-strong); }
      .sidebar-open .sidebar, body.sidebar-open .sidebar { transform:translateX(0); }
      #sidebar-overlay { display:block; opacity:0; pointer-events:none; transition:opacity .25s ease; }
      .sidebar-open #sidebar-overlay, body.sidebar-open #sidebar-overlay { opacity:1; pointer-events:auto; }
      #sidebar-toggle { display:none; }
      .grid,.overview-grid,.protocols { grid-template-columns:1fr 1fr; }
      .overview-insights { grid-template-columns:1fr; }
      .action-toolbar { align-items:stretch; flex-direction:column; }
      .toolbar-actions { justify-content:flex-start; }
      form { grid-template-columns:repeat(2,minmax(0,1fr)); }
      .outbound-card { align-items:flex-start; flex-wrap:wrap; padding:14px; }
      .outbound-main { flex-basis:calc(100% - 34px); }
      .outbound-meta { white-space:normal; word-break:break-word; }
      .outbound-actions { width:100%; justify-content:flex-start; padding-left:30px; }
      .outbound-actions .icon-btn, .outbound-actions .danger-icon-btn { min-width:40px; min-height:40px; }
    }
    @media (max-width: 560px) { .grid,.overview-grid,.protocols, form { grid-template-columns:1fr; } main { padding:calc(var(--space-5) + 56px) var(--space-3) var(--space-4); } .mobile-topbar { padding-left:var(--space-3); padding-right:var(--space-3); } .modal-content,#confirm-dialog { min-width:0; width:calc(100vw - 28px); max-width:calc(100vw - 28px); } .modal-form { grid-template-columns:1fr; } .form-actions,.modal-footer { flex-direction:column-reverse; align-items:stretch; } .socks5-pool-layout { grid-template-columns:1fr; } .socks5-pool-detail-card { min-height:auto; } .socks5-pool-list-panel { min-height:auto; } .socks5-pool-list { height:min(48vh, 360px); } }
  </style>
  <script>
const i18n={zh:{overview:"概览",inbounds:"入站",outbound:"出站",routing:"路由",settings:"设置",currentUser:"当前用户",loading:"加载中...",logout:"登出",darkMode:"深色模式",lightMode:"浅色模式",langToggle:"English",serverResources:"服务器资源",cpu:"CPU",memory:"内存",disk:"硬盘",uptime:"开机时长",businessStatus:"业务状态",clients:"客户端",totalTraffic:"总流量",routingRules:"路由规则",runningStatus:"运行状态",protocolDistribution:"协议分布",coreProtocols:"核心协议",newInbound:"新增入站",searchInbound:"搜索入站...",defaultSort:"默认排序",byPort:"按端口",byProtocol:"按协议",byClients:"按客户端数",loadingInbounds:"正在加载入站...",outboundManagement:"出站管理",outboundDesc:"配置链式代理转发（SOCKS5 / HTTP），实现流量经外部代理链路中转。",newOutbound:"新增出站",loadingOutbounds:"正在加载出站...",routingManagement:"路由管理",routingDesc:"配置域名/IP 路由规则，决定匹配流量的出站选择。",newRoute:"新增路由",loadingRoutes:"正在加载路由...",xrayConfig:"Xray 配置",xrayDesc:"Xray 运行状态、生成的配置预览与应用操作。",preview:"预览",apply:"应用",validate:"验证",restart:"重启",reloadConfig:"重载配置",singboxConfig:"Sing-box 配置",singboxDesc:"Sing-box 运行状态、生成的配置预览与应用操作。",panelSettings:"面板设置",panelSettingsDesc:"WebUI 端口、路径、凭据等面板运行参数。",refresh:"刷新",saveSettings:"保存设置",confirmRestart:"确认重启 MiGate 服务？",cancel:"取消",confirm:"确认",name:"名称",protocol:"协议类型",port:"端口",enabled:"启用",actions:"操作",edit:"编辑",delete:"删除",copy:"复制",active:"活跃",total:"总计",usedTotal:"已用 / 总量",systemUptime:"系统运行时间",checking:"检查中...",runningOverview:"运行概况",activeClients:"活跃客户端",noInbounds:"暂无入站",noOutbounds:"暂无出站",noRoutes:"暂无路由",updateNow:"立即更新",updateChecking:"正在检查更新...",updateStarted:"更新已开始，服务会短暂重启，请稍后刷新页面。",updateFailed:"更新失败",newVersionAvailablePrefix:"🚀 新版本",newVersionAvailableMiddle:"已发布（当前",updateReleaseNotes:"更新日志",dyn001:"登录状态已过期，请重新登录",dyn002:"暂无入站",dyn003:"先创建一个 VLESS / VMess / Trojan / Shadowsocks 节点；MiGate 会自动生成客户端与 Xray 配置。",dyn004:"创建入站",dyn005:"查看 Xray",dyn006:"查看 Sing-box",dyn007:" 客户端</span></div>",dyn008:")\" title=\"展开客户端\">客户端</button>",dyn009:")\" title=\"编辑\">编辑</button>",dyn010:")\" title=\"启用/禁用\">",dyn011:"禁用",dyn012:"启用",dyn013:")\" title=\"删除\">删除</button>",dyn014:"<div class=\"empty-state\"><div class=\"empty-state-title\">无匹配结果</div><div class=\"empty-state-copy\">没有入站匹配当前的搜索或筛选条件。</div></div>",dyn015:"还没有入站。建议先创建一个 VLESS/REALITY 或 TLS 入站，再添加客户端。",dyn016:"已启用 ",dyn017:" 个入站，停用 ",dyn018:" 个；受限客户端 ",dyn019:" 个，过期客户端 ",dyn020:" 个。",dyn021:"活跃客户端 ",dyn022:"无法连接",dyn023:"未安装",dyn024:"运行中",dyn025:"已停止",dyn026:"未知",dyn027:"天 ",dyn028:"小时",dyn029:"小时 ",dyn030:"分钟",dyn031:"<div class=\\\"muted\\\" style=\\\"padding:12px\\\">加载失败</div>",dyn032:"暂无出站",dyn033:"出站用于链式代理转发。点击上方\"新建出站\"添加 SOCKS5 / HTTP 代理。",dyn034:"直接连接",dyn035:"阻断",dyn036:")\\\" title=\\\"测速\\\">&#9889;</button>",dyn037:")\\\" title=\\\"编辑\\\">&#9998;</button>",dyn038:")\\\" title=\\\"删除\\\">&#10005;</button>",dyn039:"<span class=\\\"muted\\\" style=\\\"font-size:var(--text-xs);padding:4px 8px\\\">内置</span>",dyn040:"测速中...",dyn041:" 超时",dyn042:" 失败",dyn043:"没有可测速的自定义出站",dyn044:" 测速中",dyn045:"测速失败",dyn046:"完成: ",dyn047:" 成功, ",dyn048:"测速异常: ",dyn049:"排序保存失败",dyn050:"排序已保存",dyn051:"<option value=\"\">-- 请选择地区 --</option>",dyn052:"<div class=\"empty-state\"><div class=\"empty-state-title\">请选择地区后显示对应 SOCKS5</div><div class=\"empty-state-copy\">先从上方选择国家/地区，再逐行测延时。</div></div>",dyn053:"其他 / OT",dyn054:"北美 / NA",dyn055:"亚洲 / AS",dyn056:"欧洲 / EU",dyn057:"南美 / SA",dyn058:"大洋洲 / OC",dyn059:"非洲 / AF",dyn060:"测速中",dyn061:"<div class=\"empty-state\"><div class=\"empty-state-title\">地址池加载失败</div><div class=\"empty-state-copy\">",dyn062:"<div class=\"empty-state\"><div class=\"empty-state-title\">请选择地区后显示对应 SOCKS5</div><div class=\"empty-state-copy\">不会默认展开全量列表，避免滚动和测速压力。</div></div>",dyn063:"<div class=\"empty-state\"><div class=\"empty-state-title\">正在加载地区 SOCKS5</div><div class=\"empty-state-copy\">加载后会逐行测延时。</div></div>",dyn064:"SOCKS5 地址池缓存状态：",dyn065:"<div class=\"empty-state\"><div class=\"empty-state-title\">请选择地区后显示对应 SOCKS5</div></div>",dyn066:"<div class=\"empty-state\"><div class=\"empty-state-title\">暂无可用代理</div><div class=\"empty-state-copy\">换一个地区或稍后重试。</div></div>",dyn067:"<h3 style=\"margin:10px 0 8px;font-size:18px\">选择地区后查看详情</h3>",dyn068:"<p class=\"field-help\" style=\"margin:0 0 14px\">左侧显示当前选中 SOCKS5 的详细信息；右侧只在选择地区后展示列表并逐行测延时。</p>",dyn069:"<div><span class=\"muted\">地区数</span><br><strong>",dyn070:"<div><span class=\"muted\">缓存状态</span><br><strong>",dyn071:"加载中",dyn072:"<div><span class=\"muted\">刷新策略</span><br><strong>每日 06:00</strong></div></div>",dyn073:"<div><span class=\"muted\">地址</span><br><strong>",dyn074:"<div><span class=\"muted\">延时</span><br><strong>",dyn075:"<div><span class=\"muted\">地区</span><br><strong>",dyn076:"<div><span class=\"muted\">运营商</span><br><strong>",dyn077:"<div><span class=\"muted\">认证</span><br><strong>",dyn078:"需要账号密码",dyn079:"无认证",dyn080:"请选择一个 SOCKS5",dyn081:"导入中...",dyn082:"导入失败",dyn083:"SOCKS5 已添加：",dyn084:"导入失败: ",dyn085:"请输入出站标识",dyn086:"请输入代理地址",dyn087:"请输入有效端口(1-65535)",dyn088:"创建失败",dyn089:"出站已创建",dyn090:"创建失败: ",dyn091:"未找到出站",dyn092:"加载失败",dyn093:"更新失败",dyn094:"出站已更新",dyn095:"更新失败: ",dyn096:"确认删除此出站？",dyn097:"删除失败",dyn098:"出站已删除",dyn099:"删除失败: ",dyn100:"<div class=\\\"empty-state\\\"><div class=\\\"empty-state-title\\\">暂无路由规则</div><div class=\\\"empty-state-copy\\\">添加规则可将特定域名、入站或协议的流量转发到指定出站。点击上方\"新建规则\"开始。</div></div>",dyn101:"入站: ",dyn102:"域名: ",dyn103:"协议: ",dyn104:"所有流量",dyn105:")\\\" title=\\\"编辑\\\" data-rule-outbound=\\\"",dyn106:"<option value=\"\">留空 = 所有入站</option>",dyn107:"<option value=\"\">-- 选择出站 --</option>",dyn108:"加载下拉选项失败: ",dyn109:"未命名",dyn110:" (端口 ",dyn111:"请选择目标出站",dyn112:"创建中...",dyn113:"路由规则已创建",dyn114:"确认删除此路由规则？",dyn115:"路由规则已删除",dyn116:"保存中...",dyn117:"保存失败",dyn118:"路由规则已更新",dyn119:"保存失败: ",dyn120:"浅色模式",dyn121:"深色模式",dyn122:"未登录",dyn123:"未启用认证",dyn124:"无法读取用户",dyn125:"登出失败",dyn126:"已登出",dyn127:"<div class=\"list\" style=\"margin:0\">正在加载客户端...</div>",dyn128:"<div class=\"muted\" style=\"padding:12px\">入站未找到</div>",dyn129:")\" class=\"btn-sm\">新增客户端</button>",dyn130:"<div class=\"muted\" style=\"padding:12px\">加载失败</div>",dyn131:"暂无客户端",dyn132:"在当前入站下创建第一个客户端后，即可复制订阅或分享链接。",dyn133:"创建客户端",dyn134:"不限",dyn135:"到期 ",dyn136:")\" title=\"复制分享链接\">复制链接</button>",dyn137:")\" title=\"编辑客户端\">编辑</button>",dyn138:"\\')\" title=\"启用/禁用客户端\">",dyn139:"\\')\" title=\"删除客户端\">删除</button>",dyn140:"复制失败，请手动复制下面的链接",dyn141:"已复制链接",dyn142:"复制失败，请手动复制",dyn143:"确认删除入站 ",dyn144:"？此操作不可撤销，其下的客户端也将被删除。",dyn145:"删除失败：",dyn146:"确认删除客户端 ",dyn147:"删除中...",dyn148:"删除客户端失败",dyn149:"客户端已删除",dyn150:"入站未找到",dyn151:"请填写备注和端口",dyn152:"端口 ",dyn153:" 已被入站 ",dyn154:" 使用",dyn155:"编辑入站失败",dyn156:"入站已更新",dyn157:"开关入站失败",dyn158:"入站 ",dyn159:"已启用",dyn160:"已禁用",dyn161:"客户端未找到",dyn162:"请输入客户端标识",dyn163:"编辑客户端失败",dyn164:"客户端已更新",dyn165:"切换中...",dyn166:"开关客户端失败",dyn167:"客户端 ",dyn168:"确定要重置此客户端的流量数据吗？此操作不可恢复。",dyn169:"重置中...",dyn170:"重置流量失败",dyn171:"流量已重置",dyn172:"请先展开入站再创建客户端",dyn173:"创建客户端失败",dyn174:"客户端创建成功",dyn175:"VLESS + Reality：高性能，推荐优先使用。",dyn176:"VMess + WebSocket + TLS：适合 CDN 反代场景。",dyn177:"Trojan + TLS：兼容性广泛的协议。",dyn178:"Shadowsocks：轻量加密代理。",dyn179:"Hysteria2：基于 QUIC 的 UDP 加速协议；sing-box 1.13 服务端需要 TLS，MiGate 默认使用自签证书。",dyn180:"TUIC：基于 QUIC 的低延迟 UDP 代理，适合弱网环境。",dyn181:"ShadowTLS：将流量伪装成标准 TLS 连接，可绕过深度包检测。",dyn182:"\\')\">重新生成</button>",dyn183:"\\')\">显示/隐藏</button>",dyn184:"密码/密钥",dyn185:"密码",dyn186:"客户端凭据已自动生成为 ",dyn187:"，可以手动修改；不懂时保持默认即可。",dyn188:"创建入站失败",dyn189:"入站创建成功",dyn190:"是",dyn191:"否",dyn192:"无入站",dyn193:"已安装 / 未托管",dyn194:"连接失败",dyn195:"安装",dyn196:"卸载",dyn197:"确认",dyn198:" 核心？这会修改系统服务和二进制文件。",dyn199:"正在",dyn200:" 核心操作执行中，请稍候。",dyn201:"操作失败",dyn202:"完成",dyn203:" 核心已",dyn204:" 核心",dyn205:"失败",dyn206:"请检查系统权限、网络和服务状态。",dyn207:"正在应用",dyn208:"正在写入 xray.json、执行配置校验并尝试重启 Xray 及 sing-box。",dyn209:"\\nSing-box: ✅ 已应用",dyn210:" 个入站)",dyn211:"\\nSing-box: ⏭ 无 sing-box 入站",dyn212:"应用失败",dyn213:"Xray 状态：",dyn214:"应用配置失败",dyn215:"应用完成",dyn216:"配置已应用",dyn217:"请检查 Xray 配置目录、xray 命令和 systemd 服务状态。",dyn218:"加载配置失败",dyn219:"加载中...",dyn220:"暂无日志",dyn221:"加载日志失败",dyn222:"正在写入 sing-box 配置并尝试重启服务。",dyn223:"Sing-box 配置已应用",dyn224:" 个入站）",dyn225:"未知错误",dyn226:"Sing-box 应用失败",dyn227:"请求失败，请检查网络连接和服务状态。",dyn228:"数据库",dyn229:" | 密码已设置",dyn230:" | 无密码",dyn231:"设置不可用",dyn232:"需要在 panel.json 配置文件下运行，或检查配置目录是否已传入。",dyn233:"✓ 已签发",dyn234:"证书：",dyn235:" | 密钥：",dyn236:"待获取（域名已配置）",dyn237:"未配置",dyn238:"请先填写域名和邮箱",dyn239:"签发中…",dyn240:"签发中，请等待…",dyn241:"证书获取成功",dyn242:"签发失败：",dyn243:"签发失败",dyn244:"签发失败：网络错误",dyn245:"获取证书",dyn246:"请输入面板端口",dyn247:"保存设置失败",dyn248:"设置已保存，重启服务后生效",dyn249:"保存设置",dyn250:"确认重启 MiGate 服务？页面将暂时无法访问，重启后自动重试恢复。",dyn251:"重启中…",dyn252:"重启失败",dyn253:"重启服务",dyn254:"正在重启 MiGate 服务…",dyn255:"重启超时，请手动刷新",dyn256:"重启请求失败",dyn257:"<span style=\"color:var(--accent2)\">●</span> 运行中",dyn258:"异常",dyn259:"未运行",dyn260:"非 systemd 环境或服务未安装",dyn261:"不可用",dyn262:"无法查询服务状态",certNotIssued:"未找到已签发的证书，请先在设置页获取证书",certImported:"已导入设置中的证书路径",certStatusError:"无法读取证书状态："},en:{overview:"Overview",inbounds:"Inbounds",outbound:"Outbound",routing:"Routing",settings:"Settings",currentUser:"Current user",loading:"Loading...",logout:"Logout",darkMode:"Dark mode",lightMode:"Light mode",langToggle:"中文",serverResources:"Server resources",cpu:"CPU",memory:"Memory",disk:"Disk",uptime:"Uptime",businessStatus:"Business status",clients:"Clients",totalTraffic:"Total traffic",routingRules:"Routing rules",runningStatus:"Running status",protocolDistribution:"Protocol distribution",coreProtocols:"Core protocols",newInbound:"New inbound",searchInbound:"Search inbound...",defaultSort:"Default sort",byPort:"By port",byProtocol:"By protocol",byClients:"By clients",usedTotal:"Used / total",systemUptime:"System uptime",active:"Active",total:"Total",runningOverview:"Running overview",checking:"Checking",day:"d",hour:"h",minute:"min",panelSettings:"Panel settings",panelSettingsDesc:"Configure panel port, authentication, and certificate settings.",refresh:"Refresh",saveSettings:"Save settings",restart:"Restart",xrayConfig:"Xray config",xrayDesc:"View status, install/uninstall Xray core, and manage configuration.",singboxConfig:"Sing-box config",singboxDesc:"View status, install/uninstall sing-box core, and manage configuration.",preview:"Preview",apply:"Apply",outboundManagement:"Outbound management",outboundDesc:"Manage proxy outbound nodes and test latency.",routingManagement:"Routing management",routingDesc:"Configure domain-based routing rules.",newOutbound:"New outbound",newRoute:"New route",updateNow:"Update now",dyn001:"Session expired, please login again",dyn002:"No inbound configured",dyn003:"Create your first inbound to start accepting connections.",dyn004:"New inbound",dyn005:"View Xray",dyn006:"View Sing-box",dyn007:" clients</span></div>",dyn008:")\">Clients</button>",dyn009:")\" title=\"Edit\">Edit</button>",dyn010:",this)\" title=\"Toggle\">",dyn011:"Disable",dyn012:"Enable",dyn013:")\" title=\"Delete\">Delete</button>",dyn014:"No matching inbounds",dyn015:"Are you sure?",dyn016:"Confirm",dyn017:"Cancel",dyn018:"Protocol",dyn019:"Enabled",dyn020:"Network",dyn021:"Security",dyn022:"Unknown",dyn023:"Not installed",dyn024:"Running",dyn025:"Stopped",dyn026:"Unknown",dyn027:"d ",dyn028:"h",dyn029:"h ",dyn030:"min",dyn031:"Create inbound",dyn032:"Edit inbound",dyn033:"Name",dyn034:"e.g. Main entry",dyn035:"Port",dyn036:")\" title=\"Speed test\">&#9889;</button>",dyn037:")\" title=\"Edit\">&#9998;</button>",dyn038:")\" title=\"Delete\">&#10005;</button>",dyn039:"Delete inbound",dyn040:"Delete this inbound and all its clients?",dyn041:"Delete",dyn042:"Toggle inbound",dyn043:"Enable this inbound?",dyn044:"Disable this inbound?",dyn045:"Confirm",dyn046:"No clients",dyn047:"Add your first client to this inbound.",dyn048:"New client",dyn049:"Create client",dyn050:"Edit client",dyn051:"Email",dyn052:"e.g. user@example.com",dyn053:"UUID",dyn054:"Generate",dyn055:"Traffic limit (bytes, 0=unlimited)",dyn056:"Expiry (UNIX timestamp, 0=never)",dyn057:"Enabled",dyn058:"Create",dyn059:"Save",dyn060:"Delete client",dyn061:"Delete this client?",dyn062:"Delete",dyn063:"Toggle client",dyn064:"Enable this client?",dyn065:"Disable this client?",dyn066:"Confirm",dyn067:"Copied",dyn068:"Failed to copy",dyn069:"No outbound configured",dyn070:"Create your first outbound to enable routing.",dyn071:"New outbound",dyn072:"Create outbound",dyn073:"Edit outbound",dyn074:"Tag",dyn075:"e.g. proxy-1",dyn076:"Type",dyn077:"Address",dyn078:"e.g. proxy.example.com",dyn079:"Port",dyn080:"e.g. 1080",dyn081:"Username",dyn082:"Password",dyn083:"Enabled",dyn084:"Create",dyn085:"Save",dyn086:"Delete outbound",dyn087:"Delete this outbound?",dyn088:"Delete",dyn089:"Toggle outbound",dyn090:"Enable this outbound?",dyn091:"Disable this outbound?",dyn092:"Confirm",dyn093:"Test",dyn094:"Testing...",dyn095:"ms",dyn096:"Timeout",dyn097:"Error",dyn098:"No routing rules",dyn099:"Create your first routing rule.",dyn100:"New route",dyn101:"Create routing rule",dyn102:"Edit routing rule",dyn103:"Priority",dyn104:"Domains (one per line)",dyn105:")\" title=\"Edit\" data-rule-outbound=\"",dyn106:"Outbound tag",dyn107:"e.g. proxy-1",dyn108:"Enabled",dyn109:"Create",dyn110:"Save",dyn111:"Delete rule",dyn112:"Delete this routing rule?",dyn113:"Delete",dyn114:"Toggle rule",dyn115:"Enable this rule?",dyn116:"Disable this rule?",dyn117:"Confirm",dyn118:"Settings updated",dyn119:"Failed to save settings",dyn120:"Light mode",dyn121:"Dark mode",dyn122:"Certificate issued successfully",dyn123:"Failed to issue certificate",dyn124:"Please fill domain and email",dyn125:"Issuing...",dyn126:"Issue certificate",dyn127:"Xray status refreshed",dyn128:"Failed to fetch Xray status",dyn129:")\" class=\"btn-sm\">New client</button>",dyn130:"Failed to fetch Sing-box status",dyn131:"No clients",dyn132:"Add your first client to this inbound.",dyn133:"New client",dyn134:"Never",dyn135:"Expires: ",dyn136:")\" title=\"Copy link\">Copy Link</button>",dyn137:")\" title=\"Edit\">Edit</button>",dyn138:"')\" title=\"Toggle\">",dyn139:"')\" title=\"Delete\">Delete</button>",dyn140:"Please fill all required fields",dyn141:"Creating...",dyn142:"Create",dyn143:"Inbound created",dyn144:"Failed to create inbound",dyn145:"Saving...",dyn146:"Save",dyn147:"Inbound updated",dyn148:"Failed to update inbound",dyn149:"Deleting...",dyn150:"Delete",dyn151:"Inbound deleted",dyn152:"Failed to delete inbound",dyn153:"Inbound toggled",dyn154:"Failed to toggle inbound",dyn155:"Please fill all required fields",dyn156:"Creating...",dyn157:"Create",dyn158:"Client created",dyn159:"Failed to create client",dyn160:"Saving...",dyn161:"Save",dyn162:"Client updated",dyn163:"Failed to update client",dyn164:"Deleting...",dyn165:"Delete",dyn166:"Client deleted",dyn167:"Failed to delete client",dyn168:"Client toggled",dyn169:"Failed to toggle client",dyn170:"Please fill all required fields",dyn171:"Creating...",dyn172:"Create",dyn173:"Outbound created",dyn174:"Failed to create outbound",dyn175:"Saving...",dyn176:"Save",dyn177:"Outbound updated",dyn178:"Failed to update outbound",dyn179:"Deleting...",dyn180:"Delete",dyn181:"Outbound deleted",dyn182:"\\')\">Regenerate</button>",dyn183:"\\')\">Show/Hide</button>",dyn184:"Failed to toggle outbound",dyn185:"Testing...",dyn186:"Test",dyn187:"Latency: ",dyn188:"ms",dyn189:"Timeout",dyn190:"Error: ",dyn191:"Please fill all required fields",dyn192:"Creating...",dyn193:"Create",dyn194:"Route created",dyn195:"Failed to create route",dyn196:"Saving...",dyn197:"Save",dyn198:"Route updated",dyn199:"Failed to update route",dyn200:"Deleting...",dyn201:"Delete",dyn202:"Route deleted",dyn203:"Failed to delete route",dyn204:"Route toggled",dyn205:"Failed to toggle route",dyn206:"Loading inbounds...",dyn207:"Loading outbounds...",dyn208:"Loading routes...",dyn209:"Xray config preview",dyn210:"Xray logs",dyn211:"Loading...",dyn212:"Empty config",dyn213:"Failed to load config",dyn214:"Loading logs...",dyn215:"No logs",dyn216:"Failed to load logs",dyn217:"Sing-box config preview",dyn218:"Sing-box logs",dyn219:"Loading logs...",dyn220:"No logs",dyn221:"Failed to load logs",dyn222:"Installing...",dyn223:"Install",dyn224:"Core installed",dyn225:"Failed to install core",dyn226:"Uninstalling...",dyn227:"Uninstall",dyn228:"Database: ",dyn229:", password enabled",dyn230:", no password",dyn231:"Failed to load settings",dyn232:"Cannot reach settings API",dyn233:"Issued",dyn234:"Cert: ",dyn235:", Key: ",dyn236:"Domain configured, not issued",dyn237:"Not configured",dyn238:"Please fill domain and email",dyn239:"Issuing...",dyn240:"Issue certificate",dyn241:"Certificate issued",dyn242:"Failed to issue certificate",dyn243:"Checking for updates...",dyn244:"Update now",dyn245:"Update started, panel may restart",dyn246:"Failed to start update",dyn247:"Service status: <span style=\\\"font-weight:600;color:var(--accent2)\\\">●</span> Running",dyn248:"Service status: <span style=\\\"font-weight:600\\\">●</span> Stopped",dyn249:"Service status: Unknown",dyn250:"Active inbound clients",dyn251:"inbounds enabled",dyn252:"clients active",dyn253:"No enabled inbounds",dyn254:"No active clients",dyn255:"All inbounds disabled",dyn256:"No clients configured",dyn257:"Service status: <span style=\\\"font-weight:600;color:var(--accent2)\\\">●</span> Running",dyn258:"Error",dyn259:"Not running",dyn260:"Non-systemd environment or service not installed",dyn261:"Unavailable",dyn262:"Unable to query service status",certNotIssued:"No certificate issued yet, please get one in settings first",certImported:"Certificate imported from settings",certStatusError:"Unable to read certificate status: "}};
let currentLang=((document.cookie.match(/migate_lang=([^;]+)/)||[])[1]||'zh');
function t(k){return i18n[currentLang][k]||k}
function toggleLang(){currentLang=currentLang==='zh'?'en':'zh';document.cookie='migate_lang='+currentLang+';path=/;max-age=31536000';location.reload()}
const staticEnMap={"新增入站":"New inbound","名称":"Name","例如 主入口":"e.g. Main entry","只需要填写名称，其他参数会自动生成并可继续手动修改。":"Only a name is required. Other parameters are generated automatically and can still be edited.","协议类型":"Protocol type","选择核心入站协议，自动配置传输方式与安全层。":"Select the core inbound protocol; transport and security are configured automatically.","监听端口":"Listen port","例如 443":"e.g. 443","建议使用未被占用的公网端口。":"Use an unused public port.","参数类型 / 传输方式":"Parameter type / transport","只要选定参数类型，其余如 UUID、密码、短 ID、证书路径等会随机填充并可手动修改。":"After selecting a parameter type, UUIDs, passwords, short IDs, and certificate paths are generated and remain editable.","安全层":"Security layer","REALITY/TLS 会展开证书或伪装目标字段。":"REALITY/TLS expands certificate or camouflage target fields.","入站 UUID / Shadowsocks 密码":"Inbound UUID / Shadowsocks password","自动生成；Shadowsocks 会作为单用户密码/密钥":"Auto-generated; Shadowsocks uses this as the single-user password/key","重新生成":"Regenerate","显示/隐藏":"Show/hide","普通协议可保持默认；Shadowsocks 单用户模式会使用这里的值作为密码/密钥。":"Keep defaults for common protocols; Shadowsocks single-user mode uses this as the password/key.","WebSocket 设置":"WebSocket settings","适合 CDN、反向代理或路径分流场景。":"Suitable for CDN, reverse proxy, or path-based routing.","WS Path (默认 /)":"WS Path (default /)","WS Host (可选)":"WS Host (optional)","路径和 Host 用于 CDN 或反代场景。":"Path and Host are used for CDN or reverse-proxy scenarios.","gRPC 设置":"gRPC settings","用于 gRPC 传输的服务名，客户端需保持一致。":"Service name for gRPC transport; clients must match it.","XHTTP 设置":"XHTTP settings","配置 XHTTP 路径与上传模式。":"Configure XHTTP path and upload mode.","XHTTP Path (默认 /)":"XHTTP Path (default /)","REALITY 设置":"REALITY settings","填写伪装目标、SNI 与短 ID，避免与客户端参数不一致。":"Set camouflage target, SNI, and short ID to match client parameters.","目标 (dest)":"Target (dest)","ServerNames (逗号分隔)":"ServerNames (comma-separated)","ShortId (可选)":"ShortId (optional)","Shadowsocks 设置":"Shadowsocks settings","选择客户端支持的加密方法。":"Choose an encryption method supported by the client.","Hysteria2 设置":"Hysteria2 settings","Hysteria2 使用 QUIC 传输；Hysteria2 在 sing-box v1.13 需要 TLS；MiGate 会默认使用自签证书，以下为可选参数。":"Hysteria2 uses QUIC; sing-box v1.13 requires TLS. MiGate uses a self-signed certificate by default. The fields below are optional.","上行速率 mbps (0=不限) 默认 0":"Upload mbps (0=unlimited), default 0","下行速率 mbps (0=不限) 默认 0":"Download mbps (0=unlimited), default 0","混淆类型 (如 salamander, 可选)":"Obfuscation type (e.g. salamander, optional)","混淆密码（自动随机，可选）":"Obfuscation password (auto-random, optional)","端口跳跃范围 mport (如 40000-50000, 可选)":"Port hopping range mport (e.g. 40000-50000, optional)","TLS 默认自动启用。速率限制为 0 表示不限制；混淆类型默认 salamander，混淆密码会自动随机生成；端口跳跃会写入分享链接的 mport 参数。":"TLS is enabled by default. A speed limit of 0 means unlimited; obfs defaults to salamander, the obfs password is generated automatically, and port hopping is written to the share link as mport.","TUIC 设置":"TUIC settings","TUIC 基于 QUIC 的低延迟 UDP 代理。":"TUIC is a QUIC-based low-latency UDP proxy.","BBR (推荐)":"BBR (recommended)","启用 0-RTT 握手":"Enable 0-RTT handshake","拥塞控制和 0-RTT 握手可优化延迟。":"Congestion control and 0-RTT can improve latency.","WireGuard 设置":"WireGuard settings","WireGuard 简单高效的 VPN 协议。":"WireGuard is a simple and efficient VPN protocol.","私钥 (PrivateKey) 必填":"Private key (PrivateKey), required","生成密钥":"Generate key","本地地址 (如 10.0.0.1/24) 必填":"Local address (e.g. 10.0.0.1/24), required","客户端公钥 (PublicKey) 必填":"Client public key (PublicKey), required","允许的 IP (默认 0.0.0.0/0, ::/0)":"Allowed IPs (default 0.0.0.0/0, ::/0)","客户端 Endpoint (可选)":"Client Endpoint (optional)","预共享密钥 (PreSharedKey, 可选)":"Preshared key (PreSharedKey, optional)","MTU (默认 1420)":"MTU (default 1420)","WireGuard 需要服务器端生成私钥/公钥对。":"WireGuard requires a server-side private/public key pair.","ShadowTLS 设置":"ShadowTLS settings","ShadowTLS 将流量伪装成标准 TLS 连接。":"ShadowTLS disguises traffic as standard TLS connections.","密码 (Password)":"Password","v3 (推荐)":"v3 (recommended)","注意：ShadowTLS 复用 TLS 设置中的 SNI 作为 handshake_server_name。":"Note: ShadowTLS reuses the SNI from TLS settings as handshake_server_name.","TLS 设置":"TLS settings","填写证书和私钥路径，应用前会交给 Xray 校验。":"Enter certificate and private-key paths. Xray validates them before apply.","TLS 证书路径 (如 /etc/.../fullchain.pem)":"TLS certificate path (e.g. /etc/.../fullchain.pem)","TLS 密钥路径 (如 /etc/.../privkey.key)":"TLS key path (e.g. /etc/.../privkey.key)","SNI / ServerName (可选，留空则自动匹配)":"SNI / ServerName (optional, blank for auto-match)","指纹 (默认不指定)":"Fingerprint (default unset)","ALPN (逗号分隔，如 h2,http/1.1)":"ALPN (comma-separated, e.g. h2,http/1.1)","SNI 与指纹用于 TLS 握手指纹伪装；ALPN 用于协议协商，留空为默认。":"SNI and fingerprint are used for TLS handshake camouflage; ALPN is used for protocol negotiation and defaults when blank.","同时添加首个客户端（推荐）":"Add the first client at the same time (recommended)","客户端标识 (如 user01 或 sam@example.com)":"Client identifier (e.g. user01 or sam@example.com)","客户端 UUID / 密码 / 密钥（自动生成，可修改）":"Client UUID / password / key (auto-generated, editable)","流量上限，单位字节；0=无限":"Traffic limit in bytes; 0=unlimited","客户端凭据会自动生成。VLESS/VMess 使用 UUID，Trojan/Shadowsocks/Hysteria2 使用密码或密钥；不懂时保持默认即可。":"Client credentials are generated automatically. VLESS/VMess use UUID; Trojan/Shadowsocks/Hysteria2 use password or key. Keep defaults if unsure.","取消":"Cancel","保存入站":"Save inbound","创建客户端":"Create client","客户端标识":"Client identifier","例如 user01":"e.g. user01","用于区分设备或用户，也会出现在分享链接备注中。":"Used to distinguish devices or users, and shown in share-link remarks.","客户端 UUID / 密码 / 密钥":"Client UUID / password / key","自动生成，可手动修改":"Auto-generated, editable","VLESS/VMess 使用 UUID；Trojan、Shadowsocks、Hysteria2 可当作密码或密钥，不懂时保持默认即可。":"VLESS/VMess use UUID; Trojan, Shadowsocks, and Hysteria2 can use this as password or key. Keep defaults if unsure.","流量限额":"Traffic limit","0 = 不限":"0 = unlimited","单位为字节；留空或 0 表示不限流量。":"Unit is bytes; blank or 0 means unlimited.","到期时间":"Expiry time","到期后订阅会返回明确的过期提示。":"After expiry, subscriptions return a clear expired notice.","编辑入站":"Edit inbound","入站备注":"Inbound remark","备注":"Remark","用于列表识别，建议使用节点地区或用途。":"Used in lists; region or usage is recommended.","协议":"Protocol","保存后会影响客户端链接格式。":"Affects client link format after saving.","端口":"Port","1-65535，需确保防火墙已放行。":"1-65535; make sure the firewall allows it.","传输":"Transport","切换后会显示对应高级字段。":"Related advanced fields appear after switching.","安全":"Security","TLS/REALITY 会显示证书或伪装参数。":"TLS/REALITY shows certificate or camouflage parameters.","用于 REALITY 伪装目标、SNI 和短 ID。":"Used for REALITY camouflage target, SNI, and short ID.","Shadowsocks 加密":"Shadowsocks encryption","Hysteria2 上行/下行":"Hysteria2 upload/download","TUIC 拥塞控制":"TUIC congestion control","ShadowTLS 密码":"ShadowTLS password","TLS 证书":"TLS certificate","保存":"Save","编辑客户端":"Edit client","启用状态":"Enabled status","已启用":"Enabled","当前流量":"Current traffic","↑ 上行:":"↑ Upload:","↓ 下行:":"↓ Download:","总计:":"Total:","重置流量":"Reset traffic","点击重置会将上下行数据清零，不可恢复。":"Reset clears upload and download counters and cannot be undone.","过期时间":"Expiry time","留空表示不过期。":"Leave blank for no expiry.","展开菜单":"Expand menu","轻量单二进制面板，专注协议、客户端与双核心管理。":"Lightweight single-binary panel for protocols, clients, and dual-core management.","当前账号":"Current account","移动端导航栏":"Mobile navigation","概览指标":"Overview metrics","服务器资源占用":"Server resource usage","当前系统 CPU 占用":"Current system CPU usage","根分区已用 / 总量":"Root partition used / total","业务状态":"Business status","所有客户端上行+下行累计":"Total upload + download across all clients","已启用 / 总计":"Enabled / total","正在读取入站、客户端与 Xray 状态...":"Reading inbound, client, and Xray status...","Reality / TLS 入站":"Reality / TLS inbound","WebSocket / TLS 兼容":"WebSocket / TLS compatible","TLS 节点支持":"TLS node support","轻量转发协议":"Lightweight forwarding protocol","搜索入站...":"Search inbounds...","导入 SOCKS5 地址池":"Import SOCKS5 pool","一键测速":"Batch speed test","提示":"Tip","启用规则后系统会自动重写 Xray 配置文件并重启服务。可用的域名格式包括":"After enabling rules, the system rewrites the Xray config and restarts the service automatically. Supported domain formats include","状态":"Status","版本":"Version","内存":"Memory","运行时长":"Uptime","活跃连接":"Active connections","托管服务":"Managed service","服务":"Service","配置路径":"Config path","配置操作":"Config actions","应用、预览与刷新统一集中在右侧操作区。":"Apply, preview, and refresh are grouped in the action area on the right.","安装核心":"Install core","卸载核心":"Uninstall core","查看日志":"View logs","Xray 配置预览":"Xray config preview","Xray 运行日志":"Xray runtime logs","Sing-box 配置预览":"Sing-box config preview","Sing-box 运行日志":"Sing-box runtime logs","面板端口":"Panel port","保存后需要重启 MiGate 服务才会切换监听端口。":"Restart MiGate after saving to switch the listen port.","登录用户名":"Login username","与密码同时配置时启用面板认证。":"Panel authentication is enabled when username and password are both configured.","登录密码":"Login password","留空不修改":"Leave blank to keep unchanged","留空会保留现有密码，不会清空配置。":"Leaving it blank keeps the current password and does not clear config.","Xray 配置目录":"Xray config directory","例如 /usr/local/migate":"e.g. /usr/local/migate","MiGate 会在该目录写入 xray.json。":"MiGate writes xray.json in this directory.","MiGate 服务状态":"MiGate service status","检查中...":"Checking...","刷新状态":"Refresh status","Web 基础路径":"Web base path","例如 /":"e.g. /","默认使用根路径；反代到子路径时再修改。":"Root path is used by default; change this only when reverse-proxying under a subpath.","TLS 证书（Let's Encrypt）":"TLS certificate (Let's Encrypt)","配置域名后可通过 acme.sh 自动获取 Let's Encrypt 证书，证书文件保存在面板配置目录下。":"After setting a domain, acme.sh can obtain a Let's Encrypt certificate automatically. Certificate files are saved under the panel config directory.","域名":"Domain","例如 example.com":"e.g. example.com","邮箱":"Email","证书状态":"Certificate status","未获取":"Not obtained","获取证书":"Get certificate","设置操作":"Settings actions","保存配置后按需重启 MiGate 服务。":"Restart MiGate as needed after saving configuration.","从公开地址池选择地区，MiGate 会自动测速并导入为出站 SOCKS5。":"Choose a region from the public pool; MiGate tests latency and imports it as an outbound SOCKS5 proxy.","选择目标地区":"Select target region","-- 请选择地区 --":"-- Select region --","可用 SOCKS5":"Available SOCKS5","请选择地区后显示对应 SOCKS5":"Select a region to show SOCKS5 proxies","确定":"OK","新建出站":"New outbound","出站标识":"Outbound tag","例如 my-socks-proxy":"e.g. my-socks-proxy","唯一标识，用于 Xray 路由规则中的 tag 引用。":"Unique identifier used as the tag in Xray routing rules.","可选，留空使用标识":"Optional, blank uses the tag","地址":"Address","IP 或域名":"IP or domain","认证":"Auth","用户名（可选）":"Username (optional)","密码（可选）":"Password (optional)","创建":"Create","编辑出站":"Edit outbound","新建路由规则":"New routing rule","目标出站 *":"Target outbound *","-- 选择出站 --":"-- Select outbound --","匹配此条件时转发到哪个出站。":"Forward to this outbound when the condition matches.","域名匹配":"Domain match","例如 geosite:netflix 或 google.com":"e.g. geosite:netflix or google.com","留空表示匹配所有域名。支持 geosite: 和 regex: 前缀。":"Blank matches all domains. geosite: and regex: prefixes are supported.","来源入站":"Source inbound","留空 = 所有入站":"Blank = all inbounds","协议匹配":"Protocol match","例如 dns, bittorrent":"e.g. dns, bittorrent","编辑路由规则":"Edit routing rule","留空表示匹配所有域名。":"Blank matches all domains."};
function applyStaticI18n(){if(currentLang!=='en')return;var attrs=['placeholder','title','aria-label'];function tr(v){return staticEnMap[v]||v}document.querySelectorAll('body *').forEach(function(el){attrs.forEach(function(attr){var v=el.getAttribute(attr);if(v&&staticEnMap[v])el.setAttribute(attr,tr(v))});el.childNodes.forEach(function(node){if(node.nodeType!==3)return;var raw=node.nodeValue;var trimmed=raw.trim();if(!trimmed||!staticEnMap[trimmed])return;node.nodeValue=raw.replace(trimmed,staticEnMap[trimmed])})})}
document.addEventListener('DOMContentLoaded', applyStaticI18n)
  </script>
</head>
<body>
  <div id="toast-container"></div>
  <div id="confirm-overlay" class="modal-overlay hidden" onclick="if(event.target===this)rejectConfirm()">
    <div id="confirm-dialog">
      <p id="confirm-msg"></p>
      <div class="actions">
        <button class="btn-cancel" onclick="rejectConfirm()"><script>document.write(t('cancel'))</script></button>
        <button class="btn-confirm" onclick="resolveConfirm()"><script>document.write(t('confirm'))</script></button>
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
            <div class="advanced-fieldset-copy">Hysteria2 使用 QUIC 传输；Hysteria2 在 sing-box v1.13 需要 TLS；MiGate 会默认使用自签证书，以下为可选参数。</div>
            <input name="hy2_up_mbps" type="number" min="0" placeholder="上行速率 mbps (0=不限) 默认 0">
            <input name="hy2_down_mbps" type="number" min="0" placeholder="下行速率 mbps (0=不限) 默认 0">
            <input name="hy2_obfs" placeholder="混淆类型 (如 salamander, 可选)">
            <div class="inline-field-tools"><input id="inbound-hy2-obfs-password" name="hy2_obfs_password" type="password" placeholder="混淆密码（自动随机，可选）"><button type="button" class="btn-mini" onclick="regenerateField('inbound-hy2-obfs-password')">重新生成</button><button type="button" class="btn-mini" onclick="toggleSecretField('inbound-hy2-obfs-password')">显示/隐藏</button></div>
            <input name="hy2_mport" placeholder="端口跳跃范围 mport (如 40000-50000, 可选)">
            <p class="field-help">TLS 默认自动启用。速率限制为 0 表示不限制；混淆类型默认 salamander，混淆密码会自动随机生成；端口跳跃会写入分享链接的 mport 参数。</p>
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
          <button id="create-client-submit-btn" type="submit" class="btn-modal-primary" onclick="saveCreateClient()">创建客户端</button>
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
            <option value="tuic">TUIC</option>
            <option value="shadowtls">ShadowTLS</option>
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
            <div class="advanced-fieldset-copy">Hysteria2 使用 QUIC 传输；Hysteria2 在 sing-box v1.13 需要 TLS；MiGate 会默认使用自签证书，以下为可选参数。</div>
            <label class="field-label" for="ei-hy2-up">Hysteria2 上行/下行</label>
            <input id="ei-hy2-up" type="number" min="0" placeholder="上行速率 mbps (0=不限) 默认 0">
            <input id="ei-hy2-down" type="number" min="0" placeholder="下行速率 mbps (0=不限) 默认 0">
            <input id="ei-hy2-obfs" placeholder="混淆类型 (如 salamander, 可选)">
            <div class="inline-field-tools"><input id="ei-hy2-obfs-password" type="password" placeholder="混淆密码（自动随机，可选）"><button type="button" class="btn-mini" onclick="regenerateField('ei-hy2-obfs-password')">重新生成</button><button type="button" class="btn-mini" onclick="toggleSecretField('ei-hy2-obfs-password')">显示/隐藏</button></div>
            <input id="ei-hy2-mport" placeholder="端口跳跃范围 mport (如 40000-50000, 可选)">
            <p class="field-help">TLS 默认自动启用。速率限制为 0 表示不限制；混淆类型默认 salamander，混淆密码会自动随机生成；端口跳跃会写入分享链接的 mport 参数。</p>
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
            <div style="display:flex;gap:8px;align-items:center">
              <input id="ei-tls-cert-file" placeholder="TLS 证书路径 (如 /etc/.../fullchain.pem)" style="flex:1">
              <button type="button" class="secondary" onclick="importSettingsCert()" style="white-space:nowrap">导入现有证书</button>
            </div>
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
            <button id="reset-client-traffic-btn" type="button" class="btn-confirm" onclick="resetClientTraffic()">重置流量</button>
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
          <button id="edit-client-submit-btn" type="submit" class="btn-modal-primary" onclick="saveEditClient()">保存</button>
        </div>
      </form>
    </div>
  </div>

  <div class="app-shell">
    <button id="sidebar-toggle" onclick="toggleSidebar()" aria-label="展开菜单">☰</button>
    <aside class="sidebar">
      <div class="brand">MiGate</div>
      <div class="subtitle">轻量单二进制面板，专注协议、客户端与双核心管理。</div>
      <nav>
        <a class="active" href="#"><script>document.write(t('overview'))</script></a>
        <a href="#inbounds"><script>document.write(t('inbounds'))</script></a>
        <a href="#outbound"><script>document.write(t('outbound'))</script></a>
        <a href="#routing"><script>document.write(t('routing'))</script></a>
        <a href="#xray">Xray</a>
        <a href="#singbox">Sing-box</a>
        <a href="#settings"><script>document.write(t('settings'))</script></a>
      </nav>
      <div class="account-panel" aria-label="当前账号">
        <div class="account-label"><script>document.write(t('currentUser'))</script></div>
        <div id="current-username" class="account-name"><script>document.write(t('loading'))</script></div>
        <div class="account-actions">
          <button id="logout-button" class="secondary" onclick="logoutPanel()"><script>document.write(t('logout'))</script></button>
          <button id="theme-toggle" class="secondary" onclick="toggleTheme()"><script>document.write(t('darkMode'))</script></button>
          <button id="lang-toggle" class="secondary" onclick="toggleLang()"><script>document.write(t('langToggle'))</script></button>
        </div>
      </div>
    </aside>
    <div id="sidebar-overlay" onclick="closeSidebar()"></div>
    <main>
      <div class="mobile-topbar" aria-label="移动端导航栏">
        <button class="mobile-menu-button" onclick="toggleSidebar()" aria-label="展开菜单">☰</button>
        <div class="mobile-title">MiGate</div>
      </div>
      <section id="overview" class="overview-grid" aria-label="概览指标">
        <div id="version-banner" class="version-banner" style="display:none; grid-column:1 / -1"></div>
        <div class="overview-section" aria-label="服务器资源占用">
          <div class="overview-section-title"><script>document.write(t('serverResources'))</script></div>
        </div>
        <div class="card panel"><div><script>document.write(t('cpu'))</script></div><div id="server-cpu" class="metric">--</div><p>当前系统 CPU 占用</p></div>
        <div class="card panel"><div><script>document.write(t('memory'))</script></div><div id="server-memory" class="metric">--</div><p id="server-memory-detail"><script>document.write(t('usedTotal'))</script></p></div>
        <div class="card panel"><div><script>document.write(t('disk'))</script></div><div id="server-disk" class="metric">--</div><p id="server-disk-detail">根分区已用 / 总量</p></div>
        <div class="card panel"><div><script>document.write(t('uptime'))</script></div><div id="server-uptime" class="metric">--</div><p><script>document.write(t('systemUptime'))</script></p></div>
        <div class="overview-section" aria-label="业务状态">
          <div class="overview-section-title"><script>document.write(t('businessStatus'))</script></div>
        </div>
        <div class="compact-metric-card"><div><script>document.write(t('inbounds'))</script></div><div id="inbound-count" class="metric">0</div><p>VLESS / VMess / Trojan / Shadowsocks</p></div>
        <div class="compact-metric-card"><div><script>document.write(t('clients'))</script></div><div id="client-count" class="metric">0</div><p><script>document.write(t('active'))</script> / <script>document.write(t('total'))</script></p></div>
        <div class="compact-metric-card"><div><script>document.write(t('totalTraffic'))</script></div><div id="total-traffic" class="metric">0 B</div><p>所有客户端上行+下行累计</p></div>
        <div class="compact-metric-card"><div><script>document.write(t('outbound'))</script></div><div id="outbound-stats" class="metric">0</div><p>已启用 / 总计</p></div>
        <div class="compact-metric-card"><div><script>document.write(t('routingRules'))</script></div><div id="routing-stats" class="metric">0</div><p>已启用 / 总计</p></div>
        <div class="compact-metric-card"><div>Xray</div><div id="xray-status-metric" class="metric"><script>document.write(t('checking'))</script></div><p><script>document.write(t('runningStatus'))</script></p></div>
        <div class="compact-metric-card"><div>Sing-box</div><div id="singbox-status-metric" class="metric"><script>document.write(t('checking'))</script></div><p>Hysteria2 / TUIC / ShadowTLS</p></div>
        <div class="overview-insights">
          <div class="overview-card">
            <div class="overview-card-title"><script>document.write(t('runningOverview'))</script></div>
            <div id="overview-health-summary" class="muted">正在读取入站、客户端与 Xray 状态...</div>
            <div id="overview-active-summary" class="overview-pill"><script>document.write(t('activeClients'))</script> 0 / 0</div>
          </div>
          <div class="overview-card">
            <div class="overview-card-title"><script>document.write(t('protocolDistribution'))</script></div>
            <div id="overview-protocol-breakdown" class="protocol-breakdown"></div>
          </div>
        </div>
      </section>
      <section id="inbounds" class="card panel">
        <h2 class="section-heading"><script>document.write(t('coreProtocols'))</script></h2>
        <div class="protocols">
          <div class="protocol"><strong>VLESS</strong><span>Reality / TLS 入站</span></div>
          <div class="protocol"><strong>VMess</strong><span>WebSocket / TLS 兼容</span></div>
          <div class="protocol"><strong>Trojan</strong><span>TLS 节点支持</span></div>
          <div class="protocol"><strong>Shadowsocks</strong><span>轻量转发协议</span></div>
        </div>
        <div class="actions">
          <button onclick="openCreateInbound()"><script>document.write(t('newInbound'))</script></button>
          <button class="secondary" onclick="navigateTo('outbound')"><script>document.write(t('outbound'))</script></button>
          <input id="inbound-search" type="text" placeholder="搜索入站..." class="search-input" oninput="filterInbounds()">
          <select id="inbound-sort" class="sort-select" onchange="sortInbounds()">
            <option value="id"><script>document.write(t('defaultSort'))</script></option>
            <option value="port"><script>document.write(t('byPort'))</script></option>
            <option value="protocol"><script>document.write(t('byProtocol'))</script></option>
            <option value="clients"><script>document.write(t('byClients'))</script></option>
          </select>
        </div>
        <div id="inbound-list" class="list muted"><script>document.write(t('loadingInbounds'))</script></div>
      </section>
      <section id="outbound" class="card panel">
        <h2 class="section-title"><script>document.write(t('outboundManagement'))</script></h2>
        <p class="muted" style="margin-bottom:16px"><script>document.write(t('outboundDesc'))</script></p>
        <div class="actions">
          <button onclick="openCreateOutbound()"><script>document.write(t('newOutbound'))</script></button>
          <button class="secondary" onclick="openSocks5PoolDialog()">导入 SOCKS5 地址池</button>
          <button class="secondary" onclick="batchSpeedTest()">一键测速</button>
        </div>
        <div id="outbound-list" class="list muted"><script>document.write(t('loadingOutbounds'))</script></div>
      </section>
      <section id="routing" class="card panel">
        <h2 class="section-title"><script>document.write(t('routingManagement'))</script></h2>
        <p class="muted" style="margin-bottom:16px"><script>document.write(t('routingDesc'))</script></p>
        <div class="actions">
          <button onclick="openCreateRoutingRule()"><script>document.write(t('newRoute'))</script></button>
        </div>
        <div id="routing-rule-list" class="list muted"><script>document.write(t('loadingRoutes'))</script></div>
        <div class="notice" style="margin-top:16px">
          <div class="notice-title">提示</div>
          <div class="notice-copy">启用规则后系统会自动重写 Xray 配置文件并重启服务。可用的域名格式包括 <code>google.com</code>（精确域名）、<code>geosite:netflix</code>（地理位置组）、<code>regex:.*\.youtube\.com$</code>（正则）。</div>
        </div>
      </section>
      <section id="xray" class="card panel">
        <h2 class="section-title"><script>document.write(t('xrayConfig'))</script></h2>
        <p class="muted" style="margin-bottom:16px"><script>document.write(t('xrayDesc'))</script></p>
        <div class="xray-status-panel">
          <div><strong>状态</strong>：<span id="xray-status">未知</span></div>
          <div><strong>版本</strong>：<span id="xray-version">-</span></div>
          <div><strong>内存</strong>：<span id="xray-memory">-</span></div>
          <div><strong>运行时长</strong>：<span id="xray-uptime">-</span></div>
          <div><strong>活跃连接</strong>：<span id="xray-connections">-</span></div>
          <div><strong>托管服务</strong>：<span id="xray-managed">-</span></div>
          <div><strong>服务</strong>：<span id="xray-service">xray</span></div>
          <div><strong>配置路径</strong>：<span id="xray-config-path">-</span></div>
        </div>
        <div class="action-toolbar xray-toolbar">
          <div class="toolbar-copy">
            <strong>配置操作</strong>
            <span>应用、预览与刷新统一集中在右侧操作区。</span>
          </div>
          <div class="toolbar-actions">
            <button onclick="fetchXrayStatus()"><script>document.write(t('refresh'))</script></button>
            <button class="secondary" onclick="installXrayCore()">安装核心</button>
            <button class="danger" onclick="uninstallXrayCore()">卸载核心</button>
            <button class="secondary" onclick="previewXrayConfig()"><script>document.write(t('preview'))</script></button>
            <button class="secondary" onclick="applyXrayConfig()"><script>document.write(t('apply'))</script></button>
            <button class="secondary" onclick="loadXrayLogs()">查看日志</button>
          </div>
        </div>
        <div id="xray-result" class="notice-slot"></div>
        <div id="xray-config-preview" class="list muted" style="margin-top:12px;display:none"><div class="xray-preview-header"><span class="muted" style="font-weight:600">Xray 配置预览</span><button class="icon-btn" onclick="closeXrayConfig()" title="关闭" style="font-size:12px">✕</button></div><pre id="xray-config-json" class="xray-preview-pre"></pre></div>
        <div id="xray-logs-preview" class="list muted" style="margin-top:12px;display:none"><div class="xray-preview-header"><span class="muted" style="font-weight:600">Xray 运行日志</span><button class="icon-btn" onclick="closeXrayLogs()" title="关闭" style="font-size:12px">✕</button></div><pre id="xray-logs-text" class="xray-preview-pre mono"></pre></div>
      </section>
      <section id="singbox" class="card panel">
        <h2 class="section-title"><script>document.write(t('singboxConfig'))</script></h2>
        <p class="muted" style="margin-bottom:16px"><script>document.write(t('singboxDesc'))</script></p>
        <div class="xray-status-panel">
          <div><strong>状态</strong>：<span id="singbox-status">未知</span></div>
          <div><strong>版本</strong>：<span id="singbox-version">-</span></div>
          <div><strong>内存</strong>：<span id="singbox-memory">-</span></div>
          <div><strong>运行时长</strong>：<span id="singbox-uptime">-</span></div>
          <div><strong>活跃连接</strong>：<span id="singbox-connections">-</span></div>
          <div><strong>托管服务</strong>：<span id="singbox-managed">sing-box</span></div>
          <div><strong>配置路径</strong>：<span id="singbox-config-path">/etc/sing-box/config.json</span></div>
        </div>
        <div class="action-toolbar xray-toolbar">
          <div class="toolbar-copy">
            <strong>配置操作</strong>
            <span>应用、预览与刷新统一集中在右侧操作区。</span>
          </div>
          <div class="toolbar-actions">
            <button onclick="fetchSingboxStatus()"><script>document.write(t('refresh'))</script></button>
            <button class="secondary" onclick="installSingboxCore()">安装核心</button>
            <button class="danger" onclick="uninstallSingboxCore()">卸载核心</button>
            <button class="secondary" onclick="previewSingboxConfig()"><script>document.write(t('preview'))</script></button>
            <button class="secondary" onclick="applySingboxConfig()"><script>document.write(t('apply'))</script></button>
            <button class="secondary" onclick="loadSingboxLogs()">查看日志</button>
          </div>
        </div>
        <div id="singbox-result" class="notice-slot"></div>
        <div id="singbox-config-preview" class="list muted" style="margin-top:12px;display:none"><div class="xray-preview-header"><span class="muted" style="font-weight:600">Sing-box 配置预览</span><button class="icon-btn" onclick="closeSingboxConfig()" title="关闭" style="font-size:12px">✕</button></div><pre id="singbox-config-json" class="xray-preview-pre"></pre></div>
        <div id="singbox-logs-preview" class="list muted" style="margin-top:12px;display:none"><div class="xray-preview-header"><span class="muted" style="font-weight:600">Sing-box 运行日志</span><button class="icon-btn" onclick="closeSingboxLogs()" title="关闭" style="font-size:12px">✕</button></div><pre id="singbox-logs-text" class="xray-preview-pre mono"></pre></div>
      </section>
      <section id="settings" class="card panel">
        <h2 class="section-title"><script>document.write(t('panelSettings'))</script></h2>
        <p class="muted" style="margin-bottom:16px"><script>document.write(t('panelSettingsDesc'))</script></p>
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
              <button type="button" class="secondary" onclick="loadSettings()"><script>document.write(t('refresh'))</script></button>
              <button type="button" class="secondary" id="update-button" onclick="updateMiGate()"><script>document.write(t('updateNow'))</script></button>
              <button type="submit" onclick="saveSettings()"><script>document.write(t('saveSettings'))</script></button>
              <button type="button" class="danger" onclick="restartService()"><script>document.write(t('restart'))</script></button>
            </div>
          </div>
        </form>
        <div id="settings-status" class="notice-slot"></div>
      </section>
    <!-- SOCKS5 pool dialog -->
    <div id="socks5-pool-dialog" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeModal()">
      <div class="modal-content" style="max-width:920px;width:min(920px,96vw)">
        <div class="modal-header">
          <div>
            <h3 class="modal-title">导入 SOCKS5 地址池</h3>
            <p class="field-help" style="margin:4px 0 0">从公开地址池选择地区，MiGate 会自动测速并导入为出站 SOCKS5。</p>
          </div>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <div class="socks5-pool-layout">
          <div id="socks5-pool-detail" class="socks5-pool-detail-card"></div>
          <div class="socks5-pool-list-panel">
            <div class="field-group">
              <label class="field-label" for="socks5-pool-region">选择目标地区</label>
              <select id="socks5-pool-region" onchange="onSocks5PoolRegionChange()">
                <option value="">-- 请选择地区 --</option>
              </select>
            </div>
            <div class="field-group" style="flex:1;min-height:0;min-width:0">
              <label class="field-label">可用 SOCKS5</label>
              <div id="socks5-pool-list" class="list muted socks5-pool-list">请选择地区后显示对应 SOCKS5</div>
            </div>
          </div>
        </div>
        <div class="modal-footer socks5-pool-footer">
          <button class="secondary" onclick="closeModal()">取消</button>
          <button id="socks5-pool-confirm-btn" onclick="confirmSocks5PoolProxy()" class="btn-modal-primary">确定</button>
        </div>
      </div>
    </div>

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
          <button id="create-routing-rule-submit-btn" onclick="submitCreateRoutingRule()" class="btn-modal-primary">创建</button>
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
          <button id="edit-routing-rule-submit-btn" onclick="submitEditRoutingRule()" class="btn-modal-primary">保存</button>
        </div>
      </div>
    </div>

    </main>
  </div>
  <script src="./static/app.js"></script>
</html>`
