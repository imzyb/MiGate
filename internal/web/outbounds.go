package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"golang.org/x/sync/singleflight"
)

const (
	defaultSocks5PoolURL = "https://github.cmliussss.net/raw.githubusercontent.com/EDT-Pages/Proxy-List/main/data/socks5.json"
	defaultHTTPPoolURL   = "https://raw.githubusercontent.com/EDT-Pages/Proxy-List/refs/heads/main/data/http.json"
	defaultHTTPSPoolURL  = "https://raw.githubusercontent.com/EDT-Pages/Proxy-List/refs/heads/main/data/https.json"
)

func outboundsHandler(cfg *routerConfig) http.HandlerFunc {
	store := cfg.store
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			outbounds, err := store.ListOutbounds(r.Context())
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "list_outbounds_failed")
				return
			}
			writeJSON(w, http.StatusOK, outbounds)
		case http.MethodPost:
			var params db.CreateOutboundParams
			if err := decodeJSONBody(r, &params); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_json")
				return
			}
			params.Source = db.OutboundSourceManual
			params.SubscriptionID = 0
			params.SubscriptionIdentity = ""
			params.RawLink = ""
			scope, err := loadCoreInboundScope(r.Context(), store)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "list_inbounds_failed")
				return
			}
			outbound, err := store.CreateOutbound(r.Context(), params)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "create_outbound_failed")
				return
			}
			includeXray, includeSingbox := xrayAndSingboxForOutboundWrite(scope, db.Outbound{}, false, outbound)
			writeCoreWriteResult(w, r, cfg, store, http.StatusCreated, map[string]interface{}{"outbound": outbound}, includeXray, includeSingbox)
		default:
			methodNotAllowed(w)
		}
	}
}

func findOutbound(ctx context.Context, store Store, outboundID int64) (db.Outbound, bool, error) {
	if store == nil {
		return db.Outbound{}, false, nil
	}
	outbounds, err := store.ListOutbounds(ctx)
	if err != nil {
		return db.Outbound{}, false, err
	}
	for _, outbound := range outbounds {
		if outbound.ID == outboundID {
			return outbound, true, nil
		}
	}
	return db.Outbound{}, false, nil
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
	Protocol     string  `json:"protocol,omitempty"`
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

type proxyPoolListOptions struct {
	Country string
	Summary bool
	Page    int
	PerPage int
	Legacy  bool
}

type socks5PoolCache struct {
	mu                       sync.Mutex
	group                    singleflight.Group
	afterSingleflightForTest func()
	proxies                  []socks5PoolProxy
	updatedAt                time.Time
	err                      string
	sourceURL                string
}

var (
	globalSocks5PoolCache = &socks5PoolCache{}
	globalHTTPPoolCache   = &socks5PoolCache{}
	globalHTTPSPoolCache  = &socks5PoolCache{}
)

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
	return startProxyPoolCacheScheduler(func(ctx context.Context) {
		_, _, _, _ = cachedSocks5Pool(ctx, cfg)
	})
}

func StartHTTPPoolCacheScheduler(poolURL string) func() {
	cfg := &routerConfig{httpPoolURL: poolURL}
	return startProxyPoolCacheScheduler(func(ctx context.Context) {
		_, _, _, _ = cachedHTTPPool(ctx, cfg)
	})
}

func StartHTTPSPoolCacheScheduler(poolURL string) func() {
	cfg := &routerConfig{httpsPoolURL: poolURL}
	return startProxyPoolCacheScheduler(func(ctx context.Context) {
		_, _, _, _ = cachedHTTPSPool(ctx, cfg)
	})
}

func startProxyPoolCacheScheduler(refresh func(context.Context)) func() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		refresh(ctx)
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
				refresh(ctx)
			}
		}
	}()
	return cancel
}

func cachedSocks5Pool(ctx context.Context, cfg *routerConfig) ([]socks5PoolProxy, time.Time, string, error) {
	return cachedProxyPool(ctx, globalSocks5PoolCache, cfg.socks5PoolURL, defaultSocks5PoolURL, "socks")
}

func cachedHTTPPool(ctx context.Context, cfg *routerConfig) ([]socks5PoolProxy, time.Time, string, error) {
	return cachedProxyPool(ctx, globalHTTPPoolCache, cfg.httpPoolURL, defaultHTTPPoolURL, "http")
}

func cachedHTTPSPool(ctx context.Context, cfg *routerConfig) ([]socks5PoolProxy, time.Time, string, error) {
	return cachedProxyPool(ctx, globalHTTPSPoolCache, cfg.httpsPoolURL, defaultHTTPSPoolURL, "https")
}

func cachedProxyPool(ctx context.Context, cache *socks5PoolCache, poolURL string, defaultURL string, protocol string) ([]socks5PoolProxy, time.Time, string, error) {
	sourceURL := strings.TrimSpace(poolURL)
	if sourceURL == "" {
		sourceURL = defaultURL
	}
	cache.mu.Lock()
	cached := append([]socks5PoolProxy(nil), cache.proxies...)
	updatedAt := cache.updatedAt
	lastErr := cache.err
	fresh := len(cached) > 0 && cache.sourceURL == sourceURL && time.Now().Before(nextSocks5PoolRefresh(updatedAt))
	cache.mu.Unlock()
	if fresh {
		return cached, updatedAt, "hit", nil
	}
	ch := cache.group.DoChan(protocol+"\x00"+sourceURL, func() (interface{}, error) {
		fetchCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		proxies, fetchErr := fetchProxyPool(fetchCtx, sourceURL, defaultURL, protocol)
		if fetchErr != nil {
			return proxyPoolFetchResult{err: fetchErr}, nil
		}
		now := time.Now()
		cache.mu.Lock()
		cache.proxies = append([]socks5PoolProxy(nil), proxies...)
		cache.updatedAt = now
		cache.err = ""
		cache.sourceURL = sourceURL
		cache.mu.Unlock()
		return proxyPoolFetchResult{proxies: append([]socks5PoolProxy(nil), proxies...), updatedAt: now}, nil
	})
	if cache.afterSingleflightForTest != nil {
		cache.afterSingleflightForTest()
	}
	var result singleflight.Result
	select {
	case result = <-ch:
	case <-ctx.Done():
		return nil, time.Time{}, "miss", ctx.Err()
	}
	if result.Err != nil {
		return nil, time.Time{}, "miss", result.Err
	}
	fetched := result.Val.(proxyPoolFetchResult)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if fetched.err != nil {
		cache.err = fetched.err.Error()
		if len(cache.proxies) > 0 && cache.sourceURL == sourceURL {
			return append([]socks5PoolProxy(nil), cache.proxies...), cache.updatedAt, "stale", nil
		}
		return nil, time.Time{}, "miss", fetched.err
	}
	_ = lastErr
	return append([]socks5PoolProxy(nil), fetched.proxies...), fetched.updatedAt, "refresh", nil
}

type proxyPoolFetchResult struct {
	proxies   []socks5PoolProxy
	updatedAt time.Time
	err       error
}

func fetchSocks5Pool(ctx context.Context, poolURL string) ([]socks5PoolProxy, error) {
	if poolURL == "" {
		poolURL = defaultSocks5PoolURL
	}
	return fetchProxyPool(ctx, poolURL, defaultSocks5PoolURL, "socks")
}

func fetchProxyPool(ctx context.Context, poolURL string, defaultURL string, protocol string) ([]socks5PoolProxy, error) {
	if poolURL == "" {
		poolURL = defaultURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, poolURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MiGate/1.0 proxy-pool")
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
	return parseProxyPool(body, protocol)
}

func parseSocks5Pool(body []byte) ([]socks5PoolProxy, error) {
	return parseProxyPool(body, "socks")
}

func parseProxyPool(body []byte, protocol string) ([]socks5PoolProxy, error) {
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
			Protocol:     protocol,
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
	proxyPoolListHandler(func(ctx context.Context) ([]socks5PoolProxy, time.Time, string, error) {
		return cachedSocks5Pool(ctx, cfg)
	}, w, r)
}

func httpPoolListHandler(cfg *routerConfig, w http.ResponseWriter, r *http.Request) {
	proxyPoolListHandler(func(ctx context.Context) ([]socks5PoolProxy, time.Time, string, error) {
		return cachedHTTPPool(ctx, cfg)
	}, w, r)
}

func httpsPoolListHandler(cfg *routerConfig, w http.ResponseWriter, r *http.Request) {
	proxyPoolListHandler(func(ctx context.Context) ([]socks5PoolProxy, time.Time, string, error) {
		return cachedHTTPSPool(ctx, cfg)
	}, w, r)
}

func proxyPoolListHandler(load func(context.Context) ([]socks5PoolProxy, time.Time, string, error), w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	proxies, updatedAt, cacheStatus, err := load(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "pool_fetch_failed", map[string]interface{}{"cache_status": cacheStatus, "detail": err.Error()})
		return
	}
	options := proxyPoolListOptionsFromRequest(r)
	filtered := filterProxyPool(proxies, options.Country)
	if options.Legacy {
		options.PerPage = -1
	}
	paged := paginateProxyPool(filtered, options.Page, options.PerPage)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"regions": socks5PoolRegions(proxies), "proxies": paged,
		"total": len(filtered), "page": options.Page, "per_page": options.PerPage,
		"cache_status": cacheStatus, "cache_updated_at": updatedAt.Format(time.RFC3339),
		"next_refresh_at": nextSocks5PoolRefresh(time.Now()).Format(time.RFC3339),
	})
}

func proxyPoolListOptionsFromRequest(r *http.Request) proxyPoolListOptions {
	query := r.URL.Query()
	options := proxyPoolListOptions{
		Country: strings.ToUpper(strings.TrimSpace(query.Get("country"))),
		Summary: queryBool(r, "summary"),
		Page:    1,
		PerPage: 100,
	}
	hasPaging := false
	if rawPage := strings.TrimSpace(query.Get("page")); rawPage != "" {
		if page, err := strconv.Atoi(rawPage); err == nil && page > 0 {
			options.Page = page
		}
		hasPaging = true
	}
	if rawPerPage := strings.TrimSpace(query.Get("per_page")); rawPerPage != "" {
		if perPage, err := strconv.Atoi(rawPerPage); err == nil && perPage > 0 {
			options.PerPage = perPage
		}
		hasPaging = true
	}
	if options.Summary {
		options.PerPage = 0
	} else if !hasPaging {
		options.Legacy = true
	}
	if options.PerPage > 200 {
		options.PerPage = 200
	}
	return options
}

func filterProxyPool(proxies []socks5PoolProxy, country string) []socks5PoolProxy {
	if country == "" {
		return append([]socks5PoolProxy(nil), proxies...)
	}
	filtered := make([]socks5PoolProxy, 0, len(proxies))
	for _, proxy := range proxies {
		if proxy.CountryCode == country {
			filtered = append(filtered, proxy)
		}
	}
	return filtered
}

func paginateProxyPool(proxies []socks5PoolProxy, page, perPage int) []socks5PoolProxy {
	if perPage < 0 {
		return append([]socks5PoolProxy(nil), proxies...)
	}
	if perPage == 0 {
		return []socks5PoolProxy{}
	}
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * perPage
	if start >= len(proxies) {
		return []socks5PoolProxy{}
	}
	end := start + perPage
	if end > len(proxies) {
		end = len(proxies)
	}
	return proxies[start:end]
}

func socks5PoolPingHandler(w http.ResponseWriter, r *http.Request) {
	proxyPoolPingHandler(w, r)
}

func proxyPoolPingHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	var req struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	address := strings.TrimSpace(req.Address)
	if address == "" || req.Port <= 0 || req.Port > 65535 {
		writeJSONError(w, http.StatusBadRequest, "invalid_proxy")
		return
	}
	writeJSON(w, http.StatusOK, pingOutbound(address, req.Port))
}

func socks5PoolImportHandler(cfg *routerConfig, w http.ResponseWriter, r *http.Request) {
	proxyPoolImportHandler(cfg, "socks", "socks", w, r)
}

func httpPoolImportHandler(cfg *routerConfig, w http.ResponseWriter, r *http.Request) {
	proxyPoolImportHandler(cfg, "http", "http", w, r)
}

func httpsPoolImportHandler(cfg *routerConfig, w http.ResponseWriter, r *http.Request) {
	proxyPoolImportHandler(cfg, "http", "https", w, r)
}

func proxyPoolImportHandler(cfg *routerConfig, outboundProtocol string, tagProtocol string, w http.ResponseWriter, r *http.Request) {
	store := cfg.store
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "store_unavailable")
		return
	}
	var req struct {
		Address      string `json:"address"`
		Port         int    `json:"port"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		CountryCode  string `json:"country_code"`
		Country      string `json:"country"`
		City         string `json:"city"`
		ASN          string `json:"asn"`
		Organization string `json:"organization"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_json")
		return
	}
	address := strings.TrimSpace(req.Address)
	if address == "" || req.Port <= 0 || req.Port > 65535 {
		writeJSONError(w, http.StatusBadRequest, "invalid_proxy")
		return
	}
	remarkParts := []string{}
	for _, part := range []string{poolCountryLabel(req.Country, req.CountryCode), req.City, normalizeASN(req.ASN), req.Organization} {
		part = strings.TrimSpace(part)
		if part != "" {
			remarkParts = append(remarkParts, part)
		}
	}
	remark := strings.Join(remarkParts, " ")
	if remark == "" {
		remark = address
	}
	scope, err := loadCoreInboundScope(r.Context(), store)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list_inbounds_failed")
		return
	}
	outbound, err := store.CreateOutbound(r.Context(), db.CreateOutboundParams{
		Tag:      fmt.Sprintf("pool-%s-%s-%d", tagProtocol, strings.NewReplacer(".", "-", ":", "-").Replace(address), req.Port),
		Remark:   remark,
		Protocol: outboundProtocol,
		Address:  address,
		Port:     req.Port,
		Username: strings.TrimSpace(req.Username),
		Password: req.Password,
		Source:   db.OutboundSourceProxyPool,
	})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "create_outbound_failed")
		return
	}
	includeXray, includeSingbox := xrayAndSingboxForOutboundWrite(scope, db.Outbound{}, false, outbound)
	writeCoreWriteResult(w, r, cfg, store, http.StatusCreated, map[string]interface{}{"outbound": outbound}, includeXray, includeSingbox)
}

func poolCountryLabel(country, countryCode string) string {
	country = strings.TrimSpace(country)
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if country != "" && !strings.EqualFold(country, countryCode) {
		return country
	}
	return countryCode
}

func outboundChildrenHandler(cfg *routerConfig) http.HandlerFunc {
	store := cfg.store
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
			socks5PoolImportHandler(cfg, w, r)
			return
		}
		if path == "http-pool" {
			httpPoolListHandler(cfg, w, r)
			return
		}
		if path == "http-pool/ping" {
			proxyPoolPingHandler(w, r)
			return
		}
		if path == "http-pool/import" {
			httpPoolImportHandler(cfg, w, r)
			return
		}
		if path == "https-pool" {
			httpsPoolListHandler(cfg, w, r)
			return
		}
		if path == "https-pool/ping" {
			proxyPoolPingHandler(w, r)
			return
		}
		if path == "https-pool/import" {
			httpsPoolImportHandler(cfg, w, r)
			return
		}
		// Handle /api/outbounds/reorder
		if path == "reorder" {
			// ...existing reorder handler...
			if r.Method != http.MethodPost {
				writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
				return
			}
			var req struct {
				IDs []int64 `json:"ids"`
			}
			if err := decodeJSONBody(r, &req); err != nil || len(req.IDs) == 0 {
				writeJSONError(w, http.StatusBadRequest, "invalid_payload")
				return
			}
			includeXray, includeSingbox, err := xrayAndSingboxForReorder(r.Context(), store)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "list_failed")
				return
			}
			if err := store.ReorderOutbounds(r.Context(), req.IDs); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "reorder_failed")
				return
			}
			writeCoreWriteResult(w, r, cfg, store, http.StatusOK, map[string]interface{}{"status": "reordered"}, includeXray, includeSingbox)
			return
		}
		// Handle /api/outbounds/speedtest-all
		if path == "speedtest-all" {
			if r.Method != http.MethodPost {
				writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
				return
			}
			obs, err := store.ListOutbounds(r.Context())
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "load_failed")
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
			writeJSON(w, http.StatusOK, results)
			return
		}
		if strings.HasSuffix(path, "/ping") {
			if r.Method != http.MethodGet {
				writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
				return
			}
			idStr := strings.TrimSuffix(path, "/ping")
			obID, err := strconv.ParseInt(strings.TrimSpace(idStr), 10, 64)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_id")
				return
			}
			outbounds, err := store.ListOutbounds(r.Context())
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "list_failed")
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
				writeJSON(w, http.StatusOK, map[string]interface{}{"latency": -1, "error": "not_pingable"})
				return
			}
			result := pingOutbound(target.Address, target.Port)
			writeJSON(w, http.StatusOK, result)
			return
		}
		idStr := strings.TrimSuffix(path, "/")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_id")
			return
		}
		switch r.Method {
		case http.MethodPut:
			var params db.UpdateOutboundParams
			body, err := decodeJSONBodyRaw(r, &params)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_json")
				return
			}
			previous, hadPrevious, err := findOutbound(r.Context(), store, id)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "list_failed")
				return
			}
			if hadPrevious && !jsonObjectHasKey(body, "settings_json") {
				params.SettingsJSON = previous.SettingsJSON
			}
			scope, err := loadCoreInboundScope(r.Context(), store)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "list_inbounds_failed")
				return
			}
			outbound, err := store.UpdateOutbound(r.Context(), id, params)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					writeJSONError(w, http.StatusNotFound, "not_found")
				} else if strings.Contains(err.Error(), "subscription_disabled") {
					writeJSONError(w, http.StatusBadRequest, "subscription_disabled")
				} else {
					writeJSONError(w, http.StatusBadRequest, "update_failed")
				}
				return
			}
			includeXray, includeSingbox := xrayAndSingboxForOutboundWrite(scope, previous, hadPrevious, outbound)
			writeCoreWriteResult(w, r, cfg, store, http.StatusOK, map[string]interface{}{"outbound": outbound}, includeXray, includeSingbox)
		case http.MethodDelete:
			deletedOutbound, found, err := findOutbound(r.Context(), store, id)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "list_failed")
				return
			}
			if !found {
				writeJSONError(w, http.StatusNotFound, "not_found")
				return
			}
			scope, err := loadCoreInboundScope(r.Context(), store)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "list_inbounds_failed")
				return
			}
			err = store.DeleteOutbound(r.Context(), id)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					writeJSONError(w, http.StatusNotFound, "not_found")
				} else {
					writeJSONError(w, http.StatusInternalServerError, "delete_failed")
				}
				return
			}
			includeXray, includeSingbox := xrayAndSingboxForOutboundDelete(scope, deletedOutbound)
			writeCoreWriteResult(w, r, cfg, store, http.StatusOK, map[string]interface{}{"status": "deleted"}, includeXray, includeSingbox)
		default:
			methodNotAllowed(w)
		}
	}
}
