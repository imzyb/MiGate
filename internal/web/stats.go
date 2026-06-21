package web

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/singbox"
	"github.com/imzyb/MiGate/internal/xray"
)

func expectedTrafficEngine(protocol string) string {
	if singbox.IsSingboxProtocol(strings.ToLower(strings.TrimSpace(protocol))) {
		return "singbox"
	}
	return "xray"
}

func normalizeTrafficEngine(engine string) string {
	engine = strings.ToLower(strings.TrimSpace(engine))
	if engine == "sing-box" {
		return "singbox"
	}
	return engine
}

func selectTrafficState(byEngine map[string]db.TrafficState, expectedEngine string) (db.TrafficState, bool) {
	if len(byEngine) == 0 {
		return db.TrafficState{}, false
	}
	expectedEngine = normalizeTrafficEngine(expectedEngine)
	if state, ok := byEngine[expectedEngine]; ok {
		return state, true
	}
	for _, engine := range fallbackTrafficEngines(expectedEngine) {
		if state, ok := byEngine[engine]; ok {
			return state, true
		}
	}
	return db.TrafficState{}, false
}

func fallbackTrafficEngines(expectedEngine string) []string {
	switch normalizeTrafficEngine(expectedEngine) {
	case "singbox":
		return []string{"xray", "migate"}
	case "xray":
		return []string{"singbox", "migate"}
	default:
		return []string{"xray", "singbox", "migate"}
	}
}

func loadTrafficStates(ctx context.Context, store Store) []db.TrafficState {
	if store == nil {
		return nil
	}
	states, err := store.ListTrafficStates(ctx)
	if err != nil {
		return nil
	}
	return states
}

func summarizeTraffic(ctx context.Context, store Store, inbounds []db.Inbound) (map[int64]inboundTrafficSummary, map[int64]clientTrafficSummary) {
	return summarizeTrafficFromStates(loadTrafficStates(ctx, store), inbounds)
}

const trafficStateStaleAfter = 3 * time.Minute

func summarizeTrafficFromStates(states []db.TrafficState, inbounds []db.Inbound) (map[int64]inboundTrafficSummary, map[int64]clientTrafficSummary) {
	now := time.Now().UTC()
	stateByScope := map[string]map[string]db.TrafficState{}
	for _, state := range states {
		engine := normalizeTrafficEngine(state.Engine)
		scopeType := strings.ToLower(strings.TrimSpace(state.ScopeType))
		scopeKey := strings.TrimSpace(state.ScopeKey)
		if engine == "" || scopeType == "" || scopeKey == "" {
			continue
		}
		state.Engine = engine
		state.ScopeType = scopeType
		state.ScopeKey = scopeKey
		key := scopeType + "\x00" + scopeKey
		byEngine := stateByScope[key]
		if byEngine == nil {
			byEngine = map[string]db.TrafficState{}
			stateByScope[key] = byEngine
		}
		current, ok := byEngine[engine]
		if !ok || state.LastSeenAt > current.LastSeenAt {
			byEngine[engine] = state
		}
	}
	byInbound := map[int64]inboundTrafficSummary{}
	byClient := map[int64]clientTrafficSummary{}
	for _, inbound := range inbounds {
		expectedEngine := expectedTrafficEngine(inbound.Protocol)
		inboundKey := inboundStatsKey(inbound)
		inboundState, hasInboundState := selectTrafficState(stateByScope["inbound\x00"+inboundKey], expectedEngine)
		inboundSummary := inboundTrafficSummary{Status: "waiting", Source: "migate", Engine: expectedEngine}
		if hasInboundState {
			freshState := trafficStateWithFreshness(inboundState, now)
			inboundSummary.Up = inboundState.TotalUp
			inboundSummary.Down = inboundState.TotalDown
			inboundSummary.RateUp = freshState.RateUp
			inboundSummary.RateDown = freshState.RateDown
			inboundSummary.Status = stateStatus(freshState)
			inboundSummary.Message = freshState.Message
			inboundSummary.Engine = inboundState.Engine
			inboundSummary.LastSampledAt = inboundState.LastSeenAt
		}
		for _, client := range inbound.Clients {
			clientSummary := clientTrafficSummary{Status: "waiting", Source: "migate", Engine: expectedEngine}
			if state, ok := selectTrafficState(stateByScope["client\x00"+client.StatsKey], expectedEngine); ok {
				freshState := trafficStateWithFreshness(state, now)
				clientSummary.Up = state.TotalUp
				clientSummary.Down = state.TotalDown
				clientSummary.RateUp = freshState.RateUp
				clientSummary.RateDown = freshState.RateDown
				clientSummary.Status = stateStatus(freshState)
				clientSummary.Message = freshState.Message
				clientSummary.Engine = state.Engine
				clientSummary.LastSampledAt = state.LastSeenAt
				if state.Engine == "xray" {
					clientSummary.XrayUp = state.LastRawUp
					clientSummary.XrayDown = state.LastRawDown
				}
			} else if client.Up > 0 || client.Down > 0 {
				clientSummary.Up = client.Up
				clientSummary.Down = client.Down
				clientSummary.Status = "cumulative_only"
			}
			if !hasInboundState {
				inboundSummary.Up += clientSummary.Up
				inboundSummary.Down += clientSummary.Down
				inboundSummary.RateUp += clientSummary.RateUp
				inboundSummary.RateDown += clientSummary.RateDown
				inboundSummary.Status = combineTrafficStatuses(inboundSummary.Status, clientSummary.Status)
				inboundSummary.Engine = expectedEngine
			}
			byClient[client.ID] = clientSummary
		}
		inboundSummary.Total = inboundSummary.Up + inboundSummary.Down
		if inboundSummary.Status == "waiting" && inboundSummary.Total > 0 {
			inboundSummary.Status = "cumulative_only"
		}
		byInbound[inbound.ID] = inboundSummary
	}
	return byInbound, byClient
}

func trafficStateWithFreshness(state db.TrafficState, now time.Time) db.TrafficState {
	status := strings.TrimSpace(state.Status)
	if state.LastSeenAt == "" || status == "stale" || status == "unsupported" || status == "not_configured" {
		return state
	}
	sampledAt, err := time.Parse(time.RFC3339Nano, state.LastSeenAt)
	if err != nil {
		sampledAt, err = time.Parse(time.RFC3339, state.LastSeenAt)
	}
	if err != nil || now.Sub(sampledAt.UTC()) <= trafficStateStaleAfter {
		return state
	}
	state.Status = "stale"
	state.RateUp = 0
	state.RateDown = 0
	if strings.TrimSpace(state.Message) == "" {
		state.Message = "traffic sample is stale"
	}
	return state
}

func inboundStatsKey(inbound db.Inbound) string {
	switch strings.ToLower(strings.TrimSpace(inbound.Protocol)) {
	case "hysteria2":
		return fmt.Sprintf("hy2-inbound-%d", inbound.ID)
	case "tuic":
		return fmt.Sprintf("tuic-inbound-%d", inbound.ID)
	case "shadowtls":
		return fmt.Sprintf("shadowtls-inbound-%d", inbound.ID)
	default:
		return fmt.Sprintf("inbound-%d-%s", inbound.ID, strings.ToLower(strings.TrimSpace(inbound.Protocol)))
	}
}

type outboundTrafficSummary struct {
	Up         int64
	Down       int64
	RateUp     float64
	RateDown   float64
	Status     string
	LastSeenAt string
	Engines    []string
}

func outboundStatsByProfileID(states []db.TrafficState) map[int64]outboundTrafficSummary {
	result := map[int64]outboundTrafficSummary{}
	now := time.Now().UTC()
	for _, state := range states {
		if strings.ToLower(strings.TrimSpace(state.ScopeType)) != "outbound" {
			continue
		}
		engine := normalizeTrafficEngine(state.Engine)
		id, ok := db.OutboundProfileIDFromGeneratedTag(engine, state.ScopeKey)
		if !ok {
			continue
		}
		current := result[id]
		freshState := trafficStateWithFreshness(state, now)
		current.Up += state.TotalUp
		current.Down += state.TotalDown
		current.RateUp += freshState.RateUp
		current.RateDown += freshState.RateDown
		current.Status = combineTrafficStatuses(current.Status, stateStatus(freshState))
		if state.LastSeenAt > current.LastSeenAt {
			current.LastSeenAt = state.LastSeenAt
		}
		current.Engines = appendUniqueString(current.Engines, engine)
		result[id] = current
	}
	return result
}

func outboundTrafficDetails(outbounds []db.Outbound, stats map[int64]outboundTrafficSummary) []map[string]interface{} {
	details := make([]map[string]interface{}, 0, len(outbounds))
	for _, outbound := range outbounds {
		state, ok := stats[outbound.ID]
		up := int64(0)
		down := int64(0)
		rateUp := float64(0)
		rateDown := float64(0)
		status := "waiting"
		engine := ""
		engines := []string{}
		if ok {
			up = state.Up
			down = state.Down
			rateUp = state.RateUp
			rateDown = state.RateDown
			status = state.Status
			engines = state.Engines
			if len(engines) == 1 {
				engine = engines[0]
			} else if len(engines) > 1 {
				engine = "mixed"
			}
		}
		details = append(details, map[string]interface{}{
			"id":                   outbound.ID,
			"tag":                  outbound.Tag,
			"remark":               outbound.Remark,
			"protocol":             outbound.Protocol,
			"enabled":              outbound.Enabled,
			"traffic_up":           up,
			"traffic_down":         down,
			"traffic_total":        up + down,
			"rate_up":              rateUp,
			"rate_down":            rateDown,
			"traffic_status":       status,
			"traffic_engine":       engine,
			"traffic_engines":      engines,
			"traffic_last_seen_at": state.LastSeenAt,
		})
	}
	return details
}

func appendUniqueString(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func stateStatus(state db.TrafficState) string {
	status := strings.TrimSpace(state.Status)
	if status == "" {
		return "waiting"
	}
	return status
}

func combineTrafficStatuses(current, next string) string {
	if current == "" || current == "waiting" {
		return next
	}
	if next == "" || next == "waiting" || current == next {
		return current
	}
	if current == "ok" && next == "ok" {
		return "ok"
	}
	return "partial"
}

type trafficCoverageCounts struct {
	total         int
	ok            int
	partial       int
	unsupported   int
	notConfigured int
	unavailable   int
	stale         int
	waiting       int
}

func (counts *trafficCoverageCounts) add(status string) {
	counts.total++
	switch status {
	case "ok":
		counts.ok++
	case "partial":
		counts.partial++
	case "unsupported":
		counts.unsupported++
	case "not_configured":
		counts.notConfigured++
	case "unavailable":
		counts.unavailable++
	case "stale":
		counts.stale++
	case "waiting", "":
		counts.waiting++
	default:
		counts.waiting++
	}
}

func (counts trafficCoverageCounts) status() string {
	if counts.total == 0 {
		return "not_configured"
	}
	if counts.notConfigured == counts.total {
		return "not_configured"
	}
	if counts.ok == counts.total {
		return "ok"
	}
	if counts.ok > 0 {
		if counts.partial > 0 || counts.unsupported > 0 || counts.unavailable > 0 || counts.stale > 0 || counts.waiting > 0 {
			return "partial"
		}
		return "ok"
	}
	if counts.partial > 0 {
		return "partial"
	}
	if counts.unsupported > 0 && counts.unavailable == 0 {
		return "unsupported"
	}
	if counts.stale > 0 && counts.unavailable == 0 {
		return "stale"
	}
	if counts.unavailable > 0 {
		return "unavailable"
	}
	return "waiting"
}

func buildTrafficCoverage(byInbound map[int64]inboundTrafficSummary) map[string]interface{} {
	counts := trafficCoverageCounts{}
	countsByEngine := map[string]*trafficCoverageCounts{}
	engines := map[string]string{"xray": "not_configured", "singbox": "not_configured"}
	for _, summary := range byInbound {
		counts.add(summary.Status)
		if summary.Engine != "" {
			engine := coverageEngineKey(summary.Engine)
			engineCounts := countsByEngine[engine]
			if engineCounts == nil {
				engineCounts = &trafficCoverageCounts{}
				countsByEngine[engine] = engineCounts
			}
			engineCounts.add(summary.Status)
		}
	}
	for engine, engineCounts := range countsByEngine {
		engines[engine] = engineCounts.status()
	}
	return map[string]interface{}{
		"overall":        counts.status(),
		"ok":             counts.ok,
		"partial":        counts.partial,
		"unsupported":    counts.unsupported,
		"not_configured": counts.notConfigured,
		"unavailable":    counts.unavailable,
		"stale":          counts.stale,
		"waiting":        counts.waiting,
		"engines":        engines,
	}
}

func lastTrafficSampledAt(inboundTraffic map[int64]inboundTrafficSummary, clientTraffic map[int64]clientTrafficSummary) string {
	latest := time.Time{}
	consider := func(value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			parsed, err = time.Parse(time.RFC3339, value)
		}
		if err == nil && parsed.After(latest) {
			latest = parsed
		}
	}
	for _, traffic := range inboundTraffic {
		consider(traffic.LastSampledAt)
	}
	for _, traffic := range clientTraffic {
		consider(traffic.LastSampledAt)
	}
	if latest.IsZero() {
		return ""
	}
	return latest.UTC().Format(time.RFC3339)
}

func coverageEngineKey(engine string) string {
	engine = strings.ToLower(strings.TrimSpace(engine))
	switch engine {
	case "sing-box":
		return "singbox"
	default:
		return engine
	}
}

func statsHandler(store Store, statsClient xray.StatsClient) http.HandlerFunc {
	cache := newStatsResponseCache(3 * time.Second)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		if store == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "store_unavailable")
			return
		}
		detail := queryBool(r, "detail")
		response, err := cache.get(r.Context(), store, statsClient, detail)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, response)
	}
}

type statsResponseCache struct {
	ttl      time.Duration
	mu       sync.Mutex
	now      func() time.Time
	byDetail map[bool]statsResponseCacheEntry
}

type statsResponseCacheEntry struct {
	expiresAt time.Time
	value     map[string]interface{}
}

func newStatsResponseCache(ttl time.Duration) *statsResponseCache {
	return &statsResponseCache{ttl: ttl, now: time.Now, byDetail: map[bool]statsResponseCacheEntry{}}
}

func (c *statsResponseCache) get(ctx context.Context, store Store, statsClient xray.StatsClient, detail bool) (map[string]interface{}, error) {
	if c == nil || c.ttl <= 0 {
		return buildStatsResponse(ctx, store, statsClient, detail)
	}
	now := c.now()
	c.mu.Lock()
	if entry, ok := c.byDetail[detail]; ok && now.Before(entry.expiresAt) {
		value := entry.value
		c.mu.Unlock()
		return value, nil
	}
	c.mu.Unlock()

	value, err := buildStatsResponse(ctx, store, statsClient, detail)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.byDetail[detail]; ok && c.now().Before(entry.expiresAt) {
		return entry.value, nil
	}
	c.byDetail[detail] = statsResponseCacheEntry{value: value, expiresAt: c.now().Add(c.ttl)}
	return value, nil
}

func buildStatsResponse(ctx context.Context, store Store, statsClient xray.StatsClient, detail bool) (map[string]interface{}, error) {
	inb, err := store.ListInboundTraffic(ctx)
	if err != nil {
		return nil, fmt.Errorf("list_inbounds_failed")
	}
	obs, err := store.ListOutbounds(ctx)
	if err != nil {
		return nil, fmt.Errorf("list_outbounds_failed")
	}
	rules, err := store.ListRoutingRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("list_routing_rules_failed")
	}
	var clientCount int
	for _, in := range inb {
		clientCount += len(in.Clients)
	}
	enabledObs := 0
	for _, ob := range obs {
		if ob.Enabled {
			enabledObs++
		}
	}
	enabledRules := 0
	for _, rule := range rules {
		if rule.Enabled {
			enabledRules++
		}
	}

	states := loadTrafficStates(ctx, store)
	trafficByInbound, trafficByClient := summarizeTrafficFromStates(states, inb)
	var totalUp int64
	var totalDown int64
	for _, traffic := range trafficByInbound {
		totalUp += traffic.Up
		totalDown += traffic.Down
	}

	response := map[string]interface{}{
		"legacy":                true,
		"inbounds":              len(inb),
		"clients":               clientCount,
		"traffic_up":            totalUp,
		"traffic_down":          totalDown,
		"traffic_total":         totalUp + totalDown,
		"outbounds":             len(obs),
		"outbounds_enabled":     enabledObs,
		"routing_rules":         len(rules),
		"routing_rules_enabled": enabledRules,
	}
	if !detail {
		return response, nil
	}
	clientList := make([]map[string]interface{}, 0, clientCount)
	for _, in := range inb {
		for _, c := range in.Clients {
			clientTraffic := trafficByClient[c.ID]
			info := map[string]interface{}{
				"id":                   c.ID,
				"inbound_id":           c.InboundID,
				"protocol":             in.Protocol,
				"email":                c.Email,
				"enabled":              c.Enabled,
				"up":                   clientTraffic.Up,
				"down":                 clientTraffic.Down,
				"xray_up":              clientTraffic.XrayUp,
				"xray_down":            clientTraffic.XrayDown,
				"traffic_limit":        c.TrafficLimit,
				"expiry_at":            c.ExpiryAt,
				"traffic_stats_source": clientTraffic.Source,
				"rate_up":              clientTraffic.RateUp,
				"rate_down":            clientTraffic.RateDown,
				"traffic_status":       clientTraffic.Status,
			}
			if clientTraffic.Note != "" {
				info["traffic_stats_note"] = clientTraffic.Note
			}
			clientList = append(clientList, info)
		}
	}
	response["client_details"] = clientList
	outboundStats := outboundStatsByProfileID(states)
	response["outbound_details"] = outboundTrafficDetails(obs, outboundStats)
	return response, nil
}

func queryBool(r *http.Request, name string) bool {
	value := strings.ToLower(strings.TrimSpace(r.URL.Query().Get(name)))
	return value == "1" || value == "true" || value == "yes"
}

func dashboardSummaryHandler(cfg *routerConfig) http.HandlerFunc {
	cache := newDashboardSummaryCache(7*time.Second, 30*time.Second)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		if cfg == nil || cfg.store == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "store_unavailable")
			return
		}
		summary, err := cache.get(r.Context(), cfg)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, summary)
	}
}

type dashboardSummaryCache struct {
	ttl                 time.Duration
	validationTTL       time.Duration
	mu                  sync.Mutex
	expiresAt           time.Time
	value               map[string]interface{}
	validationExpiresAt time.Time
	validationValue     map[string]configValidationResult
	validationKey       string
	now                 func() time.Time
}

func newDashboardSummaryCache(ttl time.Duration, extraTTLs ...time.Duration) *dashboardSummaryCache {
	validationTTL := ttl
	if len(extraTTLs) > 0 {
		validationTTL = extraTTLs[0]
	}
	return &dashboardSummaryCache{ttl: ttl, validationTTL: validationTTL, now: time.Now}
}

func (c *dashboardSummaryCache) get(ctx context.Context, cfg *routerConfig) (map[string]interface{}, error) {
	if c == nil || c.ttl <= 0 {
		return buildDashboardSummary(ctx, cfg)
	}
	now := c.now()
	c.mu.Lock()
	if c.value != nil && now.Before(c.expiresAt) {
		value := c.value
		c.mu.Unlock()
		return value, nil
	}
	c.mu.Unlock()

	summary, err := c.build(ctx, cfg)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.value != nil && c.now().Before(c.expiresAt) {
		return c.value, nil
	}
	c.value = summary
	c.expiresAt = c.now().Add(c.ttl)
	return summary, nil
}

func (c *dashboardSummaryCache) build(ctx context.Context, cfg *routerConfig) (map[string]interface{}, error) {
	summary, base, err := buildDashboardSummaryBase(ctx, cfg)
	if err != nil {
		return nil, err
	}
	now := c.now()
	configVersion, err := cfg.store.ValidationConfigVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("validation_config_version_failed")
	}
	configKey := fmt.Sprintf("v:%d", configVersion)
	if validation := c.cachedValidation(configKey); validation != nil {
		summary["validation"] = cloneValidationMap(*validation)
		return summary, nil
	}
	snapshot, err := buildDashboardValidationSnapshot(ctx, cfg, base)
	if err != nil {
		return nil, err
	}
	built := buildDashboardValidation(ctx, cfg, snapshot)
	validation := &built
	c.mu.Lock()
	c.validationValue = built
	c.validationKey = configKey
	c.validationExpiresAt = now.Add(c.validationTTL)
	c.mu.Unlock()
	summary["validation"] = cloneValidationMap(*validation)
	return summary, nil
}

func (c *dashboardSummaryCache) cachedValidation(configHash string) *map[string]configValidationResult {
	if c == nil || c.validationTTL <= 0 {
		return nil
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.validationValue == nil || c.validationKey != configHash || !now.Before(c.validationExpiresAt) {
		return nil
	}
	value := cloneValidationMap(c.validationValue)
	return &value
}

func buildDashboardSummary(ctx context.Context, cfg *routerConfig) (map[string]interface{}, error) {
	summary, base, err := buildDashboardSummaryBase(ctx, cfg)
	if err != nil {
		return nil, err
	}
	snapshot, err := buildDashboardValidationSnapshot(ctx, cfg, base)
	if err != nil {
		return nil, err
	}
	summary["validation"] = buildDashboardValidation(ctx, cfg, snapshot)
	return summary, nil
}

type dashboardSummaryBase struct {
	inbounds  []db.Inbound
	outbounds []db.Outbound
	rules     []db.RoutingRule
}

func buildDashboardSummaryBase(ctx context.Context, cfg *routerConfig) (map[string]interface{}, dashboardSummaryBase, error) {
	if cfg == nil || cfg.store == nil {
		return nil, dashboardSummaryBase{}, fmt.Errorf("store_unavailable")
	}
	store := cfg.store
	inbounds, err := store.ListInboundTraffic(ctx)
	if err != nil {
		return nil, dashboardSummaryBase{}, fmt.Errorf("list_inbounds_failed")
	}
	outbounds, err := store.ListOutbounds(ctx)
	if err != nil {
		return nil, dashboardSummaryBase{}, fmt.Errorf("list_outbounds_failed")
	}
	rules, err := store.ListRoutingRules(ctx)
	if err != nil {
		return nil, dashboardSummaryBase{}, fmt.Errorf("list_routing_rules_failed")
	}
	now := time.Now().Unix()
	clientCount := 0
	activeClients := 0
	expiredClients := 0
	limitedClients := 0
	enabledInbounds := 0
	protocols := map[string]int{}
	for _, inbound := range inbounds {
		if inbound.Enabled {
			enabledInbounds++
		}
		if inbound.Protocol != "" {
			protocols[inbound.Protocol]++
		}
		for _, client := range inbound.Clients {
			clientCount++
			used := client.Up + client.Down
			expired := client.ExpiryAt > 0 && client.ExpiryAt <= now
			limited := client.TrafficLimit > 0 && used >= client.TrafficLimit
			if expired {
				expiredClients++
			}
			if limited {
				limitedClients++
			}
			if client.Enabled && !expired && !limited {
				activeClients++
			}
		}
	}
	enabledOutbounds := 0
	for _, outbound := range outbounds {
		if outbound.Enabled {
			enabledOutbounds++
		}
	}
	enabledRules := 0
	for _, rule := range rules {
		if rule.Enabled {
			enabledRules++
		}
	}
	return map[string]interface{}{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"counts": map[string]int{
			"inbounds":          len(inbounds),
			"inbounds_enabled":  enabledInbounds,
			"clients":           clientCount,
			"clients_active":    activeClients,
			"clients_expired":   expiredClients,
			"clients_limited":   limitedClients,
			"outbounds":         len(outbounds),
			"outbounds_enabled": enabledOutbounds,
			"routing_rules":     len(rules),
			"routing_enabled":   enabledRules,
		},
		"protocols":  protocols,
		"validation": map[string]configValidationResult{},
	}, dashboardSummaryBase{inbounds: inbounds, outbounds: outbounds, rules: rules}, nil
}

func buildDashboardValidationSnapshot(ctx context.Context, cfg *routerConfig, base dashboardSummaryBase) (validationSnapshot, error) {
	inbounds, err := cfg.store.ListInbounds(ctx)
	if err != nil {
		return validationSnapshot{}, fmt.Errorf("list_inbounds_failed")
	}
	return validationSnapshot{inbounds: inbounds, outbounds: base.outbounds, rules: base.rules}, nil
}

func buildDashboardValidation(ctx context.Context, cfg *routerConfig, snapshot validationSnapshot) map[string]configValidationResult {
	return map[string]configValidationResult{
		"xray":    validateXrayConfigSnapshot(snapshot),
		"singbox": validateSingboxConfigSnapshotWithRuntime(ctx, snapshot, cfg),
	}
}

func cloneValidationMap(value map[string]configValidationResult) map[string]configValidationResult {
	clone := make(map[string]configValidationResult, len(value))
	for key, item := range value {
		item.Warnings = append([]string(nil), item.Warnings...)
		clone[key] = item
	}
	return clone
}

type validationSnapshot struct {
	inbounds  []db.Inbound
	outbounds []db.Outbound
	rules     []db.RoutingRule
}

func (s validationSnapshot) cacheKey() string {
	payload, err := json.Marshal(validationSnapshotCachePayload{
		Inbounds:  validationInboundCacheKeys(s.inbounds),
		Outbounds: validationOutboundCacheKeys(s.outbounds),
		Rules:     validationRoutingRuleCacheKeys(s.rules),
	})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:])
}

type validationSnapshotCachePayload struct {
	Inbounds  []validationInboundCacheKey     `json:"inbounds"`
	Outbounds []validationOutboundCacheKey    `json:"outbounds"`
	Rules     []validationRoutingRuleCacheKey `json:"rules"`
}

type validationInboundCacheKey struct {
	ID                    int64                      `json:"id"`
	UUID                  string                     `json:"uuid"`
	Remark                string                     `json:"remark"`
	Protocol              string                     `json:"protocol"`
	Core                  string                     `json:"core"`
	Port                  int                        `json:"port"`
	Network               string                     `json:"network"`
	Security              string                     `json:"security"`
	Enabled               bool                       `json:"enabled"`
	WsPath                string                     `json:"ws_path"`
	WsHost                string                     `json:"ws_host"`
	GrpcServiceName       string                     `json:"grpc_service_name"`
	RealityDest           string                     `json:"reality_dest"`
	RealityServerNames    string                     `json:"reality_server_names"`
	RealityShortID        string                     `json:"reality_short_id"`
	RealityPrivateKey     string                     `json:"reality_private_key"`
	RealityPublicKey      string                     `json:"reality_public_key"`
	SSMethod              string                     `json:"ss_method"`
	TLSCertFile           string                     `json:"tls_cert_file"`
	TLSKeyFile            string                     `json:"tls_key_file"`
	TLSSNI                string                     `json:"tls_sni"`
	TLSFingerprint        string                     `json:"tls_fingerprint"`
	TLSALPN               string                     `json:"tls_alpn"`
	XHTTPPath             string                     `json:"xhttp_path"`
	XHTTPMode             string                     `json:"xhttp_mode"`
	Hy2UpMbps             int                        `json:"hy2_up_mbps"`
	Hy2DownMbps           int                        `json:"hy2_down_mbps"`
	Hy2Obfs               string                     `json:"hy2_obfs"`
	Hy2ObfsPassword       string                     `json:"hy2_obfs_password"`
	Hy2MPort              string                     `json:"hy2_mport"`
	TuicCongestionControl string                     `json:"tuic_congestion_control"`
	TuicZeroRTT           bool                       `json:"tuic_zero_rtt"`
	WgPrivateKey          string                     `json:"wg_private_key"`
	WgAddress             string                     `json:"wg_address"`
	WgPeerPublicKey       string                     `json:"wg_peer_public_key"`
	WgAllowedIPs          string                     `json:"wg_allowed_ips"`
	WgEndpoint            string                     `json:"wg_endpoint"`
	WgPresharedKey        string                     `json:"wg_preshared_key"`
	WgMTU                 int                        `json:"wg_mtu"`
	ShadowTLSVersion      int                        `json:"shadowtls_version"`
	ShadowTLSPassword     string                     `json:"shadowtls_password"`
	Clients               []validationClientCacheKey `json:"clients"`
}

type validationClientCacheKey struct {
	ID           int64  `json:"id"`
	InboundID    int64  `json:"inbound_id"`
	UUID         string `json:"uuid"`
	CredentialID string `json:"credential_id"`
	Password     string `json:"password"`
	StatsKey     string `json:"stats_key"`
	Email        string `json:"email"`
	Enabled      bool   `json:"enabled"`
}

type validationOutboundCacheKey struct {
	ID             int64    `json:"id"`
	Tag            string   `json:"tag"`
	Remark         string   `json:"remark"`
	Protocol       string   `json:"protocol"`
	Address        string   `json:"address"`
	Port           int      `json:"port"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	SupportedCores []string `json:"supported_cores"`
	Enabled        bool     `json:"enabled"`
	Sort           int      `json:"sort"`
}

type validationRoutingRuleCacheKey struct {
	ID          int64  `json:"id"`
	InboundID   int64  `json:"inbound_id"`
	InboundTag  string `json:"inbound_tag"`
	ClientID    int64  `json:"client_id"`
	ClientEmail string `json:"client_email"`
	OutboundID  int64  `json:"outbound_id"`
	OutboundTag string `json:"outbound_tag"`
	Domain      string `json:"domain"`
	IP          string `json:"ip"`
	RuleSet     string `json:"rule_set"`
	Protocol    string `json:"protocol"`
	Enabled     bool   `json:"enabled"`
	Sort        int    `json:"sort"`
}

func validationInboundCacheKeys(inbounds []db.Inbound) []validationInboundCacheKey {
	keys := make([]validationInboundCacheKey, 0, len(inbounds))
	for _, inbound := range inbounds {
		keys = append(keys, validationInboundCacheKey{
			ID:                    inbound.ID,
			UUID:                  inbound.UUID,
			Remark:                inbound.Remark,
			Protocol:              inbound.Protocol,
			Core:                  inbound.Core,
			Port:                  inbound.Port,
			Network:               inbound.Network,
			Security:              inbound.Security,
			Enabled:               inbound.Enabled,
			WsPath:                inbound.WsPath,
			WsHost:                inbound.WsHost,
			GrpcServiceName:       inbound.GrpcServiceName,
			RealityDest:           inbound.RealityDest,
			RealityServerNames:    inbound.RealityServerNames,
			RealityShortID:        inbound.RealityShortID,
			RealityPrivateKey:     inbound.RealityPrivateKey,
			RealityPublicKey:      inbound.RealityPublicKey,
			SSMethod:              inbound.SSMethod,
			TLSCertFile:           inbound.TLSCertFile,
			TLSKeyFile:            inbound.TLSKeyFile,
			TLSSNI:                inbound.TLSSNI,
			TLSFingerprint:        inbound.TLSFingerprint,
			TLSALPN:               inbound.TLSALPN,
			XHTTPPath:             inbound.XHTTPPath,
			XHTTPMode:             inbound.XHTTPMode,
			Hy2UpMbps:             inbound.Hy2UpMbps,
			Hy2DownMbps:           inbound.Hy2DownMbps,
			Hy2Obfs:               inbound.Hy2Obfs,
			Hy2ObfsPassword:       inbound.Hy2ObfsPassword,
			Hy2MPort:              inbound.Hy2MPort,
			TuicCongestionControl: inbound.TuicCongestionControl,
			TuicZeroRTT:           inbound.TuicZeroRTT,
			WgPrivateKey:          inbound.WgPrivateKey,
			WgAddress:             inbound.WgAddress,
			WgPeerPublicKey:       inbound.WgPeerPublicKey,
			WgAllowedIPs:          inbound.WgAllowedIPs,
			WgEndpoint:            inbound.WgEndpoint,
			WgPresharedKey:        inbound.WgPresharedKey,
			WgMTU:                 inbound.WgMTU,
			ShadowTLSVersion:      inbound.ShadowTLSVersion,
			ShadowTLSPassword:     inbound.ShadowTLSPassword,
			Clients:               validationClientCacheKeys(inbound.Clients),
		})
	}
	return keys
}

func validationClientCacheKeys(clients []db.Client) []validationClientCacheKey {
	keys := make([]validationClientCacheKey, 0, len(clients))
	for _, client := range clients {
		keys = append(keys, validationClientCacheKey{
			ID:           client.ID,
			InboundID:    client.InboundID,
			UUID:         client.UUID,
			CredentialID: client.CredentialID,
			Password:     client.Password,
			StatsKey:     client.StatsKey,
			Email:        client.Email,
			Enabled:      client.Enabled,
		})
	}
	return keys
}

func validationOutboundCacheKeys(outbounds []db.Outbound) []validationOutboundCacheKey {
	keys := make([]validationOutboundCacheKey, 0, len(outbounds))
	for _, outbound := range outbounds {
		keys = append(keys, validationOutboundCacheKey{
			ID:             outbound.ID,
			Tag:            outbound.Tag,
			Remark:         outbound.Remark,
			Protocol:       outbound.Protocol,
			Address:        outbound.Address,
			Port:           outbound.Port,
			Username:       outbound.Username,
			Password:       outbound.Password,
			SupportedCores: append([]string(nil), outbound.SupportedCores...),
			Enabled:        outbound.Enabled,
			Sort:           outbound.Sort,
		})
	}
	return keys
}

func validationRoutingRuleCacheKeys(rules []db.RoutingRule) []validationRoutingRuleCacheKey {
	keys := make([]validationRoutingRuleCacheKey, 0, len(rules))
	for _, rule := range rules {
		keys = append(keys, validationRoutingRuleCacheKey{
			ID:          rule.ID,
			InboundID:   rule.InboundID,
			InboundTag:  rule.InboundTag,
			ClientID:    rule.ClientID,
			ClientEmail: rule.ClientEmail,
			OutboundID:  rule.OutboundID,
			OutboundTag: rule.OutboundTag,
			Domain:      rule.Domain,
			IP:          rule.IP,
			RuleSet:     rule.RuleSet,
			Protocol:    rule.Protocol,
			Enabled:     rule.Enabled,
			Sort:        rule.Sort,
		})
	}
	return keys
}

type cpuSample struct {
	Idle  uint64
	Total uint64
}

type cpuPercentSampler struct {
	mu      sync.Mutex
	last    cpuSample
	hasLast bool
	read    func() (cpuSample, error)
}

var defaultCPUSampler = &cpuPercentSampler{read: readCPUSample}

func systemResourcesHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		memTotal, memUsed, memPercent := readMemoryUsage()
		diskTotal, diskUsed, diskPercent := readDiskUsage("/")
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"cpu_percent":    defaultCPUSampler.Sample(),
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

func (s *cpuPercentSampler) Sample() float64 {
	if s == nil {
		return 0
	}
	read := s.read
	if read == nil {
		read = readCPUSample
	}
	current, err := read()
	if err != nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasLast {
		s.last = current
		s.hasLast = true
		return 0
	}
	percent := calculateCPUPercent(s.last, current)
	s.last = current
	return percent
}

func calculateCPUPercent(previous, current cpuSample) float64 {
	if current.Total <= previous.Total {
		return 0
	}
	totalDelta := current.Total - previous.Total
	idleDelta := current.Idle - previous.Idle
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
