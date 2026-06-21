package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/singbox"
)

type fixedSingboxRuntime struct {
	capability singbox.Capability
}

func (r fixedSingboxRuntime) Capability(ctx context.Context) singbox.Capability {
	return r.capability
}

type countingSummaryStore struct {
	inbounds                []db.Inbound
	outbounds               []db.Outbound
	rules                   []db.RoutingRule
	states                  []db.TrafficState
	listInboundsErr         error
	listOutboundsErr        error
	listRulesErr            error
	listInboundsCalls       int
	listInboundTrafficCalls int
	validationHashCalls     int
	validationVersionCalls  int
	validationVersion       int64
	listTrafficStatesCalls  int
	listTrafficSamplesCalls int
}

func (s *countingSummaryStore) ListInbounds(ctx context.Context) ([]db.Inbound, error) {
	s.listInboundsCalls++
	if s.listInboundsErr != nil {
		return nil, s.listInboundsErr
	}
	return s.inbounds, nil
}

func (s *countingSummaryStore) ListInboundTraffic(ctx context.Context) ([]db.Inbound, error) {
	s.listInboundTrafficCalls++
	if s.listInboundsErr != nil {
		return nil, s.listInboundsErr
	}
	return s.inbounds, nil
}

func (s *countingSummaryStore) ValidationConfigHash(ctx context.Context) (string, error) {
	s.validationHashCalls++
	if s.listInboundsErr != nil {
		return "", s.listInboundsErr
	}
	return (validationSnapshot{inbounds: s.inbounds, outbounds: s.outbounds, rules: s.rules}).cacheKey(), nil
}

func (s *countingSummaryStore) ValidationConfigVersion(ctx context.Context) (int64, error) {
	s.validationVersionCalls++
	if s.listInboundsErr != nil {
		return 0, s.listInboundsErr
	}
	if s.validationVersion == 0 {
		s.validationVersion = 1
	}
	return s.validationVersion, nil
}

func (s *countingSummaryStore) InboundExists(ctx context.Context, id int64) (bool, error) {
	for _, inbound := range s.inbounds {
		if inbound.ID == id {
			return true, nil
		}
	}
	return false, nil
}

func (s *countingSummaryStore) FindInboundByPort(ctx context.Context, port int, excludeID int64) (db.Inbound, bool, error) {
	for _, inbound := range s.inbounds {
		if inbound.Port == port && inbound.ID != excludeID {
			return inbound, true, nil
		}
	}
	return db.Inbound{}, false, nil
}

func (s *countingSummaryStore) ListOutbounds(ctx context.Context) ([]db.Outbound, error) {
	if s.listOutboundsErr != nil {
		return nil, s.listOutboundsErr
	}
	return s.outbounds, nil
}

func (s *countingSummaryStore) ListRoutingRules(ctx context.Context) ([]db.RoutingRule, error) {
	if s.listRulesErr != nil {
		return nil, s.listRulesErr
	}
	return s.rules, nil
}

func (s *countingSummaryStore) GetSubscriptionByClientUUID(ctx context.Context, uuid string) (db.Inbound, db.Client, bool, error) {
	return db.Inbound{}, db.Client{}, false, nil
}
func (s *countingSummaryStore) GetSubscriptionByToken(ctx context.Context, token string) (db.Inbound, db.Client, bool, error) {
	return db.Inbound{}, db.Client{}, false, nil
}

func (s *countingSummaryStore) CreateInbound(ctx context.Context, params db.CreateInboundParams) (db.Inbound, error) {
	return db.Inbound{}, errors.New("not implemented")
}

func (s *countingSummaryStore) CreateOutbound(ctx context.Context, params db.CreateOutboundParams) (db.Outbound, error) {
	return db.Outbound{}, errors.New("not implemented")
}

func (s *countingSummaryStore) UpdateOutbound(ctx context.Context, id int64, params db.UpdateOutboundParams) (db.Outbound, error) {
	return db.Outbound{}, errors.New("not implemented")
}

func (s *countingSummaryStore) DeleteOutbound(ctx context.Context, id int64) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) ReorderOutbounds(ctx context.Context, ids []int64) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) ListOutboundSubscriptions(ctx context.Context) ([]db.OutboundSubscription, error) {
	return nil, nil
}

func (s *countingSummaryStore) GetOutboundSubscription(ctx context.Context, id int64) (db.OutboundSubscription, bool, error) {
	return db.OutboundSubscription{}, false, nil
}

func (s *countingSummaryStore) CreateOutboundSubscription(ctx context.Context, params db.CreateOutboundSubscriptionParams) (db.OutboundSubscription, error) {
	return db.OutboundSubscription{}, errors.New("not implemented")
}

func (s *countingSummaryStore) UpdateOutboundSubscription(ctx context.Context, id int64, params db.UpdateOutboundSubscriptionParams) (db.OutboundSubscription, error) {
	return db.OutboundSubscription{}, errors.New("not implemented")
}

func (s *countingSummaryStore) DeleteOutboundSubscription(ctx context.Context, id int64) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) ReorderOutboundSubscriptions(ctx context.Context, ids []int64) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) MarkOutboundSubscriptionFetch(ctx context.Context, id int64, fetchedAt time.Time, lastErr string, identities []string) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) MaterializeSubscriptionOutbounds(ctx context.Context, subscriptionID int64, nodes []db.MaterializedSubscriptionOutbound, identities []string) ([]db.Outbound, error) {
	return nil, errors.New("not implemented")
}

func (s *countingSummaryStore) CreateRoutingRule(ctx context.Context, params db.CreateRoutingRuleParams) (db.RoutingRule, error) {
	return db.RoutingRule{}, errors.New("not implemented")
}

func (s *countingSummaryStore) UpdateRoutingRule(ctx context.Context, id int64, params db.UpdateRoutingRuleParams) (db.RoutingRule, error) {
	return db.RoutingRule{}, errors.New("not implemented")
}

func (s *countingSummaryStore) DeleteRoutingRule(ctx context.Context, id int64) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) ReorderRoutingRules(ctx context.Context, ids []int64) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) CreateClient(ctx context.Context, params db.CreateClientParams) (db.Client, error) {
	return db.Client{}, errors.New("not implemented")
}

func (s *countingSummaryStore) DeleteInbound(ctx context.Context, id int64) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) DeleteClient(ctx context.Context, id int64) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) UpdateInbound(ctx context.Context, id int64, params db.UpdateInboundParams) (db.Inbound, error) {
	return db.Inbound{}, errors.New("not implemented")
}

func (s *countingSummaryStore) UpdateClient(ctx context.Context, id int64, params db.UpdateClientParams) (db.Client, error) {
	return db.Client{}, errors.New("not implemented")
}

func (s *countingSummaryStore) SetInboundEnabled(ctx context.Context, id int64, enabled bool) (db.Inbound, error) {
	return db.Inbound{}, errors.New("not implemented")
}

func (s *countingSummaryStore) SetOutboundEnabled(ctx context.Context, id int64, enabled bool) (db.Outbound, error) {
	return db.Outbound{}, errors.New("not implemented")
}

func (s *countingSummaryStore) SetClientEnabled(ctx context.Context, inboundID int64, id int64, enabled bool) (db.Client, error) {
	return db.Client{}, errors.New("not implemented")
}

func (s *countingSummaryStore) ResetClientTraffic(ctx context.Context, id int64) (db.Client, error) {
	return db.Client{}, errors.New("not implemented")
}

func (s *countingSummaryStore) ResetClientTrafficBaseline(ctx context.Context, id int64, baselines []db.TrafficRawStat) (db.Client, error) {
	return db.Client{}, errors.New("not implemented")
}

func (s *countingSummaryStore) GetClientTrafficUsage(ctx context.Context, statsKey string) (db.ClientTrafficUsage, bool, error) {
	return db.ClientTrafficUsage{}, false, nil
}

func (s *countingSummaryStore) GetClientTrafficUsageForClient(ctx context.Context, clientID int64) (db.ClientTrafficUsage, bool, error) {
	return db.ClientTrafficUsage{}, false, nil
}

func (s *countingSummaryStore) ListTrafficStates(ctx context.Context) ([]db.TrafficState, error) {
	s.listTrafficStatesCalls++
	return s.states, nil
}

func (s *countingSummaryStore) ListTrafficSamples(ctx context.Context, scopeType string, since time.Time, limit int) ([]db.TrafficSample, error) {
	s.listTrafficSamplesCalls++
	return nil, nil
}

func TestTrafficViewCacheSharesInboundsAndStatesAcrossHandlers(t *testing.T) {
	store := &countingSummaryStore{
		inbounds: []db.Inbound{{
			ID:       1,
			Protocol: "vless",
			Enabled:  true,
			Clients:  []db.Client{{ID: 10, StatsKey: "c_state", Email: "user@example.com", Enabled: true}},
		}},
		states: []db.TrafficState{
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_state", TotalUp: 10, TotalDown: 20, Status: "ok", LastSeenAt: "2026-06-17T00:00:00Z"},
		},
	}
	cache := newTrafficViewCache(5 * time.Second)
	now := time.Unix(100, 0)
	cache.now = func() time.Time { return now }

	first, err := cache.get(context.Background(), store)
	if err != nil {
		t.Fatalf("first traffic view: %v", err)
	}
	second, err := cache.get(context.Background(), store)
	if err != nil {
		t.Fatalf("cached traffic view: %v", err)
	}
	if store.listInboundTrafficCalls != 1 || store.listInboundsCalls != 0 || store.listTrafficStatesCalls != 1 {
		t.Fatalf("expected cache hit to avoid repeated scans, traffic_inbounds=%d inbounds=%d states=%d", store.listInboundTrafficCalls, store.listInboundsCalls, store.listTrafficStatesCalls)
	}
	if first.trafficByInbound[1].Up != 10 || second.trafficByClient[10].Down != 20 {
		t.Fatalf("unexpected cached traffic view: first=%+v second=%+v", first, second)
	}

	now = now.Add(6 * time.Second)
	if _, err := cache.get(context.Background(), store); err != nil {
		t.Fatalf("expired traffic view: %v", err)
	}
	if store.listInboundTrafficCalls != 2 || store.listInboundsCalls != 0 || store.listTrafficStatesCalls != 2 {
		t.Fatalf("expected cache expiry to refresh lightweight scans, traffic_inbounds=%d inbounds=%d states=%d", store.listInboundTrafficCalls, store.listInboundsCalls, store.listTrafficStatesCalls)
	}
}

func TestOutboundStatsByProfileIDMapsGeneratedCoreTags(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	states := []db.TrafficState{
		{Engine: "xray", ScopeType: "outbound", ScopeKey: "xray-out-42", TotalUp: 10, TotalDown: 20, RateUp: 1, RateDown: 2, Status: "ok", LastSeenAt: now},
		{Engine: "sing-box", ScopeType: "outbound", ScopeKey: "singbox-out-42", TotalUp: 30, TotalDown: 40, RateUp: 3, RateDown: 4, Status: "ok", LastSeenAt: now},
		{Engine: "xray", ScopeType: "outbound", ScopeKey: "xray-out-44-extra", TotalUp: 99, TotalDown: 99, LastSeenAt: now},
		{Engine: "xray", ScopeType: "outbound", ScopeKey: "direct", TotalUp: 88, TotalDown: 88, LastSeenAt: now},
	}
	mapped := outboundStatsByProfileID(states)
	if len(mapped) != 1 {
		t.Fatalf("expected one generated outbound profile stat, got %+v", mapped)
	}
	if got := mapped[42]; got.Up != 40 || got.Down != 60 || got.RateUp != 4 || got.RateDown != 6 || got.LastSeenAt != now || len(got.Engines) != 2 {
		t.Fatalf("unexpected aggregated outbound profile mapping: %+v", got)
	}
}

func TestOutboundStatsByProfileIDMarksStaleRates(t *testing.T) {
	staleSample := time.Now().UTC().Add(-trafficStateStaleAfter - time.Minute).Format(time.RFC3339)
	stats := outboundStatsByProfileID([]db.TrafficState{
		{Engine: "xray", ScopeType: "outbound", ScopeKey: "xray-out-42", TotalUp: 10, TotalDown: 20, RateUp: 3, RateDown: 4, Status: "ok", LastSeenAt: staleSample},
	})
	got := stats[42]
	if got.Up != 10 || got.Down != 20 || got.RateUp != 0 || got.RateDown != 0 || got.Status != "stale" {
		t.Fatalf("expected stale outbound rates to be zero while keeping totals, got %+v", got)
	}
}

func TestOutboundTrafficDetailsUsesLogicalOutboundTags(t *testing.T) {
	outbounds := []db.Outbound{{ID: 42, Tag: "proxy-a", Remark: "Proxy A", Protocol: "socks", Enabled: true}}
	stats := outboundStatsByProfileID([]db.TrafficState{
		{Engine: "xray", ScopeType: "outbound", ScopeKey: "xray-out-42", TotalUp: 10, TotalDown: 20, RateUp: 1.5, RateDown: 2.5, Status: "ok", LastSeenAt: "2026-06-17T00:00:00Z"},
	})
	details := outboundTrafficDetails(outbounds, stats)
	if len(details) != 1 {
		t.Fatalf("expected one outbound detail, got %+v", details)
	}
	got := details[0]
	if got["id"] != int64(42) || got["tag"] != "proxy-a" || got["traffic_up"] != int64(10) || got["traffic_down"] != int64(20) || got["traffic_engine"] != "xray" || got["traffic_last_seen_at"] != "2026-06-17T00:00:00Z" {
		t.Fatalf("unexpected outbound traffic detail: %+v", got)
	}
}

func TestOutboundTrafficDetailsShowsMixedEnginesForSharedProfile(t *testing.T) {
	outbounds := []db.Outbound{{ID: 42, Tag: "proxy-a", Remark: "Proxy A", Protocol: "socks", Enabled: true}}
	stats := outboundStatsByProfileID([]db.TrafficState{
		{Engine: "xray", ScopeType: "outbound", ScopeKey: "xray-out-42", TotalUp: 10, TotalDown: 20, Status: "ok", LastSeenAt: "2026-06-17T00:00:00Z"},
		{Engine: "singbox", ScopeType: "outbound", ScopeKey: "singbox-out-42", TotalUp: 30, TotalDown: 40, Status: "ok", LastSeenAt: "2026-06-17T00:01:00Z"},
	})
	details := outboundTrafficDetails(outbounds, stats)
	got := details[0]
	if got["traffic_up"] != int64(40) || got["traffic_down"] != int64(60) || got["traffic_total"] != int64(100) || got["traffic_engine"] != "mixed" {
		t.Fatalf("unexpected mixed outbound detail: %+v", got)
	}
	engines, ok := got["traffic_engines"].([]string)
	if !ok || len(engines) != 2 || engines[0] != "xray" || engines[1] != "singbox" {
		t.Fatalf("expected both engines in mixed outbound detail, got %+v", got["traffic_engines"])
	}
}

func TestBuildStatsResponseLoadsTrafficStatesOnceForDetails(t *testing.T) {
	store := &countingSummaryStore{
		inbounds: []db.Inbound{{
			ID:       1,
			Protocol: "vless",
			Clients:  []db.Client{{ID: 10, StatsKey: "c_state", Enabled: true}},
		}},
		outbounds: []db.Outbound{{ID: 42, Tag: "proxy-a", Protocol: "socks", Enabled: true}},
		states: []db.TrafficState{
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_state", TotalUp: 10, TotalDown: 20, Status: "ok", LastSeenAt: "2026-06-17T00:00:00Z"},
			{Engine: "xray", ScopeType: "outbound", ScopeKey: "xray-out-42", TotalUp: 30, TotalDown: 40, Status: "ok", LastSeenAt: "2026-06-17T00:00:00Z"},
		},
	}
	response, err := buildStatsResponse(context.Background(), store, nil, true)
	if err != nil {
		t.Fatalf("build stats response: %v", err)
	}
	if store.listTrafficStatesCalls != 1 {
		t.Fatalf("expected detail response to load traffic states once, got %d", store.listTrafficStatesCalls)
	}
	if response["outbound_details"] == nil {
		t.Fatalf("expected outbound details in detail response: %+v", response)
	}
}

func TestBuildDashboardSummaryDoesNotLoadTrafficStates(t *testing.T) {
	store := &countingSummaryStore{
		inbounds: []db.Inbound{{
			ID:       1,
			Protocol: "vless",
			Clients:  []db.Client{{ID: 10, StatsKey: "c_state", Enabled: true}},
		}},
		outbounds: []db.Outbound{{ID: 42, Tag: "proxy-a", Protocol: "socks", Enabled: true}},
		states: []db.TrafficState{
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_state", TotalUp: 10, TotalDown: 20, Status: "ok", LastSeenAt: "2026-06-17T00:00:00Z"},
			{Engine: "xray", ScopeType: "outbound", ScopeKey: "xray-out-42", TotalUp: 30, TotalDown: 40, Status: "ok", LastSeenAt: "2026-06-17T00:00:00Z"},
		},
	}
	cfg := &routerConfig{store: store, singboxRuntime: fixedSingboxRuntime{capability: singbox.Capability{V2RayAPIStats: true, Checked: true}}}
	summary, err := buildDashboardSummary(context.Background(), cfg)
	if err != nil {
		t.Fatalf("build dashboard summary: %v", err)
	}
	if store.listTrafficStatesCalls != 0 {
		t.Fatalf("dashboard summary should not load traffic states, got %d calls", store.listTrafficStatesCalls)
	}
	if _, ok := summary["outbound_traffic"]; ok {
		t.Fatalf("dashboard summary should not include outbound_traffic: %+v", summary)
	}
}

func (s *countingSummaryStore) ApplyTrafficRawStats(ctx context.Context, stats []db.TrafficRawStat, observedAt time.Time) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) MarkTrafficUnavailable(ctx context.Context, engine, status, message string, observedAt time.Time) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) AddToBlacklist(ctx context.Context, tokenHash string, expiresAt time.Time, revoked bool) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) IsBlacklisted(ctx context.Context, tokenHash string) (bool, error) {
	return false, errors.New("not implemented")
}

func (s *countingSummaryStore) RecordSessionTouch(ctx context.Context, tokenHash string) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) PruneActiveSessions(ctx context.Context, maxActive int) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) ListActiveSessions(ctx context.Context) ([]db.BlacklistedSession, error) {
	return nil, errors.New("not implemented")
}

func (s *countingSummaryStore) RevokeSession(ctx context.Context, id int64) error {
	return errors.New("not implemented")
}

func (s *countingSummaryStore) RevokeOtherSessions(ctx context.Context, currentTokenHash string) (int64, error) {
	return 0, errors.New("not implemented")
}

func TestDashboardSummaryCacheHitsExpiresAndRetriesErrors(t *testing.T) {
	store := &countingSummaryStore{
		inbounds: []db.Inbound{{
			ID:       1,
			Remark:   "cached",
			Protocol: "vless",
			Port:     443,
			Network:  "tcp",
			Security: "none",
			Enabled:  true,
			Clients:  []db.Client{{ID: 10, InboundID: 1, UUID: "uuid", Email: "a@example.com", Enabled: true}},
		}},
		outbounds: []db.Outbound{{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true}},
	}
	cache := newDashboardSummaryCache(5*time.Second, 30*time.Second)
	cfg := &routerConfig{store: store, singboxRuntime: fixedSingboxRuntime{capability: singbox.Capability{V2RayAPIStats: true, Checked: true}}}
	now := time.Unix(100, 0)
	cache.now = func() time.Time { return now }

	first, err := cache.get(context.Background(), cfg)
	if err != nil {
		t.Fatalf("first summary: %v", err)
	}
	second, err := cache.get(context.Background(), cfg)
	if err != nil {
		t.Fatalf("cached summary: %v", err)
	}
	if store.listInboundsCalls != 1 || store.listInboundTrafficCalls != 1 || store.validationVersionCalls != 1 || store.validationHashCalls != 0 {
		t.Fatalf("expected first build to read version, full validation, and lightweight summary once, full=%d light=%d version=%d hash=%d", store.listInboundsCalls, store.listInboundTrafficCalls, store.validationVersionCalls, store.validationHashCalls)
	}
	if first["generated_at"] != second["generated_at"] {
		t.Fatalf("expected cached generated_at to be reused: first=%v second=%v", first["generated_at"], second["generated_at"])
	}

	now = now.Add(6 * time.Second)
	if _, err := cache.get(context.Background(), cfg); err != nil {
		t.Fatalf("expired summary: %v", err)
	}
	if store.listInboundsCalls != 1 || store.listInboundTrafficCalls != 2 || store.validationVersionCalls != 2 || store.validationHashCalls != 0 {
		t.Fatalf("expected summary expiry with unchanged validation version to avoid full validation snapshot, full=%d light=%d version=%d hash=%d", store.listInboundsCalls, store.listInboundTrafficCalls, store.validationVersionCalls, store.validationHashCalls)
	}

	failing := &countingSummaryStore{listInboundsErr: errors.New("boom")}
	failingCfg := &routerConfig{store: failing, singboxRuntime: fixedSingboxRuntime{capability: singbox.Capability{V2RayAPIStats: true, Checked: true}}}
	failingCache := newDashboardSummaryCache(5 * time.Second)
	if _, err := failingCache.get(context.Background(), failingCfg); err == nil {
		t.Fatal("expected error from empty cache")
	}
	if _, err := failingCache.get(context.Background(), failingCfg); err == nil {
		t.Fatal("expected retry to call failing store again")
	}
	if failing.listInboundTrafficCalls != 2 {
		t.Fatalf("expected failed summaries not to be cached, got %d lightweight calls", failing.listInboundTrafficCalls)
	}
}

func TestDashboardSummaryValidationCacheRefreshesWhenLightConfigChanges(t *testing.T) {
	store := &countingSummaryStore{
		outbounds: []db.Outbound{{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true}},
	}
	cache := newDashboardSummaryCache(2*time.Second, 30*time.Second)
	cfg := &routerConfig{store: store, singboxRuntime: fixedSingboxRuntime{capability: singbox.Capability{V2RayAPIStats: true, Checked: true}}}
	now := time.Unix(100, 0)
	cache.now = func() time.Time { return now }

	first, err := cache.get(context.Background(), cfg)
	if err != nil {
		t.Fatalf("first summary: %v", err)
	}
	firstValidation := first["validation"].(map[string]configValidationResult)
	if firstValidation["singbox"].Inbounds != 0 {
		t.Fatalf("expected initial singbox validation to have no inbounds, got %+v", firstValidation["singbox"])
	}

	store.inbounds = []db.Inbound{{
		ID:       2,
		Remark:   "hy2",
		Protocol: "hysteria2",
		Port:     8443,
		Network:  "udp",
		Security: "tls",
		Enabled:  true,
		Clients:  []db.Client{{ID: 20, InboundID: 2, UUID: "client-uuid", Email: "hy2@example.com", Enabled: true}},
	}}
	store.validationVersion++
	now = now.Add(3 * time.Second)
	second, err := cache.get(context.Background(), cfg)
	if err != nil {
		t.Fatalf("second summary: %v", err)
	}
	secondValidation := second["validation"].(map[string]configValidationResult)
	if secondValidation["singbox"].Inbounds == firstValidation["singbox"].Inbounds {
		t.Fatalf("expected validation cache to refresh for changed lightweight config key, first=%+v second=%+v", firstValidation["singbox"], secondValidation["singbox"])
	}
	if secondValidation["singbox"].Inbounds != 1 {
		t.Fatalf("expected changed snapshot to rebuild singbox validation, got %+v", secondValidation["singbox"])
	}
}

func TestDashboardValidationCacheKeyIgnoresClientRuntimeTraffic(t *testing.T) {
	snapshot := validationSnapshot{
		inbounds: []db.Inbound{{
			ID:       1,
			UUID:     "inbound-uuid",
			Remark:   "edge",
			Protocol: "vless",
			Port:     443,
			Network:  "tcp",
			Security: "none",
			Enabled:  true,
			Clients: []db.Client{{
				ID:           10,
				InboundID:    1,
				UUID:         "client-uuid",
				CredentialID: "client-credential",
				Password:     "client-password",
				StatsKey:     "client-stats",
				Email:        "client@example.com",
				Enabled:      true,
				Up:           100,
				Down:         200,
				TrafficLimit: 1024,
				ExpiryAt:     1893456000,
			}},
		}},
		outbounds: []db.Outbound{{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true}},
		rules:     []db.RoutingRule{{ID: 1, InboundTag: "edge", OutboundID: 1, OutboundTag: "direct", Enabled: true}},
	}
	changed := snapshot
	changed.inbounds = append([]db.Inbound(nil), snapshot.inbounds...)
	changed.inbounds[0].Clients = append([]db.Client(nil), snapshot.inbounds[0].Clients...)
	changed.inbounds[0].Clients[0].Up = 999
	changed.inbounds[0].Clients[0].Down = 888

	if snapshot.cacheKey() != changed.cacheKey() {
		t.Fatal("client runtime up/down changes should not invalidate dashboard validation cache key")
	}
}

func TestDashboardSummaryValidationCacheReusesWhenOnlyRuntimeTrafficChanges(t *testing.T) {
	store := &countingSummaryStore{
		inbounds: []db.Inbound{{
			ID:       1,
			Remark:   "runtime",
			Protocol: "hysteria2",
			Port:     8443,
			Network:  "udp",
			Security: "tls",
			Enabled:  true,
			Clients:  []db.Client{{ID: 10, InboundID: 1, UUID: "client-uuid", Password: "secret", StatsKey: "c_state", Email: "a@example.com", Enabled: true, Up: 10, Down: 20}},
		}},
		outbounds: []db.Outbound{{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true}},
	}
	cache := newDashboardSummaryCache(2*time.Second, 30*time.Second)
	cfg := &routerConfig{store: store, singboxRuntime: fixedSingboxRuntime{capability: singbox.Capability{V2RayAPIStats: true, Checked: true}}}
	now := time.Unix(100, 0)
	cache.now = func() time.Time { return now }

	first, err := cache.get(context.Background(), cfg)
	if err != nil {
		t.Fatalf("first summary: %v", err)
	}
	_ = first
	firstValidationExpiresAt := cache.validationExpiresAt
	store.inbounds[0].Clients[0].Up = 12345
	store.inbounds[0].Clients[0].Down = 67890
	now = now.Add(3 * time.Second)

	if _, err := cache.get(context.Background(), cfg); err != nil {
		t.Fatalf("second summary: %v", err)
	}
	if !cache.validationExpiresAt.Equal(firstValidationExpiresAt) {
		t.Fatalf("expected validation cache to be reused for runtime-only traffic changes, first expiry=%s second expiry=%s", firstValidationExpiresAt, cache.validationExpiresAt)
	}
	if store.listInboundsCalls != 1 || store.listInboundTrafficCalls != 2 {
		t.Fatalf("expected runtime-only summary refresh to reuse validation without full snapshot, full=%d light=%d", store.listInboundsCalls, store.listInboundTrafficCalls)
	}
}

func TestDashboardSummaryValidationCacheRefreshesWhenFullConfigOnlyFieldsChange(t *testing.T) {
	baseInbound := db.Inbound{
		ID:             1,
		UUID:           "inbound-uuid",
		Remark:         "edge",
		Protocol:       "vless",
		Core:           db.CoreXray,
		Port:           443,
		Network:        "ws",
		Security:       "tls",
		Enabled:        true,
		WsPath:         "/ws",
		TLSCertFile:    "/cert.pem",
		TLSKeyFile:     "/key.pem",
		RealityDest:    "example.com:443",
		RealityShortID: "abcd",
		Clients: []db.Client{{
			ID:           10,
			InboundID:    1,
			UUID:         "client-uuid",
			CredentialID: "client-credential",
			Password:     "client-password",
			StatsKey:     "client-stats",
			Email:        "client@example.com",
			Enabled:      true,
		}},
	}
	cases := []struct {
		name   string
		change func(*db.Inbound)
	}{
		{name: "ws path", change: func(inbound *db.Inbound) { inbound.WsPath = "/changed" }},
		{name: "tls cert", change: func(inbound *db.Inbound) { inbound.TLSCertFile = "/changed-cert.pem" }},
		{name: "tls key", change: func(inbound *db.Inbound) { inbound.TLSKeyFile = "/changed-key.pem" }},
		{name: "reality dest", change: func(inbound *db.Inbound) { inbound.RealityDest = "changed.example.com:443" }},
		{name: "reality short id", change: func(inbound *db.Inbound) { inbound.RealityShortID = "dcba" }},
		{name: "client credential", change: func(inbound *db.Inbound) { inbound.Clients[0].CredentialID = "changed-credential" }},
		{name: "client password", change: func(inbound *db.Inbound) { inbound.Clients[0].Password = "changed-password" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inbound := baseInbound
			inbound.Clients = append([]db.Client(nil), baseInbound.Clients...)
			store := &countingSummaryStore{
				inbounds:          []db.Inbound{inbound},
				outbounds:         []db.Outbound{{ID: 1, Tag: "direct", Protocol: "freedom", Enabled: true}},
				validationVersion: 1,
			}
			cache := newDashboardSummaryCache(2*time.Second, 30*time.Second)
			cfg := &routerConfig{store: store, singboxRuntime: fixedSingboxRuntime{capability: singbox.Capability{V2RayAPIStats: true, Checked: true}}}
			now := time.Unix(100, 0)
			cache.now = func() time.Time { return now }

			if _, err := cache.get(context.Background(), cfg); err != nil {
				t.Fatalf("first summary: %v", err)
			}
			firstValidationExpiresAt := cache.validationExpiresAt
			firstVersionKey := cache.validationKey
			changed := store.inbounds[0]
			changed.Clients = append([]db.Client(nil), store.inbounds[0].Clients...)
			tc.change(&changed)
			store.inbounds[0] = changed
			store.validationVersion++
			if cache.validationKey == fmt.Sprintf("v:%d", store.validationVersion) || firstVersionKey == "" {
				t.Fatalf("%s test did not start from a stable validation version key", tc.name)
			}
			now = now.Add(3 * time.Second)

			if _, err := cache.get(context.Background(), cfg); err != nil {
				t.Fatalf("second summary: %v", err)
			}
			if !cache.validationExpiresAt.After(firstValidationExpiresAt) {
				t.Fatalf("expected %s change to rebuild validation cache, first expiry=%s second expiry=%s", tc.name, firstValidationExpiresAt, cache.validationExpiresAt)
			}
			if cache.validationKey != fmt.Sprintf("v:%d", store.validationVersion) {
				t.Fatalf("expected %s change to store new validation version key, got %q", tc.name, cache.validationKey)
			}
			if store.listInboundsCalls != 2 || store.listInboundTrafficCalls != 2 || store.validationVersionCalls != 2 || store.validationHashCalls != 0 {
				t.Fatalf("expected hidden config version change to read full snapshot inside validation TTL, full=%d light=%d version=%d hash=%d", store.listInboundsCalls, store.listInboundTrafficCalls, store.validationVersionCalls, store.validationHashCalls)
			}
		})
	}
}

func TestDashboardValidationCacheKeyChangesForConfigFields(t *testing.T) {
	base := validationSnapshot{
		inbounds: []db.Inbound{{
			ID:             1,
			UUID:           "inbound-uuid",
			Remark:         "edge",
			Protocol:       "vless",
			Core:           db.CoreXray,
			Port:           443,
			Network:        "tcp",
			Security:       "none",
			Enabled:        true,
			WsPath:         "/ws",
			TLSCertFile:    "/cert.pem",
			TLSKeyFile:     "/key.pem",
			RealityDest:    "example.com:443",
			RealityShortID: "abcd",
			Clients: []db.Client{{
				ID:           10,
				InboundID:    1,
				UUID:         "client-uuid",
				CredentialID: "client-credential",
				Password:     "client-password",
				StatsKey:     "client-stats",
				Email:        "client@example.com",
				Enabled:      true,
				Up:           10,
				Down:         20,
			}},
		}},
		outbounds: []db.Outbound{{
			ID:             1,
			Tag:            "direct",
			Protocol:       "freedom",
			Address:        "127.0.0.1",
			Port:           1080,
			Username:       "user",
			Password:       "pass",
			SupportedCores: []string{db.CoreXray, db.CoreSingbox},
			Enabled:        true,
			Sort:           1,
		}},
		rules: []db.RoutingRule{{
			ID:          1,
			InboundID:   1,
			InboundTag:  "edge",
			ClientID:    10,
			ClientEmail: "client@example.com",
			OutboundID:  1,
			OutboundTag: "direct",
			Domain:      "example.com",
			IP:          "geoip:private",
			RuleSet:     "ads",
			Protocol:    "bittorrent",
			Enabled:     true,
			Sort:        1,
		}},
	}
	baseKey := base.cacheKey()
	cases := []struct {
		name   string
		change func(*validationSnapshot)
	}{
		{name: "inbound port", change: func(s *validationSnapshot) { s.inbounds[0].Port = 8443 }},
		{name: "inbound protocol", change: func(s *validationSnapshot) { s.inbounds[0].Protocol = "trojan" }},
		{name: "inbound enabled", change: func(s *validationSnapshot) { s.inbounds[0].Enabled = false }},
		{name: "client enabled", change: func(s *validationSnapshot) { s.inbounds[0].Clients[0].Enabled = false }},
		{name: "client credential", change: func(s *validationSnapshot) { s.inbounds[0].Clients[0].CredentialID = "new-credential" }},
		{name: "client password", change: func(s *validationSnapshot) { s.inbounds[0].Clients[0].Password = "new-password" }},
		{name: "client stats key", change: func(s *validationSnapshot) { s.inbounds[0].Clients[0].StatsKey = "new-stats" }},
		{name: "outbound tag", change: func(s *validationSnapshot) { s.outbounds[0].Tag = "proxy" }},
		{name: "outbound protocol", change: func(s *validationSnapshot) { s.outbounds[0].Protocol = "socks" }},
		{name: "routing inbound id", change: func(s *validationSnapshot) { s.rules[0].InboundID = 2 }},
		{name: "routing inbound", change: func(s *validationSnapshot) { s.rules[0].InboundTag = "other" }},
		{name: "routing outbound", change: func(s *validationSnapshot) { s.rules[0].OutboundTag = "proxy" }},
		{name: "routing domain", change: func(s *validationSnapshot) { s.rules[0].Domain = "example.org" }},
		{name: "routing enabled", change: func(s *validationSnapshot) { s.rules[0].Enabled = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := cloneValidationSnapshotForTest(base)
			tc.change(&changed)
			if changed.cacheKey() == baseKey {
				t.Fatalf("expected %s change to invalidate validation cache key", tc.name)
			}
		})
	}
}

func TestStoreValidationConfigHashMatchesDashboardSnapshotKey(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{
		Remark:         "hash",
		Protocol:       "vless",
		Port:           28443,
		Network:        "ws",
		Security:       "tls",
		WsPath:         "/ws",
		TLSCertFile:    "/cert.pem",
		TLSKeyFile:     "/key.pem",
		RealityDest:    "example.com:443",
		RealityShortID: "abcd",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	if _, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "client@example.com", Password: "secret"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	outbound, err := store.CreateOutbound(ctx, db.CreateOutboundParams{Tag: "proxy", Remark: "proxy", Protocol: "socks", Address: "127.0.0.1", Port: 1080, Username: "user", Password: "pass"})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}
	if _, err := store.CreateRoutingRule(ctx, db.CreateRoutingRuleParams{InboundID: inbound.ID, OutboundID: outbound.ID, OutboundTag: outbound.Tag, Domain: "example.com", Enabled: true}); err != nil {
		t.Fatalf("create routing rule: %v", err)
	}
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	outbounds, err := store.ListOutbounds(ctx)
	if err != nil {
		t.Fatalf("list outbounds: %v", err)
	}
	rules, err := store.ListRoutingRules(ctx)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	want := (validationSnapshot{inbounds: inbounds, outbounds: outbounds, rules: rules}).cacheKey()
	got, err := store.ValidationConfigHash(ctx)
	if err != nil {
		t.Fatalf("validation config hash: %v", err)
	}
	if got != want {
		t.Fatalf("validation config hash mismatch\ngot  %s\nwant %s", got, want)
	}
}

func cloneValidationSnapshotForTest(snapshot validationSnapshot) validationSnapshot {
	clone := validationSnapshot{
		inbounds:  append([]db.Inbound(nil), snapshot.inbounds...),
		outbounds: append([]db.Outbound(nil), snapshot.outbounds...),
		rules:     append([]db.RoutingRule(nil), snapshot.rules...),
	}
	for i := range clone.inbounds {
		clone.inbounds[i].Clients = append([]db.Client(nil), clone.inbounds[i].Clients...)
	}
	for i := range clone.outbounds {
		clone.outbounds[i].SupportedCores = append([]string(nil), clone.outbounds[i].SupportedCores...)
	}
	return clone
}

func TestCoreStatusCacheHitsAndInvalidates(t *testing.T) {
	cache := newCoreStatusCache(5 * time.Second)
	now := time.Unix(100, 0)
	cache.now = func() time.Time { return now }
	calls := 0
	handler := cache.wrap("xray-status", func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeJSON(w, http.StatusOK, map[string]interface{}{"calls": calls})
	})

	first := httptest.NewRecorder()
	handler(first, httptest.NewRequest(http.MethodGet, "/api/xray/status", nil))
	second := httptest.NewRecorder()
	handler(second, httptest.NewRequest(http.MethodGet, "/api/xray/status", nil))
	if calls != 1 || first.Body.String() != second.Body.String() {
		t.Fatalf("expected cached response to be reused, calls=%d first=%s second=%s", calls, first.Body.String(), second.Body.String())
	}
	cache.invalidate("xray-status")
	third := httptest.NewRecorder()
	handler(third, httptest.NewRequest(http.MethodGet, "/api/xray/status", nil))
	if calls != 2 {
		t.Fatalf("expected invalidated cache to call handler again, calls=%d body=%s", calls, third.Body.String())
	}
}

func TestSummarizeTrafficSelectsExpectedEngineForSharedStatsKey(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	store := &countingSummaryStore{
		states: []db.TrafficState{
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_state", TotalUp: 10, TotalDown: 20, RateUp: 1, RateDown: 2, Status: "ok", LastSeenAt: now},
			{Engine: "singbox", ScopeType: "client", ScopeKey: "c_state", TotalUp: 30, TotalDown: 40, RateUp: 3, RateDown: 4, Status: "ok", LastSeenAt: now},
		},
	}
	inbounds := []db.Inbound{
		{ID: 1, Protocol: "vless", Enabled: true, Clients: []db.Client{{ID: 10, StatsKey: "c_state", Email: "xray@example.com", Enabled: true}}},
		{ID: 2, Protocol: "hysteria2", Enabled: true, Clients: []db.Client{{ID: 20, StatsKey: "c_state", Email: "hy2@example.com", Enabled: true}}},
	}
	trafficByInbound, trafficByClient := summarizeTraffic(context.Background(), store, inbounds)
	xrayClient := trafficByClient[10]
	if xrayClient.Status != "ok" || xrayClient.Up != 10 || xrayClient.Down != 20 || xrayClient.Engine != "xray" {
		t.Fatalf("expected xray inbound to select xray state, got %+v", xrayClient)
	}
	singboxClient := trafficByClient[20]
	if singboxClient.Status != "ok" || singboxClient.Up != 30 || singboxClient.Down != 40 || singboxClient.Engine != "singbox" {
		t.Fatalf("expected sing-box inbound to select singbox state, got %+v", singboxClient)
	}
	if trafficByInbound[1].Engine != "xray" || trafficByInbound[2].Engine != "singbox" {
		t.Fatalf("expected inbound summaries to keep expected engines, got xray=%+v singbox=%+v", trafficByInbound[1], trafficByInbound[2])
	}
}

func TestSummarizeTrafficKeepsExpectedEngineEvenWhenUnavailable(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	store := &countingSummaryStore{
		states: []db.TrafficState{
			{Engine: "singbox", ScopeType: "client", ScopeKey: "c_state", TotalUp: 10, TotalDown: 20, Status: "unavailable", LastSeenAt: now},
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_state", TotalUp: 30, TotalDown: 40, Status: "ok", LastSeenAt: now},
		},
	}
	inbounds := []db.Inbound{{ID: 1, Protocol: "hysteria2", Enabled: true, Clients: []db.Client{{ID: 10, StatsKey: "c_state", Email: "user@example.com", Enabled: true}}}}
	_, trafficByClient := summarizeTraffic(context.Background(), store, inbounds)
	client := trafficByClient[10]
	if client.Status != "unavailable" || client.Up != 10 || client.Down != 20 || client.Engine != "singbox" {
		t.Fatalf("expected expected singbox unavailable state, got %+v", client)
	}
}

func TestSummarizeTrafficFallsBackWhenExpectedEngineMissing(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	store := &countingSummaryStore{
		states: []db.TrafficState{
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_state", TotalUp: 30, TotalDown: 40, Status: "ok", LastSeenAt: now},
		},
	}
	inbounds := []db.Inbound{{ID: 1, Protocol: "hysteria2", Enabled: true, Clients: []db.Client{{ID: 10, StatsKey: "c_state", Email: "user@example.com", Enabled: true}}}}
	_, trafficByClient := summarizeTraffic(context.Background(), store, inbounds)
	client := trafficByClient[10]
	if client.Status != "ok" || client.Up != 30 || client.Down != 40 || client.Engine != "xray" {
		t.Fatalf("expected deterministic fallback when singbox state is missing, got %+v", client)
	}
}

func TestSummarizeTrafficMarksStaleSamples(t *testing.T) {
	staleAt := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339Nano)
	store := &countingSummaryStore{
		states: []db.TrafficState{
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_stale", TotalUp: 30, TotalDown: 40, RateUp: 3, RateDown: 4, Status: "ok", LastSeenAt: staleAt},
		},
	}
	inbounds := []db.Inbound{{ID: 1, Protocol: "vless", Enabled: true, Clients: []db.Client{{ID: 10, StatsKey: "c_stale", Email: "user@example.com", Enabled: true}}}}
	trafficByInbound, trafficByClient := summarizeTraffic(context.Background(), store, inbounds)
	client := trafficByClient[10]
	if client.Status != "stale" || client.RateUp != 0 || client.RateDown != 0 || client.LastSampledAt == "" {
		t.Fatalf("expected stale client state with zero rates, got %+v", client)
	}
	if trafficByInbound[1].Status != "stale" || trafficByInbound[1].RateUp != 0 || trafficByInbound[1].RateDown != 0 {
		t.Fatalf("expected inbound aggregate to inherit stale status and zero rates, got %+v", trafficByInbound[1])
	}
}

func TestSummarizeTrafficAggregatesClientTotalsWhenOnlyClientStateExists(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	store := &countingSummaryStore{
		states: []db.TrafficState{
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_only", TotalUp: 30, TotalDown: 40, RateUp: 3, RateDown: 4, Status: "waiting", LastSeenAt: now},
		},
	}
	inbounds := []db.Inbound{{ID: 1, Protocol: "vless", Enabled: true, Clients: []db.Client{{ID: 10, StatsKey: "c_only", Email: "user@example.com", Enabled: true}}}}
	trafficByInbound, trafficByClient := summarizeTraffic(context.Background(), store, inbounds)
	client := trafficByClient[10]
	if client.Status != "waiting" || client.Up != 30 || client.Down != 40 {
		t.Fatalf("expected waiting client totals to be preserved, got %+v", client)
	}
	inbound := trafficByInbound[1]
	if inbound.Status != "waiting" || inbound.Up != 30 || inbound.Down != 40 || inbound.Total != 70 || inbound.RateUp != 3 || inbound.RateDown != 4 {
		t.Fatalf("expected inbound to aggregate client-only traffic state, got %+v", inbound)
	}
}

func TestSummarizeTrafficUsesClientEmailWhenStatsKeyIsEmpty(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	store := &countingSummaryStore{
		states: []db.TrafficState{
			{Engine: "xray", ScopeType: "client", ScopeKey: "legacy@example.com", TotalUp: 12, TotalDown: 34, Status: "waiting", LastSeenAt: now},
		},
	}
	inbounds := []db.Inbound{{ID: 1, Protocol: "vless", Enabled: true, Clients: []db.Client{{ID: 10, Email: "legacy@example.com", Enabled: true}}}}
	trafficByInbound, trafficByClient := summarizeTraffic(context.Background(), store, inbounds)
	client := trafficByClient[10]
	if client.Status != "waiting" || client.Up != 12 || client.Down != 34 {
		t.Fatalf("expected email-keyed client state to be selected, got %+v", client)
	}
	inbound := trafficByInbound[1]
	if inbound.Status != "waiting" || inbound.Up != 12 || inbound.Down != 34 || inbound.Total != 46 {
		t.Fatalf("expected inbound to aggregate email-keyed client state, got %+v", inbound)
	}
}

func TestTrafficSummaryKeepsClientTotalsWhenOnlyClientStateExists(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	store := &countingSummaryStore{
		inbounds: []db.Inbound{{
			ID:       1,
			Protocol: "vless",
			Enabled:  true,
			Clients:  []db.Client{{ID: 10, StatsKey: "c_only", Email: "user@example.com", Enabled: true}},
		}},
		states: []db.TrafficState{
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_only", TotalUp: 30, TotalDown: 40, Status: "waiting", LastSeenAt: now},
		},
	}
	response := httptest.NewRecorder()
	trafficSummaryHandler(store, newTrafficViewCache(0))(response, httptest.NewRequest(http.MethodGet, "/api/traffic/summary", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected traffic summary status 200, got %d body=%s", response.Code, response.Body.String())
	}
	var payload map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode summary response: %v", err)
	}
	if payload["total"] != float64(70) || payload["total_up"] != float64(30) || payload["total_down"] != float64(40) {
		t.Fatalf("expected traffic summary to retain client totals, got %+v", payload)
	}
}

func TestSummarizeTrafficKeepsXrayWaitingMarkerFreshWithCumulativeTotals(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	store := &countingSummaryStore{
		states: []db.TrafficState{
			{Engine: "xray", ScopeType: "inbound", ScopeKey: "inbound-1-vless", TotalUp: 30, TotalDown: 40, RateUp: 0, RateDown: 0, Status: "waiting", LastSeenAt: now},
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_waiting", TotalUp: 30, TotalDown: 40, RateUp: 0, RateDown: 0, Status: "waiting", LastSeenAt: now},
		},
	}
	inbounds := []db.Inbound{{ID: 1, Protocol: "vless", Enabled: true, Clients: []db.Client{{ID: 10, StatsKey: "c_waiting", Email: "user@example.com", Enabled: true}}}}
	trafficByInbound, trafficByClient := summarizeTraffic(context.Background(), store, inbounds)
	client := trafficByClient[10]
	if client.Status != "waiting" || client.Up != 30 || client.Down != 40 || client.RateUp != 0 || client.RateDown != 0 {
		t.Fatalf("expected fresh waiting client with cumulative totals, got %+v", client)
	}
	inbound := trafficByInbound[1]
	if inbound.Status != "waiting" || inbound.Up != 30 || inbound.Down != 40 || inbound.RateUp != 0 || inbound.RateDown != 0 {
		t.Fatalf("expected fresh waiting inbound state instead of stale, got %+v", inbound)
	}
	coverage := buildTrafficCoverage(trafficByInbound)
	engines := coverage["engines"].(map[string]string)
	if coverage["overall"] != "waiting" || engines["xray"] != "waiting" || coverage["stale"] != 0 {
		t.Fatalf("waiting xray marker should not produce stale coverage, got %+v", coverage)
	}
}

func TestSummarizeTrafficAggregatesClientUnavailableWhenNoInboundStateExists(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	store := &countingSummaryStore{
		states: []db.TrafficState{
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_unavailable", TotalUp: 30, TotalDown: 40, RateUp: 0, RateDown: 0, Status: "unavailable", Message: "stats offline", LastSeenAt: now},
		},
	}
	inbounds := []db.Inbound{{ID: 1, Protocol: "vless", Enabled: true, Clients: []db.Client{{ID: 10, StatsKey: "c_unavailable", Email: "user@example.com", Enabled: true}}}}
	trafficByInbound, trafficByClient := summarizeTraffic(context.Background(), store, inbounds)
	client := trafficByClient[10]
	if client.Status != "unavailable" || client.Up != 30 || client.Down != 40 || client.Message != "stats offline" {
		t.Fatalf("expected unavailable client state with totals, got %+v", client)
	}
	inbound := trafficByInbound[1]
	if inbound.Status != "unavailable" || inbound.Up != 30 || inbound.Down != 40 || inbound.Total != 70 || inbound.RateUp != 0 || inbound.RateDown != 0 {
		t.Fatalf("expected inbound to aggregate unavailable client state without zeroing totals, got %+v", inbound)
	}
	coverage := buildTrafficCoverage(trafficByInbound)
	engines := coverage["engines"].(map[string]string)
	if coverage["overall"] != "unavailable" || engines["xray"] != "unavailable" {
		t.Fatalf("dashboard coverage should surface unavailable xray status, got %+v", coverage)
	}
}

func TestSummarizeTrafficMarksInboundPartialWhenSomeClientsAreWaiting(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	store := &countingSummaryStore{
		states: []db.TrafficState{
			{Engine: "xray", ScopeType: "inbound", ScopeKey: "inbound-1-vless", TotalUp: 100, TotalDown: 200, RateUp: 10, RateDown: 20, Status: "ok", LastSeenAt: now},
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_ok", TotalUp: 60, TotalDown: 80, RateUp: 6, RateDown: 8, Status: "ok", LastSeenAt: now},
			{Engine: "xray", ScopeType: "client", ScopeKey: "c_waiting", TotalUp: 40, TotalDown: 120, RateUp: 0, RateDown: 0, Status: "waiting", LastSeenAt: now},
		},
	}
	inbounds := []db.Inbound{{
		ID:       1,
		Protocol: "vless",
		Enabled:  true,
		Clients: []db.Client{
			{ID: 10, StatsKey: "c_ok", Email: "ok@example.com", Enabled: true},
			{ID: 11, StatsKey: "c_waiting", Email: "waiting@example.com", Enabled: true},
		},
	}}
	trafficByInbound, trafficByClient := summarizeTraffic(context.Background(), store, inbounds)
	if trafficByClient[10].Status != "ok" || trafficByClient[11].Status != "waiting" {
		t.Fatalf("expected client statuses ok/waiting, got ok=%+v waiting=%+v", trafficByClient[10], trafficByClient[11])
	}
	inbound := trafficByInbound[1]
	if inbound.Status != "partial" || inbound.Up != 100 || inbound.Down != 200 || inbound.RateUp != 10 || inbound.RateDown != 20 {
		t.Fatalf("inbound with ok state and waiting client should be partial without changing inbound totals/rates, got %+v", inbound)
	}
	coverage := buildTrafficCoverage(trafficByInbound)
	engines := coverage["engines"].(map[string]string)
	if coverage["overall"] != "partial" || engines["xray"] != "partial" {
		t.Fatalf("dashboard coverage should surface partial xray status, got %+v", coverage)
	}
}

func TestBuildTrafficCoverageNormalizesSingBoxEngineKey(t *testing.T) {
	coverage := buildTrafficCoverage(map[int64]inboundTrafficSummary{
		1: {Engine: "sing-box", Status: "ok"},
	})
	engines, ok := coverage["engines"].(map[string]string)
	if !ok {
		t.Fatalf("expected engines map, got %#v", coverage["engines"])
	}
	if engines["singbox"] != "ok" {
		t.Fatalf("expected normalized singbox status, got %+v", engines)
	}
	if _, exists := engines["sing-box"]; exists {
		t.Fatalf("did not expect dashed sing-box key: %+v", engines)
	}
}

func TestBuildTrafficCoverageAggregatesEngineStatusDeterministically(t *testing.T) {
	for i := 0; i < 20; i++ {
		coverage := buildTrafficCoverage(map[int64]inboundTrafficSummary{
			1: {Engine: "xray", Status: "ok"},
			2: {Engine: "xray", Status: "waiting"},
			3: {Engine: "singbox", Status: "unsupported"},
		})
		engines, ok := coverage["engines"].(map[string]string)
		if !ok {
			t.Fatalf("expected engines map, got %#v", coverage["engines"])
		}
		if coverage["overall"] != "partial" || engines["xray"] != "partial" || engines["singbox"] != "unsupported" {
			t.Fatalf("unexpected coverage: %+v", coverage)
		}
	}
}

func TestBuildTrafficCoverageStatusSemantics(t *testing.T) {
	coverage := buildTrafficCoverage(map[int64]inboundTrafficSummary{})
	engines := coverage["engines"].(map[string]string)
	if coverage["overall"] != "not_configured" || engines["xray"] != "not_configured" || engines["singbox"] != "not_configured" {
		t.Fatalf("empty traffic coverage should be not_configured, got %+v", coverage)
	}

	coverage = buildTrafficCoverage(map[int64]inboundTrafficSummary{
		1: {Engine: "singbox", Status: "not_configured"},
	})
	engines = coverage["engines"].(map[string]string)
	if coverage["overall"] != "not_configured" || engines["singbox"] != "not_configured" || coverage["not_configured"] != 1 {
		t.Fatalf("not_configured should remain distinct from waiting, got %+v", coverage)
	}

	coverage = buildTrafficCoverage(map[int64]inboundTrafficSummary{
		1: {Engine: "xray", Status: "ok"},
		2: {Engine: "singbox", Status: "not_configured"},
	})
	engines = coverage["engines"].(map[string]string)
	if coverage["overall"] != "ok" || engines["xray"] != "ok" || engines["singbox"] != "not_configured" {
		t.Fatalf("ok plus not_configured should not be partial or failed, got %+v", coverage)
	}

	coverage = buildTrafficCoverage(map[int64]inboundTrafficSummary{
		1: {Engine: "xray", Status: "ok"},
		2: {Engine: "singbox", Status: "unsupported"},
	})
	engines = coverage["engines"].(map[string]string)
	if coverage["overall"] != "partial" || engines["xray"] != "ok" || engines["singbox"] != "unsupported" {
		t.Fatalf("ok plus unsupported should be partial with singbox unsupported, got %+v", coverage)
	}

	coverage = buildTrafficCoverage(map[int64]inboundTrafficSummary{
		1: {Engine: "xray", Status: "waiting"},
		2: {Engine: "singbox", Status: "not_configured"},
	})
	engines = coverage["engines"].(map[string]string)
	if coverage["overall"] != "waiting" || engines["xray"] != "waiting" || engines["singbox"] != "not_configured" {
		t.Fatalf("waiting plus not_configured should remain waiting without core failure, got %+v", coverage)
	}

	coverage = buildTrafficCoverage(map[int64]inboundTrafficSummary{
		1: {Engine: "singbox", Status: "unsupported"},
		2: {Engine: "singbox", Status: "unsupported"},
	})
	if coverage["overall"] != "unsupported" {
		t.Fatalf("all unsupported should be unsupported, got %+v", coverage)
	}

	coverage = buildTrafficCoverage(map[int64]inboundTrafficSummary{
		1: {Engine: "xray", Status: "waiting"},
		2: {Engine: "singbox", Status: "unsupported"},
	})
	engines = coverage["engines"].(map[string]string)
	if coverage["overall"] != "unsupported" || engines["xray"] != "waiting" || engines["singbox"] != "unsupported" {
		t.Fatalf("unsupported plus waiting should keep unsupported visible, got %+v", coverage)
	}

	coverage = buildTrafficCoverage(map[int64]inboundTrafficSummary{
		1: {Engine: "xray", Status: "unavailable"},
		2: {Engine: "singbox", Status: "not_configured"},
	})
	if coverage["overall"] != "unavailable" {
		t.Fatalf("unavailable without ok should be unavailable, got %+v", coverage)
	}
}

func TestBuildTrafficCoverageCountsPartialStatus(t *testing.T) {
	coverage := buildTrafficCoverage(map[int64]inboundTrafficSummary{
		1: {Engine: "xray", Status: "partial"},
		2: {Engine: "singbox", Status: "partial"},
	})
	if coverage["overall"] != "partial" || coverage["partial"] != 2 {
		t.Fatalf("expected all-partial coverage, got %+v", coverage)
	}
}

func TestTrafficSamplesToSeriesDropsUnknownKeysAndSortsByTime(t *testing.T) {
	inbounds := []db.Inbound{{
		ID: 1, Protocol: "vless",
		Clients: []db.Client{{ID: 10, StatsKey: "c_xray"}},
	}}
	samples := []db.TrafficSample{
		{SampledAt: "2026-06-16T00:02:00Z", Engine: "xray", ScopeType: "client", ScopeKey: "c_xray", TotalUp: 20, TotalDown: 30},
		{SampledAt: "2026-06-16T00:01:00Z", Engine: "xray", ScopeType: "client", ScopeKey: "old_deleted", TotalUp: 999, TotalDown: 999},
		{SampledAt: "2026-06-16T00:01:00Z", Engine: "singbox", ScopeType: "client", ScopeKey: "c_xray", TotalUp: 888, TotalDown: 888},
		{SampledAt: "2026-06-16T00:01:00Z", Engine: "xray", ScopeType: "client", ScopeKey: "c_xray", TotalUp: 10, TotalDown: 15},
	}
	points := trafficSamplesToSeries(samples, "client", inbounds)
	if len(points) != 2 {
		t.Fatalf("expected two sorted known-key points, got %+v", points)
	}
	if points[0].Time != "2026-06-16T00:01:00Z" || points[0].Up != 10 || points[0].Down != 15 {
		t.Fatalf("unexpected first point: %+v", points[0])
	}
	if points[1].Time != "2026-06-16T00:02:00Z" || points[1].Up != 20 || points[1].Down != 30 {
		t.Fatalf("unexpected second point: %+v", points[1])
	}
}

func TestTrafficSamplesToSeriesFallsBackWhenExpectedEngineMissing(t *testing.T) {
	inbounds := []db.Inbound{{
		ID: 1, Protocol: "hysteria2",
		Clients: []db.Client{{ID: 10, StatsKey: "c_hy2"}},
	}}
	samples := []db.TrafficSample{
		{SampledAt: "2026-06-16T00:01:00Z", Engine: "xray", ScopeType: "client", ScopeKey: "c_hy2", TotalUp: 10, TotalDown: 15},
		{SampledAt: "2026-06-16T00:02:00Z", Engine: "xray", ScopeType: "client", ScopeKey: "c_hy2", TotalUp: 20, TotalDown: 30},
	}
	points := trafficSamplesToSeries(samples, "client", inbounds)
	if len(points) != 2 {
		t.Fatalf("expected fallback xray points, got %+v", points)
	}
	if points[0].Up != 10 || points[0].Down != 15 || points[1].Up != 20 || points[1].Down != 30 {
		t.Fatalf("unexpected fallback points: %+v", points)
	}
}

func TestCalculateCPUPercent(t *testing.T) {
	got := calculateCPUPercent(cpuSample{Idle: 40, Total: 100}, cpuSample{Idle: 50, Total: 140})
	if got != 75 {
		t.Fatalf("expected 75%% cpu, got %v", got)
	}
	for _, tc := range []struct {
		name     string
		previous cpuSample
		current  cpuSample
	}{
		{name: "no total delta", previous: cpuSample{Idle: 1, Total: 10}, current: cpuSample{Idle: 1, Total: 10}},
		{name: "counter reset", previous: cpuSample{Idle: 1, Total: 10}, current: cpuSample{Idle: 1, Total: 9}},
		{name: "idle exceeds total", previous: cpuSample{Idle: 1, Total: 10}, current: cpuSample{Idle: 12, Total: 15}},
	} {
		if got := calculateCPUPercent(tc.previous, tc.current); got != 0 {
			t.Fatalf("%s: expected 0, got %v", tc.name, got)
		}
	}
}

func TestCPUPercentSamplerUsesPreviousSampleWithoutSleeping(t *testing.T) {
	samples := []cpuSample{
		{Idle: 40, Total: 100},
		{Idle: 50, Total: 140},
	}
	idx := 0
	sampler := &cpuPercentSampler{read: func() (cpuSample, error) {
		if idx >= len(samples) {
			t.Fatal("unexpected extra cpu sample read")
		}
		sample := samples[idx]
		idx++
		return sample, nil
	}}
	if got := sampler.Sample(); got != 0 {
		t.Fatalf("first sample should seed baseline and return 0, got %v", got)
	}
	if got := sampler.Sample(); got != 75 {
		t.Fatalf("second sample should use previous sample, got %v", got)
	}

	failing := &cpuPercentSampler{read: func() (cpuSample, error) {
		return cpuSample{}, errors.New("read failed")
	}}
	if got := failing.Sample(); got != 0 {
		t.Fatalf("read failure should return 0, got %v", got)
	}
}
