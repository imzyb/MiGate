package scheduler

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/singbox"
	"github.com/imzyb/MiGate/internal/xray"
)

type mockStore struct {
	traffic         map[string]*xray.ClientStats
	raw             []db.TrafficRawStat
	scopeStatus     []db.TrafficStatusMarker
	unavail         []db.TrafficRawStat
	inbounds        []db.Inbound
	listInboundsErr error
}

func (m *mockStore) UpdateClientTraffic(ctx context.Context, email string, uplink, downlink int64) error {
	if m.traffic == nil {
		m.traffic = make(map[string]*xray.ClientStats)
	}
	m.traffic[email] = &xray.ClientStats{Email: email, Uplink: uplink, Downlink: downlink}
	return nil
}

func (m *mockStore) ApplyTrafficRawStats(ctx context.Context, stats []db.TrafficRawStat, observedAt time.Time) error {
	m.raw = append(m.raw, stats...)
	if m.traffic == nil {
		m.traffic = make(map[string]*xray.ClientStats)
	}
	for _, stat := range stats {
		if stat.ScopeType == "client" {
			m.traffic[stat.ScopeKey] = &xray.ClientStats{Email: stat.ScopeKey, Uplink: stat.RawUp, Downlink: stat.RawDown}
		}
	}
	return nil
}

func (m *mockStore) MarkTrafficScopeStatus(ctx context.Context, stats []db.TrafficStatusMarker, observedAt time.Time) error {
	m.scopeStatus = append(m.scopeStatus, stats...)
	return nil
}

func (m *mockStore) MarkTrafficUnavailable(ctx context.Context, engine, status, message string, observedAt time.Time) error {
	m.unavail = append(m.unavail, db.TrafficRawStat{Engine: engine, Status: status, Message: message})
	return nil
}

func (m *mockStore) ListInbounds(ctx context.Context) ([]db.Inbound, error) {
	if m.listInboundsErr != nil {
		return nil, m.listInboundsErr
	}
	return m.inbounds, nil
}

type mockStatsClient struct {
	stats map[string]*xray.ClientStats
	raw   []xray.TrafficStat
	err   error
	calls int
}

func (m *mockStatsClient) QueryAllStats(ctx context.Context) (map[string]*xray.ClientStats, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.stats, nil
}

func (m *mockStatsClient) QueryTrafficStats(ctx context.Context) ([]xray.TrafficStat, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	if m.raw != nil {
		return m.raw, nil
	}
	result := make([]xray.TrafficStat, 0, len(m.stats))
	for _, stat := range m.stats {
		result = append(result, xray.TrafficStat{Engine: "xray", ScopeType: "client", ScopeKey: stat.Email, Uplink: stat.Uplink, Downlink: stat.Downlink})
	}
	return result, nil
}

func (m *mockStatsClient) Close() error {
	return nil
}

func findTrafficState(states []db.TrafficState, engine, scopeType, scopeKey string) *db.TrafficState {
	for i := range states {
		state := &states[i]
		if state.Engine == engine && state.ScopeType == scopeType && state.ScopeKey == scopeKey {
			return state
		}
	}
	return nil
}

func TestTrafficSyncSchedulerSync(t *testing.T) {
	store := &mockStore{}
	client := &mockStatsClient{
		stats: map[string]*xray.ClientStats{
			"client1@test.com": {Email: "client1@test.com", Uplink: 1024, Downlink: 2048},
			"client2@test.com": {Email: "client2@test.com", Uplink: 512, Downlink: 1024},
		},
	}

	scheduler := NewTrafficSyncScheduler(store, client, 1*time.Minute)
	scheduler.sync()

	if len(store.traffic) != 2 {
		t.Errorf("Expected 2 clients updated, got %d", len(store.traffic))
	}

	c1 := store.traffic["client1@test.com"]
	if c1.Uplink != 1024 || c1.Downlink != 2048 {
		t.Errorf("client1 traffic mismatch: up=%d down=%d", c1.Uplink, c1.Downlink)
	}

	c2 := store.traffic["client2@test.com"]
	if c2.Uplink != 512 || c2.Downlink != 1024 {
		t.Errorf("client2 traffic mismatch: up=%d down=%d", c2.Uplink, c2.Downlink)
	}
}

func TestTrafficSyncSchedulerWithEmptyStats(t *testing.T) {
	store := &mockStore{}
	client := &mockStatsClient{stats: make(map[string]*xray.ClientStats)}

	scheduler := NewTrafficSyncScheduler(store, client, 1*time.Minute)
	scheduler.sync()

	if len(store.traffic) != 0 {
		t.Errorf("Expected 0 clients with empty stats, got %d", len(store.traffic))
	}
}

func TestTrafficSyncSchedulerMarksMissingXrayClientsWaitingWhenStatsAreEmpty(t *testing.T) {
	store := &mockStore{inbounds: []db.Inbound{
		{
			ID: 1, Protocol: "vless", Enabled: true,
			Clients: []db.Client{
				{ID: 10, StatsKey: "c_xray", Email: "xray@example.com", Enabled: true},
				{ID: 11, StatsKey: "c_disabled", Email: "disabled@example.com", Enabled: false},
			},
		},
		{
			ID: 2, Protocol: "hysteria2", Enabled: true,
			Clients: []db.Client{{ID: 20, StatsKey: "c_hy2", Email: "hy2@example.com", Enabled: true}},
		},
	}}
	client := &mockStatsClient{raw: []xray.TrafficStat{}}

	scheduler := NewTrafficSyncScheduler(store, client, 1*time.Minute)
	scheduler.sync()

	if len(store.raw) != 0 {
		t.Fatalf("expected no raw stats for empty xray response, got %+v", store.raw)
	}
	if len(store.unavail) != 0 {
		t.Fatalf("did not expect unavailable marker for successful empty stats response, got %+v", store.unavail)
	}
	if len(store.scopeStatus) != 1 {
		t.Fatalf("expected xray client waiting marker, got %+v", store.scopeStatus)
	}
	want := map[string]bool{
		"client/c_xray": false,
	}
	for _, marker := range store.scopeStatus {
		if marker.Engine != "xray" || marker.Status != "waiting" {
			t.Fatalf("unexpected xray waiting marker: %+v", marker)
		}
		key := marker.ScopeType + "/" + marker.ScopeKey
		if _, ok := want[key]; !ok {
			t.Fatalf("unexpected marker scope %q in %+v", key, store.scopeStatus)
		}
		want[key] = true
	}
	for key, found := range want {
		if !found {
			t.Fatalf("missing marker scope %q in %+v", key, store.scopeStatus)
		}
	}
}

func TestTrafficSyncSchedulerMarksOnlyMissingXrayClientsWaitingWhenRawStatsArePartial(t *testing.T) {
	store := &mockStore{inbounds: []db.Inbound{{
		ID: 1, Protocol: "vless", Enabled: true,
		Clients: []db.Client{
			{ID: 10, StatsKey: "c_seen", Enabled: true},
			{ID: 11, StatsKey: "c_missing", Enabled: true},
			{ID: 12, StatsKey: "c_disabled", Enabled: false},
		},
	}}}
	client := &mockStatsClient{raw: []xray.TrafficStat{
		{Engine: "xray", ScopeType: "client", ScopeKey: "c_seen", Uplink: 100, Downlink: 200},
	}}

	scheduler := NewTrafficSyncScheduler(store, client, 1*time.Minute)
	scheduler.sync()

	if len(store.raw) != 1 || store.raw[0].ScopeKey != "c_seen" || store.raw[0].Status != "ok" {
		t.Fatalf("expected returned xray client to be applied as ok, got %+v", store.raw)
	}
	if len(store.scopeStatus) != 1 {
		t.Fatalf("expected one missing xray client waiting marker, got %+v", store.scopeStatus)
	}
	marker := store.scopeStatus[0]
	if marker.Engine != "xray" || marker.ScopeType != "client" || marker.ScopeKey != "c_missing" || marker.Status != "waiting" {
		t.Fatalf("unexpected missing client marker: %+v", marker)
	}
	if len(store.unavail) != 0 {
		t.Fatalf("did not expect unavailable marker for partial successful stats, got %+v", store.unavail)
	}
}

func TestTrafficSyncSchedulerDoesNotMarkXrayWaitingWhenQueryFails(t *testing.T) {
	store := &mockStore{inbounds: []db.Inbound{{
		ID: 1, Protocol: "vless", Enabled: true,
		Clients: []db.Client{{ID: 10, StatsKey: "c_xray", Enabled: true}},
	}}}
	client := &mockStatsClient{err: errors.New("connection refused")}

	scheduler := NewTrafficSyncScheduler(store, client, 1*time.Minute)
	scheduler.sync()

	if len(store.scopeStatus) != 1 {
		t.Fatalf("query failure should write xray unavailable scope markers, got %+v", store.scopeStatus)
	}
	want := map[string]bool{
		"client/c_xray": false,
	}
	for _, marker := range store.scopeStatus {
		if marker.Engine != "xray" || marker.Status != "unavailable" || marker.Message != "connection refused" {
			t.Fatalf("query failure should not write waiting markers, got %+v", store.scopeStatus)
		}
		key := marker.ScopeType + "/" + marker.ScopeKey
		if _, ok := want[key]; !ok {
			t.Fatalf("unexpected unavailable marker %q in %+v", key, store.scopeStatus)
		}
		want[key] = true
	}
	for key, found := range want {
		if !found {
			t.Fatalf("missing unavailable marker %q in %+v", key, store.scopeStatus)
		}
	}
	if len(store.unavail) != 1 || store.unavail[0].Engine != "xray" || store.unavail[0].Status != "unavailable" {
		t.Fatalf("expected xray unavailable marker, got %+v", store.unavail)
	}
}

func TestTrafficSyncSchedulerCreatesUnavailableXrayStatesWhenQueryFails(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "xray-failed", Protocol: "vless", Port: 18101, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "failed@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	statsErr := errors.New("xray stats offline")
	scheduler := NewTrafficSyncScheduler(store, &mockStatsClient{err: statsErr}, time.Minute)

	scheduler.sync()

	states, err := store.ListTrafficStates(ctx)
	if err != nil {
		t.Fatalf("list states: %v", err)
	}
	clientState := findTrafficState(states, "xray", "client", client.StatsKey)
	if clientState == nil || clientState.Status != "unavailable" || !strings.Contains(clientState.Message, statsErr.Error()) {
		t.Fatalf("expected client unavailable state, got %+v in %+v", clientState, states)
	}
}

func TestTrafficSyncSchedulerDoesNotMarkXrayWaitingWhenAllRawStatsExist(t *testing.T) {
	store := &mockStore{inbounds: []db.Inbound{{
		ID: 1, Protocol: "vless", Enabled: true,
		Clients: []db.Client{{ID: 10, StatsKey: "c_xray", Enabled: true}},
	}}}
	client := &mockStatsClient{raw: []xray.TrafficStat{
		{Engine: "xray", ScopeType: "client", ScopeKey: "c_xray", Uplink: 100, Downlink: 200},
	}}

	scheduler := NewTrafficSyncScheduler(store, client, 1*time.Minute)
	scheduler.sync()

	if len(store.scopeStatus) != 0 {
		t.Fatalf("raw client stats should not write waiting markers, got %+v", store.scopeStatus)
	}
	if len(store.raw) != 1 || store.raw[0].Engine != "xray" || store.raw[0].Status != "ok" {
		t.Fatalf("expected xray raw stats to be applied, got %+v", store.raw)
	}
}

func TestTrafficSyncSchedulerKeepsXrayWhenSingboxUnavailable(t *testing.T) {
	store := &mockStore{inbounds: []db.Inbound{{
		ID: 1, Protocol: "hysteria2", Enabled: true,
		Clients: []db.Client{{ID: 2, StatsKey: "c_hy2", Enabled: true}},
	}}}
	xrayClient := &mockStatsClient{raw: []xray.TrafficStat{
		{Engine: "xray", ScopeType: "client", ScopeKey: "client1@test.com", Uplink: 1024, Downlink: 2048},
	}}
	singboxClient := &mockStatsClient{err: errors.New("connect 127.0.0.1:10086: connection refused")}

	scheduler := NewTrafficSyncSchedulerWithSingbox(store, xrayClient, singboxClient, time.Minute)
	scheduler.sync()

	if len(store.raw) != 1 {
		t.Fatalf("expected xray raw stat to be applied despite sing-box failure, got %+v", store.raw)
	}
	if store.raw[0].Engine != "xray" || store.raw[0].ScopeKey != "client1@test.com" {
		t.Fatalf("unexpected raw stat: %+v", store.raw[0])
	}
	if len(store.unavail) != 1 || store.unavail[0].Engine != "singbox" || store.unavail[0].Status != "unavailable" {
		t.Fatalf("expected singbox unavailable marker, got %+v", store.unavail)
	}
	want := map[string]bool{
		"client/c_hy2": false,
	}
	for _, marker := range store.scopeStatus {
		if marker.Engine != "singbox" {
			continue
		}
		if marker.Status != "unavailable" || marker.Message != "connect 127.0.0.1:10086: connection refused" {
			t.Fatalf("expected singbox unavailable scope marker, got %+v", marker)
		}
		key := marker.ScopeType + "/" + marker.ScopeKey
		if _, ok := want[key]; !ok {
			t.Fatalf("unexpected singbox unavailable scope marker %q in %+v", key, store.scopeStatus)
		}
		want[key] = true
	}
	for key, found := range want {
		if !found {
			t.Fatalf("missing singbox unavailable scope marker %q in %+v", key, store.scopeStatus)
		}
	}
}

func TestTrafficSyncSchedulerWritesSingboxEngineStats(t *testing.T) {
	store := &mockStore{}
	xrayClient := &mockStatsClient{raw: []xray.TrafficStat{}}
	singboxClient := &mockStatsClient{raw: []xray.TrafficStat{
		{Engine: "singbox", ScopeType: "client", ScopeKey: "c_singbox", Uplink: 10, Downlink: 20},
		{Engine: "singbox", ScopeType: "inbound", ScopeKey: "hy2-inbound-1", Uplink: 30, Downlink: 40},
	}}

	scheduler := NewTrafficSyncSchedulerWithSingbox(store, xrayClient, singboxClient, time.Minute)
	scheduler.sync()

	if len(store.raw) != 2 {
		t.Fatalf("expected singbox stats to be applied, got %+v", store.raw)
	}
	for _, stat := range store.raw {
		if stat.Engine != "singbox" || stat.Status != "ok" {
			t.Fatalf("unexpected singbox stat: %+v", stat)
		}
	}
}

func TestTrafficSyncSchedulerSkipsSingboxQueryWhenNotConfigured(t *testing.T) {
	store := &mockStore{}
	xrayClient := &mockStatsClient{raw: []xray.TrafficStat{
		{Engine: "xray", ScopeType: "client", ScopeKey: "xray-client", Uplink: 100, Downlink: 200},
	}}
	disabled := singbox.NewDisabledStatsClient("not_configured", "")

	scheduler := NewTrafficSyncSchedulerWithSingboxConfig(store, xrayClient, disabled, nil, time.Minute)
	scheduler.sync()

	if len(store.raw) != 1 || store.raw[0].Engine != "xray" {
		t.Fatalf("expected only xray stats to be applied, got raw=%+v", store.raw)
	}
	if len(store.scopeStatus) != 0 {
		t.Fatalf("expected no scope markers without singbox inbound, got %+v", store.scopeStatus)
	}
	if len(store.unavail) != 1 || store.unavail[0].Engine != "singbox" || store.unavail[0].Status != "not_configured" {
		t.Fatalf("expected singbox not_configured marker, got %+v", store.unavail)
	}
}

func TestTrafficSyncSchedulerMarksUnsupportedSingboxInboundsWithoutQuery(t *testing.T) {
	inbounds := []db.Inbound{{
		ID: 1, Protocol: "hysteria2", Enabled: true,
		Clients: []db.Client{
			{ID: 2, StatsKey: "c_hy2", Enabled: true},
			{ID: 3, Email: "fallback@example.com", Enabled: true},
		},
	}}
	store := &mockStore{inbounds: inbounds}
	xrayClient := &mockStatsClient{raw: []xray.TrafficStat{
		{Engine: "xray", ScopeType: "client", ScopeKey: "xray-client", Uplink: 100, Downlink: 200},
	}}
	disabled := singbox.NewDisabledStatsClient("unsupported", singbox.StatsUnsupportedMessage)

	scheduler := NewTrafficSyncSchedulerWithSingboxConfig(store, xrayClient, disabled, inbounds, time.Minute)
	scheduler.sync()

	if len(store.raw) != 1 {
		t.Fatalf("expected only xray raw stat to be applied, got %+v", store.raw)
	}
	if store.raw[0].Engine != "xray" || store.raw[0].ScopeKey != "xray-client" || store.raw[0].Status != "ok" {
		t.Fatalf("expected xray stat to remain applied, got %+v", store.raw)
	}
	if len(store.scopeStatus) != 3 {
		t.Fatalf("expected singbox inbound/client scope markers, got %+v", store.scopeStatus)
	}
	foundUnsupported := false
	foundEmailFallback := false
	for _, stat := range store.scopeStatus {
		if stat.Engine == "singbox" && stat.Status == "unsupported" && stat.Message == singbox.StatsUnsupportedMessage {
			foundUnsupported = true
		}
		if stat.Engine == "singbox" && stat.ScopeType == "client" && stat.ScopeKey == "fallback@example.com" {
			foundEmailFallback = true
		}
	}
	if !foundUnsupported {
		t.Fatalf("expected unsupported singbox marker, got %+v", store.scopeStatus)
	}
	if !foundEmailFallback {
		t.Fatalf("expected singbox client marker to fall back to email, got %+v", store.scopeStatus)
	}
}

func TestTrafficSyncSchedulerRefreshesSingboxClientAfterInboundAppears(t *testing.T) {
	store := &mockStore{}
	xrayClient := &mockStatsClient{raw: []xray.TrafficStat{}}
	singboxClient := &mockStatsClient{raw: []xray.TrafficStat{
		{Engine: "singbox", ScopeType: "client", ScopeKey: "c_hy2", Uplink: 10, Downlink: 20},
	}}
	scheduler := NewTrafficSyncSchedulerWithSingboxConfig(store, xrayClient, singbox.NewDisabledStatsClient("not_configured", ""), nil, time.Minute)
	scheduler.singboxCapability = func(ctx context.Context) singbox.Capability {
		return singbox.Capability{V2RayAPIStats: true, Checked: true}
	}
	scheduler.newSingboxStats = func(ctx context.Context) (singbox.StatsClient, error) {
		return singboxClient, nil
	}

	scheduler.sync()
	if singboxClient.calls != 0 {
		t.Fatalf("expected no singbox query before singbox inbound exists")
	}

	store.inbounds = []db.Inbound{{
		ID: 1, Protocol: "hysteria2", Enabled: true,
		Clients: []db.Client{{ID: 2, StatsKey: "c_hy2", Enabled: true}},
	}}
	scheduler.sync()

	if singboxClient.calls != 1 {
		t.Fatalf("expected refreshed singbox client to be queried once, got %d", singboxClient.calls)
	}
	found := false
	for _, stat := range store.raw {
		if stat.Engine == "singbox" && stat.ScopeKey == "c_hy2" && stat.Status == "ok" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected refreshed singbox stats to be applied, got %+v", store.raw)
	}
}

func TestTrafficSyncSchedulerDoesNotWriteStaleMarkersWhenInboundRefreshFails(t *testing.T) {
	staleInbounds := []db.Inbound{{
		ID: 1, Protocol: "hysteria2", Enabled: true,
		Clients: []db.Client{{ID: 2, StatsKey: "c_old", Enabled: true}},
	}}
	store := &mockStore{listInboundsErr: errors.New("database busy")}
	xrayClient := &mockStatsClient{raw: []xray.TrafficStat{}}
	scheduler := NewTrafficSyncSchedulerWithSingboxConfig(store, xrayClient, singbox.NewDisabledStatsClient("unsupported", singbox.StatsUnsupportedMessage), staleInbounds, time.Minute)

	scheduler.sync()

	if len(store.scopeStatus) != 0 {
		t.Fatalf("did not expect stale singbox marker when inbound refresh fails, got %+v", store.scopeStatus)
	}
	if len(store.unavail) != 1 || store.unavail[0].Status != "unsupported" {
		t.Fatalf("expected engine-level unsupported marker, got %+v", store.unavail)
	}
}

func TestTrafficSyncSchedulerDoesNotRefreshCapabilityWithoutSingboxInbound(t *testing.T) {
	store := &mockStore{}
	xrayClient := &mockStatsClient{raw: []xray.TrafficStat{}}
	scheduler := NewTrafficSyncSchedulerWithSingboxConfig(store, xrayClient, singbox.NewDisabledStatsClient("not_configured", ""), nil, time.Minute)
	capabilityCalls := 0
	scheduler.singboxCapability = func(ctx context.Context) singbox.Capability {
		capabilityCalls++
		return singbox.Capability{V2RayAPIStats: true, Checked: true}
	}
	builderCalls := 0
	scheduler.newSingboxStats = func(ctx context.Context) (singbox.StatsClient, error) {
		builderCalls++
		return nil, errors.New("unexpected stats client build")
	}

	scheduler.sync()

	if capabilityCalls != 0 {
		t.Fatalf("expected no capability check without singbox inbound, got %d", capabilityCalls)
	}
	if builderCalls != 0 {
		t.Fatalf("expected no singbox stats client build without singbox inbound, got %d", builderCalls)
	}
	if len(store.scopeStatus) != 0 {
		t.Fatalf("expected no scope markers without singbox inbound, got %+v", store.scopeStatus)
	}
}

func TestTrafficSyncSchedulerKeepsSingboxNotConfiguredWhenOnlyXrayInboundExists(t *testing.T) {
	store := &mockStore{inbounds: []db.Inbound{{
		ID: 1, Protocol: "vless", Enabled: true,
		Clients: []db.Client{{ID: 2, StatsKey: "c_xray", Enabled: true}},
	}}}
	xrayClient := &mockStatsClient{err: errors.New("xray stats offline")}
	scheduler := NewTrafficSyncSchedulerWithSingboxConfig(store, xrayClient, singbox.NewDisabledStatsClient("not_configured", ""), nil, time.Minute)

	scheduler.sync()

	for _, marker := range store.scopeStatus {
		if marker.Engine == "singbox" {
			t.Fatalf("only xray inbound should not receive singbox marker, got %+v", store.scopeStatus)
		}
	}
	if len(store.unavail) != 2 {
		t.Fatalf("expected xray unavailable and singbox not_configured engine markers, got %+v", store.unavail)
	}
	foundSingboxNotConfigured := false
	for _, marker := range store.unavail {
		if marker.Engine == "singbox" && marker.Status == "not_configured" {
			foundSingboxNotConfigured = true
		}
		if marker.Engine == "singbox" && marker.Status == "unavailable" {
			t.Fatalf("singbox should remain not_configured, got %+v", store.unavail)
		}
	}
	if !foundSingboxNotConfigured {
		t.Fatalf("expected singbox engine marker to remain not_configured, got %+v", store.unavail)
	}
}
