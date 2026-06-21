package xray

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

type flakyStatsClient struct {
	calls int
}

func (c *flakyStatsClient) QueryAllStats(ctx context.Context) (map[string]*ClientStats, error) {
	c.calls++
	if c.calls == 1 {
		return nil, fmt.Errorf("not ready")
	}
	return map[string]*ClientStats{
		"sam@example.com": {Email: "sam@example.com", Uplink: 100, Downlink: 200},
	}, nil
}

func (c *flakyStatsClient) QueryTrafficStats(ctx context.Context) ([]TrafficStat, error) {
	stats, err := c.QueryAllStats(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]TrafficStat, 0, len(stats))
	for _, stat := range stats {
		result = append(result, TrafficStat{Engine: "xray", ScopeType: "client", ScopeKey: stat.Email, Uplink: stat.Uplink, Downlink: stat.Downlink})
	}
	return result, nil
}

func (c *flakyStatsClient) Close() error { return nil }

func TestStubStatsClientReturnsEmptyStats(t *testing.T) {
	client := NewStubStatsClient()
	defer client.Close()

	stats, err := client.QueryAllStats(context.Background())
	if err != nil {
		t.Fatalf("QueryAllStats returned error: %v", err)
	}

	if len(stats) != 0 {
		t.Errorf("Expected empty stats map, got %d entries", len(stats))
	}
}

func TestStubStatsClientCloseIsNoOp(t *testing.T) {
	client := NewStubStatsClient()
	err := client.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
	// Second close should also be safe
	err = client.Close()
	if err != nil {
		t.Errorf("Second Close returned error: %v", err)
	}
}

func TestResilientStatsClientRetriesAfterInitialFailure(t *testing.T) {
	primary := &flakyStatsClient{}
	client := NewResilientStatsClient(primary, NewStubStatsClient())
	defer client.Close()

	first, err := client.QueryAllStats(context.Background())
	if err != nil {
		t.Fatalf("first query should use fallback without error: %v", err)
	}
	if len(first) != 0 {
		t.Fatalf("first query should return fallback empty stats, got %#v", first)
	}

	second, err := client.QueryAllStats(context.Background())
	if err != nil {
		t.Fatalf("second query should recover primary stats: %v", err)
	}
	got := second["sam@example.com"]
	if got == nil || got.Uplink != 100 || got.Downlink != 200 {
		t.Fatalf("second query did not recover live stats: %#v", second)
	}
	if primary.calls != 2 {
		t.Fatalf("primary should be retried, got %d calls", primary.calls)
	}
}

func TestResilientStatsClientTrafficStatsReturnsPrimaryError(t *testing.T) {
	primary := &flakyStatsClient{}
	client := NewResilientStatsClient(primary, NewStubStatsClient())
	defer client.Close()

	first, err := client.QueryTrafficStats(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("first traffic query should return primary error, got stats=%#v err=%v", first, err)
	}

	second, err := client.QueryTrafficStats(context.Background())
	if err != nil {
		t.Fatalf("second traffic query should recover primary stats: %v", err)
	}
	if len(second) != 1 || second[0].ScopeKey != "sam@example.com" || second[0].Uplink != 100 || second[0].Downlink != 200 {
		t.Fatalf("second traffic query did not recover live stats: %#v", second)
	}
	if primary.calls != 2 {
		t.Fatalf("primary should be retried, got %d calls", primary.calls)
	}
}

func TestClientStatsStruct(t *testing.T) {
	stats := &ClientStats{
		Email:    "test@example.com",
		Uplink:   1024,
		Downlink: 2048,
	}

	if stats.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", stats.Email, "test@example.com")
	}
	if stats.Uplink != 1024 {
		t.Errorf("Uplink = %d, want %d", stats.Uplink, 1024)
	}
	if stats.Downlink != 2048 {
		t.Errorf("Downlink = %d, want %d", stats.Downlink, 2048)
	}
}

func TestGRPCStatsClientQueriesStatsService(t *testing.T) {
	addr, closeServer := startFakeStatsService(t, []TrafficStat{
		{ScopeType: "client", ScopeKey: "sam@example.com", Uplink: 100, Downlink: 200},
		{ScopeType: "inbound", ScopeKey: "inbound-1-vless", Uplink: 30, Downlink: 40},
	})
	defer closeServer()

	client, err := NewGRPCStatsClient(context.Background(), addr)
	if err != nil {
		t.Fatalf("new grpc stats client: %v", err)
	}
	defer client.Close()

	stats, err := client.QueryTrafficStats(context.Background())
	if err != nil {
		t.Fatalf("query grpc stats: %v", err)
	}
	byScope := map[string]TrafficStat{}
	for _, stat := range stats {
		byScope[stat.ScopeType+"/"+stat.ScopeKey] = stat
	}
	if got := byScope["client/sam@example.com"]; got.Engine != "xray" || got.Uplink != 100 || got.Downlink != 200 {
		t.Fatalf("unexpected client stats: %+v", got)
	}
	if got := byScope["inbound/inbound-1-vless"]; got.Engine != "xray" || got.Uplink != 30 || got.Downlink != 40 {
		t.Fatalf("unexpected inbound stats: %+v", got)
	}
}

func TestGRPCStatsClientWithEngine(t *testing.T) {
	addr, closeServer := startFakeStatsService(t, []TrafficStat{
		{ScopeType: "client", ScopeKey: "c_singbox", Uplink: 10, Downlink: 20},
	})
	defer closeServer()

	client, err := NewGRPCStatsClientWithEngine(context.Background(), addr, "singbox")
	if err != nil {
		t.Fatalf("new grpc stats client: %v", err)
	}
	defer client.Close()

	stats, err := client.QueryTrafficStats(context.Background())
	if err != nil {
		t.Fatalf("query grpc stats: %v", err)
	}
	if len(stats) != 1 || stats[0].Engine != "singbox" || stats[0].ScopeKey != "c_singbox" || stats[0].Uplink != 10 || stats[0].Downlink != 20 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestGRPCStatsClientWithCustomServiceName(t *testing.T) {
	addr, closeServer := startFakeStatsServiceAtPath(t, "/experimental.v2rayapi.StatsService/QueryStats", []TrafficStat{
		{ScopeType: "client", ScopeKey: "c_singbox", Uplink: 10, Downlink: 20},
	})
	defer closeServer()

	client, err := NewGRPCStatsClientWithEngineAndService(context.Background(), addr, "singbox", "experimental.v2rayapi.StatsService")
	if err != nil {
		t.Fatalf("new grpc stats client: %v", err)
	}
	defer client.Close()

	stats, err := client.QueryTrafficStats(context.Background())
	if err != nil {
		t.Fatalf("query grpc stats: %v", err)
	}
	if len(stats) != 1 || stats[0].Engine != "singbox" || stats[0].ScopeKey != "c_singbox" {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestNewGRPCStatsClientHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewGRPCStatsClientWithEngineAndService(ctx, "127.0.0.1:10085", "xray", "xray.app.stats.command.StatsService"); err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestParseCommandStatsQueryOutput(t *testing.T) {
	raw := []byte(`{"stat":[{"name":"user>>>sam@example.com>>>traffic>>>uplink","value":60300000},{"name":"user>>>sam@example.com>>>traffic>>>downlink","value":202400000}]}`)
	stats, err := ParseStatsQueryOutput(raw)
	if err != nil {
		t.Fatalf("parse stats: %v", err)
	}
	got := stats["sam@example.com"]
	if got == nil || got.Uplink != 60300000 || got.Downlink != 202400000 {
		t.Fatalf("unexpected stats: %#v", got)
	}
}

func TestParseTrafficStatsQueryOutputAllScopes(t *testing.T) {
	raw := []byte(`{"stat":[
		{"name":"user>>>c_stats>>>traffic>>>uplink","value":10},
		{"name":"user>>>c_stats>>>traffic>>>downlink","value":20},
		{"name":"inbound>>>inbound-1-vless>>>traffic>>>uplink","value":30},
		{"name":"inbound>>>inbound-1-vless>>>traffic>>>downlink","value":40},
		{"name":"outbound>>>direct>>>traffic>>>uplink","value":50},
		{"name":"outbound>>>direct>>>traffic>>>downlink","value":60}
	]}`)
	stats, err := ParseTrafficStatsQueryOutput("xray", raw)
	if err != nil {
		t.Fatalf("parse traffic stats: %v", err)
	}
	byScope := map[string]TrafficStat{}
	for _, stat := range stats {
		byScope[stat.ScopeType+"/"+stat.ScopeKey] = stat
	}
	if got := byScope["client/c_stats"]; got.Uplink != 10 || got.Downlink != 20 {
		t.Fatalf("unexpected client stats: %+v", got)
	}
	if got := byScope["inbound/inbound-1-vless"]; got.Uplink != 30 || got.Downlink != 40 {
		t.Fatalf("unexpected inbound stats: %+v", got)
	}
	if got := byScope["outbound/direct"]; got.Uplink != 50 || got.Downlink != 60 {
		t.Fatalf("unexpected outbound stats: %+v", got)
	}
}

func startFakeStatsService(t *testing.T, stats []TrafficStat) (string, func()) {
	return startFakeStatsServiceAtPath(t, "/xray.app.stats.command.StatsService/QueryStats", stats)
}

func startFakeStatsServiceAtPath(t *testing.T, path string, stats []TrafficStat) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake stats service: %v", err)
	}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	server := &http.Server{
		Protocols: protocols,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				t.Errorf("unexpected stats service path: %s", r.URL.Path)
				http.NotFound(w, r)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read request body: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !strings.Contains(string(body), ">>>traffic>>>") {
				t.Errorf("request body missing traffic pattern: %x", body)
				http.Error(w, "missing pattern", http.StatusBadRequest)
				return
			}
			w.Header().Set("Trailer", "Grpc-Status")
			w.Header().Set("Content-Type", "application/grpc")
			_, _ = w.Write(encodeGRPCFrame(encodeQueryStatsResponse(stats)))
			w.Header().Set("Grpc-Status", "0")
		}),
	}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Errorf("fake stats service: %v", err)
		}
	}()
	return listener.Addr().String(), func() {
		_ = server.Close()
	}
}
