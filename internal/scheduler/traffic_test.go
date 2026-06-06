package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/imzyb/MiGate/internal/xray"
)

type mockStore struct {
	traffic map[string]*xray.ClientStats
}

func (m *mockStore) UpdateClientTraffic(ctx context.Context, email string, uplink, downlink int64) error {
	if m.traffic == nil {
		m.traffic = make(map[string]*xray.ClientStats)
	}
	m.traffic[email] = &xray.ClientStats{Email: email, Uplink: uplink, Downlink: downlink}
	return nil
}

type mockStatsClient struct {
	stats map[string]*xray.ClientStats
}

func (m *mockStatsClient) QueryAllStats(ctx context.Context) (map[string]*xray.ClientStats, error) {
	return m.stats, nil
}

func (m *mockStatsClient) Close() error {
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
