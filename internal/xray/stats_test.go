package xray

import (
	"context"
	"testing"
)

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

func TestGRPCStatsClientRequiresBuildTag(t *testing.T) {
	// Without -tags grpc, NewGRPCStatsClient should return an error
	client, err := NewGRPCStatsClient(context.Background(), "tcp:127.0.0.1:1080")
	if err == nil {
		t.Errorf("Expected error when grpc not enabled, got nil")
	}
	if client != nil {
		t.Errorf("Expected nil client when grpc not enabled, got %v", client)
	}
}
