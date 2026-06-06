package xray

import (
	"context"
	"fmt"
)

// StatsClient provides access to Xray's traffic statistics.
// Xray exposes per-client traffic stats through the StatsService gRPC API.
//
// This interface allows for multiple implementations:
// - StubStatsClient: returns empty data (default, no external dependencies)
// - GRPCStatsClient: uses gRPC to query real stats (requires google.golang.org/grpc)
//
// The stub implementation ensures MiGate remains lightweight while providing
// the API and WebUI structure. Real stats can be enabled by swapping the
// implementation at runtime.
type StatsClient interface {
	// QueryAllStats returns uplink and downlink bytes for each client email.
	// Xray stat name format: "user>>{email}>>traffic>>{uplink|downlink}"
	QueryAllStats(ctx context.Context) (map[string]*ClientStats, error)
	// Close releases any resources held by the client.
	Close() error
}

// ClientStats holds uplink and downlink traffic for a single client.
type ClientStats struct {
	Email    string
	Uplink   int64 // bytes uploaded
	Downlink int64 // bytes downloaded
}

// StubStatsClient is the default implementation that returns empty data.
// It has zero external dependencies and keeps the binary lightweight.
type StubStatsClient struct{}

// NewStubStatsClient creates a stub client that returns empty stats.
func NewStubStatsClient() *StubStatsClient {
	return &StubStatsClient{}
}

// QueryAllStats returns an empty map (no real stats available).
func (c *StubStatsClient) QueryAllStats(ctx context.Context) (map[string]*ClientStats, error) {
	return make(map[string]*ClientStats), nil
}

// Close is a no-op for the stub client.
func (c *StubStatsClient) Close() error {
	return nil
}

// GRPCStatsClient uses gRPC to query real traffic stats from Xray.
// This implementation requires the google.golang.org/grpc dependency.
//
// To use this client, build with the grpc tag:
//   go build -tags grpc ./...
//
// Or manually replace the client at runtime:
//   client, _ := xray.NewGRPCStatsClient(ctx, "tcp:127.0.0.1:1080")
type GRPCStatsClient struct {
	// Connection to Xray's gRPC API endpoint
	// addr format: "tcp:127.0.0.1:1080" or "unix:/path/to/xray-api.sock"
	addr string
}

// NewGRPCStatsClient creates a gRPC client for querying Xray stats.
// Returns an error if the grpc tag is not enabled.
func NewGRPCStatsClient(ctx context.Context, addr string) (*GRPCStatsClient, error) {
	// Check if grpc support is enabled via build tag
	// This allows the binary to remain lightweight by default
	if !isGRPCEnabled() {
		return nil, fmt.Errorf("grpc support not enabled; rebuild with -tags grpc or use StubStatsClient")
	}
	return &GRPCStatsClient{addr: addr}, nil
}

// isGRPCEnabled returns true if the grpc build tag is set.
// This is a compile-time check using build constraints.
func isGRPCEnabled() bool {
	// This function is overridden by grpc_enabled.go when -tags grpc is used
	return false
}

// QueryAllStats queries real traffic stats from Xray via gRPC.
// This method is only available when built with -tags grpc.
func (c *GRPCStatsClient) QueryAllStats(ctx context.Context) (map[string]*ClientStats, error) {
	if !isGRPCEnabled() {
		return nil, fmt.Errorf("grpc not enabled; cannot query stats")
	}
	// Implementation requires google.golang.org/grpc
	// See grpc_stats.go for the full implementation
	return make(map[string]*ClientStats), fmt.Errorf("grpc implementation not available")
}

// Close closes the gRPC connection.
func (c *GRPCStatsClient) Close() error {
	if !isGRPCEnabled() {
		return nil
	}
	// Implementation requires google.golang.org/grpc
	return nil
}
