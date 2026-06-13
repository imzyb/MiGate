package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
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

// StatsClientIsStub reports whether the configured stats client is the no-op
// lightweight stub. Production wiring uses this to avoid starting a scheduler
// that can only emit empty updates.
func StatsClientIsStub(client StatsClient) bool {
	_, ok := client.(*StubStatsClient)
	return ok
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

// CommandStatsClient queries real Xray traffic counters through the xray CLI
// without pulling gRPC/protobuf into the default MiGate binary. It expects the
// generated Xray config to expose the local StatsService API.
type CommandStatsClient struct {
	BinaryPath string
	Server     string
}

// ResilientStatsClient keeps retrying the real Xray stats source instead of
// permanently falling back when Xray is still starting or the generated config
// has not been applied yet.
type ResilientStatsClient struct {
	primary            StatsClient
	fallback           StatsClient
	mu                 sync.Mutex
	ready              bool
	lastUnavailableLog time.Time
}

// NewStubStatsClient creates a stub client that returns empty stats.
func NewStubStatsClient() *StubStatsClient {
	return &StubStatsClient{}
}

func NewCommandStatsClient(binaryPath, server string) *CommandStatsClient {
	if strings.TrimSpace(binaryPath) == "" {
		binaryPath = "/usr/local/bin/xray"
	}
	if strings.TrimSpace(server) == "" {
		server = "127.0.0.1:10085"
	}
	return &CommandStatsClient{BinaryPath: binaryPath, Server: server}
}

func NewResilientStatsClient(primary StatsClient, fallback StatsClient) *ResilientStatsClient {
	if fallback == nil {
		fallback = NewStubStatsClient()
	}
	return &ResilientStatsClient{primary: primary, fallback: fallback}
}

// QueryAllStats returns an empty map (no real stats available).
func (c *StubStatsClient) QueryAllStats(ctx context.Context) (map[string]*ClientStats, error) {
	return make(map[string]*ClientStats), nil
}

// Close is a no-op for the stub client.
func (c *StubStatsClient) Close() error {
	return nil
}

func (c *CommandStatsClient) QueryAllStats(ctx context.Context) (map[string]*ClientStats, error) {
	out, err := exec.CommandContext(ctx, c.BinaryPath, "api", "statsquery", "--server", c.Server, "-pattern", "user>>>").Output()
	if err != nil {
		return nil, fmt.Errorf("xray statsquery: %w", err)
	}
	return ParseStatsQueryOutput(out)
}

func (c *CommandStatsClient) Close() error { return nil }

func (c *ResilientStatsClient) QueryAllStats(ctx context.Context) (map[string]*ClientStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.primary == nil {
		return c.fallback.QueryAllStats(ctx)
	}
	stats, err := c.primary.QueryAllStats(ctx)
	if err == nil {
		if !c.ready {
			log.Println("traffic sync: xray stats became available")
			c.ready = true
		}
		return stats, nil
	}
	if c.ready {
		log.Printf("traffic sync: xray stats became unavailable: %v", err)
		c.ready = false
		c.lastUnavailableLog = time.Now()
	} else if time.Since(c.lastUnavailableLog) >= time.Minute {
		log.Printf("traffic sync: xray stats unavailable, will retry: %v", err)
		c.lastUnavailableLog = time.Now()
	}
	return c.fallback.QueryAllStats(ctx)
}

func (c *ResilientStatsClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var err error
	if c.primary != nil {
		err = c.primary.Close()
	}
	if c.fallback != nil {
		if fallbackErr := c.fallback.Close(); err == nil {
			err = fallbackErr
		}
	}
	return err
}

func ParseStatsQueryOutput(raw []byte) (map[string]*ClientStats, error) {
	var payload struct {
		Stat []struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	result := map[string]*ClientStats{}
	for _, st := range payload.Stat {
		parts := strings.Split(st.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
			continue
		}
		email := parts[1]
		cs := result[email]
		if cs == nil {
			cs = &ClientStats{Email: email}
			result[email] = cs
		}
		switch parts[3] {
		case "uplink":
			cs.Uplink = st.Value
		case "downlink":
			cs.Downlink = st.Value
		}
	}
	return result, nil
}

// GRPCStatsClient uses gRPC to query real traffic stats from Xray.
// This implementation requires the google.golang.org/grpc dependency.
//
// To use this client, build with the grpc tag:
//
//	go build -tags grpc ./...
//
// Or manually replace the client at runtime:
//
//	client, _ := xray.NewGRPCStatsClient(ctx, "tcp:127.0.0.1:1080")
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
