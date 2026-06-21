package xray

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	runtimecmd "github.com/imzyb/MiGate/internal/runtime/command"
)

// StatsClient provides access to Xray's traffic statistics.
// Xray exposes per-client traffic stats through the StatsService gRPC API.
//
// This interface allows for multiple implementations:
// - StubStatsClient: returns empty data (default, no external dependencies)
// - GRPCStatsClient: uses the v2ray-compatible local StatsService API
//
// The stub implementation ensures MiGate remains lightweight while providing
// the API and WebUI structure. Real stats can be enabled by swapping the
// implementation at runtime.
type StatsClient interface {
	// QueryAllStats returns uplink and downlink bytes for each client email.
	// Xray stat name format: "user>>{email}>>traffic>>{uplink|downlink}"
	QueryAllStats(ctx context.Context) (map[string]*ClientStats, error)
	// QueryTrafficStats returns raw core counters for all supported scopes.
	QueryTrafficStats(ctx context.Context) ([]TrafficStat, error)
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

type TrafficStat struct {
	Engine    string
	ScopeType string
	ScopeKey  string
	Uplink    int64
	Downlink  int64
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

type grpcRoundTripper interface {
	RoundTrip(*http.Request) (*http.Response, error)
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

func (c *StubStatsClient) QueryTrafficStats(ctx context.Context) ([]TrafficStat, error) {
	return []TrafficStat{}, nil
}

// Close is a no-op for the stub client.
func (c *StubStatsClient) Close() error {
	return nil
}

func (c *CommandStatsClient) QueryAllStats(ctx context.Context) (map[string]*ClientStats, error) {
	out, err := runtimecmd.NewRealCommandRunner(8*time.Second).RunOutput(ctx, c.BinaryPath, "api", "statsquery", "--server", c.Server, "-pattern", "user>>>")
	if err != nil {
		return nil, fmt.Errorf("xray statsquery: %w", err)
	}
	return ParseStatsQueryOutput(out)
}

func (c *CommandStatsClient) QueryTrafficStats(ctx context.Context) ([]TrafficStat, error) {
	out, err := runtimecmd.NewRealCommandRunner(8*time.Second).RunOutput(ctx, c.BinaryPath, "api", "statsquery", "--server", c.Server, "-pattern", ">>>traffic>>>")
	if err != nil {
		return nil, fmt.Errorf("xray statsquery: %w", err)
	}
	return ParseTrafficStatsQueryOutput("xray", out)
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

func (c *ResilientStatsClient) QueryTrafficStats(ctx context.Context) ([]TrafficStat, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.primary == nil {
		return c.fallback.QueryTrafficStats(ctx)
	}
	stats, err := c.primary.QueryTrafficStats(ctx)
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
	return nil, err
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
	rawStats, err := ParseTrafficStatsQueryOutput("xray", raw)
	if err != nil {
		return nil, err
	}
	result := map[string]*ClientStats{}
	for _, st := range rawStats {
		if st.ScopeType != "client" {
			continue
		}
		cs := result[st.ScopeKey]
		if cs == nil {
			cs = &ClientStats{Email: st.ScopeKey}
			result[st.ScopeKey] = cs
		}
		cs.Uplink = st.Uplink
		cs.Downlink = st.Downlink
	}
	return result, nil
}

func ParseTrafficStatsQueryOutput(engine string, raw []byte) ([]TrafficStat, error) {
	var payload struct {
		Stat []struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	byScope := map[string]*TrafficStat{}
	for _, st := range payload.Stat {
		parts := strings.Split(st.Name, ">>>")
		if len(parts) != 4 || parts[2] != "traffic" {
			continue
		}
		scopeType := normalizedScopeType(parts[0])
		if scopeType == "" || strings.TrimSpace(parts[1]) == "" {
			continue
		}
		key := engine + "\x00" + scopeType + "\x00" + parts[1]
		current := byScope[key]
		if current == nil {
			current = &TrafficStat{Engine: engine, ScopeType: scopeType, ScopeKey: parts[1]}
			byScope[key] = current
		}
		switch parts[3] {
		case "uplink":
			current.Uplink = st.Value
		case "downlink":
			current.Downlink = st.Value
		}
	}
	result := make([]TrafficStat, 0, len(byScope))
	for _, stat := range byScope {
		result = append(result, *stat)
	}
	return result, nil
}

func normalizedScopeType(scope string) string {
	switch scope {
	case "user":
		return "client"
	case "inbound", "outbound", "core":
		return scope
	default:
		return ""
	}
}

// GRPCStatsClient uses the v2ray-compatible StatsService over local h2c gRPC.
// It implements only the small protobuf/gRPC surface MiGate needs so the
// release binary does not need generated protobuf dependencies.
type GRPCStatsClient struct {
	addr      string
	baseURL   string
	service   string
	engine    string
	transport grpcRoundTripper
}

// NewGRPCStatsClient creates a gRPC client for querying Xray stats.
func NewGRPCStatsClient(ctx context.Context, addr string) (*GRPCStatsClient, error) {
	return NewGRPCStatsClientWithEngine(ctx, addr, "xray")
}

func NewGRPCStatsClientWithEngine(ctx context.Context, addr, engine string) (*GRPCStatsClient, error) {
	return NewGRPCStatsClientWithEngineAndService(ctx, addr, engine, "xray.app.stats.command.StatsService")
}

func NewGRPCStatsClientWithEngineAndService(ctx context.Context, addr, engine, service string) (*GRPCStatsClient, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	engine = strings.TrimSpace(engine)
	if engine == "" {
		engine = "xray"
	}
	service = strings.Trim(strings.TrimSpace(service), "/")
	if service == "" {
		service = "xray.app.stats.command.StatsService"
	}
	baseURL, target, err := statsServiceBaseURL(addr)
	if err != nil {
		return nil, err
	}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{
		Protocols: protocols,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", target)
		},
	}
	return &GRPCStatsClient{addr: addr, baseURL: baseURL, service: service, engine: engine, transport: transport}, nil
}

func (c *GRPCStatsClient) QueryAllStats(ctx context.Context) (map[string]*ClientStats, error) {
	rawStats, err := c.QueryTrafficStats(ctx)
	if err != nil {
		return nil, err
	}
	result := map[string]*ClientStats{}
	for _, st := range rawStats {
		if st.ScopeType != "client" {
			continue
		}
		result[st.ScopeKey] = &ClientStats{Email: st.ScopeKey, Uplink: st.Uplink, Downlink: st.Downlink}
	}
	return result, nil
}

func (c *GRPCStatsClient) QueryTrafficStats(ctx context.Context) ([]TrafficStat, error) {
	stats, err := c.queryStats(ctx, ">>>traffic>>>", false)
	if err != nil {
		return nil, err
	}
	raw := struct {
		Stat []struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
		} `json:"stat"`
	}{Stat: stats}
	payload, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	return ParseTrafficStatsQueryOutput(c.engine, payload)
}

func (c *GRPCStatsClient) Close() error {
	if transport, ok := c.transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

func (c *GRPCStatsClient) queryStats(ctx context.Context, pattern string, reset bool) ([]struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}, error) {
	payload := encodeGRPCFrame(encodeQueryStatsRequest(pattern, reset))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/"+c.service+"/QueryStats", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")
	req.Header.Set("Grpc-Encoding", "identity")
	req.Header.Set("Grpc-Accept-Encoding", "identity")

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("stats grpc query %s: %w", c.addr, err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if readErr != nil {
			return nil, fmt.Errorf("stats grpc query %s: http %d: %w", c.addr, resp.StatusCode, readErr)
		}
		return nil, fmt.Errorf("stats grpc query %s: http %d: %s", c.addr, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if readErr != nil {
		return nil, fmt.Errorf("stats grpc query %s: read response: %w", c.addr, readErr)
	}
	if status := resp.Trailer.Get("Grpc-Status"); status != "" && status != "0" {
		msg := resp.Trailer.Get("Grpc-Message")
		if decoded, err := url.QueryUnescape(msg); err == nil {
			msg = decoded
		}
		return nil, fmt.Errorf("stats grpc query %s: grpc status %s %s", c.addr, status, strings.TrimSpace(msg))
	}
	messages, err := decodeGRPCFrames(body)
	if err != nil {
		return nil, fmt.Errorf("stats grpc query %s: %w", c.addr, err)
	}
	stats := make([]struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
	}, 0)
	for _, msg := range messages {
		decoded, err := decodeQueryStatsResponse(msg)
		if err != nil {
			return nil, fmt.Errorf("stats grpc query %s: decode response: %w", c.addr, err)
		}
		stats = append(stats, decoded...)
	}
	return stats, nil
}

func statsServiceBaseURL(addr string) (baseURL, target string, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = "127.0.0.1:10085"
	}
	switch {
	case strings.HasPrefix(addr, "http://"):
		u, err := url.Parse(addr)
		if err != nil {
			return "", "", err
		}
		return "http://" + u.Host, u.Host, nil
	case strings.HasPrefix(addr, "tcp:"):
		target = strings.TrimPrefix(addr, "tcp:")
	case strings.HasPrefix(addr, "unix:"):
		return "", "", fmt.Errorf("stats grpc unix sockets are not supported without grpc dependencies")
	default:
		target = addr
	}
	if strings.TrimSpace(target) == "" {
		return "", "", fmt.Errorf("stats grpc address is empty")
	}
	return "http://" + target, target, nil
}

func encodeGRPCFrame(message []byte) []byte {
	frame := make([]byte, 5+len(message))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(message)))
	copy(frame[5:], message)
	return frame
}

func decodeGRPCFrames(raw []byte) ([][]byte, error) {
	var messages [][]byte
	for len(raw) > 0 {
		if len(raw) < 5 {
			return nil, fmt.Errorf("truncated grpc frame header")
		}
		if raw[0] != 0 {
			return nil, fmt.Errorf("compressed grpc frames are not supported")
		}
		size := int(binary.BigEndian.Uint32(raw[1:5]))
		raw = raw[5:]
		if len(raw) < size {
			return nil, fmt.Errorf("truncated grpc frame payload")
		}
		messages = append(messages, raw[:size])
		raw = raw[size:]
	}
	return messages, nil
}

func encodeQueryStatsRequest(pattern string, reset bool) []byte {
	var out []byte
	if pattern != "" {
		out = append(out, 0x0a)
		out = appendVarint(out, uint64(len(pattern)))
		out = append(out, pattern...)
	}
	if reset {
		out = append(out, 0x10, 0x01)
	}
	return out
}

func encodeQueryStatsResponse(stats []TrafficStat) []byte {
	var out []byte
	for _, st := range stats {
		if st.Uplink != 0 {
			out = append(out, encodeStatMessage(st.ScopeType, st.ScopeKey, "uplink", st.Uplink)...)
		}
		if st.Downlink != 0 {
			out = append(out, encodeStatMessage(st.ScopeType, st.ScopeKey, "downlink", st.Downlink)...)
		}
	}
	return out
}

func encodeStatMessage(scopeType, scopeKey, direction string, value int64) []byte {
	scope := scopeType
	if scopeType == "client" {
		scope = "user"
	}
	name := strings.Join([]string{scope, scopeKey, "traffic", direction}, ">>>")
	var stat []byte
	stat = append(stat, 0x0a)
	stat = appendVarint(stat, uint64(len(name)))
	stat = append(stat, name...)
	stat = append(stat, 0x10)
	stat = appendVarint(stat, uint64(value))

	var out []byte
	out = append(out, 0x0a)
	out = appendVarint(out, uint64(len(stat)))
	out = append(out, stat...)
	return out
}

func decodeQueryStatsResponse(raw []byte) ([]struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}, error) {
	stats := []struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
	}{}
	for len(raw) > 0 {
		field, n := consumeVarint(raw)
		if n <= 0 {
			return nil, fmt.Errorf("invalid protobuf field")
		}
		raw = raw[n:]
		fieldNum := field >> 3
		wireType := field & 0x7
		if fieldNum != 1 || wireType != 2 {
			var err error
			raw, err = skipProtoField(raw, wireType)
			if err != nil {
				return nil, err
			}
			continue
		}
		size, n := consumeVarint(raw)
		if n <= 0 || len(raw[n:]) < int(size) {
			return nil, fmt.Errorf("invalid stat message length")
		}
		stat, err := decodeStat(raw[n : n+int(size)])
		if err != nil {
			return nil, err
		}
		stats = append(stats, stat)
		raw = raw[n+int(size):]
	}
	return stats, nil
}

func decodeStat(raw []byte) (struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}, error) {
	var stat struct {
		Name  string `json:"name"`
		Value int64  `json:"value"`
	}
	for len(raw) > 0 {
		field, n := consumeVarint(raw)
		if n <= 0 {
			return stat, fmt.Errorf("invalid stat field")
		}
		raw = raw[n:]
		fieldNum := field >> 3
		wireType := field & 0x7
		switch {
		case fieldNum == 1 && wireType == 2:
			size, n := consumeVarint(raw)
			if n <= 0 || len(raw[n:]) < int(size) {
				return stat, fmt.Errorf("invalid stat name length")
			}
			stat.Name = string(raw[n : n+int(size)])
			raw = raw[n+int(size):]
		case fieldNum == 2 && wireType == 0:
			value, n := consumeVarint(raw)
			if n <= 0 {
				return stat, fmt.Errorf("invalid stat value")
			}
			stat.Value = int64(value)
			raw = raw[n:]
		default:
			var err error
			raw, err = skipProtoField(raw, wireType)
			if err != nil {
				return stat, err
			}
		}
	}
	return stat, nil
}

func appendVarint(out []byte, v uint64) []byte {
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func consumeVarint(raw []byte) (uint64, int) {
	var value uint64
	for i, b := range raw {
		if i == 10 {
			return 0, -1
		}
		value |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return value, i + 1
		}
	}
	return 0, -1
}

func skipProtoField(raw []byte, wireType uint64) ([]byte, error) {
	switch wireType {
	case 0:
		_, n := consumeVarint(raw)
		if n <= 0 {
			return nil, fmt.Errorf("invalid varint field")
		}
		return raw[n:], nil
	case 1:
		if len(raw) < 8 {
			return nil, fmt.Errorf("invalid fixed64 field")
		}
		return raw[8:], nil
	case 2:
		size, n := consumeVarint(raw)
		if n <= 0 || len(raw[n:]) < int(size) {
			return nil, fmt.Errorf("invalid bytes field")
		}
		return raw[n+int(size):], nil
	case 5:
		if len(raw) < 4 {
			return nil, fmt.Errorf("invalid fixed32 field")
		}
		return raw[4:], nil
	default:
		return nil, fmt.Errorf("unsupported protobuf wire type %d", wireType)
	}
}
