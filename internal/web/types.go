package web

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/paths"
	certsvc "github.com/imzyb/MiGate/internal/service/cert"
	"github.com/imzyb/MiGate/internal/singbox"
	"github.com/imzyb/MiGate/internal/xray"
)

type XrayStatusStore interface {
	ListInbounds(ctx context.Context) ([]db.Inbound, error)
}

type clientTrafficSummary struct {
	Up            int64   `json:"up"`
	Down          int64   `json:"down"`
	RateUp        float64 `json:"rate_up"`
	RateDown      float64 `json:"rate_down"`
	Status        string  `json:"status"`
	Message       string  `json:"message,omitempty"`
	Engine        string  `json:"engine,omitempty"`
	XrayUp        int64   `json:"xray_up,omitempty"`
	XrayDown      int64   `json:"xray_down,omitempty"`
	LastSampledAt string  `json:"last_sampled_at,omitempty"`
	Source        string  `json:"source,omitempty"`
	Note          string  `json:"note,omitempty"`
}

type inboundTrafficSummary struct {
	Up            int64   `json:"up"`
	Down          int64   `json:"down"`
	Total         int64   `json:"total"`
	RateUp        float64 `json:"rate_up"`
	RateDown      float64 `json:"rate_down"`
	Status        string  `json:"status"`
	Message       string  `json:"message,omitempty"`
	Engine        string  `json:"engine,omitempty"`
	LastSampledAt string  `json:"last_sampled_at,omitempty"`
	Source        string  `json:"source,omitempty"`
}

type trafficSeriesPoint struct {
	Name     string  `json:"name"`
	Time     string  `json:"time,omitempty"`
	Up       int64   `json:"up"`
	Down     int64   `json:"down"`
	RateUp   float64 `json:"rate_up,omitempty"`
	RateDown float64 `json:"rate_down,omitempty"`
}

type inboundView struct {
	db.Inbound
	TrafficUp      int64                          `json:"traffic_up"`
	TrafficDown    int64                          `json:"traffic_down"`
	TrafficTotal   int64                          `json:"traffic_total"`
	RateUp         float64                        `json:"rate_up"`
	RateDown       float64                        `json:"rate_down"`
	TrafficStatus  string                         `json:"traffic_status"`
	TrafficMessage string                         `json:"traffic_message,omitempty"`
	TrafficSource  string                         `json:"traffic_stats_source"`
	RealtimeSource string                         `json:"realtime_stats_source,omitempty"`
	ClientTraffic  map[int64]clientTrafficSummary `json:"client_traffic,omitempty"`
}

type inboundTrafficView struct {
	ID             int64                          `json:"id"`
	UUID           string                         `json:"uuid"`
	Remark         string                         `json:"remark"`
	Protocol       string                         `json:"protocol"`
	Port           int                            `json:"port"`
	Network        string                         `json:"network"`
	Security       string                         `json:"security"`
	Enabled        bool                           `json:"enabled"`
	Clients        []db.Client                    `json:"clients"`
	TrafficUp      int64                          `json:"traffic_up"`
	TrafficDown    int64                          `json:"traffic_down"`
	TrafficTotal   int64                          `json:"traffic_total"`
	RateUp         float64                        `json:"rate_up"`
	RateDown       float64                        `json:"rate_down"`
	TrafficStatus  string                         `json:"traffic_status"`
	TrafficMessage string                         `json:"traffic_message,omitempty"`
	TrafficSource  string                         `json:"traffic_stats_source"`
	RealtimeSource string                         `json:"realtime_stats_source,omitempty"`
	ClientTraffic  map[int64]clientTrafficSummary `json:"client_traffic,omitempty"`
}

type Store interface {
	ListInbounds(ctx context.Context) ([]db.Inbound, error)
	ListInboundTraffic(ctx context.Context) ([]db.Inbound, error)
	ValidationConfigHash(ctx context.Context) (string, error)
	ValidationConfigVersion(ctx context.Context) (int64, error)
	InboundExists(ctx context.Context, id int64) (bool, error)
	FindInboundByPort(ctx context.Context, port int, excludeID int64) (db.Inbound, bool, error)
	GetSubscriptionByClientUUID(ctx context.Context, uuid string) (db.Inbound, db.Client, bool, error)
	GetSubscriptionByToken(ctx context.Context, token string) (db.Inbound, db.Client, bool, error)
	CreateInbound(ctx context.Context, params db.CreateInboundParams) (db.Inbound, error)
	ListOutbounds(ctx context.Context) ([]db.Outbound, error)
	CreateOutbound(ctx context.Context, params db.CreateOutboundParams) (db.Outbound, error)
	UpdateOutbound(ctx context.Context, id int64, params db.UpdateOutboundParams) (db.Outbound, error)
	DeleteOutbound(ctx context.Context, id int64) error
	ReorderOutbounds(ctx context.Context, ids []int64) error
	ListOutboundSubscriptions(ctx context.Context) ([]db.OutboundSubscription, error)
	GetOutboundSubscription(ctx context.Context, id int64) (db.OutboundSubscription, bool, error)
	CreateOutboundSubscription(ctx context.Context, params db.CreateOutboundSubscriptionParams) (db.OutboundSubscription, error)
	UpdateOutboundSubscription(ctx context.Context, id int64, params db.UpdateOutboundSubscriptionParams) (db.OutboundSubscription, error)
	DeleteOutboundSubscription(ctx context.Context, id int64) error
	ReorderOutboundSubscriptions(ctx context.Context, ids []int64) error
	MarkOutboundSubscriptionFetch(ctx context.Context, id int64, fetchedAt time.Time, lastErr string, identities []string) error
	MaterializeSubscriptionOutbounds(ctx context.Context, subscriptionID int64, nodes []db.MaterializedSubscriptionOutbound, identities []string) ([]db.Outbound, error)
	ListRoutingRules(ctx context.Context) ([]db.RoutingRule, error)
	CreateRoutingRule(ctx context.Context, params db.CreateRoutingRuleParams) (db.RoutingRule, error)
	UpdateRoutingRule(ctx context.Context, id int64, params db.UpdateRoutingRuleParams) (db.RoutingRule, error)
	DeleteRoutingRule(ctx context.Context, id int64) error
	ReorderRoutingRules(ctx context.Context, ids []int64) error
	CreateClient(ctx context.Context, params db.CreateClientParams) (db.Client, error)
	DeleteInbound(ctx context.Context, id int64) error
	DeleteClient(ctx context.Context, id int64) error
	UpdateInbound(ctx context.Context, id int64, params db.UpdateInboundParams) (db.Inbound, error)
	UpdateClient(ctx context.Context, id int64, params db.UpdateClientParams) (db.Client, error)
	SetInboundEnabled(ctx context.Context, id int64, enabled bool) (db.Inbound, error)
	SetOutboundEnabled(ctx context.Context, id int64, enabled bool) (db.Outbound, error)
	SetClientEnabled(ctx context.Context, inboundID int64, id int64, enabled bool) (db.Client, error)
	ResetClientTraffic(ctx context.Context, id int64) (db.Client, error)
	ResetClientTrafficBaseline(ctx context.Context, id int64, baselines []db.TrafficRawStat) (db.Client, error)
	GetClientTrafficUsage(ctx context.Context, statsKey string) (db.ClientTrafficUsage, bool, error)
	GetClientTrafficUsageForClient(ctx context.Context, clientID int64) (db.ClientTrafficUsage, bool, error)
	ListTrafficStates(ctx context.Context) ([]db.TrafficState, error)
	ListTrafficSamples(ctx context.Context, scopeType string, since time.Time, limit int) ([]db.TrafficSample, error)
	ApplyTrafficRawStats(ctx context.Context, stats []db.TrafficRawStat, observedAt time.Time) error
	MarkTrafficUnavailable(ctx context.Context, engine, status, message string, observedAt time.Time) error
	AddToBlacklist(ctx context.Context, tokenHash string, expiresAt time.Time, revoked bool) error
	IsBlacklisted(ctx context.Context, tokenHash string) (bool, error)
	RecordSessionTouch(ctx context.Context, tokenHash string) error
	PruneActiveSessions(ctx context.Context, maxActive int) error
	ListActiveSessions(ctx context.Context) ([]db.BlacklistedSession, error)
	RevokeSession(ctx context.Context, id int64) error
	RevokeOtherSessions(ctx context.Context, currentTokenHash string) (int64, error)
}

type sessionTouchThrottler interface {
	RecordSessionTouchAfter(ctx context.Context, tokenHash string, minAge time.Duration) error
}

type XrayController interface {
	Status(ctx context.Context) XrayStatus
	Apply(ctx context.Context) XrayApplyResult
	Version(ctx context.Context) string
}

type CoreListenerDiagnostic struct {
	InboundID       int64  `json:"inbound_id"`
	Protocol        string `json:"protocol"`
	Port            int    `json:"port"`
	Network         string `json:"network,omitempty"`
	Transport       string `json:"transport"`
	Path            string `json:"path,omitempty"`
	GrpcServiceName string `json:"grpc_service_name,omitempty"`
	Security        string `json:"security,omitempty"`
	Listening       bool   `json:"listening"`
}

type CoreDiagnosticAction struct {
	Code      string `json:"code"`
	Severity  string `json:"severity"`
	Category  string `json:"category"`
	Message   string `json:"message"`
	Command   string `json:"command,omitempty"`
	InboundID int64  `json:"inbound_id,omitempty"`
	Port      int    `json:"port,omitempty"`
}

type CoreStatus struct {
	Core              string                   `json:"core"`
	Installed         bool                     `json:"installed"`
	Managed           bool                     `json:"managed"`
	Service           string                   `json:"service"`
	ServiceStatus     string                   `json:"service_status"`
	BinaryPath        string                   `json:"binary_path"`
	BinaryVersion     string                   `json:"binary_version"`
	ConfigPath        string                   `json:"config_path"`
	ConfigExists      bool                     `json:"config_exists"`
	ConfigValid       bool                     `json:"config_valid"`
	ConfigError       string                   `json:"config_error,omitempty"`
	Status            string                   `json:"status,omitempty"`
	Version           string                   `json:"version,omitempty"`
	MemoryRSSBytes    int64                    `json:"memory_rss_bytes,omitempty"`
	Uptime            string                   `json:"uptime,omitempty"`
	ActiveConnections int                      `json:"active_connections,omitempty"`
	CommandsExecuted  []string                 `json:"commands_executed,omitempty"`
	ListeningPorts    []CoreListenerDiagnostic `json:"listening_ports,omitempty"`
}

type XrayStatus struct {
	Core              string                   `json:"core"`
	Service           string                   `json:"service"`
	Status            string                   `json:"status"`
	ServiceStatus     string                   `json:"service_status"`
	Managed           bool                     `json:"managed"`
	Installed         bool                     `json:"installed"`
	Version           string                   `json:"version"`
	BinaryPath        string                   `json:"binary_path"`
	BinaryVersion     string                   `json:"binary_version"`
	ConfigExists      bool                     `json:"config_exists"`
	ConfigValid       bool                     `json:"config_valid"`
	ConfigError       string                   `json:"config_error,omitempty"`
	MemoryRSSBytes    int64                    `json:"memory_rss_bytes"`
	Uptime            string                   `json:"uptime"`
	ActiveConnections int                      `json:"active_connections"`
	ConfigPath        string                   `json:"config_path"`
	CommandsExecuted  []string                 `json:"commands_executed"`
	ListeningPorts    []CoreListenerDiagnostic `json:"listening_ports"`
}

type XrayApplyResult struct {
	Applied           bool     `json:"applied"`
	Status            string   `json:"status"`
	Service           string   `json:"service"`
	ConfigPath        string   `json:"config_path,omitempty"`
	CommandsExecuted  []string `json:"commands_executed"`
	Error             string   `json:"error,omitempty"`
	Detail            string   `json:"detail,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
	PostApplyWarnings []string `json:"post_apply_warnings,omitempty"`
	Inbounds          int      `json:"inbounds,omitempty"`
	Outbounds         int      `json:"outbounds,omitempty"`
	Rules             int      `json:"rules,omitempty"`
	ErrorOutput       string   `json:"error_output,omitempty"`
}

type defaultXrayController struct{}

func (defaultXrayController) Status(ctx context.Context) XrayStatus {
	return XrayStatus{Core: "xray", Service: paths.XrayService, Status: "unknown", ServiceStatus: "unknown", Managed: false, BinaryPath: paths.XrayBinary, ConfigPath: paths.XrayConfig, CommandsExecuted: []string{}}
}

func (defaultXrayController) Apply(ctx context.Context) XrayApplyResult {
	return XrayApplyResult{Applied: false, Status: "not_managed", Service: "xray", Error: "not_managed", Detail: "xray controller is not configured", CommandsExecuted: []string{}}
}

func (defaultXrayController) Version(ctx context.Context) string { return "" }

type routerConfig struct {
	store              Store
	certLookupIP       func(context.Context, string) ([]net.IP, error)
	certListenTCP      func(network, address string) (net.Listener, error)
	certIssuer         certsvc.Issuer
	xrayController     XrayController
	singboxRuntime     SingboxRuntime
	authEnabled        bool
	authUsername       string
	authPassword       string
	authMu             sync.RWMutex
	sessionSecret      []byte
	configDir          string
	certDir            string
	xrayConfigPath     string
	version            string
	basePath           string
	statsClient        xray.StatsClient
	singboxStatsClient singbox.StatsClient
	socks5PoolURL      string
	httpPoolURL        string
	httpsPoolURL       string
	updateCheckURL     string
	updateStatusPath   string
	publicHost         string
	trustProxy         bool
	loginLimiter       *loginLimiter
	coreScriptRunner   func(script string) ([]byte, error)
	singboxApplier     func(ctx context.Context, store Store, runtime SingboxRuntime, strict bool) SingboxApplySummary
	singboxApplierSet  bool
	singboxProbe       SingboxProbe
	singboxListeners   func(ctx context.Context, cfg *routerConfig) []CoreListenerDiagnostic
	xrayProbe          XrayProbe
	xrayListeners      func(ctx context.Context, cfg *routerConfig) []CoreListenerDiagnostic
	outboundFetcher    SubscriptionFetcher
	sessionTouches     map[string]time.Time
	sessionTouchGC     time.Time
	sessionTouchMu     sync.Mutex
}

type SingboxRuntime interface {
	Capability(ctx context.Context) singbox.Capability
}

type defaultSingboxRuntime struct{}

var defaultSingboxCapabilityCache = &cachedSingboxRuntime{}

func (defaultSingboxRuntime) Capability(ctx context.Context) singbox.Capability {
	return defaultSingboxCapabilityCache.Capability(ctx)
}

type cachedSingboxRuntime struct {
	mu         sync.Mutex
	capability singbox.Capability
	checked    bool
}

func (r *cachedSingboxRuntime) Capability(ctx context.Context) singbox.Capability {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.checked {
		return r.capability
	}
	r.capability = singbox.DetectCapability(ctx)
	r.checked = true
	return r.capability
}
