package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/scheduler"
	"github.com/imzyb/MiGate/internal/singbox"
	"github.com/imzyb/MiGate/internal/vpngate"
	"github.com/imzyb/MiGate/internal/web/static"
	"github.com/imzyb/MiGate/internal/xray"
)

var validDomain = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
var validEmail = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

const maxXrayLogLines = 200

type Store interface {
	ListInbounds(ctx context.Context) ([]db.Inbound, error)
	CreateInbound(ctx context.Context, params db.CreateInboundParams) (db.Inbound, error)
	ListOutbounds(ctx context.Context) ([]db.Outbound, error)
	CreateOutbound(ctx context.Context, params db.CreateOutboundParams) (db.Outbound, error)
	UpdateOutbound(ctx context.Context, id int64, params db.UpdateOutboundParams) (db.Outbound, error)
	DeleteOutbound(ctx context.Context, id int64) error
	ReorderOutbounds(ctx context.Context, ids []int64) error
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
	AddToBlacklist(ctx context.Context, tokenHash string, expiresAt time.Time, revoked bool) error
	IsBlacklisted(ctx context.Context, tokenHash string) (bool, error)
	RecordSessionTouch(ctx context.Context, tokenHash string) error
	ListActiveSessions(ctx context.Context) ([]db.BlacklistedSession, error)
	RevokeSession(ctx context.Context, id int64) error
}

type XrayController interface {
	Status(ctx context.Context) XrayStatus
	Apply(ctx context.Context) XrayApplyResult
	Version(ctx context.Context) string
}

type XrayStatus struct {
	Service          string   `json:"service"`
	Status           string   `json:"status"`
	Managed          bool     `json:"managed"`
	CommandsExecuted []string `json:"commands_executed"`
}

type XrayApplyResult struct {
	Status           string   `json:"status"`
	Service          string   `json:"service"`
	CommandsExecuted []string `json:"commands_executed"`
	ErrorOutput      string   `json:"error_output,omitempty"`
}

type defaultXrayController struct{}

func (defaultXrayController) Status(ctx context.Context) XrayStatus {
	return XrayStatus{Service: "xray", Status: "unknown", Managed: false, CommandsExecuted: []string{}}
}

func (defaultXrayController) Apply(ctx context.Context) XrayApplyResult {
	return XrayApplyResult{Status: "not_managed"}
}

// xrayApplyerAdapter adapts XrayController to scheduler.XrayApplyer.
type xrayApplyerAdapter struct {
	ctrl XrayController
}

func (a *xrayApplyerAdapter) Apply(ctx context.Context) error {
	res := a.ctrl.Apply(ctx)
	if res.Status == "applied" {
		return nil
	}
	if res.ErrorOutput != "" {
		return fmt.Errorf("apply failed: %s", res.ErrorOutput)
	}
	return fmt.Errorf("apply failed: status=%s", res.Status)
}

// NewXrayApplyer wraps an XrayController as a scheduler.XrayApplyer.
func NewXrayApplyer(ctrl XrayController) scheduler.XrayApplyer {
	return &xrayApplyerAdapter{ctrl: ctrl}
}

func (defaultXrayController) Version(ctx context.Context) string { return "" }

type routerConfig struct {
	store                       Store
	xrayController              XrayController
	authEnabled                 bool
	authUsername                string
	authPassword                string
	sessionSecret               []byte
	configDir                   string
	version                     string
	basePath                    string
	vpnGateFetcher              VPNGateFetcher
	vpnGateRuntimeProbe         VPNGateRuntimeProbe
	vpnGateRuntimeStarter       VPNGateRuntimeStarter
	vpnGateRuntimeStopper       VPNGateRuntimeStopper
	vpnGateRuntimeHealthChecker VPNGateRuntimeHealthChecker
	vpnGateRuntimeRunner        VPNGateRuntimeCommandRunner
	statsClient                 xray.StatsClient
	healthScheduler             *scheduler.VPNGateHealthScheduler
}

type VPNGateFetcher interface {
	FetchServers() ([]VPNGateServer, error)
}

type VPNGateRuntimeProbe interface {
	LookPath(name string) (string, error)
}

type VPNGateRuntimeStarter interface {
	Start(ctx context.Context, target VPNGateRuntimeStartTarget) (VPNGateRuntimeStartResult, error)
}

type VPNGateRuntimeStopper interface {
	Stop(ctx context.Context, target VPNGateRuntimeStartTarget) (VPNGateRuntimeStopResult, error)
}

type VPNGateRuntimeHealthChecker interface {
	Check(ctx context.Context, target VPNGateRuntimeStartTarget) (VPNGateRuntimeHealth, error)
}

type VPNGateRuntimeCommandRunner interface {
	Run(ctx context.Context, command string, args ...string) error
}

type VPNGateRuntimeStartTarget struct {
	Runtime         string            `json:"runtime"`
	OutboundID      int64             `json:"outbound_id"`
	OutboundTag     string            `json:"outbound_tag"`
	BridgeAddress   string            `json:"bridge_address"`
	BridgePort      int               `json:"bridge_port"`
	ServerHostName  string            `json:"server_hostname"`
	ServerIP        string            `json:"server_ip"`
	DependencyPaths map[string]string `json:"dependency_paths"`
}

type VPNGateRuntimeStartResult struct {
	Status              string   `json:"status"`
	Runtime             string   `json:"runtime"`
	OutboundID          int64    `json:"outbound_id"`
	OutboundTag         string   `json:"outbound_tag"`
	BridgeAddress       string   `json:"bridge_address"`
	BridgePort          int      `json:"bridge_port"`
	VPNConnected        bool     `json:"vpn_connected"`
	SocksBridgeRunning  bool     `json:"socks_bridge_running"`
	NonNativeEgressOK   bool     `json:"non_native_egress_ok"`
	ExitIP              string   `json:"exit_ip,omitempty"`
	NativeIP            string   `json:"native_ip,omitempty"`
	LatencyMS           int64    `json:"latency_ms,omitempty"`
	KillSwitchOK        bool     `json:"kill_switch_ok"`
	XrayApplied         bool     `json:"xray_applied"`
	LastError           string   `json:"last_error"`
	PerformsSideEffects bool     `json:"performs_side_effects"`
	CommandsExecuted    []string `json:"commands_executed"`
}

type VPNGateRuntimeHealth struct {
	VPNConnected       bool   `json:"vpn_connected"`
	SocksBridgeRunning bool   `json:"socks_bridge_running"`
	NonNativeEgressOK  bool   `json:"non_native_egress_ok"`
	ExitIP             string `json:"exit_ip,omitempty"`
	NativeIP           string `json:"native_ip,omitempty"`
	LatencyMS          int64  `json:"latency_ms,omitempty"`
	KillSwitchOK       bool   `json:"kill_switch_ok"`
	LastError          string `json:"last_error"`
}

type VPNGateRuntimeStopResult struct {
	Status              string   `json:"status"`
	Runtime             string   `json:"runtime"`
	OutboundID          int64    `json:"outbound_id"`
	OutboundTag         string   `json:"outbound_tag"`
	PerformsSideEffects bool     `json:"performs_side_effects"`
	CommandsExecuted    []string `json:"commands_executed"`
}

type execVPNGateRuntimeProbe struct{}

func (execVPNGateRuntimeProbe) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

type execVPNGateRuntimeCommandRunner struct{}

type execVPNGateRuntimeHealthChecker struct{}

func (execVPNGateRuntimeHealthChecker) Check(ctx context.Context, target VPNGateRuntimeStartTarget) (VPNGateRuntimeHealth, error) {
	address := strings.TrimSpace(target.BridgeAddress)
	if address == "" {
		address = "127.0.0.1"
	}
	endpoint := net.JoinHostPort(address, strconv.Itoa(target.BridgePort))
	started := time.Now()
	exitIP, handshakeOK, err := fetchIPViaSocks5(ctx, endpoint, "api.ipify.org")
	latency := time.Since(started).Milliseconds()
	if err != nil {
		return VPNGateRuntimeHealth{VPNConnected: false, SocksBridgeRunning: handshakeOK, NonNativeEgressOK: false, KillSwitchOK: false, LatencyMS: latency, LastError: err.Error()}, nil
	}
	nativeIP, nativeErr := fetchNativeIP(ctx)
	if nativeErr != nil {
		return VPNGateRuntimeHealth{VPNConnected: true, SocksBridgeRunning: true, NonNativeEgressOK: false, ExitIP: exitIP, LatencyMS: latency, KillSwitchOK: false, LastError: "native_ip_lookup_failed: " + nativeErr.Error()}, nil
	}
	nonNative := exitIP != "" && nativeIP != "" && exitIP != nativeIP
	lastErr := ""
	if !nonNative {
		lastErr = "native_ip_leak"
	}
	return VPNGateRuntimeHealth{VPNConnected: true, SocksBridgeRunning: true, NonNativeEgressOK: nonNative, ExitIP: exitIP, NativeIP: nativeIP, LatencyMS: latency, KillSwitchOK: nonNative, LastError: lastErr}, nil
}

func fetchNativeIP(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://api.ipify.org/", nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || net.ParseIP(ip) == nil {
		return "", fmt.Errorf("unexpected native ip response %d %q", resp.StatusCode, ip)
	}
	return ip, nil
}

func fetchIPViaSocks5(ctx context.Context, endpoint, host string) (ip string, handshakeOK bool, err error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return "", false, fmt.Errorf("socks_bridge_unreachable: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return "", false, fmt.Errorf("socks_handshake_write_failed: %w", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", false, fmt.Errorf("socks_handshake_read_failed: %w", err)
	}
	if buf[0] != 0x05 || buf[1] == 0xff {
		return "", false, fmt.Errorf("socks_handshake_rejected: %02x %02x", buf[0], buf[1])
	}
	addr := []byte(host)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(addr))}
	req = append(req, addr...)
	req = append(req, 0x00, 0x50)
	if _, err := conn.Write(req); err != nil {
		return "", true, fmt.Errorf("socks_connect_write_failed: %w", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", true, fmt.Errorf("socks_connect_read_failed: %w", err)
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		return "", true, fmt.Errorf("socks_connect_rejected: %02x %02x", head[0], head[1])
	}
	switch head[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 4+2))
	case 0x03:
		l := make([]byte, 1)
		if _, err = io.ReadFull(conn, l); err == nil {
			_, err = io.ReadFull(conn, make([]byte, int(l[0])+2))
		}
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 16+2))
	default:
		err = fmt.Errorf("socks_connect_unknown_addr_type: %02x", head[3])
	}
	if err != nil {
		return "", true, err
	}
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		return "", true, fmt.Errorf("exit_ip_request_failed: %w", err)
	}
	body, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil {
		return "", true, fmt.Errorf("exit_ip_read_failed: %w", err)
	}
	parts := strings.SplitN(string(body), "\r\n\r\n", 2)
	if len(parts) != 2 || !strings.Contains(parts[0], " 200 ") {
		return "", true, fmt.Errorf("unexpected_exit_ip_response")
	}
	ip = strings.TrimSpace(parts[1])
	if net.ParseIP(ip) == nil {
		return "", true, fmt.Errorf("invalid_exit_ip_response: %q", ip)
	}
	return ip, true, nil
}

func (execVPNGateRuntimeCommandRunner) Run(ctx context.Context, command string, args ...string) error {
	cmd := exec.CommandContext(ctx, command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return fmt.Errorf("%s %s: %w: %s", command, strings.Join(args, " "), err, detail)
		}
		return fmt.Errorf("%s %s: %w", command, strings.Join(args, " "), err)
	}
	return nil
}

type vpngateRuntimeStarter struct {
	runner VPNGateRuntimeCommandRunner
}

func NewVPNGateRuntimeStarter(runner VPNGateRuntimeCommandRunner) VPNGateRuntimeStarter {
	return vpngateRuntimeStarter{runner: runner}
}

func NewVPNGateRuntimeStopper(runner VPNGateRuntimeCommandRunner) VPNGateRuntimeStopper {
	return vpngateRuntimeStarter{runner: runner}
}

func (s vpngateRuntimeStarter) Start(ctx context.Context, target VPNGateRuntimeStartTarget) (VPNGateRuntimeStartResult, error) {
	if s.runner == nil {
		return VPNGateRuntimeStartResult{}, errors.New("runtime command runner is required")
	}
	if target.Runtime != "softether_netns_socks_bridge" {
		return VPNGateRuntimeStartResult{}, fmt.Errorf("unsupported vpngate runtime %q", target.Runtime)
	}
	netns := fmt.Sprintf("migate-vpngate-%d", target.OutboundID)
	ip := strings.TrimSpace(target.DependencyPaths["ip"])
	if ip == "" {
		ip = "ip"
	}
	vpnclient := strings.TrimSpace(target.DependencyPaths["vpnclient"])
	if vpnclient == "" {
		vpnclient = "vpnclient"
	}
	vpncmd := strings.TrimSpace(target.DependencyPaths["vpncmd"])
	if vpncmd == "" {
		vpncmd = "vpncmd"
	}
	microsocks := strings.TrimSpace(target.DependencyPaths["microsocks"])
	if microsocks == "" {
		microsocks = "microsocks"
	}
	nicName := fmt.Sprintf("migate%d", target.OutboundID)
	serverEndpoint := strings.TrimSpace(target.ServerHostName)
	if serverEndpoint == "" {
		serverEndpoint = strings.TrimSpace(target.ServerIP)
	}
	if serverEndpoint == "" {
		return VPNGateRuntimeStartResult{}, errors.New("vpngate server endpoint is required")
	}
	serverAddress := serverEndpoint + ":443"
	executed := []string{fmt.Sprintf("%s netns add %s", ip, netns)}
	if err := s.runner.Run(ctx, ip, "netns", "add", netns); err != nil {
		return VPNGateRuntimeStartResult{}, err
	}
	executed = append(executed, fmt.Sprintf("%s start", vpnclient))
	if err := s.runner.Run(ctx, vpnclient, "start"); err != nil {
		return VPNGateRuntimeStartResult{}, err
	}
	executed = append(executed, fmt.Sprintf("%s localhost /CLIENT /CMD NicCreate %s", vpncmd, nicName))
	if err := s.runner.Run(ctx, vpncmd, "localhost", "/CLIENT", "/CMD", "NicCreate", nicName); err != nil {
		return VPNGateRuntimeStartResult{}, err
	}
	executed = append(executed, fmt.Sprintf("%s localhost /CLIENT /CMD AccountCreate %s /SERVER:%s /HUB:VPNGATE /USERNAME:vpn /NICNAME:%s", vpncmd, nicName, serverAddress, nicName))
	if err := s.runner.Run(ctx, vpncmd, "localhost", "/CLIENT", "/CMD", "AccountCreate", nicName, "/SERVER:"+serverAddress, "/HUB:VPNGATE", "/USERNAME:vpn", "/NICNAME:"+nicName); err != nil {
		return VPNGateRuntimeStartResult{}, err
	}
	executed = append(executed, fmt.Sprintf("%s localhost /CLIENT /CMD AccountPasswordSet %s /PASSWORD:vpn /TYPE:standard", vpncmd, nicName))
	if err := s.runner.Run(ctx, vpncmd, "localhost", "/CLIENT", "/CMD", "AccountPasswordSet", nicName, "/PASSWORD:vpn", "/TYPE:standard"); err != nil {
		return VPNGateRuntimeStartResult{}, err
	}
	executed = append(executed, fmt.Sprintf("%s localhost /CLIENT /CMD AccountConnect %s", vpncmd, nicName))
	if err := s.runner.Run(ctx, vpncmd, "localhost", "/CLIENT", "/CMD", "AccountConnect", nicName); err != nil {
		return VPNGateRuntimeStartResult{}, err
	}
	executed = append(executed, fmt.Sprintf("%s netns exec %s sh -c 'nohup %s -i %s -p %d >/var/log/migate-vpngate-%d-microsocks.log 2>&1 &'", ip, netns, microsocks, target.BridgeAddress, target.BridgePort, target.OutboundID))
	bridgeCmd := fmt.Sprintf("nohup %s -i %s -p %d >/var/log/migate-vpngate-%d-microsocks.log 2>&1 &", shellQuote(microsocks), shellQuote(target.BridgeAddress), target.BridgePort, target.OutboundID)
	if err := s.runner.Run(ctx, ip, "netns", "exec", netns, "sh", "-c", bridgeCmd); err != nil {
		return VPNGateRuntimeStartResult{}, err
	}
	return VPNGateRuntimeStartResult{
		Status:              "started",
		Runtime:             target.Runtime,
		OutboundID:          target.OutboundID,
		OutboundTag:         target.OutboundTag,
		BridgeAddress:       target.BridgeAddress,
		BridgePort:          target.BridgePort,
		VPNConnected:        true,
		SocksBridgeRunning:  true,
		NonNativeEgressOK:   false,
		KillSwitchOK:        false,
		LastError:           "",
		PerformsSideEffects: true,
		CommandsExecuted:    executed,
	}, nil
}

func (s vpngateRuntimeStarter) Stop(ctx context.Context, target VPNGateRuntimeStartTarget) (VPNGateRuntimeStopResult, error) {
	if s.runner == nil {
		return VPNGateRuntimeStopResult{}, errors.New("runtime command runner is required")
	}
	if target.Runtime != "softether_netns_socks_bridge" {
		return VPNGateRuntimeStopResult{}, fmt.Errorf("unsupported vpngate runtime %q", target.Runtime)
	}
	ip := strings.TrimSpace(target.DependencyPaths["ip"])
	if ip == "" {
		ip = "ip"
	}
	vpncmd := strings.TrimSpace(target.DependencyPaths["vpncmd"])
	if vpncmd == "" {
		vpncmd = "vpncmd"
	}
	netns := fmt.Sprintf("migate-vpngate-%d", target.OutboundID)
	nicName := fmt.Sprintf("migate%d", target.OutboundID)
	executed := []string{fmt.Sprintf("%s localhost /CLIENT /CMD AccountDisconnect %s", vpncmd, nicName)}
	if err := s.runner.Run(ctx, vpncmd, "localhost", "/CLIENT", "/CMD", "AccountDisconnect", nicName); err != nil {
		return VPNGateRuntimeStopResult{}, err
	}
	executed = append(executed, fmt.Sprintf("%s netns exec %s pkill microsocks", ip, netns))
	if err := s.runner.Run(ctx, ip, "netns", "exec", netns, "pkill", "microsocks"); err != nil {
		return VPNGateRuntimeStopResult{}, err
	}
	executed = append(executed, fmt.Sprintf("%s netns del %s", ip, netns))
	if err := s.runner.Run(ctx, ip, "netns", "del", netns); err != nil {
		return VPNGateRuntimeStopResult{}, err
	}
	return VPNGateRuntimeStopResult{Status: "stopped", Runtime: target.Runtime, OutboundID: target.OutboundID, OutboundTag: target.OutboundTag, PerformsSideEffects: true, CommandsExecuted: executed}, nil
}

// VPNGateServer is the public type exposed to the web package.
type VPNGateServer struct {
	HostName     string `json:"hostname"`
	IP           string `json:"ip"`
	Score        int    `json:"score"`
	Ping         int    `json:"ping"`
	Speed        int64  `json:"speed"`
	CountryLong  string `json:"country_long"`
	CountryShort string `json:"country_short"`
	NumSessions  int    `json:"num_sessions"`
	Uptime       int64  `json:"uptime"`
	TotalUsers   int64  `json:"total_users"`
	TotalTraffic int64  `json:"total_traffic"`
	LogType      string `json:"log_type"`
	Operator     string `json:"operator"`
	Message      string `json:"message"`
	ServerType   string `json:"server_type"`
}

// classifyVPNGateType derives a type label from the operator string.
func classifyVPNGateType(operator string) string {
	op := strings.ToLower(operator)
	bizKeywords := []string{"aws", "amazon", "digitalocean", "vultr", "hetzner",
		"contabo", "linode", "ovh", "scaleway", "netcup", "leaseweb",
		"microsoft", "azure", "google", "gcp", "oracle", "rackspace",
		"ionos", "upcloud", "alibaba", "tencent", "vps", "hosting",
		"dedicated", "cloud", "datacenter", "server", "colocation",
		"inc", "llc", "ltd", "gmbh", "sarl"}
	for _, kw := range bizKeywords {
		if strings.Contains(op, kw) {
			return "商宽"
		}
	}
	return "家宽"
}

type Option func(*routerConfig)

func WithStore(store Store) Option {
	return func(cfg *routerConfig) {
		cfg.store = store
	}
}

func WithVersion(version string) Option {
	return func(cfg *routerConfig) {
		cfg.version = version
	}
}

func WithXrayController(controller XrayController) Option {
	return func(cfg *routerConfig) {
		cfg.xrayController = controller
	}
}

func WithConfigDir(dir string) Option {
	return func(cfg *routerConfig) {
		cfg.configDir = dir
	}
}

func WithBasePath(basePath string) Option {
	return func(cfg *routerConfig) {
		cfg.basePath = normalizeBasePath(basePath)
	}
}

func WithVPNGateFetcher(fetcher VPNGateFetcher) Option {
	return func(cfg *routerConfig) {
		cfg.vpnGateFetcher = fetcher
	}
}

func WithVPNGateRuntimeProbe(probe VPNGateRuntimeProbe) Option {
	return func(cfg *routerConfig) {
		cfg.vpnGateRuntimeProbe = probe
	}
}

func WithVPNGateRuntimeStarter(starter VPNGateRuntimeStarter) Option {
	return func(cfg *routerConfig) {
		cfg.vpnGateRuntimeStarter = starter
	}
}

func WithVPNGateRuntimeRunner(runner VPNGateRuntimeCommandRunner) Option {
	return func(cfg *routerConfig) {
		cfg.vpnGateRuntimeRunner = runner
	}
}

func WithVPNGateRuntimeHealthChecker(checker VPNGateRuntimeHealthChecker) Option {
	return func(cfg *routerConfig) {
		cfg.vpnGateRuntimeHealthChecker = checker
	}
}

func WithVPNGateRuntimeStopper(stopper VPNGateRuntimeStopper) Option {
	return func(cfg *routerConfig) {
		cfg.vpnGateRuntimeStopper = stopper
	}
}

// WithHealthScheduler sets the VPN Gate auto-health scheduler for status reporting.
func WithHealthScheduler(scheduler *scheduler.VPNGateHealthScheduler) Option {
	return func(cfg *routerConfig) {
		cfg.healthScheduler = scheduler
	}
}

// WithStatsClient sets the stats client for traffic statistics.
func WithStatsClient(client xray.StatsClient) Option {
	return func(cfg *routerConfig) {
		cfg.statsClient = client
	}
}

func NewRouter(options ...Option) http.Handler {
	cfg := routerConfig{
		xrayController: defaultXrayController{},
	}
	for _, option := range options {
		option(&cfg)
	}
	if cfg.vpnGateRuntimeStarter == nil && cfg.vpnGateRuntimeRunner != nil {
		cfg.vpnGateRuntimeStarter = NewVPNGateRuntimeStarter(cfg.vpnGateRuntimeRunner)
	}
	if cfg.vpnGateRuntimeStopper == nil && cfg.vpnGateRuntimeRunner != nil {
		cfg.vpnGateRuntimeStopper = NewVPNGateRuntimeStopper(cfg.vpnGateRuntimeRunner)
	}
	if cfg.vpnGateRuntimeHealthChecker == nil && cfg.vpnGateRuntimeRunner != nil {
		cfg.vpnGateRuntimeHealthChecker = execVPNGateRuntimeHealthChecker{}
	}
	if cfg.vpnGateRuntimeStarter == nil && cfg.vpnGateRuntimeProbe == nil {
		cfg.vpnGateRuntimeStarter = NewVPNGateRuntimeStarter(execVPNGateRuntimeCommandRunner{})
		cfg.vpnGateRuntimeStopper = NewVPNGateRuntimeStopper(execVPNGateRuntimeCommandRunner{})
		cfg.vpnGateRuntimeHealthChecker = execVPNGateRuntimeHealthChecker{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", panelHandler)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(static.FS))))
	mux.HandleFunc("/login", loginHandler(&cfg))
	mux.HandleFunc("/api/login", loginHandler(&cfg))
	mux.HandleFunc("/api/logout", logoutHandler(&cfg))
	mux.HandleFunc("/api/session", sessionHandler(&cfg))
	mux.HandleFunc("/api/sessions", sessionsListHandler(&cfg))
	mux.HandleFunc("/api/sessions/", sessionRevokeHandler(&cfg))
	mux.HandleFunc("/api/health", healthHandler)
	mux.HandleFunc("/api/inbounds", inboundsHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/inbounds/", inboundChildrenHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/outbounds", outboundsHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/outbounds/", outboundChildrenHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/routing-rules", routingRulesHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/routing-rules/", routingRuleChildrenHandler(cfg.store, cfg.xrayController))
	mux.HandleFunc("/api/stats", statsHandler(cfg.store, cfg.statsClient))
	mux.HandleFunc("/api/xray/config", xrayConfigHandler(cfg.store))
	mux.HandleFunc("/api/xray/status", xrayStatusHandler(cfg.xrayController))
	mux.HandleFunc("/api/xray/apply", xrayApplyHandler(cfg.xrayController, cfg.store))
	mux.HandleFunc("/api/xray/install", coreInstallHandler("xray"))
	mux.HandleFunc("/api/xray/uninstall", coreUninstallHandler("xray"))
	mux.HandleFunc("/api/xray/logs", xrayLogsHandler())
	mux.HandleFunc("/api/xray/version", xrayVersionHandler(cfg.xrayController))
	mux.HandleFunc("/api/cert/status", certStatusHandler(&cfg))
	mux.HandleFunc("/api/cert/issue", certIssueHandler(&cfg))
	mux.HandleFunc("/api/settings", settingsHandler(&cfg))
	mux.HandleFunc("/api/restart", restartHandler())
	mux.HandleFunc("/api/service/status", serviceStatusHandler())
	mux.HandleFunc("/api/version", versionHandler(cfg.version))
	mux.HandleFunc("/api/vpngate/servers", vpngateServersHandler(&cfg))
	mux.HandleFunc("/api/vpngate/import", vpngateImportHandler(&cfg))
	mux.HandleFunc("/api/vpngate/probe", vpngateProbeHandler())
	mux.HandleFunc("/api/vpngate/egress", vpngateCreateEgressHandler(&cfg))
	mux.HandleFunc("/api/vpngate/egress/capabilities", vpngateEgressCapabilitiesHandler())
	mux.HandleFunc("/api/vpngate/egress/plan", vpngateEgressPlanHandler(&cfg))
	mux.HandleFunc("/api/vpngate/egress/status", vpngateEgressRuntimeStatusHandler(&cfg))
	mux.HandleFunc("/api/vpngate/egress/doctor", vpngateEgressRuntimeDoctorHandler(&cfg))
	mux.HandleFunc("/api/vpngate/egress/start", vpngateEgressRuntimeStartHandler(&cfg))
	mux.HandleFunc("/api/vpngate/egress/stop", vpngateEgressRuntimeStopHandler(&cfg))
	mux.HandleFunc("/api/vpngate/outbounds/health", vpngateOutboundHealthHandler(cfg.store))
	mux.HandleFunc("/api/vpngate/auto-health/status", vpngateAutoHealthStatusHandler(&cfg))
	mux.HandleFunc("/api/singbox/status", singboxStatusHandler())
	mux.HandleFunc("/api/singbox/apply", singboxApplyHandler(cfg.store))
	mux.HandleFunc("/api/singbox/install", coreInstallHandler("singbox"))
	mux.HandleFunc("/api/singbox/uninstall", coreUninstallHandler("singbox"))
	mux.HandleFunc("/api/singbox/config", singboxConfigHandler())
	mux.HandleFunc("/api/singbox/version", singboxVersionHandler())
	mux.HandleFunc("/api/singbox/logs", singboxLogsHandler())
	mux.HandleFunc("/sub/", subscriptionHandler(cfg.store))
	handler := authMiddleware(mux, &cfg)
	if cfg.basePath != "" {
		return basePathMiddleware(handler, cfg.basePath)
	}
	return handler
}

func normalizeBasePath(basePath string) string {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" || basePath == "/" {
		return ""
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	return strings.TrimRight(basePath, "/")
}

func basePathMiddleware(next http.Handler, basePath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != basePath && !strings.HasPrefix(r.URL.Path, basePath+"/") {
			http.NotFound(w, r)
			return
		}
		cloned := r.Clone(r.Context())
		cloned.URL.Path = strings.TrimPrefix(r.URL.Path, basePath)
		if cloned.URL.Path == "" {
			cloned.URL.Path = "/"
		}
		cloned.URL.RawPath = ""
		next.ServeHTTP(w, cloned)
	})
}

func panelHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(panelHTML))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok","mode":"single-binary"}`))
}

func outboundsHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			outbounds, err := store.ListOutbounds(r.Context())
			if err != nil {
				http.Error(w, `{"error":"list_outbounds_failed"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(outbounds)
		case http.MethodPost:
			var params db.CreateOutboundParams
			if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
				http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
				return
			}
			outbound, err := store.CreateOutbound(r.Context(), params)
			if err != nil {
				http.Error(w, `{"error":"create_outbound_failed"}`, http.StatusBadRequest)
				return
			}
			applyResult := ctrl.Apply(r.Context())
			_ = tryApplySingbox(r.Context(), store)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"outbound": outbound, "xray": applyResult})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func pingOutbound(address string, port int) map[string]interface{} {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		return map[string]interface{}{"latency": -1, "error": err.Error()}
	}
	start := time.Now()
	// Send a SOCKS5 handshake greeting to measure round-trip
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte{5, 1, 0})
	var buf [1]byte
	_, _ = conn.Read(buf[:])
	latency := time.Since(start).Milliseconds()
	_ = conn.Close()
	return map[string]interface{}{"latency": latency}
}

func outboundChildrenHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/outbounds/")
		// Handle /api/outbounds/reorder
		if path == "reorder" {
			// ...existing reorder handler...
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				IDs []int64 `json:"ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
				http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
				return
			}
			if err := store.ReorderOutbounds(r.Context(), req.IDs); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "reorder_failed")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"reordered"}`))
			return
		}
		// Handle /api/outbounds/speedtest-all
		if path == "speedtest-all" {
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			obs, err := store.ListOutbounds(r.Context())
			if err != nil {
				http.Error(w, `{"error":"load_failed"}`, http.StatusInternalServerError)
				return
			}
			results := make(map[int64]map[string]interface{})
			var mu sync.Mutex
			var wg sync.WaitGroup
			for _, ob := range obs {
				if ob.Protocol == "freedom" || ob.Protocol == "blackhole" || ob.Address == "" {
					continue
				}
				wg.Add(1)
				go func(o db.Outbound) {
					defer wg.Done()
					r := pingOutbound(o.Address, o.Port)
					mu.Lock()
					results[o.ID] = r
					mu.Unlock()
				}(ob)
			}
			wg.Wait()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(results)
			return
		}
		idStr := strings.TrimSuffix(path, "/")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error":"invalid_id"}`, http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var params db.UpdateOutboundParams
			if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
				http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
				return
			}
			outbound, err := store.UpdateOutbound(r.Context(), id, params)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
				} else {
					http.Error(w, `{"error":"update_failed"}`, http.StatusBadRequest)
				}
				return
			}
			applyResult := ctrl.Apply(r.Context())
			_ = tryApplySingbox(r.Context(), store)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"outbound": outbound, "xray": applyResult})
		case http.MethodDelete:
			err := store.DeleteOutbound(r.Context(), id)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
				} else {
					http.Error(w, `{"error":"delete_failed"}`, http.StatusInternalServerError)
				}
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func routingRulesHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			rules, err := store.ListRoutingRules(r.Context())
			if err != nil {
				http.Error(w, `{"error":"list_failed"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rules)
		case http.MethodPost:
			var params db.CreateRoutingRuleParams
			if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
				http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
				return
			}
			rule, err := store.CreateRoutingRule(r.Context(), params)
			if err != nil {
				http.Error(w, `{"error":"create_failed"}`, http.StatusBadRequest)
				return
			}
			applyResult := ctrl.Apply(r.Context())
			_ = tryApplySingbox(r.Context(), store)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"rule": rule, "xray": applyResult})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func routingRuleChildrenHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/routing-rules/")
		if path == "reorder" {
			if r.Method != http.MethodPost {
				http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
				return
			}
			var req struct {
				IDs []int64 `json:"ids"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
				http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
				return
			}
			if err := store.ReorderRoutingRules(r.Context(), req.IDs); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "reorder_failed")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"reordered"}`))
			return
		}
		idStr := strings.TrimSuffix(path, "/")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, `{"error":"invalid_id"}`, http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var params db.UpdateRoutingRuleParams
			if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
				http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
				return
			}
			rule, err := store.UpdateRoutingRule(r.Context(), id, params)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
				} else {
					http.Error(w, `{"error":"update_failed"}`, http.StatusBadRequest)
				}
				return
			}
			applyResult := ctrl.Apply(r.Context())
			_ = tryApplySingbox(r.Context(), store)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"rule": rule, "xray": applyResult})
		case http.MethodDelete:
			err := store.DeleteRoutingRule(r.Context(), id)
			if err != nil {
				if strings.Contains(err.Error(), "not found") {
					http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
				} else {
					http.Error(w, `{"error":"delete_failed"}`, http.StatusInternalServerError)
				}
				return
			}
			applyResult := ctrl.Apply(r.Context())
			_ = tryApplySingbox(r.Context(), store)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "deleted", "xray": applyResult})
		case http.MethodGet:
			if strings.HasSuffix(r.URL.Path, "/ping") {
				idStr := strings.TrimSuffix(path, "/ping")
				obID, err := strconv.ParseInt(strings.TrimSpace(idStr), 10, 64)
				if err != nil {
					http.Error(w, `{"error":"invalid_id"}`, http.StatusBadRequest)
					return
				}
				// Re-fetch the outbound to get address:port
				outbounds, err := store.ListOutbounds(r.Context())
				if err != nil {
					http.Error(w, `{"error":"list_failed"}`, http.StatusInternalServerError)
					return
				}
				var target *db.Outbound
				for i := range outbounds {
					if outbounds[i].ID == obID {
						target = &outbounds[i]
						break
					}
				}
				if target == nil || !target.Enabled || target.Protocol == "freedom" || target.Protocol == "blackhole" {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"latency": -1, "error": "not_pingable"})
					return
				}
				result := pingOutbound(target.Address, target.Port)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(result)
				return
			}
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func statsHandler(store Store, statsClient xray.StatsClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		inb, _ := store.ListInbounds(ctx)
		obs, _ := store.ListOutbounds(ctx)
		rules, _ := store.ListRoutingRules(ctx)
		var clientCount int
		for _, in := range inb {
			clientCount += len(in.Clients)
		}
		totalObs := len(obs)
		enabledObs := 0
		for _, ob := range obs {
			if ob.Enabled {
				enabledObs++
			}
		}
		totalRules := len(rules)
		enabledRules := 0
		for _, r := range rules {
			if r.Enabled {
				enabledRules++
			}
		}

		// Get per-client traffic stats if statsClient is available
		clientStats := make(map[string]*xray.ClientStats)
		if statsClient != nil {
			stats, _ := statsClient.QueryAllStats(ctx)
			clientStats = stats
		}

		// Build client traffic list from DB + stats
		var clientList []map[string]interface{}
		for _, in := range inb {
			for _, c := range in.Clients {
				info := map[string]interface{}{
					"id":            c.ID,
					"inbound_id":    c.InboundID,
					"email":         c.Email,
					"enabled":       c.Enabled,
					"up":            c.Up,
					"down":          c.Down,
					"traffic_limit": c.TrafficLimit,
					"expiry_at":     c.ExpiryAt,
				}
				// Override with live stats if available
				if liveStats, ok := clientStats[c.Email]; ok {
					info["up"] = liveStats.Uplink
					info["down"] = liveStats.Downlink
				}
				clientList = append(clientList, info)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"inbounds":              len(inb),
			"clients":               clientCount,
			"client_details":        clientList,
			"outbounds":             totalObs,
			"outbounds_enabled":     enabledObs,
			"routing_rules":         totalRules,
			"routing_rules_enabled": enabledRules,
		})
	}
}

func inboundsHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			listInbounds(w, r, store)
		case http.MethodPost:
			createInbound(w, r, store)
			applyXrayAsync(ctrl)
			applySingboxAsync(store)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func applyXrayAsync(ctrl XrayController) {
	go func() {
		result := ctrl.Apply(context.Background())
		if strings.HasPrefix(result.Status, "failed") {
			log.Printf("xray apply failed: status=%s service=%s commands=%v error=%s", result.Status, result.Service, result.CommandsExecuted, result.ErrorOutput)
		}
	}()
}

func applySingboxAsync(store Store) {
	go func() {
		if err := tryApplySingbox(context.Background(), store); err != nil {
			log.Printf("sing-box auto apply: %v", err)
		}
	}()
}

func writeJSONError(w http.ResponseWriter, status int, code string, fields ...map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	payload := map[string]interface{}{"error": code}
	for _, extra := range fields {
		for k, v := range extra {
			payload[k] = v
		}
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func deriveRealityPublicKeys(inbounds []db.Inbound) {
	for i := range inbounds {
		if inbounds[i].Security == "reality" && inbounds[i].RealityPublicKey == "" && inbounds[i].RealityPrivateKey != "" {
			if pubKey, err := xray.DeriveRealityPublicKey(inbounds[i].RealityPrivateKey); err == nil {
				inbounds[i].RealityPublicKey = pubKey
			}
		}
	}
}

func listInbounds(w http.ResponseWriter, r *http.Request, store Store) {
	inbounds := []db.Inbound{}
	if store != nil {
		loaded, err := store.ListInbounds(r.Context())
		if err != nil {
			http.Error(w, `{"error":"list_inbounds_failed"}`, http.StatusInternalServerError)
			return
		}
		deriveRealityPublicKeys(loaded)
		inbounds = loaded
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"inbounds": inbounds})
}

func createInbound(w http.ResponseWriter, r *http.Request, store Store) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var payload db.CreateInboundParams
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	// Auto-generate REALITY private key if missing
	if payload.Security == "reality" && payload.RealityPrivateKey == "" {
		if privKey, pubKey, err := xray.GenerateRealityKey(); err == nil {
			payload.RealityPrivateKey = privKey
			payload.RealityPublicKey = pubKey
		}
	}
	// Port conflict check
	if payload.Port > 0 {
		existing, _ := store.ListInbounds(r.Context())
		for _, ib := range existing {
			if ib.Port == payload.Port {
				writeJSONError(w, http.StatusConflict, "port_conflict", map[string]interface{}{
					"message": "端口 " + strconv.FormatInt(int64(ib.Port), 10) + " 已被入站 " + strconv.FormatInt(ib.ID, 10) + " 使用",
				})
				return
			}
		}
	}
	created, err := store.CreateInbound(r.Context(), payload)
	if err != nil {
		http.Error(w, `{"error":"unsupported_protocol"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func inboundChildrenHandler(store Store, ctrl XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/inbounds/")
		parts := strings.Split(strings.Trim(path, "/"), "/")

		switch r.Method {
		case http.MethodPost:
			if len(parts) == 4 && parts[1] == "clients" && parts[3] == "reset-traffic" {
				clientID, err := strconv.ParseInt(parts[2], 10, 64)
				if err != nil || clientID <= 0 {
					http.NotFound(w, r)
					return
				}
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				resetClientTraffic(w, r, store, inboundID, clientID)
				applyXrayAsync(ctrl)
				applySingboxAsync(store)
			} else if len(parts) != 2 || parts[1] != "clients" {
				http.NotFound(w, r)
				return
			} else {
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				createClient(w, r, store, inboundID)
				applyXrayAsync(ctrl)
				applySingboxAsync(store)
			}
		case http.MethodPatch:
			if len(parts) == 2 && parts[1] == "enabled" {
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				patchInboundEnabled(w, r, store, inboundID)
				applyXrayAsync(ctrl)
				applySingboxAsync(store)
			} else if len(parts) == 4 && parts[1] == "clients" && parts[3] == "enabled" {
				clientID, err := strconv.ParseInt(parts[2], 10, 64)
				if err != nil || clientID <= 0 {
					http.NotFound(w, r)
					return
				}
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				patchClientEnabled(w, r, store, inboundID, clientID)
				applyXrayAsync(ctrl)
				applySingboxAsync(store)
			} else {
				http.NotFound(w, r)
			}
		case http.MethodPut:
			if len(parts) == 1 {
				// PUT /api/inbounds/{id}
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				updateInbound(w, r, store, inboundID)
				applyXrayAsync(ctrl)
				applySingboxAsync(store)
			} else if len(parts) == 3 && parts[1] == "clients" {
				// PUT /api/inbounds/{id}/clients/{clientId}
				clientID, err := strconv.ParseInt(parts[2], 10, 64)
				if err != nil || clientID <= 0 {
					http.NotFound(w, r)
					return
				}
				updateClient(w, r, store, clientID)
				applyXrayAsync(ctrl)
				applySingboxAsync(store)
			} else {
				http.NotFound(w, r)
			}
		case http.MethodDelete:
			if len(parts) == 1 {
				// DELETE /api/inbounds/{id}
				inboundID, err := strconv.ParseInt(parts[0], 10, 64)
				if err != nil || inboundID <= 0 {
					http.NotFound(w, r)
					return
				}
				if store == nil {
					http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
					return
				}
				if err := store.DeleteInbound(r.Context(), inboundID); err != nil {
					http.Error(w, `{"error":"inbound_not_found"}`, http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
				applyXrayAsync(ctrl)
				applySingboxAsync(store)
			} else if len(parts) == 3 && parts[1] == "clients" {
				// DELETE /api/inbounds/{id}/clients/{clientId}
				clientID, err := strconv.ParseInt(parts[2], 10, 64)
				if err != nil || clientID <= 0 {
					http.NotFound(w, r)
					return
				}
				if store == nil {
					http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
					return
				}
				if err := store.DeleteClient(r.Context(), clientID); err != nil {
					http.Error(w, `{"error":"client_not_found"}`, http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
				applyXrayAsync(ctrl)
				applySingboxAsync(store)
			} else {
				http.NotFound(w, r)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func createClient(w http.ResponseWriter, r *http.Request, store Store, inboundID int64) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	if !inboundExists(r.Context(), store, inboundID) {
		http.Error(w, `{"error":"inbound_not_found"}`, http.StatusNotFound)
		return
	}
	var payload struct {
		Email        string `json:"email"`
		TrafficLimit int64  `json:"traffic_limit"`
		ExpiryAt     int64  `json:"expiry_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	created, err := store.CreateClient(r.Context(), db.CreateClientParams{InboundID: inboundID, Email: payload.Email, TrafficLimit: payload.TrafficLimit, ExpiryAt: payload.ExpiryAt})
	if err != nil {
		http.Error(w, `{"error":"create_client_failed"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func patchInboundEnabled(w http.ResponseWriter, r *http.Request, store Store, inboundID int64) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var payload struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	updated, err := store.SetInboundEnabled(r.Context(), inboundID, payload.Enabled)
	if err != nil {
		http.Error(w, `{"error":"inbound_not_found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

func patchClientEnabled(w http.ResponseWriter, r *http.Request, store Store, inboundID int64, clientID int64) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var payload struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	updated, err := store.SetClientEnabled(r.Context(), inboundID, clientID, payload.Enabled)
	if err != nil {
		http.Error(w, `{"error":"client_not_found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

func inboundExists(ctx context.Context, store Store, inboundID int64) bool {
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		return false
	}
	for _, inbound := range inbounds {
		if inbound.ID == inboundID {
			return true
		}
	}
	return false
}

func updateInbound(w http.ResponseWriter, r *http.Request, store Store, inboundID int64) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var payload db.UpdateInboundParams
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	// Auto-generate REALITY private key if switching to reality without one
	if payload.Security == "reality" && payload.RealityPrivateKey == "" {
		if key, _, err := xray.GenerateRealityKey(); err == nil {
			payload.RealityPrivateKey = key
		}
	}
	// Port conflict check (excluding current inbound)
	if payload.Port > 0 {
		existing, _ := store.ListInbounds(r.Context())
		for _, ib := range existing {
			if ib.ID != inboundID && ib.Port == payload.Port {
				writeJSONError(w, http.StatusConflict, "port_conflict", map[string]interface{}{
					"message": "端口 " + strconv.FormatInt(int64(ib.Port), 10) + " 已被入站 " + strconv.FormatInt(ib.ID, 10) + " 使用",
				})
				return
			}
		}
	}
	updated, err := store.UpdateInbound(r.Context(), inboundID, payload)
	if err != nil {
		http.Error(w, `{"error":"update_inbound_failed"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

func resetClientTraffic(w http.ResponseWriter, r *http.Request, store Store, inboundID, clientID int64) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	updated, err := store.ResetClientTraffic(r.Context(), clientID)
	if err != nil {
		http.Error(w, `{"error":"reset_traffic_failed"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

func updateClient(w http.ResponseWriter, r *http.Request, store Store, clientID int64) {
	if store == nil {
		http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var payload db.UpdateClientParams
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
		return
	}
	updated, err := store.UpdateClient(r.Context(), clientID, payload)
	if err != nil {
		http.Error(w, `{"error":"update_client_failed"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

func xrayConfigHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		inbounds := []db.Inbound{}
		outbounds := []db.Outbound{}
		rules := []db.RoutingRule{}
		if store != nil {
			if loaded, err := store.ListInbounds(r.Context()); err == nil {
				inbounds = loaded
			}
			if loaded, err := store.ListOutbounds(r.Context()); err == nil {
				outbounds = loaded
			}
			if loaded, err := store.ListRoutingRules(r.Context()); err == nil {
				rules = loaded
			}
		}
		config, err := xray.BuildConfigWithOutbounds(inbounds, outbounds, rules)
		if err != nil {
			http.Error(w, `{"error":"build_xray_config_failed"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(config)
	}
}

func xrayStatusHandler(controller XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if controller == nil {
			controller = defaultXrayController{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controller.Status(r.Context()))
	}
}

func xrayApplyHandler(controller XrayController, store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			Confirm            bool `json:"confirm"`
			AllowSystemChanges bool `json:"allow_system_changes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
			return
		}
		if !payload.Confirm || !payload.AllowSystemChanges {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "confirmation_required", "commands_executed": []string{}})
			return
		}
		if controller == nil {
			controller = defaultXrayController{}
		}

		// 1. Apply Xray config
		xrayResult := controller.Apply(r.Context())

		// 2. Apply sing-box config if sing-box supported inbounds exist
		singboxResult := map[string]interface{}{
			"applied": false,
			"reason":  "not_needed",
		}
		if store != nil && singbox.IsInstalled() {
			inbounds, err := store.ListInbounds(r.Context())
			if err == nil {
				hasSingboxInbound := false
				for _, ib := range inbounds {
					if ib.Enabled {
						switch ib.Protocol {
						case "hysteria2", "tuic", "wireguard", "shadowtls":
							hasSingboxInbound = true
							break
						}
					}
				}
				if hasSingboxInbound {
					cfg := singbox.BuildConfig(inbounds)
					if _, err := os.Stat(singbox.CertFile); os.IsNotExist(err) {
						_ = singbox.GenerateSelfSignedCert()
					}
					raw, mErr := json.MarshalIndent(cfg, "", "  ")
					if mErr == nil {
						_ = os.WriteFile(singbox.DefaultConfigPath, raw, 0644)
					}
					applyErr := singbox.Apply()
					if applyErr != nil {
						singboxResult = map[string]interface{}{
							"applied": false,
							"error":   applyErr.Error(),
						}
					} else {
						singboxResult = map[string]interface{}{
							"applied":  true,
							"inbounds": len(cfg.Inbounds),
						}
					}
				}
			}
		} else if store == nil {
			singboxResult["reason"] = "no_store"
		} else {
			singboxResult["reason"] = "singbox_not_installed"
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"xray":    xrayResult,
			"singbox": singboxResult,
		})
	}
}

type coreActionPayload struct {
	Confirm            bool `json:"confirm"`
	AllowSystemChanges bool `json:"allow_system_changes"`
}

func decodeCoreActionPayload(w http.ResponseWriter, r *http.Request) (coreActionPayload, bool) {
	var payload coreActionPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_json")
		return payload, false
	}
	if !payload.Confirm || !payload.AllowSystemChanges {
		writeJSONError(w, http.StatusForbidden, "confirmation_required", map[string]interface{}{"commands_executed": []string{}})
		return payload, false
	}
	return payload, true
}

func coreInstallHandler(core string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if _, ok := decodeCoreActionPayload(w, r); !ok {
			return
		}
		var script string
		var commands []string
		switch core {
		case "xray":
			commands = []string{"bash -c curl Xray-install", "mkdir -p /usr/local/etc/xray", "ln -sf /usr/local/migate/xray.json /usr/local/etc/xray/xray.json", "systemctl enable --now xray"}
			script = `set -euo pipefail
if ! command -v curl >/dev/null 2>&1; then echo 'curl is required' >&2; exit 1; fi
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)"
mkdir -p /usr/local/etc/xray
ln -sf /usr/local/migate/xray.json /usr/local/etc/xray/xray.json
ln -sf /usr/local/migate/xray.json /usr/local/etc/xray/config.json
systemctl enable xray
systemctl restart xray || true
xray --version | head -1`
		case "singbox":
			commands = []string{"download sing-box release", "install /usr/local/bin/sing-box", "write /etc/systemd/system/migate-singbox.service", "systemctl enable --now migate-singbox"}
			script = `set -euo pipefail
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) asset_arch=amd64 ;;
  aarch64|arm64) asset_arch=arm64 ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac
version="${SINGBOX_VERSION:-1.13.13}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${asset_arch}.tar.gz"
curl -fL "$url" -o "$tmp/sing-box.tar.gz"
tar -xzf "$tmp/sing-box.tar.gz" -C "$tmp"
cp "$tmp"/sing-box-*/sing-box /usr/local/bin/sing-box
chmod +x /usr/local/bin/sing-box
mkdir -p /etc/sing-box
if [ ! -f /etc/sing-box/config.json ]; then
  printf '%s\n' '{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}' > /etc/sing-box/config.json
fi
cat > /etc/systemd/system/migate-singbox.service <<'UNIT'
[Unit]
Description=MiGate managed sing-box service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable migate-singbox
systemctl restart migate-singbox || true
sing-box version | head -1`
		default:
			writeJSONError(w, http.StatusBadRequest, "unknown_core")
			return
		}
		out, err := runCoreScript(script)
		status := "installed"
		if err != nil {
			status = "failed"
			w.WriteHeader(http.StatusInternalServerError)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"core": core, "status": status, "output": string(out), "commands_executed": commands})
	}
}

func runCoreScript(script string) ([]byte, error) {
	cmd := exec.Command("bash", "-s")
	cmd.Stdin = strings.NewReader(script)
	return cmd.CombinedOutput()
}

func coreUninstallHandler(core string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if _, ok := decodeCoreActionPayload(w, r); !ok {
			return
		}
		var script string
		var commands []string
		switch core {
		case "xray":
			commands = []string{"systemctl disable --now xray", "bash Xray-install remove", "remove MiGate xray symlinks"}
			script = `set -euo pipefail
systemctl disable --now xray 2>/dev/null || true
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" -- remove --purge 2>&1 || true
rm -f /usr/local/etc/xray/xray.json /usr/local/etc/xray/config.json
printf 'Xray removed or disabled\n'`
		case "singbox":
			commands = []string{"systemctl disable --now migate-singbox", "remove sing-box binary and service"}
			script = `set -euo pipefail
systemctl disable --now migate-singbox 2>/dev/null || true
rm -f /etc/systemd/system/migate-singbox.service /usr/local/bin/sing-box
systemctl daemon-reload 2>/dev/null || true
printf 'sing-box removed\n'`
		default:
			writeJSONError(w, http.StatusBadRequest, "unknown_core")
			return
		}
		out, err := runCoreScript(script)
		status := "uninstalled"
		if err != nil {
			status = "failed"
			w.WriteHeader(http.StatusInternalServerError)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"core": core, "status": status, "output": string(out), "commands_executed": commands})
	}
}

func xrayLogsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		lines := r.URL.Query().Get("lines")
		if lines == "" {
			lines = "50"
		}
		if n, err := strconv.Atoi(lines); err != nil || n < 1 {
			lines = "50"
		} else if n > maxXrayLogLines {
			lines = strconv.Itoa(maxXrayLogLines)
		}
		out, err := exec.Command("journalctl", "-u", "xray", "-n", lines, "--no-pager", "-o", "short-iso").CombinedOutput()
		if err != nil {
			// Fallback: try reading from syslog
			out, err = exec.Command("tail", "-n", lines, "/var/log/syslog").CombinedOutput()
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"logs": "无法读取 Xray 日志：journalctl 和 syslog 均不可用。"})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"logs": string(out)})
	}
}

func xrayVersionHandler(controller XrayController) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ver := controller.Version(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"version": ver})
	}
}

func certStatusHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		domain := ""
		email := ""
		certPath := ""
		keyPath := ""
		issued := false

		if cfg.configDir != "" {
			configPath := cfg.configDir + "/panel.json"
			data, err := os.ReadFile(configPath)
			if err == nil {
				var raw map[string]interface{}
				if err := json.Unmarshal(data, &raw); err == nil {
					if d, ok := raw["cert_domain"].(string); ok {
						domain = d
					}
					if e, ok := raw["cert_email"].(string); ok {
						email = e
					}
				}
			}
			if domain != "" {
				certDir := cfg.configDir + "/certs/" + domain
				certPath = certDir + "/fullchain.pem"
				keyPath = certDir + "/privkey.pem"
				if _, err := os.Stat(certPath); err == nil {
					if _, err := os.Stat(keyPath); err == nil {
						issued = true
					}
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"domain":    domain,
			"email":     email,
			"issued":    issued,
			"cert_path": certPath,
			"key_path":  keyPath,
		})
	}
}

func installACMESh(email string) (string, error) {
	resp, err := http.Get("https://get.acme.sh")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download acme.sh installer failed: status %d", resp.StatusCode)
	}
	script, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", err
	}
	cmd := exec.Command("sh", "-s", "email="+email)
	cmd.Stdin = bytes.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func certIssueHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Domain string `json:"domain"`
			Email  string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_json"})
			return
		}
		if req.Domain == "" || req.Email == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "domain_and_email_required"})
			return
		}
		if !validDomain.MatchString(req.Domain) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_domain"})
			return
		}
		if !validEmail.MatchString(req.Email) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_email"})
			return
		}
		if cfg.configDir == "" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "cert_not_available"})
			return
		}

		// Issue cert via acme.sh
		certDir := cfg.configDir + "/certs/" + req.Domain
		if err := os.MkdirAll(certDir, 0755); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "mkdir_cert_dir_failed"})
			return
		}

		// Check if acme.sh is installed; if not, install it without interpolating
		// request data into a shell command string.
		if _, err := exec.LookPath("acme.sh"); err != nil {
			installOut, err := installACMESh(req.Email)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":  "install_acme_failed",
					"detail": installOut,
				})
				return
			}
		}

		// Run acme.sh --issue --standalone
		out, err := exec.Command("acme.sh",
			"--issue", "--standalone", "-d", req.Domain,
			"--keylength", "ec-256",
			"--fullchain-file", certDir+"/fullchain.pem",
			"--key-file", certDir+"/privkey.pem",
			"--cert-file", certDir+"/cert.pem",
			"--reloadcmd", "systemctl restart xray || true",
		).CombinedOutput()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":  "issue_cert_failed",
				"detail": string(out),
			})
			return
		}

		// Update panel.json with cert domain/email
		configPath := cfg.configDir + "/panel.json"
		existing, err := os.ReadFile(configPath)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "read_panel_config_failed"})
			return
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(existing, &raw); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "parse_panel_config_failed"})
			return
		}
		raw["cert_domain"] = req.Domain
		raw["cert_email"] = req.Email
		updated, err := json.MarshalIndent(raw, "", "  ")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "serialize_failed"})
			return
		}
		if err := os.WriteFile(configPath, updated, 0o600); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "write_panel_config_failed"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "issued",
			"domain":    req.Domain,
			"cert_path": certDir + "/fullchain.pem",
			"key_path":  certDir + "/privkey.pem",
		})
	}
}

func versionHandler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if version == "" {
			version = "dev"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"version": version})
	}
}

func settingsHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.configDir == "" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"settings_not_available"}`))
			return
		}
		configPath := cfg.configDir + "/panel.json"
		switch r.Method {
		case http.MethodGet:
			data, err := os.ReadFile(configPath)
			if err != nil {
				http.Error(w, `{"error":"read_config_failed"}`, http.StatusInternalServerError)
				return
			}
			// Mask password for GET
			var raw map[string]interface{}
			if err := json.Unmarshal(data, &raw); err != nil {
				http.Error(w, `{"error":"parse_config_failed"}`, http.StatusInternalServerError)
				return
			}
			if _, exists := raw["panel_password"]; exists {
				raw["has_password"] = true
				delete(raw, "panel_password")
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(raw)
		case http.MethodPut:
			var updated map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
				http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
				return
			}
			// Read existing to preserve password if not provided
			existing, err := os.ReadFile(configPath)
			if err == nil {
				var existingMap map[string]interface{}
				if err := json.Unmarshal(existing, &existingMap); err == nil {
					if pw, has := updated["panel_password"]; !has || pw == "" {
						if oldPW, ok := existingMap["panel_password"]; ok {
							updated["panel_password"] = oldPW
						}
					}
					// Preserve database_path if not in update
					if _, has := updated["database_path"]; !has {
						if oldDP, ok := existingMap["database_path"]; ok {
							updated["database_path"] = oldDP
						}
					}
				}
			}
			data, err := json.MarshalIndent(updated, "", "  ")
			if err != nil {
				http.Error(w, `{"error":"serialize_failed"}`, http.StatusInternalServerError)
				return
			}
			if err := os.WriteFile(configPath, data, 0o600); err != nil {
				http.Error(w, `{"error":"write_config_failed"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func restartHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"restarting"}`))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Fork a child that restarts after a brief delay so the response is sent first
		go func() {
			time.Sleep(500 * time.Millisecond)
			_ = exec.Command("systemctl", "restart", "migate").Run()
		}()
		go func() {
			time.Sleep(2 * time.Second)
			os.Exit(0)
		}()
	}
}

func serviceStatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		status, detail := "unknown", ""
		out, err := exec.Command("systemctl", "is-active", "migate").Output()
		if err == nil {
			status = strings.TrimSpace(string(out))
		}
		if status == "active" {
			out2, _ := exec.Command("systemctl", "show", "migate", "--property=ActiveEnterTimestamp", "--value").Output()
			if len(out2) > 0 {
				detail = "启动于 " + strings.TrimSpace(string(out2))
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service": "migate",
			"status":  status,
			"detail":  detail,
		})
	}
}

func subscriptionHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if store == nil {
			http.NotFound(w, r)
			return
		}
		token := strings.Trim(strings.TrimPrefix(r.URL.Path, "/sub/"), "/")
		if token == "" {
			http.NotFound(w, r)
			return
		}
		inbounds, err := store.ListInbounds(r.Context())
		if err != nil {
			http.Error(w, `{"error":"list_inbounds_failed"}`, http.StatusInternalServerError)
			return
		}
		deriveRealityPublicKeys(inbounds)
		for _, inbound := range inbounds {
			if !inbound.Enabled {
				continue
			}
			now := time.Now().Unix()
			for _, client := range inbound.Clients {
				if client.UUID != token {
					continue
				}
				if !client.Enabled {
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = w.Write([]byte("// Subscription disabled"))
					return
				}
				// Check expired or over-limit
				if client.ExpiryAt > 0 && client.ExpiryAt <= now {
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = w.Write([]byte("// Subscription expired"))
					return
				}
				if client.TrafficLimit > 0 && (client.Up+client.Down) >= client.TrafficLimit {
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					_, _ = w.Write([]byte("// Traffic limit exceeded"))
					return
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = w.Write([]byte(shareLink(r.Host, inbound, client)))
				return
			}
		}
		http.NotFound(w, r)
	}
}

func shareLink(host string, inbound db.Inbound, client db.Client) string {
	host = subscriptionHost(host)
	switch inbound.Protocol {
	case "vmess":
		return vmessShareLink(host, inbound, client)
	case "shadowsocks":
		return ssShareLink(host, inbound, client)
	case "hysteria2":
		// hy2://password@host:port/?params#name
		var params []string
		addParam := func(k, v string) {
			if v != "" {
				params = append(params, k+"="+url.QueryEscape(v))
			}
		}
		if inbound.Hy2UpMbps > 0 {
			params = append(params, "up_mbps="+strconv.Itoa(inbound.Hy2UpMbps))
		}
		if inbound.Hy2DownMbps > 0 {
			params = append(params, "down_mbps="+strconv.Itoa(inbound.Hy2DownMbps))
		}
		addParam("obfs", inbound.Hy2Obfs)
		addParam("obfs-password", inbound.Hy2ObfsPassword)
		// sing-box v1.13 requires TLS for Hysteria2 server inbounds.
		// MiGate uses generated self-signed certs by default, so share links must
		// include TLS + allowInsecure even when the UI stores security=none.
		params = append(params, "security=tls")
		addParam("sni", inbound.RealityServerNames)
		params = append(params, "allowInsecure=1")
		query := strings.Join(params, "&")
		suffix := ""
		if query != "" {
			suffix = "?" + query
		}
		return "hy2://" + client.UUID + "@" + host + ":" + strconv.Itoa(inbound.Port) + suffix + "#" + url.QueryEscape(client.Email)
	default:
		// vless, trojan, etc. use universal link format
		var params []string
		addParam := func(k, v string) {
			if v != "" {
				params = append(params, k+"="+url.QueryEscape(v))
			}
		}
		addParam("type", inbound.Network)
		addParam("security", inbound.Security)
		if inbound.Security == "reality" {
			if inbound.Network != "xhttp" {
				params = append(params, "flow=xtls-rprx-vision")
			}
			addParam("sni", inbound.RealityServerNames)
			params = append(params, "fp=chrome")
			addParam("pbk", inbound.RealityPublicKey)
			addParam("sid", inbound.RealityShortID)
		} else if inbound.Security == "tls" {
			addParam("sni", inbound.RealityServerNames)
			params = append(params, "allowInsecure=1")
		}
		// Transport-specific params
		switch inbound.Network {
		case "ws":
			addParam("path", inbound.WsPath)
			addParam("host", inbound.WsHost)
		case "h2":
			addParam("path", inbound.WsPath)
			addParam("host", inbound.WsHost)
		case "grpc":
			addParam("serviceName", inbound.GrpcServiceName)
		case "xhttp":
			addParam("path", inbound.XHTTPPath)
			addParam("mode", inbound.XHTTPMode)
		case "kcp":
		case "quic":
		}
		query := strings.Join(params, "&")
		return inbound.Protocol + "://" + client.UUID + "@" + host + ":" + strconv.Itoa(inbound.Port) + "?" + query + "#" + url.QueryEscape(client.Email)
	}
}

func vmessShareLink(host string, inbound db.Inbound, client db.Client) string {
	inboundPort := inbound.Port
	portStr := strconv.Itoa(inboundPort)
	tls := ""
	if inbound.Security == "tls" || inbound.Security == "reality" {
		tls = "tls"
	}

	// Transport-specific host and path
	vHost, vPath := "", ""
	sni := ""
	switch inbound.Network {
	case "ws":
		vHost = inbound.WsHost
		vPath = inbound.WsPath
	case "grpc":
		vPath = inbound.GrpcServiceName
	case "xhttp":
		vPath = inbound.XHTTPPath
	case "h2":
		vHost = inbound.WsHost
		vPath = inbound.WsPath
	}
	if inbound.Security == "tls" || inbound.Security == "reality" {
		sni = inbound.RealityServerNames
	}
	vmessData := map[string]interface{}{
		"v":    "2",
		"ps":   client.Email,
		"add":  host,
		"port": portStr,
		"id":   client.UUID,
		"aid":  "0",
		"scy":  "auto",
		"net":  inbound.Network,
		"type": "none",
		"host": vHost,
		"path": vPath,
		"tls":  tls,
		"sni":  sni,
	}
	b, _ := json.Marshal(vmessData)
	encoded := base64.StdEncoding.EncodeToString(b)
	return "vmess://" + encoded
}

func ssShareLink(host string, inbound db.Inbound, client db.Client) string {
	method := inbound.SSMethod
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}
	userPass := method + ":" + inbound.UUID
	encoded := base64.StdEncoding.EncodeToString([]byte(userPass))
	return "ss://" + encoded + "@" + host + ":" + strconv.Itoa(inbound.Port) + "#" + client.Email
}

func subscriptionHost(host string) string {
	if host == "" {
		return "SERVER_IP"
	}
	name, _, err := net.SplitHostPort(host)
	if err == nil && name != "" {
		return name
	}
	return strings.Trim(host, "[]")
}

type vpngateFetcherImpl struct{}

func (vpngateFetcherImpl) FetchServers() ([]VPNGateServer, error) {
	f := &vpngate.Fetcher{}
	servers, err := f.FetchServers()
	if err != nil {
		return nil, err
	}
	result := make([]VPNGateServer, len(servers))
	for i, s := range servers {
		result[i] = VPNGateServer{
			HostName:     s.HostName,
			IP:           s.IP,
			Score:        s.Score,
			Ping:         s.Ping,
			Speed:        s.Speed,
			CountryLong:  s.CountryLong,
			CountryShort: s.CountryShort,
			NumSessions:  s.NumSessions,
			Uptime:       s.Uptime,
			TotalUsers:   s.TotalUsers,
			TotalTraffic: s.TotalTraffic,
			LogType:      s.LogType,
			Operator:     s.Operator,
			Message:      s.Message,
			ServerType:   classifyVPNGateType(s.Operator),
		}
	}
	return result, nil
}

func vpngateServersHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		fetcher := cfg.vpnGateFetcher
		if fetcher == nil {
			fetcher = vpngateFetcherImpl{}
		}
		servers, err := fetcher.FetchServers()
		if err != nil {
			log.Printf("VPN Gate fetch failed: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "fetch_failed", map[string]interface{}{"detail": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(servers)
	}
}

type importServerRequest struct {
	Servers           []importServerItem `json:"servers"`
	ProbeBeforeImport bool               `json:"probe_before_import"`
}

type vpngateImportResponse struct {
	Outbounds          []db.Outbound `json:"outbounds"`
	Created            int           `json:"created"`
	SkippedDuplicate   int           `json:"skipped_duplicate"`
	SkippedUnreachable int           `json:"skipped_unreachable"`
}

type importServerItem struct {
	HostName    string `json:"hostname"`
	IP          string `json:"ip"`
	CountryLong string `json:"country_long"`
	Ping        int    `json:"ping"`
	Port        int    `json:"port"`
}

type vpngateProbeRequest struct {
	Servers []importServerItem `json:"servers"`
}

type vpngateProbeResult struct {
	HostName  string `json:"hostname"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

func probeSOCKS5Address(address string, port int, timeout time.Duration) (bool, int64, string) {
	if port == 0 {
		port = 1080
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, strconv.Itoa(port)), timeout)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return false, latency, err.Error()
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false, time.Since(start).Milliseconds(), err.Error()
	}
	buf := []byte{0x00, 0x00}
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false, time.Since(start).Milliseconds(), err.Error()
	}
	latency = time.Since(start).Milliseconds()
	if buf[0] != 0x05 {
		return false, latency, fmt.Sprintf("not socks5 response: 0x%02x", buf[0])
	}
	if buf[1] == 0xff {
		return false, latency, "socks5 no acceptable auth method"
	}
	return true, latency, ""
}

func probeTCPAddress(address string, port int, timeout time.Duration) (bool, int64, string) {
	return probeSOCKS5Address(address, port, timeout)
}

type importProbeOutcome struct {
	key string
	ok  bool
}

func probeImportServers(ctx context.Context, servers []importServerItem, timeout time.Duration) map[string]bool {
	const maxConcurrent = 8
	seen := make(map[string]importServerItem, len(servers))
	for _, s := range servers {
		if s.IP == "" {
			continue
		}
		port := s.Port
		if port == 0 {
			port = 1080
		}
		key := s.IP + ":" + strconv.Itoa(port)
		if _, exists := seen[key]; !exists {
			s.Port = port
			seen[key] = s
		}
	}

	out := make(chan importProbeOutcome, len(seen))
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for key, server := range seen {
		wg.Add(1)
		go func(key string, server importServerItem) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out <- importProbeOutcome{key: key, ok: false}
				return
			}
			ok, _, _ := probeSOCKS5Address(server.IP, server.Port, timeout)
			out <- importProbeOutcome{key: key, ok: ok}
		}(key, server)
	}
	go func() {
		wg.Wait()
		close(out)
	}()

	result := make(map[string]bool, len(seen))
	for item := range out {
		result[item.key] = item.ok
	}
	return result
}

func vpngateProbeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var req vpngateProbeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
			return
		}
		if len(req.Servers) == 0 {
			http.Error(w, `{"error":"no_servers"}`, http.StatusBadRequest)
			return
		}
		if len(req.Servers) > 20 {
			req.Servers = req.Servers[:20]
		}
		results := make([]vpngateProbeResult, 0, len(req.Servers))
		for _, s := range req.Servers {
			port := s.Port
			if port == 0 {
				port = 1080
			}
			res := vpngateProbeResult{HostName: s.HostName, IP: s.IP, Port: port, Protocol: "socks5"}
			res.OK, res.LatencyMS, res.Error = probeTCPAddress(s.IP, port, 1200*time.Millisecond)
			results = append(results, res)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(results)
	}
}

type vpngateOutboundHealthResult struct {
	ID        int64  `json:"id"`
	Tag       string `json:"tag"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Enabled   bool   `json:"enabled"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

type vpngateOutboundHealthResponse struct {
	Results []vpngateOutboundHealthResult `json:"results"`
	Summary struct {
		Total int `json:"total"`
		OK    int `json:"ok"`
		Fail  int `json:"fail"`
	} `json:"summary"`
}

func vpngateOutboundHealthHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if store == nil {
			http.Error(w, `{"error":"store_unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		outbounds, err := store.ListOutbounds(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "list_outbounds_failed")
			return
		}
		var resp vpngateOutboundHealthResponse
		for _, ob := range outbounds {
			if !ob.Enabled || ob.Protocol != "socks" || !strings.HasPrefix(ob.Tag, "vpngate-") || ob.Address == "" {
				continue
			}
			res := vpngateOutboundHealthResult{ID: ob.ID, Tag: ob.Tag, Address: ob.Address, Port: ob.Port, Enabled: ob.Enabled}
			res.OK, res.LatencyMS, res.Error = probeTCPAddress(ob.Address, ob.Port, 1200*time.Millisecond)
			resp.Results = append(resp.Results, res)
			resp.Summary.Total++
			if res.OK {
				resp.Summary.OK++
			} else {
				resp.Summary.Fail++
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func vpngateAutoHealthStatusHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if cfg == nil || cfg.healthScheduler == nil {
			_, _ = w.Write([]byte(`{"status":"not_started","results":[],"disabled_total":0}`))
			return
		}
		results, disabled := cfg.healthScheduler.LastResult()
		type resultJSON struct {
			OutboundID int64  `json:"outbound_id"`
			Tag        string `json:"tag"`
			Address    string `json:"address"`
			Port       int    `json:"port"`
			OK         bool   `json:"ok"`
			LatencyMS  int64  `json:"latency_ms"`
			Error      string `json:"error,omitempty"`
			Disabled   bool   `json:"disabled"`
		}
		jres := make([]resultJSON, len(results))
		for i, r := range results {
			jres[i] = resultJSON{
				OutboundID: r.OutboundID,
				Tag:        r.Tag,
				Address:    r.Address,
				Port:       r.Port,
				OK:         r.OK,
				LatencyMS:  r.LatencyMS,
				Error:      r.Error,
				Disabled:   r.Disabled,
			}
		}
		out := struct {
			Status        string       `json:"status"`
			Results       []resultJSON `json:"results"`
			DisabledTotal int          `json:"disabled_total"`
		}{
			Status:        "running",
			Results:       jres,
			DisabledTotal: disabled,
		}
		b, _ := json.Marshal(out)
		_, _ = w.Write(b)
	}
}

func vpngateImportHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		writeJSONError(w, http.StatusGone, "unsupported_vpngate_import", map[string]interface{}{
			"detail": "VPN Gate 官方列表不是 SOCKS5 代理源；当前仅作为参考列表/候选信息展示，暂不支持导入为 SOCKS5 出站。",
		})
	}
}

type vpngateCreateEgressRequest struct {
	Server        VPNGateServer `json:"server"`
	BridgeAddress string        `json:"bridge_address"`
	BridgePort    int           `json:"bridge_port"`
}

type vpngateCreateEgressResponse struct {
	Status   string      `json:"status"`
	Runtime  string      `json:"runtime"`
	Outbound db.Outbound `json:"outbound"`
	Bridge   struct {
		Protocol string `json:"protocol"`
		Address  string `json:"address"`
		Port     int    `json:"port"`
	} `json:"bridge"`
	Server VPNGateServer `json:"server"`
	Notes  []string      `json:"notes"`
}

func vpngateCreateEgressHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if cfg.store == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "store_unavailable")
			return
		}
		var req vpngateCreateEgressRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_payload", map[string]interface{}{"detail": err.Error()})
			return
		}
		address := strings.TrimSpace(req.BridgeAddress)
		if address == "" {
			address = "127.0.0.1"
		}
		if address != "127.0.0.1" && address != "::1" && !strings.HasPrefix(address, "127.") {
			writeJSONError(w, http.StatusBadRequest, "invalid_bridge_address", map[string]interface{}{"detail": "bridge_address must be a loopback address for this placeholder slice"})
			return
		}
		port := req.BridgePort
		if port == 0 {
			port = 21080
		}
		if port <= 0 || port > 65535 {
			writeJSONError(w, http.StatusBadRequest, "invalid_bridge_port", map[string]interface{}{"detail": "bridge_port must be between 1 and 65535"})
			return
		}
		serverID := firstNonEmpty(req.Server.HostName, req.Server.IP, "server")
		tag := uniqueVPNGateEgressTag(r.Context(), cfg.store, serverID, port)
		remark := "VPN Gate SoftEther placeholder - " + serverID
		if req.Server.CountryLong != "" {
			remark += " (" + strings.TrimSpace(req.Server.CountryLong) + ")"
		}
		outbound, err := cfg.store.CreateOutbound(r.Context(), db.CreateOutboundParams{
			Tag:                   tag,
			Remark:                remark,
			Protocol:              "vpngate_softether",
			Address:               address,
			Port:                  port,
			VPNGateServerHostName: strings.TrimSpace(req.Server.HostName),
			VPNGateServerIP:       strings.TrimSpace(req.Server.IP),
		})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "create_outbound_failed", map[string]interface{}{"detail": err.Error()})
			return
		}
		resp := vpngateCreateEgressResponse{
			Status:   "pending_runtime",
			Runtime:  "bridge_not_started",
			Outbound: outbound,
			Server:   req.Server,
			Notes: []string{
				"仅创建受管 vpngate_softether 出口配置，暂未启动 VPN runtime。",
				"后续 SoftEther/netns/SOCKS bridge runtime 实现后，会由本地 bridge 地址提供流量出口；本次请求不访问外网、不启动进程。",
			},
		}
		resp.Bridge.Protocol = "socks5"
		resp.Bridge.Address = address
		resp.Bridge.Port = port
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func uniqueVPNGateEgressTag(ctx context.Context, store Store, serverID string, port int) string {
	base := "vpngate-" + slugForTag(serverID)
	if base == "vpngate-" {
		base = "vpngate-softether"
	}
	base = trimTag(base, 48)
	existing := map[string]bool{}
	if outbounds, err := store.ListOutbounds(ctx); err == nil {
		for _, ob := range outbounds {
			existing[ob.Tag] = true
		}
	}
	candidate := base
	if !existing[candidate] {
		return candidate
	}
	candidate = trimTag(fmt.Sprintf("%s-%d", base, port), 58)
	if !existing[candidate] {
		return candidate
	}
	for i := 2; ; i++ {
		candidate = trimTag(fmt.Sprintf("%s-%d-%d", base, port, i), 64)
		if !existing[candidate] {
			return candidate
		}
	}
}

func slugForTag(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		isAllowed := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if isAllowed {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func trimTag(tag string, maxLen int) string {
	if len(tag) <= maxLen {
		return strings.Trim(tag, "-")
	}
	return strings.Trim(tag[:maxLen], "-")
}

type vpngateFallbackProtocol struct {
	Protocol string `json:"protocol"`
	Status   string `json:"status"`
	Notes    string `json:"notes,omitempty"`
}

type vpngateEgressCapabilities struct {
	Status              string                    `json:"status"`
	Driver              string                    `json:"driver"`
	Isolation           string                    `json:"isolation"`
	Bridge              string                    `json:"bridge"`
	PerformsSideEffects bool                      `json:"performs_side_effects"`
	MaxActiveDefault    int                       `json:"max_active_default"`
	SupportedProtocols  []string                  `json:"supported_protocols"`
	FallbackProtocols   []vpngateFallbackProtocol `json:"fallback_protocols"`
	Message             string                    `json:"message"`
	Notes               []string                  `json:"notes"`
}

func vpngateEgressCapabilitiesHandler() http.HandlerFunc {
	capabilities := vpngateEgressCapabilities{
		Status:              "planned",
		Driver:              "softether",
		Isolation:           "network_namespace",
		Bridge:              "socks5",
		PerformsSideEffects: false,
		MaxActiveDefault:    1,
		SupportedProtocols:  []string{"softether"},
		FallbackProtocols: []vpngateFallbackProtocol{
			{Protocol: "openvpn", Status: "planned", Notes: "future fallback only; not implemented in this read-only preview"},
		},
		Message: "VPN Gate 未来会通过 SoftEther + network namespace + SOCKS bridge 接入 Xray outbound，不会直接按 SOCKS5 导入官方列表。",
		Notes: []string{
			"只读能力/计划预览：不会写入数据库、不会启动进程、不会调用 systemctl、不会访问外网。",
			"真实接入计划为每个 VPN Gate 出口启动隔离网络命名空间中的 SoftEther 会话，再通过本地 SOCKS5 桥接给 Xray outbound 使用。",
		},
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(capabilities)
	}
}

type vpngateRuntimeStep struct {
	Name           string `json:"name"`
	Status         string `json:"status"`
	CommandPreview string `json:"command_preview,omitempty"`
	Notes          string `json:"notes,omitempty"`
}

type VPNGateRuntimeStartPlan = vpngateRuntimePlan

type VPNGateRuntimeStartStep = vpngateRuntimeStep

type vpngateRuntimePlan struct {
	Status              string               `json:"status"`
	Runtime             string               `json:"runtime"`
	OutboundID          int64                `json:"outbound_id"`
	OutboundTag         string               `json:"outbound_tag"`
	BridgeAddress       string               `json:"bridge_address"`
	BridgePort          int                  `json:"bridge_port"`
	PerformsSideEffects bool                 `json:"performs_side_effects"`
	CommandsExecuted    []string             `json:"commands_executed,omitempty"`
	WillStartProcesses  bool                 `json:"will_start_processes"`
	WillCreateNetns     bool                 `json:"will_create_netns"`
	WillOpenSocksBridge bool                 `json:"will_open_socks_bridge"`
	Steps               []vpngateRuntimeStep `json:"steps"`
	Notes               []string             `json:"notes"`
}

type vpngateRuntimeStatus struct {
	Status              string   `json:"status"`
	Runtime             string   `json:"runtime"`
	OutboundID          int64    `json:"outbound_id"`
	OutboundTag         string   `json:"outbound_tag"`
	BridgeAddress       string   `json:"bridge_address"`
	BridgePort          int      `json:"bridge_port"`
	VPNConnected        bool     `json:"vpn_connected"`
	SocksBridgeRunning  bool     `json:"socks_bridge_running"`
	NonNativeEgressOK   bool     `json:"non_native_egress_ok"`
	ExitIP              string   `json:"exit_ip,omitempty"`
	NativeIP            string   `json:"native_ip,omitempty"`
	LatencyMS           int64    `json:"latency_ms,omitempty"`
	KillSwitchOK        bool     `json:"kill_switch_ok"`
	LastError           string   `json:"last_error"`
	PerformsSideEffects bool     `json:"performs_side_effects"`
	Notes               []string `json:"notes"`
}

type vpngateRuntimeDependencyCheck struct {
	Name    string `json:"name"`
	Command string `json:"command"`
	Status  string `json:"status"`
	Path    string `json:"path,omitempty"`
	Notes   string `json:"notes,omitempty"`
}

type vpngateRuntimeDoctor struct {
	Status              string                          `json:"status"`
	Runtime             string                          `json:"runtime"`
	OutboundID          int64                           `json:"outbound_id"`
	OutboundTag         string                          `json:"outbound_tag"`
	BridgeAddress       string                          `json:"bridge_address"`
	BridgePort          int                             `json:"bridge_port"`
	PerformsSideEffects bool                            `json:"performs_side_effects"`
	WillStartProcesses  bool                            `json:"will_start_processes"`
	WillCreateNetns     bool                            `json:"will_create_netns"`
	WillOpenSocksBridge bool                            `json:"will_open_socks_bridge"`
	Checks              []vpngateRuntimeDependencyCheck `json:"checks"`
	Notes               []string                        `json:"notes"`
}

type vpngateRuntimeStartRequest struct {
	Confirm            bool `json:"confirm"`
	AllowSystemChanges bool `json:"allow_system_changes"`
}

func BuildVPNGateRuntimeStartPlan(target VPNGateRuntimeStartTarget) VPNGateRuntimeStartPlan {
	netns := fmt.Sprintf("migate-vpngate-%d", target.OutboundID)
	paths := target.DependencyPaths
	cmd := func(name string) string {
		if path := strings.TrimSpace(paths[name]); path != "" {
			return path
		}
		return name
	}
	return vpngateRuntimePlan{
		Status:              "planned",
		Runtime:             target.Runtime,
		OutboundID:          target.OutboundID,
		OutboundTag:         target.OutboundTag,
		BridgeAddress:       target.BridgeAddress,
		BridgePort:          target.BridgePort,
		PerformsSideEffects: false,
		CommandsExecuted:    []string{},
		WillStartProcesses:  true,
		WillCreateNetns:     true,
		WillOpenSocksBridge: true,
		Steps: []vpngateRuntimeStep{
			{Name: "create_network_namespace", Status: "planned", CommandPreview: fmt.Sprintf("%s netns add %s", cmd("ip"), netns), Notes: "future gated runtime step"},
			{Name: "start_softether_client", Status: "planned", CommandPreview: fmt.Sprintf("%s start --netns %s", cmd("vpnclient"), netns), Notes: "future gated runtime step"},
			{Name: "wait_vpn_interface", Status: "planned", CommandPreview: fmt.Sprintf("%s netns exec %s %s link show", cmd("ip"), netns, cmd("ip")), Notes: "future gated runtime step"},
			{Name: "start_socks_bridge", Status: "planned", CommandPreview: fmt.Sprintf("%s -i %s -p %d", cmd("microsocks"), target.BridgeAddress, target.BridgePort), Notes: "future gated runtime step"},
			{Name: "smoke_test_non_native_egress", Status: "planned", CommandPreview: fmt.Sprintf("%s -t nat -S", cmd("iptables")), Notes: "future fail-closed verification"},
		},
		Notes: []string{
			"纯 runtime 启动计划：只生成命令预览，不执行命令、不启动进程、不创建 network namespace、不打开 SOCKS 监听。",
			"真实执行仍必须经过双确认、doctor ready 和注入 runner。",
		},
	}
}

func vpngateEgressPlanHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		outbound, ok := loadVPNGateSoftEtherOutbound(w, r, cfg)
		if !ok {
			return
		}
		plan := vpngateRuntimePlan{
			Status:              "planned",
			Runtime:             "softether_netns_socks_bridge",
			OutboundID:          outbound.ID,
			OutboundTag:         outbound.Tag,
			BridgeAddress:       outbound.Address,
			BridgePort:          outbound.Port,
			PerformsSideEffects: false,
			WillStartProcesses:  false,
			WillCreateNetns:     false,
			WillOpenSocksBridge: false,
			Steps: []vpngateRuntimeStep{
				{Name: "create_network_namespace", Status: "planned", Notes: "future gated runtime step"},
				{Name: "start_softether_client", Status: "planned", Notes: "future gated runtime step"},
				{Name: "wait_vpn_interface", Status: "planned", Notes: "future gated runtime step"},
				{Name: "start_socks_bridge", Status: "planned", Notes: "future gated runtime step"},
				{Name: "smoke_test_non_native_egress", Status: "planned", Notes: "future fail-closed verification"},
			},
			Notes: []string{
				"只读运行计划：不会写入文件、不会启动进程、不会创建网络命名空间、不会打开 SOCKS 监听。",
				"真实执行会在后续双确认门控接口中实现，并在 VPN 出口不可用时 fail-closed。",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(plan)
	}
}

func vpngateEgressRuntimeStatusHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		outbound, ok := loadVPNGateSoftEtherOutbound(w, r, cfg)
		if !ok {
			return
		}
		status := vpngateRuntimeStatus{
			Status:              "pending_runtime",
			Runtime:             "bridge_not_started",
			OutboundID:          outbound.ID,
			OutboundTag:         outbound.Tag,
			BridgeAddress:       outbound.Address,
			BridgePort:          outbound.Port,
			VPNConnected:        false,
			SocksBridgeRunning:  false,
			NonNativeEgressOK:   false,
			LastError:           "runtime_not_started",
			PerformsSideEffects: false,
			Notes: []string{
				"受管 vpngate_softether 出口已存在，但 SoftEther/netns/SOCKS bridge runtime 尚未启动。",
				"当前状态检查只读取数据库占位配置，不探测端口、不访问外网、不执行系统命令。",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	}
}

func vpngateEgressRuntimeDoctorHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		outbound, ok := loadVPNGateSoftEtherOutbound(w, r, cfg)
		if !ok {
			return
		}
		probe := cfg.vpnGateRuntimeProbe
		if probe == nil {
			probe = execVPNGateRuntimeProbe{}
		}
		doctor := buildVPNGateRuntimeDoctor(outbound, probe)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doctor)
	}
}

func vpngateEgressRuntimeStartHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		outbound, ok := loadVPNGateSoftEtherOutbound(w, r, cfg)
		if !ok {
			return
		}
		var req vpngateRuntimeStartRequest
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		if !req.Confirm || !req.AllowSystemChanges {
			writeJSONError(w, http.StatusForbidden, "confirmation_required", map[string]interface{}{
				"status":                "rejected",
				"runtime":               "softether_netns_socks_bridge",
				"outbound_id":           outbound.ID,
				"outbound_tag":          outbound.Tag,
				"performs_side_effects": false,
				"commands_executed":     []string{},
				"required_gates":        []string{"confirm", "allow_system_changes"},
			})
			return
		}

		probe := cfg.vpnGateRuntimeProbe
		if probe == nil {
			probe = execVPNGateRuntimeProbe{}
		}
		doctor := buildVPNGateRuntimeDoctor(outbound, probe)
		if doctor.Status != "ready" {
			writeJSONError(w, http.StatusFailedDependency, "runtime_preflight_failed", map[string]interface{}{
				"status":                doctor.Status,
				"runtime":               doctor.Runtime,
				"outbound_id":           doctor.OutboundID,
				"outbound_tag":          doctor.OutboundTag,
				"bridge_address":        doctor.BridgeAddress,
				"bridge_port":           doctor.BridgePort,
				"performs_side_effects": false,
				"commands_executed":     []string{},
				"checks":                doctor.Checks,
			})
			return
		}
		if cfg.vpnGateRuntimeStarter == nil {
			writeJSONError(w, http.StatusNotImplemented, "runtime_start_not_implemented", map[string]interface{}{
				"status":                doctor.Status,
				"runtime":               doctor.Runtime,
				"outbound_id":           doctor.OutboundID,
				"outbound_tag":          doctor.OutboundTag,
				"bridge_address":        doctor.BridgeAddress,
				"bridge_port":           doctor.BridgePort,
				"performs_side_effects": false,
				"commands_executed":     []string{},
				"checks":                doctor.Checks,
			})
			return
		}
		target := VPNGateRuntimeStartTarget{
			Runtime:         doctor.Runtime,
			OutboundID:      outbound.ID,
			OutboundTag:     outbound.Tag,
			BridgeAddress:   outbound.Address,
			BridgePort:      outbound.Port,
			ServerHostName:  outbound.VPNGateServerHostName,
			ServerIP:        outbound.VPNGateServerIP,
			DependencyPaths: vpngateRuntimeDependencyPaths(doctor.Checks),
		}
		result, err := cfg.vpnGateRuntimeStarter.Start(r.Context(), target)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "runtime_start_failed", map[string]interface{}{
				"status":                "failed",
				"runtime":               doctor.Runtime,
				"outbound_id":           outbound.ID,
				"outbound_tag":          outbound.Tag,
				"bridge_address":        outbound.Address,
				"bridge_port":           outbound.Port,
				"performs_side_effects": false,
				"commands_executed":     []string{},
				"detail":                err.Error(),
			})
			return
		}
		if cfg.vpnGateRuntimeHealthChecker != nil {
			health, healthErr := cfg.vpnGateRuntimeHealthChecker.Check(r.Context(), target)
			if healthErr != nil {
				_, _ = cfg.store.SetOutboundEnabled(r.Context(), outbound.ID, false)
				writeJSONError(w, http.StatusFailedDependency, "runtime_health_failed", map[string]interface{}{"status": "failed", "runtime": doctor.Runtime, "outbound_id": outbound.ID, "outbound_tag": outbound.Tag, "performs_side_effects": true, "commands_executed": result.CommandsExecuted, "detail": healthErr.Error()})
				return
			}
			result.VPNConnected = health.VPNConnected
			result.SocksBridgeRunning = health.SocksBridgeRunning
			result.NonNativeEgressOK = health.NonNativeEgressOK
			result.ExitIP = health.ExitIP
			result.NativeIP = health.NativeIP
			result.LatencyMS = health.LatencyMS
			result.KillSwitchOK = health.KillSwitchOK
			result.LastError = health.LastError
			if !health.VPNConnected || !health.SocksBridgeRunning || !health.NonNativeEgressOK || !health.KillSwitchOK {
				_, _ = cfg.store.SetOutboundEnabled(r.Context(), outbound.ID, false)
				writeJSONError(w, http.StatusFailedDependency, "runtime_health_failed_closed", map[string]interface{}{"status": "failed_closed", "runtime": doctor.Runtime, "outbound_id": outbound.ID, "outbound_tag": outbound.Tag, "vpn_connected": health.VPNConnected, "socks_bridge_running": health.SocksBridgeRunning, "non_native_egress_ok": health.NonNativeEgressOK, "exit_ip": health.ExitIP, "native_ip": health.NativeIP, "latency_ms": health.LatencyMS, "kill_switch_ok": health.KillSwitchOK, "last_error": health.LastError, "performs_side_effects": true, "commands_executed": result.CommandsExecuted})
				return
			}
			apply := cfg.xrayController.Apply(r.Context())
			result.XrayApplied = apply.Status == "applied"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}
}

func vpngateEgressRuntimeStopHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		outbound, ok := loadVPNGateSoftEtherOutbound(w, r, cfg)
		if !ok {
			return
		}
		var req vpngateRuntimeStartRequest
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		if !req.Confirm || !req.AllowSystemChanges {
			writeJSONError(w, http.StatusForbidden, "confirmation_required", map[string]interface{}{"status": "rejected", "runtime": "softether_netns_socks_bridge", "outbound_id": outbound.ID, "outbound_tag": outbound.Tag, "performs_side_effects": false, "commands_executed": []string{}, "required_gates": []string{"confirm", "allow_system_changes"}})
			return
		}
		probe := cfg.vpnGateRuntimeProbe
		if probe == nil {
			probe = execVPNGateRuntimeProbe{}
		}
		doctor := buildVPNGateRuntimeDoctor(outbound, probe)
		if doctor.Status != "ready" {
			writeJSONError(w, http.StatusFailedDependency, "runtime_preflight_failed", map[string]interface{}{"status": doctor.Status, "runtime": doctor.Runtime, "outbound_id": doctor.OutboundID, "outbound_tag": doctor.OutboundTag, "performs_side_effects": false, "commands_executed": []string{}, "checks": doctor.Checks})
			return
		}
		stopper := cfg.vpnGateRuntimeStopper
		if stopper == nil {
			writeJSONError(w, http.StatusNotImplemented, "runtime_stop_not_implemented", map[string]interface{}{"status": "not_implemented", "runtime": doctor.Runtime, "outbound_id": outbound.ID, "outbound_tag": outbound.Tag, "performs_side_effects": false, "commands_executed": []string{}})
			return
		}
		result, err := stopper.Stop(r.Context(), VPNGateRuntimeStartTarget{Runtime: doctor.Runtime, OutboundID: outbound.ID, OutboundTag: outbound.Tag, BridgeAddress: outbound.Address, BridgePort: outbound.Port, ServerHostName: outbound.VPNGateServerHostName, ServerIP: outbound.VPNGateServerIP, DependencyPaths: vpngateRuntimeDependencyPaths(doctor.Checks)})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "runtime_stop_failed", map[string]interface{}{"status": "failed", "runtime": doctor.Runtime, "outbound_id": outbound.ID, "outbound_tag": outbound.Tag, "performs_side_effects": false, "commands_executed": []string{}, "detail": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}
}

func buildVPNGateRuntimeDoctor(outbound db.Outbound, probe VPNGateRuntimeProbe) vpngateRuntimeDoctor {
	checks := []vpngateRuntimeDependencyCheck{
		vpngateRuntimeDependency(probe, "softether_vpncmd", "vpncmd", "SoftEther command automation binary"),
		vpngateRuntimeDependency(probe, "softether_vpnclient", "vpnclient", "SoftEther VPN client service binary"),
		vpngateRuntimeDependency(probe, "iproute2", "ip", "network namespace tooling"),
		vpngateRuntimeDependency(probe, "iptables", "iptables", "future fail-closed firewall tooling"),
		vpngateRuntimeDependency(probe, "socks_bridge", "microsocks", "lightweight local SOCKS bridge inside the namespace"),
	}
	status := "ready"
	for _, check := range checks {
		if check.Status != "available" {
			status = "missing_dependencies"
			break
		}
	}
	return vpngateRuntimeDoctor{
		Status:              status,
		Runtime:             "softether_netns_socks_bridge",
		OutboundID:          outbound.ID,
		OutboundTag:         outbound.Tag,
		BridgeAddress:       outbound.Address,
		BridgePort:          outbound.Port,
		PerformsSideEffects: false,
		WillStartProcesses:  false,
		WillCreateNetns:     false,
		WillOpenSocksBridge: false,
		Checks:              checks,
		Notes: []string{
			"只读 runtime 预检：只检查本机依赖是否存在，不启动 SoftEther、不创建 network namespace、不打开 SOCKS bridge。",
			"真实启动会在后续双确认门控接口中实现，并先通过该预检。",
		},
	}
}

func vpngateRuntimeDependency(probe VPNGateRuntimeProbe, name, command, notes string) vpngateRuntimeDependencyCheck {
	check := vpngateRuntimeDependencyCheck{Name: name, Command: command, Notes: notes}
	path, err := probe.LookPath(command)
	if err != nil || strings.TrimSpace(path) == "" {
		check.Status = "missing"
		return check
	}
	check.Status = "available"
	check.Path = path
	return check
}

func vpngateRuntimeDependencyPaths(checks []vpngateRuntimeDependencyCheck) map[string]string {
	paths := make(map[string]string, len(checks))
	for _, check := range checks {
		if check.Status == "available" && strings.TrimSpace(check.Command) != "" && strings.TrimSpace(check.Path) != "" {
			paths[check.Command] = check.Path
		}
	}
	return paths
}

func loadVPNGateSoftEtherOutbound(w http.ResponseWriter, r *http.Request, cfg *routerConfig) (db.Outbound, bool) {
	if cfg.store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "store_unavailable")
		return db.Outbound{}, false
	}
	id, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("outbound_id")), 10, 64)
	if err != nil || id <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_outbound_id", map[string]interface{}{"detail": "outbound_id query parameter is required"})
		return db.Outbound{}, false
	}
	outbounds, err := cfg.store.ListOutbounds(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list_outbounds_failed", map[string]interface{}{"detail": err.Error()})
		return db.Outbound{}, false
	}
	for _, outbound := range outbounds {
		if outbound.ID != id {
			continue
		}
		if outbound.Protocol != "vpngate_softether" {
			writeJSONError(w, http.StatusBadRequest, "not_vpngate_softether", map[string]interface{}{"detail": "outbound is not a vpngate_softether managed exit"})
			return db.Outbound{}, false
		}
		return outbound, true
	}
	writeJSONError(w, http.StatusNotFound, "outbound_not_found")
	return db.Outbound{}, false
}

// singboxStatusHandler returns the sing-box runtime status.
func singboxStatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		installed := singbox.IsInstalled()
		if !installed {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"installed": false,
				"status":    "not_installed",
			})
			return
		}
		status := singbox.Status()
		ver, _ := singbox.Version()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"installed":          true,
			"status":             status,
			"version":            strings.TrimSpace(ver),
			"memory_rss_bytes":   singbox.MemoryRSS(),
			"uptime":             singbox.Uptime(),
			"active_connections": singbox.ActiveConnections(),
		})
	}
}

// singboxApplyHandler reads sing-box supported inbounds from the store, builds
// a sing-box config, generates a self-signed cert if missing, writes
// the config to disk and restarts the sing-box service.
func singboxApplyHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		if !singbox.IsInstalled() {
			http.Error(w, `{"error":"singbox_not_installed"}`, http.StatusBadRequest)
			return
		}

		// Read sing-box inbounds
		inbounds, err := store.ListInbounds(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "list_failed", map[string]interface{}{"detail": err.Error()})
			return
		}

		// Build config
		cfg := singbox.BuildConfig(inbounds)

		// Ensure self-signed cert exists
		if _, err := os.Stat(singbox.CertFile); os.IsNotExist(err) {
			if err := singbox.GenerateSelfSignedCert(); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "cert_failed", map[string]interface{}{"detail": err.Error()})
				return
			}
		}

		// Encode and write config
		raw, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "marshal_failed", map[string]interface{}{"detail": err.Error()})
			return
		}
		if err := os.WriteFile(singbox.DefaultConfigPath, raw, 0644); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "write_failed", map[string]interface{}{"detail": err.Error()})
			return
		}

		// Restart sing-box
		applyErr := singbox.Apply()

		result := map[string]interface{}{
			"applied":     applyErr == nil,
			"config_path": singbox.DefaultConfigPath,
			"inbounds":    len(cfg.Inbounds),
		}
		if applyErr != nil {
			result["error"] = applyErr.Error()
			w.WriteHeader(http.StatusInternalServerError)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}
}

// tryApplySingbox reads sing-box supported inbounds from the store, builds
// a sing-box config, writes it to disk and restarts sing-box. Errors are
// silently returned (not panicked) to avoid blocking the caller.
func tryApplySingbox(ctx context.Context, store Store) error {
	if !singbox.IsInstalled() {
		return nil // sing-box not available, skip silently
	}
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		return fmt.Errorf("list inbounds: %w", err)
	}
	cfg := singbox.BuildConfig(inbounds)
	if _, err := os.Stat(singbox.CertFile); os.IsNotExist(err) {
		if err := singbox.GenerateSelfSignedCert(); err != nil {
			return fmt.Errorf("generate cert: %w", err)
		}
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(singbox.DefaultConfigPath, raw, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return singbox.Apply()
}

// singboxConfigHandler returns the current sing-box config JSON.
func singboxConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, err := os.ReadFile(singbox.DefaultConfigPath)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "read_failed", map[string]interface{}{"detail": err.Error()})
			return
		}
		// Parse and re-marshal so the client gets pretty-printed JSON
		var parsed interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			_, _ = w.Write(data)
			return
		}
		pretty, _ := json.MarshalIndent(parsed, "", "  ")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(pretty)
	}
}

// singboxVersionHandler returns the sing-box version.
func singboxVersionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if !singbox.IsInstalled() {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "not_installed"})
			return
		}
		ver, err := singbox.Version()
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": "unknown", "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": strings.TrimSpace(ver)})
	}
}

// singboxLogsHandler returns recent sing-box service logs from journalctl.
func singboxLogsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		lines := r.URL.Query().Get("lines")
		if lines == "" {
			lines = "50"
		}
		if n, err := strconv.Atoi(lines); err != nil || n < 1 {
			lines = "50"
		} else if n > maxXrayLogLines {
			lines = strconv.Itoa(maxXrayLogLines)
		}
		out, err := exec.Command("journalctl", "-u", singbox.ServiceName(), "-n", lines, "--no-pager", "-o", "short-iso").CombinedOutput()
		if err != nil {
			out, err = exec.Command("tail", "-n", lines, "/var/log/syslog").CombinedOutput()
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"logs": "无法读取 Sing-box 日志：journalctl 和 syslog 均不可用。"})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"logs": string(out)})
	}
}

const panelHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MiGate</title>
  <link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root, :root[data-theme="light"] {
      color-scheme: light;
      --bg: #ffffff;
      --fg: #171717;
      --surface: #ffffff;
      --surface-subtle: #fafafa;
      --surface-warning: #fffbeb;
      --muted: #666666;
      --line: rgba(0,0,0,.08);
      --line-strong: #ebebeb;
      --accent: #171717;
      --accent2: #16a34a;
      --danger: #dc2626;
      --amber: #f59e0b;
      --focus: hsla(212, 100%, 48%, 1);
      --shadow-sm: 0 0 0 1px rgba(0,0,0,.08);
      --shadow-md: 0 0 0 1px rgba(0,0,0,.08), 0 2px 2px rgba(0,0,0,.04), 0 8px 8px -8px rgba(0,0,0,.04);
      --radius-sm: 6px;
      --radius-md: 8px;
      --radius-lg: 12px;
      --radius-xl: 16px;
      --sidebar-width: 248px;
      --space-1: 4px;
      --space-2: 8px;
      --space-3: 12px;
      --space-4: 16px;
      --space-5: 20px;
      --space-6: 24px;
      --control-height: 40px;
      --control-radius: var(--radius-sm);
      --text-xs: 12px;
      --text-sm: 13px;
      --text-md: 14px;
      --text-lg: 16px;
      --panel-padding: var(--space-5);
      --row-padding: var(--space-4);
    }
    :root[data-theme="dark"] {
      color-scheme: dark;
      --bg: #0a0a0a;
      --fg: #ededed;
      --surface: #111111;
      --surface-subtle: #18181b;
      --surface-warning: #27251c;  /* dark amber-tinted surface */
      --muted: #a1a1aa;
      --line: rgba(255,255,255,.10);
      --line-strong: rgba(255,255,255,.14);
      --accent: #ededed;
      --accent2: #22c55e;
      --danger: #ef4444;
      --amber: #fbbf24;
      --focus: rgba(99,102,241,.36);
      --shadow-sm: 0 0 0 1px rgba(255,255,255,.10);
      --shadow-md: 0 0 0 1px rgba(255,255,255,.10), 0 12px 28px rgba(0,0,0,.35);
    }
    * { box-sizing: border-box; }
    html { background: var(--bg); }
    body { margin:0; min-height:100vh; font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; background:var(--bg); color:var(--fg); }
    code, pre, .mono { font-family:'Geist Mono',ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace; }
    a { color:inherit; }
    p { color:var(--muted); line-height:1.6; }
    .app-shell { display:grid; grid-template-columns: var(--sidebar-width) 1fr; min-height:100vh; }
    main { padding:var(--space-6); background:var(--bg); }
    main > section{display:none}
    #overview.overview-grid{display:grid}
    .overview-grid { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:var(--space-4); margin-bottom:var(--space-4); }
    .sidebar { position:sticky; top:0; height:100vh; overflow:auto; box-shadow:inset -1px 0 0 var(--line-strong); padding:var(--space-6) 18px; background:var(--surface); display:flex; flex-direction:column; }
    .brand { font-size:24px; font-weight:600; letter-spacing:-0.96px; margin-bottom:var(--space-1); color:var(--fg); }
    .subtitle { color:var(--muted); font-size:var(--text-sm); line-height:1.5; margin-bottom:var(--space-4); }
    nav { flex:1; overflow:visible; }
    #sidebar-toggle { display:none; align-items:center; justify-content:center; width:36px; height:36px; border:none; background:var(--surface); color:var(--fg); font-size:22px; cursor:pointer; border-radius:var(--radius-sm); box-shadow:var(--shadow-md); z-index:101; position:fixed; top:12px; left:12px; }
    .account-panel { display:grid; gap:var(--space-2); padding:var(--space-3); margin-top:auto; border-radius:var(--radius-md); background:transparent; box-shadow:inset 0 1px 0 var(--line); }
    .account-label { color:var(--muted); font-size:var(--text-xs); text-transform:uppercase; letter-spacing:.08em; }
    .account-name { color:var(--fg); font-size:var(--text-sm); font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .account-actions { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
    .account-actions button { min-height:32px; padding:0 10px; font-size:var(--text-xs); border-radius:var(--radius-md); background:var(--surface-subtle); color:var(--fg); box-shadow:none; }
    nav a { display:block; color:var(--fg); text-decoration:none; padding:10px var(--space-3); border-radius:var(--radius-md); margin:var(--space-1) 0; box-shadow:none; font-size:var(--text-md); font-weight:500; }
    nav a.active, nav a:hover { background:var(--surface-subtle); box-shadow:var(--shadow-sm); }
    .grid { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:var(--space-4); margin-bottom:var(--space-4); }
    .version-banner { margin-bottom:var(--space-3); padding:14px 18px; border-radius:var(--radius-md); background:var(--surface-subtle); box-shadow:var(--shadow-sm), inset 3px 0 0 var(--accent); font-size:var(--text-sm); line-height:1.5; color:var(--fg); }
    .notice-slot { margin-top:12px; }
    .client-subsection { margin:8px 0 var(--space-3) var(--space-5); padding:var(--space-3) 0 0 var(--space-4); border-left:1px solid var(--line); box-shadow:none; }

    .overview-insights { display:grid; grid-template-columns:1.2fr 1fr 1fr; gap:var(--space-4); grid-column:1 / -1; }
    .overview-card { display:grid; gap:var(--space-3); align-content:start; background:var(--surface); border-radius:var(--radius-lg); box-shadow:var(--shadow-md); padding:var(--panel-padding); min-height:156px; }
    .overview-card-title { color:var(--fg); font-size:var(--text-lg); font-weight:600; letter-spacing:-0.24px; }
    .overview-pill { display:inline-flex; align-items:center; width:max-content; min-height:26px; padding:0 10px; border-radius:9999px; background:var(--surface-subtle); color:var(--fg); box-shadow:var(--shadow-sm); font-size:var(--text-xs); font-weight:500; }
    .type-pill { display:inline-flex; align-items:center; padding:2px 8px; border-radius:8px; font-size:11px; font-weight:600; line-height:1.4; }
    .type-pill.type-home { background:color-mix(in srgb, #2e7d32 15%, transparent); color:var(--green, #2e7d32); }
    .type-pill.type-biz { background:color-mix(in srgb, #1565c0 15%, transparent); color:var(--blue, #1565c0); }
    .panel, .card { background:var(--surface); border-radius:var(--radius-lg); box-shadow:var(--shadow-md); padding:var(--panel-padding); }
    .metric { font-size:30px; font-weight:600; line-height:1.05; letter-spacing:-0.96px; margin-top:10px; color:var(--fg); }
    .section-heading, .section-title { font-size:24px; line-height:1.2; letter-spacing:-0.96px; font-weight:600; margin:0 0 var(--space-3); color:var(--fg); }
    .protocols { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:var(--space-3); }
    .protocol-breakdown { display:grid; gap:8px; }
    .protocol-breakdown-row { display:grid; grid-template-columns:1fr auto; gap:10px; align-items:center; color:var(--muted); font-size:var(--text-sm); }
    .protocol { padding:14px; border-radius:var(--radius-lg); background:var(--surface); box-shadow:var(--shadow-sm); }
    .protocol strong { display:block; margin-bottom:6px; color:var(--fg); }
    .actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:14px; }
    button { appearance:none; border:none; background:var(--accent); color:var(--bg); min-height:var(--control-height); padding:0 14px; border-radius:var(--control-radius); font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; font-size:var(--text-md); font-weight:500; cursor:pointer; box-shadow:var(--shadow-sm); }
    button:hover { opacity:.96; }
    button.secondary, .btn-cancel { background:var(--surface); color:var(--fg); box-shadow:var(--shadow-sm); }
    button.danger { background:var(--danger); color:var(--bg); }
    .btn-confirm { background:var(--danger); color:var(--bg); }
    .btn-modal-primary { background:var(--accent); color:var(--bg); }
    form { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:var(--space-3); margin:var(--space-4) 0; }
    .form-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:var(--space-4); margin:var(--space-4) 0; }
    .field-group { display:grid; gap:var(--space-2); min-width:0; }
    .field-group.span-2 { grid-column:1 / -1; }
    .field-label { color:var(--fg); font-size:var(--text-sm); font-weight:500; line-height:1.3; }
    .field-help { color:var(--muted); font-size:var(--text-xs); line-height:1.45; margin:0; }
    .inline-field-tools { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .btn-mini { background:var(--surface); color:var(--accent); border:1px solid var(--border); border-radius:var(--control-radius); padding:4px 12px; font-size:var(--text-xs); cursor:pointer; white-space:nowrap; transition:all .15s; min-height:32px; }
    .btn-mini:hover { background:var(--accent-subtle, rgba(99,102,241,0.08)); border-color:var(--accent); }
    .form-actions { grid-column:1 / -1; display:flex; justify-content:flex-end; align-items:center; gap:10px; padding-top:var(--space-4); margin-top:var(--space-2); }
    .action-toolbar { display:flex; align-items:center; justify-content:space-between; gap:var(--space-4); padding:var(--space-4); border-radius:var(--radius-lg); background:var(--surface-subtle); box-shadow:var(--shadow-sm); margin:var(--space-4) 0; }
    .action-toolbar.span-2 { grid-column:1 / -1; }
    .toolbar-copy { display:grid; gap:var(--space-1); min-width:0; color:var(--muted); font-size:var(--text-sm); line-height:1.5; }
    .toolbar-copy strong { color:var(--fg); font-size:var(--text-md); font-weight:600; letter-spacing:-0.14px; }
    .toolbar-actions { display:flex; align-items:center; justify-content:flex-end; gap:10px; flex-wrap:wrap; }
    .ui-control, input, select, textarea { width:100%; min-height:var(--control-height); border:none; outline:none; background:var(--surface); color:var(--fg); border-radius:var(--control-radius); padding:0 var(--space-3); box-shadow:var(--shadow-sm); font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; font-size:var(--text-md); line-height:1.4; transition:box-shadow .15s; }
    textarea { padding-top:10px; padding-bottom:10px; }
    input:focus, select:focus, textarea:focus, button:focus { box-shadow:var(--shadow-sm), 0 0 0 2px var(--focus); }
    .list { display:grid; gap:10px; margin-top:14px; }
    .row { display:grid; grid-template-columns:1.2fr .8fr .8fr .8fr .8fr .6fr; gap:10px; align-items:center; padding:var(--row-padding); border-radius:var(--radius-lg); background:var(--surface); box-shadow:var(--shadow-sm); }
    .resource-row { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:var(--space-4); align-items:center; padding:var(--row-padding); border-radius:var(--radius-lg); background:var(--surface); box-shadow:var(--shadow-sm); transition:box-shadow .16s ease, transform .16s ease; }
    .client-resource-row { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:var(--space-3); align-items:center; padding:10px var(--space-3); border-radius:var(--radius-md); background:var(--surface-subtle); box-shadow:var(--shadow-sm); border-left:3px solid var(--accent2); font-size:var(--text-sm); }
    .client-subsection .list { margin-top:0; gap:8px; }
    .client-add-row { display:flex; justify-content:flex-start; padding-top:var(--space-2); }
    .client-add-row .btn-sm { background:var(--surface-subtle); color:var(--fg); box-shadow:var(--shadow-sm); }
    .resource-row:hover { box-shadow:var(--shadow-md); transform:translateY(-1px); }
    .resource-main { min-width:0; display:grid; gap:var(--space-2); }
    .resource-title { display:flex; align-items:center; gap:var(--space-2); min-width:0; font-size:15px; font-weight:600; color:var(--fg); }
    .resource-title strong { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .resource-meta { display:flex; flex-wrap:wrap; align-items:center; gap:var(--space-2); color:var(--muted); font-size:var(--text-xs); line-height:1.5; }
    .status-badge { display:inline-flex; align-items:center; height:22px; padding:0 var(--space-2); border-radius:9999px; font-size:var(--text-xs); font-weight:500; box-shadow:var(--shadow-sm); }
    .status-badge.enabled { color:var(--accent2); background:rgba(22,163,74,.14); }
    .status-badge.disabled { color:var(--muted); background:rgba(161,161,170,.14); }
    .resource-actions { display:flex; align-items:center; justify-content:flex-end; gap:6px; }
    .icon-btn, .danger-icon-btn { display:inline-flex; align-items:center; justify-content:center; min-width:32px; min-height:32px; height:32px; padding:0 var(--space-2); border-radius:var(--control-radius); font-size:var(--text-xs); }
    .icon-btn { background:var(--surface); color:var(--fg); box-shadow:var(--shadow-sm); }
    .danger-icon-btn { background:rgba(239,68,68,.12); color:var(--danger); box-shadow:var(--shadow-sm); }
    .traffic-track { width:128px; height:4px; margin-top:5px; overflow:hidden; border-radius:9999px; background:var(--line-strong); }
    .traffic-fill { height:100%; border-radius:9999px; background:var(--accent2); }
    .empty-state { display:grid; gap:10px; justify-items:start; padding:22px; border-radius:var(--radius-xl); background:var(--surface); box-shadow:var(--shadow-sm); color:var(--muted); }
    .empty-state-title { color:var(--fg); font-size:16px; font-weight:600; letter-spacing:-0.32px; }
    .empty-state-copy { max-width:560px; color:var(--muted); font-size:13px; line-height:1.6; }
    .empty-state-actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:4px; }
    .version-banner { margin-bottom:var(--space-3); padding:14px 18px; border-radius:var(--radius-md); background:var(--surface-subtle); box-shadow:var(--shadow-sm), inset 3px 0 0 var(--accent); font-size:var(--text-sm); line-height:1.5; color:var(--fg); }
    .version-banner a { color:var(--fg); text-decoration:underline; }
    .notice-slot { margin-top:12px; }
    .xray-status-panel { box-shadow:var(--shadow-sm); border-radius:var(--radius-xl); padding:var(--space-5); margin-bottom:var(--space-4); display:grid; gap:5px; font-size:var(--text-sm); line-height:1.7; }
    .search-input { height:36px; min-width:160px; border:none; border-radius:var(--radius-md); padding:0 12px; font-size:var(--text-sm); background:var(--surface); color:var(--fg); box-shadow:var(--shadow-sm); outline:none; font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; transition:box-shadow .15s; }
    .search-input:focus { box-shadow:var(--shadow-sm), 0 0 0 2px var(--focus); }
    .sort-select { height:36px; border:none; border-radius:var(--radius-md); padding:0 10px; font-size:var(--text-sm); background:var(--surface); color:var(--fg); box-shadow:var(--shadow-sm); cursor:pointer; outline:none; font-family:'Geist',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif; transition:box-shadow .15s; }
    .xray-preview-pre { background:var(--surface-subtle); border-radius:var(--radius-lg); padding:16px; font-size:12px; overflow-x:auto; white-space:pre-wrap; max-height:400px; overflow-y:auto; box-shadow:var(--shadow-sm); margin:0; }
    .xray-preview-header { display:flex; align-items:center; justify-content:space-between; padding:8px 0 4px; }
    .notice { display:grid; gap:8px; padding:16px; border-radius:var(--radius-lg); background:var(--surface); box-shadow:var(--shadow-sm), inset 3px 0 0 var(--accent); }
    .notice-title { color:var(--fg); font-size:14px; font-weight:600; letter-spacing:-0.14px; }
    .notice-copy { color:var(--muted); font-size:13px; line-height:1.55; white-space:pre-wrap; }
    .notice.success { box-shadow:var(--shadow-sm), inset 3px 0 0 var(--accent2); }
    .notice.error { box-shadow:var(--shadow-sm), inset 3px 0 0 var(--danger); }
    .muted { color:var(--muted); }
    .error { color:var(--danger); }
    .btn-del { background:var(--danger); border:none; color:white; padding:4px 10px; border-radius:var(--radius-sm); font-size:12px; cursor:pointer; }
    .bar-low { background:var(--accent2); }
    .bar-mid { background:var(--amber); }
    .bar-high { background:var(--danger); }
    .copy-link { font-size:11px; cursor:pointer; }
    .btn-sm { border:none; color:var(--bg); padding:4px 8px; border-radius:var(--radius-sm); font-size:11px; cursor:pointer; }
    .hidden { display:none; }
    #toast-container { position:fixed; top:20px; right:20px; z-index:9999; display:flex; flex-direction:column; gap:10px; }
    .toast { background:var(--surface); border:none; color:var(--fg); padding:12px 18px; border-radius:var(--radius-md); box-shadow:var(--shadow-md); animation: toastIn .3s ease, toastOut .3s ease 2.7s forwards; }
    .toast.error { box-shadow:var(--shadow-md), inset 3px 0 0 rgba(220,38,38,.55); }
    .toast.success { box-shadow:var(--shadow-md), inset 3px 0 0 rgba(22,163,74,.55); }
    @keyframes toastIn { from { opacity:0; transform:translateX(40px); } to { opacity:1; transform:translateX(0); } }
    @keyframes toastOut { from { opacity:1; } to { opacity:0; transform:translateX(40px); } }
    #confirm-overlay.hidden { display:none; }
    #create-inbound-overlay.hidden { display:none; }
    #create-client-overlay.hidden { display:none; }
    #edit-inbound-overlay.hidden { display:none; }
    #edit-client-overlay.hidden { display:none; }
    #confirm-dialog { background:var(--surface); box-shadow:var(--shadow-md); border-radius:var(--radius-xl); padding:var(--space-6); min-width:360px; max-width:520px; max-height:80vh; overflow-y:auto; }
    #confirm-dialog p { margin:0 0 20px; font-size:15px; line-height:1.6; color:var(--fg); }
    #confirm-dialog .actions { display:flex; gap:10px; justify-content:flex-end; }
    .modal-title { margin:0 0 var(--space-4); font-size:var(--text-lg); line-height:1.3; font-weight:600; letter-spacing:-0.2px; color:var(--fg); }
    .modal-overlay { position:fixed; inset:0; z-index:10000; background:rgba(0,0,0,.12); backdrop-filter:blur(4px); display:flex; align-items:center; justify-content:center; animation:fadeIn .2s; }
    .modal-content { background:var(--surface); box-shadow:var(--shadow-md); border-radius:var(--radius-xl); padding:var(--space-6); min-width:360px; max-width:520px; max-height:80vh; overflow-y:auto; }
    .modal-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:var(--space-4); }
    .modal-header .modal-title { margin:0; }
    .modal-close { width:32px; height:32px; min-height:32px; padding:0; display:inline-flex; align-items:center; justify-content:center; border-radius:var(--radius-sm); background:var(--surface); color:var(--fg); box-shadow:var(--shadow-sm); font-size:16px; line-height:1; }
    .modal-footer { display:flex; gap:10px; justify-content:flex-end; margin-top:var(--space-4); }
    .modal-checkbox { display:flex; align-items:center; gap:8px; font-size:var(--text-sm); color:var(--fg); cursor:pointer; }
    .modal-checkbox input[type=checkbox] { width:16px; height:16px; accent-color:var(--accent); cursor:pointer; margin:0; }
    .modal-form { margin:0; grid-template-columns:repeat(2,minmax(0,1fr)); }
    #create-inbound-form.modal-form, #create-client-form.modal-form, #edit-inbound-form.modal-form, #edit-client-form.modal-form { gap:var(--space-4); }
    .modal-actions { margin-top: var(--space-4); }
    .advanced-fieldset { padding:var(--space-4); border-radius:var(--radius-lg); background:var(--surface-subtle); box-shadow:var(--shadow-sm), inset 0 0 0 1px var(--line); }
    .advanced-fieldset-title { color:var(--fg); font-size:var(--text-sm); font-weight:600; letter-spacing:-0.12px; }
    .advanced-fieldset-copy { color:var(--muted); font-size:var(--text-xs); line-height:1.55; }
    #dynamic-fields, #ei-dynamic-fields { display:contents; }
    #create-inbound-dialog input, #create-inbound-dialog select, #create-client-dialog input, #create-client-dialog select, #edit-inbound-dialog input, #edit-inbound-dialog select, #edit-client-dialog input, #edit-client-dialog select { width:100%; box-sizing:border-box; margin-bottom:0; }
    @keyframes fadeIn { from { opacity:0; } to { opacity:1; } }
    /* Mobile sidebar overlay */
    #sidebar-overlay { display:none; position:fixed; inset:0; background:rgba(0,0,0,.12); backdrop-filter:blur(4px); z-index:99; }
    @media (max-width: 768px) {
      .app-shell { grid-template-columns:1fr; }
      .sidebar { position:fixed; top:0; left:0; bottom:0; width:var(--sidebar-width); z-index:100; transform:translateX(-100%); transition:transform .25s ease; box-shadow:inset -1px 0 0 var(--line-strong); }
      .sidebar-open .sidebar { transform:translateX(0); }
      #sidebar-overlay { display:block; opacity:0; pointer-events:none; transition:opacity .25s ease; }
      .sidebar-open #sidebar-overlay { opacity:1; pointer-events:auto; }
      #sidebar-toggle { display:flex; }
      .grid,.overview-grid,.protocols { grid-template-columns:1fr 1fr; }
      .overview-insights { grid-template-columns:1fr; }
      form { grid-template-columns:repeat(2,minmax(0,1fr)); }
    }
    @media (max-width: 560px) { .grid,.overview-grid,.protocols, form { grid-template-columns:1fr; } main { padding:18px; } }
  </style>
</head>
<body>
  <div id="toast-container"></div>
  <div id="confirm-overlay" class="modal-overlay hidden" onclick="if(event.target===this)rejectConfirm()">
    <div id="confirm-dialog">
      <p id="confirm-msg"></p>
      <div class="actions">
        <button class="btn-cancel" onclick="rejectConfirm()">取消</button>
        <button class="btn-confirm" onclick="resolveConfirm()">确认</button>
      </div>
    </div>
  </div>

  <!-- Create Inbound Modal -->
<div id="create-inbound-overlay" class="modal-overlay hidden" onclick="if(event.target===this)closeCreateInbound()">
      <div id="create-inbound-dialog" class="modal-content">
        <div class="modal-header">
          <h3 class="modal-title">新增入站</h3>
          <button class="modal-close" onclick="closeCreateInbound()">✕</button>
        </div>
      <form id="create-inbound-form" class="form-grid modal-form" onsubmit="return false">
        <div class="field-group">
          <label class="field-label" for="inbound-remark">名称</label>
          <input id="inbound-remark" name="remark" placeholder="例如 主入口" required>
          <p class="field-help">只需要填写名称，其他参数会自动生成并可继续手动修改。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="inbound-protocol">协议类型</label>
          <select id="inbound-protocol" name="protocol" onchange="onProtocolChange()">
            <option value="vless">VLESS</option>
            <option value="vmess">VMess</option>
            <option value="trojan">Trojan</option>
            <option value="shadowsocks">Shadowsocks</option>
            <option value="hysteria2">Hysteria2</option>
            <option value="tuic">TUIC</option>
            <option value="wireguard">WireGuard ⚠️ (需升级 sing-box v1.14+)</option>
            <option value="shadowtls">ShadowTLS</option>
          </select>
          <p id="protocol-description" class="field-help" style="color:var(--accent);font-weight:500">选择核心入站协议，自动配置传输方式与安全层。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="inbound-port">监听端口</label>
          <input id="inbound-port" name="port" type="number" min="1" max="65535" placeholder="例如 443" required>
          <p class="field-help">建议使用未被占用的公网端口。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="inbound-network">参数类型 / 传输方式</label>
          <select name="network" id="inbound-network">
            <option value="tcp">TCP</option>
            <option value="ws">WebSocket</option>
            <option value="kcp">mKCP</option>
            <option value="grpc">gRPC</option>
            <option value="quic">QUIC</option>
            <option value="h2">HTTP/2</option>
            <option value="xhttp">XHTTP</option>
          </select>
          <p class="field-help">只要选定参数类型，其余如 UUID、密码、短 ID、证书路径等会随机填充并可手动修改。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="inbound-security">安全层</label>
          <select id="inbound-security" name="security">
            <option value="none">none</option>
            <option value="tls">tls</option>
            <option value="reality">reality</option>
          </select>
          <p class="field-help">REALITY/TLS 会展开证书或伪装目标字段。</p>
        </div>
        <div class="field-group span-2">
          <label class="field-label" for="inbound-uuid">入站 UUID / Shadowsocks 密码</label>
          <div class="inline-field-tools"><input id="inbound-uuid" name="uuid" placeholder="自动生成；Shadowsocks 会作为单用户密码/密钥"><button type="button" class="btn-mini" onclick="regenerateField('inbound-uuid')">重新生成</button><button type="button" class="btn-mini" onclick="toggleSecretField('inbound-uuid')">显示/隐藏</button></div>
          <p class="field-help">普通协议可保持默认；Shadowsocks 单用户模式会使用这里的值作为密码/密钥。</p>
        </div>
        <div id="dynamic-fields">
          <div id="ws-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">WebSocket 设置</div>
            <div class="advanced-fieldset-copy">适合 CDN、反向代理或路径分流场景。</div>
            <input name="ws_path" placeholder="WS Path (默认 /)">
            <input name="ws_host" placeholder="WS Host (可选)">
            <p class="field-help">路径和 Host 用于 CDN 或反代场景。</p>
          </div>
          <div id="grpc-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">gRPC 设置</div>
            <div class="advanced-fieldset-copy">用于 gRPC 传输的服务名，客户端需保持一致。</div>
            <input name="grpc_service_name" value="migate" placeholder="gRPC ServiceName">
          </div>
          <div id="xhttp-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">XHTTP 设置</div>
            <div class="advanced-fieldset-copy">配置 XHTTP 路径与上传模式。</div>
            <input name="xhttp_path" value="/" placeholder="XHTTP Path (默认 /)">
            <select name="xhttp_mode">
              <option value="stream-one">stream-one</option>
              <option value="packet-up">packet-up</option>
              <option value="stream-up">stream-up</option>
            </select>
          </div>
          <div id="reality-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">REALITY 设置</div>
            <div class="advanced-fieldset-copy">填写伪装目标、SNI 与短 ID，避免与客户端参数不一致。</div>
            <input name="reality_dest" value="www.cloudflare.com:443" placeholder="目标 (dest)">
            <input name="reality_server_names" value="www.cloudflare.com" placeholder="ServerNames (逗号分隔)">
            <div class="inline-field-tools"><input id="inbound-reality-short-id" name="reality_short_id" placeholder="ShortId (可选)"><button type="button" class="btn-mini" onclick="regenerateField('inbound-reality-short-id')">重新生成</button></div>
          </div>
          <div id="ss-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">Shadowsocks 设置</div>
            <div class="advanced-fieldset-copy">选择客户端支持的加密方法。</div>
            <div class="inline-field-tools"><select id="inbound-ss-method" name="ss_method">
              <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
              <option value="aes-256-gcm">aes-256-gcm</option>
              <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
            </select><button type="button" class="btn-mini" onclick="regenerateField('inbound-ss-method')">重新生成</button></div>
          </div>
          <div id="hy2-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">Hysteria2 设置</div>
            <div class="advanced-fieldset-copy">Hysteria2 使用 QUIC 传输，以下为可选参数。</div>
            <input name="hy2_up_mbps" type="number" min="0" placeholder="上行速率 mbps (0=不限) 默认 0">
            <input name="hy2_down_mbps" type="number" min="0" placeholder="下行速率 mbps (0=不限) 默认 0">
            <input name="hy2_obfs" placeholder="混淆类型 (如 salamander, 可选)">
            <div class="inline-field-tools"><input id="inbound-hy2-obfs-password" name="hy2_obfs_password" type="password" placeholder="混淆密码 (可选)"><button type="button" class="btn-mini" onclick="regenerateField('inbound-hy2-obfs-password')">重新生成</button><button type="button" class="btn-mini" onclick="toggleSecretField('inbound-hy2-obfs-password')">显示/隐藏</button></div>
            <p class="field-help">速率限制为 0 表示不限制。混淆类型通常为 salamander。</p>
          </div>
          <div id="tuic-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">TUIC 设置</div>
            <div class="advanced-fieldset-copy">TUIC 基于 QUIC 的低延迟 UDP 代理。</div>
            <select name="tuic_congestion_control">
              <option value="bbr">BBR (推荐)</option>
              <option value="cubic">Cubic</option>
              <option value="new_reno">NewReno</option>
            </select>
            <label><input name="tuic_zero_rtt" type="checkbox" value="1"> 启用 0-RTT 握手</label>
            <p class="field-help">拥塞控制和 0-RTT 握手可优化延迟。</p>
          </div>
          <div id="wireguard-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">WireGuard 设置</div>
            <div class="advanced-fieldset-copy">WireGuard 简单高效的 VPN 协议。</div>
            <div class="inline-field-tools"><input name="wg_private_key" placeholder="私钥 (PrivateKey) 必填"><button type="button" class="btn-mini" onclick="regenerateFieldByName('wg_private_key')">生成密钥</button></div>
            <input name="wg_address" placeholder="本地地址 (如 10.0.0.1/24) 必填">
            <input name="wg_peer_public_key" placeholder="客户端公钥 (PublicKey) 必填">
            <input name="wg_allowed_ips" placeholder="允许的 IP (默认 0.0.0.0/0, ::/0)">
            <input name="wg_endpoint" placeholder="客户端 Endpoint (可选)">
            <div class="inline-field-tools"><input name="wg_preshared_key" placeholder="预共享密钥 (PreSharedKey, 可选)"><button type="button" class="btn-mini" onclick="regenerateFieldByName('wg_preshared_key')">生成密钥</button></div>
            <input name="wg_mtu" type="number" min="1280" placeholder="MTU (默认 1420)">
            <p class="field-help">WireGuard 需要服务器端生成私钥/公钥对。</p>
          </div>
          <div id="shadowtls-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">ShadowTLS 设置</div>
            <div class="advanced-fieldset-copy">ShadowTLS 将流量伪装成标准 TLS 连接。</div>
            <div class="inline-field-tools"><input name="shadowtls_password" placeholder="密码 (Password)"><button type="button" class="btn-mini" onclick="regenerateFieldByName('shadowtls_password')">重新生成</button></div>
            <select name="shadowtls_version">
              <option value="3">v3 (推荐)</option>
              <option value="2">v2</option>
              <option value="1">v1</option>
            </select>
            <p class="field-help">注意：ShadowTLS 复用 TLS 设置中的 SNI 作为 handshake_server_name。</p>
          </div>
          <div id="tls-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">TLS 设置</div>
            <div class="advanced-fieldset-copy">填写证书和私钥路径，应用前会交给 Xray 校验。</div>
            <input name="tls_cert_file" placeholder="TLS 证书路径 (如 /etc/.../fullchain.pem)">
            <div class="inline-field-tools"><input name="tls_key_file" placeholder="TLS 密钥路径 (如 /etc/.../privkey.key)"></div>
            <input name="tls_sni" placeholder="SNI / ServerName (可选，留空则自动匹配)">
            <select name="tls_fingerprint">
              <option value="">指纹 (默认不指定)</option>
              <option value="chrome">Chrome</option>
              <option value="firefox">Firefox</option>
              <option value="safari">Safari</option>
              <option value="random">Random</option>
              <option value="randomized">Randomized</option>
            </select>
            <input name="tls_alpn" placeholder="ALPN (逗号分隔，如 h2,http/1.1)">
            <p class="field-help">SNI 与指纹用于 TLS 握手指纹伪装；ALPN 用于协议协商，留空为默认。</p>
          </div>
        </div>
        <div class="advanced-fieldset field-group span-2" style="border-left:2px solid var(--accent);padding-left:12px;margin-bottom:0">
          <div onclick="toggleInitClient(this)" style="cursor:pointer;color:var(--accent);user-select:none;font-size:13px">
            <span class="chevron">▼</span> 同时添加首个客户端（推荐）
          </div>
          <div id="init-client-fields" style="margin-top:8px;display:grid;gap:10px">
            <div class="inline-field-tools" style="grid-column:1/-1"><input id="init-client-email" placeholder="客户端标识 (如 user01 或 sam@example.com)"><button type="button" class="btn-mini" onclick="regenerateField('init-client-email')">重新生成</button></div>
            <div class="inline-field-tools" style="grid-column:1/-1"><input id="init-client-uuid" placeholder="客户端 UUID / 密码 / 密钥（自动生成，可修改）"><button type="button" class="btn-mini" onclick="regenerateField('init-client-uuid')">重新生成</button><button type="button" class="btn-mini" onclick="toggleSecretField('init-client-uuid')">显示/隐藏</button></div>
            <input id="init-client-traffic" type="number" min="0" placeholder="流量上限，单位字节；0=无限" value="0">
            <input id="init-client-expiry" type="datetime-local">
            <p id="init-client-credential-help" class="field-help" style="grid-column:1/-1">客户端凭据会自动生成。VLESS/VMess 使用 UUID，Trojan/Shadowsocks/Hysteria2 使用密码或密钥；不懂时保持默认即可。</p>
          </div>
        </div>
        <div class="form-actions modal-actions">
          <button type="button" class="btn-cancel" onclick="closeCreateInbound()">取消</button>
          <button type="submit" class="btn-modal-primary" onclick="saveCreateInbound()">保存入站</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Create Client Modal -->
  <div id="create-client-overlay" class="modal-overlay hidden" onclick="if(event.target===this)closeCreateClient()">
    <div id="create-client-dialog" class="modal-content">
      <div class="modal-header">
        <h3 class="modal-title">创建客户端</h3>
        <button class="modal-close" onclick="closeCreateClient()">✕</button>
      </div>
      <form id="create-client-form" class="form-grid modal-form" onsubmit="return false">
        <input id="client-inbound-id" type="hidden" value="">
        <div class="field-group span-2">
          <label class="field-label" for="client-email">客户端标识</label>
          <input id="client-email" name="email" placeholder="例如 user01" required>
          <p class="field-help">用于区分设备或用户，也会出现在分享链接备注中。</p>
        </div>
        <div class="field-group span-2">
          <label class="field-label" for="client-uuid">客户端 UUID / 密码 / 密钥</label>
          <div class="inline-field-tools"><input id="client-uuid" name="uuid" placeholder="自动生成，可手动修改"><button type="button" class="btn-mini" onclick="regenerateField('client-uuid')">重新生成</button><button type="button" class="btn-mini" onclick="toggleSecretField('client-uuid')">显示/隐藏</button></div>
          <p class="field-help">VLESS/VMess 使用 UUID；Trojan、Shadowsocks、Hysteria2 可当作密码或密钥，不懂时保持默认即可。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="client-traffic-limit">流量限额</label>
          <input id="client-traffic-limit" name="traffic_limit" type="number" min="0" placeholder="0 = 不限">
          <p class="field-help">单位为字节；留空或 0 表示不限流量。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="client-expiry">到期时间</label>
          <input name="expiry_at" type="datetime-local" id="client-expiry" placeholder="到期时间">
          <p class="field-help">到期后订阅会返回明确的过期提示。</p>
        </div>
        <div class="form-actions modal-actions">
          <button type="button" class="btn-cancel" onclick="closeCreateClient()">取消</button>
          <button type="submit" class="btn-modal-primary" onclick="saveCreateClient()">创建客户端</button>
        </div>
      </form>
    </div>
  </div>


  <!-- Edit Inbound Modal -->
  <div id="edit-inbound-overlay" class="modal-overlay hidden" onclick="if(event.target===this)closeEditInbound()">
    <div id="edit-inbound-dialog" class="modal-content">
      <div class="modal-header">
        <h3 class="modal-title">编辑入站</h3>
        <button class="modal-close" onclick="closeEditInbound()">✕</button>
      </div>
      <form id="edit-inbound-form" class="form-grid modal-form" onsubmit="return false">
        <div class="field-group">
          <label class="field-label" for="ei-remark">入站备注</label>
          <input id="ei-remark" placeholder="备注" required>
          <p class="field-help">用于列表识别，建议使用节点地区或用途。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="ei-protocol">协议</label>
          <select id="ei-protocol">
            <option value="vless">VLESS</option>
            <option value="vmess">VMess</option>
            <option value="trojan">Trojan</option>
            <option value="shadowsocks">Shadowsocks</option>
            <option value="hysteria2">Hysteria2</option>
          </select>
          <p class="field-help">保存后会影响客户端链接格式。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="ei-port">监听端口</label>
          <input id="ei-port" type="number" min="1" max="65535" placeholder="端口" required>
          <p class="field-help">1-65535，需确保防火墙已放行。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="ei-network">传输</label>
          <select id="ei-network">
            <option value="tcp">TCP</option>
            <option value="ws">WebSocket</option>
            <option value="kcp">mKCP</option>
            <option value="grpc">gRPC</option>
            <option value="quic">QUIC</option>
            <option value="h2">HTTP/2</option>
            <option value="xhttp">XHTTP</option>
          </select>
          <p class="field-help">切换后会显示对应高级字段。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="ei-security">安全</label>
          <select id="ei-security">
            <option value="none">none</option>
            <option value="tls">tls</option>
            <option value="reality">reality</option>
          </select>
          <p class="field-help">TLS/REALITY 会显示证书或伪装参数。</p>
        </div>
        <div id="ei-dynamic-fields">
          <div id="ei-ws-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">WebSocket 设置</div>
            <div class="advanced-fieldset-copy">适合 CDN、反向代理或路径分流场景。</div>
            <label class="field-label" for="ei-ws-path">WebSocket</label>
            <input id="ei-ws-path" placeholder="WS Path (默认 /)">
            <input id="ei-ws-host" placeholder="WS Host (可选)">
            <p class="field-help">路径和 Host 用于 CDN 或反代场景。</p>
          </div>
          <div id="ei-grpc-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">gRPC 设置</div>
            <div class="advanced-fieldset-copy">用于 gRPC 传输的服务名，客户端需保持一致。</div>
            <label class="field-label" for="ei-grpc-service-name">gRPC ServiceName</label>
            <input id="ei-grpc-service-name" value="migate" placeholder="gRPC ServiceName">
            <p class="field-help">客户端需与服务端保持一致。</p>
          </div>
          <div id="ei-xhttp-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">XHTTP 设置</div>
            <div class="advanced-fieldset-copy">配置 XHTTP 路径与上传模式。</div>
            <label class="field-label" for="ei-xhttp-path">XHTTP</label>
            <input id="ei-xhttp-path" value="/" placeholder="XHTTP Path (默认 /)">
            <select id="ei-xhttp-mode">
              <option value="stream-one">stream-one</option>
              <option value="packet-up">packet-up</option>
              <option value="stream-up">stream-up</option>
            </select>
            <p class="field-help">选择 XHTTP 路径和上传模式。</p>
          </div>
          <div id="ei-reality-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">REALITY 设置</div>
            <div class="advanced-fieldset-copy">填写伪装目标、SNI 与短 ID，避免与客户端参数不一致。</div>
            <label class="field-label" for="ei-reality-dest">REALITY</label>
            <input id="ei-reality-dest" value="www.cloudflare.com:443" placeholder="目标 (dest)">
            <input id="ei-reality-server-names" value="www.cloudflare.com" placeholder="ServerNames (逗号分隔)">
            <input id="ei-reality-short-id" placeholder="ShortId (可选)">
            <input type="hidden" id="ei-reality-private-key">
            <p class="field-help">用于 REALITY 伪装目标、SNI 和短 ID。</p>
          </div>
          <div id="ei-ss-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">Shadowsocks 设置</div>
            <div class="advanced-fieldset-copy">选择客户端支持的加密方法。</div>
            <label class="field-label" for="ei-ss-method">Shadowsocks 加密</label>
            <select id="ei-ss-method">
              <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
              <option value="aes-256-gcm">aes-256-gcm</option>
              <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
            </select>
            <p class="field-help">选择与客户端兼容的加密方法。</p>
          </div>
          <div id="ei-hy2-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">Hysteria2 设置</div>
            <div class="advanced-fieldset-copy">Hysteria2 使用 QUIC 传输，以下为可选参数。</div>
            <label class="field-label" for="ei-hy2-up">Hysteria2 上行/下行</label>
            <input id="ei-hy2-up" type="number" min="0" placeholder="上行速率 mbps (0=不限) 默认 0">
            <input id="ei-hy2-down" type="number" min="0" placeholder="下行速率 mbps (0=不限) 默认 0">
            <input id="ei-hy2-obfs" placeholder="混淆类型 (如 salamander, 可选)">
            <input id="ei-hy2-obfs-password" placeholder="混淆密码 (可选)">
            <p class="field-help">速率限制为 0 表示不限制。混淆类型通常为 salamander。</p>
          </div>
          <div id="ei-tuic-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">TUIC 设置</div>
            <div class="advanced-fieldset-copy">TUIC 基于 QUIC 的低延迟 UDP 代理。</div>
            <label class="field-label" for="ei-tuic-cc">TUIC 拥塞控制</label>
            <select id="ei-tuic-cc">
              <option value="bbr">BBR (推荐)</option>
              <option value="cubic">Cubic</option>
              <option value="new_reno">NewReno</option>
            </select>
            <label><input id="ei-tuic-zero-rtt" type="checkbox" value="1"> 启用 0-RTT 握手</label>
            <p class="field-help">拥塞控制和 0-RTT 握手可优化延迟。</p>
          </div>
          <div id="ei-wireguard-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">WireGuard 设置</div>
            <div class="advanced-fieldset-copy">WireGuard 简单高效的 VPN 协议。</div>
            <label class="field-label" for="ei-wg-private-key">WireGuard 私钥</label>
            <input id="ei-wg-private-key" placeholder="私钥 (PrivateKey) 必填">
            <input id="ei-wg-address" placeholder="本地地址 (如 10.0.0.1/24) 必填">
            <input id="ei-wg-peer-public-key" placeholder="客户端公钥 (PublicKey) 必填">
            <input id="ei-wg-allowed-ips" placeholder="允许的 IP (默认 0.0.0.0/0, ::/0)">
            <input id="ei-wg-endpoint" placeholder="客户端 Endpoint (可选)">
            <input id="ei-wg-preshared-key" placeholder="预共享密钥 (PreSharedKey, 可选)">
            <input id="ei-wg-mtu" type="number" min="1280" placeholder="MTU (默认 1420)">
            <p class="field-help">WireGuard 需要服务器端生成私钥/公钥对。</p>
          </div>
          <div id="ei-shadowtls-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">ShadowTLS 设置</div>
            <div class="advanced-fieldset-copy">ShadowTLS 将流量伪装成标准 TLS 连接。</div>
            <label class="field-label" for="ei-shadowtls-password">ShadowTLS 密码</label>
            <input id="ei-shadowtls-password" placeholder="密码 (Password)">
            <select id="ei-shadowtls-version">
              <option value="3">v3 (推荐)</option>
              <option value="2">v2</option>
              <option value="1">v1</option>
            </select>
            <p class="field-help">注意：ShadowTLS 复用 TLS 设置中的 SNI 作为 handshake_server_name。</p>
          </div>
          <div id="ei-tls-settings" class="advanced-fieldset field-group span-2 hidden">
            <div class="advanced-fieldset-title">TLS 设置</div>
            <div class="advanced-fieldset-copy">填写证书和私钥路径，应用前会交给 Xray 校验。</div>
            <label class="field-label" for="ei-tls-cert-file">TLS 证书</label>
            <input id="ei-tls-cert-file" placeholder="TLS 证书路径 (如 /etc/.../fullchain.pem)">
            <input id="ei-tls-key-file" placeholder="TLS 密钥路径 (如 /etc/.../privkey.key)">
            <input id="ei-tls-sni" placeholder="SNI / ServerName (可选，留空则自动匹配)">
            <select id="ei-tls-fingerprint">
              <option value="">指纹 (默认不指定)</option>
              <option value="chrome">Chrome</option>
              <option value="firefox">Firefox</option>
              <option value="safari">Safari</option>
              <option value="random">Random</option>
              <option value="randomized">Randomized</option>
            </select>
            <input id="ei-tls-alpn" placeholder="ALPN (逗号分隔，如 h2,http/1.1)">
            <p class="field-help">SNI 与指纹用于 TLS 握手指纹伪装；ALPN 用于协议协商，留空为默认。</p>
          </div>
        </div>
        <div class="form-actions modal-actions">
          <button type="button" class="btn-cancel" onclick="closeEditInbound()">取消</button>
          <button type="submit" class="btn-modal-primary" onclick="saveEditInbound()">保存</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Edit Client Modal -->
  <div id="edit-client-overlay" class="modal-overlay hidden" onclick="if(event.target===this)closeEditClient()">
    <div id="edit-client-dialog" class="modal-content">
      <div class="modal-header">
        <h3 class="modal-title">编辑客户端</h3>
        <button class="modal-close" onclick="closeEditClient()">✕</button>
      </div>
      <form id="edit-client-form" class="form-grid modal-form" onsubmit="return false">
        <div class="field-group span-2">
          <label class="field-label" for="ec-email">客户端标识</label>
          <input id="ec-email" placeholder="客户端标识，例如 user01" required>
          <p class="field-help">用于识别用户或设备，不影响 UUID。</p>
        </div>
        <div class="field-group">
          <label class="field-label">启用状态</label>
          <div style="display:flex;align-items:center;gap:12px;margin-top:4px">
            <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
              <input id="ec-enabled" type="checkbox" style="width:18px;height:18px;accent-color:var(--accent)">
              <span id="ec-enabled-label">已启用</span>
            </label>
          </div>
        </div>
        <div class="field-group">
          <label class="field-label" for="ec-traffic-limit">流量限额</label>
          <input id="ec-traffic-limit" type="number" min="0" placeholder="流量限额（字节，0=不限）">
          <p class="field-help">单位为字节，填 0 表示不限。</p>
        </div>
        <div class="field-group span-2" style="border:1px solid var(--line-strong);border-radius:8px;padding:12px;background:var(--surface)">
          <label class="field-label" style="margin-top:0">当前流量</label>
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
            <div>
              <span style="font-size:13px">↑ 上行: <strong id="ec-up-display">0 B</strong></span>
              <span style="font-size:13px;margin-left:16px">↓ 下行: <strong id="ec-down-display">0 B</strong></span>
              <span style="font-size:13px;margin-left:16px">总计: <strong id="ec-total-display">0 B</strong></span>
            </div>
            <button type="button" class="btn-confirm" onclick="resetClientTraffic()">重置流量</button>
          </div>
          <p class="field-help" style="margin-bottom:0">点击重置会将上下行数据清零，不可恢复。</p>
        </div>
        <div class="field-group">
          <label class="field-label" for="ec-expiry-at">过期时间</label>
          <input id="ec-expiry-at" type="datetime-local">
          <p class="field-help">留空表示不过期。</p>
        </div>
        <div class="form-actions modal-actions">
          <button type="button" class="btn-cancel" onclick="closeEditClient()">取消</button>
          <button type="submit" class="btn-modal-primary" onclick="saveEditClient()">保存</button>
        </div>
      </form>
    </div>
  </div>

  <div class="app-shell">
    <button id="sidebar-toggle" onclick="toggleSidebar()" aria-label="展开菜单">☰</button>
    <aside class="sidebar">
      <div class="brand">MiGate</div>
      <div class="subtitle">轻量单二进制面板，专注协议、客户端与双核心管理。</div>
      <nav>
        <a class="active" href="#">概览</a>
        <a href="#inbounds">入站</a>
        <a href="#outbound">出站</a>
        <a href="#routing">路由</a>
        <a href="#xray">Xray</a>
        <a href="#singbox">Sing-box</a>
        <a href="#settings">设置</a>
      </nav>
      <div class="account-panel" aria-label="当前账号">
        <div class="account-label">当前用户</div>
        <div id="current-username" class="account-name">加载中...</div>
        <div class="account-actions">
          <button id="logout-button" class="secondary" onclick="logoutPanel()">登出</button>
          <button id="theme-toggle" class="secondary" onclick="toggleTheme()">深色模式</button>
        </div>
      </div>
    </aside>
    <div id="sidebar-overlay" onclick="closeSidebar()"></div>
    <main>
      <section id="overview" class="overview-grid" aria-label="概览指标">
        <div id="version-banner" class="version-banner" style="display:none; grid-column:1 / -1"></div>
        <div class="card panel"><div>入站</div><div id="inbound-count" class="metric">0</div><p>VLESS / VMess / Trojan / Shadowsocks</p></div>
        <div class="card panel"><div>客户端</div><div id="client-count" class="metric">0</div><p>活跃 / 总计</p></div>
        <div class="card panel"><div>总流量</div><div id="total-traffic" class="metric">0 B</div><p>所有客户端上行+下行累计</p></div>
        <div class="card panel"><div>出站</div><div id="outbound-stats" class="metric">0</div><p>已启用 / 总计</p></div>
        <div class="card panel"><div>路由规则</div><div id="routing-stats" class="metric">0</div><p>已启用 / 总计</p></div>
        <div class="card panel"><div>Xray</div><div id="xray-status-metric" class="metric">检查中...</div><p>运行状态</p></div>
        <div class="card panel"><div>Sing-box</div><div id="singbox-status-metric" class="metric">检查中...</div><p>Hysteria2 / TUIC / ShadowTLS</p></div>
        <div class="overview-insights">
          <div class="overview-card">
            <div class="overview-card-title">运行概况</div>
            <div id="overview-health-summary" class="muted">正在读取入站、客户端与 Xray 状态...</div>
            <div id="overview-active-summary" class="overview-pill">活跃客户端 0 / 0</div>
          </div>
          <div class="overview-card">
            <div class="overview-card-title">协议分布</div>
            <div id="overview-protocol-breakdown" class="protocol-breakdown"></div>
          </div>
        </div>
      </section>
      <section id="inbounds" class="card panel">
        <h2 class="section-heading">核心协议</h2>
        <div class="protocols">
          <div class="protocol"><strong>VLESS</strong><span>Reality / TLS 入站</span></div>
          <div class="protocol"><strong>VMess</strong><span>WebSocket / TLS 兼容</span></div>
          <div class="protocol"><strong>Trojan</strong><span>TLS 节点支持</span></div>
          <div class="protocol"><strong>Shadowsocks</strong><span>轻量转发协议</span></div>
        </div>
        <div class="actions">
          <button onclick="openCreateInbound()">新增入站</button>
          <button class="secondary" onclick="navigateTo('outbound')">出站</button>
          <input id="inbound-search" type="text" placeholder="搜索入站..." class="search-input" oninput="filterInbounds()">
          <select id="inbound-sort" class="sort-select" onchange="sortInbounds()">
            <option value="id">默认排序</option>
            <option value="port">按端口</option>
            <option value="protocol">按协议</option>
            <option value="clients">按客户端数</option>
          </select>
        </div>
        <div id="inbound-list" class="list muted">正在加载入站...</div>
      </section>
      <section id="outbound" class="card panel">
        <h2 class="section-title">出站管理</h2>
        <p class="muted" style="margin-bottom:16px">配置链式代理转发（SOCKS5 / HTTP），实现流量经外部代理链路中转。</p>
        <div class="actions">
          <button onclick="openCreateOutbound()">新建出站</button>
          <button class="secondary" onclick="batchSpeedTest()">一键测速</button>
          <button class="secondary" onclick="checkVPNGateOutboundHealth()">检测 VPN Gate</button>
          <button class="secondary" onclick="showVPNGateDialog()">VPN Gate</button>
        </div>
        <div id="outbound-list" class="list muted">正在加载出站...</div>
      </section>
      <section id="routing" class="card panel">
        <h2 class="section-title">路由规则</h2>
        <p class="muted" style="margin-bottom:16px">按域名、入站、协议将流量分配到指定出站。规则按顺序匹配，命中的规则立即生效。</p>
        <div class="actions">
          <button onclick="openCreateRoutingRule()">新建规则</button>
        </div>
        <div id="routing-rule-list" class="list muted">正在加载路由规则...</div>
        <div class="notice" style="margin-top:16px">
          <div class="notice-title">提示</div>
          <div class="notice-copy">启用规则后系统会自动重写 Xray 配置文件并重启服务。可用的域名格式包括 <code>google.com</code>（精确域名）、<code>geosite:netflix</code>（地理位置组）、<code>regex:.*\.youtube\.com$</code>（正则）。</div>
        </div>
      </section>
      <section id="xray" class="card panel">
        <h2 class="section-title">Xray 管理</h2>
        <p class="muted" style="margin-bottom:16px">查看 Xray 服务状态，应用配置变更。</p>
        <div class="xray-status-panel">
          <div><strong>状态</strong>：<span id="xray-status">未知</span></div>
          <div><strong>版本</strong>：<span id="xray-version">-</span></div>
          <div><strong>托管</strong>：<span id="xray-managed">-</span></div>
          <div><strong>服务</strong>：<span id="xray-service">xray</span></div>
        </div>
        <div id="xray-unsupported-warning" class="xray-warning muted" style="display:none;margin-top:12px;padding:12px 16px;border-radius:var(--radius-md);background:var(--surface-warning);color:var(--fg)">当前 Xray 版本不支持 Hysteria2 协议，需要使用 sing-box 等后端配合。</div>
        <div id="vpngate-auto-health-card" class="muted" style="display:none;margin-top:12px;padding:12px 16px;border-radius:var(--radius-md);background:var(--surface-subtle)">
          <span><strong>VPN Gate 自动检测</strong></span>
          <span id="vpngate-auto-health-status" style="margin-left:8px">检查中...</span>
          <button class="icon-btn" onclick="refreshAutoHealthStatus()" title="刷新" style="margin-left:8px;font-size:11px;float:right">⟳</button>
        </div>
        <div class="action-toolbar xray-toolbar">
          <div class="toolbar-copy">
            <strong>配置操作</strong>
            <span>应用、预览与刷新统一集中在右侧操作区。</span>
          </div>
          <div class="toolbar-actions">
            <button onclick="fetchXrayStatus()">刷新状态</button>
            <button class="secondary" onclick="installXrayCore()">安装核心</button>
            <button class="danger" onclick="uninstallXrayCore()">卸载核心</button>
            <button class="secondary" onclick="previewXrayConfig()">预览配置</button>
            <button class="secondary" onclick="applyXrayConfig()">应用配置</button>
            <button class="secondary" onclick="loadXrayLogs()">查看日志</button>
          </div>
        </div>
        <div id="xray-result" class="notice-slot"></div>
        <div id="xray-config-preview" class="list muted" style="margin-top:12px;display:none"><div class="xray-preview-header"><span class="muted" style="font-weight:600">Xray 配置预览</span><button class="icon-btn" onclick="closeXrayConfig()" title="关闭" style="font-size:12px">✕</button></div><pre id="xray-config-json" class="xray-preview-pre"></pre></div>
        <div id="xray-logs-preview" class="list muted" style="margin-top:12px;display:none"><div class="xray-preview-header"><span class="muted" style="font-weight:600">Xray 运行日志</span><button class="icon-btn" onclick="closeXrayLogs()" title="关闭" style="font-size:12px">✕</button></div><pre id="xray-logs-text" class="xray-preview-pre mono"></pre></div>
      </section>
      <section id="singbox" class="card panel">
        <h2 class="section-title">Sing-box 管理</h2>
        <p class="muted" style="margin-bottom:16px">查看 Sing-box 服务状态，管理 Hysteria2 / TUIC / ShadowTLS 等协议配置。</p>
        <div class="xray-status-panel">
          <div><strong>状态</strong>：<span id="singbox-status">未知</span></div>
          <div><strong>版本</strong>：<span id="singbox-version">-</span></div>
          <div><strong>内存</strong>：<span id="singbox-memory">-</span></div>
          <div><strong>运行时长</strong>：<span id="singbox-uptime">-</span></div>
          <div><strong>活跃连接</strong>：<span id="singbox-connections">-</span></div>
          <div><strong>托管服务</strong>：<span id="singbox-managed">sing-box</span></div>
          <div><strong>配置路径</strong>：<span id="singbox-config-path">/etc/sing-box/config.json</span></div>
        </div>
        <div class="action-toolbar xray-toolbar">
          <div class="toolbar-copy">
            <strong>配置操作</strong>
            <span>应用、预览与刷新统一集中在右侧操作区。</span>
          </div>
          <div class="toolbar-actions">
            <button onclick="fetchSingboxStatus()">刷新状态</button>
            <button class="secondary" onclick="installSingboxCore()">安装核心</button>
            <button class="danger" onclick="uninstallSingboxCore()">卸载核心</button>
            <button class="secondary" onclick="previewSingboxConfig()">预览配置</button>
            <button class="secondary" onclick="applySingboxConfig()">应用配置</button>
            <button class="secondary" onclick="loadSingboxLogs()">查看日志</button>
          </div>
        </div>
        <div id="singbox-result" class="notice-slot"></div>
        <div id="singbox-config-preview" class="list muted" style="margin-top:12px;display:none"><div class="xray-preview-header"><span class="muted" style="font-weight:600">Sing-box 配置预览</span><button class="icon-btn" onclick="closeSingboxConfig()" title="关闭" style="font-size:12px">✕</button></div><pre id="singbox-config-json" class="xray-preview-pre"></pre></div>
        <div id="singbox-logs-preview" class="list muted" style="margin-top:12px;display:none"><div class="xray-preview-header"><span class="muted" style="font-weight:600">Sing-box 运行日志</span><button class="icon-btn" onclick="closeSingboxLogs()" title="关闭" style="font-size:12px">✕</button></div><pre id="singbox-logs-text" class="xray-preview-pre mono"></pre></div>
      </section>
      <section id="settings" class="card panel">
        <h2 class="section-title">面板设置</h2>
        <p class="muted" style="margin-bottom:16px">编辑 panel.json 配置。修改面板端口或认证后需重启服务生效。</p>
        <form id="settings-form" class="form-grid" onsubmit="return false">
          <div class="field-group">
            <label class="field-label" for="set-panel-port">面板端口</label>
            <input id="set-panel-port" type="number" min="1" max="65535" placeholder="例如 9999" required>
            <p class="field-help">保存后需要重启 MiGate 服务才会切换监听端口。</p>
          </div>
          <div class="field-group">
            <label class="field-label" for="set-username">登录用户名</label>
            <input id="set-username" placeholder="admin">
            <p class="field-help">与密码同时配置时启用面板认证。</p>
          </div>
          <div class="field-group">
            <label class="field-label" for="set-password">登录密码</label>
            <input id="set-password" type="password" placeholder="留空不修改">
            <p class="field-help">留空会保留现有密码，不会清空配置。</p>
          </div>
          <div class="field-group">
            <label class="field-label" for="set-xray-config-path">Xray 配置目录</label>
            <input id="set-xray-config-path" placeholder="例如 /usr/local/migate">
            <p class="field-help">MiGate 会在该目录写入 xray.json。</p>
          </div>
          <div class="field-group span-2" style="border:1px solid var(--border);border-radius:8px;padding:12px;background:var(--surface-subtle)">
            <label class="field-label" style="margin-top:0">MiGate 服务状态</label>
            <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
              <div>
                <span id="svc-status-badge" style="display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:12px;font-size:13px;background:var(--surface-subtle)">检查中...</span>
                <span id="svc-status-detail" class="muted" style="margin-left:12px;font-size:13px"></span>
              </div>
              <button type="button" class="secondary" onclick="fetchServiceStatus()" style="font-size:12px">刷新状态</button>
            </div>
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="set-web-path">Web 基础路径</label>
            <input id="set-web-path" placeholder="例如 /">
            <p class="field-help">默认使用根路径；反代到子路径时再修改。</p>
          </div>
          <div class="field-group span-2" style="margin-top:var(--space-4);padding-top:var(--space-4);border-top:1px solid var(--line)">
            <h3 style="margin-bottom:var(--space-3);font-size:var(--text-md)">TLS 证书（Let's Encrypt）</h3>
            <p class="field-help">配置域名后可通过 acme.sh 自动获取 Let's Encrypt 证书，证书文件保存在面板配置目录下。</p>
          </div>
          <div class="field-group">
            <label class="field-label" for="set-cert-domain">域名</label>
            <input id="set-cert-domain" placeholder="例如 example.com">
          </div>
          <div class="field-group">
            <label class="field-label" for="set-cert-email">邮箱</label>
            <input id="set-cert-email" placeholder="admin@example.com">
          </div>
          <div class="field-group span-2" id="cert-status-area" style="display:none">
            <div class="cert-status-box" style="padding:var(--space-3) var(--space-4);border-radius:var(--radius-md);background:var(--surface-subtle);margin-bottom:var(--space-3)">
              <div><strong>证书状态</strong>：<span id="cert-status-label">未获取</span></div>
              <div id="cert-path-label" class="muted" style="font-size:var(--text-sm);margin-top:var(--space-1)"></div>
            </div>
            <button type="button" class="secondary" id="btn-issue-cert" onclick="issueCert()">获取证书</button>
          </div>
          <div class="action-toolbar settings-toolbar span-2">
            <div class="toolbar-copy">
              <strong>设置操作</strong>
              <span>保存配置后按需重启 MiGate 服务。</span>
            </div>
            <div class="toolbar-actions">
              <button type="button" class="secondary" onclick="loadSettings()">刷新</button>
              <button type="submit" onclick="saveSettings()">保存设置</button>
              <button type="button" class="danger" onclick="restartService()">重启服务</button>
            </div>
          </div>
        </form>
        <div id="settings-status" class="notice-slot"></div>
      </section>
    <!-- Create outbound dialog -->
    <div id="create-outbound-dialog" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeModal()">
      <div class="modal-content" style="max-width:480px">
        <div class="modal-header">
          <h3 class="modal-title">新建出站</h3>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <form id="create-outbound-form" class="form-grid modal-form" onsubmit="return false">
          <div class="field-group span-2">
            <label class="field-label" for="co-tag">出站标识</label>
            <input id="co-tag" placeholder="例如 my-socks-proxy" required>
            <p class="field-help">唯一标识，用于 Xray 路由规则中的 tag 引用。</p>
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="co-remark">备注</label>
            <input id="co-remark" placeholder="可选，留空使用标识">
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="co-protocol">协议</label>
            <select id="co-protocol">
              <option value="socks">SOCKS5</option>
              <option value="http">HTTP</option>
            </select>
          </div>
          <div class="field-group" id="co-address-row">
            <label class="field-label" for="co-address">地址</label>
            <input id="co-address" placeholder="IP 或域名">
          </div>
          <div class="field-group" id="co-port-row">
            <label class="field-label" for="co-port">端口</label>
            <input id="co-port" type="number" min="1" max="65535" placeholder="1080">
          </div>
          <div class="field-group span-2" id="co-cred-row">
            <label class="field-label">认证</label>
            <div style="display:flex;gap:8px">
              <input id="co-username" placeholder="用户名（可选）" style="flex:1">
              <input id="co-password" type="password" placeholder="密码（可选）" style="flex:1">
            </div>
          </div>
        </form>
        <div class="modal-footer">
          <button class="secondary" onclick="closeModal()">取消</button>
          <button onclick="submitCreateOutbound()" class="btn-modal-primary">创建</button>
        </div>
      </div>
    </div>

    <!-- Edit outbound dialog -->
    <div id="edit-outbound-dialog" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeModal()">
      <div class="modal-content" style="max-width:480px">
        <div class="modal-header">
          <h3 class="modal-title">编辑出站</h3>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <form id="edit-outbound-form" class="form-grid modal-form" onsubmit="return false">
          <input type="hidden" id="eo-id">
          <div class="field-group span-2">
            <label class="field-label" for="eo-tag">出站标识</label>
            <input id="eo-tag" placeholder="例如 my-socks-proxy" required>
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="eo-remark">备注</label>
            <input id="eo-remark" placeholder="可选，留空使用标识">
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="eo-protocol">协议</label>
            <select id="eo-protocol">
              <option value="socks">SOCKS5</option>
              <option value="http">HTTP</option>
            </select>
          </div>
          <div class="field-group" id="eo-address-row">
            <label class="field-label" for="eo-address">地址</label>
            <input id="eo-address" placeholder="IP 或域名">
          </div>
          <div class="field-group" id="eo-port-row">
            <label class="field-label" for="eo-port">端口</label>
            <input id="eo-port" type="number" min="1" max="65535" placeholder="1080">
          </div>
          <div class="field-group span-2" id="eo-cred-row">
            <label class="field-label">认证</label>
            <div style="display:flex;gap:8px">
              <input id="eo-username" placeholder="用户名（可选）" style="flex:1">
              <input id="eo-password" type="password" placeholder="密码（可选）" style="flex:1">
            </div>
          </div>
          <div class="field-group span-2">
            <label class="modal-checkbox">
              <input type="checkbox" id="eo-enabled" checked>
              已启用
            </label>
          </div>
        </form>
        <div class="modal-footer">
          <button class="secondary" onclick="closeModal()">取消</button>
          <button onclick="submitEditOutbound()" class="btn-modal-primary">保存</button>
        </div>
      </div>
    </div>
    <!-- Create routing rule dialog -->
    <div id="create-routing-rule-dialog" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeModal()">
      <div class="modal-content" style="max-width:480px">
        <div class="modal-header">
          <h3 class="modal-title">新建路由规则</h3>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <form id="create-routing-rule-form" class="form-grid modal-form" onsubmit="return false">
          <div class="field-group span-2">
            <label class="field-label" for="crr-outbound">目标出站 *</label>
            <select id="crr-outbound" required>
              <option value="">-- 选择出站 --</option>
            </select>
            <p class="field-help">匹配此条件时转发到哪个出站。</p>
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="crr-domain">域名匹配</label>
            <input id="crr-domain" placeholder="例如 geosite:netflix 或 google.com">
            <p class="field-help">留空表示匹配所有域名。支持 geosite: 和 regex: 前缀。</p>
          </div>
          <div class="field-group">
            <label class="field-label" for="crr-inbound">来源入站</label>
            <select id="crr-inbound">
              <option value="">留空 = 所有入站</option>
            </select>
          </div>
          <div class="field-group">
            <label class="field-label" for="crr-protocol">协议匹配</label>
            <input id="crr-protocol" placeholder="例如 dns, bittorrent">
          </div>
          <div class="field-group span-2">
            <label class="modal-checkbox">
              <input type="checkbox" id="crr-enabled" checked>
              已启用
            </label>
          </div>
        </form>
        <div class="modal-footer">
          <button class="secondary" onclick="closeModal()">取消</button>
          <button onclick="submitCreateRoutingRule()" class="btn-modal-primary">创建</button>
        </div>
      </div>
    </div>
    <!-- Edit routing rule dialog -->
    <div id="edit-routing-rule-dialog" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeModal()">
      <div class="modal-content" style="max-width:480px">
        <div class="modal-header">
          <h3 class="modal-title">编辑路由规则</h3>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <form id="edit-routing-rule-form" class="form-grid modal-form" onsubmit="return false">
          <div class="field-group span-2">
            <label class="field-label" for="err-outbound">目标出站 *</label>
            <select id="err-outbound" required>
              <option value="">-- 选择出站 --</option>
            </select>
            <p class="field-help">匹配此条件时转发到哪个出站。</p>
          </div>
          <div class="field-group span-2">
            <label class="field-label" for="err-domain">域名匹配</label>
            <input id="err-domain" placeholder="例如 geosite:netflix 或 google.com">
            <p class="field-help">留空表示匹配所有域名。</p>
          </div>
          <div class="field-group">
            <label class="field-label" for="err-inbound">来源入站</label>
            <select id="err-inbound">
              <option value="">留空 = 所有入站</option>
            </select>
          </div>
          <div class="field-group">
            <label class="field-label" for="err-protocol">协议匹配</label>
            <input id="err-protocol" placeholder="例如 dns, bittorrent">
          </div>
          <div class="field-group span-2">
            <label class="modal-checkbox">
              <input type="checkbox" id="err-enabled" checked>
              已启用
            </label>
          </div>
          <input type="hidden" id="err-id">
        </form>
        <div class="modal-footer">
          <button class="secondary" onclick="closeModal()">取消</button>
          <button onclick="submitEditRoutingRule()" class="btn-modal-primary">保存</button>
        </div>
      </div>
    </div>

    <!-- VPN Gate dialog -->
    <div id="vpngate-dialog" class="modal-overlay" style="display:none" onclick="if(event.target===this)closeModal()">
      <div class="modal-content" style="max-width:800px;max-height:80vh;overflow:hidden;display:flex;flex-direction:column">
        <div class="modal-header">
          <h3 class="modal-title">VPN Gate 公共服务器</h3>
          <button class="modal-close" onclick="closeModal()">✕</button>
        </div>
        <div style="flex:1;overflow-y:auto;padding:12px 16px">
          <div id="vpngate-loading" style="text-align:center;padding:40px;color:var(--muted)">
            <p style="font-size:18px;margin-bottom:8px">正在获取服务器列表...</p>
            <p>从 VPN Gate API 获取全球公共代理服务器</p>
          </div>
          <div id="vpngate-error" style="display:none;text-align:center;padding:40px">
            <p style="color:var(--danger);font-size:16px;margin-bottom:8px">获取失败</p>
            <p id="vpngate-error-msg" class="muted" style="margin-bottom:16px"></p>
            <button class="secondary" onclick="showVPNGateDialog()">重试</button>
          </div>
          <div id="vpngate-list" style="display:none">
            <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <span id="vpngate-count" class="muted"></span>
              <input id="vpngate-filter" type="text" placeholder="搜索国家/IP/运营商..." style="flex:1;min-width:180px;max-width:260px" oninput="renderVPNGateList()">
              <select id="vpngate-type-filter" style="width:110px" onchange="renderVPNGateList()">
                <option value="all">全部类型</option>
                <option value="家宽">家宽</option>
                <option value="商宽">商宽</option>
              </select>
              <input id="vpngate-country-filter" type="text" placeholder="国家 JP/US" style="width:110px" oninput="renderVPNGateList()">
              <input id="vpngate-max-ping" type="number" min="1" placeholder="延迟≤ms" style="width:110px" oninput="renderVPNGateList()">
              <select id="vpngate-topn" style="width:90px">
                <option value="5">Top 5</option>
                <option value="10" selected>Top 10</option>
                <option value="20">Top 20</option>
              </select>
              <button class="secondary" onclick="refreshVPNGateServers()">重新拉取</button>
              <button class="secondary" onclick="smartSelectVPNGate()">智能选择参考</button>
              <button class="secondary" id="vpngate-import-btn" onclick="importSelectedVPNGate()" title="仅创建受管出口配置，暂未启动 VPN runtime">创建 SoftEther 出口占位</button>
            </div>
            <div class="notice" style="margin-bottom:12px;background:var(--surface-warning);color:var(--fg)">
              <div class="notice-title">VPN Gate 官方列表不是 SOCKS5 代理源</div>
              <div class="notice-copy">官方节点通常开放 HTTPS/SoftEther/OpenVPN 等 VPN 端口；MiGate 将它们作为 SoftEther 出口候选信息展示；当前创建按钮只生成受管出口占位配置，不会把官方列表当作 SOCKS5 代理源。</div>
            </div>
            <div class="notice" style="margin-bottom:12px;background:var(--surface-subtle);color:var(--fg)">
              <div class="notice-title">下一步路线：SoftEther + 隔离网络命名空间 + SOCKS 桥接</div>
              <div class="notice-copy">当前按钮仅创建受管 vpngate_softether 出口配置，暂未启动 VPN runtime；后续会将 VPN Gate SoftEther 会话放入隔离网络命名空间，并通过本地 SOCKS 桥接接入 Xray outbound。</div>
            </div>
            <table style="width:100%;border-collapse:collapse;font-size:13px">
              <thead>
                <tr style="background:var(--surface-subtle)">
                  <th style="padding:6px 8px;text-align:left"><input type="checkbox" id="vpngate-select-all" onchange="toggleAllVPNGate()"></th>
                  <th style="padding:6px 8px;text-align:left">国家</th>
                  <th style="padding:6px 8px;text-align:left">IP</th>
                  <th style="padding:6px 8px;text-align:right">延迟</th>
                  <th style="padding:6px 8px;text-align:right">速度</th>
                  <th style="padding:6px 8px;text-align:left">类型</th>
                  <th style="padding:6px 8px;text-align:left">运营商</th>
                </tr>
              </thead>
              <tbody id="vpngate-tbody"></tbody>
            </table>
          </div>
        </div>
        <div class="modal-footer">
          <span class="muted" style="font-size:12px">参考列表/候选信息，来自 vpngate.net；创建出口只生成本地 SoftEther bridge 占位配置</span>
          <button class="secondary" onclick="closeModal()">关闭</button>
        </div>
      </div>
    </div>
    </main>
  </div>
  <script src="static/app.js"></script>
</html>`
