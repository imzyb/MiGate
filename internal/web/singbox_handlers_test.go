package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/lockfile"
	"github.com/imzyb/MiGate/internal/paths"
	"github.com/imzyb/MiGate/internal/singbox"
)

func TestValidateSingboxUnsupportedStatsWarnsWithoutFailing(t *testing.T) {
	store := &countingSummaryStore{
		inbounds: []db.Inbound{{
			ID: 1, Protocol: "hysteria2", Enabled: true,
			Clients: []db.Client{{ID: 2, StatsKey: "c_hy2", Email: "hy2@example.com", Enabled: true}},
		}},
	}
	cfg := &routerConfig{
		store: store,
		singboxRuntime: fixedSingboxRuntime{capability: singbox.Capability{
			Checked: true, Unsupported: true, Message: singbox.StatsUnsupportedMessage,
		}},
	}

	result := validateSingboxConfig(context.Background(), cfg)
	if !result.Valid {
		t.Fatalf("unsupported stats should not fail validation: %+v", result)
	}
	if !containsString(result.Warnings, "singbox_stats_unsupported") {
		t.Fatalf("expected unsupported warning, got %+v", result.Warnings)
	}
}

func TestBuildSingboxConfigUnsupportedStatsOmitsV2RayAPI(t *testing.T) {
	inbounds := []db.Inbound{{
		ID: 1, Protocol: "hysteria2", Port: 21001, Enabled: true,
		Clients: []db.Client{{ID: 2, UUID: "pass", StatsKey: "c_hy2", Email: "hy2@example.com", Enabled: true}},
	}}
	cfg := &routerConfig{
		singboxRuntime: fixedSingboxRuntime{capability: singbox.Capability{
			Checked: true, Unsupported: true, Message: singbox.StatsUnsupportedMessage,
		}},
	}

	built := buildSingboxConfigForRuntime(context.Background(), cfg, inbounds, nil, nil)
	raw, err := json.Marshal(built.config)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if strings.Contains(string(raw), "v2ray_api") {
		t.Fatalf("unsupported stats config must not include v2ray_api: %s", raw)
	}
	if !containsString(built.warnings, "singbox_stats_unsupported") {
		t.Fatalf("expected unsupported warning, got %+v", built.warnings)
	}
}

func TestBuildSingboxConfigCapabilityFailureDoesNotWarnUnsupported(t *testing.T) {
	inbounds := []db.Inbound{{
		ID: 1, Protocol: "hysteria2", Port: 21001, Enabled: true,
		Clients: []db.Client{{ID: 2, UUID: "pass", StatsKey: "c_hy2", Email: "hy2@example.com", Enabled: true}},
	}}
	cfg := &routerConfig{
		singboxRuntime: fixedSingboxRuntime{capability: singbox.Capability{
			Checked: true, Message: "sing-box check permission denied",
		}},
	}

	built := buildSingboxConfigForRuntime(context.Background(), cfg, inbounds, nil, nil)
	if containsString(built.warnings, "singbox_stats_unsupported") {
		t.Fatalf("capability check failure must not be reported as unsupported: %+v", built.warnings)
	}
	if !containsString(built.warnings, "singbox_stats_capability_check_failed") {
		t.Fatalf("expected capability failure warning, got %+v", built.warnings)
	}
}

func TestBuildSingboxConfigSkipsCapabilityWhenNoSingboxInbound(t *testing.T) {
	var calls int32
	cfg := &routerConfig{
		singboxRuntime: countingSingboxRuntime{calls: &calls},
	}

	built := buildSingboxConfigForRuntime(context.Background(), cfg, []db.Inbound{{ID: 1, Protocol: "vless", Enabled: true}}, nil, nil)
	if len(built.warnings) != 0 {
		t.Fatalf("expected no warnings without singbox inbound, got %+v", built.warnings)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected capability detection to be skipped, got %d calls", got)
	}
}

func TestBuildSingboxConfigForRuntimeReadsManagementDirectConfigDir(t *testing.T) {
	configDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(configDir, "panel.json"), []byte(`{"panel_port":9999,"database_path":"/var/lib/migate/migate.db","management_direct_hosts":["103.193.149.217"],"management_direct_ports":[22]}`), 0o600); err != nil {
		t.Fatalf("write panel config: %v", err)
	}
	built := buildSingboxConfigForRuntime(context.Background(), &routerConfig{configDir: configDir}, nil, nil, nil)
	if built.err != nil {
		t.Fatalf("build sing-box config: %v", built.err)
	}
	if built.config.Route == nil || len(built.config.Route.Rules) == 0 {
		t.Fatalf("expected management direct route from panel config, got %+v", built.config.Route)
	}
	rule := built.config.Route.Rules[0]
	if rule.Outbound != singbox.SystemDirectOutboundTag || len(rule.IPCIDR) != 1 || rule.IPCIDR[0] != "103.193.149.217/32" {
		t.Fatalf("unexpected management direct rule: %+v", rule)
	}
}

func TestTryApplySingboxBestEffortMissingBinaryIsNotApplied(t *testing.T) {
	origBinary := singbox.DefaultBinaryPath
	singbox.DefaultBinaryPath = t.TempDir() + "/missing-sing-box"
	defer func() { singbox.DefaultBinaryPath = origBinary }()

	result := tryApplySingboxWithRuntime(context.Background(), &countingSummaryStore{}, fixedSingboxRuntime{}, false)
	if result.Applied {
		t.Fatalf("missing sing-box binary must not be reported as applied: %+v", result)
	}
	if result.Error != "" {
		t.Fatalf("best-effort missing binary should not be a hard error: %+v", result)
	}
	if result.Detail != "singbox_not_installed" || !containsString(result.Warnings, "singbox_not_installed") {
		t.Fatalf("expected missing binary warning, got %+v", result)
	}
}

func TestSingboxApplyUsesApplyLock(t *testing.T) {
	origApplyLock := paths.ApplyLock
	paths.ApplyLock = filepath.Join(t.TempDir(), "apply.lock")
	t.Cleanup(func() { paths.ApplyLock = origApplyLock })
	unlock, err := lockfile.TryAcquire(paths.ApplyLock)
	if err != nil {
		t.Fatalf("acquire apply lock: %v", err)
	}
	defer unlock()
	origBinary := singbox.DefaultBinaryPath
	singbox.DefaultBinaryPath = filepath.Join(t.TempDir(), "sing-box")
	t.Cleanup(func() { singbox.DefaultBinaryPath = origBinary })
	if err := os.WriteFile(singbox.DefaultBinaryPath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	router := NewRouter(WithStore(&countingSummaryStore{}), WithSingboxApplier(func(ctx context.Context, store Store, runtime SingboxRuntime, strict bool) SingboxApplySummary {
		return SingboxApplySummary{Applied: true}
	}))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/singbox/apply", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusConflict {
		t.Fatalf("expected apply lock conflict, got %d: %s", response.Code, response.Body.String())
	}
	var payload ErrorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if payload.Error.Code != "apply_locked" {
		t.Fatalf("expected apply_locked error code, got %q", payload.Error.Code)
	}
}

func TestSingboxStatusUsesInjectedProbe(t *testing.T) {
	router := NewRouter(WithSingboxProbe(fakeSingboxProbe{
		installed:    true,
		managed:      true,
		service:      "sing-box",
		status:       "failed",
		configExists: true,
		checkErr:     errors.New("bad config"),
		version:      "sing-box probe-version",
		memoryRSS:    12345,
		uptime:       "2h",
		connections:  7,
	}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/singbox/status", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var data map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if data["installed"] != true || data["status"] != "stopped" || data["normalized_status"] != "stopped" || data["raw_status"] != "failed" {
		t.Fatalf("status response did not use injected probe: %+v", data)
	}
	if data["version"] != "sing-box probe-version" {
		t.Fatalf("version response did not use injected probe: %+v", data)
	}
	if data["config_exists"] != true || data["config_valid"] != false || data["config_error"] != "bad config" {
		t.Fatalf("config response did not use injected probe: %+v", data)
	}
	if data["memory_rss_bytes"] != float64(12345) || data["uptime"] != "2h" || data["active_connections"] != float64(7) {
		t.Fatalf("runtime metrics response did not use injected probe: %+v", data)
	}
}

func TestSingboxDiagnosticsNotInstalled(t *testing.T) {
	restore := useTempSingboxConfigPath(t, "")
	defer restore()
	cfg := &routerConfig{
		store:        &countingSummaryStore{},
		singboxProbe: fakeSingboxProbe{installed: false, managed: false, service: "sing-box"},
	}

	result := buildSingboxDiagnostics(context.Background(), cfg)
	if result.Installed || result.ServiceStatus != "not_installed" {
		t.Fatalf("expected not installed diagnostics, got %+v", result)
	}
	if !containsString(result.Warnings, "singbox_not_installed") {
		t.Fatalf("expected not installed warning, got %+v", result.Warnings)
	}
}

func TestSingboxDiagnosticsNotManaged(t *testing.T) {
	restore := useTempSingboxConfigPath(t, `{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}`)
	defer restore()
	cfg := &routerConfig{
		store:        &countingSummaryStore{},
		singboxProbe: fakeSingboxProbe{installed: true, managed: false, service: "sing-box", configExists: true, configValid: true, version: "sing-box 1.13.13"},
	}

	result := buildSingboxDiagnostics(context.Background(), cfg)
	if result.ServiceStatus != "not_managed" || result.Managed {
		t.Fatalf("expected not managed diagnostics, got %+v", result)
	}
	if !containsString(result.Warnings, "singbox_not_systemd_managed") {
		t.Fatalf("expected not managed warning, got %+v", result.Warnings)
	}
}

func TestSingboxDiagnosticsMissingConfig(t *testing.T) {
	restore := useTempSingboxConfigPath(t, "")
	defer restore()
	cfg := &routerConfig{
		store:        &countingSummaryStore{},
		singboxProbe: fakeSingboxProbe{installed: true, managed: true, service: "sing-box", status: "running", configExists: false, version: "sing-box 1.13.13"},
	}

	result := buildSingboxDiagnostics(context.Background(), cfg)
	if result.ConfigExists || result.ConfigValid {
		t.Fatalf("expected missing config diagnostics, got %+v", result)
	}
	if !containsString(result.Warnings, "singbox_config_missing") || result.SyncReason != "disk_missing" {
		t.Fatalf("expected config missing warning and disk_missing reason, got warnings=%+v reason=%s", result.Warnings, result.SyncReason)
	}
}

func TestSingboxDiagnosticsCheckFailed(t *testing.T) {
	restore := useTempSingboxConfigPath(t, `{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}`)
	defer restore()
	cfg := &routerConfig{
		store:        &countingSummaryStore{},
		singboxProbe: fakeSingboxProbe{installed: true, managed: true, service: "sing-box", status: "running", configExists: true, checkErr: errors.New("parse config: bad field"), version: "sing-box 1.13.13"},
	}

	result := buildSingboxDiagnostics(context.Background(), cfg)
	if result.ConfigValid || !strings.Contains(result.ConfigError, "bad field") {
		t.Fatalf("expected check failure diagnostics, got %+v", result)
	}
	if !containsString(result.Warnings, "singbox_config_invalid") {
		t.Fatalf("expected config invalid warning, got %+v", result.Warnings)
	}
}

func TestSingboxDiagnosticsKeepsCompatibleServiceStatusWithRawStatus(t *testing.T) {
	restore := useTempSingboxConfigPath(t, `{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}`)
	defer restore()
	cfg := &routerConfig{
		store:        &countingSummaryStore{},
		singboxProbe: fakeSingboxProbe{installed: true, managed: true, service: "sing-box", status: "failed", configExists: true, configValid: true, version: "sing-box 1.13.13"},
	}

	result := buildSingboxDiagnostics(context.Background(), cfg)
	if result.ServiceStatus != "stopped" || result.RawServiceStatus != "failed" {
		t.Fatalf("expected compatible stopped status with raw failed state, got %+v", result)
	}
	if !containsString(result.Warnings, "singbox_service_not_running") {
		t.Fatalf("expected service not running warning, got %+v", result.Warnings)
	}
}

func TestSingboxDiagnosticsConfigOutOfSync(t *testing.T) {
	restore := useTempSingboxConfigPath(t, `{"log":{"level":"debug"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}`)
	defer restore()
	cfg := &routerConfig{
		store:        &countingSummaryStore{},
		singboxProbe: fakeSingboxProbe{installed: true, managed: true, service: "sing-box", status: "running", configExists: true, configValid: true, version: "sing-box 1.13.13"},
	}

	result := buildSingboxDiagnostics(context.Background(), cfg)
	if result.DiskGeneratedInSync || result.SyncReason != "hash_mismatch" {
		t.Fatalf("expected hash mismatch diagnostics, got %+v", result)
	}
	if !containsString(result.Warnings, "singbox_config_out_of_sync") {
		t.Fatalf("expected out of sync warning, got %+v", result.Warnings)
	}
}

func TestSingboxDiagnosticsRunningWithMissingListener(t *testing.T) {
	restore := useTempSingboxConfigPath(t, `{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}`)
	defer restore()
	cfg := &routerConfig{
		store: &countingSummaryStore{inbounds: []db.Inbound{{
			ID: 1, Protocol: "hysteria2", Port: 21000, Enabled: true,
			Clients: []db.Client{{ID: 2, Password: "secret", Enabled: true}},
		}}},
		singboxRuntime: fixedSingboxRuntime{capability: singbox.Capability{V2RayAPIStats: true, Checked: true}},
		singboxProbe:   fakeSingboxProbe{installed: true, managed: true, service: "sing-box", status: "running", configExists: true, configValid: true, version: "sing-box 1.13.13"},
		singboxListeners: func(ctx context.Context, cfg *routerConfig) []SingboxListenerDiagnostic {
			return []SingboxListenerDiagnostic{{InboundID: 1, Protocol: "hysteria2", Port: 21000, Transport: "udp", Listening: false}}
		},
	}

	result := buildSingboxDiagnostics(context.Background(), cfg)
	if len(result.MissingListeners) != 1 || result.MissingListeners[0].Port != 21000 {
		t.Fatalf("expected missing listener diagnostics, got %+v", result.MissingListeners)
	}
	if !containsString(result.Warnings, "singbox_missing_listeners") {
		t.Fatalf("expected missing listeners warning, got %+v", result.Warnings)
	}
}

func TestCreateSingboxInboundAppliedWithMissingListenerWarning(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := NewRouter(
		WithStore(store),
		WithSingboxApplier(func(ctx context.Context, store Store, runtime SingboxRuntime, strict bool) SingboxApplySummary {
			return SingboxApplySummary{Applied: true, Service: "sing-box", ConfigPath: "/etc/migate/cores/sing-box.json", CommandsExecuted: []string{"sing-box check"}}
		}),
		WithSingboxListenerDiagnostics(func(ctx context.Context) []SingboxListenerDiagnostic {
			return []SingboxListenerDiagnostic{{InboundID: 1, Protocol: "hysteria2", Port: 21000, Transport: "udp", Listening: false}}
		}),
	)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", strings.NewReader(`{"remark":"hy2","protocol":"hysteria2","port":21000,"network":"udp","security":"tls"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "配置已应用，但端口未监听：21000/udp") {
		t.Fatalf("expected missing listener warning in response: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "post_apply_warnings") {
		t.Fatalf("expected post_apply_warnings in response: %s", response.Body.String())
	}
}

func TestPostApplyDiagnosticsRetriesListenerBeforeWarning(t *testing.T) {
	origAttempts := singboxPostApplyListenerAttempts
	origDelay := singboxPostApplyListenerDelay
	singboxPostApplyListenerAttempts = 3
	singboxPostApplyListenerDelay = time.Millisecond
	defer func() {
		singboxPostApplyListenerAttempts = origAttempts
		singboxPostApplyListenerDelay = origDelay
	}()

	var calls int32
	cfg := &routerConfig{
		singboxListeners: func(ctx context.Context, cfg *routerConfig) []SingboxListenerDiagnostic {
			listening := atomic.AddInt32(&calls, 1) >= 2
			return []SingboxListenerDiagnostic{{InboundID: 1, Protocol: "hysteria2", Port: 21000, Transport: "udp", Listening: listening}}
		},
	}
	result := addSingboxPostApplyDiagnostics(context.Background(), cfg, SingboxApplySummary{Applied: true})

	if len(result.PostApplyWarnings) != 0 || len(result.Warnings) != 0 {
		t.Fatalf("expected retry to avoid listener warning, got %+v", result)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected two listener checks, got %d", got)
	}
}

func TestPostApplyDiagnosticsWarnsAfterRetriesStillMissing(t *testing.T) {
	origAttempts := singboxPostApplyListenerAttempts
	origDelay := singboxPostApplyListenerDelay
	singboxPostApplyListenerAttempts = 3
	singboxPostApplyListenerDelay = time.Millisecond
	defer func() {
		singboxPostApplyListenerAttempts = origAttempts
		singboxPostApplyListenerDelay = origDelay
	}()

	var calls int32
	cfg := &routerConfig{
		singboxListeners: func(ctx context.Context, cfg *routerConfig) []SingboxListenerDiagnostic {
			atomic.AddInt32(&calls, 1)
			return []SingboxListenerDiagnostic{{InboundID: 1, Protocol: "hysteria2", Port: 21000, Transport: "udp", Listening: false}}
		},
	}
	result := addSingboxPostApplyDiagnostics(context.Background(), cfg, SingboxApplySummary{Applied: true})

	want := "配置已应用，但端口未监听：21000/udp"
	if !containsString(result.PostApplyWarnings, want) || !containsString(result.Warnings, want) {
		t.Fatalf("expected post-apply listener warning, got %+v", result)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected three listener checks, got %d", got)
	}
}

func TestNonFatalApplyWarningsAreNotApplyFailures(t *testing.T) {
	result := newSingboxApplySummary()
	result.Applied = true
	addSingboxApplyWarnings(&result, "singbox_stats_unsupported", "singbox_stats_capability_check_failed")

	if !result.Applied || result.Error != "" {
		t.Fatalf("non-fatal warnings must not mark apply failed: %+v", result)
	}
	if !containsString(result.NonFatalWarnings, "singbox_stats_unsupported") || !containsString(result.NonFatalWarnings, "singbox_stats_capability_check_failed") {
		t.Fatalf("expected non-fatal warning classification, got %+v", result)
	}
}

type countingSingboxRuntime struct {
	calls *int32
}

func (r countingSingboxRuntime) Capability(ctx context.Context) singbox.Capability {
	atomic.AddInt32(r.calls, 1)
	return singbox.Capability{V2RayAPIStats: true, Checked: true}
}

type fakeSingboxProbe struct {
	installed    bool
	version      string
	managed      bool
	service      string
	status       string
	configExists bool
	configValid  bool
	checkErr     error
	memoryRSS    int64
	uptime       string
	connections  int
	logs         []string
}

func (p fakeSingboxProbe) IsInstalled() bool { return p.installed }
func (p fakeSingboxProbe) Version() (string, error) {
	if p.version == "" {
		return "sing-box 1.13.13", nil
	}
	return p.version, nil
}
func (p fakeSingboxProbe) Management() singbox.ManagementStatus {
	service := p.service
	if service == "" {
		service = "sing-box"
	}
	return singbox.ManagementStatus{Managed: p.managed, Service: service}
}
func (p fakeSingboxProbe) Status() string {
	if p.status == "" {
		return "stopped"
	}
	return p.status
}
func (p fakeSingboxProbe) ConfigExists(path string) bool { return p.configExists }
func (p fakeSingboxProbe) CheckConfig(path string) error {
	if p.checkErr != nil {
		return p.checkErr
	}
	if p.configValid {
		return nil
	}
	return errors.New("invalid")
}
func (p fakeSingboxProbe) MemoryRSS() int64       { return p.memoryRSS }
func (p fakeSingboxProbe) Uptime() string         { return p.uptime }
func (p fakeSingboxProbe) ActiveConnections() int { return p.connections }
func (p fakeSingboxProbe) RecentLogs(service string, lines int) []string {
	if len(p.logs) <= lines {
		return p.logs
	}
	return p.logs[len(p.logs)-lines:]
}

func useTempSingboxConfigPath(t *testing.T, content string) func() {
	t.Helper()
	orig := singbox.DefaultConfigPath
	path := t.TempDir() + "/config.json"
	if content != "" {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("write temp singbox config: %v", err)
		}
	}
	singbox.DefaultConfigPath = path
	return func() {
		singbox.DefaultConfigPath = orig
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
