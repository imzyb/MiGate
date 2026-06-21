package web

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/lockfile"
	"github.com/imzyb/MiGate/internal/paths"
	runtimecmd "github.com/imzyb/MiGate/internal/runtime/command"
	"github.com/imzyb/MiGate/internal/singbox"
)

var errSingboxNotInstalled = errors.New("singbox_not_installed")

type SingboxApplySummary struct {
	Applied           bool     `json:"applied"`
	Service           string   `json:"service"`
	ConfigPath        string   `json:"config_path"`
	CommandsExecuted  []string `json:"commands_executed"`
	Error             string   `json:"error,omitempty"`
	Detail            string   `json:"detail,omitempty"`
	Warnings          []string `json:"warnings,omitempty"`
	PostApplyWarnings []string `json:"post_apply_warnings,omitempty"`
	NonFatalWarnings  []string `json:"non_fatal_warnings,omitempty"`
	Inbounds          int      `json:"inbounds,omitempty"`
	Outbounds         int      `json:"outbounds,omitempty"`
	Rules             int      `json:"rules,omitempty"`
}

type SingboxListenerDiagnostic = CoreListenerDiagnostic

type SingboxDiagnostics struct {
	Installed           bool                     `json:"installed"`
	Version             string                   `json:"version"`
	Managed             bool                     `json:"managed"`
	Service             string                   `json:"service"`
	ServiceStatus       string                   `json:"service_status"`
	RawServiceStatus    string                   `json:"raw_service_status,omitempty"`
	ConfigPath          string                   `json:"config_path"`
	ConfigExists        bool                     `json:"config_exists"`
	ConfigValid         bool                     `json:"config_valid"`
	ConfigError         string                   `json:"config_error,omitempty"`
	DiskGeneratedInSync bool                     `json:"disk_generated_in_sync"`
	SyncReason          string                   `json:"sync_reason,omitempty"`
	ExpectedListeners   []CoreListenerDiagnostic `json:"expected_listeners"`
	MissingListeners    []CoreListenerDiagnostic `json:"missing_listeners"`
	RecentLogs          []string                 `json:"recent_logs"`
	Warnings            []string                 `json:"warnings"`
	Suggestions         []string                 `json:"suggestions"`
	Actions             []CoreDiagnosticAction   `json:"actions,omitempty"`
	SuggestionDetails   []CoreDiagnosticAction   `json:"suggestion_details,omitempty"`
}

type singboxDiskConfigPreview struct {
	ConfigPath string      `json:"config_path"`
	Hash       string      `json:"hash"`
	Config     interface{} `json:"config,omitempty"`
	Error      string      `json:"error,omitempty"`
	Detail     string      `json:"detail,omitempty"`
}

type singboxGeneratedConfigPreview struct {
	ConfigPath string      `json:"config_path"`
	Hash       string      `json:"hash"`
	Config     interface{} `json:"config,omitempty"`
	Error      string      `json:"error,omitempty"`
	Detail     string      `json:"detail,omitempty"`
	Warnings   []string    `json:"warnings,omitempty"`
	Inbounds   int         `json:"inbounds"`
	Outbounds  int         `json:"outbounds"`
	Rules      int         `json:"rules"`
}

type singboxConfigSyncPreview struct {
	ConfigPath string                        `json:"config_path"`
	InSync     bool                          `json:"in_sync"`
	Reason     string                        `json:"reason,omitempty"`
	Disk       singboxDiskConfigPreview      `json:"disk"`
	Generated  singboxGeneratedConfigPreview `json:"generated"`
}

type SingboxProbe interface {
	IsInstalled() bool
	Version() (string, error)
	Management() singbox.ManagementStatus
	Status() string
	ConfigExists(path string) bool
	CheckConfig(path string) error
	MemoryRSS() int64
	Uptime() string
	ActiveConnections() int
	RecentLogs(service string, lines int) []string
}

type defaultSingboxProbe struct{}

func (defaultSingboxProbe) IsInstalled() bool                    { return singbox.IsInstalled() }
func (defaultSingboxProbe) Version() (string, error)             { return singbox.Version() }
func (defaultSingboxProbe) Management() singbox.ManagementStatus { return singbox.Management() }
func (defaultSingboxProbe) Status() string                       { return singbox.Status() }
func (defaultSingboxProbe) ConfigExists(path string) bool {
	return singbox.CheckConfigFile(path).OK()
}
func (defaultSingboxProbe) CheckConfig(path string) error { return singbox.CheckConfigPath(path) }
func (defaultSingboxProbe) MemoryRSS() int64              { return singbox.MemoryRSS() }
func (defaultSingboxProbe) Uptime() string                { return singbox.Uptime() }
func (defaultSingboxProbe) ActiveConnections() int        { return singbox.ActiveConnections() }
func (defaultSingboxProbe) RecentLogs(service string, lines int) []string {
	if lines < 1 {
		lines = 20
	}
	if lines > maxSingboxDiagnosticLogLines {
		lines = maxSingboxDiagnosticLogLines
	}
	out, err := runtimecmd.RunOutput(context.Background(), "journalctl", "-u", service, "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso")
	if err != nil {
		return []string{}
	}
	return trimLogLines(string(out), lines)
}

const maxSingboxDiagnosticLogLines = 40

var (
	singboxPostApplyListenerAttempts = 3
	singboxPostApplyListenerDelay    = 400 * time.Millisecond
)

func singboxStatusHandler(cfg ...*routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		cfg := firstRouterConfig(cfg)
		probe := singboxProbeForConfig(cfg)
		installed := probe.IsInstalled()
		if !installed {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"core":              "sing-box",
				"installed":         false,
				"status":            "not_installed",
				"service_status":    "not_installed",
				"managed":           false,
				"service":           singbox.ServiceName(),
				"binary_path":       singbox.DefaultBinaryPath,
				"binary_version":    "",
				"config_path":       singbox.DefaultConfigPath,
				"config_exists":     false,
				"config_valid":      false,
				"commands_executed": []string{},
			})
			return
		}
		management := probe.Management()
		rawStatus := strings.TrimSpace(probe.Status())
		status := normalizeCoreServiceStatus(rawStatus)
		ver, _ := probe.Version()
		ports := singboxExpectedListeningPorts(r.Context(), cfg)
		configExists := false
		configValid := false
		configError := ""
		if probe.ConfigExists(singbox.DefaultConfigPath) {
			configExists = true
			if err := probe.CheckConfig(singbox.DefaultConfigPath); err != nil {
				configError = err.Error()
			} else {
				configValid = true
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"core":               "sing-box",
			"installed":          true,
			"managed":            management.Managed,
			"service":            management.Service,
			"status":             status,
			"service_status":     status,
			"raw_status":         rawStatus,
			"normalized_status":  status,
			"version":            strings.TrimSpace(ver),
			"binary_path":        singbox.DefaultBinaryPath,
			"binary_version":     strings.TrimSpace(ver),
			"config_exists":      configExists,
			"config_valid":       configValid,
			"config_error":       configError,
			"memory_rss_bytes":   probe.MemoryRSS(),
			"uptime":             probe.Uptime(),
			"active_connections": probe.ActiveConnections(),
			"config_path":        singbox.DefaultConfigPath,
			"commands_executed":  []string{},
			"listening_ports":    ports,
		})
	}
}

func normalizeCoreServiceStatus(status string) string {
	switch strings.TrimSpace(status) {
	case "active", "running":
		return "running"
	case "activating", "deactivating", "inactive", "failed", "stopped":
		return "stopped"
	case "not_installed", "not_managed":
		return strings.TrimSpace(status)
	default:
		return strings.TrimSpace(status)
	}
}

func firstRouterConfig(cfg []*routerConfig) *routerConfig {
	if len(cfg) == 0 {
		return nil
	}
	return cfg[0]
}

func singboxExpectedListeningPorts(ctx context.Context, cfg *routerConfig) []CoreListenerDiagnostic {
	if cfg == nil || cfg.store == nil {
		return []CoreListenerDiagnostic{}
	}
	inbounds, err := cfg.store.ListInbounds(ctx)
	if err != nil {
		return []CoreListenerDiagnostic{}
	}
	expected := []int{}
	records := []db.Inbound{}
	for _, inbound := range inbounds {
		if !inbound.Enabled || db.InboundCore(inbound) != db.CoreSingbox {
			continue
		}
		switch db.NormalizeInboundProtocol(inbound.Protocol) {
		case "hysteria2", "tuic", "shadowtls":
			if inbound.Port > 0 {
				expected = append(expected, inbound.Port)
				records = append(records, inbound)
			}
		}
	}
	udpListening := singbox.ListeningUDPPorts(expected)
	result := make([]CoreListenerDiagnostic, 0, len(records))
	for _, inbound := range records {
		network := "tcp"
		listening := false
		switch db.NormalizeInboundProtocol(inbound.Protocol) {
		case "hysteria2", "tuic":
			network = "udp"
			listening = udpListening[inbound.Port]
		case "shadowtls":
			network = "tcp"
			listening = isTCPPortListening(inbound.Port)
		}
		result = append(result, CoreListenerDiagnostic{
			InboundID: inbound.ID,
			Protocol:  inbound.Protocol,
			Port:      inbound.Port,
			Network:   network,
			Transport: network,
			Listening: listening,
		})
	}
	return result
}

func isTCPPortListening(port int) bool {
	if port <= 0 {
		return false
	}
	for _, command := range []struct {
		name string
		args []string
	}{
		{name: "ss", args: []string{"-H", "-ltn"}},
		{name: "netstat", args: []string{"-ltn"}},
	} {
		out, err := runtimecmd.RunOutput(context.Background(), command.name, command.args...)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			for _, field := range fields {
				if portFromAddress(field) == port {
					return true
				}
			}
		}
	}
	return false
}

func portFromAddress(address string) int {
	address = strings.TrimSpace(address)
	if address == "" {
		return 0
	}
	if idx := strings.LastIndex(address, ":"); idx >= 0 && idx < len(address)-1 {
		port, _ := strconv.Atoi(strings.Trim(address[idx+1:], "[]"))
		return port
	}
	return 0
}

// singboxApplyHandler reads sing-box supported inbounds from the store, builds
// a sing-box config, generates a self-signed cert if missing, validates a temp
// config, atomically installs it, and restarts the sing-box service.
func singboxApplyHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if _, ok := decodeCoreActionPayload(w, r); !ok {
			return
		}

		if !singbox.IsInstalled() {
			writeJSONError(w, http.StatusBadRequest, "singbox_not_installed")
			return
		}

		if cfg == nil || cfg.store == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "store_unavailable")
			return
		}
		unlock, err := lockfile.TryAcquire(paths.ApplyLock)
		if err != nil {
			writeJSONError(w, http.StatusConflict, "apply_locked", map[string]interface{}{"detail": err.Error(), "lock_path": paths.ApplyLock})
			return
		}
		defer unlock()

		// Read sing-box inbounds
		inbounds, err := cfg.store.ListInbounds(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "list_failed", map[string]interface{}{"detail": err.Error()})
			return
		}

		outbounds, err := cfg.store.ListOutbounds(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "list_outbounds_failed", map[string]interface{}{"detail": err.Error()})
			return
		}
		rules, err := cfg.store.ListRoutingRules(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "list_routing_rules_failed", map[string]interface{}{"detail": err.Error()})
			return
		}

		// Build config
		built := buildSingboxConfigForRuntime(r.Context(), cfg, inbounds, outbounds, rules)
		if built.err != nil {
			writeJSONError(w, http.StatusBadRequest, "build_failed", map[string]interface{}{"detail": built.err.Error()})
			return
		}

		// Ensure self-signed cert exists
		if _, err := os.Stat(singbox.CertFile); os.IsNotExist(err) {
			if err := singbox.GenerateSelfSignedCert(); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "cert_failed", map[string]interface{}{"detail": err.Error()})
				return
			}
		}

		result := addSingboxPostApplyDiagnostics(r.Context(), cfg, applyBuiltSingboxConfig(built))
		if !result.Applied {
			writeJSON(w, http.StatusInternalServerError, result)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func singboxValidateHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		result := validateSingboxConfig(r.Context(), cfg)
		writeJSON(w, http.StatusOK, result)
	}
}

func singboxDiagnosticsHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		writeJSON(w, http.StatusOK, buildSingboxDiagnostics(r.Context(), cfg))
	}
}

func buildSingboxDiagnostics(ctx context.Context, cfg *routerConfig) SingboxDiagnostics {
	probe := singboxProbeForConfig(cfg)
	result := SingboxDiagnostics{
		Service:             singbox.ServiceName(),
		ServiceStatus:       "not_installed",
		ConfigPath:          singbox.DefaultConfigPath,
		ConfigValid:         false,
		DiskGeneratedInSync: false,
		ExpectedListeners:   []CoreListenerDiagnostic{},
		MissingListeners:    []CoreListenerDiagnostic{},
		RecentLogs:          []string{},
		Warnings:            []string{},
		Suggestions:         []string{},
	}

	result.Installed = probe.IsInstalled()
	management := probe.Management()
	result.Managed = management.Managed
	result.Service = management.Service
	result.ConfigExists = probe.ConfigExists(singbox.DefaultConfigPath)
	if result.Installed {
		if version, err := probe.Version(); err == nil {
			result.Version = strings.TrimSpace(version)
		}
		if !result.Managed {
			result.ServiceStatus = "not_managed"
		} else {
			result.RawServiceStatus = strings.TrimSpace(probe.Status())
			result.ServiceStatus = normalizeCoreServiceStatus(result.RawServiceStatus)
		}
	} else {
		result.ServiceStatus = "not_installed"
	}
	if result.Managed {
		result.RecentLogs = probe.RecentLogs(result.Service, maxSingboxDiagnosticLogLines)
	}
	if result.Installed && result.ConfigExists {
		if err := probe.CheckConfig(singbox.DefaultConfigPath); err != nil {
			result.ConfigError = err.Error()
		} else {
			result.ConfigValid = true
		}
	}

	if cfg != nil && cfg.store != nil {
		preview := buildSingboxConfigSyncPreview(ctx, cfg)
		result.DiskGeneratedInSync = preview.InSync
		result.SyncReason = preview.Reason
		result.ExpectedListeners = singboxListenerDiagnosticsForConfig(ctx, cfg)
		for _, listener := range result.ExpectedListeners {
			if !listener.Listening {
				result.MissingListeners = append(result.MissingListeners, listener)
			}
		}
		addSingboxDataDiagnostics(ctx, cfg, &result)
	} else {
		result.SyncReason = "store_unavailable"
		addUniqueString(&result.Warnings, "store_unavailable")
		addUniqueString(&result.Suggestions, "检查数据库连接后刷新诊断。")
	}

	if !result.Installed {
		addUniqueString(&result.Warnings, "singbox_not_installed")
		addUniqueString(&result.Suggestions, "安装 sing-box 后，点击应用重新写入 sing-box 配置。")
	}
	if result.Installed && !result.Managed {
		addUniqueString(&result.Warnings, "singbox_not_systemd_managed")
		addUniqueString(&result.Suggestions, "运行 systemctl status "+singbox.ServiceName()+" 确认服务是否由 systemd 托管。")
	}
	if result.Installed && result.Managed && result.ServiceStatus != "running" {
		addUniqueString(&result.Warnings, "singbox_service_not_running")
		addUniqueString(&result.Suggestions, "运行 systemctl status "+result.Service+" && journalctl -u "+result.Service+" -n 80 --no-pager。")
	}
	if !result.ConfigExists {
		addUniqueString(&result.Warnings, "singbox_config_missing")
		addUniqueString(&result.Suggestions, "点击应用重新写入 sing-box 配置。")
	}
	if result.ConfigExists && !result.ConfigValid {
		addUniqueString(&result.Warnings, "singbox_config_invalid")
		addUniqueString(&result.Suggestions, "运行 sing-box check -c "+result.ConfigPath+"，按报错修复后重新应用。")
	}
	if result.SyncReason != "" && result.SyncReason != "store_unavailable" {
		addUniqueString(&result.Warnings, "singbox_config_out_of_sync")
		addUniqueString(&result.Suggestions, "点击应用重新写入 sing-box 配置。")
	}
	if result.ServiceStatus == "running" && len(result.MissingListeners) > 0 {
		addUniqueString(&result.Warnings, "singbox_missing_listeners")
		for _, listener := range result.MissingListeners {
			network := listenerNetwork(listener)
			addUniqueString(&result.Suggestions, fmt.Sprintf("检查安全组/防火墙是否放行 %s 端口 %d。", strings.ToUpper(network), listener.Port))
		}
		addUniqueString(&result.Suggestions, "运行 systemctl status "+result.Service+" && journalctl -u "+result.Service+" -n 80 --no-pager。")
	}
	return result
}

func singboxProbeForConfig(cfg *routerConfig) SingboxProbe {
	if cfg != nil && cfg.singboxProbe != nil {
		return cfg.singboxProbe
	}
	return defaultSingboxProbe{}
}

func singboxListenerDiagnosticsForConfig(ctx context.Context, cfg *routerConfig) []CoreListenerDiagnostic {
	if cfg != nil && cfg.singboxListeners != nil {
		return cfg.singboxListeners(ctx, cfg)
	}
	return singboxExpectedListeningPorts(ctx, cfg)
}

func addSingboxDataDiagnostics(ctx context.Context, cfg *routerConfig, result *SingboxDiagnostics) {
	inbounds, err := cfg.store.ListInbounds(ctx)
	if err != nil {
		addUniqueString(&result.Warnings, "list_inbounds_failed")
		addUniqueString(&result.Suggestions, "读取入站失败："+err.Error())
		return
	}
	outbounds, err := cfg.store.ListOutbounds(ctx)
	if err != nil {
		addUniqueString(&result.Warnings, "list_outbounds_failed")
		addUniqueString(&result.Suggestions, "读取出站失败："+err.Error())
		return
	}
	rules, err := cfg.store.ListRoutingRules(ctx)
	if err != nil {
		addUniqueString(&result.Warnings, "list_routing_rules_failed")
		addUniqueString(&result.Suggestions, "读取路由规则失败："+err.Error())
		return
	}

	hasSingboxInbound := false
	for _, inbound := range inbounds {
		if !inbound.Enabled || db.InboundCore(inbound) != db.CoreSingbox {
			continue
		}
		hasSingboxInbound = true
		enabledClients := enabledSingboxClients(inbound.Clients)
		if len(enabledClients) == 0 {
			addUniqueString(&result.Warnings, "singbox_inbound_without_enabled_clients")
			addUniqueString(&result.Suggestions, "为入站创建或启用至少一个客户端。")
		}
		protocol := db.NormalizeInboundProtocol(inbound.Protocol)
		if protocol == "hysteria2" || protocol == "tuic" {
			for _, client := range enabledClients {
				if err := db.ValidateClientCredential(protocol, client); err != nil {
					addUniqueString(&result.Warnings, "singbox_client_credentials_missing")
					addUniqueString(&result.Suggestions, fmt.Sprintf("检查入站 %d 的 %s 客户端凭据并重新保存。", inbound.ID, protocol))
					break
				}
			}
		}
		if protocol == "shadowtls" && strings.TrimSpace(inbound.TLSSNI) == "" {
			addUniqueString(&result.Warnings, "shadowtls_handshake_missing")
			addUniqueString(&result.Suggestions, fmt.Sprintf("为 ShadowTLS 入站 %d 设置握手服务器/SNI。", inbound.ID))
		}
	}

	for _, rule := range rules {
		if !rule.Enabled || !db.RoutingRuleAppliesToCore(rule, inbounds, db.CoreSingbox) {
			continue
		}
		outbound, ok := db.ResolveRuleOutbound(rule, outbounds)
		if !ok || !outbound.Enabled || !db.OutboundSupportsCore(outbound, db.CoreSingbox) {
			addUniqueString(&result.Warnings, "singbox_route_outbound_unavailable")
			addUniqueString(&result.Suggestions, fmt.Sprintf("将路由规则 %d 的出站改为支持 sing-box 且已启用的出站。", rule.ID))
		}
	}

	built := buildSingboxConfigForRuntime(ctx, cfg, inbounds, outbounds, rules)
	for _, warning := range built.warnings {
		addUniqueString(&result.Warnings, warning)
		if warning == "singbox_stats_unsupported" && hasSingboxInbound {
			addUniqueString(&result.Suggestions, "当前 sing-box 会跳过实时统计；如需统计请安装支持 v2ray_api 的构建。")
		}
		if warning == "singbox_stats_capability_check_failed" && hasSingboxInbound {
			addUniqueString(&result.Suggestions, "手动运行 sing-box check -c "+result.ConfigPath+" 确认二进制能力。")
		}
	}
	if built.err != nil {
		addUniqueString(&result.Warnings, "singbox_generated_config_build_failed")
		addUniqueString(&result.Suggestions, "修复数据库中的 sing-box 入站、出站或路由配置后重新应用。")
	}
}

func enabledSingboxClients(clients []db.Client) []db.Client {
	result := []db.Client{}
	for _, client := range clients {
		if client.Enabled {
			result = append(result, client)
		}
	}
	return result
}

func trimLogLines(logs string, maxLines int) []string {
	lines := []string{}
	for _, line := range strings.Split(logs, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines = append(lines, line)
	}
	if maxLines > 0 && len(lines) > maxLines {
		return lines[len(lines)-maxLines:]
	}
	return lines
}

func addUniqueString(values *[]string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	for _, existing := range *values {
		if existing == value {
			return
		}
	}
	*values = append(*values, value)
}

func validateSingboxConfig(ctx context.Context, cfg *routerConfig) configValidationResult {
	result := configValidationResult{Target: "singbox", Valid: true, Warnings: []string{}}
	if cfg == nil || cfg.store == nil {
		result.Valid = false
		result.Error = "store_unavailable"
		return result
	}
	inbounds, err := cfg.store.ListInbounds(ctx)
	if err != nil {
		result.Valid = false
		result.Error = "list_inbounds_failed"
		return result
	}
	outbounds, err := cfg.store.ListOutbounds(ctx)
	if err != nil {
		result.Valid = false
		result.Error = "list_outbounds_failed"
		return result
	}
	rules, err := cfg.store.ListRoutingRules(ctx)
	if err != nil {
		result.Valid = false
		result.Error = "list_routing_rules_failed"
		return result
	}
	return validateSingboxConfigSnapshotWithRuntime(ctx, validationSnapshot{inbounds: inbounds, outbounds: outbounds, rules: rules}, cfg)
}

func validateSingboxConfigSnapshotWithOptions(snapshot validationSnapshot, opts singbox.BuildOptions) configValidationResult {
	result := configValidationResult{Target: "singbox", Valid: true, Warnings: []string{}}
	cfg, err := singbox.BuildConfigWithOutboundsOptions(snapshot.inbounds, snapshot.outbounds, snapshot.rules, opts)
	if err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}
	result.Inbounds = len(cfg.Inbounds)
	if result.Inbounds == 0 {
		result.Warnings = append(result.Warnings, "no_enabled_singbox_inbounds")
	}
	if _, err := json.Marshal(cfg); err != nil {
		result.Valid = false
		result.Error = err.Error()
	}
	return result
}

func validateSingboxConfigSnapshotWithRuntime(ctx context.Context, snapshot validationSnapshot, runtimeCfg *routerConfig) configValidationResult {
	result := configValidationResult{Target: "singbox", Valid: true, Warnings: []string{}}
	inbounds := snapshot.inbounds
	built := buildSingboxConfigForRuntime(ctx, runtimeCfg, inbounds, snapshot.outbounds, snapshot.rules)
	result.Inbounds = len(built.config.Inbounds)
	result.Outbounds = len(built.config.Outbounds)
	if built.config.Route != nil {
		result.Rules = len(built.config.Route.Rules)
	}
	if result.Inbounds == 0 {
		result.Warnings = append(result.Warnings, "no_enabled_singbox_inbounds")
	}
	result.Warnings = append(result.Warnings, built.warnings...)
	if built.err != nil {
		result.Valid = false
		result.Error = built.err.Error()
		return result
	}
	if _, err := json.Marshal(built.config); err != nil {
		result.Valid = false
		result.Error = err.Error()
	}
	return result
}

func newSingboxApplySummary() SingboxApplySummary {
	service := singbox.ServiceName()
	return SingboxApplySummary{
		Applied:           false,
		Service:           service,
		ConfigPath:        singbox.DefaultConfigPath,
		CommandsExecuted:  []string{"sing-box check -c <temp>", "systemctl restart " + service},
		Warnings:          []string{},
		PostApplyWarnings: []string{},
		NonFatalWarnings:  []string{},
	}
}

func applyBuiltSingboxConfig(built builtSingboxConfig) SingboxApplySummary {
	result := newSingboxApplySummary()
	addSingboxApplyWarnings(&result, built.warnings...)
	result.Inbounds = len(built.config.Inbounds)
	result.Outbounds = len(built.config.Outbounds)
	if built.config.Route != nil {
		result.Rules = len(built.config.Route.Rules)
	}
	if built.err != nil {
		result.Error = "build_failed"
		result.Detail = built.err.Error()
		return result
	}
	raw, err := json.MarshalIndent(built.config, "", "  ")
	if err != nil {
		result.Error = "marshal_failed"
		result.Detail = err.Error()
		return result
	}
	if err := singbox.ApplyConfig(raw); err != nil {
		result.Error = "singbox_apply_failed"
		result.Detail = err.Error()
		return result
	}
	result.Applied = true
	return result
}

func applySingboxSummary(ctx context.Context, cfg *routerConfig, store Store, strict bool) SingboxApplySummary {
	if cfg != nil && cfg.singboxApplier != nil && cfg.singboxApplierSet {
		return cfg.singboxApplier(ctx, store, cfg.singboxRuntime, strict)
	}
	return tryApplySingboxWithRouterConfig(ctx, cfg, store, strict)
}

func attachSingboxResult(payload map[string]interface{}, summary SingboxApplySummary) map[string]interface{} {
	payload["singbox"] = summary
	payload["applied"] = summary.Applied
	if len(summary.Warnings) > 0 {
		payload["warnings"] = summary.Warnings
	}
	if len(summary.PostApplyWarnings) > 0 {
		payload["post_apply_warnings"] = summary.PostApplyWarnings
	}
	if len(summary.NonFatalWarnings) > 0 {
		payload["non_fatal_warnings"] = summary.NonFatalWarnings
	}
	if !summary.Applied {
		payload["error"] = summary.Error
		payload["detail"] = summary.Detail
	}
	return payload
}

func addSingboxPostApplyDiagnostics(ctx context.Context, cfg *routerConfig, summary SingboxApplySummary) SingboxApplySummary {
	if cfg == nil || !summary.Applied {
		return summary
	}
	for _, listener := range retrySingboxListenerDiagnostics(ctx, cfg, singboxPostApplyListenerAttempts, singboxPostApplyListenerDelay) {
		if listener.Listening {
			continue
		}
		addPostApplyWarning(&summary, fmt.Sprintf("配置已应用，但端口未监听：%d/%s", listener.Port, listenerNetwork(listener)))
	}
	return summary
}

func retrySingboxListenerDiagnostics(ctx context.Context, cfg *routerConfig, attempts int, delay time.Duration) []CoreListenerDiagnostic {
	if attempts < 1 {
		attempts = 1
	}
	var last []CoreListenerDiagnostic
	for attempt := 0; attempt < attempts; attempt++ {
		last = singboxListenerDiagnosticsForConfig(ctx, cfg)
		if allListenersReady(last) || attempt == attempts-1 || delay <= 0 {
			return last
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return last
		case <-timer.C:
		}
	}
	return last
}

func allListenersReady(listeners []CoreListenerDiagnostic) bool {
	for _, listener := range listeners {
		if !listener.Listening {
			return false
		}
	}
	return true
}

func listenerNetwork(listener CoreListenerDiagnostic) string {
	network := listener.Transport
	if network == "" {
		network = listener.Network
	}
	if network == "" {
		network = "tcp"
	}
	return strings.ToLower(network)
}

func addSingboxApplyWarnings(summary *SingboxApplySummary, warnings ...string) {
	for _, warning := range warnings {
		addUniqueString(&summary.Warnings, warning)
		if isNonFatalSingboxWarning(warning) {
			addUniqueString(&summary.NonFatalWarnings, warning)
		}
	}
}

func addPostApplyWarning(summary *SingboxApplySummary, warning string) {
	addUniqueString(&summary.PostApplyWarnings, warning)
	addUniqueString(&summary.Warnings, warning)
}

func isNonFatalSingboxWarning(warning string) bool {
	return warning == "singbox_stats_unsupported" || warning == "singbox_stats_capability_check_failed"
}

type builtSingboxConfig struct {
	config   singbox.Config
	warnings []string
	err      error
}

func buildSingboxConfigForRuntime(ctx context.Context, cfg *routerConfig, inbounds []db.Inbound, outbounds []db.Outbound, rules []db.RoutingRule) builtSingboxConfig {
	opts := singboxOptionsForRouterConfig(cfg)
	hasSingboxInbound := singbox.HasEnabledSingboxInbound(inbounds)
	if !hasSingboxInbound {
		built, err := singbox.BuildConfigWithOutboundsOptions(inbounds, outbounds, rules, opts)
		return builtSingboxConfig{config: built, err: err}
	}
	runtime := SingboxRuntime(defaultSingboxRuntime{})
	if cfg != nil && cfg.singboxRuntime != nil {
		runtime = cfg.singboxRuntime
	}
	capability := runtime.Capability(ctx)
	built, err := singbox.BuildConfigWithOutboundsOptions(inbounds, outbounds, rules, opts)
	result := builtSingboxConfig{
		config: built,
		err:    err,
	}
	if result.config.Experimental == nil && capability.V2RayAPIStats {
		result.config = singbox.BuildConfigWithOptions(inbounds, singbox.BuildOptions{EnableV2RayAPIStats: true})
		withOutbounds, buildErr := singbox.BuildConfigWithOutboundsOptions(inbounds, outbounds, rules, opts)
		if buildErr != nil {
			result.err = buildErr
		} else {
			withOutbounds.Experimental = result.config.Experimental
			result.config = withOutbounds
		}
	}
	if capability.Unsupported {
		result.warnings = append(result.warnings, "singbox_stats_unsupported")
	} else if !capability.V2RayAPIStats && strings.TrimSpace(capability.Message) != "" {
		result.warnings = append(result.warnings, "singbox_stats_capability_check_failed")
	}
	return result
}

// tryApplySingbox reads sing-box supported inbounds from the store, builds
// a sing-box config, validates a temp config, atomically installs it, and
// restarts sing-box. Errors are returned to the caller for UI/API visibility.
func tryApplySingbox(ctx context.Context, store Store) SingboxApplySummary {
	return tryApplySingboxWithRuntime(ctx, store, defaultSingboxRuntime{}, false)
}

func tryApplySingboxWithRuntime(ctx context.Context, store Store, runtime SingboxRuntime, strict bool) SingboxApplySummary {
	return tryApplySingboxWithRuntimeAndConfigDir(ctx, store, runtime, strict, "")
}

func tryApplySingboxWithRouterConfig(ctx context.Context, cfg *routerConfig, store Store, strict bool) SingboxApplySummary {
	runtime := SingboxRuntime(defaultSingboxRuntime{})
	configDir := ""
	if cfg != nil {
		if cfg.singboxRuntime != nil {
			runtime = cfg.singboxRuntime
		}
		configDir = cfg.configDir
	}
	return tryApplySingboxWithRuntimeAndConfigDir(ctx, store, runtime, strict, configDir)
}

func tryApplySingboxWithRuntimeAndConfigDir(ctx context.Context, store Store, runtime SingboxRuntime, strict bool, configDir string) SingboxApplySummary {
	result := newSingboxApplySummary()
	if !singbox.IsInstalled() {
		if strict {
			result.Error = errSingboxNotInstalled.Error()
			result.Detail = errSingboxNotInstalled.Error()
			return result
		}
		result.Detail = "singbox_not_installed"
		addSingboxApplyWarnings(&result, "singbox_not_installed")
		return result
	}
	if store == nil {
		result.Error = "store_unavailable"
		result.Detail = "store_unavailable"
		return result
	}
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		result.Error = "list_inbounds_failed"
		result.Detail = err.Error()
		return result
	}
	outbounds, err := store.ListOutbounds(ctx)
	if err != nil {
		result.Error = "list_outbounds_failed"
		result.Detail = err.Error()
		return result
	}
	rules, err := store.ListRoutingRules(ctx)
	if err != nil {
		result.Error = "list_routing_rules_failed"
		result.Detail = err.Error()
		return result
	}
	built := buildSingboxConfigForRuntime(ctx, &routerConfig{singboxRuntime: runtime, configDir: configDir}, inbounds, outbounds, rules)
	if _, err := os.Stat(singbox.CertFile); os.IsNotExist(err) {
		if err := singbox.GenerateSelfSignedCert(); err != nil {
			result.Error = "cert_failed"
			result.Detail = err.Error()
			return result
		}
	}
	return applyBuiltSingboxConfig(built)
}

// singboxConfigHandler returns the current sing-box config JSON.
func singboxConfigHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
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

func singboxConfigPreviewHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if cfg == nil || cfg.store == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "store_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, buildSingboxConfigSyncPreview(r.Context(), cfg))
	}
}

func buildSingboxConfigSyncPreview(ctx context.Context, cfg *routerConfig) singboxConfigSyncPreview {
	disk := readSingboxDiskConfigPreview()
	generated := buildSingboxGeneratedConfigPreview(ctx, cfg)
	reason := singboxConfigSyncReason(disk, generated)
	return singboxConfigSyncPreview{
		ConfigPath: singbox.DefaultConfigPath,
		InSync:     reason == "",
		Reason:     reason,
		Disk:       disk,
		Generated:  generated,
	}
}

func singboxConfigSyncReason(disk singboxDiskConfigPreview, generated singboxGeneratedConfigPreview) string {
	if disk.Error == "" && generated.Error == "" && disk.Hash == generated.Hash {
		return ""
	}
	if disk.Error == "read_failed" {
		return "disk_missing"
	}
	if disk.Error == "parse_failed" {
		return "disk_parse_failed"
	}
	if generated.Error != "" {
		return "generated_build_failed"
	}
	return "hash_mismatch"
}

func readSingboxDiskConfigPreview() singboxDiskConfigPreview {
	result := singboxDiskConfigPreview{ConfigPath: singbox.DefaultConfigPath}
	data, err := os.ReadFile(singbox.DefaultConfigPath)
	if err != nil {
		result.Error = "read_failed"
		result.Detail = err.Error()
		return result
	}
	normalized, parsed, err := normalizedJSON(data)
	if err != nil {
		result.Error = "parse_failed"
		result.Detail = err.Error()
		result.Hash = hashBytes(data)
		return result
	}
	result.Config = parsed
	result.Hash = hashBytes(normalized)
	return result
}

func buildSingboxGeneratedConfigPreview(ctx context.Context, cfg *routerConfig) singboxGeneratedConfigPreview {
	result := singboxGeneratedConfigPreview{ConfigPath: singbox.DefaultConfigPath, Warnings: []string{}}
	inbounds, err := cfg.store.ListInbounds(ctx)
	if err != nil {
		result.Error = "list_inbounds_failed"
		result.Detail = err.Error()
		return result
	}
	outbounds, err := cfg.store.ListOutbounds(ctx)
	if err != nil {
		result.Error = "list_outbounds_failed"
		result.Detail = err.Error()
		return result
	}
	rules, err := cfg.store.ListRoutingRules(ctx)
	if err != nil {
		result.Error = "list_routing_rules_failed"
		result.Detail = err.Error()
		return result
	}
	built := buildSingboxConfigForRuntime(ctx, cfg, inbounds, outbounds, rules)
	result.Warnings = built.warnings
	result.Inbounds = len(built.config.Inbounds)
	result.Outbounds = len(built.config.Outbounds)
	if built.config.Route != nil {
		result.Rules = len(built.config.Route.Rules)
	}
	if built.err != nil {
		result.Error = "build_failed"
		result.Detail = built.err.Error()
		return result
	}
	raw, err := json.Marshal(built.config)
	if err != nil {
		result.Error = "marshal_failed"
		result.Detail = err.Error()
		return result
	}
	normalized, parsed, err := normalizedJSON(raw)
	if err != nil {
		result.Error = "parse_failed"
		result.Detail = err.Error()
		return result
	}
	result.Config = parsed
	result.Hash = hashBytes(normalized)
	return result
}

func normalizedJSON(data []byte) ([]byte, interface{}, error) {
	var parsed interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, nil, err
	}
	normalized, err := json.Marshal(parsed)
	if err != nil {
		return nil, nil, err
	}
	return normalized, parsed, nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

// singboxVersionHandler returns the sing-box version.
func singboxVersionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if !singbox.IsInstalled() {
			writeJSON(w, http.StatusOK, map[string]interface{}{"version": "not_installed"})
			return
		}
		ver, err := singbox.Version()
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{"version": "unknown", "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"version": strings.TrimSpace(ver)})
	}
}

// singboxLogsHandler returns recent sing-box service logs from journalctl.
func singboxLogsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
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
		out, err := runtimecmd.RunOutput(context.Background(), "journalctl", "-u", singbox.ServiceName(), "-n", lines, "--no-pager", "-o", "short-iso")
		if err != nil {
			out, err = runtimecmd.RunOutput(context.Background(), "tail", "-n", lines, "/var/log/syslog")
			if err != nil {
				writeJSON(w, http.StatusOK, map[string]string{"logs": "无法读取 Sing-box 日志：journalctl 和 syslog 均不可用。"})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"logs": string(out)})
	}
}
