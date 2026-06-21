package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/imzyb/MiGate/internal/corefile"
	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/lockfile"
	"github.com/imzyb/MiGate/internal/paths"
	runtimecmd "github.com/imzyb/MiGate/internal/runtime/command"
	"github.com/imzyb/MiGate/internal/singbox"
	"github.com/imzyb/MiGate/internal/xray"
)

var (
	xrayPostApplyListenerAttempts = 3
	xrayPostApplyListenerDelay    = 400 * time.Millisecond
	xrayGrpcServiceNamePattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

func xrayConfigHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		if cfg == nil || cfg.store == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "store_unavailable")
			return
		}
		config, _, errCode, detail := buildXrayConfigFromRouter(r.Context(), cfg)
		if errCode != "" {
			writeJSONError(w, xrayConfigErrorStatus(errCode), errCode, map[string]interface{}{"detail": detail})
			return
		}
		if _, err := json.Marshal(config); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "marshal_failed", map[string]interface{}{"detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, config)
	}
}

func xrayConfigErrorStatus(code string) int {
	if code == "build_xray_config_failed" {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

type xrayConfigCounts struct {
	inbounds  int
	outbounds int
	rules     int
}

func buildXrayConfigFromStore(ctx context.Context, store Store) (xray.Config, xrayConfigCounts, string, string) {
	return buildXrayConfigFromStoreWithOptions(ctx, store, xray.BuildOptions{})
}

func buildXrayConfigFromRouter(ctx context.Context, cfg *routerConfig) (xray.Config, xrayConfigCounts, string, string) {
	if cfg == nil {
		return xray.Config{}, xrayConfigCounts{}, "store_unavailable", "store_unavailable"
	}
	return buildXrayConfigFromStoreWithOptions(ctx, cfg.store, xrayOptionsForRouterConfig(cfg))
}

func buildXrayConfigFromStoreWithOptions(ctx context.Context, store Store, opts xray.BuildOptions) (xray.Config, xrayConfigCounts, string, string) {
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		return xray.Config{}, xrayConfigCounts{}, "list_inbounds_failed", err.Error()
	}
	outbounds, err := store.ListOutbounds(ctx)
	if err != nil {
		return xray.Config{}, xrayConfigCounts{}, "list_outbounds_failed", err.Error()
	}
	rules, err := store.ListRoutingRules(ctx)
	if err != nil {
		return xray.Config{}, xrayConfigCounts{}, "list_routing_rules_failed", err.Error()
	}
	config, err := xray.BuildConfigWithOutboundsOptions(inbounds, outbounds, rules, opts)
	if err != nil {
		return xray.Config{}, xrayConfigCounts{}, "build_xray_config_failed", err.Error()
	}
	counts := xrayConfigCounts{inbounds: len(config.Inbounds), outbounds: len(config.Outbounds)}
	if config.Routing != nil {
		counts.rules = len(config.Routing.Rules)
	}
	return config, counts, "", ""
}

func xrayConfigPreviewHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		if cfg == nil || cfg.store == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "store_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, buildXrayConfigSyncPreview(r.Context(), cfg))
	}
}

type xrayDiskConfigPreview struct {
	ConfigPath string      `json:"config_path"`
	Hash       string      `json:"hash,omitempty"`
	Config     interface{} `json:"config,omitempty"`
	Error      string      `json:"error,omitempty"`
	Detail     string      `json:"detail,omitempty"`
}

type xrayGeneratedConfigPreview struct {
	ConfigPath string      `json:"config_path"`
	Hash       string      `json:"hash,omitempty"`
	Config     interface{} `json:"config,omitempty"`
	Error      string      `json:"error,omitempty"`
	Detail     string      `json:"detail,omitempty"`
	Warnings   []string    `json:"warnings,omitempty"`
	Inbounds   int         `json:"inbounds"`
	Outbounds  int         `json:"outbounds"`
	Rules      int         `json:"rules"`
}

type xrayConfigSyncPreview struct {
	ConfigPath string                     `json:"config_path"`
	InSync     bool                       `json:"in_sync"`
	Reason     string                     `json:"reason,omitempty"`
	Disk       xrayDiskConfigPreview      `json:"disk"`
	Generated  xrayGeneratedConfigPreview `json:"generated"`
}

func xrayConfigPath(cfg *routerConfig) string {
	if cfg != nil && strings.TrimSpace(cfg.xrayConfigPath) != "" {
		return cfg.xrayConfigPath
	}
	return paths.XrayConfig
}

func buildXrayConfigSyncPreview(ctx context.Context, cfg *routerConfig) xrayConfigSyncPreview {
	path := xrayConfigPath(cfg)
	disk := readXrayDiskConfigPreview(path)
	generated := buildXrayGeneratedConfigPreview(ctx, cfg, path)
	reason := xrayConfigSyncReason(disk, generated)
	return xrayConfigSyncPreview{
		ConfigPath: path,
		InSync:     reason == "",
		Reason:     reason,
		Disk:       disk,
		Generated:  generated,
	}
}

func xrayConfigSyncReason(disk xrayDiskConfigPreview, generated xrayGeneratedConfigPreview) string {
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

func readXrayDiskConfigPreview(path string) xrayDiskConfigPreview {
	result := xrayDiskConfigPreview{ConfigPath: path}
	data, err := os.ReadFile(path)
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

func buildXrayGeneratedConfigPreview(ctx context.Context, cfg *routerConfig, path string) xrayGeneratedConfigPreview {
	result := xrayGeneratedConfigPreview{ConfigPath: path, Warnings: []string{}}
	if cfg == nil || cfg.store == nil {
		result.Error = "store_unavailable"
		result.Detail = "store_unavailable"
		return result
	}
	config, counts, errCode, detail := buildXrayConfigFromRouter(ctx, cfg)
	result.Inbounds = counts.inbounds
	result.Outbounds = counts.outbounds
	result.Rules = counts.rules
	if errCode != "" {
		result.Error = errCode
		result.Detail = detail
		return result
	}
	raw, err := json.Marshal(config)
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

type XrayProbe interface {
	IsInstalled(ctx context.Context) bool
	Version(ctx context.Context) string
	Managed(ctx context.Context) bool
	Status(ctx context.Context) string
	ConfigExists(path string) bool
	CheckConfig(ctx context.Context, path string) error
	RecentLogs(ctx context.Context, service string, lines int) []string
}

type defaultXrayProbe struct {
	controller XrayController
	runCmd     CmdRunner
}

func (p defaultXrayProbe) IsInstalled(ctx context.Context) bool {
	return strings.TrimSpace(p.Version(ctx)) != ""
}

func (p defaultXrayProbe) Version(ctx context.Context) string {
	if p.controller != nil {
		return strings.TrimSpace(p.controller.Version(ctx))
	}
	out, err := p.command(ctx, paths.XrayBinary, "version")
	if err != nil {
		return ""
	}
	lines := strings.SplitN(strings.TrimSpace(out), "\n", 2)
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}

func (p defaultXrayProbe) Managed(ctx context.Context) bool {
	if p.controller != nil {
		return p.controller.Status(ctx).Managed
	}
	out, err := p.command(ctx, "systemctl", "show", paths.XrayService, "--property=LoadState")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "LoadState=loaded" {
			return true
		}
		if strings.HasPrefix(line, "LoadState=") {
			return false
		}
	}
	return false
}

func (p defaultXrayProbe) Status(ctx context.Context) string {
	if p.controller != nil {
		status := p.controller.Status(ctx).Status
		if status != "" {
			return status
		}
	}
	out, err := p.command(ctx, "systemctl", "is-active", paths.XrayService)
	if err != nil {
		return "stopped"
	}
	if strings.TrimSpace(out) == "active" {
		return "running"
	}
	return strings.TrimSpace(out)
}

func (p defaultXrayProbe) ConfigExists(path string) bool {
	return corefile.CheckPath(path, corefile.Requirement{Kind: corefile.KindFile, Readable: true}).OK()
}

func (p defaultXrayProbe) CheckConfig(ctx context.Context, path string) error {
	if status := corefile.CheckPath(path, corefile.Requirement{Kind: corefile.KindFile, Readable: true}); !status.OK() {
		return errors.New(status.Error())
	}
	out, err := p.command(ctx, paths.XrayBinary, "run", "-test", "-c", path)
	if err != nil {
		if strings.TrimSpace(out) != "" {
			return errors.New(strings.TrimSpace(out))
		}
		return err
	}
	return nil
}

func (p defaultXrayProbe) RecentLogs(ctx context.Context, service string, lines int) []string {
	if lines < 1 {
		lines = 20
	}
	if lines > maxSingboxDiagnosticLogLines {
		lines = maxSingboxDiagnosticLogLines
	}
	out, err := p.command(ctx, "journalctl", "-u", service, "-n", strconv.Itoa(lines), "--no-pager", "-o", "short-iso")
	if err != nil {
		return []string{}
	}
	return trimLogLines(out, lines)
}

func (p defaultXrayProbe) command(ctx context.Context, name string, args ...string) (string, error) {
	if p.runCmd != nil {
		return p.runCmd(name, args...)
	}
	out, err := runtimecmd.RunOutput(ctx, name, args...)
	return string(out), err
}

type XrayDiagnostics struct {
	Installed           bool                     `json:"installed"`
	Version             string                   `json:"version"`
	Managed             bool                     `json:"managed"`
	Service             string                   `json:"service"`
	ServiceStatus       string                   `json:"service_status"`
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

func xrayDiagnosticsHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		writeJSON(w, http.StatusOK, buildXrayDiagnostics(r.Context(), cfg))
	}
}

func buildXrayDiagnostics(ctx context.Context, cfg *routerConfig) XrayDiagnostics {
	probe := xrayProbeForConfig(cfg)
	path := xrayConfigPath(cfg)
	result := XrayDiagnostics{
		Service:             paths.XrayService,
		ServiceStatus:       "not_installed",
		ConfigPath:          path,
		ConfigValid:         false,
		DiskGeneratedInSync: false,
		ExpectedListeners:   []CoreListenerDiagnostic{},
		MissingListeners:    []CoreListenerDiagnostic{},
		RecentLogs:          []string{},
		Warnings:            []string{},
		Suggestions:         []string{},
		Actions:             []CoreDiagnosticAction{},
		SuggestionDetails:   []CoreDiagnosticAction{},
	}
	result.Installed = probe.IsInstalled(ctx)
	result.Managed = probe.Managed(ctx)
	result.ConfigExists = probe.ConfigExists(path)
	if result.Installed {
		result.Version = probe.Version(ctx)
		if !result.Managed {
			result.ServiceStatus = "not_managed"
		} else {
			result.ServiceStatus = probe.Status(ctx)
		}
	}
	if result.Managed {
		result.RecentLogs = probe.RecentLogs(ctx, result.Service, maxSingboxDiagnosticLogLines)
	}
	if result.Installed && result.ConfigExists {
		if err := probe.CheckConfig(ctx, path); err != nil {
			result.ConfigError = err.Error()
		} else {
			result.ConfigValid = true
		}
	}

	if cfg != nil && cfg.store != nil {
		preview := buildXrayConfigSyncPreview(ctx, cfg)
		result.DiskGeneratedInSync = preview.InSync
		result.SyncReason = preview.Reason
		result.ExpectedListeners = xrayListenerDiagnosticsForConfig(ctx, cfg)
		for _, listener := range result.ExpectedListeners {
			if !listener.Listening {
				result.MissingListeners = append(result.MissingListeners, listener)
			}
		}
		addXrayDataDiagnostics(ctx, cfg, &result)
	} else {
		result.SyncReason = "store_unavailable"
		addUniqueString(&result.Warnings, "store_unavailable")
		addUniqueString(&result.Suggestions, "检查数据库连接后刷新诊断。")
	}

	if !result.Installed {
		addUniqueString(&result.Warnings, "xray_not_installed")
		addXrayDiagnosticAction(&result, CoreDiagnosticAction{Code: "xray_not_installed", Severity: "error", Category: "service", Message: "安装 Xray 后，点击应用重新写入 Xray 配置。"})
	}
	if result.Installed && !result.Managed {
		addUniqueString(&result.Warnings, "xray_not_systemd_managed")
		addXrayDiagnosticAction(&result, CoreDiagnosticAction{Code: "xray_not_systemd_managed", Severity: "warning", Category: "service", Message: "确认 Xray 服务是否由 systemd 托管。", Command: "systemctl status " + paths.XrayService})
	}
	if result.Installed && result.Managed && result.ServiceStatus != "running" {
		addUniqueString(&result.Warnings, "xray_service_not_running")
		addXrayDiagnosticAction(&result, CoreDiagnosticAction{Code: "xray_service_not_running", Severity: "error", Category: "service", Message: "检查 Xray 服务状态和最近日志。", Command: "systemctl status " + paths.XrayService + " && journalctl -u " + paths.XrayService + " -n 80 --no-pager"})
	}
	if !result.ConfigExists {
		addUniqueString(&result.Warnings, "xray_config_missing")
		addXrayDiagnosticAction(&result, CoreDiagnosticAction{Code: "xray_config_missing", Severity: "error", Category: "config", Message: "点击应用重新写入 Xray 配置。"})
	}
	if result.ConfigExists && !result.ConfigValid {
		addUniqueString(&result.Warnings, "xray_config_invalid")
		addXrayDiagnosticAction(&result, CoreDiagnosticAction{Code: "xray_config_invalid", Severity: "error", Category: "config", Message: "按 xray 配置校验报错修复后重新应用。", Command: paths.XrayBinary + " run -test -c " + result.ConfigPath})
	}
	if result.SyncReason != "" && result.SyncReason != "store_unavailable" {
		addUniqueString(&result.Warnings, "xray_config_out_of_sync")
		addXrayDiagnosticAction(&result, CoreDiagnosticAction{Code: "xray_config_out_of_sync", Severity: "warning", Category: "config", Message: "点击应用重新写入 Xray 配置。"})
	}
	if result.ServiceStatus == "running" && len(result.MissingListeners) > 0 {
		addUniqueString(&result.Warnings, "xray_missing_listeners")
		for _, listener := range result.MissingListeners {
			addXrayDiagnosticAction(&result, CoreDiagnosticAction{Code: "xray_missing_listeners", Severity: "warning", Category: "listener", Message: fmt.Sprintf("检查防火墙/安全组是否放行 TCP 端口 %d。", listener.Port), InboundID: listener.InboundID, Port: listener.Port})
		}
		addXrayDiagnosticAction(&result, CoreDiagnosticAction{Code: "xray_missing_listeners_logs", Severity: "info", Category: "log", Message: "检查 Xray 服务状态和最近日志。", Command: "systemctl status " + paths.XrayService + " && journalctl -u " + paths.XrayService + " -n 80 --no-pager"})
	}
	addXrayLogAttribution(&result)
	return result
}

func xrayProbeForConfig(cfg *routerConfig) XrayProbe {
	if cfg != nil && cfg.xrayProbe != nil {
		return cfg.xrayProbe
	}
	var controller XrayController
	if cfg != nil {
		controller = cfg.xrayController
	}
	return defaultXrayProbe{controller: controller}
}

func xrayListenerDiagnosticsForConfig(ctx context.Context, cfg *routerConfig) []CoreListenerDiagnostic {
	if cfg != nil && cfg.xrayListeners != nil {
		return cfg.xrayListeners(ctx, cfg)
	}
	return xrayExpectedListeningPorts(ctx, cfg)
}

func xrayExpectedListeningPorts(ctx context.Context, cfg *routerConfig) []CoreListenerDiagnostic {
	if cfg == nil || cfg.store == nil {
		return []CoreListenerDiagnostic{}
	}
	inbounds, err := cfg.store.ListInbounds(ctx)
	if err != nil {
		return []CoreListenerDiagnostic{}
	}
	result := []CoreListenerDiagnostic{}
	for _, inbound := range inbounds {
		if !inbound.Enabled || db.InboundCore(inbound) != db.CoreXray || inbound.Port <= 0 {
			continue
		}
		transport, ok := xrayListenerTransport(inbound)
		if !ok {
			continue
		}
		result = append(result, CoreListenerDiagnostic{
			InboundID:       inbound.ID,
			Protocol:        inbound.Protocol,
			Port:            inbound.Port,
			Network:         xrayListenerNetwork(inbound),
			Transport:       transport,
			Path:            xrayListenerPath(inbound),
			GrpcServiceName: xrayListenerGrpcServiceName(inbound),
			Security:        xrayListenerSecurity(inbound),
			Listening:       isTCPPortListening(inbound.Port),
		})
	}
	return result
}

func xrayListenerNetwork(inbound db.Inbound) string {
	network := strings.ToLower(strings.TrimSpace(inbound.Network))
	if network == "" {
		return "tcp"
	}
	return network
}

func xrayListenerPath(inbound db.Inbound) string {
	switch xrayListenerNetwork(inbound) {
	case "ws", "h2":
		return strings.TrimSpace(inbound.WsPath)
	case "xhttp":
		return strings.TrimSpace(inbound.XHTTPPath)
	default:
		return ""
	}
}

func xrayListenerGrpcServiceName(inbound db.Inbound) string {
	if xrayListenerNetwork(inbound) != "grpc" {
		return ""
	}
	name := strings.TrimSpace(inbound.GrpcServiceName)
	if name == "" {
		return "migate"
	}
	return name
}

func xrayListenerSecurity(inbound db.Inbound) string {
	security := strings.ToLower(strings.TrimSpace(inbound.Security))
	if security == "" {
		return "none"
	}
	return security
}

func xrayListenerTransport(inbound db.Inbound) (string, bool) {
	network := strings.ToLower(strings.TrimSpace(inbound.Network))
	switch network {
	case "", "tcp", "ws", "grpc", "h2", "xhttp":
		return "tcp", true
	default:
		return "", false
	}
}

func addXrayDataDiagnostics(ctx context.Context, cfg *routerConfig, result *XrayDiagnostics) {
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
	for _, inbound := range inbounds {
		if !inbound.Enabled || db.InboundCore(inbound) != db.CoreXray {
			continue
		}
		hasEnabledClient := false
		for _, client := range inbound.Clients {
			if client.Enabled {
				hasEnabledClient = true
				break
			}
		}
		if !hasEnabledClient {
			addUniqueString(&result.Warnings, "xray_inbound_without_enabled_clients")
			addUniqueString(&result.Suggestions, fmt.Sprintf("为 Xray 入站 %d 创建或启用至少一个客户端。", inbound.ID))
		}
		addXrayInboundSemanticDiagnostics(inbound, result)
	}
	for _, rule := range rules {
		if !rule.Enabled || !db.RoutingRuleAppliesToCore(rule, inbounds, db.CoreXray) {
			continue
		}
		outbound, ok := db.ResolveRuleOutbound(rule, outbounds)
		if !ok || !outbound.Enabled || !db.OutboundSupportsCore(outbound, db.CoreXray) {
			addUniqueString(&result.Warnings, "xray_route_outbound_unavailable")
			addXrayDiagnosticAction(result, CoreDiagnosticAction{Code: "xray_route_outbound_unavailable", Severity: "warning", Category: "routing", Message: fmt.Sprintf("将路由规则 %d 的出站改为支持 Xray 且已启用的出站。", rule.ID)})
		}
	}
	if _, _, errCode, detail := buildXrayConfigFromRouter(ctx, cfg); errCode != "" {
		addUniqueString(&result.Warnings, "xray_generated_config_build_failed")
		addXrayDiagnosticAction(result, CoreDiagnosticAction{Code: "xray_generated_config_build_failed", Severity: "error", Category: "config", Message: "修复数据库中的 Xray 入站、出站或路由配置后重新应用。"})
		if detail != "" {
			addUniqueString(&result.Suggestions, detail)
		}
	}
}

func addXrayInboundSemanticDiagnostics(inbound db.Inbound, result *XrayDiagnostics) {
	for _, issue := range xrayInboundSemanticIssues(inbound) {
		addUniqueString(&result.Warnings, issue.Code)
		addXrayDiagnosticAction(result, CoreDiagnosticAction{Code: issue.Code, Severity: issue.Severity, Category: issue.Category, Message: issue.Suggestion, InboundID: inbound.ID, Port: inbound.Port})
	}
}

func addXrayDiagnosticAction(result *XrayDiagnostics, action CoreDiagnosticAction) {
	action.Code = strings.TrimSpace(action.Code)
	action.Message = strings.TrimSpace(action.Message)
	if action.Code == "" || action.Message == "" {
		return
	}
	if strings.TrimSpace(action.Severity) == "" {
		action.Severity = "warning"
	}
	if strings.TrimSpace(action.Category) == "" {
		action.Category = "config"
	}
	addUniqueString(&result.Suggestions, actionSuggestionText(action))
	for _, existing := range result.Actions {
		if existing.Code == action.Code && existing.Message == action.Message && existing.Command == action.Command && existing.InboundID == action.InboundID && existing.Port == action.Port {
			return
		}
	}
	result.Actions = append(result.Actions, action)
	result.SuggestionDetails = append(result.SuggestionDetails, action)
}

func actionSuggestionText(action CoreDiagnosticAction) string {
	if strings.TrimSpace(action.Command) == "" {
		return action.Message
	}
	return action.Message + " 运行 " + action.Command + "。"
}

type xrayDiagnosticIssue struct {
	Code       string
	Suggestion string
	Severity   string
	Category   string
}

func xrayInboundSemanticIssues(inbound db.Inbound) []xrayDiagnosticIssue {
	if !inbound.Enabled || db.InboundCore(inbound) != db.CoreXray {
		return nil
	}
	issues := []xrayDiagnosticIssue{}
	network := xrayListenerNetwork(inbound)
	security := xrayListenerSecurity(inbound)
	switch network {
	case "ws", "h2":
		if !validXrayPath(inbound.WsPath) {
			issues = append(issues, xrayDiagnosticIssue{
				Code:       "xray_ws_path_invalid",
				Suggestion: fmt.Sprintf("将 Xray 入站 %d 的 %s path 设置为以 / 开头的路径。", inbound.ID, strings.ToUpper(network)),
				Severity:   "warning",
				Category:   "listener",
			})
		}
	case "grpc":
		serviceName := strings.TrimSpace(inbound.GrpcServiceName)
		if serviceName == "" {
			issues = append(issues, xrayDiagnosticIssue{
				Code:       "xray_grpc_service_name_default",
				Suggestion: fmt.Sprintf("Xray 入站 %d 的 gRPC serviceName 为空，将使用默认值 migate。", inbound.ID),
				Severity:   "info",
				Category:   "listener",
			})
		} else if !xrayGrpcServiceNamePattern.MatchString(serviceName) {
			issues = append(issues, xrayDiagnosticIssue{
				Code:       "xray_grpc_service_name_invalid",
				Suggestion: fmt.Sprintf("将 Xray 入站 %d 的 gRPC serviceName 改为字母、数字、点、下划线或短横线。", inbound.ID),
				Severity:   "warning",
				Category:   "listener",
			})
		}
	case "xhttp":
		if !validXrayPath(inbound.XHTTPPath) {
			issues = append(issues, xrayDiagnosticIssue{
				Code:       "xray_xhttp_path_invalid",
				Suggestion: fmt.Sprintf("将 Xray 入站 %d 的 XHTTP path 设置为以 / 开头的路径。", inbound.ID),
				Severity:   "warning",
				Category:   "listener",
			})
		}
	}
	switch security {
	case "reality":
		if strings.TrimSpace(inbound.RealityPrivateKey) == "" || strings.TrimSpace(inbound.RealityServerNames) == "" || strings.TrimSpace(inbound.RealityDest) == "" {
			issues = append(issues, xrayDiagnosticIssue{
				Code:       "xray_reality_settings_incomplete",
				Suggestion: fmt.Sprintf("补齐 Xray 入站 %d 的 REALITY private_key、server_names 和 dest。", inbound.ID),
				Severity:   "warning",
				Category:   "security",
			})
		}
	case "tls":
		if strings.TrimSpace(inbound.TLSCertFile) == "" || strings.TrimSpace(inbound.TLSKeyFile) == "" {
			issues = append(issues, xrayDiagnosticIssue{
				Code:       "xray_tls_certificate_missing",
				Suggestion: fmt.Sprintf("补齐 Xray 入站 %d 的 TLS cert/key 文件路径。", inbound.ID),
				Severity:   "warning",
				Category:   "security",
			})
		}
	}
	if db.NormalizeInboundProtocol(inbound.Protocol) == "shadowsocks" && strings.HasPrefix(strings.ToLower(strings.TrimSpace(inbound.SSMethod)), "2022-") && !xrayShadowsocksHasCredentials(inbound) {
		issues = append(issues, xrayDiagnosticIssue{
			Code:       "xray_shadowsocks_credentials_missing",
			Suggestion: fmt.Sprintf("为 Xray Shadowsocks 2022 入站 %d 配置可用的 password/key 或启用有密码的客户端。", inbound.ID),
			Severity:   "warning",
			Category:   "security",
		})
	}
	return issues
}

func validXrayPath(path string) bool {
	path = strings.TrimSpace(path)
	return path != "" && strings.HasPrefix(path, "/")
}

func xrayShadowsocksHasCredentials(inbound db.Inbound) bool {
	if strings.TrimSpace(inbound.UUID) != "" {
		return true
	}
	for _, client := range inbound.Clients {
		if !client.Enabled {
			continue
		}
		if strings.TrimSpace(client.PasswordValue()) != "" {
			return true
		}
	}
	return false
}

func addXrayLogAttribution(result *XrayDiagnostics) {
	for _, suggestion := range xrayLogAttributionSuggestions(result.ConfigError, result.RecentLogs, result.MissingListeners) {
		addUniqueString(&result.Suggestions, suggestion)
	}
	for _, action := range xrayLogAttributionActions(result.ConfigError, result.RecentLogs, result.MissingListeners) {
		addXrayDiagnosticAction(result, action)
	}
}

func xrayLogAttributionSuggestions(configError string, recentLogs []string, missingListeners []CoreListenerDiagnostic) []string {
	actions := xrayLogAttributionActions(configError, recentLogs, missingListeners)
	suggestions := make([]string, 0, len(actions))
	for _, action := range actions {
		addUniqueString(&suggestions, actionSuggestionText(action))
	}
	return suggestions
}

func xrayLogAttributionActions(configError string, recentLogs []string, missingListeners []CoreListenerDiagnostic) []CoreDiagnosticAction {
	text := strings.ToLower(strings.Join(append([]string{configError}, recentLogs...), "\n"))
	if strings.TrimSpace(text) == "" {
		return nil
	}
	actions := []CoreDiagnosticAction{}
	add := func(action CoreDiagnosticAction) {
		action.Code = strings.TrimSpace(action.Code)
		action.Message = strings.TrimSpace(action.Message)
		if action.Code == "" || action.Message == "" {
			return
		}
		if action.Severity == "" {
			action.Severity = "warning"
		}
		if action.Category == "" {
			action.Category = "log"
		}
		for _, existing := range actions {
			if existing.Code == action.Code && existing.Message == action.Message && existing.Command == action.Command && existing.InboundID == action.InboundID && existing.Port == action.Port {
				return
			}
		}
		actions = append(actions, action)
	}
	if containsAny(text, "failed to listen", "failed to bind", "address already in use", "bind: address already in use") {
		if len(missingListeners) > 0 {
			for _, listener := range missingListeners {
				add(CoreDiagnosticAction{Code: "xray_listener_port_in_use", Severity: "error", Category: "listener", Message: fmt.Sprintf("日志显示端口可能被占用，优先检查 Xray 入站端口 %d。", listener.Port), Command: fmt.Sprintf("ss -ltnp | grep :%d", listener.Port), InboundID: listener.InboundID, Port: listener.Port})
			}
		} else {
			add(CoreDiagnosticAction{Code: "xray_listener_port_in_use", Severity: "error", Category: "listener", Message: "日志显示端口可能被占用，排查监听进程。", Command: "ss -ltnp"})
		}
	}
	if strings.Contains(text, "permission denied") {
		add(CoreDiagnosticAction{Code: "xray_log_permission_denied", Severity: "error", Category: "log", Message: "日志显示权限不足，检查 Xray systemd sandbox、配置文件权限和端口绑定权限。"})
	}
	if containsAny(text, "failed to load certificate", "no such file", "cannot load certificate", "open /") && containsAny(text, "cert", "certificate", "key", ".pem", ".crt") {
		add(CoreDiagnosticAction{Code: "xray_tls_certificate_missing", Severity: "error", Category: "security", Message: "日志显示 TLS 证书或私钥路径不可用，检查入站 TLS cert/key 文件是否存在且 xray 可读取。"})
	}
	if containsAny(text, "reality", "shortid", "short id", "privatekey", "private key") {
		add(CoreDiagnosticAction{Code: "xray_reality_settings_incomplete", Severity: "warning", Category: "security", Message: "日志包含 REALITY/privateKey/shortId 相关错误，检查 REALITY private_key、short_id、server_names 和 dest。"})
	}
	if strings.Contains(text, "xhttp") {
		add(CoreDiagnosticAction{Code: "xray_xhttp_path_invalid", Severity: "warning", Category: "listener", Message: "日志包含 XHTTP 相关错误，检查 XHTTP path/mode 与客户端配置是否一致。"})
	}
	if strings.Contains(text, "grpc") {
		add(CoreDiagnosticAction{Code: "xray_grpc_service_name_invalid", Severity: "warning", Category: "listener", Message: "日志包含 gRPC 相关错误，检查 gRPC serviceName 与客户端配置是否一致。"})
	}
	if containsAny(text, "websocket", " ws ", " ws:", " ws/", "network ws") {
		add(CoreDiagnosticAction{Code: "xray_ws_path_invalid", Severity: "warning", Category: "listener", Message: "日志包含 WebSocket 相关错误，检查 WS path/host 与客户端配置是否一致。"})
	}
	return actions
}

func containsAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func xrayApplyForWrite(ctx context.Context, ctrl XrayController) XrayApplyResult {
	if ctrl == nil {
		ctrl = defaultXrayController{}
	}
	result := ctrl.Apply(ctx)
	if result.Service == "" {
		result.Service = paths.XrayService
	}
	if result.CommandsExecuted == nil {
		result.CommandsExecuted = []string{}
	}
	if result.Status == "" {
		if result.Applied {
			result.Status = "applied"
		} else if result.Error != "" {
			result.Status = xrayApplyStatusForError(result.Error)
		}
	}
	if result.Applied {
		result.Status = "applied"
	} else if result.Error == "" && strings.HasPrefix(result.Status, "failed") {
		result.Error = strings.TrimPrefix(result.Status, "failed: ")
		if result.Detail == "" {
			result.Detail = result.ErrorOutput
		}
	} else if result.Error == "" && result.Status != "" && result.Status != "applied" {
		result.Error = result.Status
	}
	return result
}

func addXrayPostApplyDiagnostics(ctx context.Context, cfg *routerConfig, summary XrayApplyResult) XrayApplyResult {
	if cfg == nil || !summary.Applied {
		return summary
	}
	for _, listener := range retryXrayListenerDiagnostics(ctx, cfg, xrayPostApplyListenerAttempts, xrayPostApplyListenerDelay) {
		if listener.Listening {
			continue
		}
		warning := fmt.Sprintf("配置已应用，但端口未监听：%d/%s", listener.Port, listenerNetwork(listener))
		addUniqueString(&summary.PostApplyWarnings, warning)
		addUniqueString(&summary.Warnings, warning)
	}
	return summary
}

func addXraySemanticWarningsForWrite(ctx context.Context, cfg *routerConfig, summary XrayApplyResult) XrayApplyResult {
	if cfg == nil || cfg.store == nil {
		return summary
	}
	inbounds, err := cfg.store.ListInbounds(ctx)
	if err != nil {
		return summary
	}
	for _, inbound := range inbounds {
		if !inbound.Enabled || db.InboundCore(inbound) != db.CoreXray {
			continue
		}
		for _, issue := range xrayInboundSemanticIssues(inbound) {
			if isXrayWriteSemanticWarning(issue.Code) {
				addUniqueString(&summary.Warnings, issue.Code)
			}
		}
	}
	return summary
}

func isXrayWriteSemanticWarning(code string) bool {
	switch code {
	case "xray_ws_path_invalid",
		"xray_grpc_service_name_invalid",
		"xray_xhttp_path_invalid",
		"xray_reality_settings_incomplete",
		"xray_tls_certificate_missing",
		"xray_shadowsocks_credentials_missing":
		return true
	default:
		return false
	}
}

func retryXrayListenerDiagnostics(ctx context.Context, cfg *routerConfig, attempts int, delay time.Duration) []CoreListenerDiagnostic {
	if attempts < 1 {
		attempts = 1
	}
	var last []CoreListenerDiagnostic
	for attempt := 0; attempt < attempts; attempt++ {
		last = xrayListenerDiagnosticsForConfig(ctx, cfg)
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

func attachXrayResult(payload map[string]interface{}, summary XrayApplyResult) map[string]interface{} {
	payload["xray"] = summary
	return payload
}

func attachSingboxNestedResult(payload map[string]interface{}, summary SingboxApplySummary) map[string]interface{} {
	payload["singbox"] = summary
	return payload
}

func attachXrayAndMaybeSingboxResult(ctx context.Context, cfg *routerConfig, store Store, payload map[string]interface{}, includeXray bool, includeSingbox bool) map[string]interface{} {
	if includeXray {
		var ctrl XrayController
		if cfg != nil {
			ctrl = cfg.xrayController
		}
		attachXrayResult(payload, addXraySemanticWarningsForWrite(ctx, cfg, addXrayPostApplyDiagnostics(ctx, cfg, xrayApplyForWrite(ctx, ctrl))))
	}
	if includeSingbox {
		summary := strictSingboxApply(ctx, cfg, store)
		if includeXray {
			attachSingboxNestedResult(payload, summary)
		} else {
			attachSingboxResult(payload, summary)
		}
	}
	return payload
}

func writeCoreWriteResult(w http.ResponseWriter, r *http.Request, cfg *routerConfig, store Store, status int, payload map[string]interface{}, includeXray bool, includeSingbox bool) {
	attachXrayAndMaybeSingboxResult(r.Context(), cfg, store, payload, includeXray, includeSingbox)
	writeJSON(w, status, payload)
}

func xrayAndSingboxForInboundWrite(previous db.Inbound, hadPrevious bool, current db.Inbound) (bool, bool) {
	return db.InboundCore(current) == db.CoreXray || (hadPrevious && db.InboundCore(previous) == db.CoreXray), inboundChangeAffectsSingbox(previous, hadPrevious, current)
}

func xrayAndSingboxForInboundDelete(inbound db.Inbound) (bool, bool) {
	return db.InboundCore(inbound) == db.CoreXray, db.InboundCore(inbound) == db.CoreSingbox
}

func xrayAndSingboxForClientWrite(inbound db.Inbound) (bool, bool) {
	return db.InboundCore(inbound) == db.CoreXray, db.InboundCore(inbound) == db.CoreSingbox
}

type coreInboundScope struct {
	inbounds   []db.Inbound
	rules      []db.RoutingRule
	hasXray    bool
	hasSingbox bool
}

func loadCoreInboundScope(ctx context.Context, store Store) (coreInboundScope, error) {
	if store == nil {
		return coreInboundScope{}, nil
	}
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		return coreInboundScope{}, err
	}
	rules, err := store.ListRoutingRules(ctx)
	if err != nil {
		return coreInboundScope{}, err
	}
	scope := coreInboundScope{inbounds: inbounds, rules: rules}
	for _, inbound := range inbounds {
		switch db.InboundCore(inbound) {
		case db.CoreXray:
			scope.hasXray = true
		case db.CoreSingbox:
			scope.hasSingbox = true
		}
	}
	return scope, nil
}

func (s coreInboundScope) hasCore(core string) bool {
	switch db.NormalizeCore(core) {
	case db.CoreXray:
		return s.hasXray
	case db.CoreSingbox:
		return s.hasSingbox
	default:
		return false
	}
}

func xrayAndSingboxForOutboundWrite(scope coreInboundScope, previous db.Outbound, hadPrevious bool, current db.Outbound) (bool, bool) {
	return outboundWriteAffectsCore(scope, previous, hadPrevious, current, db.CoreXray), outboundWriteAffectsCore(scope, previous, hadPrevious, current, db.CoreSingbox)
}

func xrayAndSingboxForOutboundDelete(scope coreInboundScope, outbound db.Outbound) (bool, bool) {
	return outboundDeleteAffectsCore(scope, outbound, db.CoreXray), outboundDeleteAffectsCore(scope, outbound, db.CoreSingbox)
}

func outboundWriteAffectsCore(scope coreInboundScope, previous db.Outbound, hadPrevious bool, current db.Outbound, core string) bool {
	if !scope.hasCore(core) {
		return false
	}
	return db.OutboundSupportsCore(current, core) || (hadPrevious && db.OutboundSupportsCore(previous, core)) || outboundReferencedByCoreRule(scope, current, core) || (hadPrevious && outboundReferencedByCoreRule(scope, previous, core))
}

func outboundDeleteAffectsCore(scope coreInboundScope, outbound db.Outbound, core string) bool {
	return scope.hasCore(core) && (db.OutboundSupportsCore(outbound, core) || outboundReferencedByCoreRule(scope, outbound, core))
}

func outboundReferencedByCoreRule(scope coreInboundScope, outbound db.Outbound, core string) bool {
	for _, rule := range scope.rules {
		if !rule.Enabled || !db.RoutingRuleAppliesToCore(rule, scope.inbounds, core) {
			continue
		}
		if rule.OutboundID > 0 && outbound.ID > 0 && rule.OutboundID == outbound.ID {
			return true
		}
		if strings.TrimSpace(rule.OutboundTag) != "" && strings.TrimSpace(rule.OutboundTag) == strings.TrimSpace(outbound.Tag) {
			return true
		}
	}
	return false
}

func xrayAndSingboxForRoutingRuleWrite(ctx context.Context, store Store, previous db.RoutingRule, hadPrevious bool, current db.RoutingRule) (bool, bool, error) {
	scope, err := loadCoreInboundScope(ctx, store)
	if err != nil {
		return false, false, err
	}
	includeXray, includeSingbox := xrayAndSingboxForRoutingRuleWriteWithScope(scope, previous, hadPrevious, current)
	return includeXray, includeSingbox, nil
}

func xrayAndSingboxForRoutingRuleWriteWithScope(scope coreInboundScope, previous db.RoutingRule, hadPrevious bool, current db.RoutingRule) (bool, bool) {
	xrayCurrent := db.RoutingRuleAppliesToCore(current, scope.inbounds, db.CoreXray)
	singboxCurrent := db.RoutingRuleAppliesToCore(current, scope.inbounds, db.CoreSingbox)
	if !hadPrevious {
		return xrayCurrent, singboxCurrent
	}
	xrayPrevious := db.RoutingRuleAppliesToCore(previous, scope.inbounds, db.CoreXray)
	singboxPrevious := db.RoutingRuleAppliesToCore(previous, scope.inbounds, db.CoreSingbox)
	return xrayCurrent || xrayPrevious, singboxCurrent || singboxPrevious
}

func xrayAndSingboxForRoutingRuleDelete(ctx context.Context, store Store, rule db.RoutingRule) (bool, bool, error) {
	scope, err := loadCoreInboundScope(ctx, store)
	if err != nil {
		return false, false, err
	}
	includeXray, includeSingbox := xrayAndSingboxForRoutingRuleDeleteWithScope(scope, rule)
	return includeXray, includeSingbox, nil
}

func xrayAndSingboxForRoutingRuleDeleteWithScope(scope coreInboundScope, rule db.RoutingRule) (bool, bool) {
	return db.RoutingRuleAppliesToCore(rule, scope.inbounds, db.CoreXray), db.RoutingRuleAppliesToCore(rule, scope.inbounds, db.CoreSingbox)
}

func xrayAndSingboxForReorder(ctx context.Context, store Store) (bool, bool, error) {
	scope, err := loadCoreInboundScope(ctx, store)
	if err != nil {
		return false, false, err
	}
	return scope.hasXray, scope.hasSingbox, nil
}

func xrayStatusHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		var controller XrayController
		if cfg != nil {
			controller = cfg.xrayController
		}
		if controller == nil {
			controller = defaultXrayController{}
		}
		status := controller.Status(r.Context())
		if strings.TrimSpace(status.Core) == "" {
			status.Core = "xray"
		}
		if strings.TrimSpace(status.Service) == "" {
			status.Service = paths.XrayService
		}
		if strings.TrimSpace(status.ServiceStatus) == "" {
			status.ServiceStatus = normalizeCoreServiceStatus(status.Status)
		}
		if strings.TrimSpace(status.Status) == "" {
			status.Status = status.ServiceStatus
		}
		if strings.TrimSpace(status.BinaryPath) == "" {
			status.BinaryPath = paths.XrayBinary
		}
		if strings.TrimSpace(status.BinaryVersion) == "" {
			status.BinaryVersion = status.Version
		}
		if strings.TrimSpace(status.ConfigPath) == "" {
			status.ConfigPath = xrayConfigPath(cfg)
		}
		if status.CommandsExecuted == nil {
			status.CommandsExecuted = []string{}
		}
		status.ListeningPorts = xrayListenerDiagnosticsForConfig(r.Context(), cfg)
		if status.ListeningPorts == nil {
			status.ListeningPorts = []CoreListenerDiagnostic{}
		}
		writeJSON(w, http.StatusOK, status)
	}
}

type configValidationResult struct {
	Target    string   `json:"target"`
	Valid     bool     `json:"valid"`
	Error     string   `json:"error,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Inbounds  int      `json:"inbounds"`
	Outbounds int      `json:"outbounds,omitempty"`
	Rules     int      `json:"rules,omitempty"`
}

func xrayValidateHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		result := validateXrayConfig(r.Context(), cfg)
		writeJSON(w, http.StatusOK, result)
	}
}

func validateXrayConfig(ctx context.Context, cfg *routerConfig) configValidationResult {
	result := configValidationResult{Target: "xray", Valid: true, Warnings: []string{}}
	if cfg == nil || cfg.store == nil {
		result.Valid = false
		result.Error = "store_unavailable"
		return result
	}
	store := cfg.store
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		result.Valid = false
		result.Error = "list_inbounds_failed"
		return result
	}
	outbounds, err := store.ListOutbounds(ctx)
	if err != nil {
		result.Valid = false
		result.Error = "list_outbounds_failed"
		return result
	}
	rules, err := store.ListRoutingRules(ctx)
	if err != nil {
		result.Valid = false
		result.Error = "list_routing_rules_failed"
		return result
	}
	return validateXrayConfigSnapshotWithOptions(validationSnapshot{inbounds: inbounds, outbounds: outbounds, rules: rules}, xrayOptionsForRouterConfig(cfg))
}

func validateXrayConfigSnapshot(snapshot validationSnapshot) configValidationResult {
	return validateXrayConfigSnapshotWithOptions(snapshot, xray.BuildOptions{})
}

func validateXrayConfigSnapshotWithOptions(snapshot validationSnapshot, opts xray.BuildOptions) configValidationResult {
	result := configValidationResult{Target: "xray", Valid: true, Warnings: []string{}}
	inbounds := snapshot.inbounds
	outbounds := snapshot.outbounds
	rules := snapshot.rules
	cfg, err := xray.BuildConfigWithOutboundsOptions(inbounds, outbounds, rules, opts)
	if err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result
	}
	result.Inbounds = len(cfg.Inbounds)
	result.Outbounds = len(cfg.Outbounds)
	if cfg.Routing != nil {
		result.Rules = len(cfg.Routing.Rules)
	}
	for _, inbound := range inbounds {
		if inbound.Enabled && singbox.IsSingboxProtocol(inbound.Protocol) {
			result.Warnings = append(result.Warnings, inbound.Protocol+" is handled by sing-box")
		}
	}
	for _, rule := range rules {
		if strings.TrimSpace(rule.RuleSet) != "" {
			result.Warnings = append(result.Warnings, "rule_set is stored for future use but not emitted in Xray config")
			break
		}
	}
	return result
}

func xrayApplyHandler(cfg *routerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		var payload struct {
			Confirm            bool `json:"confirm"`
			AllowSystemChanges bool `json:"allow_system_changes"`
		}
		if err := decodeJSONBody(r, &payload); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_json")
			return
		}
		if !payload.Confirm || !payload.AllowSystemChanges {
			writeJSONError(w, http.StatusForbidden, "confirmation_required", map[string]interface{}{"commands_executed": []string{}})
			return
		}
		unlock, err := lockfile.TryAcquire(paths.ApplyLock)
		if err != nil {
			writeJSONError(w, http.StatusConflict, "apply_locked", map[string]interface{}{"detail": err.Error(), "lock_path": paths.ApplyLock})
			return
		}
		defer unlock()
		var controller XrayController = defaultXrayController{}
		if cfg != nil && cfg.xrayController != nil {
			controller = cfg.xrayController
		}
		var store Store
		var singboxRuntime SingboxRuntime = defaultSingboxRuntime{}
		singboxApplier := tryApplySingboxWithRuntime
		usingDefaultSingboxApplier := true
		if cfg != nil {
			store = cfg.store
			if cfg.singboxRuntime != nil {
				singboxRuntime = cfg.singboxRuntime
			}
			if cfg.singboxApplier != nil {
				singboxApplier = cfg.singboxApplier
				usingDefaultSingboxApplier = !cfg.singboxApplierSet
			}
		}

		// 1. Apply Xray config
		xrayResult := addXraySemanticWarningsForWrite(r.Context(), cfg, addXrayPostApplyDiagnostics(r.Context(), cfg, xrayApplyForWrite(r.Context(), controller)))

		// 2. Apply sing-box config if sing-box supported inbounds exist
		var singboxResult map[string]interface{}
		if store != nil && xrayResult.Applied {
			inbounds, err := store.ListInbounds(r.Context())
			if err != nil {
				singboxResult = map[string]interface{}{
					"applied": false,
					"reason":  "list_inbounds_failed",
					"detail":  err.Error(),
				}
			} else {
				if singbox.HasEnabledSingboxInbound(inbounds) {
					if usingDefaultSingboxApplier && !singbox.IsInstalled() {
						singboxResult = map[string]interface{}{
							"applied": false,
							"reason":  "singbox_not_installed",
						}
					} else {
						var applyResult SingboxApplySummary
						if usingDefaultSingboxApplier {
							applyResult = tryApplySingboxWithRouterConfig(r.Context(), cfg, store, false)
						} else {
							applyResult = singboxApplier(r.Context(), store, singboxRuntime, false)
						}
						if !applyResult.Applied {
							singboxResult = map[string]interface{}{
								"applied":           false,
								"service":           applyResult.Service,
								"config_path":       applyResult.ConfigPath,
								"commands_executed": applyResult.CommandsExecuted,
								"error":             applyResult.Error,
								"detail":            applyResult.Detail,
								"warnings":          applyResult.Warnings,
							}
						} else {
							singboxResult = map[string]interface{}{
								"applied":           true,
								"service":           applyResult.Service,
								"config_path":       applyResult.ConfigPath,
								"commands_executed": applyResult.CommandsExecuted,
								"warnings":          applyResult.Warnings,
								"inbounds":          len(singbox.BuildConfigWithOptions(inbounds, singbox.BuildOptions{}).Inbounds),
							}
						}
					}
				}
			}
		}

		response := map[string]interface{}{"xray": xrayResult}
		if singboxResult != nil {
			response["singbox"] = singboxResult
		}
		writeJSON(w, http.StatusOK, response)
	}
}
