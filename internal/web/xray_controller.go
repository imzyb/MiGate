package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/imzyb/MiGate/internal/corefile"
	"github.com/imzyb/MiGate/internal/paths"
	"github.com/imzyb/MiGate/internal/xray"
)

// CmdRunner runs an external command and returns its stdout + error.
type CmdRunner func(name string, args ...string) (string, error)

// RealController implements XrayController by writing config to disk,
// validating with xray, and restarting the xray systemd service.
type RealController struct {
	store      Store
	configPath string
	configDir  string
	runCmd     CmdRunner
}

// NewRealController creates a controller that persists the generated xray
// configuration, validates it, and restarts the xray service.
func NewRealController(store Store, configPath string, runCmd CmdRunner) *RealController {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = paths.XrayConfig
	}
	return &RealController{store: store, configPath: configPath, runCmd: runCmd}
}

func (c *RealController) WithConfigDir(configDir string) *RealController {
	c.configDir = strings.TrimSpace(configDir)
	return c
}

// Status reports whether the xray binary and systemd service appear to be
// running on this host.
func (c *RealController) Status(ctx context.Context) XrayStatus {
	executed := []string{}
	configPath := c.normalizedConfigPath()

	out, err := c.runCmd("systemctl", "is-active", paths.XrayService)
	executed = append(executed, "systemctl is-active "+paths.XrayService)

	status := "unknown"
	managed := false
	if err == nil || strings.TrimSpace(out) != "" {
		managed = true
		status = strings.TrimSpace(out)
		if status == "active" {
			status = "running"
		}
	}

	showOut, showErr := c.runCmd("systemctl", "show", paths.XrayService, "--property=MemoryCurrent", "--property=MainPID", "--property=ActiveEnterTimestamp")
	executed = append(executed, "systemctl show "+paths.XrayService+" --property=MemoryCurrent --property=MainPID --property=ActiveEnterTimestamp")
	memoryRSS, uptime := parseXrayServiceStatus(showOut)
	if showErr == nil {
		managed = true
	}

	version := c.Version(ctx)
	if version != "" {
		executed = append(executed, "xray version")
		if status == "unknown" {
			status = "not_managed"
		}
	} else {
		status = "not_installed"
	}

	configExists := false
	configValid := false
	configError := ""
	configStatus := corefile.CheckPath(configPath, corefile.Requirement{Kind: corefile.KindFile, Readable: true})
	if configStatus.OK() {
		configExists = true
		if version != "" {
			validateOut, validateErr := c.runCmd(paths.XrayBinary, "run", "-test", "-c", configPath)
			executed = append(executed, fmt.Sprintf("xray run -test -c %s", configPath))
			if validateErr != nil {
				configError = strings.TrimSpace(validateOut)
				if configError == "" {
					configError = validateErr.Error()
				}
			} else {
				configValid = true
			}
		}
	} else {
		configExists = configStatus.Exists
		if configStatus.Code != "not_exists" {
			configError = configStatus.Error()
		}
	}

	activeConnections := countXrayActiveConnections(ctx, c.store, c.runCmd)
	executed = append(executed, "ss -tn state established")

	return XrayStatus{
		Core:              "xray",
		Service:           paths.XrayService,
		Status:            status,
		ServiceStatus:     status,
		Managed:           managed,
		Installed:         version != "",
		Version:           version,
		BinaryPath:        paths.XrayBinary,
		BinaryVersion:     version,
		ConfigExists:      configExists,
		ConfigValid:       configValid,
		ConfigError:       configError,
		MemoryRSSBytes:    memoryRSS,
		Uptime:            uptime,
		ActiveConnections: activeConnections,
		ConfigPath:        configPath,
		CommandsExecuted:  executed,
	}
}

// Apply reads the current inbounds from the store, builds an xray config,
// writes it to disk, validates it with `xray run -test`, and on success
// restarts the xray systemd service.
func (c *RealController) Apply(ctx context.Context) XrayApplyResult {
	executed := []string{}
	configPath := c.normalizedConfigPath()
	configDir := filepath.Dir(configPath)
	result := XrayApplyResult{
		Applied:          false,
		Status:           "failed",
		Service:          "xray",
		ConfigPath:       configPath,
		CommandsExecuted: executed,
		Warnings:         []string{},
	}
	fail := func(code string, detail string) XrayApplyResult {
		result.Applied = false
		result.Status = xrayApplyStatusForError(code)
		result.Error = code
		result.Detail = detail
		result.ErrorOutput = detail
		result.CommandsExecuted = append([]string(nil), executed...)
		return result
	}

	// 1. Build config from store, including managed outbounds and routing rules.
	// The WebUI preview uses BuildConfigWithOutbounds; Apply must use the same
	// builder or Xray will restart with only inbounds and traffic will keep using
	// the implicit direct outbound.
	inbounds, err := c.store.ListInbounds(ctx)
	if err != nil {
		return fail("list_inbounds_failed", err.Error())
	}
	outbounds, err := c.store.ListOutbounds(ctx)
	if err != nil {
		return fail("list_outbounds_failed", err.Error())
	}
	rules, err := c.store.ListRoutingRules(ctx)
	if err != nil {
		return fail("list_routing_rules_failed", err.Error())
	}

	opts := xray.BuildOptions{}
	if strings.TrimSpace(c.configDir) != "" {
		opts = xrayOptionsForRouterConfig(&routerConfig{configDir: c.configDir})
	}
	cfg, err := xray.BuildConfigWithOutboundsOptions(inbounds, outbounds, rules, opts)
	if err != nil {
		return fail("build_failed", err.Error())
	}
	result.Inbounds = len(cfg.Inbounds)
	result.Outbounds = len(cfg.Outbounds)
	if cfg.Routing != nil {
		result.Rules = len(cfg.Routing.Rules)
	}

	// 2. Validate a temporary config before touching the live config.
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fail("marshal_failed", err.Error())
	}
	if status := corefile.EnsureDir(configDir, corefile.Requirement{Readable: true, Writable: true, Executable: true}); !status.OK() {
		return fail("create_config_dir_failed", status.Error())
	}
	tmp, err := os.CreateTemp(configDir, ".xray-*.json")
	if err != nil {
		return fail("create_temp_failed", err.Error())
	}
	tmpPath := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fail("write_temp_failed", err.Error())
	}
	if err := tmp.Chmod(0640); err != nil {
		_ = tmp.Close()
		return fail("chmod_temp_failed", err.Error())
	}
	if err := tmp.Close(); err != nil {
		return fail("close_temp_failed", err.Error())
	}
	validateOut, err := c.runCmd("xray", "run", "-test", "-c", tmpPath)
	executed = append(executed, "xray run -test -c <temp>")
	if err != nil {
		detail := strings.TrimSpace(validateOut)
		if detail == "" {
			detail = err.Error()
		}
		return fail("validation_failed", detail)
	}
	var backupPath string
	if status := corefile.CheckPath(configPath, corefile.Requirement{Kind: corefile.KindFile, Readable: true}); status.OK() {
		backup, createErr := os.CreateTemp(configDir, ".xray-backup-*.json")
		if createErr != nil {
			return fail("backup_failed", fmt.Sprintf("%s: %v", configPath, createErr))
		}
		backupPath = backup.Name()
		current, readErr := os.ReadFile(configPath)
		if readErr != nil {
			_ = backup.Close()
			return fail("backup_failed", fmt.Sprintf("%s: %v", configPath, readErr))
		}
		if _, writeErr := backup.Write(current); writeErr != nil {
			_ = backup.Close()
			return fail("backup_failed", fmt.Sprintf("%s: %v", backupPath, writeErr))
		}
		if closeErr := backup.Close(); closeErr != nil {
			return fail("backup_failed", fmt.Sprintf("%s: %v", backupPath, closeErr))
		}
	} else if status.Code != "not_exists" {
		return fail("stat_config_failed", status.Error())
	}
	if err := os.Rename(tmpPath, configPath); err != nil {
		return fail("write_failed", fmt.Sprintf("%s: %v", configPath, err))
	}
	cleanupTmp = false
	executed = append(executed, fmt.Sprintf("write %s", configPath))

	// 3. Restart xray service. If restart fails, restore the previous config.
	restartOut, err := c.runCmd("systemctl", "restart", paths.XrayService)
	executed = append(executed, "systemctl restart "+paths.XrayService)
	if err != nil {
		detail := strings.TrimSpace(restartOut)
		if detail == "" {
			detail = err.Error()
		}
		if backupPath != "" {
			if restoreErr := os.Rename(backupPath, configPath); restoreErr != nil {
				return fail("restart_failed", fmt.Sprintf("%s; restore previous config failed: %v", detail, restoreErr))
			}
			restoreOut, restoreRestartErr := c.runCmd("systemctl", "restart", paths.XrayService)
			executed = append(executed, "restore previous config", "systemctl restart "+paths.XrayService)
			if restoreRestartErr != nil {
				restoreDetail := strings.TrimSpace(restoreOut)
				if restoreDetail == "" {
					restoreDetail = restoreRestartErr.Error()
				}
				return fail("restart_failed", fmt.Sprintf("%s; previous config restored but restart failed: %s", detail, restoreDetail))
			}
			return fail("restart_failed", detail)
		}
		return fail("restart_failed", detail)
	}
	if backupPath != "" {
		_ = os.Remove(backupPath)
	}

	result.Applied = true
	result.Status = "applied"
	result.Error = ""
	result.Detail = ""
	result.ErrorOutput = ""
	result.CommandsExecuted = append([]string(nil), executed...)
	return result
}

func (c *RealController) normalizedConfigPath() string {
	path := strings.TrimSpace(c.configPath)
	if path == "" {
		return paths.XrayConfig
	}
	return path
}

func xrayApplyStatusForError(code string) string {
	switch code {
	case "validation_failed":
		return "failed: validation"
	case "restart_failed":
		return "failed: restart"
	default:
		return "failed: " + code
	}
}

func parseXrayServiceStatus(output string) (int64, string) {
	var memory int64
	var activeEnter string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "MemoryCurrent="):
			memory, _ = strconv.ParseInt(strings.TrimPrefix(line, "MemoryCurrent="), 10, 64)
		case strings.HasPrefix(line, "ActiveEnterTimestamp="):
			activeEnter = strings.TrimPrefix(line, "ActiveEnterTimestamp=")
		}
	}
	return memory, humanUptimeSinceSystemdTimestamp(activeEnter)
}

func humanUptimeSinceSystemdTimestamp(ts string) string {
	if ts == "" {
		return "未知"
	}
	for _, layout := range []string{"Mon 2006-01-02 15:04:05 MST", "Mon 2006-01-02 15:04:05 -0700"} {
		t, err := time.Parse(layout, ts)
		if err != nil {
			continue
		}
		dur := time.Since(t)
		if dur < 0 {
			return "刚启动"
		}
		h := int(dur.Hours())
		m := int(dur.Minutes()) % 60
		if h > 0 {
			return fmt.Sprintf("%dh%dm", h, m)
		}
		return fmt.Sprintf("%dm", m)
	}
	return "未知"
}

func countXrayActiveConnections(ctx context.Context, store Store, run CmdRunner) int {
	out, err := run("ss", "-tn", "state", "established")
	if err != nil {
		return 0
	}
	inboundPorts := map[int]struct{}{}
	if store != nil {
		inbounds, err := store.ListInbounds(ctx)
		if err == nil {
			for _, inbound := range inbounds {
				if inbound.Enabled && isXrayHandledProtocol(inbound.Protocol) && inbound.Port > 0 {
					inboundPorts[inbound.Port] = struct{}{}
				}
			}
		}
	}
	count := 0
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if len(inboundPorts) == 0 {
			count++
			continue
		}
		for port := range inboundPorts {
			if strings.Contains(trimmed, fmt.Sprintf(":%d ", port)) || strings.HasSuffix(trimmed, fmt.Sprintf(":%d", port)) {
				count++
				break
			}
		}
	}
	return count
}

func isXrayHandledProtocol(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "hysteria2", "tuic", "shadowtls", "wireguard":
		return false
	default:
		return true
	}
}

// Version runs `xray version` and returns the first line.
func (c *RealController) Version(ctx context.Context) string {
	out, err := c.runCmd(paths.XrayBinary, "version")
	if err != nil {
		return ""
	}
	lines := strings.SplitN(strings.TrimSpace(out), "\n", 2)
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}
