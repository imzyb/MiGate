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

	"github.com/imzyb/MiGate/internal/xray"
)

// CmdRunner runs an external command and returns its stdout + error.
type CmdRunner func(name string, args ...string) (string, error)

// RealController implements XrayController by writing config to disk,
// validating with xray, and restarting the xray systemd service.
type RealController struct {
	store     Store
	configDir string
	runCmd    CmdRunner
}

// NewRealController creates a controller that persists the generated xray
// configuration, validates it, and restarts the xray service.
func NewRealController(store Store, configDir string, runCmd CmdRunner) *RealController {
	return &RealController{store: store, configDir: configDir, runCmd: runCmd}
}

// Status reports whether the xray binary and systemd service appear to be
// running on this host.
func (c *RealController) Status(ctx context.Context) XrayStatus {
	executed := []string{}

	out, err := c.runCmd("systemctl", "is-active", "xray")
	executed = append(executed, "systemctl is-active xray")

	status := "unknown"
	managed := false
	if err == nil {
		managed = true
		status = strings.TrimSpace(out)
		if status == "active" {
			status = "running"
		}
	}

	showOut, showErr := c.runCmd("systemctl", "show", "xray", "--property=MemoryCurrent", "--property=MainPID", "--property=ActiveEnterTimestamp")
	executed = append(executed, "systemctl show xray --property=MemoryCurrent --property=MainPID --property=ActiveEnterTimestamp")
	memoryRSS, uptime := parseXrayServiceStatus(showOut)
	if showErr == nil {
		managed = true
	}

	version := c.Version(ctx)
	if version != "" {
		executed = append(executed, "xray version")
		if hasNoXrayInbounds(ctx, c.store) {
			status = "no_inbounds"
		} else if status == "unknown" {
			status = "not_managed"
		}
	}

	activeConnections := countXrayActiveConnections(ctx, c.store, c.runCmd)
	executed = append(executed, "ss -tn state established")

	return XrayStatus{
		Service:           "xray",
		Status:            status,
		Managed:           managed,
		Installed:         version != "",
		Version:           version,
		MemoryRSSBytes:    memoryRSS,
		Uptime:            uptime,
		ActiveConnections: activeConnections,
		ConfigPath:        filepath.Join(c.configDir, "xray.json"),
		CommandsExecuted:  executed,
	}
}

// Apply reads the current inbounds from the store, builds an xray config,
// writes it to disk, validates it with `xray run -test`, and on success
// restarts the xray systemd service.
func (c *RealController) Apply(ctx context.Context) XrayApplyResult {
	executed := []string{}

	// 1. Build config from store, including managed outbounds and routing rules.
	// The WebUI preview uses BuildConfigWithOutbounds; Apply must use the same
	// builder or Xray will restart with only inbounds and traffic will keep using
	// the implicit direct outbound.
	inbounds, err := c.store.ListInbounds(ctx)
	if err != nil {
		return XrayApplyResult{
			Status:           fmt.Sprintf("failed: read inbounds: %v", err),
			Service:          "xray",
			CommandsExecuted: executed,
		}
	}
	outbounds, err := c.store.ListOutbounds(ctx)
	if err != nil {
		return XrayApplyResult{
			Status:           fmt.Sprintf("failed: read outbounds: %v", err),
			Service:          "xray",
			CommandsExecuted: executed,
		}
	}
	rules, err := c.store.ListRoutingRules(ctx)
	if err != nil {
		return XrayApplyResult{
			Status:           fmt.Sprintf("failed: read routing rules: %v", err),
			Service:          "xray",
			CommandsExecuted: executed,
		}
	}

	cfg, err := xray.BuildConfigWithOutbounds(inbounds, outbounds, rules)
	if err != nil {
		return XrayApplyResult{
			Status:           fmt.Sprintf("failed: build config: %v", err),
			Service:          "xray",
			CommandsExecuted: executed,
		}
	}

	// 2. Write config to disk
	configPath := filepath.Join(c.configDir, "xray.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return XrayApplyResult{
			Status:           fmt.Sprintf("failed: marshal config: %v", err),
			Service:          "xray",
			CommandsExecuted: executed,
		}
	}
	if err := os.MkdirAll(c.configDir, 0755); err != nil {
		return XrayApplyResult{
			Status:           fmt.Sprintf("failed: create config dir: %v", err),
			Service:          "xray",
			CommandsExecuted: executed,
		}
	}
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return XrayApplyResult{
			Status:           fmt.Sprintf("failed: write config: %v", err),
			Service:          "xray",
			CommandsExecuted: executed,
		}
	}
	executed = append(executed, fmt.Sprintf("write %s", configPath))

	// 3. Validate with xray -test
	validateOut, err := c.runCmd("xray", "run", "-test", "-c", configPath)
	executed = append(executed, fmt.Sprintf("xray run -test -c %s", configPath))
	if err != nil {
		return XrayApplyResult{
			Status:           "failed: validation",
			Service:          "xray",
			CommandsExecuted: executed,
			ErrorOutput:      validateOut,
		}
	}

	// 4. Restart xray service
	restartOut, err := c.runCmd("systemctl", "restart", "xray")
	executed = append(executed, "systemctl restart xray")
	if err != nil {
		return XrayApplyResult{
			Status:           "failed: restart",
			Service:          "xray",
			CommandsExecuted: executed,
			ErrorOutput:      restartOut,
		}
	}

	return XrayApplyResult{
		Status:           "applied",
		Service:          "xray",
		CommandsExecuted: executed,
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

func hasNoXrayInbounds(ctx context.Context, store Store) bool {
	if store == nil {
		return false
	}
	inbounds, err := store.ListInbounds(ctx)
	if err != nil {
		return false
	}
	for _, inbound := range inbounds {
		if inbound.Enabled && isXrayHandledProtocol(inbound.Protocol) {
			return false
		}
	}
	return true
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
	out, err := c.runCmd("xray", "version")
	if err != nil {
		return ""
	}
	lines := strings.SplitN(strings.TrimSpace(out), "\n", 2)
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}
