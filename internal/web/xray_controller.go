package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/imzyb/MiGate/internal/xray"
)

// CmdRunner runs an external command and returns its stdout + error.
type CmdRunner func(name string, args ...string) (string, error)

// RealController implements XrayController by writing config to disk,
// validating with xray, and restarting the xray systemd service.
type RealController struct {
	store      Store
	configDir  string
	runCmd     CmdRunner
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

	return XrayStatus{
		Service:          "xray",
		Status:           status,
		Managed:          managed,
		CommandsExecuted: executed,
	}
}

// Apply reads the current inbounds from the store, builds an xray config,
// writes it to disk, validates it with `xray run -test`, and on success
// restarts the xray systemd service.
func (c *RealController) Apply(ctx context.Context) XrayApplyResult {
	executed := []string{}

	// 1. Build config from store
	inbounds, err := c.store.ListInbounds(ctx)
	if err != nil {
		return XrayApplyResult{
			Status:           fmt.Sprintf("failed: read inbounds: %v", err),
			Service:          "xray",
			CommandsExecuted: executed,
		}
	}

	cfg, err := xray.BuildConfig(inbounds)
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