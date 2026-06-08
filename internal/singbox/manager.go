package singbox

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var (
	// DefaultBinaryPath is the default location for the sing-box binary.
	DefaultBinaryPath = "/usr/local/bin/sing-box"
	// DefaultConfigDir is the default directory for sing-box config and certs.
	DefaultConfigDir = "/etc/sing-box"
	// DefaultConfigPath is the default sing-box config file path.
	DefaultConfigPath = "/etc/sing-box/config.json"
	// CertFile is the auto-generated self-signed certificate path.
	CertFile = "/etc/sing-box/server.crt"
	// KeyFile is the auto-generated self-signed key path.
	KeyFile = "/etc/sing-box/server.key"
	// SBBasePort is the starting port for sing-box inbounds (21000-21999).
	SBBasePort = 21000
	// SBMaxPort is the max port for sing-box inbounds.
	SBMaxPort = 21999
)

// IsInstalled returns true if the sing-box binary exists.
func IsInstalled() bool {
	_, err := os.Stat(DefaultBinaryPath)
	return err == nil
}

// CheckConfigDir ensures the config directory exists.
func CheckConfigDir() error {
	return os.MkdirAll(DefaultConfigDir, 0755)
}

// Version returns the sing-box version string.
func Version() (string, error) {
	if !IsInstalled() {
		return "", fmt.Errorf("sing-box not installed")
	}
	out, err := exec.Command(DefaultBinaryPath, "version").Output()
	if err != nil {
		return "", fmt.Errorf("sing-box version: %w", err)
	}
	return NormalizeVersion(string(out)), nil
}

// NormalizeVersion keeps the compact user-facing sing-box version line and
// drops verbose build metadata such as "Tags:" and later lines.
func NormalizeVersion(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Tags:") {
			continue
		}
		return line
	}
	return strings.TrimSpace(raw)
}

// CheckConfig validates the config file with sing-box.
func CheckConfig() error {
	out, err := exec.Command(DefaultBinaryPath, "check", "-c", DefaultConfigPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box config check failed: %s: %w", string(out), err)
	}
	return nil
}

// Status returns "running" if the service is active, "stopped" otherwise.
func Status() string {
	out, err := ServiceStatus()
	if err != nil {
		return "stopped"
	}
	status := strings.TrimSpace(string(out))
	switch status {
	case "active", "activating":
		return "running"
	default:
		return "stopped"
	}
}

// Apply writes the config file, checks config validity, and restarts the service.
func Apply() error {
	if err := CheckConfig(); err != nil {
		return fmt.Errorf("config check failed: %w", err)
	}
	_, err := RestartService()
	return err
}

// ServiceName returns the systemd service name.
func ServiceName() string {
	return "migate-singbox"
}

// RestartService restarts the systemd service.
func RestartService() (string, error) {
	cmd := exec.Command("systemctl", "restart", ServiceName())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("systemctl restart %s failed: %w", ServiceName(), err)
	}
	return string(out), nil
}

// ServiceStatus returns the systemd service status.
func ServiceStatus() (string, error) {
	cmd := exec.Command("systemctl", "is-active", ServiceName())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemctl is-active %s failed: %w", ServiceName(), err)
	}
	return string(out), nil
}

// ConfigPath returns the full path for a given config file name.
func ConfigPath() string {
	return DefaultConfigPath
}

// NextPort finds the next available port for a new sing-box inbound.
// Returns SBBasePort + count, clamped to SBMaxPort.
func NextPort(count int) int {
	port := SBBasePort + count
	if port > SBMaxPort {
		port = SBMaxPort
	}
	return port
}

// ServiceProperties holds parsed systemctl show data for the sing-box service.
type ServiceProperties struct {
	MemoryRSS                     int64
	MainPID                       int64
	ActiveEnterTimestamp          string
	ActiveEnterTimestampMonotonic int64
}

// Show returns parsed systemd service properties via systemctl show.
func Show() (*ServiceProperties, error) {
	cmd := exec.Command("systemctl", "show", ServiceName(),
		"--property=MemoryCurrent",
		"--property=MainPID",
		"--property=ActiveEnterTimestamp",
		"--property=ActiveEnterTimestampMonotonic")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("systemctl show: %w", err)
	}
	props := &ServiceProperties{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "MemoryCurrent=") {
			val := strings.TrimPrefix(line, "MemoryCurrent=")
			props.MemoryRSS, _ = strconv.ParseInt(val, 10, 64)
		} else if strings.HasPrefix(line, "MainPID=") {
			val := strings.TrimPrefix(line, "MainPID=")
			props.MainPID, _ = strconv.ParseInt(val, 10, 64)
		} else if strings.HasPrefix(line, "ActiveEnterTimestamp=") {
			props.ActiveEnterTimestamp = strings.TrimPrefix(line, "ActiveEnterTimestamp=")
		}
	}
	return props, nil
}

// MemoryRSS returns the current RSS memory usage in bytes.
func MemoryRSS() int64 {
	props, err := Show()
	if err != nil {
		return 0
	}
	return props.MemoryRSS
}

// Uptime returns a human-readable uptime string (e.g. "2h15m").
func Uptime() string {
	props, err := Show()
	if err != nil {
		return "未知"
	}
	ts := props.ActiveEnterTimestamp
	if ts == "" {
		return "未知"
	}
	layout := "Mon 2006-01-02 15:04:05 MST"
	t, err := time.Parse(layout, ts)
	if err != nil {
		return "未知"
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

// ActiveConnections returns the number of established TCP connections
// to sing-box ports (21000-21999 range) via ss.
func ActiveConnections() int {
	out, err := exec.Command("ss", "-tn", "state", "established").CombinedOutput()
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		for port := SBBasePort; port <= SBMaxPort; port++ {
			if strings.Contains(line, fmt.Sprintf(":%d ", port)) ||
				strings.HasSuffix(strings.TrimSpace(line), fmt.Sprintf(":%d", port)) {
				count++
				break
			}
		}
	}
	return count
}
