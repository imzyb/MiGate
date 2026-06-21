package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/imzyb/MiGate/internal/panelconfig"
	"github.com/imzyb/MiGate/internal/paths"
)

type Config struct {
	PanelPort     int    `json:"panel_port"`
	PanelUsername string `json:"panel_username"`
	PanelPassword string `json:"panel_password"`
	WebPath       string `json:"web_base_path"`
	PublicHost    string `json:"public_host,omitempty"`
	TrustProxy    bool   `json:"trust_proxy,omitempty"`
	DatabasePath  string `json:"database_path"`
	CertDomain    string `json:"cert_domain,omitempty"`
	CertEmail     string `json:"cert_email,omitempty"`

	ManagementDirectEnabled    bool     `json:"management_direct_enabled"`
	ManagementDirectAutoDetect bool     `json:"management_direct_auto_detect"`
	ManagementDirectHosts      []string `json:"management_direct_hosts,omitempty"`
	ManagementDirectPorts      []int    `json:"management_direct_ports,omitempty"`

	managementDirectEnabledSet    bool
	managementDirectAutoDetectSet bool
}

func Default() Config {
	return Config{
		PanelPort:                     paths.DefaultHTTPPort,
		WebPath:                       "/panel",
		DatabasePath:                  paths.Database,
		ManagementDirectEnabled:       true,
		ManagementDirectAutoDetect:    true,
		managementDirectEnabledSet:    true,
		managementDirectAutoDetectSet: true,
	}
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	_, cfg.managementDirectEnabledSet = raw["management_direct_enabled"]
	_, cfg.managementDirectAutoDetectSet = raw["management_direct_auto_detect"]
	if err := validateManagementDirectPortsRaw(raw); err != nil {
		return Config{}, err
	}
	cfg = NormalizeLoaded(cfg)
	if err := ValidateLoaded(cfg, raw); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
	cfg = Normalize(cfg)
	if err := Validate(cfg); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return panelconfig.WriteFile(path, b)
}

func Normalize(cfg Config) Config {
	defaults := Default()
	if cfg.PanelPort == 0 {
		cfg.PanelPort = defaults.PanelPort
	}
	cfg.PanelUsername = strings.TrimSpace(cfg.PanelUsername)
	cfg.WebPath = normalizeWebPath(cfg.WebPath, defaults.WebPath)
	cfg.PublicHost = strings.TrimSpace(cfg.PublicHost)
	if strings.TrimSpace(cfg.DatabasePath) == "" {
		cfg.DatabasePath = defaults.DatabasePath
	} else {
		cfg.DatabasePath = strings.TrimSpace(cfg.DatabasePath)
	}
	cfg.CertDomain = strings.TrimSpace(cfg.CertDomain)
	cfg.CertEmail = strings.TrimSpace(cfg.CertEmail)
	if !cfg.managementDirectEnabledSet {
		cfg.ManagementDirectEnabled = true
	}
	if !cfg.managementDirectAutoDetectSet {
		cfg.ManagementDirectAutoDetect = true
	}
	cfg.managementDirectEnabledSet = true
	cfg.managementDirectAutoDetectSet = true
	cfg.ManagementDirectHosts = NormalizeManagementDirectHosts(cfg.ManagementDirectHosts)
	cfg.ManagementDirectPorts = NormalizeManagementDirectPorts(cfg.ManagementDirectPorts)
	return cfg
}

func NormalizeLoaded(cfg Config) Config {
	cfg.PanelUsername = strings.TrimSpace(cfg.PanelUsername)
	if strings.TrimSpace(cfg.WebPath) != "" {
		cfg.WebPath = normalizeWebPath(cfg.WebPath, "")
	}
	cfg.PublicHost = strings.TrimSpace(cfg.PublicHost)
	cfg.DatabasePath = strings.TrimSpace(cfg.DatabasePath)
	cfg.CertDomain = strings.TrimSpace(cfg.CertDomain)
	cfg.CertEmail = strings.TrimSpace(cfg.CertEmail)
	if !cfg.managementDirectEnabledSet {
		cfg.ManagementDirectEnabled = true
	}
	if !cfg.managementDirectAutoDetectSet {
		cfg.ManagementDirectAutoDetect = true
	}
	cfg.ManagementDirectHosts = NormalizeManagementDirectHosts(cfg.ManagementDirectHosts)
	cfg.ManagementDirectPorts = NormalizeManagementDirectPorts(cfg.ManagementDirectPorts)
	return cfg
}

func Validate(cfg Config) error {
	if cfg.PanelPort < 1 || cfg.PanelPort > 65535 {
		return fmt.Errorf("panel_port must be between 1 and 65535")
	}
	if strings.TrimSpace(cfg.DatabasePath) == "" {
		return fmt.Errorf("database_path is required")
	}
	if strings.Contains(cfg.DatabasePath, "\x00") {
		return fmt.Errorf("database_path is invalid")
	}
	if !filepath.IsAbs(cfg.DatabasePath) {
		return fmt.Errorf("database_path must be absolute")
	}
	return nil
}

func ValidateLoaded(cfg Config, rawFields ...map[string]json.RawMessage) error {
	panelPortPresent := false
	if len(rawFields) > 0 && rawFields[0] != nil {
		_, panelPortPresent = rawFields[0]["panel_port"]
	}
	if cfg.PanelPort < 0 || cfg.PanelPort > 65535 || (panelPortPresent && cfg.PanelPort == 0) {
		return fmt.Errorf("panel_port must be between 1 and 65535")
	}
	if cfg.DatabasePath != "" {
		if strings.Contains(cfg.DatabasePath, "\x00") {
			return fmt.Errorf("database_path is invalid")
		}
		if !filepath.IsAbs(cfg.DatabasePath) {
			return fmt.Errorf("database_path must be absolute")
		}
	}
	for _, port := range cfg.ManagementDirectPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("management_direct_ports must be between 1 and 65535")
		}
	}
	return nil
}

func validateManagementDirectPortsRaw(raw map[string]json.RawMessage) error {
	if raw == nil {
		return nil
	}
	value, ok := raw["management_direct_ports"]
	if !ok {
		return nil
	}
	var ports []int
	if err := json.Unmarshal(value, &ports); err != nil {
		return fmt.Errorf("management_direct_ports must be an array of ports")
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("management_direct_ports must be between 1 and 65535")
		}
	}
	return nil
}

func ManagementDirectTargets(cfg Config) (hosts []string, ports []int) {
	hostValues := []string{}
	if cfg.ManagementDirectAutoDetect {
		hostValues = append(hostValues, cfg.PublicHost, cfg.CertDomain)
	}
	hostValues = append(hostValues, cfg.ManagementDirectHosts...)
	hosts = NormalizeManagementDirectHosts(hostValues)
	portValues := []int{cfg.PanelPort}
	portValues = append(portValues, cfg.ManagementDirectPorts...)
	ports = NormalizeManagementDirectPorts(portValues)
	return hosts, ports
}

func NormalizeManagementDirectHosts(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		host := normalizeManagementDirectHost(value)
		if host == "" {
			continue
		}
		key := strings.ToLower(host)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, host)
	}
	return out
}

func NormalizeManagementDirectPorts(values []int) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, port := range values {
		if port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

func normalizeManagementDirectHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			value = parsed.Host
		}
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	} else if strings.Count(value, ":") == 1 {
		if idx := strings.LastIndex(value, ":"); idx > 0 {
			if _, err := strconv.Atoi(value[idx+1:]); err == nil {
				value = value[:idx]
			}
		}
	}
	value = strings.Trim(value, "[] \t\r\n")
	if value == "" {
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return strings.ToLower(value)
}

func Update(path string, mutate func(Config) (Config, error)) (Config, error) {
	cfg, err := Load(path)
	if err != nil {
		return Config{}, err
	}
	cfg, err = mutate(cfg)
	if err != nil {
		return Config{}, err
	}
	cfg = Normalize(cfg)
	return cfg, Save(path, cfg)
}

func EnsureManagementDirectDefaults(path string, hosts []string, ports []int) (Config, error) {
	return Update(path, func(cfg Config) (Config, error) {
		if !cfg.managementDirectEnabledSet {
			cfg.ManagementDirectEnabled = true
		}
		if !cfg.managementDirectAutoDetectSet {
			cfg.ManagementDirectAutoDetect = true
		}
		if cfg.ManagementDirectAutoDetect {
			cfg.ManagementDirectHosts = append(cfg.ManagementDirectHosts, hosts...)
			cfg.ManagementDirectPorts = append(cfg.ManagementDirectPorts, ports...)
		}
		return cfg, nil
	})
}

func (cfg *Config) SetManagementDirectEnabled(enabled bool) {
	cfg.ManagementDirectEnabled = enabled
	cfg.managementDirectEnabledSet = true
}

func (cfg *Config) SetManagementDirectAutoDetect(enabled bool) {
	cfg.ManagementDirectAutoDetect = enabled
	cfg.managementDirectAutoDetectSet = true
}

func LoadCertFields(path string) (domain, email string, err error) {
	cfg, err := Load(path)
	if err != nil {
		return "", "", err
	}
	return cfg.CertDomain, cfg.CertEmail, nil
}

func normalizeWebPath(path, fallback string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		path = fallback
	}
	if path == "/" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(path, "/")
}
