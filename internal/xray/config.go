package xray

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"

	panelcfg "github.com/imzyb/MiGate/internal/config"
	"github.com/imzyb/MiGate/internal/db"
)

const SystemDirectOutboundTag = "migate-system-direct"

type Config struct {
	Log       LogConfig        `json:"log"`
	Inbounds  []InboundConfig  `json:"inbounds"`
	Outbounds []OutboundConfig `json:"outbounds"`
	Routing   *RoutingConfig   `json:"routing,omitempty"`
	Stats     *StatsConfig     `json:"stats,omitempty"`
	Policy    *PolicyConfig    `json:"policy,omitempty"`
	API       *APIConfig       `json:"api,omitempty"`
}

type StatsConfig struct{}

type APIConfig struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services"`
}

type PolicyConfig struct {
	Levels map[string]PolicyLevel `json:"levels"`
}

type PolicyLevel struct {
	StatsUserUplink   bool `json:"statsUserUplink"`
	StatsUserDownlink bool `json:"statsUserDownlink"`
}

type RoutingConfig struct {
	DomainStrategy string        `json:"domainStrategy"`
	Rules          []RoutingRule `json:"rules"`
	Balancers      []Balancer    `json:"balancers,omitempty"`
}

type Balancer struct {
	Tag      string   `json:"tag"`
	Selector []string `json:"selector"`
}

type RoutingRule struct {
	InboundTag  []string `json:"inboundTag,omitempty"`
	User        []string `json:"user,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	Protocol    []string `json:"protocol,omitempty"`
	OutboundTag string   `json:"outboundTag,omitempty"`
	BalancerTag string   `json:"balancerTag,omitempty"`
}

type BuildOptions struct {
	ManagementDirect ManagementDirectOptions
}

type ManagementDirectOptions struct {
	Enabled bool
	Hosts   []string
	Ports   []int
}

type LogConfig struct {
	LogLevel string `json:"loglevel"`
}

type InboundConfig struct {
	Tag            string                 `json:"tag"`
	Listen         string                 `json:"listen"`
	Port           int                    `json:"port"`
	Protocol       string                 `json:"protocol"`
	Settings       map[string]interface{} `json:"settings"`
	StreamSettings map[string]interface{} `json:"streamSettings,omitempty"`
}

type OutboundConfig struct {
	Tag            string                 `json:"tag"`
	Protocol       string                 `json:"protocol"`
	Settings       map[string]interface{} `json:"settings"`
	StreamSettings map[string]interface{} `json:"streamSettings,omitempty"`
}

func BuildConfig(inbounds []db.Inbound) (Config, error) {
	config := Config{
		Log:      LogConfig{LogLevel: "warning"},
		Inbounds: []InboundConfig{},
		Outbounds: []OutboundConfig{{
			Tag:      "xray-out-0",
			Protocol: "freedom",
			Settings: map[string]interface{}{},
		}},
		Stats:  &StatsConfig{},
		Policy: enableUserStats(),
		API:    enableStatsAPI(),
	}
	config, err := appendInbounds(config, inbounds)
	if err != nil {
		return Config{}, err
	}
	return appendStatsAPIInbound(config), nil
}

func BuildConfigWithOutbounds(inbounds []db.Inbound, outbounds []db.Outbound, routingRules []db.RoutingRule) (Config, error) {
	return BuildConfigWithOutboundsOptions(inbounds, outbounds, routingRules, BuildOptions{})
}

func BuildConfigWithOutboundsOptions(inbounds []db.Inbound, outbounds []db.Outbound, routingRules []db.RoutingRule, opts BuildOptions) (Config, error) {
	config := Config{
		Log:       LogConfig{LogLevel: "warning"},
		Inbounds:  []InboundConfig{},
		Outbounds: []OutboundConfig{},
		Stats:     &StatsConfig{},
		Policy:    enableUserStats(),
		API:       enableStatsAPI(),
	}
	config, err := appendInbounds(config, inbounds)
	if err != nil {
		return Config{}, err
	}
	for _, ob := range outbounds {
		if !ob.Enabled || !db.OutboundSupportsCore(ob, db.CoreXray) {
			continue
		}
		built, err := buildOutbound(ob)
		if err != nil {
			return Config{}, err
		}
		config.Outbounds = append(config.Outbounds, built)
	}
	if len(config.Outbounds) == 0 {
		config.Outbounds = append(config.Outbounds, OutboundConfig{
			Tag: "xray-out-0", Protocol: "freedom", Settings: map[string]interface{}{},
		})
	}
	systemRules := xraySystemRoutingRules(opts.ManagementDirect)
	if len(systemRules) > 0 {
		config.Outbounds = ensureXraySystemDirectOutbound(config.Outbounds)
	}
	if len(routingRules) > 0 {
		inboundTagsByID := map[int64]string{}
		inboundTagAliases := map[string]string{}
		clientsByID := map[int64]db.Client{}
		for _, inbound := range inbounds {
			if !inbound.Enabled {
				continue
			}
			if db.InboundCore(inbound) != db.CoreXray {
				continue
			}
			actualTag := db.GeneratedInboundTag(inbound)
			inboundTagsByID[inbound.ID] = actualTag
			if strings.TrimSpace(inbound.Remark) != "" {
				inboundTagAliases[strings.TrimSpace(inbound.Remark)] = actualTag
			}
			inboundTagAliases[actualTag] = actualTag
			for _, client := range inbound.Clients {
				if !client.Enabled || strings.TrimSpace(client.Email) == "" {
					continue
				}
				clientsByID[client.ID] = client
			}
		}
		r := &RoutingConfig{DomainStrategy: "AsIs", Rules: append([]RoutingRule{}, systemRules...)}
		for _, rule := range routingRules {
			if !rule.Enabled {
				continue
			}
			if !db.RoutingRuleAppliesToCore(rule, inbounds, db.CoreXray) {
				continue
			}
			outbound, ok := db.ResolveRuleOutbound(rule, outbounds)
			if !ok {
				return Config{}, fmt.Errorf("routing rule %d targets missing outbound profile", rule.ID)
			}
			if !db.OutboundSupportsCore(outbound, db.CoreXray) {
				return Config{}, fmt.Errorf("routing rule %d targets outbound %q that does not support xray", rule.ID, outbound.Tag)
			}
			xr := RoutingRule{}
			xr.OutboundTag = db.GeneratedOutboundTag(db.CoreXray, outbound.ID, rule.OutboundTag)
			if rule.ClientID > 0 {
				client, ok := clientsByID[rule.ClientID]
				if !ok || strings.TrimSpace(clientStatsName(client)) == "" {
					continue
				}
				xr.User = []string{clientStatsName(client)}
			}
			if rule.InboundID > 0 {
				if actual, ok := inboundTagsByID[rule.InboundID]; ok {
					xr.InboundTag = []string{actual}
				} else {
					continue
				}
			} else if inboundTag := strings.TrimSpace(rule.InboundTag); inboundTag != "" {
				if actual, ok := inboundTagAliases[inboundTag]; ok {
					xr.InboundTag = []string{actual}
				} else {
					continue
				}
			}
			if rule.Domain != "" {
				xr.Domain = splitRuleValues(rule.Domain)
			}
			if rule.IP != "" {
				xr.IP = splitRuleValues(rule.IP)
			}
			if rule.Protocol != "" {
				xr.Protocol = splitRuleValues(rule.Protocol)
			}
			r.Rules = append(r.Rules, xr)
		}
		if len(r.Rules) > 0 {
			config.Routing = r
		}
	} else if len(systemRules) > 0 {
		config.Routing = &RoutingConfig{DomainStrategy: "AsIs", Rules: systemRules}
	}
	return appendStatsAPIInbound(config), nil
}

func ensureXraySystemDirectOutbound(outbounds []OutboundConfig) []OutboundConfig {
	system := OutboundConfig{Tag: SystemDirectOutboundTag, Protocol: "freedom", Settings: map[string]interface{}{}}
	for i, outbound := range outbounds {
		if outbound.Tag == SystemDirectOutboundTag {
			outbounds[i] = system
			return outbounds
		}
	}
	return append(outbounds, system)
}

func xraySystemRoutingRules(opts ManagementDirectOptions) []RoutingRule {
	if !opts.Enabled {
		return nil
	}
	hosts := panelcfg.NormalizeManagementDirectHosts(opts.Hosts)
	ports := panelcfg.NormalizeManagementDirectPorts(opts.Ports)
	if len(hosts) == 0 || len(ports) == 0 {
		return nil
	}
	domains := []string{}
	ips := []string{}
	for _, host := range hosts {
		if isCIDROrIP(host) {
			ips = append(ips, host)
		} else {
			domains = append(domains, host)
		}
	}
	port := joinPorts(ports)
	rules := []RoutingRule{}
	if len(ips) > 0 {
		rules = append(rules, RoutingRule{IP: ips, Port: port, OutboundTag: SystemDirectOutboundTag})
	}
	if len(domains) > 0 {
		rules = append(rules, RoutingRule{Domain: domains, Port: port, OutboundTag: SystemDirectOutboundTag})
	}
	return rules
}

func splitRuleValues(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t'
	})
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port))
	}
	return strings.Join(parts, ",")
}

func isCIDROrIP(value string) bool {
	if net.ParseIP(value) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

// enableUserStats returns a PolicyConfig that enables per-client traffic stats.
func enableStatsAPI() *APIConfig {
	return &APIConfig{Tag: "api", Services: []string{"StatsService"}}
}

func appendStatsAPIInbound(config Config) Config {
	config.Inbounds = append(config.Inbounds, InboundConfig{
		Tag: "api", Listen: "127.0.0.1", Port: 10085, Protocol: "dokodemo-door",
		Settings: map[string]interface{}{"address": "127.0.0.1"},
	})
	if config.Routing == nil {
		config.Routing = &RoutingConfig{DomainStrategy: "AsIs", Rules: []RoutingRule{}}
	}
	apiRule := RoutingRule{InboundTag: []string{"api"}, OutboundTag: "api"}
	config.Routing.Rules = append([]RoutingRule{apiRule}, config.Routing.Rules...)
	return config
}

func enableUserStats() *PolicyConfig {
	return &PolicyConfig{
		Levels: map[string]PolicyLevel{
			"0": {
				StatsUserUplink:   true,
				StatsUserDownlink: true,
			},
		},
	}
}

func appendInbounds(config Config, inbounds []db.Inbound) (Config, error) {
	for _, inbound := range inbounds {
		if !inbound.Enabled {
			continue
		}
		if db.InboundCore(inbound) != db.CoreXray {
			continue
		}
		built, err := buildInbound(inbound)
		if err != nil {
			return Config{}, err
		}
		config.Inbounds = append(config.Inbounds, built)
	}
	return config, nil
}

func buildInbound(inbound db.Inbound) (InboundConfig, error) {
	protocol := strings.ToLower(strings.TrimSpace(inbound.Protocol))
	if inbound.Port <= 0 || inbound.Port > 65535 {
		return InboundConfig{}, fmt.Errorf("invalid inbound port: %d", inbound.Port)
	}

	clients := enabledClients(inbound.Clients)

	base := InboundConfig{
		Tag:            db.GeneratedInboundTag(inbound),
		Listen:         "0.0.0.0",
		Port:           inbound.Port,
		Protocol:       protocol,
		StreamSettings: buildStreamSettings(inbound),
	}

	switch protocol {
	case "vless":
		flow := ""
		if strings.ToLower(strings.TrimSpace(inbound.Security)) == "reality" && strings.ToLower(strings.TrimSpace(inbound.Network)) != "xhttp" {
			flow = "xtls-rprx-vision"
		}
		base.Settings = map[string]interface{}{
			"clients":    clientsAsIDEmail(clients, flow),
			"decryption": "none",
		}
	case "vmess":
		base.Settings = map[string]interface{}{
			"clients": clientsAsAlterIDEmail(clients),
		}
	case "trojan":
		base.Settings = map[string]interface{}{
			"clients": clientsAsPasswordEmail(clients),
		}
	case "shadowsocks":
		ssMethod := "2022-blake3-aes-128-gcm"
		if inbound.SSMethod != "" {
			ssMethod = inbound.SSMethod
		}
		password := SSInboundPassword(ssMethod, inbound.UUID)
		base.Settings = map[string]interface{}{
			"method":   ssMethod,
			"password": password,
			// Xray Shadowsocks only supports single-user mode (no "clients" array)
		}
	case "socks":
		base.StreamSettings = nil
		base.Settings = map[string]interface{}{
			"auth":     "password",
			"accounts": clientsAsUserPass(clients),
			"udp":      true,
		}
	case "http":
		base.StreamSettings = nil
		base.Settings = map[string]interface{}{
			"accounts": clientsAsUserPass(clients),
		}
	default:
		return InboundConfig{}, fmt.Errorf("unsupported protocol: %s", inbound.Protocol)
	}
	return base, nil
}

func enabledClients(clients []db.Client) []db.Client {
	result := make([]db.Client, 0, len(clients))
	for _, client := range clients {
		if client.Enabled {
			result = append(result, client)
		}
	}
	return result
}

// ss2022Key generates a proper base64-encoded key for SS 2022 ciphers.
// For 2022-blake3-aes-128-gcm (16-byte key), for 2022-blake3-aes-256-gcm (32-byte key).
// Non-2022 ciphers fall back to the inbound UUID.
func SSInboundPassword(method string, fallback string) string {
	if !strings.HasPrefix(method, "2022-blake3") {
		return fallback
	}
	var keySize int
	switch {
	case strings.Contains(method, "aes-128"):
		keySize = 16
	case strings.Contains(method, "aes-256"):
		keySize = 32
	default:
		// For unknown 2022 variants, default to 16 bytes
		keySize = 16
	}
	seed := strings.TrimSpace(fallback)
	if seed == "" {
		return fallback
	}
	sum := sha256.Sum256([]byte(method + ":" + seed))
	return base64.StdEncoding.EncodeToString(sum[:keySize])
}

func ss2022Key(method string, fallback string) string {
	return SSInboundPassword(method, fallback)
}

func clientsAsIDEmail(clients []db.Client, flow string) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(clients))
	for _, client := range clients {
		entry := map[string]interface{}{
			"id":    client.CredentialIDValue(),
			"email": clientStatsName(client),
		}
		if flow != "" {
			entry["flow"] = flow
		}
		result = append(result, entry)
	}
	return result
}

func clientsAsAlterIDEmail(clients []db.Client) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(clients))
	for _, client := range clients {
		result = append(result, map[string]interface{}{
			"id":      client.CredentialIDValue(),
			"email":   clientStatsName(client),
			"alterId": 0,
		})
	}
	return result
}

func clientsAsPasswordEmail(clients []db.Client) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(clients))
	for _, client := range clients {
		result = append(result, map[string]interface{}{
			"password": client.PasswordValue(),
			"email":    clientStatsName(client),
		})
	}
	return result
}

func clientsAsUserPass(clients []db.Client) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(clients))
	for _, client := range clients {
		result = append(result, map[string]interface{}{
			"user": client.CredentialIDValue(),
			"pass": client.PasswordValue(),
		})
	}
	return result
}

func clientStatsName(client db.Client) string {
	if strings.TrimSpace(client.StatsKey) != "" {
		return strings.TrimSpace(client.StatsKey)
	}
	return strings.TrimSpace(client.Email)
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func buildStreamSettings(inbound db.Inbound) map[string]interface{} {
	network := strings.ToLower(strings.TrimSpace(inbound.Network))
	security := strings.ToLower(strings.TrimSpace(inbound.Security))
	if network == "" {
		network = "tcp"
	}
	if security == "" {
		security = "none"
	}
	settings := map[string]interface{}{
		"network":  network,
		"security": security,
	}
	if network == "ws" {
		wsSettings := map[string]interface{}{"path": "/"}
		if inbound.WsPath != "" {
			wsSettings["path"] = inbound.WsPath
		}
		if inbound.WsHost != "" {
			wsSettings["host"] = inbound.WsHost
		}
		settings["wsSettings"] = wsSettings
	}
	if network == "h2" {
		httpSettings := map[string]interface{}{"path": "/"}
		if inbound.WsPath != "" {
			httpSettings["path"] = inbound.WsPath
		}
		if inbound.WsHost != "" {
			httpSettings["host"] = splitCSV(inbound.WsHost)
		}
		settings["httpSettings"] = httpSettings
	}
	if network == "grpc" {
		grpcSettings := map[string]interface{}{"serviceName": "migate"}
		if inbound.GrpcServiceName != "" {
			grpcSettings["serviceName"] = inbound.GrpcServiceName
		}
		settings["grpcSettings"] = grpcSettings
	}
	if network == "xhttp" {
		xhttpSettings := map[string]interface{}{
			"path": "/",
			"mode": "stream-one",
		}
		if inbound.XHTTPPath != "" {
			xhttpSettings["path"] = inbound.XHTTPPath
		}
		if inbound.XHTTPMode != "" {
			xhttpSettings["mode"] = inbound.XHTTPMode
		}
		settings["xhttpSettings"] = xhttpSettings
	}
	if security == "reality" {
		dest := "www.cloudflare.com:443"
		if inbound.RealityDest != "" {
			dest = inbound.RealityDest
		}
		serverNames := []string{"www.cloudflare.com"}
		if inbound.RealityServerNames != "" {
			serverNames = splitCSV(inbound.RealityServerNames)
		}
		shortIds := []string{""}
		if inbound.RealityShortID != "" {
			shortIds = []string{inbound.RealityShortID}
		}
		realitySettings := map[string]interface{}{
			"show":        false,
			"dest":        dest,
			"serverNames": serverNames,
		}
		realitySettings["shortIds"] = shortIds
		if inbound.RealityPrivateKey != "" {
			realitySettings["privateKey"] = inbound.RealityPrivateKey
		}
		if inbound.TLSFingerprint != "" {
			realitySettings["fingerprint"] = inbound.TLSFingerprint
		}
		settings["realitySettings"] = realitySettings
	}
	if security == "tls" {
		tlsSettings := map[string]interface{}{}
		if inbound.TLSCertFile != "" && inbound.TLSKeyFile != "" {
			tlsSettings["certificates"] = []map[string]interface{}{
				{
					"certificateFile": inbound.TLSCertFile,
					"keyFile":         inbound.TLSKeyFile,
				},
			}
		}
		if inbound.TLSSNI != "" {
			tlsSettings["serverName"] = inbound.TLSSNI
		}
		if inbound.TLSFingerprint != "" {
			tlsSettings["fingerprint"] = inbound.TLSFingerprint
		}
		if inbound.TLSALPN != "" {
			alpn := splitCSV(inbound.TLSALPN)
			if len(alpn) > 0 {
				tlsSettings["alpn"] = alpn
			}
		}
		if len(tlsSettings) > 0 {
			settings["tlsSettings"] = tlsSettings
		}
	}
	return settings
}

func buildHy2StreamSettings(inbound db.Inbound) map[string]interface{} {
	security := strings.ToLower(strings.TrimSpace(inbound.Security))
	if security == "" {
		security = "none"
	}
	settings := map[string]interface{}{
		"security": security,
	}
	if security == "tls" {
		tlsSettings := map[string]interface{}{}
		if inbound.TLSCertFile != "" && inbound.TLSKeyFile != "" {
			tlsSettings["certificates"] = []map[string]interface{}{
				{
					"certificateFile": inbound.TLSCertFile,
					"keyFile":         inbound.TLSKeyFile,
				},
			}
		}
		if inbound.TLSSNI != "" {
			tlsSettings["serverName"] = inbound.TLSSNI
		}
		if inbound.TLSFingerprint != "" {
			tlsSettings["fingerprint"] = inbound.TLSFingerprint
		}
		if inbound.TLSALPN != "" {
			alpnParts := strings.Split(inbound.TLSALPN, ",")
			alpn := make([]string, 0, len(alpnParts))
			for _, p := range alpnParts {
				trimmed := strings.TrimSpace(p)
				if trimmed != "" {
					alpn = append(alpn, trimmed)
				}
			}
			if len(alpn) > 0 {
				tlsSettings["alpn"] = alpn
			}
		}
		if len(tlsSettings) > 0 {
			settings["tlsSettings"] = tlsSettings
		}
	}
	return settings
}

func buildOutbound(ob db.Outbound) (OutboundConfig, error) {
	protocol := db.NormalizeOutboundProtocol(ob.Protocol)
	tag := db.GeneratedOutboundTag(db.CoreXray, ob.ID, ob.Tag)
	if err := db.ValidateOutboundProfile(ob); err != nil {
		return OutboundConfig{}, err
	}
	switch protocol {
	case "freedom":
		return OutboundConfig{
			Tag:      tag,
			Protocol: "freedom",
			Settings: map[string]interface{}{},
		}, nil
	case "blackhole":
		return OutboundConfig{
			Tag:      tag,
			Protocol: "blackhole",
			Settings: map[string]interface{}{},
		}, nil
	case "dns":
		return OutboundConfig{
			Tag:      tag,
			Protocol: "dns",
			Settings: map[string]interface{}{},
		}, nil
	case "socks":
		users := []map[string]interface{}{}
		user := strings.TrimSpace(ob.Username)
		pass := ob.Password
		if user != "" {
			entry := map[string]interface{}{"user": user}
			if pass != "" {
				entry["pass"] = pass
			}
			users = append(users, entry)
		}
		servers := []map[string]interface{}{{
			"address": ob.Address,
			"port":    ob.Port,
		}}
		if len(users) > 0 {
			servers[0]["users"] = users
		}
		return OutboundConfig{
			Tag:      tag,
			Protocol: protocol,
			Settings: map[string]interface{}{"servers": servers},
		}, nil
	case "http", "https":
		users := []map[string]interface{}{}
		user := strings.TrimSpace(ob.Username)
		pass := ob.Password
		if user != "" {
			entry := map[string]interface{}{"user": user}
			if pass != "" {
				entry["pass"] = pass
			}
			users = append(users, entry)
		}
		servers := []map[string]interface{}{{
			"address": ob.Address,
			"port":    ob.Port,
		}}
		if len(users) > 0 {
			servers[0]["users"] = users
		}
		return OutboundConfig{
			Tag:      tag,
			Protocol: "http",
			Settings: map[string]interface{}{"servers": servers},
		}, nil
	case "vless":
		outboundSettings := db.ParseOutboundSettings(ob.SettingsJSON)
		user := map[string]interface{}{
			"id":         strings.TrimSpace(ob.Username),
			"encryption": "none",
		}
		if strings.TrimSpace(outboundSettings.Flow) != "" {
			user["flow"] = strings.TrimSpace(outboundSettings.Flow)
		}
		vnext := []map[string]interface{}{{
			"address": ob.Address,
			"port":    ob.Port,
			"users":   []map[string]interface{}{user},
		}}
		return OutboundConfig{Tag: tag, Protocol: "vless", Settings: map[string]interface{}{"vnext": vnext}, StreamSettings: buildOutboundStreamSettings(outboundSettings)}, nil
	case "trojan":
		outboundSettings := db.ParseOutboundSettings(ob.SettingsJSON)
		servers := []map[string]interface{}{{
			"address":  ob.Address,
			"port":     ob.Port,
			"password": firstNonEmpty(ob.Password, ob.Username),
		}}
		return OutboundConfig{Tag: tag, Protocol: "trojan", Settings: map[string]interface{}{"servers": servers}, StreamSettings: buildOutboundStreamSettings(outboundSettings)}, nil
	case "shadowsocks":
		outboundSettings := db.ParseOutboundSettings(ob.SettingsJSON)
		servers := []map[string]interface{}{{
			"address":  ob.Address,
			"port":     ob.Port,
			"method":   firstNonEmpty(ob.Username, outboundSettings.Method, "aes-128-gcm"),
			"password": ob.Password,
		}}
		return OutboundConfig{Tag: tag, Protocol: "shadowsocks", Settings: map[string]interface{}{"servers": servers}, StreamSettings: buildOutboundStreamSettings(outboundSettings)}, nil
	default:
		return OutboundConfig{}, fmt.Errorf("unsupported outbound protocol: %s", ob.Protocol)
	}
}

func buildOutboundStreamSettings(settings db.OutboundSettings) map[string]interface{} {
	network := strings.ToLower(strings.TrimSpace(settings.Network))
	security := strings.ToLower(strings.TrimSpace(settings.Security))
	if security == "" {
		if settings.Reality {
			security = "reality"
		} else if settings.TLS {
			security = "tls"
		}
	}
	if network == "" && security == "" {
		return nil
	}
	if network == "" {
		network = "tcp"
	}
	stream := map[string]interface{}{"network": network}
	if security != "" && security != "none" {
		stream["security"] = security
	}
	switch network {
	case "ws", "websocket":
		wsSettings := map[string]interface{}{}
		if settings.Path != "" {
			wsSettings["path"] = settings.Path
		}
		if settings.Host != "" {
			wsSettings["headers"] = map[string]interface{}{"Host": settings.Host}
		}
		if len(wsSettings) > 0 {
			stream["wsSettings"] = wsSettings
		}
	case "grpc":
		grpcSettings := map[string]interface{}{}
		if settings.ServiceName != "" {
			grpcSettings["serviceName"] = settings.ServiceName
		}
		if len(grpcSettings) > 0 {
			stream["grpcSettings"] = grpcSettings
		}
	}
	if security == "tls" {
		tlsSettings := map[string]interface{}{}
		if settings.SNI != "" {
			tlsSettings["serverName"] = settings.SNI
		}
		if settings.Fingerprint != "" {
			tlsSettings["fingerprint"] = settings.Fingerprint
		}
		if len(settings.ALPN) > 0 {
			tlsSettings["alpn"] = settings.ALPN
		}
		if settings.AllowInsecure {
			tlsSettings["allowInsecure"] = true
		}
		if len(tlsSettings) > 0 {
			stream["tlsSettings"] = tlsSettings
		}
	}
	if security == "reality" {
		realitySettings := map[string]interface{}{}
		if settings.SNI != "" {
			realitySettings["serverName"] = settings.SNI
		}
		if settings.Fingerprint != "" {
			realitySettings["fingerprint"] = settings.Fingerprint
		}
		if settings.PublicKey != "" {
			realitySettings["publicKey"] = settings.PublicKey
		}
		if settings.ShortID != "" {
			realitySettings["shortId"] = settings.ShortID
		}
		if len(realitySettings) > 0 {
			stream["realitySettings"] = realitySettings
		}
	}
	return stream
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
