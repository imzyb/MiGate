package singbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	panelcfg "github.com/imzyb/MiGate/internal/config"
	"github.com/imzyb/MiGate/internal/db"
)

const SystemDirectOutboundTag = "migate-system-direct"

// Config is the top-level sing-box configuration.
type Config struct {
	Log          LogConfig           `json:"log"`
	Inbounds     []InboundConfig     `json:"inbounds"`
	Outbounds    []OutboundConfig    `json:"outbounds"`
	Route        *RouteConfig        `json:"route,omitempty"`
	Experimental *ExperimentalConfig `json:"experimental,omitempty"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level string `json:"level"`
}

// InboundConfig is a sing-box inbound configuration.
type InboundConfig struct {
	Type              string           `json:"type"`
	Tag               string           `json:"tag"`
	Listen            string           `json:"listen,omitempty"`
	ListenPort        int              `json:"listen_port"`
	Sniff             bool             `json:"sniff,omitempty"`
	SniffOverrideDest bool             `json:"sniff_override_destination,omitempty"`
	UpMbps            int              `json:"up_mbps,omitempty"`
	DownMbps          int              `json:"down_mbps,omitempty"`
	TLS               *TLSConfig       `json:"tls,omitempty"`
	Users             []UserConfig     `json:"users,omitempty"`
	Obfs              *ObfsConfig      `json:"obfs,omitempty"`
	CongestionControl string           `json:"congestion_control,omitempty"`
	ZeroRTTHandshake  bool             `json:"zero_rtt_handshake,omitempty"`
	PrivateKey        string           `json:"private_key,omitempty"`
	Address           []string         `json:"address,omitempty"`
	Peers             []PeerConfig     `json:"peers,omitempty"`
	MTU               int              `json:"mtu,omitempty"`
	Version           int              `json:"version,omitempty"`
	Password          string           `json:"password,omitempty"`
	Handshake         *HandshakeConfig `json:"handshake,omitempty"`
}

// HandshakeConfig represents the handshake server for ShadowTLS.
type HandshakeConfig struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

// UserConfig represents a sing-box user.
type UserConfig struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
	UUID     string `json:"uuid,omitempty"`
}

// PeerConfig represents a WireGuard peer.
type PeerConfig struct {
	PublicKey    string   `json:"public_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips,omitempty"`
	Endpoint     string   `json:"endpoint,omitempty"`
	PreSharedKey string   `json:"pre_shared_key,omitempty"`
}

// ObfsConfig holds obfuscation settings.
type ObfsConfig struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

// TLSConfig holds TLS settings for the inbound.
type TLSConfig struct {
	Enabled         bool           `json:"enabled"`
	CertificatePath string         `json:"certificate_path,omitempty"`
	KeyPath         string         `json:"key_path,omitempty"`
	ServerName      string         `json:"server_name,omitempty"`
	ALPN            []string       `json:"alpn,omitempty"`
	UTLS            *UTLSConfig    `json:"utls,omitempty"`
	Reality         *RealityConfig `json:"reality,omitempty"`
	Insecure        bool           `json:"insecure,omitempty"`
}

type UTLSConfig struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type RealityConfig struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
}

// OutboundConfig is a sing-box outbound configuration.
type OutboundConfig struct {
	Type       string           `json:"type"`
	Tag        string           `json:"tag"`
	Server     string           `json:"server,omitempty"`
	ServerPort int              `json:"server_port,omitempty"`
	Username   string           `json:"username,omitempty"`
	Password   string           `json:"password,omitempty"`
	Method     string           `json:"method,omitempty"`
	UUID       string           `json:"uuid,omitempty"`
	Flow       string           `json:"flow,omitempty"`
	TLS        *TLSConfig       `json:"tls,omitempty"`
	Transport  *TransportConfig `json:"transport,omitempty"`
}

type TransportConfig struct {
	Type        string            `json:"type,omitempty"`
	Path        string            `json:"path,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	ServiceName string            `json:"service_name,omitempty"`
}

type RouteConfig struct {
	Rules []RouteRule `json:"rules,omitempty"`
}

type RouteRule struct {
	Inbound  []string `json:"inbound,omitempty"`
	Domain   []string `json:"domain,omitempty"`
	IPCIDR   []string `json:"ip_cidr,omitempty"`
	Port     []int    `json:"port,omitempty"`
	Protocol []string `json:"protocol,omitempty"`
	Outbound string   `json:"outbound"`
}

type ExperimentalConfig struct {
	V2RayAPI *V2RayAPIConfig `json:"v2ray_api,omitempty"`
}

type V2RayAPIConfig struct {
	Listen string          `json:"listen,omitempty"`
	Stats  *StatsAPIConfig `json:"stats,omitempty"`
}

type StatsAPIConfig struct {
	Enabled   bool     `json:"enabled"`
	Inbounds  []string `json:"inbounds,omitempty"`
	Outbounds []string `json:"outbounds,omitempty"`
	Users     []string `json:"users,omitempty"`
}

type BuildOptions struct {
	EnableV2RayAPIStats bool
	ManagementDirect    ManagementDirectOptions
}

type ManagementDirectOptions struct {
	Enabled bool
	Hosts   []string
	Ports   []int
}

// BuildConfig generates a sing-box configuration for supported inbounds.
// Returns the config and a list of port assignments (inbound index -> port).
func BuildConfig(inbounds []db.Inbound) Config {
	return BuildConfigWithOptions(inbounds, BuildOptions{})
}

func BuildConfigWithOptions(inbounds []db.Inbound, opts BuildOptions) Config {
	cfg := Config{
		Log: LogConfig{Level: "warn"},
		Outbounds: []OutboundConfig{
			{Type: "direct", Tag: "direct"},
		},
		Inbounds: []InboundConfig{},
	}
	if opts.EnableV2RayAPIStats {
		cfg.Experimental = &ExperimentalConfig{V2RayAPI: &V2RayAPIConfig{
			Listen: "127.0.0.1:10086",
			Stats:  &StatsAPIConfig{Enabled: true},
		}}
	}
	addStatsInbound := func(tag string) {
		if cfg.Experimental != nil && cfg.Experimental.V2RayAPI != nil && cfg.Experimental.V2RayAPI.Stats != nil {
			cfg.Experimental.V2RayAPI.Stats.Inbounds = append(cfg.Experimental.V2RayAPI.Stats.Inbounds, tag)
		}
	}
	addStatsUser := func(name string) {
		if cfg.Experimental != nil && cfg.Experimental.V2RayAPI != nil && cfg.Experimental.V2RayAPI.Stats != nil {
			cfg.Experimental.V2RayAPI.Stats.Users = append(cfg.Experimental.V2RayAPI.Stats.Users, name)
		}
	}

	for i, inbound := range inbounds {
		if !inbound.Enabled {
			continue
		}
		if db.InboundCore(inbound) != db.CoreSingbox {
			continue
		}
		protocol := inbound.Protocol

		port := inbound.Port
		if port <= 0 {
			port = NextPort(i)
		}

		switch protocol {
		case "hysteria2":
			tag := InboundStatsTag(inbound)
			ib := InboundConfig{
				Type:       "hysteria2",
				Tag:        tag,
				Listen:     "0.0.0.0",
				ListenPort: port,
				UpMbps:     inbound.Hy2UpMbps,
				DownMbps:   inbound.Hy2DownMbps,
			}
			addStatsInbound(tag)

			// Build users from clients
			for _, client := range enabledClients(inbound.Clients) {
				name := UserStatsKey(client)
				ib.Users = append(ib.Users, UserConfig{
					Name:     name,
					Password: client.PasswordValue(),
				})
				addStatsUser(name)
			}

			// Obfuscation
			if inbound.Hy2Obfs != "" {
				obfs := &ObfsConfig{Type: inbound.Hy2Obfs}
				if inbound.Hy2ObfsPassword != "" {
					obfs.Password = inbound.Hy2ObfsPassword
				}
				ib.Obfs = obfs
			}

			// sing-box v1.13 requires TLS for Hysteria2 server inbounds.
			// MiGate keeps the UI simple by using generated self-signed certs by default
			// and only honoring custom cert paths when the user explicitly enables TLS.
			ib.TLS = &TLSConfig{
				Enabled:         true,
				CertificatePath: CertFile,
				KeyPath:         KeyFile,
			}
			if inbound.Security == "tls" {
				if inbound.TLSCertFile != "" && inbound.TLSKeyFile != "" && fileExists(inbound.TLSCertFile) && fileExists(inbound.TLSKeyFile) {
					ib.TLS.CertificatePath = inbound.TLSCertFile
					ib.TLS.KeyPath = inbound.TLSKeyFile
				}
				if inbound.TLSSNI != "" {
					ib.TLS.ServerName = inbound.TLSSNI
				}
			}

			cfg.Inbounds = append(cfg.Inbounds, ib)

		case "tuic":
			tag := InboundStatsTag(inbound)
			ib := InboundConfig{
				Type:              "tuic",
				Tag:               tag,
				Listen:            "0.0.0.0",
				ListenPort:        port,
				CongestionControl: "bbr",
				ZeroRTTHandshake:  inbound.TuicZeroRTT,
			}
			addStatsInbound(tag)

			if inbound.TuicCongestionControl != "" {
				ib.CongestionControl = inbound.TuicCongestionControl
			}

			// Build users from clients (TUIC in sing-box v1.13 requires valid UUID format for uuid)
			for _, client := range enabledClients(inbound.Clients) {
				name := UserStatsKey(client)
				ib.Users = append(ib.Users, UserConfig{
					Name:     name,
					UUID:     stableTUICUUID(client.CredentialIDValue()),
					Password: client.PasswordValue(),
				})
				addStatsUser(name)
			}

			// TLS (required for tuic)
			ib.TLS = &TLSConfig{
				Enabled:         true,
				CertificatePath: CertFile,
				KeyPath:         KeyFile,
			}
			if inbound.TLSCertFile != "" && inbound.TLSKeyFile != "" {
				ib.TLS.CertificatePath = inbound.TLSCertFile
				ib.TLS.KeyPath = inbound.TLSKeyFile
			}
			if inbound.TLSSNI != "" {
				ib.TLS.ServerName = inbound.TLSSNI
			}

			cfg.Inbounds = append(cfg.Inbounds, ib)

		case "wireguard":
			// NOTE: WireGuard inbound requires sing-box >= 1.14
			// Skipping for now — current deployed version is 1.13.x
			continue

		case "shadowtls":
			tag := InboundStatsTag(inbound)
			ib := InboundConfig{
				Type:       "shadowtls",
				Tag:        tag,
				Listen:     "0.0.0.0",
				ListenPort: port,
				Version:    firstNonZero(inbound.ShadowTLSVersion, 3),
				// NOTE: sing-box v1.13: inbound-level password + users conflicts.
				// Put password on users only; omit inbound password entirely.
				// Password: inbound.ShadowTLSPassword,
			}
			addStatsInbound(tag)

			if inbound.TLSSNI != "" {
				ib.Handshake = &HandshakeConfig{
					Server:     inbound.TLSSNI,
					ServerPort: 443,
				}
			}

			// Build users from clients
			for _, client := range enabledClients(inbound.Clients) {
				name := UserStatsKey(client)
				ib.Users = append(ib.Users, UserConfig{
					Name:     name,
					Password: client.PasswordValue(),
				})
				addStatsUser(name)
			}

			cfg.Inbounds = append(cfg.Inbounds, ib)

		default:
			continue
		}
	}

	return cfg
}

func BuildConfigWithOutbounds(inbounds []db.Inbound, outbounds []db.Outbound, routingRules []db.RoutingRule) (Config, error) {
	return BuildConfigWithOutboundsOptions(inbounds, outbounds, routingRules, BuildOptions{})
}

func BuildConfigWithOutboundsOptions(inbounds []db.Inbound, outbounds []db.Outbound, routingRules []db.RoutingRule, opts BuildOptions) (Config, error) {
	cfg := BuildConfigWithOptions(inbounds, opts)
	cfg.Outbounds = []OutboundConfig{}
	for _, outbound := range outbounds {
		if !outbound.Enabled || !db.OutboundSupportsCore(outbound, db.CoreSingbox) || isRemovedSingboxOutbound(outbound) {
			continue
		}
		built, err := buildOutbound(outbound)
		if err != nil {
			return Config{}, err
		}
		cfg.Outbounds = append(cfg.Outbounds, built)
	}
	if len(cfg.Outbounds) == 0 {
		cfg.Outbounds = append(cfg.Outbounds, OutboundConfig{Type: "direct", Tag: "singbox-out-0"})
	}
	systemRules := singboxSystemRouteRules(opts.ManagementDirect)
	if len(systemRules) > 0 {
		cfg.Outbounds = ensureSingboxSystemDirectOutbound(cfg.Outbounds)
	}
	if len(routingRules) > 0 {
		inboundTagsByID := map[int64]string{}
		inboundAliases := map[string]string{}
		for _, inbound := range inbounds {
			if !inbound.Enabled || db.InboundCore(inbound) != db.CoreSingbox {
				continue
			}
			tag := InboundStatsTag(inbound)
			inboundTagsByID[inbound.ID] = tag
			inboundAliases[db.GeneratedInboundTag(inbound)] = tag
			if strings.TrimSpace(inbound.Remark) != "" {
				inboundAliases[strings.TrimSpace(inbound.Remark)] = tag
			}
		}
		route := &RouteConfig{Rules: append([]RouteRule{}, systemRules...)}
		for _, rule := range routingRules {
			if !rule.Enabled {
				continue
			}
			if !db.RoutingRuleAppliesToCore(rule, inbounds, db.CoreSingbox) {
				continue
			}
			outbound, ok := db.ResolveRuleOutbound(rule, outbounds)
			if !ok {
				return Config{}, fmt.Errorf("routing rule %d targets missing outbound profile", rule.ID)
			}
			if !db.OutboundSupportsCore(outbound, db.CoreSingbox) {
				return Config{}, fmt.Errorf("routing rule %d targets outbound %q that does not support sing-box", rule.ID, outbound.Tag)
			}
			if isRemovedSingboxOutbound(outbound) {
				continue
			}
			sr := RouteRule{Outbound: db.GeneratedOutboundTag(db.CoreSingbox, outbound.ID, rule.OutboundTag)}
			if rule.InboundID > 0 {
				if actual, ok := inboundTagsByID[rule.InboundID]; ok {
					sr.Inbound = []string{actual}
				} else {
					continue
				}
			} else if inboundTag := strings.TrimSpace(rule.InboundTag); inboundTag != "" {
				if actual, ok := inboundAliases[inboundTag]; ok {
					sr.Inbound = []string{actual}
				} else {
					continue
				}
			}
			if strings.TrimSpace(rule.Domain) != "" {
				sr.Domain = splitRuleValues(rule.Domain)
			}
			if strings.TrimSpace(rule.IP) != "" {
				sr.IPCIDR = splitRuleValues(rule.IP)
			}
			if strings.TrimSpace(rule.Protocol) != "" {
				sr.Protocol = splitRuleValues(rule.Protocol)
			}
			route.Rules = append(route.Rules, sr)
		}
		if len(route.Rules) > 0 {
			cfg.Route = route
		}
	} else if len(systemRules) > 0 {
		cfg.Route = &RouteConfig{Rules: systemRules}
	}
	return cfg, nil
}

func ensureSingboxSystemDirectOutbound(outbounds []OutboundConfig) []OutboundConfig {
	system := OutboundConfig{Type: "direct", Tag: SystemDirectOutboundTag}
	for i, outbound := range outbounds {
		if outbound.Tag == SystemDirectOutboundTag {
			outbounds[i] = system
			return outbounds
		}
	}
	return append(outbounds, system)
}

func singboxSystemRouteRules(opts ManagementDirectOptions) []RouteRule {
	if !opts.Enabled {
		return nil
	}
	hosts := panelcfg.NormalizeManagementDirectHosts(opts.Hosts)
	ports := panelcfg.NormalizeManagementDirectPorts(opts.Ports)
	if len(hosts) == 0 || len(ports) == 0 {
		return nil
	}
	domains := []string{}
	ipCIDRs := []string{}
	for _, host := range hosts {
		if isCIDROrIP(host) {
			ipCIDRs = append(ipCIDRs, singboxRouteIPCIDR(host))
		} else {
			domains = append(domains, host)
		}
	}
	rules := []RouteRule{}
	if len(ipCIDRs) > 0 {
		rules = append(rules, RouteRule{IPCIDR: ipCIDRs, Port: ports, Outbound: SystemDirectOutboundTag})
	}
	if len(domains) > 0 {
		rules = append(rules, RouteRule{Domain: domains, Port: ports, Outbound: SystemDirectOutboundTag})
	}
	return rules
}

func isRemovedSingboxOutbound(outbound db.Outbound) bool {
	return db.NormalizeOutboundProtocol(outbound.Protocol) == "dns"
}

// GenerateSelfSignedCert generates a self-signed TLS certificate and key
// saved to CertFile and KeyFile paths.
func GenerateSelfSignedCert() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "MiGate Auto-Generated Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "migate"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}

	if err := os.MkdirAll(ConfigDir(), 0755); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}

	certOut, err := os.Create(CertFile)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	keyOut, err := os.Create(KeyFile)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	return nil
}

// ConfigDir returns the config directory for sing-box.
func ConfigDir() string {
	return DefaultConfigDir
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func enabledClients(clients []db.Client) []db.Client {
	var result []db.Client
	for _, c := range clients {
		if c.Enabled {
			result = append(result, c)
		}
	}
	return result
}

// generateUUID returns a UUID v4 string.
func generateUUID() string {
	uuid := make([]byte, 16)
	rand.Read(uuid)
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}

func stableTUICUUID(seed string) string {
	seed = strings.TrimSpace(seed)
	if isUUID(seed) {
		return seed
	}
	sum := sha256.Sum256([]byte(seed))
	uuid := make([]byte, 16)
	copy(uuid, sum[:16])
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
}

func buildOutbound(outbound db.Outbound) (OutboundConfig, error) {
	protocol := db.NormalizeOutboundProtocol(outbound.Protocol)
	tag := db.GeneratedOutboundTag(db.CoreSingbox, outbound.ID, outbound.Tag)
	if err := db.ValidateOutboundProfile(outbound); err != nil {
		return OutboundConfig{}, err
	}
	switch protocol {
	case "freedom":
		return OutboundConfig{Type: "direct", Tag: tag}, nil
	case "blackhole":
		return OutboundConfig{Type: "block", Tag: tag}, nil
	case "dns":
		return OutboundConfig{}, fmt.Errorf("dns outbound is not supported by sing-box 1.13+; use route rule actions instead")
	case "socks":
		return OutboundConfig{Type: "socks", Tag: tag, Server: outbound.Address, ServerPort: outbound.Port, Username: strings.TrimSpace(outbound.Username), Password: outbound.Password}, nil
	case "http", "https":
		return OutboundConfig{Type: "http", Tag: tag, Server: outbound.Address, ServerPort: outbound.Port, Username: strings.TrimSpace(outbound.Username), Password: outbound.Password}, nil
	case "vless":
		settings := db.ParseOutboundSettings(outbound.SettingsJSON)
		cfg := OutboundConfig{Type: "vless", Tag: tag, Server: outbound.Address, ServerPort: outbound.Port, UUID: strings.TrimSpace(outbound.Username), Flow: strings.TrimSpace(settings.Flow)}
		applyOutboundSettings(&cfg, settings)
		return cfg, nil
	case "trojan":
		cfg := OutboundConfig{Type: "trojan", Tag: tag, Server: outbound.Address, ServerPort: outbound.Port, Password: firstNonEmpty(outbound.Password, outbound.Username)}
		applyOutboundSettings(&cfg, db.ParseOutboundSettings(outbound.SettingsJSON))
		return cfg, nil
	case "shadowsocks":
		settings := db.ParseOutboundSettings(outbound.SettingsJSON)
		cfg := OutboundConfig{Type: "shadowsocks", Tag: tag, Server: outbound.Address, ServerPort: outbound.Port, Method: firstNonEmpty(outbound.Username, settings.Method, "aes-128-gcm"), Password: outbound.Password}
		applyOutboundSettings(&cfg, settings)
		return cfg, nil
	case "hysteria2":
		return OutboundConfig{Type: "hysteria2", Tag: tag, Server: outbound.Address, ServerPort: outbound.Port, Password: firstNonEmpty(outbound.Password, outbound.Username)}, nil
	case "tuic":
		return OutboundConfig{Type: "tuic", Tag: tag, Server: outbound.Address, ServerPort: outbound.Port, UUID: strings.TrimSpace(outbound.Username), Password: outbound.Password}, nil
	case "shadowtls":
		return OutboundConfig{Type: "shadowtls", Tag: tag, Server: outbound.Address, ServerPort: outbound.Port, Password: firstNonEmpty(outbound.Password, outbound.Username)}, nil
	default:
		return OutboundConfig{}, fmt.Errorf("unsupported outbound protocol: %s", outbound.Protocol)
	}
}

func applyOutboundSettings(cfg *OutboundConfig, settings db.OutboundSettings) {
	security := strings.ToLower(strings.TrimSpace(settings.Security))
	if security == "" {
		if settings.Reality {
			security = "reality"
		} else if settings.TLS {
			security = "tls"
		}
	}
	if security == "tls" || security == "reality" {
		tls := &TLSConfig{Enabled: true}
		if settings.SNI != "" {
			tls.ServerName = settings.SNI
		}
		if len(settings.ALPN) > 0 {
			tls.ALPN = settings.ALPN
		}
		if settings.AllowInsecure {
			tls.Insecure = true
		}
		if settings.Fingerprint != "" {
			tls.UTLS = &UTLSConfig{Enabled: true, Fingerprint: settings.Fingerprint}
		}
		if security == "reality" {
			tls.Reality = &RealityConfig{Enabled: true, PublicKey: settings.PublicKey, ShortID: settings.ShortID}
		}
		cfg.TLS = tls
	}
	switch strings.ToLower(strings.TrimSpace(settings.Network)) {
	case "ws", "websocket":
		transport := &TransportConfig{Type: "ws"}
		if settings.Path != "" {
			transport.Path = settings.Path
		}
		if settings.Host != "" {
			transport.Headers = map[string]string{"Host": settings.Host}
		}
		cfg.Transport = transport
	case "grpc":
		transport := &TransportConfig{Type: "grpc"}
		if settings.ServiceName != "" {
			transport.ServiceName = settings.ServiceName
		}
		cfg.Transport = transport
	}
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

func isCIDROrIP(value string) bool {
	if net.ParseIP(value) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

func singboxRouteIPCIDR(value string) string {
	if strings.Contains(value, "/") {
		return value
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return value
	}
	if ip.To4() != nil {
		return ip.String() + "/32"
	}
	return ip.String() + "/128"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
