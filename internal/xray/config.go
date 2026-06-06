package xray

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/imzyb/MiGate/internal/db"
)

type Config struct {
	Log       LogConfig        `json:"log"`
	Inbounds  []InboundConfig  `json:"inbounds"`
	Outbounds []OutboundConfig `json:"outbounds"`
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
	Tag      string                 `json:"tag"`
	Protocol string                 `json:"protocol"`
	Settings map[string]interface{} `json:"settings"`
}

func BuildConfig(inbounds []db.Inbound) (Config, error) {
	config := Config{
		Log:      LogConfig{LogLevel: "warning"},
		Inbounds: []InboundConfig{},
		Outbounds: []OutboundConfig{{
			Tag:      "direct",
			Protocol: "freedom",
			Settings: map[string]interface{}{},
		}},
	}
	return appendInbounds(config, inbounds)
}

func BuildConfigWithOutbounds(inbounds []db.Inbound, outbounds []db.Outbound) (Config, error) {
	config := Config{
		Log:       LogConfig{LogLevel: "warning"},
		Inbounds:  []InboundConfig{},
		Outbounds: []OutboundConfig{},
	}
	config, err := appendInbounds(config, inbounds)
	if err != nil {
		return Config{}, err
	}
	for _, ob := range outbounds {
		if !ob.Enabled {
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
			Tag: "direct", Protocol: "freedom", Settings: map[string]interface{}{},
		})
	}
	return config, nil
}

func appendInbounds(config Config, inbounds []db.Inbound) (Config, error) {
	for _, inbound := range inbounds {
		if !inbound.Enabled {
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

	// Auto-generate REALITY private key if security=reality but key is missing
	if strings.ToLower(strings.TrimSpace(inbound.Security)) == "reality" && inbound.RealityPrivateKey == "" {
		if privKey, pubKey, err := GenerateRealityKey(); err == nil {
			inbound.RealityPrivateKey = privKey
			inbound.RealityPublicKey = pubKey
		}
	}

	base := InboundConfig{
		Tag:            fmt.Sprintf("inbound-%d-%s", inbound.ID, protocol),
		Listen:         "0.0.0.0",
		Port:           inbound.Port,
		Protocol:       protocol,
		StreamSettings: buildStreamSettings(inbound),
	}

	switch protocol {
	case "vless":
		flow := ""
		if strings.ToLower(strings.TrimSpace(inbound.Security)) == "reality" {
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
		password := inbound.UUID
		base.Settings = map[string]interface{}{
			"method":   ssMethod,
			"password": password,
			// Xray Shadowsocks only supports single-user mode (no "clients" array)
		}
	case "hysteria2":
		settings := map[string]interface{}{
			"clients": clientsAsPasswordEmail(clients),
		}
		if inbound.Hy2UpMbps > 0 {
			settings["up_mbps"] = inbound.Hy2UpMbps
		}
		if inbound.Hy2DownMbps > 0 {
			settings["down_mbps"] = inbound.Hy2DownMbps
		}
		if inbound.Hy2Obfs != "" {
			settings["obfs"] = inbound.Hy2Obfs
			if inbound.Hy2ObfsPassword != "" {
				settings["obfs_password"] = inbound.Hy2ObfsPassword
			}
		}
		base.Settings = settings
		// Hysteria2 uses its own QUIC transport; build stream settings without network field
		base.StreamSettings = buildHy2StreamSettings(inbound)
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

func clientsAsIDEmail(clients []db.Client, flow string) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(clients))
	for _, client := range clients {
		entry := map[string]interface{}{
			"id":    client.UUID,
			"email": client.Email,
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
			"id":      client.UUID,
			"email":   client.Email,
			"alterId": 0,
		})
	}
	return result
}

func clientsAsPasswordEmail(clients []db.Client) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(clients))
	for _, client := range clients {
		result = append(result, map[string]interface{}{
			"password": client.UUID,
			"email":    client.Email,
		})
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
	if network == "ws" || network == "h2" {
		wsSettings := map[string]interface{}{"path": "/"}
		if inbound.WsPath != "" {
			wsSettings["path"] = inbound.WsPath
		}
		if inbound.WsHost != "" {
			wsSettings["host"] = inbound.WsHost
		}
		settings["wsSettings"] = wsSettings
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
			serverNames = strings.Split(inbound.RealityServerNames, ",")
		}
		shortIds := []string{""}
		if inbound.RealityShortID != "" {
			shortIds = []string{inbound.RealityShortID}
		}
		// Auto-generate a random shortId if none is set (REALITY requires non-empty hex shortIds)
		if shortIds[0] == "" {
			b := make([]byte, 4)
			_, _ = rand.Read(b)
			shortIds[0] = fmt.Sprintf("%x", b)
		}
		realitySettings := map[string]interface{}{
			"show":        false,
			"dest":        dest,
			"serverNames": serverNames,
			"shortIds":    shortIds,
		}
		if inbound.RealityPrivateKey != "" {
			realitySettings["privateKey"] = inbound.RealityPrivateKey
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
		if len(tlsSettings) > 0 {
			settings["tlsSettings"] = tlsSettings
		}
	}
	return settings
}

func buildOutbound(ob db.Outbound) (OutboundConfig, error) {
	protocol := strings.ToLower(strings.TrimSpace(ob.Protocol))
	switch protocol {
	case "freedom", "blackhole":
		return OutboundConfig{
			Tag:      ob.Tag,
			Protocol: protocol,
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
			Tag:      ob.Tag,
			Protocol: protocol,
			Settings: map[string]interface{}{"servers": servers},
		}, nil
	case "http":
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
			Tag:      ob.Tag,
			Protocol: protocol,
			Settings: map[string]interface{}{"servers": servers},
		}, nil
	default:
		return OutboundConfig{}, fmt.Errorf("unsupported outbound protocol: %s", ob.Protocol)
	}
}
