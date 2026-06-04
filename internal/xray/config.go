package xray

import (
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
	base := InboundConfig{
		Tag:            fmt.Sprintf("inbound-%d-%s", inbound.ID, protocol),
		Listen:         "0.0.0.0",
		Port:           inbound.Port,
		Protocol:       protocol,
		StreamSettings: buildStreamSettings(inbound),
	}

	switch protocol {
	case "vless":
		base.Settings = map[string]interface{}{
			"clients":    clientsAsIDEmail(clients),
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
		base.Settings = map[string]interface{}{
			"method":   ssMethod,
			"password": inbound.UUID,
			"clients":  clientsAsPasswordEmail(clients),
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

func clientsAsIDEmail(clients []db.Client) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(clients))
	for _, client := range clients {
		result = append(result, map[string]interface{}{
			"id":    client.UUID,
			"email": client.Email,
		})
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
	if security == "reality" {
		dest := "www.cloudflare.com:443"
		if inbound.RealityDest != "" {
			dest = inbound.RealityDest
		}
		serverNames := []string{"www.cloudflare.com"}
		if inbound.RealityServerNames != "" {
			serverNames = strings.Split(inbound.RealityServerNames, ",")
		}
		realitySettings := map[string]interface{}{
			"show":        false,
			"dest":        dest,
			"serverNames": serverNames,
		}
		if inbound.RealityShortID != "" {
			realitySettings["shortId"] = inbound.RealityShortID
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
