package singbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/imzyb/MiGate/internal/db"
)

// Config is the top-level sing-box configuration.
type Config struct {
	Log      LogConfig       `json:"log"`
	Inbounds []InboundConfig `json:"inbounds"`
	Outbounds []OutboundConfig `json:"outbounds"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level string `json:"level"`
}

// InboundConfig is a sing-box inbound configuration.
type InboundConfig struct {
	Type              string          `json:"type"`
	Tag               string          `json:"tag"`
	Listen            string          `json:"listen,omitempty"`
	ListenPort        int             `json:"listen_port"`
	Sniff             bool            `json:"sniff,omitempty"`
	SniffOverrideDest bool            `json:"sniff_override_destination,omitempty"`
	UpMbps            int             `json:"up_mbps,omitempty"`
	DownMbps          int             `json:"down_mbps,omitempty"`
	TLS               *TLSConfig      `json:"tls,omitempty"`
	Users             []UserConfig    `json:"users,omitempty"`
	Obfs              *ObfsConfig     `json:"obfs,omitempty"`
	CongestionControl string          `json:"congestion_control,omitempty"`
	ZeroRTTHandshake  bool            `json:"zero_rtt_handshake,omitempty"`
	PrivateKey        string          `json:"private_key,omitempty"`
	Address           []string        `json:"address,omitempty"`
	Peers             []PeerConfig    `json:"peers,omitempty"`
	MTU               int             `json:"mtu,omitempty"`
	Version           int             `json:"version,omitempty"`
	Password          string          `json:"password,omitempty"`
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
	Password string `json:"password"`
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
	Enabled         bool   `json:"enabled"`
	CertificatePath string `json:"certificate_path,omitempty"`
	KeyPath         string `json:"key_path,omitempty"`
	ServerName      string `json:"server_name,omitempty"`
}

// OutboundConfig is a sing-box outbound configuration.
type OutboundConfig struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

// BuildConfig generates a sing-box configuration for supported inbounds.
// Returns the config and a list of port assignments (inbound index -> port).
func BuildConfig(inbounds []db.Inbound) Config {
	cfg := Config{
		Log: LogConfig{Level: "warn"},
		Outbounds: []OutboundConfig{
			{Type: "direct", Tag: "direct"},
		},
		Inbounds: []InboundConfig{},
	}

	for i, inbound := range inbounds {
		if !inbound.Enabled {
			continue
		}
		protocol := inbound.Protocol

		port := NextPort(i)

		switch protocol {
		case "hysteria2":
			ib := InboundConfig{
				Type:       "hysteria2",
				Tag:        fmt.Sprintf("hy2-inbound-%d", inbound.ID),
				Listen:     "0.0.0.0",
				ListenPort: port,
				UpMbps:     inbound.Hy2UpMbps,
				DownMbps:   inbound.Hy2DownMbps,
			}

			// Build users from clients
			for _, client := range enabledClients(inbound.Clients) {
				ib.Users = append(ib.Users, UserConfig{
					Name:     client.Email,
					Password: client.UUID,
				})
			}

			// Obfuscation
			if inbound.Hy2Obfs != "" {
				obfs := &ObfsConfig{Type: inbound.Hy2Obfs}
				if inbound.Hy2ObfsPassword != "" {
					obfs.Password = inbound.Hy2ObfsPassword
				}
				ib.Obfs = obfs
			}

			// TLS (required for hysteria2)
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

		case "tuic":
			ib := InboundConfig{
				Type:               "tuic",
				Tag:                fmt.Sprintf("tuic-inbound-%d", inbound.ID),
				Listen:             "0.0.0.0",
				ListenPort:         port,
				CongestionControl:  "bbr",
				ZeroRTTHandshake:   inbound.TuicZeroRTT,
			}

			if inbound.TuicCongestionControl != "" {
				ib.CongestionControl = inbound.TuicCongestionControl
			}

			// Build users from clients
			for _, client := range enabledClients(inbound.Clients) {
				ib.Users = append(ib.Users, UserConfig{
					Name:     client.Email,
					Password: client.UUID,
				})
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
			ib := InboundConfig{
				Type:       "shadowtls",
				Tag:        fmt.Sprintf("shadowtls-inbound-%d", inbound.ID),
				Listen:     "0.0.0.0",
				ListenPort: port,
				Version:    inbound.ShadowTLSVersion,
				Password:   inbound.ShadowTLSPassword,
			}

			if inbound.TLSSNI != "" {
				ib.Handshake = &HandshakeConfig{
					Server:     inbound.TLSSNI,
					ServerPort: 443,
				}
			}

			// Build users from clients
			for _, client := range enabledClients(inbound.Clients) {
				ib.Users = append(ib.Users, UserConfig{
					Name:     client.Email,
					Password: client.UUID,
				})
			}

			cfg.Inbounds = append(cfg.Inbounds, ib)

		default:
			continue
		}
	}

	return cfg
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

func enabledClients(clients []db.Client) []db.Client {
	var result []db.Client
	for _, c := range clients {
		if c.Enabled {
			result = append(result, c)
		}
	}
	return result
}