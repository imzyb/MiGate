package db

import (
	"encoding/json"
	"strings"
)

const (
	CertStatusIssued       = "issued"
	CertStatusPending      = "pending"
	CertStatusFailed       = "failed"
	CertStatusExpired      = "expired"
	CertStatusExpiringSoon = "expiring_soon"

	CertSourceACME   = "acme"
	CertSourceImport = "import"

	OutboundSourceManual       = "manual"
	OutboundSourceSubscription = "subscription"
	OutboundSourceProxyPool    = "proxy_pool"

	DefaultOutboundSubscriptionUpdateIntervalSeconds = 21600
)

type Certificate struct {
	ID               int64     `json:"id"`
	Name             string    `json:"name"`
	Source           string    `json:"source"`
	Status           string    `json:"status"`
	Domains          []string  `json:"domains"`
	CertPath         string    `json:"cert_path"`
	KeyPath          string    `json:"key_path"`
	NotBefore        string    `json:"not_before,omitempty"`
	NotAfter         string    `json:"not_after,omitempty"`
	Fingerprint      string    `json:"fingerprint,omitempty"`
	Serial           string    `json:"serial,omitempty"`
	IssueEmail       string    `json:"issue_email,omitempty"`
	ACMEDirectoryURL string    `json:"acme_directory_url,omitempty"`
	ChallengeMethod  string    `json:"challenge_method,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
	CreatedAt        string    `json:"created_at,omitempty"`
	UpdatedAt        string    `json:"updated_at,omitempty"`
	LastRenewed      string    `json:"last_renewed,omitempty"`
	UsageCount       int       `json:"usage_count"`
	Usages           []Inbound `json:"usages,omitempty"`
}

type CertificateOperation struct {
	ID            int64  `json:"id"`
	CertificateID int64  `json:"certificate_id,omitempty"`
	Type          string `json:"type"`
	Status        string `json:"status"`
	Code          string `json:"code,omitempty"`
	Message       string `json:"message,omitempty"`
	Detail        string `json:"detail,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

type UpsertCertificateParams struct {
	ID               int64
	Name             string
	Source           string
	Status           string
	Domains          []string
	CertPath         string
	KeyPath          string
	NotBefore        string
	NotAfter         string
	Fingerprint      string
	Serial           string
	IssueEmail       string
	ACMEDirectoryURL string
	ChallengeMethod  string
	LastError        string
	LastRenewed      string
}

type RoutingRule struct {
	ID          int64  `json:"id"`
	InboundID   int64  `json:"inbound_id,omitempty"`
	InboundTag  string `json:"inbound_tag"`
	ClientID    int64  `json:"client_id,omitempty"`
	ClientEmail string `json:"client_email,omitempty"`
	OutboundID  int64  `json:"outbound_id,omitempty"`
	OutboundTag string `json:"outbound_tag"`
	Domain      string `json:"domain"`
	IP          string `json:"ip"`
	RuleSet     string `json:"rule_set"`
	Protocol    string `json:"protocol"`
	Enabled     bool   `json:"enabled"`
	Sort        int    `json:"sort"`
}

type CreateRoutingRuleParams struct {
	InboundID   int64  `json:"inbound_id,omitempty"`
	InboundTag  string `json:"inbound_tag"`
	ClientID    int64  `json:"client_id,omitempty"`
	ClientEmail string `json:"client_email,omitempty"`
	OutboundID  int64  `json:"outbound_id,omitempty"`
	OutboundTag string `json:"outbound_tag"`
	Domain      string `json:"domain"`
	IP          string `json:"ip"`
	RuleSet     string `json:"rule_set"`
	Protocol    string `json:"protocol"`
	Enabled     bool   `json:"enabled"`
}

type UpdateRoutingRuleParams struct {
	InboundID   int64  `json:"inbound_id,omitempty"`
	InboundTag  string `json:"inbound_tag"`
	ClientID    int64  `json:"client_id,omitempty"`
	ClientEmail string `json:"client_email,omitempty"`
	OutboundID  int64  `json:"outbound_id,omitempty"`
	OutboundTag string `json:"outbound_tag"`
	Domain      string `json:"domain"`
	IP          string `json:"ip"`
	RuleSet     string `json:"rule_set"`
	Protocol    string `json:"protocol"`
	Enabled     bool   `json:"enabled"`
}

type Inbound struct {
	ID                    int64    `json:"id"`
	UUID                  string   `json:"uuid"`
	Remark                string   `json:"remark"`
	Protocol              string   `json:"protocol"`
	Core                  string   `json:"core"`
	Port                  int      `json:"port"`
	Network               string   `json:"network"`
	Security              string   `json:"security"`
	Enabled               bool     `json:"enabled"`
	WsPath                string   `json:"ws_path"`
	WsHost                string   `json:"ws_host"`
	GrpcServiceName       string   `json:"grpc_service_name"`
	RealityDest           string   `json:"reality_dest"`
	RealityServerNames    string   `json:"reality_server_names"`
	RealityShortID        string   `json:"reality_short_id"`
	RealityPrivateKey     string   `json:"reality_private_key"`
	RealityPublicKey      string   `json:"reality_public_key"`
	SSMethod              string   `json:"ss_method"`
	TLSCertFile           string   `json:"tls_cert_file"`
	TLSKeyFile            string   `json:"tls_key_file"`
	TLSSNI                string   `json:"tls_sni"`
	TLSFingerprint        string   `json:"tls_fingerprint"`
	TLSALPN               string   `json:"tls_alpn"`
	XHTTPPath             string   `json:"xhttp_path"`
	XHTTPMode             string   `json:"xhttp_mode"`
	Hy2UpMbps             int      `json:"hy2_up_mbps"`
	Hy2DownMbps           int      `json:"hy2_down_mbps"`
	Hy2Obfs               string   `json:"hy2_obfs"`
	Hy2ObfsPassword       string   `json:"hy2_obfs_password"`
	Hy2MPort              string   `json:"hy2_mport"`
	TuicCongestionControl string   `json:"tuic_congestion_control"`
	TuicZeroRTT           bool     `json:"tuic_zero_rtt"`
	WgPrivateKey          string   `json:"wg_private_key"`
	WgAddress             string   `json:"wg_address"`
	WgPeerPublicKey       string   `json:"wg_peer_public_key"`
	WgAllowedIPs          string   `json:"wg_allowed_ips"`
	WgEndpoint            string   `json:"wg_endpoint"`
	WgPresharedKey        string   `json:"wg_preshared_key"`
	WgMTU                 int      `json:"wg_mtu"`
	ShadowTLSVersion      int      `json:"shadowtls_version"`
	ShadowTLSPassword     string   `json:"shadowtls_password"`
	Clients               []Client `json:"clients"`
}

type Outbound struct {
	ID                   int64    `json:"id"`
	Tag                  string   `json:"tag"`
	Remark               string   `json:"remark"`
	Protocol             string   `json:"protocol"`
	Address              string   `json:"address"`
	Port                 int      `json:"port"`
	Username             string   `json:"username"`
	Password             string   `json:"password"`
	SupportedCores       []string `json:"supported_cores"`
	Enabled              bool     `json:"enabled"`
	Sort                 int      `json:"sort"`
	Source               string   `json:"source"`
	SubscriptionID       int64    `json:"subscription_id,omitempty"`
	SubscriptionIdentity string   `json:"subscription_identity,omitempty"`
	RawLink              string   `json:"raw_link,omitempty"`
	SettingsJSON         string   `json:"settings_json,omitempty"`
	LastSeenAt           string   `json:"last_seen_at,omitempty"`
}

type CreateOutboundParams struct {
	Tag                  string `json:"tag"`
	Remark               string `json:"remark"`
	Protocol             string `json:"protocol"`
	Address              string `json:"address"`
	Port                 int    `json:"port"`
	Username             string `json:"username"`
	Password             string `json:"password"`
	Source               string `json:"source,omitempty"`
	SubscriptionID       int64  `json:"subscription_id,omitempty"`
	SubscriptionIdentity string `json:"subscription_identity,omitempty"`
	RawLink              string `json:"raw_link,omitempty"`
	SettingsJSON         string `json:"settings_json,omitempty"`
}

type UpdateOutboundParams struct {
	Tag          string `json:"tag"`
	Remark       string `json:"remark"`
	Protocol     string `json:"protocol"`
	Address      string `json:"address"`
	Port         int    `json:"port"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Enabled      bool   `json:"enabled"`
	SettingsJSON string `json:"settings_json,omitempty"`
}

type OutboundSubscription struct {
	ID                    int64  `json:"id"`
	Remark                string `json:"remark"`
	URL                   string `json:"url"`
	TagPrefix             string `json:"tag_prefix"`
	UpdateIntervalSeconds int    `json:"update_interval_seconds"`
	Enabled               bool   `json:"enabled"`
	AllowPrivate          bool   `json:"allow_private"`
	Prepend               bool   `json:"prepend"`
	Priority              int    `json:"priority"`
	LastFetchedAt         string `json:"last_fetched_at,omitempty"`
	LastAttemptAt         string `json:"last_attempt_at,omitempty"`
	LastError             string `json:"last_error,omitempty"`
	LinkIdentitiesJSON    string `json:"link_identities_json,omitempty"`
	CreatedAt             string `json:"created_at,omitempty"`
	UpdatedAt             string `json:"updated_at,omitempty"`
	OutboundCount         int    `json:"outbound_count"`
}

type CreateOutboundSubscriptionParams struct {
	Remark                string `json:"remark"`
	URL                   string `json:"url"`
	TagPrefix             string `json:"tag_prefix"`
	UpdateIntervalSeconds int    `json:"update_interval_seconds"`
	Enabled               bool   `json:"enabled"`
	AllowPrivate          bool   `json:"allow_private"`
	Prepend               bool   `json:"prepend"`
}

type UpdateOutboundSubscriptionParams struct {
	Remark                string `json:"remark"`
	URL                   string `json:"url"`
	TagPrefix             string `json:"tag_prefix"`
	UpdateIntervalSeconds int    `json:"update_interval_seconds"`
	Enabled               bool   `json:"enabled"`
	AllowPrivate          bool   `json:"allow_private"`
	Prepend               bool   `json:"prepend"`
}

type MaterializedSubscriptionOutbound struct {
	ID                   int64
	Tag                  string
	Remark               string
	Protocol             string
	Address              string
	Port                 int
	Username             string
	Password             string
	SubscriptionIdentity string
	RawLink              string
	SettingsJSON         string
	Position             int
}

type Client struct {
	ID                int64  `json:"id"`
	InboundID         int64  `json:"inbound_id"`
	UUID              string `json:"uuid"`
	CredentialID      string `json:"credential_id,omitempty"`
	Password          string `json:"password,omitempty"`
	SubscriptionToken string `json:"subscription_token,omitempty"`
	StatsKey          string `json:"stats_key,omitempty"`
	Email             string `json:"email"`
	Enabled           bool   `json:"enabled"`
	Up                int64  `json:"up"`
	Down              int64  `json:"down"`
	TrafficLimit      int64  `json:"traffic_limit"`
	ExpiryAt          int64  `json:"expiry_at"`
}

type ClientTrafficUpdate struct {
	Up   int64
	Down int64
}

func (c Client) CredentialIDValue() string {
	if strings.TrimSpace(c.CredentialID) != "" {
		return strings.TrimSpace(c.CredentialID)
	}
	return strings.TrimSpace(c.UUID)
}

func (c Client) PasswordValue() string {
	if strings.TrimSpace(c.Password) != "" {
		return c.Password
	}
	return c.UUID
}

type OutboundSettings struct {
	Security      string   `json:"security,omitempty"`
	Network       string   `json:"network,omitempty"`
	TLS           bool     `json:"tls,omitempty"`
	Reality       bool     `json:"reality,omitempty"`
	SNI           string   `json:"sni,omitempty"`
	Host          string   `json:"host,omitempty"`
	Path          string   `json:"path,omitempty"`
	Flow          string   `json:"flow,omitempty"`
	Fingerprint   string   `json:"fp,omitempty"`
	PublicKey     string   `json:"pbk,omitempty"`
	ShortID       string   `json:"sid,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	Method        string   `json:"method,omitempty"`
	ServiceName   string   `json:"service_name,omitempty"`
	AllowInsecure bool     `json:"allow_insecure,omitempty"`
}

func ParseOutboundSettings(raw string) OutboundSettings {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return OutboundSettings{}
	}
	var settings OutboundSettings
	_ = json.Unmarshal([]byte(raw), &settings)
	return settings
}

type TrafficRawStat struct {
	Engine    string
	ScopeType string
	ScopeKey  string
	RawUp     int64
	RawDown   int64
	Status    string
	Message   string
}

type TrafficStatusMarker struct {
	Engine    string
	ScopeType string
	ScopeKey  string
	Status    string
	Message   string
}

type TrafficState struct {
	Engine      string  `json:"engine"`
	ScopeType   string  `json:"scope_type"`
	ScopeKey    string  `json:"scope_key"`
	TotalUp     int64   `json:"total_up"`
	TotalDown   int64   `json:"total_down"`
	LastRawUp   int64   `json:"last_raw_up"`
	LastRawDown int64   `json:"last_raw_down"`
	RateUp      float64 `json:"rate_up"`
	RateDown    float64 `json:"rate_down"`
	LastSeenAt  string  `json:"last_seen_at"`
	Status      string  `json:"status"`
	Message     string  `json:"message,omitempty"`
}

type TrafficSample struct {
	SampledAt string  `json:"sampled_at"`
	Engine    string  `json:"engine"`
	ScopeType string  `json:"scope_type"`
	ScopeKey  string  `json:"scope_key"`
	TotalUp   int64   `json:"total_up"`
	TotalDown int64   `json:"total_down"`
	RateUp    float64 `json:"rate_up"`
	RateDown  float64 `json:"rate_down"`
	Status    string  `json:"status"`
}

type ClientTrafficUsage struct {
	ClientID   int64   `json:"client_id"`
	StatsKey   string  `json:"stats_key"`
	Engine     string  `json:"engine"`
	TotalUp    int64   `json:"total_up"`
	TotalDown  int64   `json:"total_down"`
	RateUp     float64 `json:"rate_up"`
	RateDown   float64 `json:"rate_down"`
	Status     string  `json:"status"`
	Message    string  `json:"message,omitempty"`
	LastSeenAt string  `json:"last_seen_at,omitempty"`
}

type CreateInboundParams struct {
	UUID                  string              `json:"uuid,omitempty"`
	Remark                string              `json:"remark"`
	Protocol              string              `json:"protocol"`
	Port                  int                 `json:"port"`
	Network               string              `json:"network"`
	Security              string              `json:"security"`
	WsPath                string              `json:"ws_path"`
	WsHost                string              `json:"ws_host"`
	GrpcServiceName       string              `json:"grpc_service_name"`
	RealityDest           string              `json:"reality_dest"`
	RealityServerNames    string              `json:"reality_server_names"`
	RealityShortID        string              `json:"reality_short_id"`
	RealityPrivateKey     string              `json:"reality_private_key"`
	RealityPublicKey      string              `json:"reality_public_key"`
	SSMethod              string              `json:"ss_method"`
	TLSCertFile           string              `json:"tls_cert_file"`
	TLSKeyFile            string              `json:"tls_key_file"`
	TLSSNI                string              `json:"tls_sni"`
	TLSFingerprint        string              `json:"tls_fingerprint"`
	TLSALPN               string              `json:"tls_alpn"`
	XHTTPPath             string              `json:"xhttp_path"`
	XHTTPMode             string              `json:"xhttp_mode"`
	Hy2UpMbps             int                 `json:"hy2_up_mbps"`
	Hy2DownMbps           int                 `json:"hy2_down_mbps"`
	Hy2Obfs               string              `json:"hy2_obfs"`
	Hy2ObfsPassword       string              `json:"hy2_obfs_password"`
	Hy2MPort              string              `json:"hy2_mport"`
	TuicCongestionControl string              `json:"tuic_congestion_control"`
	TuicZeroRTT           bool                `json:"tuic_zero_rtt"`
	WgPrivateKey          string              `json:"wg_private_key"`
	WgAddress             string              `json:"wg_address"`
	WgPeerPublicKey       string              `json:"wg_peer_public_key"`
	WgAllowedIPs          string              `json:"wg_allowed_ips"`
	WgEndpoint            string              `json:"wg_endpoint"`
	WgPresharedKey        string              `json:"wg_preshared_key"`
	WgMTU                 int                 `json:"wg_mtu"`
	ShadowTLSVersion      int                 `json:"shadowtls_version"`
	ShadowTLSPassword     string              `json:"shadowtls_password"`
	InitialClient         *CreateClientParams `json:"initial_client,omitempty"`
}

type CreateClientParams struct {
	InboundID    int64  `json:"inbound_id,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	Password     string `json:"password,omitempty"`
	Email        string `json:"email"`
	Enabled      *bool  `json:"enabled,omitempty"`
	TrafficLimit int64  `json:"traffic_limit,omitempty"`
	ExpiryAt     int64  `json:"expiry_at,omitempty"`
}

type UpdateInboundParams struct {
	UUID                  string `json:"uuid"`
	Remark                string `json:"remark"`
	Protocol              string `json:"protocol"`
	Port                  int    `json:"port"`
	Network               string `json:"network"`
	Security              string `json:"security"`
	Enabled               bool   `json:"enabled"`
	WsPath                string `json:"ws_path"`
	WsHost                string `json:"ws_host"`
	GrpcServiceName       string `json:"grpc_service_name"`
	RealityDest           string `json:"reality_dest"`
	RealityServerNames    string `json:"reality_server_names"`
	RealityShortID        string `json:"reality_short_id"`
	RealityPrivateKey     string `json:"reality_private_key"`
	RealityPublicKey      string `json:"reality_public_key"`
	SSMethod              string `json:"ss_method"`
	TLSCertFile           string `json:"tls_cert_file"`
	TLSKeyFile            string `json:"tls_key_file"`
	TLSSNI                string `json:"tls_sni"`
	TLSFingerprint        string `json:"tls_fingerprint"`
	TLSALPN               string `json:"tls_alpn"`
	XHTTPPath             string `json:"xhttp_path"`
	XHTTPMode             string `json:"xhttp_mode"`
	Hy2UpMbps             int    `json:"hy2_up_mbps"`
	Hy2DownMbps           int    `json:"hy2_down_mbps"`
	Hy2Obfs               string `json:"hy2_obfs"`
	Hy2ObfsPassword       string `json:"hy2_obfs_password"`
	Hy2MPort              string `json:"hy2_mport"`
	TuicCongestionControl string `json:"tuic_congestion_control"`
	TuicZeroRTT           bool   `json:"tuic_zero_rtt"`
	WgPrivateKey          string `json:"wg_private_key"`
	WgAddress             string `json:"wg_address"`
	WgPeerPublicKey       string `json:"wg_peer_public_key"`
	WgAllowedIPs          string `json:"wg_allowed_ips"`
	WgEndpoint            string `json:"wg_endpoint"`
	WgPresharedKey        string `json:"wg_preshared_key"`
	WgMTU                 int    `json:"wg_mtu"`
	ShadowTLSVersion      int    `json:"shadowtls_version"`
	ShadowTLSPassword     string `json:"shadowtls_password"`
}

type UpdateClientParams struct {
	UUID         string `json:"uuid,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	Password     string `json:"password,omitempty"`
	Email        string `json:"email"`
	Enabled      bool   `json:"enabled"`
	TrafficLimit int64  `json:"traffic_limit"`
	ExpiryAt     int64  `json:"expiry_at"`
}
