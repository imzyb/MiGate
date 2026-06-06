package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var supportedProtocols = map[string]bool{
	"vless":       true,
	"vmess":       true,
	"trojan":      true,
	"shadowsocks": true,
	"hysteria2":   true,
}

var supportedOutboundProtocols = map[string]bool{
	"freedom":   true,
	"blackhole": true,
	"socks":     true,
	"http":      true,
}

type RoutingRule struct {
	ID          int64  `json:"id"`
	InboundTag  string `json:"inbound_tag"`
	OutboundTag string `json:"outbound_tag"`
	Domain      string `json:"domain"`
	Protocol    string `json:"protocol"`
	Enabled     bool   `json:"enabled"`
	Sort        int    `json:"sort"`
}

type CreateRoutingRuleParams struct {
	InboundTag  string `json:"inbound_tag"`
	OutboundTag string `json:"outbound_tag"`
	Domain      string `json:"domain"`
	Protocol    string `json:"protocol"`
	Enabled     bool   `json:"enabled"`
}

type UpdateRoutingRuleParams struct {
	InboundTag  string `json:"inbound_tag"`
	OutboundTag string `json:"outbound_tag"`
	Domain      string `json:"domain"`
	Protocol    string `json:"protocol"`
	Enabled     bool   `json:"enabled"`
}

type Store struct {
	db *sql.DB
}

type Inbound struct {
	ID                 int64    `json:"id"`
	UUID               string   `json:"uuid"`
	Remark             string   `json:"remark"`
	Protocol           string   `json:"protocol"`
	Port               int      `json:"port"`
	Network            string   `json:"network"`
	Security           string   `json:"security"`
	Enabled            bool     `json:"enabled"`
	WsPath             string   `json:"ws_path"`
	WsHost             string   `json:"ws_host"`
	GrpcServiceName    string   `json:"grpc_service_name"`
	RealityDest        string   `json:"reality_dest"`
	RealityServerNames string   `json:"reality_server_names"`
	RealityShortID     string   `json:"reality_short_id"`
	RealityPrivateKey  string   `json:"reality_private_key"`
	RealityPublicKey   string   `json:"reality_public_key"`
	SSMethod           string   `json:"ss_method"`
	TLSCertFile        string   `json:"tls_cert_file"`
	TLSKeyFile         string   `json:"tls_key_file"`
	TLSSNI             string   `json:"tls_sni"`
	TLSFingerprint     string   `json:"tls_fingerprint"`
	TLSALPN            string   `json:"tls_alpn"`
	XHTTPPath          string   `json:"xhttp_path"`
	XHTTPMode          string   `json:"xhttp_mode"`
	Hy2UpMbps          int      `json:"hy2_up_mbps"`
	Hy2DownMbps        int      `json:"hy2_down_mbps"`
	Hy2Obfs            string   `json:"hy2_obfs"`
	Hy2ObfsPassword    string   `json:"hy2_obfs_password"`
	Clients            []Client `json:"clients"`
}

type Outbound struct {
	ID       int64  `json:"id"`
	Tag      string `json:"tag"`
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
	Sort     int    `json:"sort"`
}

type CreateOutboundParams struct {
	Tag      string `json:"tag"`
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type UpdateOutboundParams struct {
	Tag      string `json:"tag"`
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Enabled  bool   `json:"enabled"`
}

type Client struct {
	ID           int64  `json:"id"`
	InboundID    int64  `json:"inbound_id"`
	UUID         string `json:"uuid"`
	Email        string `json:"email"`
	Enabled      bool   `json:"enabled"`
	Up           int64  `json:"up"`
	Down         int64  `json:"down"`
	TrafficLimit int64  `json:"traffic_limit"`
	ExpiryAt     int64  `json:"expiry_at"`
}

type CreateInboundParams struct {
	UUID               string              `json:"uuid,omitempty"`
	Remark             string              `json:"remark"`
	Protocol           string              `json:"protocol"`
	Port               int                 `json:"port"`
	Network            string              `json:"network"`
	Security           string              `json:"security"`
	WsPath             string              `json:"ws_path"`
	WsHost             string              `json:"ws_host"`
	GrpcServiceName    string              `json:"grpc_service_name"`
	RealityDest        string              `json:"reality_dest"`
	RealityServerNames string              `json:"reality_server_names"`
	RealityShortID     string              `json:"reality_short_id"`
	RealityPrivateKey  string              `json:"reality_private_key"`
	RealityPublicKey   string              `json:"reality_public_key"`
	SSMethod           string              `json:"ss_method"`
	TLSCertFile        string              `json:"tls_cert_file"`
	TLSKeyFile         string              `json:"tls_key_file"`
	TLSSNI             string              `json:"tls_sni"`
	TLSFingerprint     string              `json:"tls_fingerprint"`
	TLSALPN            string              `json:"tls_alpn"`
	XHTTPPath          string              `json:"xhttp_path"`
	XHTTPMode          string              `json:"xhttp_mode"`
	Hy2UpMbps          int                 `json:"hy2_up_mbps"`
	Hy2DownMbps        int                 `json:"hy2_down_mbps"`
	Hy2Obfs            string              `json:"hy2_obfs"`
	Hy2ObfsPassword    string              `json:"hy2_obfs_password"`
	InitialClient      *CreateClientParams `json:"initial_client,omitempty"`
}

type CreateClientParams struct {
	InboundID    int64  `json:"inbound_id,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	Email        string `json:"email"`
	TrafficLimit int64  `json:"traffic_limit,omitempty"`
	ExpiryAt     int64  `json:"expiry_at,omitempty"`
}

type UpdateInboundParams struct {
	Remark             string `json:"remark"`
	Protocol           string `json:"protocol"`
	Port               int    `json:"port"`
	Network            string `json:"network"`
	Security           string `json:"security"`
	Enabled            bool   `json:"enabled"`
	WsPath             string `json:"ws_path"`
	WsHost             string `json:"ws_host"`
	GrpcServiceName    string `json:"grpc_service_name"`
	RealityDest        string `json:"reality_dest"`
	RealityServerNames string `json:"reality_server_names"`
	RealityShortID     string `json:"reality_short_id"`
	RealityPrivateKey  string `json:"reality_private_key"`
	RealityPublicKey   string `json:"reality_public_key"`
	SSMethod           string `json:"ss_method"`
	TLSCertFile        string `json:"tls_cert_file"`
	TLSKeyFile         string `json:"tls_key_file"`
	TLSSNI             string `json:"tls_sni"`
	TLSFingerprint     string `json:"tls_fingerprint"`
	TLSALPN            string `json:"tls_alpn"`
	XHTTPPath          string `json:"xhttp_path"`
	XHTTPMode          string `json:"xhttp_mode"`
	Hy2UpMbps          int    `json:"hy2_up_mbps"`
	Hy2DownMbps        int    `json:"hy2_down_mbps"`
	Hy2Obfs            string `json:"hy2_obfs"`
	Hy2ObfsPassword    string `json:"hy2_obfs_password"`
}

type UpdateClientParams struct {
	Email        string `json:"email"`
	Enabled      bool   `json:"enabled"`
	TrafficLimit int64  `json:"traffic_limit"`
	ExpiryAt     int64  `json:"expiry_at"`
}

func Open(ctx context.Context, path string) (*Store, error) {
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	store := &Store{db: database}
	if err := store.migrate(ctx); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS inbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  remark TEXT NOT NULL,
  protocol TEXT NOT NULL,
  port INTEGER NOT NULL,
  network TEXT NOT NULL,
  security TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  inbound_id INTEGER NOT NULL REFERENCES inbounds(id) ON DELETE CASCADE,
  uuid TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_clients_inbound_id ON clients(inbound_id);
CREATE TABLE IF NOT EXISTS outbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tag TEXT NOT NULL UNIQUE,
  remark TEXT NOT NULL,
  protocol TEXT NOT NULL,
  address TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL DEFAULT 0,
  username TEXT NOT NULL DEFAULT '',
  password TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  sort INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS routing_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  inbound_tag TEXT NOT NULL DEFAULT '',
  outbound_tag TEXT NOT NULL,
  domain TEXT NOT NULL DEFAULT '',
  protocol TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  sort INTEGER NOT NULL DEFAULT 0
);
`)
	if err != nil {
		return err
	}
	if err := s.seedDefaultOutbounds(ctx); err != nil {
		return err
	}
	// Migration: add traffic/expiry columns (ignore errors if already exist)
	for _, col := range []struct{ name, typ string }{
		{"up", "INTEGER NOT NULL DEFAULT 0"},
		{"down", "INTEGER NOT NULL DEFAULT 0"},
		{"traffic_limit", "INTEGER NOT NULL DEFAULT 0"},
		{"expiry_at", "INTEGER NOT NULL DEFAULT 0"},
	} {
		_, _ = s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE clients ADD COLUMN %s %s", col.name, col.typ))
	}
	// Migration: add transport columns to inbounds (ignore errors if already exist)
	for _, col := range []struct{ name, typ, def string }{
		{"ws_path", "TEXT", "DEFAULT ''"},
		{"ws_host", "TEXT", "DEFAULT ''"},
		{"grpc_service_name", "TEXT", "DEFAULT ''"},
		{"reality_dest", "TEXT", "DEFAULT ''"},
		{"reality_server_names", "TEXT", "DEFAULT ''"},
		{"reality_short_id", "TEXT", "DEFAULT ''"},
		{"reality_private_key", "TEXT", "DEFAULT ''"},
		{"reality_public_key", "TEXT", "DEFAULT ''"},
		{"ss_method", "TEXT", "DEFAULT '2022-blake3-aes-128-gcm'"},
		{"tls_cert_file", "TEXT", "DEFAULT ''"},
		{"tls_key_file", "TEXT", "DEFAULT ''"},
		{"xhttp_path", "TEXT", "DEFAULT ''"},
		{"xhttp_mode", "TEXT", "DEFAULT ''"},
		{"hy2_up_mbps", "INTEGER", "DEFAULT 0"},
		{"hy2_down_mbps", "INTEGER", "DEFAULT 0"},
		{"hy2_obfs", "TEXT", "DEFAULT ''"},
		{"hy2_obfs_password", "TEXT", "DEFAULT ''"},
		{"tls_sni", "TEXT", "DEFAULT ''"},
		{"tls_fingerprint", "TEXT", "DEFAULT ''"},
		{"tls_alpn", "TEXT", "DEFAULT ''"},
	} {
		_, _ = s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE inbounds ADD COLUMN %s %s %s", col.name, col.typ, col.def))
	}
	return nil
}

func (s *Store) seedDefaultOutbounds(ctx context.Context) error {
	now := time.Now().UTC().Format(time.RFC3339)
	defaults := []Outbound{
		{Tag: "direct", Remark: "直接连接", Protocol: "freedom", Enabled: true, Sort: 0},
		{Tag: "blocked", Remark: "阻断", Protocol: "blackhole", Enabled: true, Sort: 1},
	}
	for _, outbound := range defaults {
		_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO outbounds (tag, remark, protocol, address, port, username, password, enabled, sort, created_at) VALUES (?, ?, ?, '', 0, '', '', 1, ?, ?)`,
			outbound.Tag, outbound.Remark, outbound.Protocol, outbound.Sort, now)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListOutbounds(ctx context.Context) ([]Outbound, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, tag, remark, protocol, address, port, username, password, enabled, sort FROM outbounds ORDER BY sort ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	outbounds := []Outbound{}
	for rows.Next() {
		var outbound Outbound
		var enabled int
		if err := rows.Scan(&outbound.ID, &outbound.Tag, &outbound.Remark, &outbound.Protocol, &outbound.Address, &outbound.Port, &outbound.Username, &outbound.Password, &enabled, &outbound.Sort); err != nil {
			return nil, err
		}
		outbound.Enabled = enabled != 0
		outbounds = append(outbounds, outbound)
	}
	return outbounds, rows.Err()
}

func (s *Store) CreateOutbound(ctx context.Context, params CreateOutboundParams) (Outbound, error) {
	protocol := strings.ToLower(strings.TrimSpace(params.Protocol))
	if !supportedOutboundProtocols[protocol] {
		return Outbound{}, fmt.Errorf("unsupported outbound protocol: %s", params.Protocol)
	}
	tag := strings.TrimSpace(params.Tag)
	if tag == "" {
		return Outbound{}, fmt.Errorf("tag cannot be empty")
	}
	remark := strings.TrimSpace(params.Remark)
	if remark == "" {
		remark = tag
	}
	address := strings.TrimSpace(params.Address)
	if (protocol == "socks" || protocol == "http") && address == "" {
		return Outbound{}, fmt.Errorf("address cannot be empty")
	}
	if (protocol == "socks" || protocol == "http") && (params.Port <= 0 || params.Port > 65535) {
		return Outbound{}, fmt.Errorf("invalid port: %d", params.Port)
	}
	var sort int
	_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(sort)+1, 0) FROM outbounds`).Scan(&sort)
	result, err := s.db.ExecContext(ctx, `INSERT INTO outbounds (tag, remark, protocol, address, port, username, password, enabled, sort, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		tag, remark, protocol, address, params.Port, strings.TrimSpace(params.Username), params.Password, sort, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return Outbound{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Outbound{}, err
	}
	return Outbound{ID: id, Tag: tag, Remark: remark, Protocol: protocol, Address: address, Port: params.Port, Username: strings.TrimSpace(params.Username), Password: params.Password, Enabled: true, Sort: sort}, nil
}

func (s *Store) UpdateOutbound(ctx context.Context, id int64, params UpdateOutboundParams) (Outbound, error) {
	protocol := strings.ToLower(strings.TrimSpace(params.Protocol))
	if !supportedOutboundProtocols[protocol] {
		return Outbound{}, fmt.Errorf("unsupported outbound protocol: %s", params.Protocol)
	}
	tag := strings.TrimSpace(params.Tag)
	if tag == "" {
		return Outbound{}, fmt.Errorf("tag cannot be empty")
	}
	remark := strings.TrimSpace(params.Remark)
	if remark == "" {
		remark = tag
	}
	address := strings.TrimSpace(params.Address)
	if (protocol == "socks" || protocol == "http") && address == "" {
		return Outbound{}, fmt.Errorf("address cannot be empty")
	}
	if (protocol == "socks" || protocol == "http") && (params.Port <= 0 || params.Port > 65535) {
		return Outbound{}, fmt.Errorf("invalid port: %d", params.Port)
	}
	enabled := 0
	if params.Enabled {
		enabled = 1
	}
	result, err := s.db.ExecContext(ctx, `UPDATE outbounds SET tag=?, remark=?, protocol=?, address=?, port=?, username=?, password=?, enabled=? WHERE id=?`,
		tag, remark, protocol, address, params.Port, strings.TrimSpace(params.Username), params.Password, enabled, id)
	if err != nil {
		return Outbound{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return Outbound{}, err
	}
	if n == 0 {
		return Outbound{}, fmt.Errorf("outbound not found: %d", id)
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, tag, remark, protocol, address, port, username, password, enabled, sort FROM outbounds WHERE id=?`, id)
	var outbound Outbound
	var dbEnabled int
	if err := row.Scan(&outbound.ID, &outbound.Tag, &outbound.Remark, &outbound.Protocol, &outbound.Address, &outbound.Port, &outbound.Username, &outbound.Password, &dbEnabled, &outbound.Sort); err != nil {
		return Outbound{}, err
	}
	outbound.Enabled = dbEnabled != 0
	return outbound, nil
}

func (s *Store) DeleteOutbound(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM outbounds WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("outbound not found: %d", id)
	}
	return nil
}

func (s *Store) ReorderOutbounds(ctx context.Context, ids []int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Collect IDs of editable (non-default) outbounds already in DB
	rows, err := tx.QueryContext(ctx, `SELECT id FROM outbounds WHERE protocol NOT IN ('freedom','blackhole') ORDER BY sort ASC`)
	if err != nil {
		return err
	}
	var existing []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		existing = append(existing, id)
	}
	rows.Close()

	if len(ids) != len(existing) {
		return fmt.Errorf("expected %d IDs for reordering, got %d", len(existing), len(ids))
	}

	// Find defaults count
	var defaultCount int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbounds WHERE protocol IN ('freedom','blackhole')`).Scan(&defaultCount); err != nil {
		return err
	}

	for i, id := range ids {
		_, err := tx.ExecContext(ctx, `UPDATE outbounds SET sort = ? WHERE id = ?`, int(defaultCount)+i, id)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListRoutingRules(ctx context.Context) ([]RoutingRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, inbound_tag, outbound_tag, domain, protocol, enabled, sort FROM routing_rules ORDER BY sort ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []RoutingRule
	for rows.Next() {
		var r RoutingRule
		var dbEnabled int
		if err := rows.Scan(&r.ID, &r.InboundTag, &r.OutboundTag, &r.Domain, &r.Protocol, &dbEnabled, &r.Sort); err != nil {
			return nil, err
		}
		r.Enabled = dbEnabled != 0
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *Store) CreateRoutingRule(ctx context.Context, params CreateRoutingRuleParams) (RoutingRule, error) {
	ob := strings.TrimSpace(params.OutboundTag)
	if ob == "" {
		return RoutingRule{}, fmt.Errorf("outbound_tag cannot be empty")
	}
	var sort int
	_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(sort)+1, 0) FROM routing_rules`).Scan(&sort)
	enabled := 0
	if params.Enabled {
		enabled = 1
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO routing_rules (inbound_tag, outbound_tag, domain, protocol, enabled, sort) VALUES (?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(params.InboundTag), ob, strings.TrimSpace(params.Domain), strings.TrimSpace(params.Protocol), enabled, sort)
	if err != nil {
		return RoutingRule{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return RoutingRule{}, err
	}
	return RoutingRule{ID: id, InboundTag: strings.TrimSpace(params.InboundTag), OutboundTag: ob, Domain: strings.TrimSpace(params.Domain), Protocol: strings.TrimSpace(params.Protocol), Enabled: params.Enabled, Sort: sort}, nil
}

func (s *Store) UpdateRoutingRule(ctx context.Context, id int64, params UpdateRoutingRuleParams) (RoutingRule, error) {
	ob := strings.TrimSpace(params.OutboundTag)
	if ob == "" {
		return RoutingRule{}, fmt.Errorf("outbound_tag cannot be empty")
	}
	enabled := 0
	if params.Enabled {
		enabled = 1
	}
	result, err := s.db.ExecContext(ctx, `UPDATE routing_rules SET inbound_tag=?, outbound_tag=?, domain=?, protocol=?, enabled=? WHERE id=?`,
		strings.TrimSpace(params.InboundTag), ob, strings.TrimSpace(params.Domain), strings.TrimSpace(params.Protocol), enabled, id)
	if err != nil {
		return RoutingRule{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return RoutingRule{}, err
	}
	if n == 0 {
		return RoutingRule{}, fmt.Errorf("routing rule not found: %d", id)
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, inbound_tag, outbound_tag, domain, protocol, enabled, sort FROM routing_rules WHERE id=?`, id)
	var r RoutingRule
	var dbEnabled int
	if err := row.Scan(&r.ID, &r.InboundTag, &r.OutboundTag, &r.Domain, &r.Protocol, &dbEnabled, &r.Sort); err != nil {
		return RoutingRule{}, err
	}
	r.Enabled = dbEnabled != 0
	return r, nil
}

func (s *Store) DeleteRoutingRule(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM routing_rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("routing rule not found: %d", id)
	}
	return nil
}

func (s *Store) CreateInbound(ctx context.Context, params CreateInboundParams) (Inbound, error) {
	protocol := strings.ToLower(strings.TrimSpace(params.Protocol))
	if !supportedProtocols[protocol] {
		return Inbound{}, fmt.Errorf("unsupported protocol: %s", params.Protocol)
	}
	if params.Port <= 0 || params.Port > 65535 {
		return Inbound{}, fmt.Errorf("invalid port: %d", params.Port)
	}
	network := strings.ToLower(strings.TrimSpace(params.Network))
	if network == "" {
		network = "tcp"
	}
	security := strings.ToLower(strings.TrimSpace(params.Security))
	remark := strings.TrimSpace(params.Remark)
	if remark == "" {
		remark = protocol
	}
	id, uuid, err := s.insertInbound(ctx, params.UUID, remark, protocol, params.Port, network, security,
		params.WsPath, params.WsHost, params.GrpcServiceName,
		params.RealityDest, params.RealityServerNames, params.RealityShortID, params.RealityPrivateKey, params.RealityPublicKey,
		params.SSMethod, params.TLSCertFile, params.TLSKeyFile, params.TLSSNI, params.TLSFingerprint, params.TLSALPN, params.XHTTPPath, params.XHTTPMode,
		params.Hy2UpMbps, params.Hy2DownMbps, params.Hy2Obfs, params.Hy2ObfsPassword)
	if err != nil {
		return Inbound{}, err
	}
	var clients []Client
	if params.InitialClient != nil {
		params.InitialClient.InboundID = id
		createdClient, err := s.CreateClient(ctx, *params.InitialClient)
		if err != nil {
			return Inbound{}, err
		}
		clients = []Client{createdClient}
	}
	return Inbound{ID: id, UUID: uuid, Remark: remark, Protocol: protocol, Port: params.Port, Network: network, Security: security, Enabled: true,
		WsPath: params.WsPath, WsHost: params.WsHost, GrpcServiceName: params.GrpcServiceName,
		RealityDest: params.RealityDest, RealityServerNames: params.RealityServerNames, RealityShortID: params.RealityShortID,
		RealityPrivateKey: params.RealityPrivateKey,
		RealityPublicKey:  params.RealityPublicKey,
		SSMethod:          params.SSMethod,
		TLSCertFile:       params.TLSCertFile, TLSKeyFile: params.TLSKeyFile,
		TLSSNI: params.TLSSNI, TLSFingerprint: params.TLSFingerprint, TLSALPN: params.TLSALPN,
		XHTTPPath: params.XHTTPPath, XHTTPMode: params.XHTTPMode,
		Hy2UpMbps: params.Hy2UpMbps, Hy2DownMbps: params.Hy2DownMbps,
		Hy2Obfs: params.Hy2Obfs, Hy2ObfsPassword: params.Hy2ObfsPassword,
		Clients: clients}, nil
}

func (s *Store) insertInbound(ctx context.Context, inboundUUID, remark, protocol string, port int, network, security string,
	wsPath, wsHost, grpcServiceName, realityDest, realityServerNames, realityShortID, realityPrivateKey, realityPublicKey, ssMethod, tlsCertFile, tlsKeyFile, tlsSNI, tlsFingerprint, tlsALPN, xhttpPath, xhttpMode string,
	hy2UpMbps, hy2DownMbps int, hy2Obfs, hy2ObfsPassword string) (int64, string, error) {
	uuid := strings.TrimSpace(inboundUUID)
	if uuid == "" {
		uuid = newUUID()
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO inbounds (uuid, remark, protocol, port, network, security, enabled, created_at,
	  ws_path, ws_host, grpc_service_name, reality_dest, reality_server_names, reality_short_id, reality_private_key, reality_public_key, ss_method, tls_cert_file, tls_key_file, tls_sni, tls_fingerprint, tls_alpn, xhttp_path, xhttp_mode,
	  hy2_up_mbps, hy2_down_mbps, hy2_obfs, hy2_obfs_password)
	VALUES (?, ?, ?, ?, ?, ?, 1, ?,
	  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
	  ?, ?, ?, ?)`,
		uuid, remark, protocol, port, network, security, time.Now().UTC().Format(time.RFC3339),
		wsPath, wsHost, grpcServiceName, realityDest, realityServerNames, realityShortID, realityPrivateKey, realityPublicKey, ssMethod, tlsCertFile, tlsKeyFile, tlsSNI, tlsFingerprint, tlsALPN, xhttpPath, xhttpMode,
		hy2UpMbps, hy2DownMbps, hy2Obfs, hy2ObfsPassword)
	if err != nil {
		return 0, "", err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, "", err
	}
	return id, uuid, nil
}

func (s *Store) CreateClient(ctx context.Context, params CreateClientParams) (Client, error) {
	if params.InboundID <= 0 {
		return Client{}, fmt.Errorf("invalid inbound id: %d", params.InboundID)
	}
	email := strings.TrimSpace(params.Email)
	if email == "" {
		email = "client"
	}
	uuid := strings.TrimSpace(params.UUID)
	if uuid == "" {
		uuid = newUUID()
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO clients (inbound_id, uuid, email, enabled, created_at, traffic_limit, expiry_at)
VALUES (?, ?, ?, 1, ?, ?, ?)
`, params.InboundID, uuid, email, time.Now().UTC().Format(time.RFC3339), params.TrafficLimit, params.ExpiryAt)
	if err != nil {
		return Client{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Client{}, err
	}
	return Client{ID: id, InboundID: params.InboundID, UUID: uuid, Email: email, Enabled: true, TrafficLimit: params.TrafficLimit, ExpiryAt: params.ExpiryAt}, nil
}

func (s *Store) DeleteClient(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("client not found: %d", id)
	}
	return nil
}

func (s *Store) DeleteInbound(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM inbounds WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("inbound not found: %d", id)
	}
	return nil
}

func (s *Store) UpdateInbound(ctx context.Context, id int64, params UpdateInboundParams) (Inbound, error) {
	remark := strings.TrimSpace(params.Remark)
	if remark == "" {
		return Inbound{}, fmt.Errorf("remark cannot be empty")
	}
	if params.Port <= 0 || params.Port > 65535 {
		return Inbound{}, fmt.Errorf("invalid port: %d", params.Port)
	}
	network := strings.ToLower(strings.TrimSpace(params.Network))
	if network == "" {
		network = "tcp"
	}
	security := strings.ToLower(strings.TrimSpace(params.Security))
	protocol := strings.ToLower(strings.TrimSpace(params.Protocol))
	if protocol == "" {
		protocol = "vless"
	}
	enabled := 0
	if params.Enabled {
		enabled = 1
	}
	result, err := s.db.ExecContext(ctx, `UPDATE inbounds SET remark=?, protocol=?, port=?, network=?, security=?, enabled=?,
		ws_path=?, ws_host=?, grpc_service_name=?, reality_dest=?, reality_server_names=?, reality_short_id=?, reality_private_key=?, reality_public_key=?, ss_method=?,
		tls_cert_file=?, tls_key_file=?, tls_sni=?, tls_fingerprint=?, tls_alpn=?, xhttp_path=?, xhttp_mode=?,
		hy2_up_mbps=?, hy2_down_mbps=?, hy2_obfs=?, hy2_obfs_password=? WHERE id=?`,
		remark, protocol, params.Port, network, security, enabled,
		params.WsPath, params.WsHost, params.GrpcServiceName, params.RealityDest, params.RealityServerNames, params.RealityShortID, params.RealityPrivateKey, params.RealityPublicKey, params.SSMethod,
		params.TLSCertFile, params.TLSKeyFile, params.TLSSNI, params.TLSFingerprint, params.TLSALPN, params.XHTTPPath, params.XHTTPMode,
		params.Hy2UpMbps, params.Hy2DownMbps, params.Hy2Obfs, params.Hy2ObfsPassword, id)
	if err != nil {
		return Inbound{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return Inbound{}, err
	}
	if n == 0 {
		return Inbound{}, fmt.Errorf("inbound not found: %d", id)
	}
	// Reload to get the full row
	row := s.db.QueryRowContext(ctx, `SELECT id, uuid, remark, protocol, port, network, security, enabled,
		ws_path, ws_host, grpc_service_name, reality_dest, reality_server_names, reality_short_id, reality_private_key, reality_public_key, ss_method,
		tls_cert_file, tls_key_file, tls_sni, tls_fingerprint, tls_alpn, xhttp_path, xhttp_mode,
		hy2_up_mbps, hy2_down_mbps, hy2_obfs, hy2_obfs_password FROM inbounds WHERE id=?`, id)
	var inbound Inbound
	var dbEnabled int
	if err := row.Scan(&inbound.ID, &inbound.UUID, &inbound.Remark, &inbound.Protocol, &inbound.Port, &inbound.Network, &inbound.Security, &dbEnabled,
		&inbound.WsPath, &inbound.WsHost, &inbound.GrpcServiceName, &inbound.RealityDest, &inbound.RealityServerNames, &inbound.RealityShortID, &inbound.RealityPrivateKey, &inbound.RealityPublicKey, &inbound.SSMethod,
		&inbound.TLSCertFile, &inbound.TLSKeyFile, &inbound.TLSSNI, &inbound.TLSFingerprint, &inbound.TLSALPN, &inbound.XHTTPPath, &inbound.XHTTPMode,
		&inbound.Hy2UpMbps, &inbound.Hy2DownMbps, &inbound.Hy2Obfs, &inbound.Hy2ObfsPassword); err != nil {
		return Inbound{}, err
	}
	inbound.Enabled = dbEnabled != 0
	inbound.Clients = []Client{}
	return inbound, nil
}

func (s *Store) UpdateClient(ctx context.Context, id int64, params UpdateClientParams) (Client, error) {
	email := strings.TrimSpace(params.Email)
	if email == "" {
		email = "client"
	}
	enabled := 0
	if params.Enabled {
		enabled = 1
	}
	result, err := s.db.ExecContext(ctx, `UPDATE clients SET email=?, enabled=?, traffic_limit=?, expiry_at=? WHERE id=?`,
		email, enabled, params.TrafficLimit, params.ExpiryAt, id)
	if err != nil {
		return Client{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return Client{}, err
	}
	if n == 0 {
		return Client{}, fmt.Errorf("client not found: %d", id)
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, inbound_id, uuid, email, enabled, up, down, traffic_limit, expiry_at FROM clients WHERE id=?`, id)
	var client Client
	var dbEnabled int
	if err := row.Scan(&client.ID, &client.InboundID, &client.UUID, &client.Email, &dbEnabled, &client.Up, &client.Down, &client.TrafficLimit, &client.ExpiryAt); err != nil {
		return Client{}, err
	}
	client.Enabled = dbEnabled != 0
	return client, nil
}

func (s *Store) SetInboundEnabled(ctx context.Context, id int64, enabled bool) (Inbound, error) {
	dbEnabled := 0
	if enabled {
		dbEnabled = 1
	}
	result, err := s.db.ExecContext(ctx, `UPDATE inbounds SET enabled=? WHERE id=?`, dbEnabled, id)
	if err != nil {
		return Inbound{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return Inbound{}, err
	}
	if n == 0 {
		return Inbound{}, fmt.Errorf("inbound not found: %d", id)
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, uuid, remark, protocol, port, network, security, enabled,
		ws_path, ws_host, grpc_service_name, reality_dest, reality_server_names, reality_short_id, reality_private_key, reality_public_key, ss_method,
		tls_cert_file, tls_key_file, tls_sni, tls_fingerprint, tls_alpn, xhttp_path, xhttp_mode,
		hy2_up_mbps, hy2_down_mbps, hy2_obfs, hy2_obfs_password FROM inbounds WHERE id=?`, id)
	var inbound Inbound
	if err := row.Scan(&inbound.ID, &inbound.UUID, &inbound.Remark, &inbound.Protocol, &inbound.Port, &inbound.Network, &inbound.Security, &dbEnabled,
		&inbound.WsPath, &inbound.WsHost, &inbound.GrpcServiceName, &inbound.RealityDest, &inbound.RealityServerNames, &inbound.RealityShortID, &inbound.RealityPrivateKey, &inbound.RealityPublicKey, &inbound.SSMethod,
		&inbound.TLSCertFile, &inbound.TLSKeyFile, &inbound.TLSSNI, &inbound.TLSFingerprint, &inbound.TLSALPN, &inbound.XHTTPPath, &inbound.XHTTPMode,
		&inbound.Hy2UpMbps, &inbound.Hy2DownMbps, &inbound.Hy2Obfs, &inbound.Hy2ObfsPassword); err != nil {
		return Inbound{}, err
	}
	inbound.Enabled = dbEnabled != 0
	inbound.Clients = []Client{}
	return inbound, nil
}

func (s *Store) SetClientEnabled(ctx context.Context, inboundID int64, id int64, enabled bool) (Client, error) {
	dbEnabled := 0
	if enabled {
		dbEnabled = 1
	}
	result, err := s.db.ExecContext(ctx, `UPDATE clients SET enabled=? WHERE inbound_id=? AND id=?`, dbEnabled, inboundID, id)
	if err != nil {
		return Client{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return Client{}, err
	}
	if n == 0 {
		return Client{}, fmt.Errorf("client not found: %d", id)
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, inbound_id, uuid, email, enabled, up, down, traffic_limit, expiry_at FROM clients WHERE inbound_id=? AND id=?`, inboundID, id)
	var client Client
	if err := row.Scan(&client.ID, &client.InboundID, &client.UUID, &client.Email, &dbEnabled, &client.Up, &client.Down, &client.TrafficLimit, &client.ExpiryAt); err != nil {
		return Client{}, err
	}
	client.Enabled = dbEnabled != 0
	return client, nil
}

func (s *Store) ListInbounds(ctx context.Context) ([]Inbound, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, uuid, remark, protocol, port, network, security, enabled,
  ws_path, ws_host, grpc_service_name, reality_dest, reality_server_names, reality_short_id, reality_private_key, reality_public_key, ss_method,
  tls_cert_file, tls_key_file, tls_sni, tls_fingerprint, tls_alpn, xhttp_path, xhttp_mode,
  hy2_up_mbps, hy2_down_mbps, hy2_obfs, hy2_obfs_password
FROM inbounds
ORDER BY id ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var inbounds []Inbound
	byID := make(map[int64]int)
	for rows.Next() {
		var inbound Inbound
		var enabled int
		if err := rows.Scan(&inbound.ID, &inbound.UUID, &inbound.Remark, &inbound.Protocol, &inbound.Port, &inbound.Network, &inbound.Security, &enabled,
			&inbound.WsPath, &inbound.WsHost, &inbound.GrpcServiceName, &inbound.RealityDest, &inbound.RealityServerNames, &inbound.RealityShortID, &inbound.RealityPrivateKey, &inbound.RealityPublicKey, &inbound.SSMethod,
			&inbound.TLSCertFile, &inbound.TLSKeyFile, &inbound.TLSSNI, &inbound.TLSFingerprint, &inbound.TLSALPN, &inbound.XHTTPPath, &inbound.XHTTPMode,
			&inbound.Hy2UpMbps, &inbound.Hy2DownMbps, &inbound.Hy2Obfs, &inbound.Hy2ObfsPassword); err != nil {
			return nil, err
		}
		inbound.Enabled = enabled != 0
		inbound.Clients = []Client{}
		byID[inbound.ID] = len(inbounds)
		inbounds = append(inbounds, inbound)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	clientRows, err := s.db.QueryContext(ctx, `
SELECT id, inbound_id, uuid, email, enabled, up, down, traffic_limit, expiry_at
FROM clients
ORDER BY id ASC
`)
	if err != nil {
		return nil, err
	}
	defer clientRows.Close()
	for clientRows.Next() {
		var client Client
		var enabled int
		if err := clientRows.Scan(&client.ID, &client.InboundID, &client.UUID, &client.Email, &enabled, &client.Up, &client.Down, &client.TrafficLimit, &client.ExpiryAt); err != nil {
			return nil, err
		}
		client.Enabled = enabled != 0
		if idx, ok := byID[client.InboundID]; ok {
			inbounds[idx].Clients = append(inbounds[idx].Clients, client)
		}
	}
	if err := clientRows.Err(); err != nil {
		return nil, err
	}
	return inbounds, nil
}

func (s *Store) ResetClientTraffic(ctx context.Context, id int64) (Client, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE clients SET up=0, down=0 WHERE id=?`, id)
	if err != nil {
		return Client{}, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return Client{}, err
	}
	if n == 0 {
		return Client{}, fmt.Errorf("client not found: %d", id)
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, inbound_id, uuid, email, enabled, up, down, traffic_limit, expiry_at FROM clients WHERE id=?`, id)
	var client Client
	var dbEnabled int
	if err := row.Scan(&client.ID, &client.InboundID, &client.UUID, &client.Email, &dbEnabled, &client.Up, &client.Down, &client.TrafficLimit, &client.ExpiryAt); err != nil {
		return Client{}, err
	}
	client.Enabled = dbEnabled != 0
	return client, nil
}

// UpdateClientTraffic updates the traffic counters for a client by email.
// This is used by the traffic sync scheduler to update DB with Xray stats.
func (s *Store) UpdateClientTraffic(ctx context.Context, email string, uplink, downlink int64) error {
	result, err := s.db.ExecContext(ctx, `UPDATE clients SET up=?, down=? WHERE email=?`, uplink, downlink, email)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		// Client not found - may have been deleted, silently ignore
		return nil
	}
	return nil
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16]))
}
