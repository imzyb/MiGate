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
	RealityShortID     string `json:"reality_short_id"`
	RealityPrivateKey  string `json:"reality_private_key"`
	RealityPublicKey   string `json:"reality_public_key"`
	SSMethod           string `json:"ss_method"`
	TLSCertFile        string `json:"tls_cert_file"`
	TLSKeyFile         string `json:"tls_key_file"`
	XHTTPPath          string `json:"xhttp_path"`
	XHTTPMode          string `json:"xhttp_mode"`
	Clients            []Client `json:"clients"`
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
	Remark             string `json:"remark"`
	Protocol           string `json:"protocol"`
	Port               int    `json:"port"`
	Network            string `json:"network"`
	Security           string `json:"security"`
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
	XHTTPPath          string `json:"xhttp_path"`
	XHTTPMode          string `json:"xhttp_mode"`
	InitialClient      *CreateClientParams `json:"initial_client,omitempty"`
}

type CreateClientParams struct {
	InboundID    int64
	Email        string
	TrafficLimit int64
	ExpiryAt     int64
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
	XHTTPPath          string `json:"xhttp_path"`
	XHTTPMode          string `json:"xhttp_mode"`
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
`)
	if err != nil {
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
	} {
		_, _ = s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE inbounds ADD COLUMN %s %s %s", col.name, col.typ, col.def))
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
	id, uuid, err := s.insertInbound(ctx, remark, protocol, params.Port, network, security,
		params.WsPath, params.WsHost, params.GrpcServiceName,
		params.RealityDest, params.RealityServerNames, params.RealityShortID, params.RealityPrivateKey, params.RealityPublicKey,
		params.SSMethod, params.TLSCertFile, params.TLSKeyFile, params.XHTTPPath, params.XHTTPMode)
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
		XHTTPPath: params.XHTTPPath, XHTTPMode: params.XHTTPMode,
		Clients: clients}, nil
}

func (s *Store) insertInbound(ctx context.Context, remark, protocol string, port int, network, security string,
	wsPath, wsHost, grpcServiceName, realityDest, realityServerNames, realityShortID, realityPrivateKey, realityPublicKey, ssMethod, tlsCertFile, tlsKeyFile, xhttpPath, xhttpMode string) (int64, string, error) {
	uuid := newUUID()
	result, err := s.db.ExecContext(ctx, `
INSERT INTO inbounds (uuid, remark, protocol, port, network, security, enabled, created_at,
  ws_path, ws_host, grpc_service_name, reality_dest, reality_server_names, reality_short_id, reality_private_key, reality_public_key, ss_method, tls_cert_file, tls_key_file, xhttp_path, xhttp_mode)
VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`, uuid, remark, protocol, port, network, security, time.Now().UTC().Format(time.RFC3339),
		wsPath, wsHost, grpcServiceName, realityDest, realityServerNames, realityShortID, realityPrivateKey, realityPublicKey, ssMethod, tlsCertFile, tlsKeyFile, xhttpPath, xhttpMode)
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
	uuid := newUUID()
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
		tls_cert_file=?, tls_key_file=?, xhttp_path=?, xhttp_mode=? WHERE id=?`,
		remark, protocol, params.Port, network, security, enabled,
		params.WsPath, params.WsHost, params.GrpcServiceName, params.RealityDest, params.RealityServerNames, params.RealityShortID, params.RealityPrivateKey, params.RealityPublicKey, params.SSMethod,
		params.TLSCertFile, params.TLSKeyFile, params.XHTTPPath, params.XHTTPMode, id)
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
		tls_cert_file, tls_key_file, xhttp_path, xhttp_mode FROM inbounds WHERE id=?`, id)
	var inbound Inbound
	var dbEnabled int
	if err := row.Scan(&inbound.ID, &inbound.UUID, &inbound.Remark, &inbound.Protocol, &inbound.Port, &inbound.Network, &inbound.Security, &dbEnabled,
		&inbound.WsPath, &inbound.WsHost, &inbound.GrpcServiceName, &inbound.RealityDest, &inbound.RealityServerNames, &inbound.RealityShortID, &inbound.RealityPrivateKey, &inbound.RealityPublicKey, &inbound.SSMethod,
		&inbound.TLSCertFile, &inbound.TLSKeyFile, &inbound.XHTTPPath, &inbound.XHTTPMode); err != nil {
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
		tls_cert_file, tls_key_file, xhttp_path, xhttp_mode FROM inbounds WHERE id=?`, id)
	var inbound Inbound
	if err := row.Scan(&inbound.ID, &inbound.UUID, &inbound.Remark, &inbound.Protocol, &inbound.Port, &inbound.Network, &inbound.Security, &dbEnabled,
		&inbound.WsPath, &inbound.WsHost, &inbound.GrpcServiceName, &inbound.RealityDest, &inbound.RealityServerNames, &inbound.RealityShortID, &inbound.RealityPrivateKey, &inbound.RealityPublicKey, &inbound.SSMethod,
		&inbound.TLSCertFile, &inbound.TLSKeyFile, &inbound.XHTTPPath, &inbound.XHTTPMode); err != nil {
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
  tls_cert_file, tls_key_file, xhttp_path, xhttp_mode
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
			&inbound.TLSCertFile, &inbound.TLSKeyFile, &inbound.XHTTPPath, &inbound.XHTTPMode); err != nil {
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

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16]))
}
