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
	ID       int64    `json:"id"`
	UUID     string   `json:"uuid"`
	Remark   string   `json:"remark"`
	Protocol string   `json:"protocol"`
	Port     int      `json:"port"`
	Network  string   `json:"network"`
	Security string   `json:"security"`
	Enabled  bool     `json:"enabled"`
	Clients  []Client `json:"clients"`
}

type Client struct {
	ID        int64  `json:"id"`
	InboundID int64  `json:"inbound_id"`
	UUID      string `json:"uuid"`
	Email     string `json:"email"`
	Enabled   bool   `json:"enabled"`
}

type CreateInboundParams struct {
	Remark   string
	Protocol string
	Port     int
	Network  string
	Security string
}

type CreateClientParams struct {
	InboundID int64
	Email     string
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
	return err
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
	id, uuid, err := s.insertInbound(ctx, remark, protocol, params.Port, network, security)
	if err != nil {
		return Inbound{}, err
	}
	return Inbound{ID: id, UUID: uuid, Remark: remark, Protocol: protocol, Port: params.Port, Network: network, Security: security, Enabled: true, Clients: []Client{}}, nil
}

func (s *Store) insertInbound(ctx context.Context, remark, protocol string, port int, network, security string) (int64, string, error) {
	uuid := newUUID()
	result, err := s.db.ExecContext(ctx, `
INSERT INTO inbounds (uuid, remark, protocol, port, network, security, enabled, created_at)
VALUES (?, ?, ?, ?, ?, ?, 1, ?)
`, uuid, remark, protocol, port, network, security, time.Now().UTC().Format(time.RFC3339))
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
INSERT INTO clients (inbound_id, uuid, email, enabled, created_at)
VALUES (?, ?, ?, 1, ?)
`, params.InboundID, uuid, email, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return Client{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Client{}, err
	}
	return Client{ID: id, InboundID: params.InboundID, UUID: uuid, Email: email, Enabled: true}, nil
}

func (s *Store) ListInbounds(ctx context.Context) ([]Inbound, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, uuid, remark, protocol, port, network, security, enabled
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
		if err := rows.Scan(&inbound.ID, &inbound.UUID, &inbound.Remark, &inbound.Protocol, &inbound.Port, &inbound.Network, &inbound.Security, &enabled); err != nil {
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
SELECT id, inbound_id, uuid, email, enabled
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
		if err := clientRows.Scan(&client.ID, &client.InboundID, &client.UUID, &client.Email, &enabled); err != nil {
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
