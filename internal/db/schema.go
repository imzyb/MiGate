package db

import (
	"context"
	"database/sql"
)

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS inbounds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  remark TEXT NOT NULL,
  protocol TEXT NOT NULL,
  core TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL,
  network TEXT NOT NULL,
  security TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  ws_path TEXT NOT NULL DEFAULT '',
  ws_host TEXT NOT NULL DEFAULT '',
  grpc_service_name TEXT NOT NULL DEFAULT '',
  reality_dest TEXT NOT NULL DEFAULT '',
  reality_server_names TEXT NOT NULL DEFAULT '',
  reality_short_id TEXT NOT NULL DEFAULT '',
  reality_private_key TEXT NOT NULL DEFAULT '',
  reality_public_key TEXT NOT NULL DEFAULT '',
  ss_method TEXT NOT NULL DEFAULT '2022-blake3-aes-128-gcm',
  tls_cert_file TEXT NOT NULL DEFAULT '',
  tls_key_file TEXT NOT NULL DEFAULT '',
  tls_sni TEXT NOT NULL DEFAULT '',
  tls_fingerprint TEXT NOT NULL DEFAULT '',
  tls_alpn TEXT NOT NULL DEFAULT '',
  xhttp_path TEXT NOT NULL DEFAULT '',
  xhttp_mode TEXT NOT NULL DEFAULT '',
  hy2_up_mbps INTEGER NOT NULL DEFAULT 0,
  hy2_down_mbps INTEGER NOT NULL DEFAULT 0,
  hy2_obfs TEXT NOT NULL DEFAULT '',
  hy2_obfs_password TEXT NOT NULL DEFAULT '',
  hy2_mport TEXT NOT NULL DEFAULT '',
  tuic_congestion_control TEXT NOT NULL DEFAULT 'bbr',
  tuic_zero_rtt INTEGER NOT NULL DEFAULT 0,
  wg_private_key TEXT NOT NULL DEFAULT '',
  wg_address TEXT NOT NULL DEFAULT '',
  wg_peer_public_key TEXT NOT NULL DEFAULT '',
  wg_allowed_ips TEXT NOT NULL DEFAULT '0.0.0.0/0, ::/0',
  wg_endpoint TEXT NOT NULL DEFAULT '',
  wg_preshared_key TEXT NOT NULL DEFAULT '',
  wg_mtu INTEGER NOT NULL DEFAULT 0,
  shadowtls_version INTEGER NOT NULL DEFAULT 3,
  shadowtls_password TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  inbound_id INTEGER NOT NULL REFERENCES inbounds(id) ON DELETE CASCADE,
  uuid TEXT NOT NULL UNIQUE,
  credential_id TEXT NOT NULL DEFAULT '',
  password TEXT NOT NULL DEFAULT '',
  subscription_token TEXT NOT NULL DEFAULT '',
  stats_key TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  up INTEGER NOT NULL DEFAULT 0,
  down INTEGER NOT NULL DEFAULT 0,
  traffic_limit INTEGER NOT NULL DEFAULT 0,
  expiry_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_clients_inbound_id ON clients(inbound_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_credential_id ON clients(credential_id) WHERE credential_id <> '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_subscription_token ON clients(subscription_token) WHERE subscription_token <> '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_stats_key ON clients(stats_key) WHERE stats_key <> '';
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
  source TEXT NOT NULL DEFAULT 'manual',
  subscription_id INTEGER NULL REFERENCES outbound_subscriptions(id) ON DELETE SET NULL,
  subscription_identity TEXT NOT NULL DEFAULT '',
  raw_link TEXT NOT NULL DEFAULT '',
  settings_json TEXT NOT NULL DEFAULT '',
  last_seen_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outbound_subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  remark TEXT NOT NULL,
  url TEXT NOT NULL,
  tag_prefix TEXT NOT NULL DEFAULT '',
  update_interval_seconds INTEGER NOT NULL DEFAULT 600,
  enabled INTEGER NOT NULL DEFAULT 1,
  allow_private INTEGER NOT NULL DEFAULT 0,
  prepend INTEGER NOT NULL DEFAULT 0,
  priority INTEGER NOT NULL DEFAULT 0,
  last_fetched_at TEXT NOT NULL DEFAULT '',
  last_attempt_at TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  link_identities_json TEXT NOT NULL DEFAULT '',
  deleted_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS routing_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  inbound_id INTEGER NULL REFERENCES inbounds(id) ON DELETE CASCADE,
  inbound_tag TEXT NOT NULL DEFAULT '',
  client_id INTEGER NULL REFERENCES clients(id) ON DELETE CASCADE,
  client_email TEXT NOT NULL DEFAULT '',
  outbound_id INTEGER NOT NULL REFERENCES outbounds(id) ON DELETE RESTRICT,
  outbound_tag TEXT NOT NULL,
  domain TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  rule_set TEXT NOT NULL DEFAULT '',
  protocol TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  sort INTEGER NOT NULL DEFAULT 0,
  CHECK (outbound_id > 0),
  CHECK (client_id IS NULL OR client_id > 0),
  CHECK (inbound_id IS NULL OR inbound_id > 0)
);
CREATE TABLE IF NOT EXISTS token_blacklist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_used TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS traffic_states (
  engine TEXT NOT NULL,
  scope_type TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  total_up INTEGER NOT NULL DEFAULT 0,
  total_down INTEGER NOT NULL DEFAULT 0,
  last_raw_up INTEGER NOT NULL DEFAULT 0,
  last_raw_down INTEGER NOT NULL DEFAULT 0,
  rate_up REAL NOT NULL DEFAULT 0,
  rate_down REAL NOT NULL DEFAULT 0,
  last_seen_at TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'waiting',
  message TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (engine, scope_type, scope_key)
);
CREATE TABLE IF NOT EXISTS traffic_samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sampled_at TEXT NOT NULL,
  engine TEXT NOT NULL,
  scope_type TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  total_up INTEGER NOT NULL DEFAULT 0,
  total_down INTEGER NOT NULL DEFAULT 0,
  rate_up REAL NOT NULL DEFAULT 0,
  rate_down REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'waiting'
);
CREATE TABLE IF NOT EXISTS certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  source TEXT NOT NULL,
  status TEXT NOT NULL,
  domains TEXT NOT NULL DEFAULT '',
  cert_path TEXT NOT NULL,
  key_path TEXT NOT NULL,
  not_before TEXT NOT NULL DEFAULT '',
  not_after TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL DEFAULT '',
  serial TEXT NOT NULL DEFAULT '',
  issue_email TEXT NOT NULL DEFAULT '',
  acme_directory_url TEXT NOT NULL DEFAULT '',
  challenge_method TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  last_renewed TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS certificate_operations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  certificate_id INTEGER NULL REFERENCES certificates(id) ON DELETE SET NULL,
  type TEXT NOT NULL,
  status TEXT NOT NULL,
  code TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS config_meta (
  key TEXT PRIMARY KEY,
  value INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO config_meta (key, value) VALUES ('validation_version', 1);
CREATE INDEX IF NOT EXISTS idx_outbounds_sort_id ON outbounds(sort, id);
CREATE INDEX IF NOT EXISTS idx_routing_rules_sort_id ON routing_rules(sort, id);
CREATE INDEX IF NOT EXISTS idx_routing_rules_outbound_id ON routing_rules(outbound_id);
CREATE INDEX IF NOT EXISTS idx_routing_rules_client_id ON routing_rules(client_id);
CREATE INDEX IF NOT EXISTS idx_routing_rules_inbound_id ON routing_rules(inbound_id);
CREATE INDEX IF NOT EXISTS idx_clients_email ON clients(email);
CREATE INDEX IF NOT EXISTS idx_clients_inbound_email ON clients(inbound_id, email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_inbounds_port ON inbounds(port);
CREATE INDEX IF NOT EXISTS idx_token_blacklist_expires_at ON token_blacklist(expires_at);
CREATE INDEX IF NOT EXISTS idx_token_blacklist_active ON token_blacklist(revoked, expires_at, id);
CREATE INDEX IF NOT EXISTS idx_traffic_states_scope ON traffic_states(scope_type, scope_key);
CREATE INDEX IF NOT EXISTS idx_traffic_samples_lookup ON traffic_samples(scope_type, scope_key, sampled_at);
CREATE INDEX IF NOT EXISTS idx_traffic_samples_scope_time ON traffic_samples(scope_type, sampled_at);
CREATE INDEX IF NOT EXISTS idx_traffic_samples_sampled_at ON traffic_samples(sampled_at);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificates_cert_key ON certificates(cert_path, key_path);
CREATE INDEX IF NOT EXISTS idx_certificate_operations_certificate_id ON certificate_operations(certificate_id, id);
CREATE INDEX IF NOT EXISTS idx_outbound_subscriptions_priority_id ON outbound_subscriptions(priority, id);
`)
	if err != nil {
		return err
	}
	if err := s.ensureTrafficSamplesBucketIndex(ctx); err != nil {
		return err
	}
	if err := s.ensureConfigVersionTriggers(ctx); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "certificates", "issue_email", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "certificates", "acme_directory_url", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "certificates", "challenge_method", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "outbounds", "source", "TEXT NOT NULL DEFAULT 'manual'"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "outbounds", "subscription_id", "INTEGER NULL REFERENCES outbound_subscriptions(id) ON DELETE SET NULL"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "outbounds", "subscription_identity", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "outbounds", "raw_link", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "outbounds", "settings_json", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "outbounds", "last_seen_at", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "outbound_subscriptions", "deleted_at", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "outbound_subscriptions", "last_attempt_at", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_outbounds_subscription ON outbounds(subscription_id, subscription_identity)`); err != nil {
		return err
	}
	if err := s.seedDefaultOutbounds(ctx); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensureTrafficSamplesBucketIndex(ctx context.Context) error {
	exists, err := s.indexExists(ctx, "idx_traffic_samples_bucket")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := s.db.ExecContext(ctx, `
DELETE FROM traffic_samples
WHERE id NOT IN (
  SELECT MAX(id)
  FROM traffic_samples
  GROUP BY sampled_at, engine, scope_type, scope_key
);
`); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_samples_bucket ON traffic_samples(sampled_at, engine, scope_type, scope_key)`)
	return err
}

func (s *Store) indexExists(ctx context.Context, name string) (bool, error) {
	var found int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM sqlite_master WHERE type='index' AND name=? LIMIT 1`, name).Scan(&found)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return found == 1, nil
}

func (s *Store) ensureConfigVersionTriggers(ctx context.Context) error {
	const bump = `UPDATE config_meta SET value = value + 1 WHERE key = 'validation_version';`
	triggers := map[string]string{
		"trg_config_version_inbounds_insert":  `CREATE TRIGGER IF NOT EXISTS trg_config_version_inbounds_insert AFTER INSERT ON inbounds BEGIN ` + bump + ` END;`,
		"trg_config_version_inbounds_update":  `CREATE TRIGGER IF NOT EXISTS trg_config_version_inbounds_update AFTER UPDATE ON inbounds BEGIN ` + bump + ` END;`,
		"trg_config_version_inbounds_delete":  `CREATE TRIGGER IF NOT EXISTS trg_config_version_inbounds_delete AFTER DELETE ON inbounds BEGIN ` + bump + ` END;`,
		"trg_config_version_clients_insert":   `CREATE TRIGGER IF NOT EXISTS trg_config_version_clients_insert AFTER INSERT ON clients BEGIN ` + bump + ` END;`,
		"trg_config_version_clients_update":   `CREATE TRIGGER IF NOT EXISTS trg_config_version_clients_update AFTER UPDATE OF uuid, credential_id, password, stats_key, email, enabled ON clients BEGIN ` + bump + ` END;`,
		"trg_config_version_clients_delete":   `CREATE TRIGGER IF NOT EXISTS trg_config_version_clients_delete AFTER DELETE ON clients BEGIN ` + bump + ` END;`,
		"trg_config_version_outbounds_insert": `CREATE TRIGGER IF NOT EXISTS trg_config_version_outbounds_insert AFTER INSERT ON outbounds BEGIN ` + bump + ` END;`,
		"trg_config_version_outbounds_update": `CREATE TRIGGER IF NOT EXISTS trg_config_version_outbounds_update AFTER UPDATE ON outbounds BEGIN ` + bump + ` END;`,
		"trg_config_version_outbounds_delete": `CREATE TRIGGER IF NOT EXISTS trg_config_version_outbounds_delete AFTER DELETE ON outbounds BEGIN ` + bump + ` END;`,
		"trg_config_version_rules_insert":     `CREATE TRIGGER IF NOT EXISTS trg_config_version_rules_insert AFTER INSERT ON routing_rules BEGIN ` + bump + ` END;`,
		"trg_config_version_rules_update":     `CREATE TRIGGER IF NOT EXISTS trg_config_version_rules_update AFTER UPDATE ON routing_rules BEGIN ` + bump + ` END;`,
		"trg_config_version_rules_delete":     `CREATE TRIGGER IF NOT EXISTS trg_config_version_rules_delete AFTER DELETE ON routing_rules BEGIN ` + bump + ` END;`,
	}
	for _, ddl := range triggers {
		if _, err := s.db.ExecContext(ctx, ddl); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureColumn(ctx context.Context, table, column, definition string) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column+` `+definition)
	return err
}
