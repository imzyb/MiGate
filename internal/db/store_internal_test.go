package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestStoreCreatesTrafficLookupIndexes(t *testing.T) {
	store, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	indexes := map[string]bool{}
	uniqueIndexes := map[string]bool{}
	rows, err := store.db.QueryContext(context.Background(), `SELECT name, sql FROM sqlite_master WHERE type='index'`)
	if err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var ddl sql.NullString
		if err := rows.Scan(&name, &ddl); err != nil {
			t.Fatalf("scan index: %v", err)
		}
		indexes[name] = true
		if ddl.Valid && strings.Contains(strings.ToUpper(ddl.String), "CREATE UNIQUE INDEX") {
			uniqueIndexes[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("index rows: %v", err)
	}
	for _, name := range []string{"idx_clients_inbound_email", "idx_clients_credential_id", "idx_inbounds_port", "idx_traffic_samples_lookup", "idx_traffic_samples_scope_time", "idx_traffic_samples_sampled_at", "idx_traffic_samples_bucket"} {
		if !indexes[name] {
			t.Fatalf("expected index %s to exist, got %#v", name, indexes)
		}
	}
	for _, name := range []string{"idx_clients_credential_id", "idx_inbounds_port"} {
		if !uniqueIndexes[name] {
			t.Fatalf("expected index %s to be unique, got %#v", name, uniqueIndexes)
		}
	}
}

func TestStoreConfiguresSQLiteRuntimeForWriteContention(t *testing.T) {
	store, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	var busyTimeout int
	if err := store.db.QueryRowContext(context.Background(), `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatalf("busy_timeout: %v", err)
	}
	if busyTimeout < 5000 {
		t.Fatalf("expected busy_timeout >= 5000, got %d", busyTimeout)
	}
	var synchronous int
	if err := store.db.QueryRowContext(context.Background(), `PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatalf("synchronous: %v", err)
	}
	if synchronous != 1 {
		t.Fatalf("expected synchronous NORMAL (1), got %d", synchronous)
	}
	if stats := store.db.Stats(); stats.MaxOpenConnections != 1 {
		t.Fatalf("expected in-memory sqlite to use one connection, got %+v", stats)
	}
}

func TestStoreConfiguresSQLitePragmasForEveryFileConnection(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "migate.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if stats := store.db.Stats(); stats.MaxOpenConnections != 4 {
		t.Fatalf("expected file sqlite to allow four open connections, got %+v", stats)
	}
	conns := make([]*sql.Conn, 0, 4)
	for i := 0; i < 4; i++ {
		conn, err := store.db.Conn(ctx)
		if err != nil {
			t.Fatalf("open conn %d: %v", i, err)
		}
		conns = append(conns, conn)
	}
	defer func() {
		for _, conn := range conns {
			conn.Close()
		}
	}()

	for i, conn := range conns {
		assertSQLitePragmasForTest(t, ctx, conn, i)
	}
}

type pragmaQuerier interface {
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func assertSQLitePragmasForTest(t *testing.T, ctx context.Context, conn pragmaQuerier, index int) {
	t.Helper()
	var foreignKeys int
	if err := conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatalf("conn %d foreign_keys: %v", index, err)
	}
	if foreignKeys != 1 {
		t.Fatalf("conn %d expected foreign_keys enabled, got %d", index, foreignKeys)
	}
	var busyTimeout int
	if err := conn.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatalf("conn %d busy_timeout: %v", index, err)
	}
	if busyTimeout < 5000 {
		t.Fatalf("conn %d expected busy_timeout >= 5000, got %d", index, busyTimeout)
	}
	var synchronous int
	if err := conn.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatalf("conn %d synchronous: %v", index, err)
	}
	if synchronous != 1 {
		t.Fatalf("conn %d expected synchronous NORMAL (1), got %d", index, synchronous)
	}
	var tempStore int
	if err := conn.QueryRowContext(ctx, `PRAGMA temp_store`).Scan(&tempStore); err != nil {
		t.Fatalf("conn %d temp_store: %v", index, err)
	}
	if tempStore != 2 {
		t.Fatalf("conn %d expected temp_store MEMORY (2), got %d", index, tempStore)
	}
	var journalMode string
	if err := conn.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatalf("conn %d journal_mode: %v", index, err)
	}
	if strings.ToLower(journalMode) != "wal" {
		t.Fatalf("conn %d expected journal_mode WAL, got %s", index, journalMode)
	}
}

func TestListInboundTrafficUsesLightweightClientFields(t *testing.T) {
	store, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, CreateInboundParams{Remark: "light", Protocol: "vless", Port: 28095, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, CreateClientParams{InboundID: inbound.ID, Email: "light@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	light, err := store.ListInboundTraffic(ctx)
	if err != nil {
		t.Fatalf("list inbound traffic: %v", err)
	}
	if len(light) != 1 || len(light[0].Clients) != 1 {
		t.Fatalf("expected one lightweight inbound/client, got %+v", light)
	}
	got := light[0].Clients[0]
	if got.UUID != "" || got.CredentialID != "" || got.Password != "" || got.SubscriptionToken != "" {
		t.Fatalf("lightweight traffic client leaked sensitive fields: %+v", got)
	}
	if got.ID != client.ID || got.StatsKey != client.StatsKey || got.Email != client.Email {
		t.Fatalf("lightweight traffic client lost summary fields: got=%+v want=%+v", got, client)
	}
}

func TestValidationConfigVersionTracksConfigFieldsOnly(t *testing.T) {
	store, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	version, err := store.ValidationConfigVersion(ctx)
	if err != nil {
		t.Fatalf("initial version: %v", err)
	}
	inbound, err := store.CreateInbound(ctx, CreateInboundParams{
		Remark: "edge", Protocol: "hysteria2", Port: 28098, Network: "udp", Security: "tls",
		TLSCertFile: "/cert.pem", TLSKeyFile: "/key.pem",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	version = expectValidationVersionIncreased(t, store, ctx, version, "create inbound")
	client, err := store.CreateClient(ctx, CreateClientParams{InboundID: inbound.ID, Email: "edge@example.com", Password: "secret-a"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	version = expectValidationVersionIncreased(t, store, ctx, version, "create client")
	_, err = store.UpdateInbound(ctx, inbound.ID, UpdateInboundParams{
		UUID: inbound.UUID, Remark: inbound.Remark, Protocol: inbound.Protocol, Port: inbound.Port, Network: inbound.Network, Security: inbound.Security, Enabled: inbound.Enabled,
		TLSCertFile: "/changed-cert.pem", TLSKeyFile: "/changed-key.pem", RealityDest: "reality.example.com:443", RealityShortID: "abcd",
	})
	if err != nil {
		t.Fatalf("update inbound config fields: %v", err)
	}
	version = expectValidationVersionIncreased(t, store, ctx, version, "update inbound config fields")
	_, err = store.UpdateClient(ctx, client.ID, UpdateClientParams{UUID: client.UUID, Password: "secret-b", Email: client.Email, Enabled: client.Enabled, TrafficLimit: client.TrafficLimit, ExpiryAt: client.ExpiryAt})
	if err != nil {
		t.Fatalf("update client credential fields: %v", err)
	}
	version = expectValidationVersionIncreased(t, store, ctx, version, "update client credential fields")
	if err := store.UpdateClientTraffic(ctx, client.Email, 1024, 2048); err != nil {
		t.Fatalf("update runtime traffic: %v", err)
	}
	afterTraffic, err := store.ValidationConfigVersion(ctx)
	if err != nil {
		t.Fatalf("version after traffic: %v", err)
	}
	if afterTraffic != version {
		t.Fatalf("runtime traffic should not bump validation version, before=%d after=%d", version, afterTraffic)
	}
	updates := []struct {
		name  string
		query string
		args  []interface{}
	}{
		{name: "ws_path", query: `UPDATE inbounds SET ws_path=? WHERE id=?`, args: []interface{}{"/trigger-ws", inbound.ID}},
		{name: "reality", query: `UPDATE inbounds SET reality_dest=?, reality_short_id=? WHERE id=?`, args: []interface{}{"reality.changed:443", "dcba", inbound.ID}},
		{name: "client credential and password", query: `UPDATE clients SET credential_id=?, password=? WHERE id=?`, args: []interface{}{"credential-trigger", "password-trigger", client.ID}},
	}
	for _, update := range updates {
		if _, err := store.db.ExecContext(ctx, update.query, update.args...); err != nil {
			t.Fatalf("direct update %s: %v", update.name, err)
		}
		version = expectValidationVersionIncreased(t, store, ctx, version, update.name)
	}
}

func expectValidationVersionIncreased(t *testing.T, store *Store, ctx context.Context, previous int64, action string) int64 {
	t.Helper()
	current, err := store.ValidationConfigVersion(ctx)
	if err != nil {
		t.Fatalf("%s version: %v", action, err)
	}
	if current <= previous {
		t.Fatalf("%s should increase validation version, before=%d after=%d", action, previous, current)
	}
	return current
}

func TestTrafficSamplesAreBucketedPerMinute(t *testing.T) {
	store, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, CreateInboundParams{Remark: "bucket", Protocol: "vless", Port: 28097, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, CreateClientParams{InboundID: inbound.ID, Email: "bucket@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	firstAt := time.Date(2026, 6, 17, 12, 30, 10, 0, time.UTC)
	secondAt := firstAt.Add(30 * time.Second)
	if err := store.ApplyTrafficRawStats(ctx, []TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 100, RawDown: 200, Status: "ok"}}, firstAt); err != nil {
		t.Fatalf("first sample: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 150, RawDown: 260, Status: "ok"}}, secondAt); err != nil {
		t.Fatalf("second sample: %v", err)
	}
	samples, err := store.ListTrafficSamples(ctx, "client", firstAt.Add(-time.Minute), 100)
	if err != nil {
		t.Fatalf("list samples: %v", err)
	}
	if len(samples) != 1 {
		t.Fatalf("expected samples in one minute bucket to merge, got %+v", samples)
	}
	if samples[0].SampledAt != firstAt.Truncate(time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("expected minute bucket timestamp, got %+v", samples[0])
	}
	if samples[0].TotalUp != 50 || samples[0].TotalDown != 60 {
		t.Fatalf("expected bucket to keep latest total delta, got %+v", samples[0])
	}
}

func TestTrafficSamplesBucketMigrationRunsOnlyWhenIndexMissing(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "traffic-migrate.db")
	raw, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `
CREATE TABLE traffic_samples (
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
INSERT INTO traffic_samples (sampled_at, engine, scope_type, scope_key, total_up, total_down, rate_up, rate_down, status) VALUES
  ('2026-06-17T12:30:00Z', 'xray', 'client', 'a', 1, 1, 0, 0, 'ok'),
  ('2026-06-17T12:30:00Z', 'xray', 'client', 'a', 2, 2, 0, 0, 'ok'),
  ('2026-06-17T12:31:00Z', 'xray', 'client', 'a', 3, 3, 0, 0, 'ok');
`); err != nil {
		raw.Close()
		t.Fatalf("seed legacy duplicates: %v", err)
	}
	raw.Close()

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("open migrated store: %v", err)
	}
	defer store.Close()
	assertTrafficSampleCountForTest(t, store, 2)
	if !indexExistsForTest(t, store, "idx_traffic_samples_bucket") {
		t.Fatal("expected traffic sample bucket index to exist after migration")
	}
	store.Close()

	store, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen migrated store: %v", err)
	}
	defer store.Close()
	assertTrafficSampleCountForTest(t, store, 2)
	if _, err := store.db.ExecContext(ctx, `INSERT INTO traffic_samples (sampled_at, engine, scope_type, scope_key, total_up, total_down, rate_up, rate_down, status) VALUES ('2026-06-17T12:31:00Z', 'xray', 'client', 'a', 4, 4, 0, 0, 'ok')`); err == nil {
		t.Fatal("expected unique bucket index to reject duplicate sample after second open")
	}
}

func assertTrafficSampleCountForTest(t *testing.T, store *Store, want int) {
	t.Helper()
	var count int
	if err := store.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM traffic_samples`).Scan(&count); err != nil {
		t.Fatalf("count traffic samples: %v", err)
	}
	if count != want {
		t.Fatalf("expected %d traffic samples, got %d", want, count)
	}
}

func indexExistsForTest(t *testing.T, store *Store, name string) bool {
	t.Helper()
	exists, err := store.indexExists(context.Background(), name)
	if err != nil {
		t.Fatalf("index exists %s: %v", name, err)
	}
	return exists
}

func TestTrafficSamplesCleanupIsThrottled(t *testing.T) {
	store, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, CreateInboundParams{Remark: "cleanup", Protocol: "vless", Port: 28096, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, CreateClientParams{InboundID: inbound.ID, Email: "cleanup@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	oldAt := time.Unix(100, 0)
	if err := store.ApplyTrafficRawStats(ctx, []TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 100, RawDown: 100, Status: "ok"}}, oldAt); err != nil {
		t.Fatalf("old baseline: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 110, RawDown: 110, Status: "ok"}}, oldAt.Add(10*time.Second)); err != nil {
		t.Fatalf("old increment: %v", err)
	}
	newAt := oldAt.Add(8 * 24 * time.Hour)
	if err := store.ApplyTrafficRawStats(ctx, []TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 120, RawDown: 120, Status: "ok"}}, newAt); err != nil {
		t.Fatalf("new cleanup trigger: %v", err)
	}
	samples, err := store.ListTrafficSamples(ctx, "client", time.Unix(0, 0), 100)
	if err != nil {
		t.Fatalf("list samples after cleanup trigger: %v", err)
	}
	if len(samples) != 1 || samples[0].SampledAt != newAt.UTC().Truncate(time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("expected first new sample to prune old samples, got %+v", samples)
	}
	staleAt := newAt.Add(-8 * 24 * time.Hour)
	if _, err := store.db.ExecContext(ctx, `INSERT INTO traffic_samples (sampled_at, engine, scope_type, scope_key, total_up, total_down, rate_up, rate_down, status) VALUES (?, 'xray', 'client', ?, 1, 1, 0, 0, 'ok')`, staleAt.UTC().Format(time.RFC3339Nano), client.StatsKey); err != nil {
		t.Fatalf("insert manual stale sample: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 130, RawDown: 130, Status: "ok"}}, newAt.Add(30*time.Minute)); err != nil {
		t.Fatalf("within throttle sample: %v", err)
	}
	samples, err = store.ListTrafficSamples(ctx, "client", time.Unix(0, 0), 100)
	if err != nil {
		t.Fatalf("list samples after throttled write: %v", err)
	}
	foundManualStale := false
	for _, sample := range samples {
		if sample.SampledAt == staleAt.UTC().Format(time.RFC3339Nano) {
			foundManualStale = true
		}
	}
	if !foundManualStale {
		t.Fatalf("expected stale manual sample to remain until cleanup throttle expires, got %+v", samples)
	}
	if err := store.ApplyTrafficRawStats(ctx, []TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 140, RawDown: 140, Status: "ok"}}, newAt.Add(2*time.Hour)); err != nil {
		t.Fatalf("post-throttle sample: %v", err)
	}
	samples, err = store.ListTrafficSamples(ctx, "client", time.Unix(0, 0), 100)
	if err != nil {
		t.Fatalf("list samples after cleanup expiry: %v", err)
	}
	for _, sample := range samples {
		if sample.SampledAt == staleAt.UTC().Format(time.RFC3339Nano) {
			t.Fatalf("expected stale manual sample to be pruned after throttle expiry, got %+v", samples)
		}
	}
}

func TestStoreInitializesStrictRoutingRuleSchema(t *testing.T) {
	store, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if !indexIsUnique(t, store, "inbounds", "idx_inbounds_port") {
		t.Fatal("expected idx_inbounds_port to be unique in new schema")
	}
	if !indexIsUnique(t, store, "clients", "idx_clients_credential_id") {
		t.Fatal("expected idx_clients_credential_id to be unique in new schema")
	}
	columns := routingRuleColumnNullability(t, store)
	for _, name := range []string{"inbound_id", "client_id"} {
		if columns[name] {
			t.Fatalf("expected routing_rules.%s to be nullable, got NOT NULL", name)
		}
	}
	if !columns["outbound_id"] {
		t.Fatal("expected routing_rules.outbound_id to be NOT NULL")
	}
	foreignKeys := routingRuleForeignKeys(t, store)
	for _, want := range []string{"outbound_id->outbounds.id", "client_id->clients.id", "inbound_id->inbounds.id"} {
		if !foreignKeys[want] {
			t.Fatalf("expected routing_rules foreign key %s, got %#v", want, foreignKeys)
		}
	}
}

func routingRuleColumnNullability(t *testing.T, store *Store) map[string]bool {
	t.Helper()
	rows, err := store.db.QueryContext(context.Background(), `PRAGMA table_info(routing_rules)`)
	if err != nil {
		t.Fatalf("table info: %v", err)
	}
	defer rows.Close()
	notNullByName := map[string]bool{}
	for rows.Next() {
		var cid int
		var name string
		var typ string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatalf("scan table info: %v", err)
		}
		notNullByName[name] = notNull != 0
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table info rows: %v", err)
	}
	return notNullByName
}

func routingRuleForeignKeys(t *testing.T, store *Store) map[string]bool {
	t.Helper()
	rows, err := store.db.QueryContext(context.Background(), `PRAGMA foreign_key_list(routing_rules)`)
	if err != nil {
		t.Fatalf("foreign key list: %v", err)
	}
	defer rows.Close()
	keys := map[string]bool{}
	for rows.Next() {
		var id int
		var seq int
		var table string
		var from string
		var to string
		var onUpdate string
		var onDelete string
		var match string
		if err := rows.Scan(&id, &seq, &table, &from, &to, &onUpdate, &onDelete, &match); err != nil {
			t.Fatalf("scan foreign key: %v", err)
		}
		keys[from+"->"+table+"."+to] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("foreign key rows: %v", err)
	}
	return keys
}

func indexIsUnique(t *testing.T, store *Store, table string, indexName string) bool {
	t.Helper()
	rows, err := store.db.QueryContext(context.Background(), `PRAGMA index_list(`+table+`)`)
	if err != nil {
		t.Fatalf("index list: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name string
		var unique int
		var origin string
		var partial int
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			t.Fatalf("scan index list: %v", err)
		}
		if name == indexName {
			return unique != 0
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("index rows: %v", err)
	}
	return false
}

func TestStoreLightweightInboundQueries(t *testing.T) {
	store, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), CreateInboundParams{
		Remark: "edge", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality",
		RealityPrivateKey: "private-key", TLSCertFile: "/etc/cert.pem",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	if _, err := store.CreateClient(context.Background(), CreateClientParams{InboundID: inbound.ID, Email: "sam@example.com"}); err != nil {
		t.Fatalf("create client: %v", err)
	}

	exists, err := store.InboundExists(context.Background(), inbound.ID)
	if err != nil || !exists {
		t.Fatalf("expected inbound to exist, exists=%v err=%v", exists, err)
	}
	conflict, ok, err := store.FindInboundByPort(context.Background(), 443, 0)
	if err != nil || !ok || conflict.ID != inbound.ID {
		t.Fatalf("expected port conflict, conflict=%+v ok=%v err=%v", conflict, ok, err)
	}
	if _, ok, err := store.FindInboundByPort(context.Background(), 443, inbound.ID); err != nil || ok {
		t.Fatalf("expected excluded port conflict to be ignored, ok=%v err=%v", ok, err)
	}

	light, err := store.ListInboundTraffic(context.Background())
	if err != nil {
		t.Fatalf("list inbound traffic: %v", err)
	}
	if len(light) != 1 || len(light[0].Clients) != 1 {
		t.Fatalf("unexpected traffic snapshot: %+v", light)
	}
	if light[0].RealityPrivateKey != "" || light[0].TLSCertFile != "" {
		t.Fatalf("traffic snapshot should omit full config fields: %+v", light[0])
	}
}
