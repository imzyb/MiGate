package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

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
	row := s.db.QueryRowContext(ctx, `SELECT id, inbound_id, uuid, credential_id, password, subscription_token, stats_key, email, enabled, up, down, traffic_limit, expiry_at FROM clients WHERE id=?`, id)
	var client Client
	var dbEnabled int
	if err := row.Scan(&client.ID, &client.InboundID, &client.UUID, &client.CredentialID, &client.Password, &client.SubscriptionToken, &client.StatsKey, &client.Email, &dbEnabled, &client.Up, &client.Down, &client.TrafficLimit, &client.ExpiryAt); err != nil {
		return Client{}, err
	}
	client.Enabled = dbEnabled != 0
	return client, nil
}

func (s *Store) UpdateClientTraffic(ctx context.Context, email string, uplink, downlink int64) error {
	key, ok, err := s.resolveLegacyTrafficKey(ctx, email)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return s.ApplyTrafficRawStats(ctx, []TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: key, RawUp: uplink, RawDown: downlink, Status: "ok"}}, time.Now().UTC())
}

func (s *Store) UpdateClientTrafficBatch(ctx context.Context, stats map[string]ClientTrafficUpdate) error {
	if len(stats) == 0 {
		return nil
	}
	raw := make([]TrafficRawStat, 0, len(stats))
	for key, traffic := range stats {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if !strings.HasPrefix(key, "c_") {
			resolved, ok, err := s.resolveLegacyTrafficKey(ctx, key)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			key = resolved
		}
		raw = append(raw, TrafficRawStat{Engine: "xray", ScopeType: "client", ScopeKey: key, RawUp: traffic.Up, RawDown: traffic.Down, Status: "ok"})
	}
	return s.ApplyTrafficRawStats(ctx, raw, time.Now().UTC())
}

func (s *Store) resolveLegacyTrafficKey(ctx context.Context, key string) (string, bool, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", false, nil
	}
	var statsKey string
	if err := s.db.QueryRowContext(ctx, `SELECT stats_key FROM clients WHERE stats_key=? LIMIT 1`, key).Scan(&statsKey); err == nil {
		return statsKey, true, nil
	} else if err != sql.ErrNoRows {
		return "", false, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT stats_key FROM clients WHERE email=? ORDER BY id ASC LIMIT 2`, key)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	keys := []string{}
	for rows.Next() {
		var candidate string
		if err := rows.Scan(&candidate); err != nil {
			return "", false, err
		}
		keys = append(keys, candidate)
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	if len(keys) != 1 || strings.TrimSpace(keys[0]) == "" {
		return "", false, nil
	}
	return keys[0], true, nil
}

func (s *Store) ApplyTrafficRawStats(ctx context.Context, stats []TrafficRawStat, observedAt time.Time) error {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	normalizedStats := normalizeTrafficRawStats(stats)
	if len(normalizedStats) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	currentStates, err := prefetchTrafficStates(ctx, tx, normalizedStats)
	if err != nil {
		return err
	}
	clientInfo, err := prefetchTrafficClientInfo(ctx, tx, normalizedStats)
	if err != nil {
		return err
	}
	seenClients := map[string]trafficClientInfo{}
	seenAt := observedAt.UTC().Format(time.RFC3339Nano)
	sampleBucketAt := trafficSampleBucket(observedAt).UTC().Format(time.RFC3339Nano)
	upsertState, err := tx.PrepareContext(ctx, `
INSERT INTO traffic_states (engine, scope_type, scope_key, total_up, total_down, last_raw_up, last_raw_down, rate_up, rate_down, last_seen_at, status, message)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(engine, scope_type, scope_key) DO UPDATE SET
  total_up=excluded.total_up,
  total_down=excluded.total_down,
  last_raw_up=excluded.last_raw_up,
  last_raw_down=excluded.last_raw_down,
  rate_up=excluded.rate_up,
  rate_down=excluded.rate_down,
  last_seen_at=excluded.last_seen_at,
  status=excluded.status,
  message=excluded.message
`)
	if err != nil {
		return err
	}
	defer upsertState.Close()
	insertSample, err := tx.PrepareContext(ctx, `
INSERT INTO traffic_samples (sampled_at, engine, scope_type, scope_key, total_up, total_down, rate_up, rate_down, status)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(sampled_at, engine, scope_type, scope_key) DO UPDATE SET
  total_up=excluded.total_up,
  total_down=excluded.total_down,
  rate_up=excluded.rate_up,
  rate_down=excluded.rate_down,
  status=excluded.status
`)
	if err != nil {
		return err
	}
	defer insertSample.Close()
	updateClientTraffic, err := tx.PrepareContext(ctx, `UPDATE clients SET up = ?, down = ? WHERE stats_key = ?`)
	if err != nil {
		return err
	}
	defer updateClientTraffic.Close()
	for _, raw := range normalizedStats {
		stateKey := trafficStateKey(raw.Engine, raw.ScopeType, raw.ScopeKey)
		current, hasCurrent := currentStates[stateKey]
		if !hasCurrent && raw.ScopeType == "client" {
			if info, ok := clientInfo[raw.ScopeKey]; ok {
				current.TotalUp = info.Up
				current.TotalDown = info.Down
			}
		}
		var elapsed float64
		if hasCurrent && current.LastSeenAt != "" {
			if previous, parseErr := time.Parse(time.RFC3339Nano, current.LastSeenAt); parseErr == nil && observedAt.After(previous) {
				elapsed = observedAt.Sub(previous).Seconds()
			}
		}
		deltaUp := int64(0)
		deltaDown := int64(0)
		if !hasCurrent || isResetWithoutRawBaseline(current) {
			deltaUp = 0
			deltaDown = 0
		} else {
			if raw.RawUp >= current.LastRawUp {
				deltaUp = raw.RawUp - current.LastRawUp
			}
			if raw.RawDown >= current.LastRawDown {
				deltaDown = raw.RawDown - current.LastRawDown
			}
		}
		totalUp := current.TotalUp + deltaUp
		totalDown := current.TotalDown + deltaDown
		rateUp := 0.0
		rateDown := 0.0
		if elapsed > 0 && !shouldSuppressRecoveredTrafficRate(current) {
			rateUp = float64(deltaUp) / elapsed
			rateDown = float64(deltaDown) / elapsed
		}
		if _, err := upsertState.ExecContext(ctx, raw.Engine, raw.ScopeType, raw.ScopeKey, totalUp, totalDown, raw.RawUp, raw.RawDown, rateUp, rateDown, seenAt, raw.Status, strings.TrimSpace(raw.Message)); err != nil {
			return err
		}
		if _, err := insertSample.ExecContext(ctx, sampleBucketAt, raw.Engine, raw.ScopeType, raw.ScopeKey, totalUp, totalDown, rateUp, rateDown, raw.Status); err != nil {
			return err
		}
		current.Engine = raw.Engine
		current.ScopeType = raw.ScopeType
		current.ScopeKey = raw.ScopeKey
		current.TotalUp = totalUp
		current.TotalDown = totalDown
		current.LastRawUp = raw.RawUp
		current.LastRawDown = raw.RawDown
		current.RateUp = rateUp
		current.RateDown = rateDown
		current.LastSeenAt = seenAt
		current.Status = raw.Status
		current.Message = strings.TrimSpace(raw.Message)
		currentStates[stateKey] = current
		if raw.ScopeType == "client" {
			if info, ok := clientInfo[raw.ScopeKey]; ok && info.ExpectedEngine == raw.Engine {
				info.Up = totalUp
				info.Down = totalDown
				seenClients[raw.ScopeKey] = info
			}
		}
	}
	for statsKey, info := range seenClients {
		if _, err := updateClientTraffic.ExecContext(ctx, info.Up, info.Down, statsKey); err != nil {
			return err
		}
	}
	rollbackCleanup, err := s.cleanupTrafficSamples(ctx, tx, observedAt)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		rollbackCleanup()
		return err
	}
	return nil
}

func normalizeTrafficRawStats(stats []TrafficRawStat) []TrafficRawStat {
	normalized := make([]TrafficRawStat, 0, len(stats))
	for _, raw := range stats {
		raw.Engine = normalizeTrafficEngine(raw.Engine)
		raw.ScopeType = normalizeTrafficToken(raw.ScopeType)
		raw.ScopeKey = strings.TrimSpace(raw.ScopeKey)
		raw.Status = strings.TrimSpace(raw.Status)
		raw.Message = strings.TrimSpace(raw.Message)
		if raw.Status == "" {
			raw.Status = "ok"
		}
		if raw.Engine == "" || raw.ScopeType == "" || raw.ScopeKey == "" {
			continue
		}
		normalized = append(normalized, raw)
	}
	return normalized
}

func trafficStateKey(engine, scopeType, scopeKey string) string {
	return engine + "\x00" + scopeType + "\x00" + scopeKey
}

func prefetchTrafficStates(ctx context.Context, tx *sql.Tx, stats []TrafficRawStat) (map[string]TrafficState, error) {
	keys := make([]string, 0, len(stats))
	seen := map[string]struct{}{}
	for _, raw := range stats {
		key := trafficStateKey(raw.Engine, raw.ScopeType, raw.ScopeKey)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	states := map[string]TrafficState{}
	for start := 0; start < len(keys); start += sqliteVariableChunkSize / 3 {
		end := start + sqliteVariableChunkSize/3
		if end > len(keys) {
			end = len(keys)
		}
		conditions := make([]string, 0, end-start)
		args := make([]interface{}, 0, (end-start)*3)
		for _, key := range keys[start:end] {
			parts := strings.SplitN(key, "\x00", 3)
			conditions = append(conditions, "(engine=? AND scope_type=? AND scope_key=?)")
			args = append(args, parts[0], parts[1], parts[2])
		}
		rows, err := tx.QueryContext(ctx, `
SELECT engine, scope_type, scope_key, total_up, total_down, last_raw_up, last_raw_down, rate_up, rate_down, last_seen_at, status, message
FROM traffic_states
WHERE `+strings.Join(conditions, " OR "), args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var state TrafficState
			if err := rows.Scan(&state.Engine, &state.ScopeType, &state.ScopeKey, &state.TotalUp, &state.TotalDown, &state.LastRawUp, &state.LastRawDown, &state.RateUp, &state.RateDown, &state.LastSeenAt, &state.Status, &state.Message); err != nil {
				rows.Close()
				return nil, err
			}
			state.Engine = normalizeTrafficEngine(state.Engine)
			state.ScopeType = normalizeTrafficToken(state.ScopeType)
			state.ScopeKey = strings.TrimSpace(state.ScopeKey)
			states[trafficStateKey(state.Engine, state.ScopeType, state.ScopeKey)] = state
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	return states, nil
}

type trafficClientInfo struct {
	ExpectedEngine string
	Up             int64
	Down           int64
}

func prefetchTrafficClientInfo(ctx context.Context, tx *sql.Tx, stats []TrafficRawStat) (map[string]trafficClientInfo, error) {
	keys := make([]string, 0, len(stats))
	seen := map[string]struct{}{}
	for _, raw := range stats {
		if raw.ScopeType != "client" {
			continue
		}
		if _, ok := seen[raw.ScopeKey]; ok {
			continue
		}
		seen[raw.ScopeKey] = struct{}{}
		keys = append(keys, raw.ScopeKey)
	}
	info := map[string]trafficClientInfo{}
	for start := 0; start < len(keys); start += sqliteVariableChunkSize {
		end := start + sqliteVariableChunkSize
		if end > len(keys) {
			end = len(keys)
		}
		placeholders := placeholders(len(keys[start:end]))
		args := make([]interface{}, 0, end-start)
		for _, key := range keys[start:end] {
			args = append(args, key)
		}
		rows, err := tx.QueryContext(ctx, `
SELECT c.stats_key, c.up, c.down, i.protocol
FROM clients c
JOIN inbounds i ON i.id = c.inbound_id
WHERE c.stats_key IN (`+placeholders+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var statsKey string
			var protocol string
			var item trafficClientInfo
			if err := rows.Scan(&statsKey, &item.Up, &item.Down, &protocol); err != nil {
				rows.Close()
				return nil, err
			}
			item.ExpectedEngine = expectedTrafficEngineForProtocol(protocol)
			info[statsKey] = item
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	return info, nil
}

const (
	trafficSampleBucketSize       = time.Minute
	trafficSamplesHotRetention    = 24 * time.Hour
	trafficSamplesRetention       = 7 * 24 * time.Hour
	trafficSamplesCleanupInterval = time.Hour
)

func trafficSampleBucket(observedAt time.Time) time.Time {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	return observedAt.UTC().Truncate(trafficSampleBucketSize)
}

func (s *Store) cleanupTrafficSamples(ctx context.Context, tx *sql.Tx, observedAt time.Time) (func(), error) {
	s.trafficCleanupMu.Lock()
	if !s.nextTrafficSamplesCleanup.IsZero() && observedAt.Before(s.nextTrafficSamplesCleanup) {
		s.trafficCleanupMu.Unlock()
		return func() {}, nil
	}
	previousCleanup := s.nextTrafficSamplesCleanup
	nextCleanup := observedAt.Add(trafficSamplesCleanupInterval)
	s.nextTrafficSamplesCleanup = nextCleanup
	s.trafficCleanupMu.Unlock()
	cutoff := observedAt.Add(-trafficSamplesRetention).UTC().Format(time.RFC3339Nano)
	hotCutoff := observedAt.Add(-trafficSamplesHotRetention).UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
DELETE FROM traffic_samples
WHERE sampled_at < ?
   OR (sampled_at < ? AND CAST(strftime('%M', sampled_at) AS INTEGER) % 5 <> 0)
`, cutoff, hotCutoff); err != nil {
		s.trafficCleanupMu.Lock()
		if s.nextTrafficSamplesCleanup.Equal(nextCleanup) {
			s.nextTrafficSamplesCleanup = previousCleanup
		}
		s.trafficCleanupMu.Unlock()
		return func() {}, err
	}
	return func() {
		s.trafficCleanupMu.Lock()
		if s.nextTrafficSamplesCleanup.Equal(nextCleanup) {
			s.nextTrafficSamplesCleanup = previousCleanup
		}
		s.trafficCleanupMu.Unlock()
	}, nil
}

func isResetWithoutRawBaseline(state TrafficState) bool {
	return state.TotalUp == 0 && state.TotalDown == 0 &&
		state.LastRawUp == 0 && state.LastRawDown == 0 &&
		normalizeTrafficStatus(state.Status) == "unavailable" &&
		strings.Contains(strings.ToLower(state.Message), "baseline unavailable")
}

func shouldSuppressRecoveredTrafficRate(state TrafficState) bool {
	switch normalizeTrafficStatus(state.Status) {
	case "waiting", "unavailable", "unsupported", "not_configured":
		return true
	default:
		return false
	}
}

func (s *Store) MarkTrafficUnavailable(ctx context.Context, engine, status, message string, observedAt time.Time) error {
	engine = normalizeTrafficToken(engine)
	if engine == "" {
		return nil
	}
	status = strings.TrimSpace(status)
	if status == "" {
		status = "unavailable"
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `UPDATE traffic_states SET rate_up=0, rate_down=0, status=?, message=?, last_seen_at=? WHERE engine=?`,
		status, strings.TrimSpace(message), observedAt.UTC().Format(time.RFC3339Nano), engine)
	return err
}

func (s *Store) MarkTrafficScopeStatus(ctx context.Context, stats []TrafficStatusMarker, observedAt time.Time) error {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	normalizedStats := normalizeTrafficStatusMarkers(stats)
	if len(normalizedStats) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	currentStates, err := prefetchTrafficStates(ctx, tx, trafficRawStatsForStatusMarkers(normalizedStats))
	if err != nil {
		return err
	}
	seenAt := observedAt.UTC().Format(time.RFC3339Nano)
	sampleBucketAt := trafficSampleBucket(observedAt).UTC().Format(time.RFC3339Nano)
	insertSample, err := tx.PrepareContext(ctx, `
INSERT INTO traffic_samples (sampled_at, engine, scope_type, scope_key, total_up, total_down, rate_up, rate_down, status)
VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)
ON CONFLICT(sampled_at, engine, scope_type, scope_key) DO UPDATE SET
  total_up=excluded.total_up,
  total_down=excluded.total_down,
  rate_up=0,
  rate_down=0,
  status=excluded.status
`)
	if err != nil {
		return err
	}
	defer insertSample.Close()
	for _, marker := range normalizedStats {
		current := currentStates[trafficStateKey(marker.Engine, marker.ScopeType, marker.ScopeKey)]
		if _, err := tx.ExecContext(ctx, `
INSERT INTO traffic_states (engine, scope_type, scope_key, total_up, total_down, last_raw_up, last_raw_down, rate_up, rate_down, last_seen_at, status, message)
VALUES (?, ?, ?, 0, 0, 0, 0, 0, 0, ?, ?, ?)
ON CONFLICT(engine, scope_type, scope_key) DO UPDATE SET
  rate_up=0,
  rate_down=0,
  last_seen_at=excluded.last_seen_at,
  status=excluded.status,
  message=excluded.message
`, marker.Engine, marker.ScopeType, marker.ScopeKey, seenAt, marker.Status, marker.Message); err != nil {
			return err
		}
		if _, err := insertSample.ExecContext(ctx, sampleBucketAt, marker.Engine, marker.ScopeType, marker.ScopeKey, current.TotalUp, current.TotalDown, marker.Status); err != nil {
			return err
		}
	}
	rollbackCleanup, err := s.cleanupTrafficSamples(ctx, tx, observedAt)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		rollbackCleanup()
		return err
	}
	return nil
}

func normalizeTrafficStatusMarkers(stats []TrafficStatusMarker) []TrafficStatusMarker {
	normalized := make([]TrafficStatusMarker, 0, len(stats))
	for _, marker := range stats {
		marker.Engine = normalizeTrafficToken(marker.Engine)
		marker.ScopeType = normalizeTrafficToken(marker.ScopeType)
		marker.ScopeKey = strings.TrimSpace(marker.ScopeKey)
		marker.Status = strings.TrimSpace(marker.Status)
		marker.Message = strings.TrimSpace(marker.Message)
		if marker.Status == "" {
			marker.Status = "unavailable"
		}
		if marker.Engine == "" || marker.ScopeType == "" || marker.ScopeKey == "" {
			continue
		}
		normalized = append(normalized, marker)
	}
	return normalized
}

func trafficRawStatsForStatusMarkers(markers []TrafficStatusMarker) []TrafficRawStat {
	rawStats := make([]TrafficRawStat, 0, len(markers))
	for _, marker := range markers {
		rawStats = append(rawStats, TrafficRawStat{Engine: marker.Engine, ScopeType: marker.ScopeType, ScopeKey: marker.ScopeKey})
	}
	return rawStats
}

func (s *Store) ResetClientTrafficBaseline(ctx context.Context, id int64, baselines []TrafficRawStat) (Client, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Client{}, err
	}
	defer tx.Rollback()
	row := tx.QueryRowContext(ctx, `SELECT id, inbound_id, uuid, credential_id, password, subscription_token, stats_key, email, enabled, up, down, traffic_limit, expiry_at FROM clients WHERE id=?`, id)
	var client Client
	var dbEnabled int
	if err := row.Scan(&client.ID, &client.InboundID, &client.UUID, &client.CredentialID, &client.Password, &client.SubscriptionToken, &client.StatsKey, &client.Email, &dbEnabled, &client.Up, &client.Down, &client.TrafficLimit, &client.ExpiryAt); err != nil {
		return Client{}, err
	}
	client.Enabled = dbEnabled != 0
	now := time.Now().UTC().Format(time.RFC3339Nano)
	existingEngines, err := trafficStateEnginesForClient(ctx, tx, client.StatsKey)
	if err != nil {
		return Client{}, err
	}
	expectedEngine, ok, err := clientExpectedTrafficEngineByID(ctx, tx, client.ID)
	if err != nil {
		return Client{}, err
	}
	if ok && expectedEngine != "" {
		existingEngines[expectedEngine] = struct{}{}
	}
	baselineByEngine := map[string]TrafficRawStat{}
	for _, raw := range baselines {
		if normalizeTrafficToken(raw.ScopeType) != "client" || strings.TrimSpace(raw.ScopeKey) != client.StatsKey {
			continue
		}
		engine := normalizeTrafficToken(raw.Engine)
		if engine == "" {
			continue
		}
		baselineByEngine[engine] = raw
		existingEngines[engine] = struct{}{}
	}
	if len(existingEngines) == 0 {
		existingEngines["migate"] = struct{}{}
	}
	for engine := range existingEngines {
		raw, hasBaseline := baselineByEngine[engine]
		status := "waiting"
		message := "baseline reset"
		lastRawUp := int64(0)
		lastRawDown := int64(0)
		if hasBaseline {
			lastRawUp = raw.RawUp
			lastRawDown = raw.RawDown
		} else if engine != "migate" {
			status = "unavailable"
			message = "baseline unavailable during reset"
		} else {
			message = "waiting for first sample"
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO traffic_states (engine, scope_type, scope_key, total_up, total_down, last_raw_up, last_raw_down, rate_up, rate_down, last_seen_at, status, message)
VALUES (?, 'client', ?, 0, 0, ?, ?, 0, 0, ?, ?, ?)
ON CONFLICT(engine, scope_type, scope_key) DO UPDATE SET
  total_up=0,
  total_down=0,
  last_raw_up=excluded.last_raw_up,
  last_raw_down=excluded.last_raw_down,
  rate_up=0,
  rate_down=0,
  last_seen_at=excluded.last_seen_at,
  status=excluded.status,
  message=excluded.message
`, engine, client.StatsKey, lastRawUp, lastRawDown, now, status, message); err != nil {
			return Client{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE clients SET up=0, down=0 WHERE id=?`, id); err != nil {
		return Client{}, err
	}
	if err := tx.Commit(); err != nil {
		return Client{}, err
	}
	client.Up = 0
	client.Down = 0
	return client, nil
}

func (s *Store) ListTrafficStates(ctx context.Context) ([]TrafficState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT engine, scope_type, scope_key, total_up, total_down, last_raw_up, last_raw_down, rate_up, rate_down, last_seen_at, status, message FROM traffic_states ORDER BY engine, scope_type, scope_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := []TrafficState{}
	for rows.Next() {
		var state TrafficState
		if err := rows.Scan(&state.Engine, &state.ScopeType, &state.ScopeKey, &state.TotalUp, &state.TotalDown, &state.LastRawUp, &state.LastRawDown, &state.RateUp, &state.RateDown, &state.LastSeenAt, &state.Status, &state.Message); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

func (s *Store) ListTrafficSamples(ctx context.Context, scopeType string, since time.Time, limit int) ([]TrafficSample, error) {
	scopeType = normalizeTrafficToken(scopeType)
	if scopeType == "" {
		scopeType = "core"
	}
	if limit <= 0 || limit > 2000 {
		limit = 2000
	}
	sinceText := since.UTC().Format(time.RFC3339Nano)
	rows, err := s.db.QueryContext(ctx, `
SELECT sampled_at, engine, scope_type, scope_key, total_up, total_down, rate_up, rate_down, status
FROM traffic_samples
WHERE scope_type = ? AND sampled_at >= ?
ORDER BY sampled_at ASC, engine ASC, scope_key ASC
LIMIT ?`, scopeType, sinceText, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	samples := []TrafficSample{}
	for rows.Next() {
		var sample TrafficSample
		if err := rows.Scan(&sample.SampledAt, &sample.Engine, &sample.ScopeType, &sample.ScopeKey, &sample.TotalUp, &sample.TotalDown, &sample.RateUp, &sample.RateDown, &sample.Status); err != nil {
			return nil, err
		}
		samples = append(samples, sample)
	}
	return samples, rows.Err()
}

func (s *Store) GetClientTrafficUsage(ctx context.Context, statsKey string) (ClientTrafficUsage, bool, error) {
	statsKey = strings.TrimSpace(statsKey)
	if statsKey == "" {
		return ClientTrafficUsage{}, false, nil
	}
	row := s.db.QueryRowContext(ctx, `
SELECT c.id, c.stats_key, c.up, c.down, i.protocol
FROM clients c
JOIN inbounds i ON i.id = c.inbound_id
WHERE c.stats_key = ?
LIMIT 1`, statsKey)
	return s.getClientTrafficUsageFromRow(ctx, row)
}

func (s *Store) GetClientTrafficUsageForClient(ctx context.Context, clientID int64) (ClientTrafficUsage, bool, error) {
	if clientID <= 0 {
		return ClientTrafficUsage{}, false, nil
	}
	row := s.db.QueryRowContext(ctx, `
SELECT c.id, c.stats_key, c.up, c.down, i.protocol
FROM clients c
JOIN inbounds i ON i.id = c.inbound_id
WHERE c.id = ?
LIMIT 1`, clientID)
	return s.getClientTrafficUsageFromRow(ctx, row)
}

func (s *Store) getClientTrafficUsageFromRow(ctx context.Context, row *sql.Row) (ClientTrafficUsage, bool, error) {
	var clientID int64
	var statsKey string
	var legacyUp int64
	var legacyDown int64
	var protocol string
	if err := row.Scan(&clientID, &statsKey, &legacyUp, &legacyDown, &protocol); err != nil {
		if err == sql.ErrNoRows {
			return ClientTrafficUsage{}, false, nil
		}
		return ClientTrafficUsage{}, false, err
	}
	states, err := s.trafficStatesForClient(ctx, statsKey)
	if err != nil {
		return ClientTrafficUsage{}, false, err
	}
	usage := chooseClientTrafficUsage(clientID, statsKey, expectedTrafficEngineForProtocol(protocol), states, legacyUp, legacyDown)
	return usage, true, nil
}

func (s *Store) trafficStatesForClient(ctx context.Context, statsKey string) ([]TrafficState, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT engine, scope_type, scope_key, total_up, total_down, last_raw_up, last_raw_down, rate_up, rate_down, last_seen_at, status, message
FROM traffic_states
WHERE scope_type='client' AND scope_key=?
ORDER BY engine ASC`, statsKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := []TrafficState{}
	for rows.Next() {
		var state TrafficState
		if err := rows.Scan(&state.Engine, &state.ScopeType, &state.ScopeKey, &state.TotalUp, &state.TotalDown, &state.LastRawUp, &state.LastRawDown, &state.RateUp, &state.RateDown, &state.LastSeenAt, &state.Status, &state.Message); err != nil {
			return nil, err
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

func chooseClientTrafficUsage(clientID int64, statsKey, expectedEngine string, states []TrafficState, legacyUp, legacyDown int64) ClientTrafficUsage {
	byEngine := map[string]TrafficState{}
	for _, state := range states {
		if normalizeTrafficToken(state.ScopeType) != "client" || strings.TrimSpace(state.ScopeKey) != statsKey {
			continue
		}
		engine := normalizeTrafficEngine(state.Engine)
		if engine == "" {
			continue
		}
		state.Engine = engine
		state.Status = normalizeTrafficStatus(state.Status)
		byEngine[engine] = state
	}
	if state, ok := byEngine[expectedEngine]; ok {
		return usageFromTrafficState(clientID, statsKey, state)
	}
	for _, engine := range fallbackTrafficEngines(expectedEngine) {
		if state, ok := byEngine[engine]; ok {
			return usageFromTrafficState(clientID, statsKey, state)
		}
	}
	if legacyUp > 0 || legacyDown > 0 {
		return ClientTrafficUsage{
			ClientID:  clientID,
			StatsKey:  statsKey,
			Engine:    "migate",
			TotalUp:   legacyUp,
			TotalDown: legacyDown,
			Status:    "cumulative_only",
		}
	}
	return ClientTrafficUsage{ClientID: clientID, StatsKey: statsKey, Engine: expectedEngine, Status: "waiting"}
}

func usageFromTrafficState(clientID int64, statsKey string, state TrafficState) ClientTrafficUsage {
	return ClientTrafficUsage{
		ClientID: clientID, StatsKey: statsKey, Engine: normalizeTrafficEngine(state.Engine),
		TotalUp: state.TotalUp, TotalDown: state.TotalDown, RateUp: state.RateUp, RateDown: state.RateDown,
		Status: normalizeTrafficStatus(state.Status), Message: state.Message, LastSeenAt: state.LastSeenAt,
	}
}

func fallbackTrafficEngines(expectedEngine string) []string {
	switch normalizeTrafficEngine(expectedEngine) {
	case "singbox":
		return []string{"xray", "migate"}
	case "xray":
		return []string{"singbox", "migate"}
	default:
		return []string{"xray", "singbox", "migate"}
	}
}

func trafficStateEnginesForClient(ctx context.Context, tx *sql.Tx, statsKey string) (map[string]struct{}, error) {
	rows, err := tx.QueryContext(ctx, `SELECT engine FROM traffic_states WHERE scope_type='client' AND scope_key=? ORDER BY engine ASC`, statsKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	engines := map[string]struct{}{}
	for rows.Next() {
		var engine string
		if err := rows.Scan(&engine); err != nil {
			return nil, err
		}
		if engine = normalizeTrafficEngine(engine); engine != "" {
			engines[engine] = struct{}{}
		}
	}
	return engines, rows.Err()
}

func clientExpectedTrafficEngineByID(ctx context.Context, tx *sql.Tx, clientID int64) (string, bool, error) {
	var protocol string
	if err := tx.QueryRowContext(ctx, `
SELECT i.protocol
FROM clients c
JOIN inbounds i ON i.id = c.inbound_id
WHERE c.id = ?
LIMIT 1`, clientID).Scan(&protocol); err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	return expectedTrafficEngineForProtocol(protocol), true, nil
}

func lookupClientExpectedTrafficEngine(ctx context.Context, tx *sql.Tx, statsKey string) (string, bool, error) {
	var protocol string
	if err := tx.QueryRowContext(ctx, `
SELECT i.protocol
FROM clients c
JOIN inbounds i ON i.id = c.inbound_id
WHERE c.stats_key = ?
LIMIT 1`, statsKey).Scan(&protocol); err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	return expectedTrafficEngineForProtocol(protocol), true, nil
}

func expectedTrafficEngineForProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "hysteria2", "tuic", "shadowtls":
		return "singbox"
	default:
		return "xray"
	}
}

func normalizeTrafficEngine(engine string) string {
	switch normalizeTrafficToken(engine) {
	case "sing-box":
		return "singbox"
	default:
		return normalizeTrafficToken(engine)
	}
}

func normalizeTrafficStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return "waiting"
	}
	return status
}

func lookupClientLegacyTraffic(ctx context.Context, tx *sql.Tx, statsKey string) (int64, int64, bool, error) {
	var up int64
	var down int64
	if err := tx.QueryRowContext(ctx, `SELECT up, down FROM clients WHERE stats_key=? LIMIT 1`, statsKey).Scan(&up, &down); err != nil {
		if err == sql.ErrNoRows {
			return 0, 0, false, nil
		}
		return 0, 0, false, err
	}
	return up, down, true, nil
}

func normalizeTrafficToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
