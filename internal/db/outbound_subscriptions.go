package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func (s *Store) ListOutboundSubscriptions(ctx context.Context) ([]OutboundSubscription, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT s.id, s.remark, s.url, s.tag_prefix, s.update_interval_seconds, s.enabled, s.allow_private, s.prepend, s.priority,
       s.last_fetched_at, s.last_attempt_at, s.last_error, s.link_identities_json, s.created_at, s.updated_at,
       COUNT(o.id) AS outbound_count
FROM outbound_subscriptions s
LEFT JOIN outbounds o ON o.subscription_id = s.id AND o.source = 'subscription'
WHERE s.deleted_at = ''
GROUP BY s.id
ORDER BY s.priority ASC, s.id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var subs []OutboundSubscription
	for rows.Next() {
		sub, err := scanOutboundSubscription(rows)
		if err != nil {
			return nil, err
		}
		subs = append(subs, sub)
	}
	return subs, rows.Err()
}

func (s *Store) GetOutboundSubscription(ctx context.Context, id int64) (OutboundSubscription, bool, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT s.id, s.remark, s.url, s.tag_prefix, s.update_interval_seconds, s.enabled, s.allow_private, s.prepend, s.priority,
       s.last_fetched_at, s.last_attempt_at, s.last_error, s.link_identities_json, s.created_at, s.updated_at,
       COUNT(o.id) AS outbound_count
FROM outbound_subscriptions s
LEFT JOIN outbounds o ON o.subscription_id = s.id AND o.source = 'subscription'
WHERE s.id = ? AND s.deleted_at = ''
GROUP BY s.id`, id)
	sub, err := scanOutboundSubscription(row)
	if err == sql.ErrNoRows {
		return OutboundSubscription{}, false, nil
	}
	if err != nil {
		return OutboundSubscription{}, false, err
	}
	return sub, true, nil
}

func (s *Store) CreateOutboundSubscription(ctx context.Context, params CreateOutboundSubscriptionParams) (OutboundSubscription, error) {
	remark := strings.TrimSpace(params.Remark)
	urlValue := strings.TrimSpace(params.URL)
	if urlValue == "" {
		return OutboundSubscription{}, fmt.Errorf("url cannot be empty")
	}
	if remark == "" {
		remark = urlValue
	}
	interval := params.UpdateIntervalSeconds
	if interval <= 0 {
		interval = DefaultOutboundSubscriptionUpdateIntervalSeconds
	}
	var priority int
	_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(priority)+1, 0) FROM outbound_subscriptions`).Scan(&priority)
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := s.db.ExecContext(ctx, `
INSERT INTO outbound_subscriptions (remark, url, tag_prefix, update_interval_seconds, enabled, allow_private, prepend, priority, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		remark, urlValue, strings.TrimSpace(params.TagPrefix), interval, boolInt(params.Enabled), boolInt(params.AllowPrivate), boolInt(params.Prepend), priority, now, now)
	if err != nil {
		return OutboundSubscription{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return OutboundSubscription{}, err
	}
	sub, ok, err := s.GetOutboundSubscription(ctx, id)
	if err != nil {
		return OutboundSubscription{}, err
	}
	if !ok {
		return OutboundSubscription{}, fmt.Errorf("created outbound subscription not found: %d", id)
	}
	return sub, nil
}

func (s *Store) UpdateOutboundSubscription(ctx context.Context, id int64, params UpdateOutboundSubscriptionParams) (OutboundSubscription, error) {
	remark := strings.TrimSpace(params.Remark)
	urlValue := strings.TrimSpace(params.URL)
	if urlValue == "" {
		return OutboundSubscription{}, fmt.Errorf("url cannot be empty")
	}
	if remark == "" {
		remark = urlValue
	}
	interval := params.UpdateIntervalSeconds
	if interval <= 0 {
		interval = DefaultOutboundSubscriptionUpdateIntervalSeconds
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OutboundSubscription{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
UPDATE outbound_subscriptions
SET remark=?, url=?, tag_prefix=?, update_interval_seconds=?, enabled=?, allow_private=?, prepend=?, updated_at=?
WHERE id=? AND deleted_at=''`,
		remark, urlValue, strings.TrimSpace(params.TagPrefix), interval, boolInt(params.Enabled), boolInt(params.AllowPrivate), boolInt(params.Prepend), time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return OutboundSubscription{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return OutboundSubscription{}, err
	}
	if affected == 0 {
		return OutboundSubscription{}, fmt.Errorf("outbound subscription not found: %d", id)
	}
	if !params.Enabled {
		if _, err := tx.ExecContext(ctx, `UPDATE outbounds SET enabled=0 WHERE subscription_id=? AND source='subscription'`, id); err != nil {
			return OutboundSubscription{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return OutboundSubscription{}, err
	}
	sub, ok, err := s.GetOutboundSubscription(ctx, id)
	if err == nil && !ok {
		err = fmt.Errorf("outbound subscription not found: %d", id)
	}
	return sub, err
}

func (s *Store) DeleteOutboundSubscription(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM outbound_subscriptions WHERE id=?`, id).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("outbound subscription not found: %d", id)
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE outbounds SET enabled=0, last_seen_at=last_seen_at WHERE subscription_id=? AND source='subscription'`, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE outbound_subscriptions SET enabled=0, deleted_at=?, updated_at=? WHERE id=? AND deleted_at=''`, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("outbound subscription not found: %d", id)
	}
	if err := rebalanceOutboundSortsTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReorderOutboundSubscriptions(ctx context.Context, ids []int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id FROM outbound_subscriptions WHERE deleted_at = '' ORDER BY priority ASC, id ASC`)
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
	seen := map[int64]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	for _, id := range existing {
		if !seen[id] {
			return fmt.Errorf("unknown outbound subscription id in reorder payload")
		}
	}
	for i, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE outbound_subscriptions SET priority=?, updated_at=? WHERE id=?`, i, time.Now().UTC().Format(time.RFC3339), id); err != nil {
			return err
		}
	}
	if err := rebalanceOutboundSortsTx(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) MarkOutboundSubscriptionFetch(ctx context.Context, id int64, fetchedAt time.Time, lastErr string, identities []string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	lastErr = strings.TrimSpace(lastErr)
	fetched := strings.TrimSpace(fetchedAt.UTC().Format(time.RFC3339))
	if identities != nil {
		identitiesJSON := ""
		if data, err := json.Marshal(identities); err == nil {
			identitiesJSON = string(data)
		}
		result, err := s.db.ExecContext(ctx, `UPDATE outbound_subscriptions SET last_fetched_at=?, last_attempt_at=?, last_error=?, link_identities_json=?, updated_at=? WHERE id=? AND deleted_at=''`,
			fetched, fetched, lastErr, identitiesJSON, now, id)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return fmt.Errorf("outbound subscription not found: %d", id)
		}
		return nil
	}
	result, err := s.db.ExecContext(ctx, `UPDATE outbound_subscriptions SET last_attempt_at=?, last_error=?, updated_at=? WHERE id=? AND deleted_at=''`,
		fetched, lastErr, now, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("outbound subscription not found: %d", id)
	}
	return nil
}

func (s *Store) MaterializeSubscriptionOutbounds(ctx context.Context, subscriptionID int64, nodes []MaterializedSubscriptionOutbound, identities []string) ([]Outbound, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT enabled FROM outbound_subscriptions WHERE id=? AND deleted_at=''`, subscriptionID).Scan(&enabled); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("outbound subscription not found: %d", subscriptionID)
		}
		return nil, err
	}
	if enabled == 0 {
		return nil, fmt.Errorf("outbound subscription disabled: %d", subscriptionID)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	seenIDs := map[int64]bool{}
	for _, node := range nodes {
		protocol := NormalizeOutboundProtocol(node.Protocol)
		if err := ValidateOutboundProfile(Outbound{Protocol: protocol, Address: node.Address, Port: node.Port, Username: node.Username, Password: node.Password}); err != nil {
			return nil, err
		}
		identity := strings.TrimSpace(node.SubscriptionIdentity)
		if identity == "" {
			return nil, fmt.Errorf("subscription outbound identity cannot be empty")
		}
		existingID := node.ID
		var existingTag string
		if existingID > 0 {
			err := tx.QueryRowContext(ctx, `SELECT tag FROM outbounds WHERE id=? AND subscription_id=? AND source='subscription'`, existingID, subscriptionID).Scan(&existingTag)
			if err == sql.ErrNoRows {
				existingID = 0
			} else if err != nil {
				return nil, err
			}
		}
		if existingID == 0 {
			err := tx.QueryRowContext(ctx, `SELECT id, tag FROM outbounds WHERE subscription_id=? AND source='subscription' AND subscription_identity=? ORDER BY id ASC LIMIT 1`, subscriptionID, identity).Scan(&existingID, &existingTag)
			if err != nil && err != sql.ErrNoRows {
				return nil, err
			}
		}
		if existingID > 0 {
			if _, err := tx.ExecContext(ctx, `
UPDATE outbounds
SET tag=?, remark=?, protocol=?, address=?, port=?, username=?, password=?, enabled=1, sort=?, subscription_identity=?, raw_link=?, settings_json=?, last_seen_at=?
WHERE id=?`,
				strings.TrimSpace(existingTag), strings.TrimSpace(node.Remark), protocol, strings.TrimSpace(node.Address), node.Port, strings.TrimSpace(node.Username), node.Password, 50000+node.Position, identity, node.RawLink, strings.TrimSpace(node.SettingsJSON), now, existingID); err != nil {
				return nil, err
			}
			seenIDs[existingID] = true
			continue
		}
		result, err := tx.ExecContext(ctx, `
INSERT INTO outbounds (tag, remark, protocol, address, port, username, password, enabled, sort, source, subscription_id, subscription_identity, raw_link, settings_json, last_seen_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, 'subscription', ?, ?, ?, ?, ?, ?)`,
			strings.TrimSpace(node.Tag), strings.TrimSpace(node.Remark), protocol, strings.TrimSpace(node.Address), node.Port, strings.TrimSpace(node.Username), node.Password, 50000+node.Position, subscriptionID, identity, node.RawLink, strings.TrimSpace(node.SettingsJSON), now, now)
		if err != nil {
			return nil, err
		}
		id, err := result.LastInsertId()
		if err != nil {
			return nil, err
		}
		seenIDs[id] = true
	}
	if len(seenIDs) == 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE outbounds SET enabled=0 WHERE subscription_id=? AND source='subscription'`, subscriptionID); err != nil {
			return nil, err
		}
	} else {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM outbounds WHERE subscription_id=? AND source='subscription'`, subscriptionID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			if !seenIDs[id] {
				if _, err := tx.ExecContext(ctx, `UPDATE outbounds SET enabled=0 WHERE id=?`, id); err != nil {
					rows.Close()
					return nil, err
				}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	if err := updateSubscriptionFetchTx(ctx, tx, subscriptionID, now, "", identities); err != nil {
		return nil, err
	}
	if err := rebalanceOutboundSortsTx(ctx, tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.ListOutbounds(ctx)
}

func updateSubscriptionFetchTx(ctx context.Context, tx *sql.Tx, subscriptionID int64, fetchedAt string, lastErr string, identities []string) error {
	if identities != nil {
		identitiesJSON := ""
		if data, err := json.Marshal(identities); err == nil {
			identitiesJSON = string(data)
		}
		_, err := tx.ExecContext(ctx, `UPDATE outbound_subscriptions SET last_fetched_at=?, last_attempt_at=?, last_error=?, link_identities_json=?, updated_at=? WHERE id=?`,
			fetchedAt, fetchedAt, strings.TrimSpace(lastErr), identitiesJSON, time.Now().UTC().Format(time.RFC3339), subscriptionID)
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE outbound_subscriptions SET last_attempt_at=?, last_error=?, updated_at=? WHERE id=?`,
		fetchedAt, strings.TrimSpace(lastErr), time.Now().UTC().Format(time.RFC3339), subscriptionID)
	return err
}

type outboundSubscriptionScanner interface {
	Scan(dest ...interface{}) error
}

func scanOutboundSubscription(scanner outboundSubscriptionScanner) (OutboundSubscription, error) {
	var sub OutboundSubscription
	var enabled, allowPrivate, prepend int
	err := scanner.Scan(&sub.ID, &sub.Remark, &sub.URL, &sub.TagPrefix, &sub.UpdateIntervalSeconds, &enabled, &allowPrivate, &prepend, &sub.Priority, &sub.LastFetchedAt, &sub.LastAttemptAt, &sub.LastError, &sub.LinkIdentitiesJSON, &sub.CreatedAt, &sub.UpdatedAt, &sub.OutboundCount)
	if err != nil {
		return OutboundSubscription{}, err
	}
	sub.Enabled = enabled != 0
	sub.AllowPrivate = allowPrivate != 0
	sub.Prepend = prepend != 0
	return sub, nil
}

func rebalanceOutboundSortsTx(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `
SELECT o.id
FROM outbounds o
LEFT JOIN outbound_subscriptions s ON s.id = o.subscription_id
ORDER BY
  CASE
    WHEN o.tag='direct' AND o.protocol='freedom' THEN 0
    WHEN o.tag='blocked' AND o.protocol='blackhole' THEN 0
    WHEN o.tag='dns' AND o.protocol='dns' THEN 0
    WHEN o.source='subscription' AND COALESCE(s.prepend, 0)=1 THEN 1
    WHEN o.source <> 'subscription' THEN 2
    ELSE 3
  END ASC,
  CASE
    WHEN o.tag='direct' AND o.protocol='freedom' THEN 0
    WHEN o.tag='blocked' AND o.protocol='blackhole' THEN 1
    WHEN o.tag='dns' AND o.protocol='dns' THEN 2
    ELSE COALESCE(s.priority, o.sort)
  END ASC,
  o.sort ASC,
  o.id ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE outbounds SET sort=? WHERE id=?`, i, id); err != nil {
			return err
		}
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
