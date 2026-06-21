package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func (s *Store) ListRoutingRules(ctx context.Context) ([]RoutingRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, inbound_id, inbound_tag, client_id, client_email, outbound_id, outbound_tag, domain, ip, rule_set, protocol, enabled, sort FROM routing_rules ORDER BY sort ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules = make([]RoutingRule, 0)
	for rows.Next() {
		var r RoutingRule
		if err := scanRoutingRule(rows, &r); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

type routingRuleScanner interface {
	Scan(dest ...interface{}) error
}

func scanRoutingRule(scanner routingRuleScanner, r *RoutingRule) error {
	var inboundID sql.NullInt64
	var clientID sql.NullInt64
	var dbEnabled int
	if err := scanner.Scan(&r.ID, &inboundID, &r.InboundTag, &clientID, &r.ClientEmail, &r.OutboundID, &r.OutboundTag, &r.Domain, &r.IP, &r.RuleSet, &r.Protocol, &dbEnabled, &r.Sort); err != nil {
		return err
	}
	if inboundID.Valid {
		r.InboundID = inboundID.Int64
	}
	if clientID.Valid {
		r.ClientID = clientID.Int64
	}
	r.Enabled = dbEnabled != 0
	return nil
}

func outboundProtocolNeedsAddress(protocol string) bool {
	switch protocol {
	case "socks", "http", "https", "vless", "trojan", "shadowsocks", "hysteria2", "tuic", "shadowtls":
		return true
	default:
		return false
	}
}

func (s *Store) CreateRoutingRule(ctx context.Context, params CreateRoutingRuleParams) (RoutingRule, error) {
	clientID, clientEmail, inboundTag, inboundID, err := s.resolveRoutingRuleSource(ctx, params.ClientID, params.ClientEmail, params.InboundID, params.InboundTag)
	if err != nil {
		return RoutingRule{}, err
	}
	outbound, err := s.resolveRoutingOutbound(ctx, params.OutboundID, params.OutboundTag)
	if err != nil {
		return RoutingRule{}, err
	}
	if err := s.validateRoutingCoreCompatibility(ctx, inboundID, clientID, outbound); err != nil {
		return RoutingRule{}, err
	}
	var sort int
	_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(sort)+1, 0) FROM routing_rules`).Scan(&sort)
	enabled := 0
	if params.Enabled {
		enabled = 1
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO routing_rules (inbound_id, inbound_tag, client_id, client_email, outbound_id, outbound_tag, domain, ip, rule_set, protocol, enabled, sort) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nullableInt64(inboundID), inboundTag, nullableInt64(clientID), clientEmail, outbound.ID, outbound.Tag, strings.TrimSpace(params.Domain), strings.TrimSpace(params.IP), strings.TrimSpace(params.RuleSet), strings.TrimSpace(params.Protocol), enabled, sort)
	if err != nil {
		return RoutingRule{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return RoutingRule{}, err
	}
	return RoutingRule{ID: id, InboundID: inboundID, InboundTag: inboundTag, ClientID: clientID, ClientEmail: clientEmail, OutboundID: outbound.ID, OutboundTag: outbound.Tag, Domain: strings.TrimSpace(params.Domain), IP: strings.TrimSpace(params.IP), RuleSet: strings.TrimSpace(params.RuleSet), Protocol: strings.TrimSpace(params.Protocol), Enabled: params.Enabled, Sort: sort}, nil
}

func (s *Store) UpdateRoutingRule(ctx context.Context, id int64, params UpdateRoutingRuleParams) (RoutingRule, error) {
	clientID, clientEmail, inboundTag, inboundID, err := s.resolveRoutingRuleSource(ctx, params.ClientID, params.ClientEmail, params.InboundID, params.InboundTag)
	if err != nil {
		return RoutingRule{}, err
	}
	outbound, err := s.resolveRoutingOutbound(ctx, params.OutboundID, params.OutboundTag)
	if err != nil {
		return RoutingRule{}, err
	}
	if err := s.validateRoutingCoreCompatibility(ctx, inboundID, clientID, outbound); err != nil {
		return RoutingRule{}, err
	}
	enabled := 0
	if params.Enabled {
		enabled = 1
	}
	result, err := s.db.ExecContext(ctx, `UPDATE routing_rules SET inbound_id=?, inbound_tag=?, client_id=?, client_email=?, outbound_id=?, outbound_tag=?, domain=?, ip=?, rule_set=?, protocol=?, enabled=? WHERE id=?`,
		nullableInt64(inboundID), inboundTag, nullableInt64(clientID), clientEmail, outbound.ID, outbound.Tag, strings.TrimSpace(params.Domain), strings.TrimSpace(params.IP), strings.TrimSpace(params.RuleSet), strings.TrimSpace(params.Protocol), enabled, id)
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
	row := s.db.QueryRowContext(ctx, `SELECT id, inbound_id, inbound_tag, client_id, client_email, outbound_id, outbound_tag, domain, ip, rule_set, protocol, enabled, sort FROM routing_rules WHERE id=?`, id)
	var r RoutingRule
	if err := scanRoutingRule(row, &r); err != nil {
		return RoutingRule{}, err
	}
	return r, nil
}

func (s *Store) resolveRoutingRuleSource(ctx context.Context, clientID int64, clientEmail string, inboundID int64, inboundTag string) (int64, string, string, int64, error) {
	clientEmail = strings.TrimSpace(clientEmail)
	inboundTag = strings.TrimSpace(inboundTag)
	if clientID <= 0 {
		if clientEmail != "" {
			return 0, "", "", 0, fmt.Errorf("client_id is required when client_email is set")
		}
		if inboundID > 0 {
			actualTag, err := s.resolveRoutingInboundTagByID(ctx, inboundID)
			return 0, "", actualTag, inboundID, err
		}
		resolvedInboundID, err := s.resolveRoutingInboundTag(ctx, inboundTag)
		return 0, "", inboundTag, resolvedInboundID, err
	}
	var clientInboundID int64
	var protocol string
	var remark string
	var email string
	if err := s.db.QueryRowContext(ctx, `
SELECT c.inbound_id, c.email, i.protocol, i.remark
FROM clients c
JOIN inbounds i ON i.id = c.inbound_id
WHERE c.id = ?
`, clientID).Scan(&clientInboundID, &email, &protocol, &remark); err != nil {
		if err == sql.ErrNoRows {
			return 0, "", "", 0, fmt.Errorf("client not found: %d", clientID)
		}
		return 0, "", "", 0, err
	}
	actualTag := fmt.Sprintf("inbound-%d-%s", clientInboundID, strings.ToLower(strings.TrimSpace(protocol)))
	if inboundID > 0 && inboundID != clientInboundID {
		return 0, "", "", 0, fmt.Errorf("client %d does not belong to inbound_id %d", clientID, inboundID)
	}
	remark = strings.TrimSpace(remark)
	if inboundID <= 0 && inboundTag != "" && inboundTag != actualTag && inboundTag != remark {
		return 0, "", "", 0, fmt.Errorf("client %d does not belong to inbound_tag %q", clientID, inboundTag)
	}
	return clientID, strings.TrimSpace(email), actualTag, clientInboundID, nil
}

func (s *Store) resolveRoutingOutbound(ctx context.Context, outboundID int64, outboundTag string) (Outbound, error) {
	if outboundID <= 0 {
		return Outbound{}, fmt.Errorf("outbound_id is required")
	}
	row := s.db.QueryRowContext(ctx, `SELECT id, tag, remark, protocol, address, port, username, password, enabled, sort FROM outbounds WHERE id=?`, outboundID)
	var outbound Outbound
	var enabled int
	if err := row.Scan(&outbound.ID, &outbound.Tag, &outbound.Remark, &outbound.Protocol, &outbound.Address, &outbound.Port, &outbound.Username, &outbound.Password, &enabled, &outbound.Sort); err != nil {
		if err == sql.ErrNoRows {
			return Outbound{}, fmt.Errorf("outbound not found: %d", outboundID)
		}
		return Outbound{}, err
	}
	outbound.Enabled = enabled != 0
	outbound.SupportedCores = OutboundProtocolSupportedCores(outbound.Protocol)
	return outbound, nil
}

func (s *Store) resolveRoutingInboundTag(ctx context.Context, inboundTag string) (int64, error) {
	inboundTag = strings.TrimSpace(inboundTag)
	if inboundTag == "" {
		return 0, nil
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `
SELECT id FROM inbounds
WHERE ? = ('inbound-' || id || '-' || lower(protocol)) OR TRIM(remark) = ?
ORDER BY id ASC
LIMIT 1
`, inboundTag, inboundTag).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("inbound_tag %q does not match any existing inbound", inboundTag)
		}
		return 0, err
	}
	return id, nil
}

func (s *Store) resolveRoutingInboundTagByID(ctx context.Context, inboundID int64) (string, error) {
	var protocol string
	if err := s.db.QueryRowContext(ctx, `SELECT protocol FROM inbounds WHERE id=?`, inboundID).Scan(&protocol); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("inbound not found: %d", inboundID)
		}
		return "", err
	}
	return fmt.Sprintf("inbound-%d-%s", inboundID, strings.ToLower(strings.TrimSpace(protocol))), nil
}

func (s *Store) validateRoutingCoreCompatibility(ctx context.Context, inboundID int64, clientID int64, outbound Outbound) error {
	cores, err := s.routingRuleCores(ctx, inboundID, clientID)
	if err != nil {
		return err
	}
	for _, core := range cores {
		if !OutboundSupportsCore(outbound, core) {
			return fmt.Errorf("outbound %q does not support %s", outbound.Tag, core)
		}
	}
	return nil
}

func (s *Store) routingRuleCores(ctx context.Context, inboundID int64, clientID int64) ([]string, error) {
	if inboundID > 0 {
		var protocol string
		var core string
		err := s.db.QueryRowContext(ctx, `SELECT protocol, core FROM inbounds WHERE id=?`, inboundID).Scan(&protocol, &core)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("inbound not found: %d", inboundID)
			}
			return nil, err
		}
		if strings.TrimSpace(core) == "" {
			core = InferInboundCore(protocol)
		}
		return []string{NormalizeCore(core)}, nil
	}
	if clientID > 0 {
		var protocol string
		var core string
		if err := s.db.QueryRowContext(ctx, `
SELECT i.protocol, i.core
FROM clients c
JOIN inbounds i ON i.id = c.inbound_id
WHERE c.id = ?
`, clientID).Scan(&protocol, &core); err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("client not found: %d", clientID)
			}
			return nil, err
		}
		if strings.TrimSpace(core) == "" {
			core = InferInboundCore(protocol)
		}
		return []string{NormalizeCore(core)}, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT protocol, core FROM inbounds ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	cores := []string{}
	for rows.Next() {
		var protocol string
		var core string
		if err := rows.Scan(&protocol, &core); err != nil {
			return nil, err
		}
		if strings.TrimSpace(core) == "" {
			core = InferInboundCore(protocol)
		}
		core = NormalizeCore(core)
		if !seen[core] {
			seen[core] = true
			cores = append(cores, core)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cores) == 0 {
		return []string{CoreXray}, nil
	}
	return cores, nil
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

func (s *Store) ReorderRoutingRules(ctx context.Context, ids []int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i, id := range ids {
		_, err := tx.ExecContext(ctx, `UPDATE routing_rules SET sort = ? WHERE id = ?`, i, id)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
