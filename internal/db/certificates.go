package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func (s *Store) ListCertificates(ctx context.Context) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, source, status, domains, cert_path, key_path, not_before, not_after, fingerprint, serial, issue_email, acme_directory_url, challenge_method, last_error, last_renewed, created_at, updated_at
FROM certificates
ORDER BY id DESC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	certs := []Certificate{}
	for rows.Next() {
		cert, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := s.attachCertificateUsage(ctx, certs); err != nil {
		return nil, err
	}
	return certs, nil
}

func (s *Store) GetCertificate(ctx context.Context, id int64) (Certificate, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, source, status, domains, cert_path, key_path, not_before, not_after, fingerprint, serial, issue_email, acme_directory_url, challenge_method, last_error, last_renewed, created_at, updated_at
FROM certificates
WHERE id=?
`, id)
	cert, err := scanCertificate(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return Certificate{}, fmt.Errorf("certificate not found: %d", id)
		}
		return Certificate{}, err
	}
	certs := []Certificate{cert}
	if err := s.attachCertificateUsage(ctx, certs); err != nil {
		return Certificate{}, err
	}
	return certs[0], nil
}

func (s *Store) UpsertCertificate(ctx context.Context, params UpsertCertificateParams) (Certificate, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	name := strings.TrimSpace(params.Name)
	if name == "" && len(params.Domains) > 0 {
		name = strings.TrimSpace(params.Domains[0])
	}
	if name == "" {
		name = "certificate"
	}
	source := strings.TrimSpace(params.Source)
	if source == "" {
		source = CertSourceImport
	}
	status := strings.TrimSpace(params.Status)
	if status == "" {
		status = CertStatusIssued
	}
	domains, err := encodeDomains(params.Domains)
	if err != nil {
		return Certificate{}, err
	}
	if params.ID > 0 {
		result, err := s.db.ExecContext(ctx, `
UPDATE certificates SET name=?, source=?, status=?, domains=?, cert_path=?, key_path=?, not_before=?, not_after=?, fingerprint=?, serial=?, issue_email=?, acme_directory_url=?, challenge_method=?, last_error=?, last_renewed=?, updated_at=?
WHERE id=?
`, name, source, status, domains, params.CertPath, params.KeyPath, params.NotBefore, params.NotAfter, params.Fingerprint, params.Serial, params.IssueEmail, params.ACMEDirectoryURL, params.ChallengeMethod, params.LastError, params.LastRenewed, now, params.ID)
		if err != nil {
			return Certificate{}, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return Certificate{}, err
		}
		if n == 0 {
			return Certificate{}, fmt.Errorf("certificate not found: %d", params.ID)
		}
		return s.GetCertificate(ctx, params.ID)
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO certificates (name, source, status, domains, cert_path, key_path, not_before, not_after, fingerprint, serial, issue_email, acme_directory_url, challenge_method, last_error, last_renewed, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`, name, source, status, domains, params.CertPath, params.KeyPath, params.NotBefore, params.NotAfter, params.Fingerprint, params.Serial, params.IssueEmail, params.ACMEDirectoryURL, params.ChallengeMethod, params.LastError, params.LastRenewed, now, now)
	if err != nil {
		return Certificate{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Certificate{}, err
	}
	return s.GetCertificate(ctx, id)
}

func (s *Store) UpdateCertificateStatus(ctx context.Context, id int64, status, lastError, lastRenewed string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE certificates SET status=?, last_error=?, last_renewed=?, updated_at=? WHERE id=?`,
		status, lastError, lastRenewed, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("certificate not found: %d", id)
	}
	return nil
}

func (s *Store) DeleteCertificate(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM certificates WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("certificate not found: %d", id)
	}
	return nil
}

func (s *Store) ListCertificateOperations(ctx context.Context, certificateID int64, limit int) ([]CertificateOperation, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `
SELECT id, COALESCE(certificate_id, 0), type, status, code, message, detail, created_at, updated_at
FROM certificate_operations
`
	args := []interface{}{}
	if certificateID > 0 {
		query += `WHERE certificate_id=? `
		args = append(args, certificateID)
	}
	query += `ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	operations := []CertificateOperation{}
	for rows.Next() {
		var op CertificateOperation
		if err := rows.Scan(&op.ID, &op.CertificateID, &op.Type, &op.Status, &op.Code, &op.Message, &op.Detail, &op.CreatedAt, &op.UpdatedAt); err != nil {
			return nil, err
		}
		operations = append(operations, op)
	}
	return operations, rows.Err()
}

func (s *Store) RecordCertificateOperation(ctx context.Context, op CertificateOperation) (CertificateOperation, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	var certID interface{}
	if op.CertificateID > 0 {
		certID = op.CertificateID
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO certificate_operations (certificate_id, type, status, code, message, detail, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`, certID, strings.TrimSpace(op.Type), strings.TrimSpace(op.Status), strings.TrimSpace(op.Code), strings.TrimSpace(op.Message), strings.TrimSpace(op.Detail), now, now)
	if err != nil {
		return CertificateOperation{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return CertificateOperation{}, err
	}
	op.ID = id
	op.CreatedAt = now
	op.UpdatedAt = now
	return op, nil
}

func (s *Store) ApplyCertificateToInbounds(ctx context.Context, cert Certificate, inboundIDs []int64) ([]Inbound, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	updated := []Inbound{}
	for _, id := range inboundIDs {
		if id <= 0 {
			return nil, fmt.Errorf("invalid inbound id: %d", id)
		}
		var existing Inbound
		var enabled int
		row := tx.QueryRowContext(ctx, `SELECT id, uuid, remark, protocol, core, port, network, security, enabled,
			ws_path, ws_host, grpc_service_name, reality_dest, reality_server_names, reality_short_id, reality_private_key, reality_public_key, ss_method,
			tls_cert_file, tls_key_file, tls_sni, tls_fingerprint, tls_alpn, xhttp_path, xhttp_mode,
			hy2_up_mbps, hy2_down_mbps, hy2_obfs, hy2_obfs_password, hy2_mport,
			tuic_congestion_control, tuic_zero_rtt,
			wg_private_key, wg_address, wg_peer_public_key, wg_allowed_ips, wg_endpoint, wg_preshared_key, wg_mtu,
			shadowtls_version, shadowtls_password FROM inbounds WHERE id=?`, id)
		if err := row.Scan(&existing.ID, &existing.UUID, &existing.Remark, &existing.Protocol, &existing.Core, &existing.Port, &existing.Network, &existing.Security, &enabled,
			&existing.WsPath, &existing.WsHost, &existing.GrpcServiceName, &existing.RealityDest, &existing.RealityServerNames, &existing.RealityShortID, &existing.RealityPrivateKey, &existing.RealityPublicKey, &existing.SSMethod,
			&existing.TLSCertFile, &existing.TLSKeyFile, &existing.TLSSNI, &existing.TLSFingerprint, &existing.TLSALPN, &existing.XHTTPPath, &existing.XHTTPMode,
			&existing.Hy2UpMbps, &existing.Hy2DownMbps, &existing.Hy2Obfs, &existing.Hy2ObfsPassword, &existing.Hy2MPort,
			&existing.TuicCongestionControl, &existing.TuicZeroRTT,
			&existing.WgPrivateKey, &existing.WgAddress, &existing.WgPeerPublicKey, &existing.WgAllowedIPs, &existing.WgEndpoint, &existing.WgPresharedKey, &existing.WgMTU,
			&existing.ShadowTLSVersion, &existing.ShadowTLSPassword); err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("inbound not found: %d", id)
			}
			return nil, err
		}
		if NormalizeInboundSecurity(existing.Protocol, existing.Security) != "tls" {
			return nil, fmt.Errorf("inbound %d is not a TLS inbound", id)
		}
		nextSNI := firstDomain(cert.Domains)
		if nextSNI == "" {
			nextSNI = strings.TrimSpace(existing.TLSSNI)
		}
		nextWSHost := existing.WsHost
		if nextSNI != "" && shouldSyncCertificateWSHost(existing.Network, existing.WsHost, existing.TLSSNI) {
			nextWSHost = nextSNI
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inbounds SET tls_cert_file=?, tls_key_file=?, tls_sni=?, ws_host=? WHERE id=?`, cert.CertPath, cert.KeyPath, nextSNI, nextWSHost, id); err != nil {
			return nil, err
		}
		existing.Enabled = enabled != 0
		if existing.Core == "" {
			existing.Core = InferInboundCore(existing.Protocol)
		}
		existing.TLSCertFile = cert.CertPath
		existing.TLSKeyFile = cert.KeyPath
		existing.TLSSNI = nextSNI
		existing.WsHost = nextWSHost
		existing.Clients = []Client{}
		updated = append(updated, existing)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return updated, nil
}

func shouldSyncCertificateWSHost(network, wsHost, oldSNI string) bool {
	normalizedNetwork := strings.ToLower(strings.TrimSpace(network))
	if normalizedNetwork != "ws" && normalizedNetwork != "h2" {
		return false
	}
	currentHost := strings.TrimSpace(wsHost)
	if currentHost == "" || currentHost == "example.com" {
		return true
	}
	previousSNI := strings.TrimSpace(oldSNI)
	return previousSNI != "" && currentHost == previousSNI
}

type certificateScanner interface {
	Scan(dest ...interface{}) error
}

func scanCertificate(row certificateScanner) (Certificate, error) {
	var cert Certificate
	var domains string
	if err := row.Scan(&cert.ID, &cert.Name, &cert.Source, &cert.Status, &domains, &cert.CertPath, &cert.KeyPath, &cert.NotBefore, &cert.NotAfter, &cert.Fingerprint, &cert.Serial, &cert.IssueEmail, &cert.ACMEDirectoryURL, &cert.ChallengeMethod, &cert.LastError, &cert.LastRenewed, &cert.CreatedAt, &cert.UpdatedAt); err != nil {
		return Certificate{}, err
	}
	cert.Domains = decodeDomains(domains)
	cert.Usages = []Inbound{}
	return cert, nil
}

func (s *Store) attachCertificateUsage(ctx context.Context, certs []Certificate) error {
	if len(certs) == 0 {
		return nil
	}
	inbounds, err := s.ListInbounds(ctx)
	if err != nil {
		return err
	}
	for i := range certs {
		for _, inbound := range inbounds {
			if strings.TrimSpace(inbound.TLSCertFile) == certs[i].CertPath && strings.TrimSpace(inbound.TLSKeyFile) == certs[i].KeyPath {
				certs[i].UsageCount++
				certs[i].Usages = append(certs[i].Usages, inbound)
			}
		}
	}
	return nil
}

func encodeDomains(domains []string) (string, error) {
	clean := make([]string, 0, len(domains))
	seen := map[string]bool{}
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		clean = append(clean, domain)
	}
	data, err := json.Marshal(clean)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeDomains(raw string) []string {
	var domains []string
	if err := json.Unmarshal([]byte(raw), &domains); err == nil {
		return domains
	}
	return []string{}
}

func firstDomain(domains []string) string {
	if len(domains) == 0 {
		return ""
	}
	return domains[0]
}
