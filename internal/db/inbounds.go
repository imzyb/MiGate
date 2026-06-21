package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const (
	autoInboundPortMin = 20000
	autoInboundPortMax = 60000
)

func (s *Store) CreateInbound(ctx context.Context, params CreateInboundParams) (Inbound, error) {
	protocol := NormalizeInboundProtocol(params.Protocol)
	if !SupportedInboundProtocol(protocol) {
		return Inbound{}, fmt.Errorf("unsupported protocol: %s", params.Protocol)
	}
	core := InferInboundCore(protocol)
	port := params.Port
	if port == 0 {
		allocated, err := s.allocateInboundPort(ctx, 0)
		if err != nil {
			return Inbound{}, err
		}
		port = allocated
	}
	if port <= 0 || port > 65535 {
		return Inbound{}, fmt.Errorf("invalid port: %d", params.Port)
	}
	network := NormalizeInboundNetwork(protocol, params.Network)
	security := NormalizeInboundSecurity(protocol, params.Security)
	if err := prepareCreateInboundRealityMaterial(security, &params); err != nil {
		return Inbound{}, err
	}
	remark := strings.TrimSpace(params.Remark)
	if remark == "" {
		remark = protocol
	}
	candidate := Inbound{Remark: remark, Protocol: protocol, Core: core, Port: port, Network: network, Security: security,
		RealityDest: params.RealityDest, RealityServerNames: params.RealityServerNames, RealityPrivateKey: params.RealityPrivateKey, RealityPublicKey: params.RealityPublicKey,
		ShadowTLSVersion: params.ShadowTLSVersion, TLSSNI: params.TLSSNI}
	if err := ValidateInboundCombination(candidate); err != nil {
		return Inbound{}, err
	}
	var preparedClient *Client
	if params.InitialClient != nil {
		initialClient := *params.InitialClient
		initialClient.InboundID = 0
		client, err := s.prepareClientForCreate(ctx, Inbound{Protocol: protocol}, initialClient)
		if err != nil {
			return Inbound{}, err
		}
		preparedClient = &client
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Inbound{}, err
	}
	defer tx.Rollback()
	id, uuid, err := s.insertInboundTx(ctx, tx, params.UUID, remark, protocol, core, port, network, security,
		params.WsPath, params.WsHost, params.GrpcServiceName,
		params.RealityDest, params.RealityServerNames, params.RealityShortID, params.RealityPrivateKey, params.RealityPublicKey,
		params.SSMethod, params.TLSCertFile, params.TLSKeyFile, params.TLSSNI, params.TLSFingerprint, params.TLSALPN, params.XHTTPPath, params.XHTTPMode,
		params.Hy2UpMbps, params.Hy2DownMbps, params.Hy2Obfs, params.Hy2ObfsPassword, params.Hy2MPort,
		params.TuicCongestionControl, params.TuicZeroRTT,
		params.WgPrivateKey, params.WgAddress, params.WgPeerPublicKey, params.WgAllowedIPs, params.WgEndpoint, params.WgPresharedKey, params.WgMTU,
		params.ShadowTLSVersion, params.ShadowTLSPassword)
	if err != nil {
		return Inbound{}, err
	}
	var clients []Client
	if preparedClient != nil {
		preparedClient.InboundID = id
		createdClient, err := s.insertClientTx(ctx, tx, *preparedClient)
		if err != nil {
			return Inbound{}, err
		}
		clients = []Client{createdClient}
	}
	if err := tx.Commit(); err != nil {
		return Inbound{}, err
	}
	return Inbound{ID: id, UUID: uuid, Remark: remark, Protocol: protocol, Core: core, Port: port, Network: network, Security: security, Enabled: true,
		WsPath: params.WsPath, WsHost: params.WsHost, GrpcServiceName: params.GrpcServiceName,
		RealityDest: params.RealityDest, RealityServerNames: params.RealityServerNames, RealityShortID: params.RealityShortID,
		RealityPrivateKey: params.RealityPrivateKey,
		RealityPublicKey:  params.RealityPublicKey,
		SSMethod:          params.SSMethod,
		TLSCertFile:       params.TLSCertFile, TLSKeyFile: params.TLSKeyFile,
		TLSSNI: params.TLSSNI, TLSFingerprint: params.TLSFingerprint, TLSALPN: params.TLSALPN,
		XHTTPPath: params.XHTTPPath, XHTTPMode: params.XHTTPMode,
		Hy2UpMbps: params.Hy2UpMbps, Hy2DownMbps: params.Hy2DownMbps,
		Hy2Obfs: params.Hy2Obfs, Hy2ObfsPassword: params.Hy2ObfsPassword, Hy2MPort: params.Hy2MPort,
		TuicCongestionControl: params.TuicCongestionControl,
		TuicZeroRTT:           params.TuicZeroRTT,
		WgPrivateKey:          params.WgPrivateKey,
		WgAddress:             params.WgAddress,
		WgPeerPublicKey:       params.WgPeerPublicKey,
		WgAllowedIPs:          params.WgAllowedIPs,
		WgEndpoint:            params.WgEndpoint,
		WgPresharedKey:        params.WgPresharedKey,
		WgMTU:                 params.WgMTU,
		ShadowTLSVersion:      params.ShadowTLSVersion,
		ShadowTLSPassword:     params.ShadowTLSPassword,
		Clients:               clients}, nil
}

func (s *Store) insertInbound(ctx context.Context, inboundUUID, remark, protocol, core string, port int, network, security string,
	wsPath, wsHost, grpcServiceName, realityDest, realityServerNames, realityShortID, realityPrivateKey, realityPublicKey, ssMethod, tlsCertFile, tlsKeyFile, tlsSNI, tlsFingerprint, tlsALPN, xhttpPath, xhttpMode string,
	hy2UpMbps, hy2DownMbps int, hy2Obfs, hy2ObfsPassword, hy2MPort string,
	tuicCongestionControl string, tuicZeroRTT bool,
	wgPrivateKey, wgAddress, wgPeerPublicKey, wgAllowedIPs, wgEndpoint, wgPresharedKey string, wgMTU int,
	shadowTLSVersion int, shadowTLSPassword string) (int64, string, error) {
	return s.insertInboundTx(ctx, s.db, inboundUUID, remark, protocol, core, port, network, security,
		wsPath, wsHost, grpcServiceName, realityDest, realityServerNames, realityShortID, realityPrivateKey, realityPublicKey, ssMethod, tlsCertFile, tlsKeyFile, tlsSNI, tlsFingerprint, tlsALPN, xhttpPath, xhttpMode,
		hy2UpMbps, hy2DownMbps, hy2Obfs, hy2ObfsPassword, hy2MPort,
		tuicCongestionControl, tuicZeroRTT,
		wgPrivateKey, wgAddress, wgPeerPublicKey, wgAllowedIPs, wgEndpoint, wgPresharedKey, wgMTU,
		shadowTLSVersion, shadowTLSPassword)
}

func (s *Store) insertInboundTx(ctx context.Context, execer sqlExecer, inboundUUID, remark, protocol, core string, port int, network, security string,
	wsPath, wsHost, grpcServiceName, realityDest, realityServerNames, realityShortID, realityPrivateKey, realityPublicKey, ssMethod, tlsCertFile, tlsKeyFile, tlsSNI, tlsFingerprint, tlsALPN, xhttpPath, xhttpMode string,
	hy2UpMbps, hy2DownMbps int, hy2Obfs, hy2ObfsPassword, hy2MPort string,
	tuicCongestionControl string, tuicZeroRTT bool,
	wgPrivateKey, wgAddress, wgPeerPublicKey, wgAllowedIPs, wgEndpoint, wgPresharedKey string, wgMTU int,
	shadowTLSVersion int, shadowTLSPassword string) (int64, string, error) {
	uuid := strings.TrimSpace(inboundUUID)
	if uuid == "" {
		uuid = newUUID()
	}
	tuicZeroRTTInt := 0
	if tuicZeroRTT {
		tuicZeroRTTInt = 1
	}
	result, err := execer.ExecContext(ctx, `
INSERT INTO inbounds (uuid, remark, protocol, core, port, network, security, enabled, created_at,
  ws_path, ws_host, grpc_service_name, reality_dest, reality_server_names, reality_short_id, reality_private_key, reality_public_key, ss_method, tls_cert_file, tls_key_file, tls_sni, tls_fingerprint, tls_alpn, xhttp_path, xhttp_mode,
  hy2_up_mbps, hy2_down_mbps, hy2_obfs, hy2_obfs_password, hy2_mport,
  tuic_congestion_control, tuic_zero_rtt,
  wg_private_key, wg_address, wg_peer_public_key, wg_allowed_ips, wg_endpoint, wg_preshared_key, wg_mtu,
  shadowtls_version, shadowtls_password)
VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?,
  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?,
  ?, ?,
  ?, ?, ?, ?, ?, ?, ?,
  ?, ?)`,
		uuid, remark, protocol, core, port, network, security, time.Now().UTC().Format(time.RFC3339),
		wsPath, wsHost, grpcServiceName, realityDest, realityServerNames, realityShortID, realityPrivateKey, realityPublicKey, ssMethod, tlsCertFile, tlsKeyFile, tlsSNI, tlsFingerprint, tlsALPN, xhttpPath, xhttpMode,
		hy2UpMbps, hy2DownMbps, hy2Obfs, hy2ObfsPassword, hy2MPort,
		tuicCongestionControl, tuicZeroRTTInt,
		wgPrivateKey, wgAddress, wgPeerPublicKey, wgAllowedIPs, wgEndpoint, wgPresharedKey, wgMTU,
		shadowTLSVersion, shadowTLSPassword)
	if err != nil {
		return 0, "", err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, "", err
	}
	return id, uuid, nil
}

func (s *Store) DeleteInbound(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var protocol string
	var remark string
	if err := tx.QueryRowContext(ctx, `SELECT protocol, remark FROM inbounds WHERE id=?`, id).Scan(&protocol, &remark); err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("inbound not found: %d", id)
		}
		return err
	}
	generatedTag := fmt.Sprintf("inbound-%d-%s", id, strings.ToLower(strings.TrimSpace(protocol)))
	if _, err := tx.ExecContext(ctx, `
DELETE FROM routing_rules
WHERE client_id IN (SELECT clients.id FROM clients WHERE clients.inbound_id = ?)
   OR inbound_tag = ?
   OR (TRIM(?) <> '' AND inbound_tag = TRIM(?))
`, id, generatedTag, remark, remark); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM clients WHERE inbound_id = ?`, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM inbounds WHERE id = ?`, id)
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
	return tx.Commit()
}

func (s *Store) getInboundBasic(ctx context.Context, id int64) (Inbound, error) {
	var inbound Inbound
	if err := s.db.QueryRowContext(ctx, `SELECT id, uuid, remark, protocol, core, port, network, security, enabled FROM inbounds WHERE id=?`, id).Scan(
		&inbound.ID, &inbound.UUID, &inbound.Remark, &inbound.Protocol, &inbound.Core, &inbound.Port, &inbound.Network, &inbound.Security, new(int),
	); err != nil {
		if err == sql.ErrNoRows {
			return Inbound{}, fmt.Errorf("inbound not found: %d", id)
		}
		return Inbound{}, err
	}
	if inbound.Core == "" {
		inbound.Core = InferInboundCore(inbound.Protocol)
	}
	return inbound, nil
}

func prepareCreateInboundRealityMaterial(security string, params *CreateInboundParams) error {
	if strings.ToLower(strings.TrimSpace(security)) != "reality" {
		return nil
	}
	if strings.TrimSpace(params.RealityDest) == "" {
		params.RealityDest = "www.cloudflare.com:443"
	}
	if strings.TrimSpace(params.RealityServerNames) == "" {
		params.RealityServerNames = "www.cloudflare.com"
	}
	if strings.TrimSpace(params.RealityPrivateKey) == "" {
		privateKey, publicKey, err := generateRealityKeyPair()
		if err != nil {
			return err
		}
		params.RealityPrivateKey = privateKey
		params.RealityPublicKey = publicKey
	} else if strings.TrimSpace(params.RealityPublicKey) == "" {
		publicKey, err := deriveRealityPublicKey(params.RealityPrivateKey)
		if err == nil {
			params.RealityPublicKey = publicKey
		} else {
			privateKey, publicKey, err := generateRealityKeyPair()
			if err != nil {
				return err
			}
			params.RealityPrivateKey = privateKey
			params.RealityPublicKey = publicKey
		}
	}
	if strings.TrimSpace(params.RealityShortID) == "" {
		params.RealityShortID = newSecret(4)
	}
	return nil
}

func (s *Store) prepareUpdateInboundRealityMaterial(ctx context.Context, id int64, security string, params *UpdateInboundParams) error {
	if strings.ToLower(strings.TrimSpace(security)) != "reality" {
		return nil
	}
	if strings.TrimSpace(params.RealityDest) == "" {
		params.RealityDest = "www.cloudflare.com:443"
	}
	if strings.TrimSpace(params.RealityServerNames) == "" {
		params.RealityServerNames = "www.cloudflare.com"
	}
	var existingPrivateKey string
	var existingPublicKey string
	var existingShortID string
	_ = s.db.QueryRowContext(ctx, `SELECT reality_private_key, reality_public_key, reality_short_id FROM inbounds WHERE id=?`, id).Scan(&existingPrivateKey, &existingPublicKey, &existingShortID)
	if strings.TrimSpace(params.RealityPrivateKey) == "" {
		params.RealityPrivateKey = existingPrivateKey
	}
	if strings.TrimSpace(params.RealityPublicKey) == "" {
		params.RealityPublicKey = existingPublicKey
	}
	if strings.TrimSpace(params.RealityShortID) == "" {
		params.RealityShortID = existingShortID
	}
	if strings.TrimSpace(params.RealityPrivateKey) == "" {
		privateKey, publicKey, err := generateRealityKeyPair()
		if err != nil {
			return err
		}
		params.RealityPrivateKey = privateKey
		params.RealityPublicKey = publicKey
	} else if strings.TrimSpace(params.RealityPublicKey) == "" {
		publicKey, err := deriveRealityPublicKey(params.RealityPrivateKey)
		if err == nil {
			params.RealityPublicKey = publicKey
		} else {
			privateKey, publicKey, err := generateRealityKeyPair()
			if err != nil {
				return err
			}
			params.RealityPrivateKey = privateKey
			params.RealityPublicKey = publicKey
		}
	}
	if strings.TrimSpace(params.RealityShortID) == "" {
		params.RealityShortID = newSecret(4)
	}
	return nil
}

func generateRealityKeyPair() (string, string, error) {
	privateBytes := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateBytes); err != nil {
		return "", "", err
	}
	publicBytes, err := curve25519.X25519(privateBytes, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(privateBytes), base64.RawURLEncoding.EncodeToString(publicBytes), nil
}

func deriveRealityPublicKey(privateKey string) (string, error) {
	privateBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil {
		return "", err
	}
	if len(privateBytes) != curve25519.ScalarSize {
		return "", fmt.Errorf("invalid reality private key length: %d", len(privateBytes))
	}
	publicBytes, err := curve25519.X25519(privateBytes, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(publicBytes), nil
}

func (s *Store) UpdateInbound(ctx context.Context, id int64, params UpdateInboundParams) (Inbound, error) {
	remark := strings.TrimSpace(params.Remark)
	if remark == "" {
		return Inbound{}, fmt.Errorf("remark cannot be empty")
	}
	port := params.Port
	if port == 0 {
		allocated, err := s.allocateInboundPort(ctx, id)
		if err != nil {
			return Inbound{}, err
		}
		port = allocated
	}
	if port <= 0 || port > 65535 {
		return Inbound{}, fmt.Errorf("invalid port: %d", params.Port)
	}
	protocol := NormalizeInboundProtocol(params.Protocol)
	if protocol == "" {
		protocol = "vless"
	}
	if !SupportedInboundProtocol(protocol) {
		return Inbound{}, fmt.Errorf("unsupported protocol: %s", params.Protocol)
	}
	core := InferInboundCore(protocol)
	network := NormalizeInboundNetwork(protocol, params.Network)
	security := NormalizeInboundSecurity(protocol, params.Security)
	if err := s.prepareUpdateInboundRealityMaterial(ctx, id, security, &params); err != nil {
		return Inbound{}, err
	}
	candidate := Inbound{ID: id, UUID: params.UUID, Remark: remark, Protocol: protocol, Core: core, Port: port, Network: network, Security: security,
		RealityDest: params.RealityDest, RealityServerNames: params.RealityServerNames, RealityPrivateKey: params.RealityPrivateKey, RealityPublicKey: params.RealityPublicKey,
		ShadowTLSVersion: params.ShadowTLSVersion, TLSSNI: params.TLSSNI}
	if err := ValidateInboundCombination(candidate); err != nil {
		return Inbound{}, err
	}
	// Preserve existing UUID if not provided in update
	uuid := params.UUID
	if uuid == "" {
		var existingUUID string
		err := s.db.QueryRowContext(ctx, `SELECT uuid FROM inbounds WHERE id=?`, id).Scan(&existingUUID)
		if err == nil {
			uuid = existingUUID
		}
	}
	enabled := 0
	if params.Enabled {
		enabled = 1
	}
	tuicZeroRTTInt := 0
	if params.TuicZeroRTT {
		tuicZeroRTTInt = 1
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Inbound{}, err
	}
	defer tx.Rollback()
	var oldRemark string
	var oldProtocol string
	if err := tx.QueryRowContext(ctx, `SELECT remark, protocol FROM inbounds WHERE id=?`, id).Scan(&oldRemark, &oldProtocol); err != nil {
		if err == sql.ErrNoRows {
			return Inbound{}, fmt.Errorf("inbound not found: %d", id)
		}
		return Inbound{}, err
	}
	if NormalizeInboundProtocol(oldProtocol) != protocol {
		if err := validateExistingClientsForProtocolChange(ctx, tx, id, protocol); err != nil {
			return Inbound{}, err
		}
	}
	oldRemark = strings.TrimSpace(oldRemark)
	oldRemarkMatches := 0
	if oldRemark != "" {
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM inbounds WHERE TRIM(remark)=?`, oldRemark).Scan(&oldRemarkMatches); err != nil {
			return Inbound{}, err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE inbounds SET uuid=?, remark=?, protocol=?, core=?, port=?, network=?, security=?, enabled=?,
		ws_path=?, ws_host=?, grpc_service_name=?, reality_dest=?, reality_server_names=?, reality_short_id=?, reality_private_key=?, reality_public_key=?, ss_method=?,
		tls_cert_file=?, tls_key_file=?, tls_sni=?, tls_fingerprint=?, tls_alpn=?, xhttp_path=?, xhttp_mode=?,
		hy2_up_mbps=?, hy2_down_mbps=?, hy2_obfs=?, hy2_obfs_password=?, hy2_mport=?,
		tuic_congestion_control=?, tuic_zero_rtt=?,
		wg_private_key=?, wg_address=?, wg_peer_public_key=?, wg_allowed_ips=?, wg_endpoint=?, wg_preshared_key=?, wg_mtu=?,
		shadowtls_version=?, shadowtls_password=? WHERE id=?`,
		uuid, remark, protocol, core, port, network, security, enabled,
		params.WsPath, params.WsHost, params.GrpcServiceName, params.RealityDest, params.RealityServerNames, params.RealityShortID, params.RealityPrivateKey, params.RealityPublicKey, params.SSMethod,
		params.TLSCertFile, params.TLSKeyFile, params.TLSSNI, params.TLSFingerprint, params.TLSALPN, params.XHTTPPath, params.XHTTPMode,
		params.Hy2UpMbps, params.Hy2DownMbps, params.Hy2Obfs, params.Hy2ObfsPassword, params.Hy2MPort,
		params.TuicCongestionControl, tuicZeroRTTInt,
		params.WgPrivateKey, params.WgAddress, params.WgPeerPublicKey, params.WgAllowedIPs, params.WgEndpoint, params.WgPresharedKey, params.WgMTU,
		params.ShadowTLSVersion, params.ShadowTLSPassword, id)
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
	oldGeneratedTag := fmt.Sprintf("inbound-%d-%s", id, strings.ToLower(strings.TrimSpace(oldProtocol)))
	newGeneratedTag := fmt.Sprintf("inbound-%d-%s", id, protocol)
	if oldGeneratedTag != newGeneratedTag {
		if _, err := tx.ExecContext(ctx, `UPDATE routing_rules SET inbound_tag=? WHERE inbound_tag=?`, newGeneratedTag, oldGeneratedTag); err != nil {
			return Inbound{}, err
		}
	}
	if oldRemark != "" && oldRemark != remark && oldRemarkMatches == 1 {
		if _, err := tx.ExecContext(ctx, `UPDATE routing_rules SET inbound_tag=? WHERE inbound_tag=?`, remark, oldRemark); err != nil {
			return Inbound{}, err
		}
	}
	// Reload to get the full row
	row := tx.QueryRowContext(ctx, `SELECT id, uuid, remark, protocol, core, port, network, security, enabled,
		ws_path, ws_host, grpc_service_name, reality_dest, reality_server_names, reality_short_id, reality_private_key, reality_public_key, ss_method,
		tls_cert_file, tls_key_file, tls_sni, tls_fingerprint, tls_alpn, xhttp_path, xhttp_mode,
		hy2_up_mbps, hy2_down_mbps, hy2_obfs, hy2_obfs_password, hy2_mport,
		tuic_congestion_control, tuic_zero_rtt,
		wg_private_key, wg_address, wg_peer_public_key, wg_allowed_ips, wg_endpoint, wg_preshared_key, wg_mtu,
		shadowtls_version, shadowtls_password FROM inbounds WHERE id=?`, id)
	var inbound Inbound
	var dbEnabled int
	if err := row.Scan(&inbound.ID, &inbound.UUID, &inbound.Remark, &inbound.Protocol, &inbound.Core, &inbound.Port, &inbound.Network, &inbound.Security, &dbEnabled,
		&inbound.WsPath, &inbound.WsHost, &inbound.GrpcServiceName, &inbound.RealityDest, &inbound.RealityServerNames, &inbound.RealityShortID, &inbound.RealityPrivateKey, &inbound.RealityPublicKey, &inbound.SSMethod,
		&inbound.TLSCertFile, &inbound.TLSKeyFile, &inbound.TLSSNI, &inbound.TLSFingerprint, &inbound.TLSALPN, &inbound.XHTTPPath, &inbound.XHTTPMode,
		&inbound.Hy2UpMbps, &inbound.Hy2DownMbps, &inbound.Hy2Obfs, &inbound.Hy2ObfsPassword, &inbound.Hy2MPort,
		&inbound.TuicCongestionControl, &inbound.TuicZeroRTT,
		&inbound.WgPrivateKey, &inbound.WgAddress, &inbound.WgPeerPublicKey, &inbound.WgAllowedIPs, &inbound.WgEndpoint, &inbound.WgPresharedKey, &inbound.WgMTU,
		&inbound.ShadowTLSVersion, &inbound.ShadowTLSPassword); err != nil {
		return Inbound{}, err
	}
	if err := tx.Commit(); err != nil {
		return Inbound{}, err
	}
	inbound.Enabled = dbEnabled != 0
	if inbound.Core == "" {
		inbound.Core = InferInboundCore(inbound.Protocol)
	}
	inbound.Clients = []Client{}
	return inbound, nil
}

func validateExistingClientsForProtocolChange(ctx context.Context, querier sqlQuerier, inboundID int64, targetProtocol string) error {
	rows, err := querier.QueryContext(ctx, `SELECT id, uuid, credential_id, password, email FROM clients WHERE inbound_id=? ORDER BY id ASC`, inboundID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var client Client
		if err := rows.Scan(&client.ID, &client.UUID, &client.CredentialID, &client.Password, &client.Email); err != nil {
			return err
		}
		if err := ValidateClientCredential(targetProtocol, client); err != nil {
			label := strings.TrimSpace(client.Email)
			if label == "" {
				label = fmt.Sprintf("client-%d", client.ID)
			}
			return fmt.Errorf("cannot change inbound protocol to %s: client %s has incompatible credentials: %w", targetProtocol, label, err)
		}
	}
	return rows.Err()
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
	row := s.db.QueryRowContext(ctx, `SELECT id, uuid, remark, protocol, core, port, network, security, enabled,
		ws_path, ws_host, grpc_service_name, reality_dest, reality_server_names, reality_short_id, reality_private_key, reality_public_key, ss_method,
		tls_cert_file, tls_key_file, tls_sni, tls_fingerprint, tls_alpn, xhttp_path, xhttp_mode,
		hy2_up_mbps, hy2_down_mbps, hy2_obfs, hy2_obfs_password, hy2_mport,
		tuic_congestion_control, tuic_zero_rtt,
		wg_private_key, wg_address, wg_peer_public_key, wg_allowed_ips, wg_endpoint, wg_preshared_key, wg_mtu,
		shadowtls_version, shadowtls_password FROM inbounds WHERE id=?`, id)
	var inbound Inbound
	if err := row.Scan(&inbound.ID, &inbound.UUID, &inbound.Remark, &inbound.Protocol, &inbound.Core, &inbound.Port, &inbound.Network, &inbound.Security, &dbEnabled,
		&inbound.WsPath, &inbound.WsHost, &inbound.GrpcServiceName, &inbound.RealityDest, &inbound.RealityServerNames, &inbound.RealityShortID, &inbound.RealityPrivateKey, &inbound.RealityPublicKey, &inbound.SSMethod,
		&inbound.TLSCertFile, &inbound.TLSKeyFile, &inbound.TLSSNI, &inbound.TLSFingerprint, &inbound.TLSALPN, &inbound.XHTTPPath, &inbound.XHTTPMode,
		&inbound.Hy2UpMbps, &inbound.Hy2DownMbps, &inbound.Hy2Obfs, &inbound.Hy2ObfsPassword, &inbound.Hy2MPort,
		&inbound.TuicCongestionControl, &inbound.TuicZeroRTT,
		&inbound.WgPrivateKey, &inbound.WgAddress, &inbound.WgPeerPublicKey, &inbound.WgAllowedIPs, &inbound.WgEndpoint, &inbound.WgPresharedKey, &inbound.WgMTU,
		&inbound.ShadowTLSVersion, &inbound.ShadowTLSPassword); err != nil {
		return Inbound{}, err
	}
	inbound.Enabled = dbEnabled != 0
	if inbound.Core == "" {
		inbound.Core = InferInboundCore(inbound.Protocol)
	}
	inbound.Clients = []Client{}
	return inbound, nil
}
func (s *Store) ListInbounds(ctx context.Context) ([]Inbound, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, uuid, remark, protocol, core, port, network, security, enabled,
  ws_path, ws_host, grpc_service_name, reality_dest, reality_server_names, reality_short_id, reality_private_key, reality_public_key, ss_method,
  tls_cert_file, tls_key_file, tls_sni, tls_fingerprint, tls_alpn, xhttp_path, xhttp_mode,
  hy2_up_mbps, hy2_down_mbps, hy2_obfs, hy2_obfs_password, hy2_mport,
  tuic_congestion_control, tuic_zero_rtt,
  wg_private_key, wg_address, wg_peer_public_key, wg_allowed_ips, wg_endpoint, wg_preshared_key, wg_mtu,
  shadowtls_version, shadowtls_password
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
		if err := rows.Scan(&inbound.ID, &inbound.UUID, &inbound.Remark, &inbound.Protocol, &inbound.Core, &inbound.Port, &inbound.Network, &inbound.Security, &enabled,
			&inbound.WsPath, &inbound.WsHost, &inbound.GrpcServiceName, &inbound.RealityDest, &inbound.RealityServerNames, &inbound.RealityShortID, &inbound.RealityPrivateKey, &inbound.RealityPublicKey, &inbound.SSMethod,
			&inbound.TLSCertFile, &inbound.TLSKeyFile, &inbound.TLSSNI, &inbound.TLSFingerprint, &inbound.TLSALPN, &inbound.XHTTPPath, &inbound.XHTTPMode,
			&inbound.Hy2UpMbps, &inbound.Hy2DownMbps, &inbound.Hy2Obfs, &inbound.Hy2ObfsPassword, &inbound.Hy2MPort,
			&inbound.TuicCongestionControl, &inbound.TuicZeroRTT,
			&inbound.WgPrivateKey, &inbound.WgAddress, &inbound.WgPeerPublicKey, &inbound.WgAllowedIPs, &inbound.WgEndpoint, &inbound.WgPresharedKey, &inbound.WgMTU,
			&inbound.ShadowTLSVersion, &inbound.ShadowTLSPassword); err != nil {
			return nil, err
		}
		inbound.Enabled = enabled != 0
		if inbound.Core == "" {
			inbound.Core = InferInboundCore(inbound.Protocol)
		}
		inbound.Clients = []Client{}
		byID[inbound.ID] = len(inbounds)
		inbounds = append(inbounds, inbound)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	clientRows, err := s.db.QueryContext(ctx, `
SELECT id, inbound_id, uuid, credential_id, password, subscription_token, stats_key, email, enabled, up, down, traffic_limit, expiry_at
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
		if err := clientRows.Scan(&client.ID, &client.InboundID, &client.UUID, &client.CredentialID, &client.Password, &client.SubscriptionToken, &client.StatsKey, &client.Email, &enabled, &client.Up, &client.Down, &client.TrafficLimit, &client.ExpiryAt); err != nil {
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

func (s *Store) ListInboundTraffic(ctx context.Context) ([]Inbound, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, uuid, remark, protocol, core, port, network, security, enabled
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
		if err := rows.Scan(&inbound.ID, &inbound.UUID, &inbound.Remark, &inbound.Protocol, &inbound.Core, &inbound.Port, &inbound.Network, &inbound.Security, &enabled); err != nil {
			return nil, err
		}
		inbound.Enabled = enabled != 0
		if inbound.Core == "" {
			inbound.Core = InferInboundCore(inbound.Protocol)
		}
		inbound.Clients = []Client{}
		byID[inbound.ID] = len(inbounds)
		inbounds = append(inbounds, inbound)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	clientRows, err := s.db.QueryContext(ctx, `
SELECT id, inbound_id, stats_key, email, enabled, up, down, traffic_limit, expiry_at
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
		if err := clientRows.Scan(&client.ID, &client.InboundID, &client.StatsKey, &client.Email, &enabled, &client.Up, &client.Down, &client.TrafficLimit, &client.ExpiryAt); err != nil {
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

func (s *Store) ValidationConfigHash(ctx context.Context) (string, error) {
	inbounds, err := s.validationInboundKeys(ctx)
	if err != nil {
		return "", err
	}
	outbounds, err := s.validationOutboundKeys(ctx)
	if err != nil {
		return "", err
	}
	rules, err := s.validationRoutingRuleKeys(ctx)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(validationConfigHashPayload{Inbounds: inbounds, Outbounds: outbounds, Rules: rules})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("%x", sum[:]), nil
}

func (s *Store) ValidationConfigVersion(ctx context.Context) (int64, error) {
	var version int64
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM config_meta WHERE key='validation_version'`).Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

type validationConfigHashPayload struct {
	Inbounds  []validationInboundHashKey     `json:"inbounds"`
	Outbounds []validationOutboundHashKey    `json:"outbounds"`
	Rules     []validationRoutingRuleHashKey `json:"rules"`
}

type validationInboundHashKey struct {
	ID                    int64                     `json:"id"`
	UUID                  string                    `json:"uuid"`
	Remark                string                    `json:"remark"`
	Protocol              string                    `json:"protocol"`
	Core                  string                    `json:"core"`
	Port                  int                       `json:"port"`
	Network               string                    `json:"network"`
	Security              string                    `json:"security"`
	Enabled               bool                      `json:"enabled"`
	WsPath                string                    `json:"ws_path"`
	WsHost                string                    `json:"ws_host"`
	GrpcServiceName       string                    `json:"grpc_service_name"`
	RealityDest           string                    `json:"reality_dest"`
	RealityServerNames    string                    `json:"reality_server_names"`
	RealityShortID        string                    `json:"reality_short_id"`
	RealityPrivateKey     string                    `json:"reality_private_key"`
	RealityPublicKey      string                    `json:"reality_public_key"`
	SSMethod              string                    `json:"ss_method"`
	TLSCertFile           string                    `json:"tls_cert_file"`
	TLSKeyFile            string                    `json:"tls_key_file"`
	TLSSNI                string                    `json:"tls_sni"`
	TLSFingerprint        string                    `json:"tls_fingerprint"`
	TLSALPN               string                    `json:"tls_alpn"`
	XHTTPPath             string                    `json:"xhttp_path"`
	XHTTPMode             string                    `json:"xhttp_mode"`
	Hy2UpMbps             int                       `json:"hy2_up_mbps"`
	Hy2DownMbps           int                       `json:"hy2_down_mbps"`
	Hy2Obfs               string                    `json:"hy2_obfs"`
	Hy2ObfsPassword       string                    `json:"hy2_obfs_password"`
	Hy2MPort              string                    `json:"hy2_mport"`
	TuicCongestionControl string                    `json:"tuic_congestion_control"`
	TuicZeroRTT           bool                      `json:"tuic_zero_rtt"`
	WgPrivateKey          string                    `json:"wg_private_key"`
	WgAddress             string                    `json:"wg_address"`
	WgPeerPublicKey       string                    `json:"wg_peer_public_key"`
	WgAllowedIPs          string                    `json:"wg_allowed_ips"`
	WgEndpoint            string                    `json:"wg_endpoint"`
	WgPresharedKey        string                    `json:"wg_preshared_key"`
	WgMTU                 int                       `json:"wg_mtu"`
	ShadowTLSVersion      int                       `json:"shadowtls_version"`
	ShadowTLSPassword     string                    `json:"shadowtls_password"`
	Clients               []validationClientHashKey `json:"clients"`
}

type validationClientHashKey struct {
	ID           int64  `json:"id"`
	InboundID    int64  `json:"inbound_id"`
	UUID         string `json:"uuid"`
	CredentialID string `json:"credential_id"`
	Password     string `json:"password"`
	StatsKey     string `json:"stats_key"`
	Email        string `json:"email"`
	Enabled      bool   `json:"enabled"`
}

type validationOutboundHashKey struct {
	ID             int64    `json:"id"`
	Tag            string   `json:"tag"`
	Remark         string   `json:"remark"`
	Protocol       string   `json:"protocol"`
	Address        string   `json:"address"`
	Port           int      `json:"port"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	SupportedCores []string `json:"supported_cores"`
	Enabled        bool     `json:"enabled"`
	Sort           int      `json:"sort"`
}

type validationRoutingRuleHashKey struct {
	ID          int64  `json:"id"`
	InboundID   int64  `json:"inbound_id"`
	InboundTag  string `json:"inbound_tag"`
	ClientID    int64  `json:"client_id"`
	ClientEmail string `json:"client_email"`
	OutboundID  int64  `json:"outbound_id"`
	OutboundTag string `json:"outbound_tag"`
	Domain      string `json:"domain"`
	IP          string `json:"ip"`
	RuleSet     string `json:"rule_set"`
	Protocol    string `json:"protocol"`
	Enabled     bool   `json:"enabled"`
	Sort        int    `json:"sort"`
}

func (s *Store) validationInboundKeys(ctx context.Context) ([]validationInboundHashKey, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, uuid, remark, protocol, core, port, network, security, enabled,
  ws_path, ws_host, grpc_service_name, reality_dest, reality_server_names, reality_short_id, reality_private_key, reality_public_key, ss_method,
  tls_cert_file, tls_key_file, tls_sni, tls_fingerprint, tls_alpn, xhttp_path, xhttp_mode,
  hy2_up_mbps, hy2_down_mbps, hy2_obfs, hy2_obfs_password, hy2_mport,
  tuic_congestion_control, tuic_zero_rtt,
  wg_private_key, wg_address, wg_peer_public_key, wg_allowed_ips, wg_endpoint, wg_preshared_key, wg_mtu,
  shadowtls_version, shadowtls_password
FROM inbounds
ORDER BY id ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []validationInboundHashKey{}
	byID := map[int64]int{}
	for rows.Next() {
		var key validationInboundHashKey
		var enabled, tuicZeroRTT int
		if err := rows.Scan(&key.ID, &key.UUID, &key.Remark, &key.Protocol, &key.Core, &key.Port, &key.Network, &key.Security, &enabled,
			&key.WsPath, &key.WsHost, &key.GrpcServiceName, &key.RealityDest, &key.RealityServerNames, &key.RealityShortID, &key.RealityPrivateKey, &key.RealityPublicKey, &key.SSMethod,
			&key.TLSCertFile, &key.TLSKeyFile, &key.TLSSNI, &key.TLSFingerprint, &key.TLSALPN, &key.XHTTPPath, &key.XHTTPMode,
			&key.Hy2UpMbps, &key.Hy2DownMbps, &key.Hy2Obfs, &key.Hy2ObfsPassword, &key.Hy2MPort,
			&key.TuicCongestionControl, &tuicZeroRTT,
			&key.WgPrivateKey, &key.WgAddress, &key.WgPeerPublicKey, &key.WgAllowedIPs, &key.WgEndpoint, &key.WgPresharedKey, &key.WgMTU,
			&key.ShadowTLSVersion, &key.ShadowTLSPassword); err != nil {
			return nil, err
		}
		key.Enabled = enabled != 0
		key.TuicZeroRTT = tuicZeroRTT != 0
		if key.Core == "" {
			key.Core = InferInboundCore(key.Protocol)
		}
		key.Clients = []validationClientHashKey{}
		byID[key.ID] = len(keys)
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	clientRows, err := s.db.QueryContext(ctx, `
SELECT id, inbound_id, uuid, credential_id, password, stats_key, email, enabled
FROM clients
ORDER BY id ASC
`)
	if err != nil {
		return nil, err
	}
	defer clientRows.Close()
	for clientRows.Next() {
		var client validationClientHashKey
		var enabled int
		if err := clientRows.Scan(&client.ID, &client.InboundID, &client.UUID, &client.CredentialID, &client.Password, &client.StatsKey, &client.Email, &enabled); err != nil {
			return nil, err
		}
		client.Enabled = enabled != 0
		if idx, ok := byID[client.InboundID]; ok {
			keys[idx].Clients = append(keys[idx].Clients, client)
		}
	}
	return keys, clientRows.Err()
}

func (s *Store) validationOutboundKeys(ctx context.Context) ([]validationOutboundHashKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, tag, remark, protocol, address, port, username, password, enabled, sort FROM outbounds ORDER BY sort ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []validationOutboundHashKey{}
	for rows.Next() {
		var key validationOutboundHashKey
		var enabled int
		if err := rows.Scan(&key.ID, &key.Tag, &key.Remark, &key.Protocol, &key.Address, &key.Port, &key.Username, &key.Password, &enabled, &key.Sort); err != nil {
			return nil, err
		}
		key.Enabled = enabled != 0
		key.SupportedCores = OutboundProtocolSupportedCores(key.Protocol)
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) validationRoutingRuleKeys(ctx context.Context) ([]validationRoutingRuleHashKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, inbound_id, inbound_tag, client_id, client_email, outbound_id, outbound_tag, domain, ip, rule_set, protocol, enabled, sort FROM routing_rules ORDER BY sort ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []validationRoutingRuleHashKey{}
	for rows.Next() {
		var key validationRoutingRuleHashKey
		var inboundID, clientID sql.NullInt64
		var enabled int
		if err := rows.Scan(&key.ID, &inboundID, &key.InboundTag, &clientID, &key.ClientEmail, &key.OutboundID, &key.OutboundTag, &key.Domain, &key.IP, &key.RuleSet, &key.Protocol, &enabled, &key.Sort); err != nil {
			return nil, err
		}
		if inboundID.Valid {
			key.InboundID = inboundID.Int64
		}
		if clientID.Valid {
			key.ClientID = clientID.Int64
		}
		key.Enabled = enabled != 0
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) InboundExists(ctx context.Context, id int64) (bool, error) {
	if id <= 0 {
		return false, nil
	}
	var found int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM inbounds WHERE id=? LIMIT 1`, id).Scan(&found); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *Store) FindInboundByPort(ctx context.Context, port int, excludeID int64) (Inbound, bool, error) {
	if port <= 0 {
		return Inbound{}, false, nil
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, uuid, remark, protocol, core, port, network, security, enabled
FROM inbounds
WHERE port=? AND id<>?
ORDER BY id ASC
LIMIT 1
`, port, excludeID)
	var inbound Inbound
	var enabled int
	if err := row.Scan(&inbound.ID, &inbound.UUID, &inbound.Remark, &inbound.Protocol, &inbound.Core, &inbound.Port, &inbound.Network, &inbound.Security, &enabled); err != nil {
		if err == sql.ErrNoRows {
			return Inbound{}, false, nil
		}
		return Inbound{}, false, err
	}
	inbound.Enabled = enabled != 0
	if inbound.Core == "" {
		inbound.Core = InferInboundCore(inbound.Protocol)
	}
	inbound.Clients = []Client{}
	return inbound, true, nil
}

func (s *Store) allocateInboundPort(ctx context.Context, excludeID int64) (int, error) {
	portCount := autoInboundPortMax - autoInboundPortMin + 1
	offset, err := rand.Int(rand.Reader, big.NewInt(int64(portCount)))
	if err != nil {
		return 0, err
	}
	start := int(offset.Int64())
	for step := 0; step < portCount; step++ {
		port := autoInboundPortMin + (start+step)%portCount
		if _, ok, err := s.FindInboundByPort(ctx, port, excludeID); err != nil {
			return 0, err
		} else if ok {
			continue
		}
		if !inboundPortAvailable(port) {
			continue
		}
		return port, nil
	}
	return 0, fmt.Errorf("no available inbound port in range %d-%d", autoInboundPortMin, autoInboundPortMax)
}

func inboundPortAvailable(port int) bool {
	tcpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	defer tcpListener.Close()
	udpConn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = udpConn.Close()
	return true
}
