package cert

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/paths"
)

const (
	CodePreflightFailed       = "preflight_failed"
	CodeDomainNotResolved     = "domain_not_resolved"
	CodeHTTP01PortUnavailable = "http_01_port_unavailable"
	CodeCertDirNotWritable    = "cert_dir_not_writable"
	CodeACMEIssueFailed       = "acme_issue_failed"
	CodeInvalidDomain         = "invalid_domain"
	CodeInvalidEmail          = "invalid_email"
	CodeInvalidCertificate    = "invalid_certificate"
	CodePrivateKeyMismatch    = "certificate_key_mismatch"
	CodeCertificateNotFound   = "certificate_not_found"
	CodeInboundNotFound       = "inbound_not_found"
	CodeConfirmationRequired  = "confirmation_required"
)

var validDomain = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

type Store interface {
	ListCertificates(ctx context.Context) ([]db.Certificate, error)
	GetCertificate(ctx context.Context, id int64) (db.Certificate, error)
	UpsertCertificate(ctx context.Context, params db.UpsertCertificateParams) (db.Certificate, error)
	UpdateCertificateStatus(ctx context.Context, id int64, status, lastError, lastRenewed string) error
	DeleteCertificate(ctx context.Context, id int64) error
	ListCertificateOperations(ctx context.Context, certificateID int64, limit int) ([]db.CertificateOperation, error)
	RecordCertificateOperation(ctx context.Context, op db.CertificateOperation) (db.CertificateOperation, error)
	ListInbounds(ctx context.Context) ([]db.Inbound, error)
	ApplyCertificateToInbounds(ctx context.Context, cert db.Certificate, inboundIDs []int64) ([]db.Inbound, error)
}

type Issuer interface {
	Issue(ctx context.Context, req IssueRequest, certPath, keyPath string) (IssueResult, error)
}

type Service struct {
	Store     Store
	CertDir   string
	Issuer    Issuer
	Now       func() time.Time
	LookupIP  func(context.Context, string) ([]net.IP, error)
	ListenTCP func(network, address string) (net.Listener, error)
}

var assetWriteLocks sync.Map

type IssueRequest struct {
	Domains []string `json:"domains"`
	Domain  string   `json:"domain,omitempty"`
	Email   string   `json:"email"`
	Method  string   `json:"method,omitempty"`
}

type IssueResult struct {
	CertPEM []byte
	KeyPEM  []byte
}

type ImportRequest struct {
	Name      string `json:"name"`
	Fullchain string `json:"fullchain"`
	Key       string `json:"private_key"`
}

type ApplyRequest struct {
	CertificateID int64   `json:"certificate_id"`
	InboundIDs    []int64 `json:"inbound_ids"`
}

type RenewResult struct {
	Checked []db.Certificate `json:"checked"`
	Renewed []db.Certificate `json:"renewed"`
	Failed  []db.Certificate `json:"failed"`
}

type PreflightCheck struct {
	Code    string `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type PreflightResult struct {
	OK     bool             `json:"ok"`
	Checks []PreflightCheck `json:"checks"`
}

type StatusResponse struct {
	Domain   string `json:"domain"`
	Email    string `json:"email"`
	Issued   bool   `json:"issued"`
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

type Error struct {
	Code      string
	Detail    string
	Preflight *PreflightResult
}

func (e Error) Error() string {
	if e.Detail != "" {
		return e.Code + ": " + e.Detail
	}
	return e.Code
}

func (e Error) ServiceCode() string   { return e.Code }
func (e Error) ServiceDetail() string { return e.Detail }
func (e Error) ServiceFields() map[string]interface{} {
	if e.Preflight == nil {
		return nil
	}
	return map[string]interface{}{"preflight": e.Preflight}
}

func (s Service) List(ctx context.Context) ([]db.Certificate, error) {
	if s.Store == nil {
		return []db.Certificate{}, nil
	}
	certs, err := s.Store.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}
	for i := range certs {
		certs[i].Status = s.statusFor(certs[i])
	}
	return certs, nil
}

func (s Service) Get(ctx context.Context, id int64) (db.Certificate, error) {
	if s.Store == nil {
		return db.Certificate{}, Error{Code: "store_unavailable"}
	}
	cert, err := s.Store.GetCertificate(ctx, id)
	if err != nil {
		return db.Certificate{}, Error{Code: CodeCertificateNotFound, Detail: err.Error()}
	}
	cert.Status = s.statusFor(cert)
	return cert, nil
}

func (s Service) Status(ctx context.Context) StatusResponse {
	certs, err := s.List(ctx)
	if err != nil || len(certs) == 0 {
		return StatusResponse{}
	}
	sort.SliceStable(certs, func(i, j int) bool { return certTime(certs[i].NotAfter).After(certTime(certs[j].NotAfter)) })
	cert := certs[0]
	domain := ""
	if len(cert.Domains) > 0 {
		domain = cert.Domains[0]
	}
	return StatusResponse{Domain: domain, Email: cert.IssueEmail, Issued: cert.Status == db.CertStatusIssued || cert.Status == db.CertStatusExpiringSoon, CertPath: cert.CertPath, KeyPath: cert.KeyPath}
}

func (s Service) Preflight(ctx context.Context, req IssueRequest) (PreflightResult, error) {
	result := PreflightResult{OK: true}
	add := func(code, status, detail string) {
		if status == "failed" {
			result.OK = false
		}
		result.Checks = append(result.Checks, PreflightCheck{Code: code, Status: status, Detail: detail})
	}
	domains, err := normalizeDomains(req)
	if err != nil {
		add(errorCode(err), "failed", err.Error())
		return result, err
	}
	if err := validateEmail(req.Email); err != nil {
		add(errorCode(err), "failed", err.Error())
		return result, err
	}
	add("request_valid", "ok", "")
	for _, domain := range domains {
		ips, err := s.lookupIP(ctx, domain)
		if err != nil || len(ips) == 0 {
			add(CodeDomainNotResolved, "failed", fmt.Sprintf("%s: %v", domain, err))
		} else {
			add("domain_resolved", "ok", domain)
		}
	}
	ln, err := s.listenTCP("tcp", ":80")
	if err != nil {
		add(CodeHTTP01PortUnavailable, "failed", err.Error())
	} else {
		_ = ln.Close()
		add("http_01_port_available", "ok", "")
	}
	if err := s.ensureCertDirWritable(); err != nil {
		add(CodeCertDirNotWritable, "failed", err.Error())
	} else {
		add("cert_dir_writable", "ok", s.certDir())
	}
	add("core_apply_required", "warning", "证书应用到入站后会重新生成并重载对应核心配置")
	return result, nil
}

func (s Service) Issue(ctx context.Context, req IssueRequest) (db.Certificate, PreflightResult, error) {
	if s.Store == nil {
		return db.Certificate{}, PreflightResult{}, Error{Code: "store_unavailable"}
	}
	preflight, err := s.Preflight(ctx, req)
	if err != nil || !preflight.OK {
		code := CodePreflightFailed
		detail := "certificate preflight failed"
		if err != nil {
			code = errorCode(err)
			detail = errorDetail(err)
		}
		_ = s.record(ctx, 0, "issue", "failed", code, "preflight failed", detail)
		if err != nil {
			if serviceErr, ok := err.(Error); ok {
				serviceErr.Preflight = &preflight
				return db.Certificate{}, preflight, serviceErr
			}
			return db.Certificate{}, preflight, err
		}
		return db.Certificate{}, preflight, Error{Code: CodePreflightFailed, Detail: detail, Preflight: &preflight}
	}
	domains, _ := normalizeDomains(req)
	name := domains[0]
	certPath, keyPath := s.assetPaths(name)
	existing, hasExisting, err := s.existingAssetCertificate(ctx, certPath, keyPath)
	if err != nil {
		return db.Certificate{}, preflight, Error{Code: "list_certificates_failed", Detail: err.Error()}
	}
	certID := int64(0)
	if hasExisting {
		certID = existing.ID
		certPath = existing.CertPath
		keyPath = existing.KeyPath
	}
	_ = s.record(ctx, certID, "issue", "pending", "", "certificate issue started", strings.Join(domains, ","))
	issuer := s.issuer()
	method := challengeMethod(req.Method)
	directoryURL := issuerDirectoryURL(issuer)
	issued, err := issuer.Issue(ctx, IssueRequest{Domains: domains, Email: strings.TrimSpace(req.Email), Method: method}, certPath, keyPath)
	if err != nil {
		_ = s.record(ctx, certID, "issue", "failed", CodeACMEIssueFailed, "ACME issue failed", err.Error())
		return db.Certificate{}, preflight, Error{Code: CodeACMEIssueFailed, Detail: err.Error()}
	}
	certPEM := issued.CertPEM
	keyPEM := issued.KeyPEM
	if len(certPEM) == 0 {
		var readErr error
		certPEM, readErr = os.ReadFile(certPath)
		if readErr != nil {
			return db.Certificate{}, preflight, Error{Code: "read_issued_cert_failed", Detail: readErr.Error()}
		}
	}
	if len(keyPEM) == 0 {
		var readErr error
		keyPEM, readErr = os.ReadFile(keyPath)
		if readErr != nil {
			return db.Certificate{}, preflight, Error{Code: "read_issued_key_failed", Detail: readErr.Error()}
		}
	}
	meta, err := parseCertificatePair(certPEM, keyPEM)
	if err != nil {
		_ = s.record(ctx, certID, "issue", "failed", errorCode(err), "issued certificate validation failed", err.Error())
		return db.Certificate{}, preflight, err
	}
	if err := s.writeAssetFiles(certPath, keyPath, certPEM, keyPEM); err != nil {
		return db.Certificate{}, preflight, Error{Code: CodeCertDirNotWritable, Detail: err.Error()}
	}
	cert, err := s.Store.UpsertCertificate(ctx, db.UpsertCertificateParams{
		ID:               certID,
		Name:             name,
		Source:           db.CertSourceACME,
		Status:           s.statusForMeta(meta),
		Domains:          meta.Domains,
		CertPath:         certPath,
		KeyPath:          keyPath,
		NotBefore:        meta.NotBefore.Format(time.RFC3339),
		NotAfter:         meta.NotAfter.Format(time.RFC3339),
		Fingerprint:      meta.Fingerprint,
		Serial:           meta.Serial,
		IssueEmail:       strings.TrimSpace(req.Email),
		ACMEDirectoryURL: directoryURL,
		ChallengeMethod:  method,
	})
	if err != nil {
		return db.Certificate{}, preflight, Error{Code: "write_certificate_failed", Detail: err.Error()}
	}
	_ = s.record(ctx, cert.ID, "issue", "success", "", "certificate issued", "")
	return cert, preflight, nil
}

func (s Service) Import(ctx context.Context, req ImportRequest) (db.Certificate, error) {
	if s.Store == nil {
		return db.Certificate{}, Error{Code: "store_unavailable"}
	}
	meta, err := parseCertificatePair([]byte(req.Fullchain), []byte(req.Key))
	if err != nil {
		_ = s.record(ctx, 0, "import", "failed", errorCode(err), "certificate import failed", err.Error())
		return db.Certificate{}, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" && len(meta.Domains) > 0 {
		name = meta.Domains[0]
	}
	certPath, keyPath := s.assetPaths(name)
	existing, hasExisting, err := s.existingAssetCertificate(ctx, certPath, keyPath)
	if err != nil {
		return db.Certificate{}, Error{Code: "list_certificates_failed", Detail: err.Error()}
	}
	certID := int64(0)
	if hasExisting {
		certID = existing.ID
		certPath = existing.CertPath
		keyPath = existing.KeyPath
	}
	if err := s.writeAssetFiles(certPath, keyPath, []byte(req.Fullchain), []byte(req.Key)); err != nil {
		_ = s.record(ctx, certID, "import", "failed", CodeCertDirNotWritable, "write imported certificate failed", err.Error())
		return db.Certificate{}, Error{Code: CodeCertDirNotWritable, Detail: err.Error()}
	}
	cert, err := s.Store.UpsertCertificate(ctx, db.UpsertCertificateParams{
		ID:          certID,
		Name:        name,
		Source:      db.CertSourceImport,
		Status:      s.statusForMeta(meta),
		Domains:     meta.Domains,
		CertPath:    certPath,
		KeyPath:     keyPath,
		NotBefore:   meta.NotBefore.Format(time.RFC3339),
		NotAfter:    meta.NotAfter.Format(time.RFC3339),
		Fingerprint: meta.Fingerprint,
		Serial:      meta.Serial,
	})
	if err != nil {
		return db.Certificate{}, Error{Code: "write_certificate_failed", Detail: err.Error()}
	}
	_ = s.record(ctx, cert.ID, "import", "success", "", "certificate imported", "")
	return cert, nil
}

func (s Service) Apply(ctx context.Context, req ApplyRequest) ([]db.Inbound, []string, error) {
	cert, err := s.Get(ctx, req.CertificateID)
	if err != nil {
		_ = s.record(ctx, req.CertificateID, "apply", "failed", errorCode(err), "certificate apply failed", err.Error())
		return nil, nil, err
	}
	if len(req.InboundIDs) == 0 {
		return nil, nil, Error{Code: "inbound_ids_required"}
	}
	updated, err := s.Store.ApplyCertificateToInbounds(ctx, cert, req.InboundIDs)
	if err != nil {
		code := CodeInboundNotFound
		if strings.Contains(err.Error(), "not a TLS inbound") {
			code = "inbound_not_tls"
		}
		_ = s.record(ctx, cert.ID, "apply", "failed", code, "certificate apply failed", err.Error())
		return nil, nil, Error{Code: code, Detail: err.Error()}
	}
	warnings := []string{}
	if cert.Status == db.CertStatusExpired {
		warnings = append(warnings, "certificate_expired")
	}
	if cert.Status == db.CertStatusExpiringSoon {
		warnings = append(warnings, "certificate_expiring_soon")
	}
	_ = s.record(ctx, cert.ID, "apply", "success", "", "certificate applied", fmt.Sprintf("%d inbounds", len(updated)))
	return updated, warnings, nil
}

func (s Service) Delete(ctx context.Context, id int64) error {
	cert, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if cert.UsageCount > 0 {
		return Error{Code: "certificate_in_use", Detail: fmt.Sprintf("%d inbound(s) still use this certificate", cert.UsageCount)}
	}
	if err := s.Store.DeleteCertificate(ctx, id); err != nil {
		return Error{Code: CodeCertificateNotFound, Detail: err.Error()}
	}
	_ = s.record(ctx, id, "delete", "success", "", "certificate deleted", "")
	return nil
}

func (s Service) Operations(ctx context.Context, certificateID int64, limit int) ([]db.CertificateOperation, error) {
	if s.Store == nil {
		return []db.CertificateOperation{}, nil
	}
	return s.Store.ListCertificateOperations(ctx, certificateID, limit)
}

func (s Service) RenewDue(ctx context.Context, days int) (RenewResult, error) {
	if days <= 0 {
		days = 30
	}
	certs, err := s.List(ctx)
	if err != nil {
		return RenewResult{}, err
	}
	result := RenewResult{}
	for _, cert := range certs {
		if !s.ShouldRenew(cert, days) {
			continue
		}
		result.Checked = append(result.Checked, cert)
		if cert.Source != db.CertSourceACME {
			cert.LastError = "certificate is not ACME-managed"
			result.Failed = append(result.Failed, cert)
			_ = s.Store.UpdateCertificateStatus(ctx, cert.ID, cert.Status, cert.LastError, cert.LastRenewed)
			_ = s.record(ctx, cert.ID, "renew", "failed", "renew_unsupported_source", "renew skipped", cert.LastError)
			continue
		}
		renewed, err := s.renewOne(ctx, cert)
		if err != nil {
			cert.LastError = err.Error()
			result.Failed = append(result.Failed, cert)
			_ = s.Store.UpdateCertificateStatus(ctx, cert.ID, cert.Status, cert.LastError, cert.LastRenewed)
			_ = s.record(ctx, cert.ID, "renew", "failed", errorCode(err), "renew failed", err.Error())
			continue
		}
		result.Renewed = append(result.Renewed, renewed)
	}
	return result, nil
}

func (s Service) ShouldRenew(cert db.Certificate, days int) bool {
	if cert.Source != db.CertSourceACME {
		return false
	}
	notAfter := certTime(cert.NotAfter)
	if notAfter.IsZero() {
		return false
	}
	return s.now().Add(time.Duration(days) * 24 * time.Hour).After(notAfter)
}

func (s Service) renewOne(ctx context.Context, cert db.Certificate) (db.Certificate, error) {
	if len(cert.Domains) == 0 {
		return db.Certificate{}, Error{Code: "certificate_domains_missing"}
	}
	method := challengeMethod(cert.ChallengeMethod)
	directoryURL := strings.TrimSpace(cert.ACMEDirectoryURL)
	issuer := s.issuerForDirectory(directoryURL)
	issued, err := issuer.Issue(ctx, IssueRequest{Domains: cert.Domains, Email: strings.TrimSpace(cert.IssueEmail), Method: method}, cert.CertPath, cert.KeyPath)
	if err != nil {
		return db.Certificate{}, Error{Code: CodeACMEIssueFailed, Detail: err.Error()}
	}
	certPEM, keyPEM := issued.CertPEM, issued.KeyPEM
	if len(certPEM) == 0 {
		certPEM, err = os.ReadFile(cert.CertPath)
		if err != nil {
			return db.Certificate{}, err
		}
	}
	if len(keyPEM) == 0 {
		keyPEM, err = os.ReadFile(cert.KeyPath)
		if err != nil {
			return db.Certificate{}, err
		}
	}
	meta, err := parseCertificatePair(certPEM, keyPEM)
	if err != nil {
		return db.Certificate{}, err
	}
	if err := s.writeAssetFiles(cert.CertPath, cert.KeyPath, certPEM, keyPEM); err != nil {
		return db.Certificate{}, Error{Code: CodeCertDirNotWritable, Detail: err.Error()}
	}
	updated, err := s.Store.UpsertCertificate(ctx, db.UpsertCertificateParams{
		ID:               cert.ID,
		Name:             cert.Name,
		Source:           db.CertSourceACME,
		Status:           s.statusForMeta(meta),
		Domains:          meta.Domains,
		CertPath:         cert.CertPath,
		KeyPath:          cert.KeyPath,
		NotBefore:        meta.NotBefore.Format(time.RFC3339),
		NotAfter:         meta.NotAfter.Format(time.RFC3339),
		Fingerprint:      meta.Fingerprint,
		Serial:           meta.Serial,
		IssueEmail:       cert.IssueEmail,
		ACMEDirectoryURL: directoryURL,
		ChallengeMethod:  method,
		LastRenewed:      s.now().Format(time.RFC3339),
	})
	if err != nil {
		return db.Certificate{}, err
	}
	_ = s.record(ctx, cert.ID, "renew", "success", "", "certificate renewed", "")
	return updated, nil
}

func (s Service) statusFor(cert db.Certificate) string {
	status := strings.TrimSpace(cert.Status)
	if status == db.CertStatusFailed || status == db.CertStatusPending {
		return status
	}
	notAfter := certTime(cert.NotAfter)
	if notAfter.IsZero() {
		if status != "" {
			return status
		}
		return db.CertStatusFailed
	}
	if s.now().After(notAfter) {
		return db.CertStatusExpired
	}
	if s.now().Add(30 * 24 * time.Hour).After(notAfter) {
		return db.CertStatusExpiringSoon
	}
	return db.CertStatusIssued
}

func (s Service) statusForMeta(meta certificateMeta) string {
	return s.statusFor(db.Certificate{Status: db.CertStatusIssued, NotAfter: meta.NotAfter.Format(time.RFC3339)})
}

func (s Service) certDir() string {
	if strings.TrimSpace(s.CertDir) != "" {
		return strings.TrimSpace(s.CertDir)
	}
	return paths.CertDir
}

func (s Service) existingAssetCertificate(ctx context.Context, certPath, keyPath string) (db.Certificate, bool, error) {
	if s.Store == nil {
		return db.Certificate{}, false, nil
	}
	certs, err := s.Store.ListCertificates(ctx)
	if err != nil {
		return db.Certificate{}, false, err
	}
	for _, cert := range certs {
		if cert.CertPath == certPath && cert.KeyPath == keyPath {
			return cert, true, nil
		}
	}
	legacyKeyPath := legacyPrivateKeyPath(keyPath)
	if legacyKeyPath != "" {
		for _, cert := range certs {
			if cert.CertPath == certPath && cert.KeyPath == legacyKeyPath {
				return cert, true, nil
			}
		}
	}
	return db.Certificate{}, false, nil
}

func (s Service) assetPaths(name string) (string, string) {
	slug := sanitizeAssetName(name)
	dir := filepath.Join(s.certDir(), slug)
	return filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.key")
}

func legacyPrivateKeyPath(keyPath string) string {
	if filepath.Base(keyPath) != "privkey.key" {
		return ""
	}
	return filepath.Join(filepath.Dir(keyPath), "privkey.pem")
}

func (s Service) ensureCertDirWritable() error {
	dir := s.certDir()
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Remove(name)
}

func (s Service) writeAssetFiles(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0750); err != nil {
		return err
	}
	lockKey := filepath.Dir(certPath)
	lockValue, _ := assetWriteLocks.LoadOrStore(lockKey, &sync.Mutex{})
	mu := lockValue.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()
	if err := writeFileAtomic(certPath, certPEM, 0640); err != nil {
		return err
	}
	return writeFileAtomic(keyPath, keyPEM, 0600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (s Service) issuer() Issuer {
	if s.Issuer != nil {
		return s.Issuer
	}
	return NativeHTTP01Issuer{}
}

func (s Service) issuerForDirectory(directoryURL string) Issuer {
	if s.Issuer != nil {
		return s.Issuer
	}
	return NativeHTTP01Issuer{DirectoryURL: directoryURL}
}

func (s Service) lookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	if s.LookupIP != nil {
		return s.LookupIP(ctx, domain)
	}
	var resolver net.Resolver
	return resolver.LookupIP(ctx, "ip", domain)
}

func (s Service) listenTCP(network, address string) (net.Listener, error) {
	if s.ListenTCP != nil {
		return s.ListenTCP(network, address)
	}
	return net.Listen(network, address)
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s Service) record(ctx context.Context, certID int64, typ, status, code, message, detail string) error {
	if s.Store == nil {
		return nil
	}
	_, err := s.Store.RecordCertificateOperation(ctx, db.CertificateOperation{CertificateID: certID, Type: typ, Status: status, Code: code, Message: message, Detail: detail})
	return err
}

func challengeMethod(method string) string {
	method = strings.TrimSpace(method)
	if method == "" {
		return "http-01"
	}
	return method
}

type directoryIssuer interface {
	ACMEDirectory() string
}

func issuerDirectoryURL(issuer Issuer) string {
	if issuer == nil {
		return ""
	}
	if d, ok := issuer.(directoryIssuer); ok {
		return d.ACMEDirectory()
	}
	return ""
}

type certificateMeta struct {
	Domains     []string
	NotBefore   time.Time
	NotAfter    time.Time
	Fingerprint string
	Serial      string
}

func parseCertificatePair(certPEM, keyPEM []byte) (certificateMeta, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return certificateMeta{}, Error{Code: CodeInvalidCertificate, Detail: "missing PEM certificate block"}
	}
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return certificateMeta{}, Error{Code: CodeInvalidCertificate, Detail: err.Error()}
	}
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		return certificateMeta{}, Error{Code: CodeInvalidCertificate, Detail: err.Error()}
	}
	if !publicKeysEqual(leaf.PublicKey, key.Public()) {
		return certificateMeta{}, Error{Code: CodePrivateKeyMismatch}
	}
	domains := append([]string{}, leaf.DNSNames...)
	if len(domains) == 0 && leaf.Subject.CommonName != "" {
		domains = append(domains, leaf.Subject.CommonName)
	}
	for i := range domains {
		domains[i] = strings.ToLower(strings.TrimSpace(domains[i]))
	}
	sum := sha256.Sum256(certBlock.Bytes)
	return certificateMeta{
		Domains:     uniqueStrings(domains),
		NotBefore:   leaf.NotBefore.UTC(),
		NotAfter:    leaf.NotAfter.UTC(),
		Fingerprint: strings.ToUpper(hex.EncodeToString(sum[:])),
		Serial:      strings.ToUpper(leaf.SerialNumber.Text(16)),
	}, nil
}

func parsePrivateKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("missing PEM private key block")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key type")
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	aBytes, aErr := x509.MarshalPKIXPublicKey(a)
	bBytes, bErr := x509.MarshalPKIXPublicKey(b)
	return aErr == nil && bErr == nil && string(aBytes) == string(bBytes)
}

func normalizeDomains(req IssueRequest) ([]string, error) {
	domains := append([]string{}, req.Domains...)
	if strings.TrimSpace(req.Domain) != "" {
		domains = append(domains, req.Domain)
	}
	domains = uniqueStrings(domains)
	if len(domains) == 0 {
		return nil, Error{Code: "domain_required"}
	}
	for _, domain := range domains {
		if !validDomain.MatchString(domain) {
			return nil, Error{Code: CodeInvalidDomain, Detail: domain}
		}
	}
	return domains, nil
}

func validateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return Error{Code: "email_required"}
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return Error{Code: CodeInvalidEmail, Detail: err.Error()}
	}
	return nil
}

func uniqueStrings(values []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func sanitizeAssetName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return "certificate"
		}
		name = hex.EncodeToString(b)
	}
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), ".-")
}

func certTime(value string) time.Time {
	if strings.TrimSpace(value) == "" {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339, value)
	return t
}

func errorCode(err error) string {
	if err == nil {
		return ""
	}
	if serviceErr, ok := err.(Error); ok {
		return serviceErr.Code
	}
	return "request_failed"
}

func errorDetail(err error) string {
	if err == nil {
		return ""
	}
	if serviceErr, ok := err.(Error); ok {
		return serviceErr.Detail
	}
	return err.Error()
}
