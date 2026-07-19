package cert

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imzyb/MiGate/internal/db"
)

type memoryStore struct {
	certs     []db.Certificate
	ops       []db.CertificateOperation
	inbounds  []db.Inbound
	nextCert  int64
	nextOp    int64
	applyErr  error
	statusErr error
}

func (s *memoryStore) ListCertificates(ctx context.Context) ([]db.Certificate, error) {
	out := append([]db.Certificate(nil), s.certs...)
	for i := range out {
		for _, inbound := range s.inbounds {
			if inbound.TLSCertFile == out[i].CertPath && inbound.TLSKeyFile == out[i].KeyPath {
				out[i].UsageCount++
				out[i].Usages = append(out[i].Usages, inbound)
			}
		}
	}
	return out, nil
}

func (s *memoryStore) GetCertificate(ctx context.Context, id int64) (db.Certificate, error) {
	certs, _ := s.ListCertificates(ctx)
	for _, cert := range certs {
		if cert.ID == id {
			return cert, nil
		}
	}
	return db.Certificate{}, fmt.Errorf("certificate not found: %d", id)
}

func (s *memoryStore) UpsertCertificate(ctx context.Context, params db.UpsertCertificateParams) (db.Certificate, error) {
	if params.ID > 0 {
		for i := range s.certs {
			if s.certs[i].ID == params.ID {
				s.certs[i] = db.Certificate{ID: params.ID, Name: params.Name, Source: params.Source, Status: params.Status, Domains: params.Domains, CertPath: params.CertPath, KeyPath: params.KeyPath, NotBefore: params.NotBefore, NotAfter: params.NotAfter, Fingerprint: params.Fingerprint, Serial: params.Serial, IssueEmail: params.IssueEmail, ACMEDirectoryURL: params.ACMEDirectoryURL, ChallengeMethod: params.ChallengeMethod, LastError: params.LastError, LastRenewed: params.LastRenewed}
				return s.GetCertificate(ctx, params.ID)
			}
		}
		return db.Certificate{}, fmt.Errorf("certificate not found: %d", params.ID)
	}
	s.nextCert++
	cert := db.Certificate{ID: s.nextCert, Name: params.Name, Source: params.Source, Status: params.Status, Domains: params.Domains, CertPath: params.CertPath, KeyPath: params.KeyPath, NotBefore: params.NotBefore, NotAfter: params.NotAfter, Fingerprint: params.Fingerprint, Serial: params.Serial, IssueEmail: params.IssueEmail, ACMEDirectoryURL: params.ACMEDirectoryURL, ChallengeMethod: params.ChallengeMethod, LastError: params.LastError, LastRenewed: params.LastRenewed}
	s.certs = append(s.certs, cert)
	return cert, nil
}

func (s *memoryStore) UpdateCertificateStatus(ctx context.Context, id int64, status, lastError, lastRenewed string) error {
	if s.statusErr != nil {
		return s.statusErr
	}
	for i := range s.certs {
		if s.certs[i].ID == id {
			s.certs[i].Status = status
			s.certs[i].LastError = lastError
			s.certs[i].LastRenewed = lastRenewed
			return nil
		}
	}
	return fmt.Errorf("certificate not found: %d", id)
}

func (s *memoryStore) DeleteCertificate(ctx context.Context, id int64) error {
	for i := range s.certs {
		if s.certs[i].ID == id {
			s.certs = append(s.certs[:i], s.certs[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("certificate not found: %d", id)
}

func (s *memoryStore) ListCertificateOperations(ctx context.Context, certificateID int64, limit int) ([]db.CertificateOperation, error) {
	return append([]db.CertificateOperation(nil), s.ops...), nil
}

func (s *memoryStore) RecordCertificateOperation(ctx context.Context, op db.CertificateOperation) (db.CertificateOperation, error) {
	s.nextOp++
	op.ID = s.nextOp
	s.ops = append(s.ops, op)
	return op, nil
}

func (s *memoryStore) ListInbounds(ctx context.Context) ([]db.Inbound, error) {
	return append([]db.Inbound(nil), s.inbounds...), nil
}

func (s *memoryStore) ApplyCertificateToInbounds(ctx context.Context, cert db.Certificate, ids []int64) ([]db.Inbound, error) {
	if s.applyErr != nil {
		return nil, s.applyErr
	}
	updated := []db.Inbound{}
	for _, id := range ids {
		found := false
		for i := range s.inbounds {
			if s.inbounds[i].ID == id {
				found = true
				if db.NormalizeInboundSecurity(s.inbounds[i].Protocol, s.inbounds[i].Security) != "tls" {
					return nil, fmt.Errorf("inbound %d is not a TLS inbound", id)
				}
				s.inbounds[i].TLSCertFile = cert.CertPath
				s.inbounds[i].TLSKeyFile = cert.KeyPath
				if len(cert.Domains) > 0 {
					s.inbounds[i].TLSSNI = cert.Domains[0]
				}
				updated = append(updated, s.inbounds[i])
			}
		}
		if !found {
			return nil, fmt.Errorf("inbound not found: %d", id)
		}
	}
	return updated, nil
}

type stubIssuer struct {
	certPEM  []byte
	keyPEM   []byte
	err      error
	calls    int
	requests []IssueRequest
}

func (i *stubIssuer) Issue(ctx context.Context, req IssueRequest, certPath, keyPath string) (IssueResult, error) {
	i.calls++
	i.requests = append(i.requests, req)
	if i.err != nil {
		return IssueResult{}, i.err
	}
	return IssueResult{CertPEM: i.certPEM, KeyPEM: i.keyPEM}, nil
}

func TestPreflightReportsDomainPortAndDirChecks(t *testing.T) {
	service := Service{
		CertDir: t.TempDir(),
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
		ListenTCP: func(string, string) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	result, err := service.Preflight(context.Background(), IssueRequest{Domain: "example.com", Email: "admin@example.com"})
	if err != nil {
		t.Fatalf("Preflight returned error: %v", err)
	}
	if !result.OK {
		t.Fatalf("preflight should be ok: %#v", result)
	}
	if !hasCheck(result, "domain_resolved", "ok") || !hasCheck(result, "http_01_port_available", "ok") || !hasCheck(result, "cert_dir_writable", "ok") {
		t.Fatalf("missing expected checks: %#v", result.Checks)
	}
}

func TestPreflightReturnsStableFailureCodes(t *testing.T) {
	service := Service{
		CertDir: filepath.Join(t.TempDir(), "certs"),
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return nil, errors.New("no such host")
		},
		ListenTCP: func(string, string) (net.Listener, error) {
			return nil, errors.New("bind: address already in use")
		},
	}
	result, err := service.Preflight(context.Background(), IssueRequest{Domain: "example.com", Email: "admin@example.com"})
	if err != nil {
		t.Fatalf("Preflight should collect diagnostics without returning DNS/port errors: %v", err)
	}
	if result.OK || !hasCheck(result, CodeDomainNotResolved, "failed") || !hasCheck(result, CodeHTTP01PortUnavailable, "failed") {
		t.Fatalf("unexpected preflight: %#v", result)
	}
}

func TestImportCertificateValidatesAndStoresMetadata(t *testing.T) {
	certPEM, keyPEM, err := selfSignedPair([]string{"example.com", "www.example.com"}, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryStore{}
	service := Service{Store: store, CertDir: t.TempDir(), Now: fixedNow}
	cert, err := service.Import(context.Background(), ImportRequest{Name: "example", Fullchain: string(certPEM), Key: string(keyPEM)})
	if err != nil {
		t.Fatalf("Import returned error: %v", err)
	}
	if cert.Status != db.CertStatusIssued || cert.CertPath == "" || cert.KeyPath == "" || len(cert.Domains) != 2 || cert.Fingerprint == "" {
		t.Fatalf("unexpected cert: %#v", cert)
	}
	if filepath.Base(cert.KeyPath) != "privkey.key" {
		t.Fatalf("private key path = %q, want privkey.key suffix", cert.KeyPath)
	}
	if _, err := os.Stat(cert.CertPath); err != nil {
		t.Fatalf("cert file not written: %v", err)
	}
}

func TestImportCertificateWithSameAssetPathUpdatesExistingRecord(t *testing.T) {
	firstCert, firstKey, err := selfSignedPair([]string{"example.com"}, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	secondCert, secondKey, err := selfSignedPair([]string{"example.com"}, time.Now().Add(120*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryStore{}
	service := Service{Store: store, CertDir: t.TempDir(), Now: fixedNow}
	first, err := service.Import(context.Background(), ImportRequest{Name: "example.com", Fullchain: string(firstCert), Key: string(firstKey)})
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	second, err := service.Import(context.Background(), ImportRequest{Name: "example.com", Fullchain: string(secondCert), Key: string(secondKey)})
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if second.ID != first.ID || len(store.certs) != 1 {
		t.Fatalf("same asset import should update existing record, first=%#v second=%#v count=%d", first, second, len(store.certs))
	}
	if second.Fingerprint == first.Fingerprint || second.NotAfter == first.NotAfter {
		t.Fatalf("existing record metadata was not refreshed: first=%#v second=%#v", first, second)
	}
}

func TestImportCertificateReusesLegacyPEMKeyPathRecord(t *testing.T) {
	certPEM, keyPEM, err := selfSignedPair([]string{"example.com"}, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := &memoryStore{certs: []db.Certificate{{
		ID:       7,
		Name:     "example.com",
		Source:   db.CertSourceACME,
		Status:   db.CertStatusIssued,
		Domains:  []string{"example.com"},
		CertPath: filepath.Join(dir, "example.com", "fullchain.pem"),
		KeyPath:  filepath.Join(dir, "example.com", "privkey.pem"),
	}}}
	cert, err := (Service{Store: store, CertDir: dir, Now: fixedNow}).Import(context.Background(), ImportRequest{Name: "example.com", Fullchain: string(certPEM), Key: string(keyPEM)})
	if err != nil {
		t.Fatalf("import over legacy path: %v", err)
	}
	if cert.ID != 7 || len(store.certs) != 1 || filepath.Base(cert.KeyPath) != "privkey.pem" {
		t.Fatalf("legacy PEM key path record was not reused: cert=%#v count=%d", cert, len(store.certs))
	}
	if _, err := os.Stat(cert.KeyPath); err != nil {
		t.Fatalf("legacy key path was not written: %v", err)
	}
}

func TestImportRejectsMismatchedPrivateKey(t *testing.T) {
	certPEM, _, err := selfSignedPair([]string{"example.com"}, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey, err := selfSignedPair([]string{"other.example.com"}, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, err = (Service{Store: &memoryStore{}, CertDir: t.TempDir()}).Import(context.Background(), ImportRequest{Name: "bad", Fullchain: string(certPEM), Key: string(otherKey)})
	serviceErr, ok := err.(Error)
	if !ok || serviceErr.Code != CodePrivateKeyMismatch {
		t.Fatalf("error = %#v, want %s", err, CodePrivateKeyMismatch)
	}
}

func TestStatusAndRenewalDecision(t *testing.T) {
	now := time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC)
	service := Service{Now: func() time.Time { return now }}
	issued := db.Certificate{Source: db.CertSourceACME, Status: db.CertStatusIssued, NotAfter: now.Add(60 * 24 * time.Hour).Format(time.RFC3339)}
	soon := db.Certificate{Source: db.CertSourceACME, Status: db.CertStatusIssued, NotAfter: now.Add(10 * 24 * time.Hour).Format(time.RFC3339)}
	expired := db.Certificate{Source: db.CertSourceACME, Status: db.CertStatusIssued, NotAfter: now.Add(-time.Hour).Format(time.RFC3339)}
	if service.statusFor(issued) != db.CertStatusIssued || service.statusFor(soon) != db.CertStatusExpiringSoon || service.statusFor(expired) != db.CertStatusExpired {
		t.Fatalf("unexpected statuses: %s %s %s", service.statusFor(issued), service.statusFor(soon), service.statusFor(expired))
	}
	if service.ShouldRenew(issued, 30) || !service.ShouldRenew(soon, 30) {
		t.Fatalf("unexpected renewal decision")
	}
}

func TestStatusReturnsIssueEmail(t *testing.T) {
	now := fixedNow()
	store := &memoryStore{certs: []db.Certificate{{
		ID: 1, Source: db.CertSourceACME, Status: db.CertStatusIssued, Domains: []string{"example.com"}, IssueEmail: "ops@example.com",
		CertPath: "/cert.pem", KeyPath: "/key.key", NotAfter: now.Add(60 * 24 * time.Hour).Format(time.RFC3339),
	}}}
	status := (Service{Store: store, Now: func() time.Time { return now }}).Status(context.Background())
	if status.Email != "ops@example.com" || status.Domain != "example.com" || !status.Issued {
		t.Fatalf("unexpected status response: %#v", status)
	}
}

func TestWriteAssetFilesReplacesFilesAtomicallyAndLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "example.com", "fullchain.pem")
	keyPath := filepath.Join(dir, "example.com", "privkey.key")
	svc := Service{CertDir: dir}
	if err := svc.writeAssetFiles(certPath, keyPath, []byte("old-cert"), []byte("old-key")); err != nil {
		t.Fatalf("initial write: %v", err)
	}
	if err := svc.writeAssetFiles(certPath, keyPath, []byte("new-cert"), []byte("new-key")); err != nil {
		t.Fatalf("replacement write: %v", err)
	}
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(certData) != "new-cert" || string(keyData) != "new-key" {
		t.Fatalf("unexpected replacement contents cert=%q key=%q", certData, keyData)
	}
	entries, err := os.ReadDir(filepath.Dir(certPath))
	if err != nil {
		t.Fatalf("read cert dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".fullchain.pem-") || strings.HasPrefix(entry.Name(), ".privkey.key-") {
			t.Fatalf("temporary asset file left behind: %s", entry.Name())
		}
	}
}

func TestApplyCertificateToTLSInbounds(t *testing.T) {
	store := &memoryStore{
		certs: []db.Certificate{{ID: 1, Source: db.CertSourceImport, Status: db.CertStatusIssued, Domains: []string{"example.com"}, CertPath: "/etc/migate/certs/example/fullchain.pem", KeyPath: "/etc/migate/certs/example/privkey.pem"}},
		inbounds: []db.Inbound{
			{ID: 10, Protocol: "vless", Core: db.CoreXray, Security: "tls"},
			{ID: 11, Protocol: "hysteria2", Core: db.CoreSingbox, Security: "tls"},
		},
	}
	updated, warnings, err := (Service{Store: store, Now: fixedNow}).Apply(context.Background(), ApplyRequest{CertificateID: 1, InboundIDs: []int64{10, 11}})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if len(warnings) != 0 || len(updated) != 2 {
		t.Fatalf("unexpected apply result: updated=%#v warnings=%#v", updated, warnings)
	}
	for _, inbound := range updated {
		if !strings.Contains(inbound.TLSCertFile, "fullchain.pem") || inbound.TLSSNI != "example.com" {
			t.Fatalf("certificate not applied: %#v", inbound)
		}
	}
}

func TestIssueUsesIssuerAndRecordsCertificate(t *testing.T) {
	certPEM, keyPEM, err := selfSignedPair([]string{"example.com"}, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	issuer := &stubIssuer{certPEM: certPEM, keyPEM: keyPEM}
	store := &memoryStore{}
	service := Service{
		Store:   store,
		CertDir: t.TempDir(),
		Issuer:  issuer,
		Now:     fixedNow,
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
		ListenTCP: func(string, string) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	cert, preflight, err := service.Issue(context.Background(), IssueRequest{Domain: "example.com", Email: "admin@example.com"})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}
	if !preflight.OK || issuer.calls != 1 || cert.Source != db.CertSourceACME || cert.Status != db.CertStatusIssued {
		t.Fatalf("unexpected issue result: cert=%#v preflight=%#v calls=%d", cert, preflight, issuer.calls)
	}
	if cert.IssueEmail != "admin@example.com" || cert.ChallengeMethod != "http-01" {
		t.Fatalf("ACME metadata not stored: %#v", cert)
	}
}

func TestIssueWithSameAssetPathUpdatesExistingRecord(t *testing.T) {
	now := fixedNow()
	firstCert, firstKey, err := selfSignedPair([]string{"example.com"}, now.Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	secondCert, secondKey, err := selfSignedPair([]string{"example.com"}, now.Add(120*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	issuer := &stubIssuer{certPEM: firstCert, keyPEM: firstKey}
	store := &memoryStore{}
	service := Service{
		Store:   store,
		CertDir: t.TempDir(),
		Issuer:  issuer,
		Now:     fixedNow,
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
		ListenTCP: func(string, string) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	first, _, err := service.Issue(context.Background(), IssueRequest{Domain: "example.com", Email: "admin@example.com"})
	if err != nil {
		t.Fatalf("first issue: %v", err)
	}
	issuer.certPEM = secondCert
	issuer.keyPEM = secondKey
	second, _, err := service.Issue(context.Background(), IssueRequest{Domain: "example.com", Email: "admin@example.com"})
	if err != nil {
		t.Fatalf("second issue: %v", err)
	}
	if second.ID != first.ID || len(store.certs) != 1 {
		t.Fatalf("same asset issue should update existing record, first=%#v second=%#v count=%d", first, second, len(store.certs))
	}
	if second.Fingerprint == first.Fingerprint || second.NotAfter == first.NotAfter {
		t.Fatalf("existing issue metadata was not refreshed: first=%#v second=%#v", first, second)
	}
}

func TestIssueCertificateReusesLegacyPEMKeyPathRecord(t *testing.T) {
	now := fixedNow()
	certPEM, keyPEM, err := selfSignedPair([]string{"example.com"}, now.Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := &memoryStore{certs: []db.Certificate{{
		ID:       8,
		Name:     "example.com",
		Source:   db.CertSourceACME,
		Status:   db.CertStatusIssued,
		Domains:  []string{"example.com"},
		CertPath: filepath.Join(dir, "example.com", "fullchain.pem"),
		KeyPath:  filepath.Join(dir, "example.com", "privkey.pem"),
	}}}
	issuer := &stubIssuer{certPEM: certPEM, keyPEM: keyPEM}
	service := Service{
		Store:   store,
		CertDir: dir,
		Issuer:  issuer,
		Now:     fixedNow,
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		},
		ListenTCP: func(string, string) (net.Listener, error) {
			return net.Listen("tcp", "127.0.0.1:0")
		},
	}
	cert, _, err := service.Issue(context.Background(), IssueRequest{Domain: "example.com", Email: "admin@example.com"})
	if err != nil {
		t.Fatalf("issue over legacy path: %v", err)
	}
	if cert.ID != 8 || len(store.certs) != 1 || filepath.Base(cert.KeyPath) != "privkey.pem" {
		t.Fatalf("legacy PEM key path record was not reused: cert=%#v count=%d", cert, len(store.certs))
	}
	if _, err := os.Stat(cert.KeyPath); err != nil {
		t.Fatalf("legacy key path was not written: %v", err)
	}
}

func TestRenewUsesOriginalACMEMetadata(t *testing.T) {
	now := fixedNow()
	certPEM, keyPEM, err := selfSignedPair([]string{"example.com"}, now.Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	issuer := &stubIssuer{certPEM: certPEM, keyPEM: keyPEM}
	store := &memoryStore{certs: []db.Certificate{{
		ID: 1, Name: "example.com", Source: db.CertSourceACME, Status: db.CertStatusIssued,
		Domains: []string{"example.com"}, CertPath: filepath.Join(t.TempDir(), "fullchain.pem"), KeyPath: filepath.Join(t.TempDir(), "privkey.pem"),
		NotAfter: now.Add(5 * 24 * time.Hour).Format(time.RFC3339), IssueEmail: "ops@example.com", ACMEDirectoryURL: "https://acme.example/directory", ChallengeMethod: "http-01",
	}}}
	service := Service{Store: store, Issuer: issuer, Now: func() time.Time { return now }, CertDir: t.TempDir()}
	result, err := service.RenewDue(context.Background(), 30)
	if err != nil {
		t.Fatalf("RenewDue returned error: %v", err)
	}
	if len(result.Renewed) != 1 || issuer.calls != 1 {
		t.Fatalf("unexpected renew result: result=%#v calls=%d", result, issuer.calls)
	}
	if issuer.requests[0].Email != "ops@example.com" || issuer.requests[0].Method != "http-01" {
		t.Fatalf("renew request did not use original ACME metadata: %#v", issuer.requests[0])
	}
	if result.Renewed[0].IssueEmail != "ops@example.com" || result.Renewed[0].ACMEDirectoryURL != "https://acme.example/directory" {
		t.Fatalf("renewed cert lost ACME metadata: %#v", result.Renewed[0])
	}
}

func TestRenewDueOnlyRenewsDueACMECertificates(t *testing.T) {
	now := fixedNow()
	certPEM, keyPEM, err := selfSignedPair([]string{"due.example.com"}, now.Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store := &memoryStore{certs: []db.Certificate{
		{ID: 1, Name: "due", Source: db.CertSourceACME, Status: db.CertStatusIssued, Domains: []string{"due.example.com"}, CertPath: filepath.Join(dir, "due.pem"), KeyPath: filepath.Join(dir, "due.key"), NotAfter: now.Add(5 * 24 * time.Hour).Format(time.RFC3339), IssueEmail: "ops@example.com", ChallengeMethod: "http-01"},
		{ID: 2, Name: "later", Source: db.CertSourceACME, Status: db.CertStatusIssued, Domains: []string{"later.example.com"}, CertPath: filepath.Join(dir, "later.pem"), KeyPath: filepath.Join(dir, "later.key"), NotAfter: now.Add(60 * 24 * time.Hour).Format(time.RFC3339), IssueEmail: "ops@example.com", ChallengeMethod: "http-01"},
		{ID: 3, Name: "import", Source: db.CertSourceImport, Status: db.CertStatusIssued, Domains: []string{"import.example.com"}, CertPath: filepath.Join(dir, "import.pem"), KeyPath: filepath.Join(dir, "import.key"), NotAfter: now.Add(5 * 24 * time.Hour).Format(time.RFC3339)},
	}}
	issuer := &stubIssuer{certPEM: certPEM, keyPEM: keyPEM}
	result, err := (Service{Store: store, Issuer: issuer, Now: func() time.Time { return now }, CertDir: dir}).RenewDue(context.Background(), 30)
	if err != nil {
		t.Fatalf("RenewDue returned error: %v", err)
	}
	if issuer.calls != 1 || len(result.Renewed) != 1 || result.Renewed[0].ID != 1 || len(result.Failed) != 0 {
		t.Fatalf("unexpected renewal selection: calls=%d result=%#v", issuer.calls, result)
	}
}

func TestApplySynchronizesSNIWithCertificateDomain(t *testing.T) {
	store := &memoryStore{
		certs: []db.Certificate{{ID: 1, Source: db.CertSourceImport, Status: db.CertStatusIssued, Domains: []string{"cert.example.com"}, CertPath: "/cert.pem", KeyPath: "/key.pem"}},
		inbounds: []db.Inbound{
			{ID: 10, Protocol: "vless", Core: db.CoreXray, Security: "tls", TLSSNI: "custom.example.com"},
			{ID: 11, Protocol: "vless", Core: db.CoreXray, Security: "tls"},
		},
	}
	updated, _, err := (Service{Store: store, Now: fixedNow}).Apply(context.Background(), ApplyRequest{CertificateID: 1, InboundIDs: []int64{10, 11}})
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if updated[0].TLSSNI != "cert.example.com" || updated[1].TLSSNI != "cert.example.com" {
		t.Fatalf("SNI was not synchronized with certificate domain: %#v", updated)
	}
}

func fixedNow() time.Time {
	return time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC)
}

func hasCheck(result PreflightResult, code, status string) bool {
	for _, check := range result.Checks {
		if check.Code == code && check.Status == status {
			return true
		}
	}
	return false
}
