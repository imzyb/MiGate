package web_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/lockfile"
	"github.com/imzyb/MiGate/internal/paths"
	"github.com/imzyb/MiGate/internal/singbox"
	"github.com/imzyb/MiGate/internal/web"
	"github.com/imzyb/MiGate/internal/xray"
)

func testCertificatePair(t *testing.T, domain string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func openWebTestStore(t *testing.T) *db.Store {
	t.Helper()
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func withTempApplyLock(t *testing.T) {
	t.Helper()
	origApplyLock := paths.ApplyLock
	paths.ApplyLock = filepath.Join(t.TempDir(), "apply.lock")
	t.Cleanup(func() { paths.ApplyLock = origApplyLock })
}

func TestRemovedLegacyAPIRoutesReturnNotFound(t *testing.T) {
	router := web.NewRouter()
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/" + join("vpn", "gate") + "/servers"},
		{http.MethodPost, "/api/" + join("vpn", "gate") + "/import"},
		{http.MethodPost, "/api/" + join("vpn", "gate") + "/probe"},
		{http.MethodPost, "/api/" + join("vpn", "gate") + "/outbounds/health"},
		{http.MethodGet, "/api/" + join("vpn", "gate") + "/egress/capabilities"},
		{http.MethodGet, "/api/" + join("vpn", "gate") + "/egress/plan"},
		{http.MethodGet, "/api/" + join("vpn", "gate") + "/auto-health/status"},
	} {
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, httptest.NewRequest(tc.method, tc.path, nil))
		if resp.Code != http.StatusNotFound {
			t.Fatalf("expected removed route %s %s to return 404, got %d: %s", tc.method, tc.path, resp.Code, resp.Body.String())
		}
	}
}

func TestCreateClientAPIRejectsDuplicateEmailWithConflict(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "dupe", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(web.WithStore(store), web.WithCertDir(t.TempDir()))
	for i := 0; i < 2; i++ {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients", strings.NewReader(`{"email":"sam@example.com","uuid":"11111111-1111-4111-8111-111111111111"}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(resp, req)
		if i == 0 && resp.Code != http.StatusCreated {
			t.Fatalf("expected first client 201, got %d: %s", resp.Code, resp.Body.String())
		}
		if i == 1 {
			if resp.Code != http.StatusConflict {
				t.Fatalf("expected duplicate client 409, got %d: %s", resp.Code, resp.Body.String())
			}
			assertStandardAPIError(t, resp.Body.Bytes(), "duplicate_client")
		}
	}
}

func TestUpdateClientAPIRejectsDuplicateEmailWithConflict(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "dupe-update", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	_, err = store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "sam@example.com"})
	if err != nil {
		t.Fatalf("create first client: %v", err)
	}
	second, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "other@example.com"})
	if err != nil {
		t.Fatalf("create second client: %v", err)
	}
	router := web.NewRouter(web.WithStore(store), web.WithCertDir(t.TempDir()))
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients/"+strconv.FormatInt(second.ID, 10), strings.NewReader(`{"email":"sam@example.com","enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusConflict {
		t.Fatalf("expected duplicate client update 409, got %d: %s", resp.Code, resp.Body.String())
	}
	assertStandardAPIError(t, resp.Body.Bytes(), "duplicate_client")
}

func TestSocks5PoolAPIFetchesRegionsAndImportsOutbound(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Fatalf("expected pool fetch to send user agent")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"proxy":"socks5://sam:secret@184.181.217.201:4145","ip":"184.181.217.201","port":4145,"country":"US","city":"Goodyear","asn":"22773","asOrganization":"Cox Communications","latitude":"33.4353","longitude":"-112.3582","country_cn":"美国","country_en":"United States"},
			{"ip":"203.0.113.9","port":1080,"country":"JP","city":"Tokyo","asn":"AS64500","org":"Example ISP","latitude":35.6762,"longitude":139.6503}
		]`))
	}))
	defer upstream.Close()

	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store), web.WithSocks5PoolURL(upstream.URL))

	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/outbounds/socks5-pool?country=US", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 listing socks5 pool, got %d: %s", list.Code, list.Body.String())
	}
	for _, want := range []string{`"regions"`, `"country_code":"US"`, `"city":"Goodyear"`, `"asn":"AS22773"`, `"organization":"Cox Communications"`, `"latitude":33.4353`, `"longitude":-112.3582`} {
		if !strings.Contains(list.Body.String(), want) {
			t.Fatalf("socks5 pool response missing %q: %s", want, list.Body.String())
		}
	}
	if strings.Contains(list.Body.String(), `"country_code":"JP"`) {
		t.Fatalf("country filter should exclude JP: %s", list.Body.String())
	}

	importResp := httptest.NewRecorder()
	payload := strings.NewReader(`{"address":"184.181.217.201","port":4145,"country_code":"US","country":"美国","city":"Goodyear","asn":"AS22773","organization":"Cox Communications"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/outbounds/socks5-pool/import", payload)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importResp, req)
	if importResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 importing socks5 outbound, got %d: %s", importResp.Code, importResp.Body.String())
	}
	for _, want := range []string{`"protocol":"socks"`, `"address":"184.181.217.201"`, `"port":4145`, `"tag":"pool-socks-184-181-217-201-4145"`, `"remark":"美国 Goodyear AS22773 Cox Communications"`} {
		if !strings.Contains(importResp.Body.String(), want) {
			t.Fatalf("import response missing %q: %s", want, importResp.Body.String())
		}
	}
}

func TestProxyPoolAPISupportsSummaryAndPagination(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"ip":"198.51.100.1","port":1080,"country":"US","country_en":"United States"},
			{"ip":"198.51.100.2","port":1081,"country":"US","country_en":"United States"},
			{"ip":"203.0.113.1","port":1082,"country":"JP","country_en":"Japan"}
		]`))
	}))
	defer upstream.Close()

	router := web.NewRouter(web.WithSocks5PoolURL(upstream.URL))
	summary := httptest.NewRecorder()
	router.ServeHTTP(summary, httptest.NewRequest(http.MethodGet, "/api/outbounds/socks5-pool?summary=1", nil))
	if summary.Code != http.StatusOK {
		t.Fatalf("expected summary 200, got %d: %s", summary.Code, summary.Body.String())
	}
	for _, want := range []string{`"regions"`, `"code":"US"`, `"count":2`, `"proxies":[]`, `"total":3`} {
		if !strings.Contains(summary.Body.String(), want) {
			t.Fatalf("summary response missing %q: %s", want, summary.Body.String())
		}
	}
	if strings.Contains(summary.Body.String(), `"address":"198.51.100.1"`) {
		t.Fatalf("summary response should not include proxy details: %s", summary.Body.String())
	}

	page := httptest.NewRecorder()
	router.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/api/outbounds/socks5-pool?country=US&page=2&per_page=1", nil))
	if page.Code != http.StatusOK {
		t.Fatalf("expected paged 200, got %d: %s", page.Code, page.Body.String())
	}
	for _, want := range []string{`"address":"198.51.100.2"`, `"total":2`, `"page":2`, `"per_page":1`} {
		if !strings.Contains(page.Body.String(), want) {
			t.Fatalf("paged response missing %q: %s", want, page.Body.String())
		}
	}
	if strings.Contains(page.Body.String(), `"address":"198.51.100.1"`) || strings.Contains(page.Body.String(), `"address":"203.0.113.1"`) {
		t.Fatalf("paged response should include only the selected country/page: %s", page.Body.String())
	}
}

func TestProxyPoolColdCacheConcurrentSummaryAndPageShareFetch(t *testing.T) {
	var fetches int32
	started := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&fetches, 1) == 1 {
			close(started)
		}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"ip":"198.51.100.1","port":1080,"country":"US","country_en":"United States"},
			{"ip":"198.51.100.2","port":1081,"country":"US","country_en":"United States"}
		]`))
	}))
	defer upstream.Close()

	cache := &web.Socks5PoolCacheForTest{}
	ready := make(chan struct{}, 2)
	releaseWait := make(chan struct{})
	web.SetProxyPoolAfterSingleflightForTest(cache, func() {
		ready <- struct{}{}
		<-releaseWait
	})
	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)
	for _, path := range []string{"/api/outbounds/socks5-pool?summary=1", "/api/outbounds/socks5-pool?country=US&page=1&per_page=1"} {
		go func(path string) {
			defer wg.Done()
			resp := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			web.ProxyPoolListHandlerForTest(cache, upstream.URL, "socks", resp, req)
			if resp.Code != http.StatusOK {
				errs <- fmt.Errorf("%s returned %d: %s", path, resp.Code, resp.Body.String())
				return
			}
			errs <- nil
		}(path)
	}
	<-ready
	<-ready
	close(releaseWait)
	<-started
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt32(&fetches); got != 1 {
		t.Fatalf("expected concurrent cold cache requests to share one upstream fetch, got %d", got)
	}
}

func TestHTTPProxyPoolAPIFetchesAndImportsHTTPOutbound(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Fatalf("expected pool fetch to send user agent")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"proxy":"http://sam:secret@37.187.109.70:10111","protocol":"http","ip":"37.187.109.70","port":10111,"country":"FR","city":"Dunkirk","asn":"16276","asOrganization":"OVH SAS","latitude":"51.0344","longitude":"2.37681","country_cn":"法国","country_en":"France"}
		]`))
	}))
	defer upstream.Close()

	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store), web.WithHTTPPoolURL(upstream.URL))

	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/outbounds/http-pool?country=FR", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 listing http pool, got %d: %s", list.Code, list.Body.String())
	}
	for _, want := range []string{`"protocol":"http"`, `"country_code":"FR"`, `"city":"Dunkirk"`, `"asn":"AS16276"`, `"organization":"OVH SAS"`, `"latitude":51.0344`, `"longitude":2.37681`, `"username":"sam"`, `"password":"secret"`} {
		if !strings.Contains(list.Body.String(), want) {
			t.Fatalf("http pool response missing %q: %s", want, list.Body.String())
		}
	}

	importResp := httptest.NewRecorder()
	payload := strings.NewReader(`{"address":"37.187.109.70","port":10111,"username":"sam","password":"secret","country_code":"FR","country":"法国","city":"Dunkirk","asn":"AS16276","organization":"OVH SAS"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/outbounds/http-pool/import", payload)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importResp, req)
	if importResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 importing http outbound, got %d: %s", importResp.Code, importResp.Body.String())
	}
	for _, want := range []string{`"protocol":"http"`, `"address":"37.187.109.70"`, `"port":10111`, `"tag":"pool-http-37-187-109-70-10111"`, `"remark":"法国 Dunkirk AS16276 OVH SAS"`, `"username":"sam"`, `"password":"secret"`} {
		if !strings.Contains(importResp.Body.String(), want) {
			t.Fatalf("import response missing %q: %s", want, importResp.Body.String())
		}
	}
}

func TestHTTPSProxyPoolImportsHTTPOutbound(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"proxy":"https://205.178.137.78:8447","protocol":"https","ip":"205.178.137.78","port":8447,"country":"US","city":"Jacksonville","asn":"19871","asOrganization":"Web.com Group, Inc.","country_en":"United States"}]`))
	}))
	defer upstream.Close()

	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store), web.WithHTTPSPoolURL(upstream.URL))

	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/outbounds/https-pool?country=US", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 listing https pool, got %d: %s", list.Code, list.Body.String())
	}
	if !strings.Contains(list.Body.String(), `"protocol":"https"`) || !strings.Contains(list.Body.String(), `"address":"205.178.137.78"`) {
		t.Fatalf("unexpected https pool response: %s", list.Body.String())
	}

	importResp := httptest.NewRecorder()
	payload := strings.NewReader(`{"address":"205.178.137.78","port":8447,"country_code":"US","country":"United States","city":"Jacksonville","asn":"AS19871","organization":"Web.com Group, Inc."}`)
	req := httptest.NewRequest(http.MethodPost, "/api/outbounds/https-pool/import", payload)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(importResp, req)
	if importResp.Code != http.StatusCreated {
		t.Fatalf("expected 201 importing https outbound, got %d: %s", importResp.Code, importResp.Body.String())
	}
	for _, want := range []string{`"protocol":"http"`, `"tag":"pool-https-205-178-137-78-8447"`, `"remark":"United States Jacksonville AS19871 Web.com Group, Inc."`} {
		if !strings.Contains(importResp.Body.String(), want) {
			t.Fatalf("https import response missing %q: %s", want, importResp.Body.String())
		}
	}
}

func TestHTTPProxyPoolCacheRefreshesWhenURLChanges(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"proxy":"http://198.51.100.10:8080","country":"US","country_en":"United States"}]`))
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"proxy":"http://203.0.113.20:8080","country":"JP","country_en":"Japan"}]`))
	}))
	defer second.Close()

	firstRouter := web.NewRouter(web.WithHTTPPoolURL(first.URL))
	firstResp := httptest.NewRecorder()
	firstRouter.ServeHTTP(firstResp, httptest.NewRequest(http.MethodGet, "/api/outbounds/http-pool", nil))
	if firstResp.Code != http.StatusOK || !strings.Contains(firstResp.Body.String(), `"address":"198.51.100.10"`) {
		t.Fatalf("expected first upstream response, got %d: %s", firstResp.Code, firstResp.Body.String())
	}

	secondRouter := web.NewRouter(web.WithHTTPPoolURL(second.URL))
	secondResp := httptest.NewRecorder()
	secondRouter.ServeHTTP(secondResp, httptest.NewRequest(http.MethodGet, "/api/outbounds/http-pool", nil))
	if secondResp.Code != http.StatusOK || !strings.Contains(secondResp.Body.String(), `"address":"203.0.113.20"`) {
		t.Fatalf("expected second upstream response after URL change, got %d: %s", secondResp.Code, secondResp.Body.String())
	}
	if strings.Contains(secondResp.Body.String(), `"address":"198.51.100.10"`) {
		t.Fatalf("second URL should not reuse first URL cache: %s", secondResp.Body.String())
	}
}

func TestOutboundsAPIListsDefaultsAndCreatesOutbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "socks-in", Protocol: "socks", Port: 2080, Network: "tcp", Security: "none"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))

	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/outbounds", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 listing outbounds, got %d: %s", list.Code, list.Body.String())
	}
	for _, want := range []string{`"tag":"direct"`, `"protocol":"freedom"`, `"tag":"blocked"`, `"protocol":"blackhole"`} {
		if !strings.Contains(list.Body.String(), want) {
			t.Fatalf("outbounds list missing %q: %s", want, list.Body.String())
		}
	}

	payload := []byte(`{"tag":"proxy-socks","remark":"SOCKS代理","protocol":"socks","address":"127.0.0.1","port":1080,"username":"sam","password":"secret","supported_cores":["xray"],"source":"subscription","subscription_id":123,"subscription_identity":"spoofed","raw_link":"trojan://spoofed"}`)
	created := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/outbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(created, req)
	if created.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating outbound, got %d: %s", created.Code, created.Body.String())
	}
	for _, want := range []string{`"tag":"proxy-socks"`, `"protocol":"socks"`, `"address":"127.0.0.1"`, `"port":1080`, `"enabled":true`, `"supported_cores":["xray","sing-box"]`} {
		if !strings.Contains(created.Body.String(), want) {
			t.Fatalf("create outbound response missing %q: %s", want, created.Body.String())
		}
	}

	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list outbounds: %v", err)
	}
	if len(outbounds) != 4 || outbounds[3].Tag != "proxy-socks" {
		t.Fatalf("outbound was not persisted: %+v", outbounds)
	}
	if outbounds[3].Source != db.OutboundSourceManual || outbounds[3].SubscriptionID != 0 || outbounds[3].SubscriptionIdentity != "" || outbounds[3].RawLink != "" {
		t.Fatalf("public create should ignore spoofed source metadata: %+v", outbounds[3])
	}
	if !db.SupportsCore(outbounds[3].SupportedCores, db.CoreXray) || !db.SupportsCore(outbounds[3].SupportedCores, db.CoreSingbox) {
		t.Fatalf("request supported_cores should not narrow protocol-derived response cores: %+v", outbounds[3].SupportedCores)
	}
}

func TestUpdateOutboundAPIUpdatesFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ob, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag: "proxy-http", Protocol: "http", Address: "10.0.0.1", Port: 8080,
	})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"tag":"proxy-http-v2","remark":"HTTP代理v2","protocol":"socks","address":"10.0.0.2","port":1080,"username":"newuser","password":"newpass","enabled":false}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/outbounds/"+strconv.FormatInt(ob.ID, 10), bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"tag":"proxy-http-v2"`, `"protocol":"socks"`, `"address":"10.0.0.2"`, `"port":1080`, `"enabled":false`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("update response missing %q: %s", want, response.Body.String())
		}
	}

	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, o := range outbounds {
		if o.ID == ob.ID {
			if o.Tag != "proxy-http-v2" || o.Enabled != false {
				t.Fatalf("updated values not persisted: %+v", o)
			}
		}
	}
}

func TestUpdateOutboundAPIProtectsSubscriptionNodeConnectionFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{Remark: "sub", URL: "https://example.com/sub", Enabled: true})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", RawLink: "trojan://pw@example.com:443#a", SettingsJSON: `{"tls":true}`, Position: 0},
	}, []string{"a"}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	var target db.Outbound
	for _, outbound := range mustListOutbounds(t, store) {
		if outbound.SubscriptionID == sub.ID {
			target = outbound
		}
	}
	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"tag":"changed","remark":"可改备注","protocol":"socks","address":"127.0.0.1","port":1080,"username":"sam","password":"secret","enabled":false,"settings_json":"{\"security\":\"none\"}"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/outbounds/"+strconv.FormatInt(target.ID, 10), bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"tag":"sub1-a"`, `"protocol":"trojan"`, `"address":"example.com"`, `"port":443`, `"enabled":false`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("subscription update response missing preserved field %q: %s", want, response.Body.String())
		}
	}
	for _, outbound := range mustListOutbounds(t, store) {
		if outbound.ID == target.ID {
			if outbound.Tag != target.Tag || outbound.Protocol != target.Protocol || outbound.Address != target.Address || outbound.SettingsJSON != target.SettingsJSON {
				t.Fatalf("subscription connection fields should be preserved, before=%+v after=%+v", target, outbound)
			}
			if outbound.Remark != "可改备注" || outbound.Enabled {
				t.Fatalf("editable subscription fields not updated: %+v", outbound)
			}
		}
	}
}

func TestCreateOutboundAPIDoesNotCreateSpoofedSubscriptionNode(t *testing.T) {
	store := openWebTestStore(t)
	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"tag":"spoofed-sub","protocol":"socks","address":"127.0.0.1","port":1080,"source":"subscription","subscription_id":42,"subscription_identity":"fake","raw_link":"trojan://fake"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/outbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating normal outbound, got %d: %s", response.Code, response.Body.String())
	}
	outbounds := mustListOutbounds(t, store)
	for _, outbound := range outbounds {
		if outbound.Tag == "spoofed-sub" {
			if outbound.Source == db.OutboundSourceSubscription || outbound.SubscriptionID != 0 || outbound.SubscriptionIdentity != "" || outbound.RawLink != "" {
				t.Fatalf("public create should not persist spoofed subscription metadata: %+v", outbound)
			}
			return
		}
	}
	t.Fatalf("created outbound not found: %+v", outbounds)
}

func TestUpdateOutboundAPIRejectsEnablingDisabledSubscriptionNode(t *testing.T) {
	store := openWebTestStore(t)
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{Remark: "sub", URL: "https://example.com/sub", Enabled: true})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", RawLink: "trojan://pw@example.com:443#a", Position: 0},
	}, []string{"a"}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	var target db.Outbound
	for _, outbound := range mustListOutbounds(t, store) {
		if outbound.SubscriptionID == sub.ID {
			target = outbound
		}
	}
	if _, err := store.UpdateOutboundSubscription(context.Background(), sub.ID, db.UpdateOutboundSubscriptionParams{Remark: "sub", URL: "https://example.com/sub", Enabled: false}); err != nil {
		t.Fatalf("disable subscription: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"tag":"sub1-a","remark":"a","protocol":"trojan","address":"example.com","port":443,"password":"pw","enabled":true}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/outbounds/"+strconv.FormatInt(target.ID, 10), bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "subscription_disabled") {
		t.Fatalf("expected subscription_disabled response, got %s", response.Body.String())
	}
	for _, outbound := range mustListOutbounds(t, store) {
		if outbound.ID == target.ID && outbound.Enabled {
			t.Fatalf("disabled subscription node should remain disabled: %+v", outbound)
		}
	}
}

func TestUpdateOutboundAPIKeepsSettingsJSONWhenOmitted(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ob, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag: "proxy-vless", Protocol: "vless", Address: "example.com", Port: 443, Username: "11111111-1111-4111-8111-111111111111", SettingsJSON: `{"security":"reality","sni":"example.com"}`,
	})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"tag":"proxy-vless-v2","remark":"VLESS代理v2","protocol":"vless","address":"example.org","port":443,"username":"11111111-1111-4111-8111-111111111111","password":"","enabled":true}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/outbounds/"+strconv.FormatInt(ob.ID, 10), bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}

	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, o := range outbounds {
		if o.ID == ob.ID {
			if o.SettingsJSON != `{"security":"reality","sni":"example.com"}` {
				t.Fatalf("expected settings_json to be preserved when omitted, got %+v", o)
			}
			return
		}
	}
	t.Fatalf("updated outbound not found")
}

func TestUpdateOutboundAPIClearsSettingsJSONWhenExplicitEmpty(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ob, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag: "proxy-vless", Protocol: "vless", Address: "example.com", Port: 443, Username: "11111111-1111-4111-8111-111111111111", SettingsJSON: `{"security":"tls"}`,
	})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"tag":"proxy-vless-v2","remark":"VLESS代理v2","protocol":"vless","address":"example.org","port":443,"username":"11111111-1111-4111-8111-111111111111","password":"","enabled":true,"settings_json":""}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/outbounds/"+strconv.FormatInt(ob.ID, 10), bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}

	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, o := range outbounds {
		if o.ID == ob.ID {
			if o.SettingsJSON != "" {
				t.Fatalf("expected settings_json to be cleared when explicit empty, got %+v", o)
			}
			return
		}
	}
	t.Fatalf("updated outbound not found")
}

func TestUpdateOutboundAPIRejectsUnknownID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "socks-in", Protocol: "socks", Port: 2080, Network: "tcp", Security: "none"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"tag":"x","remark":"x","protocol":"socks","address":"1.1.1.1","port":80}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/outbounds/99999", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", response.Code, response.Body.String())
	}
}

func TestOutboundSubscriptionPreviewShowsSkippedLinks(t *testing.T) {
	router := web.NewRouter(web.WithStore(openWebTestStore(t)))
	payload := strings.NewReader(`{"body":"trojan://secret@example.com:443#ok\nvmess://eyJhZGQiOiJleGFtcGxlLmNvbSJ9"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/outbound-subscriptions/preview", payload)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"count":1`, `"skipped_count":1`, `"protocol":"vmess"`, `"reason":"vmess links are not supported yet"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("preview response missing %q: %s", want, response.Body.String())
		}
	}
}

func TestOutboundSubscriptionPreviewShowsSkippedWhenAllLinksUnsupported(t *testing.T) {
	router := web.NewRouter(web.WithStore(openWebTestStore(t)))
	payload := strings.NewReader(`{"body":"vmess://eyJhZGQiOiJleGFtcGxlLmNvbSJ9"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/outbound-subscriptions/preview", payload)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 for all-skipped preview, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"count":0`, `"skipped_count":1`, `"protocol":"vmess"`, `"reason":"vmess links are not supported yet"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("preview response missing %q: %s", want, response.Body.String())
		}
	}
}

func TestRefreshOutboundSubscriptionRejectsDisabledSubscription(t *testing.T) {
	store := openWebTestStore(t)
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{Remark: "sub", URL: "https://example.com/sub", Enabled: false})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/outbound-subscriptions/"+strconv.FormatInt(sub.ID, 10)+"/refresh", nil))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("expected disabled refresh to fail, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "disabled") {
		t.Fatalf("expected disabled detail, got %s", response.Body.String())
	}
}

func TestDisabledOutboundSubscriptionNodesAreOmittedFromBuiltConfig(t *testing.T) {
	store := openWebTestStore(t)
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{Remark: "sub", URL: "https://example.com/sub", Enabled: true})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", RawLink: "trojan://pw@example.com:443#a", Position: 0},
	}, []string{"a"}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if _, err := store.UpdateOutboundSubscription(context.Background(), sub.ID, db.UpdateOutboundSubscriptionParams{Remark: "sub", URL: "https://example.com/sub", Enabled: false}); err != nil {
		t.Fatalf("disable subscription: %v", err)
	}
	config, err := xray.BuildConfigWithOutbounds(nil, mustListOutbounds(t, store), nil)
	if err != nil {
		t.Fatalf("build xray config: %v", err)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal xray config: %v", err)
	}
	if strings.Contains(string(raw), "sub1-a") || strings.Contains(string(raw), "example.com") {
		t.Fatalf("disabled subscription node should not be in built config: %s", raw)
	}
	singboxConfig, err := singbox.BuildConfigWithOutbounds(nil, mustListOutbounds(t, store), nil)
	if err != nil {
		t.Fatalf("build sing-box config: %v", err)
	}
	singboxRaw, err := json.Marshal(singboxConfig)
	if err != nil {
		t.Fatalf("marshal sing-box config: %v", err)
	}
	if strings.Contains(string(singboxRaw), "sub1-a") || strings.Contains(string(singboxRaw), "example.com") {
		t.Fatalf("disabled subscription node should not be in sing-box config: %s", singboxRaw)
	}
}

func TestReEnableOutboundSubscriptionReturnsNeedsRefreshAndKeepsNodesDisabled(t *testing.T) {
	store := openWebTestStore(t)
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{Remark: "sub", URL: "https://example.com/sub", TagPrefix: "sub1-", Enabled: true})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", Position: 0},
	}, []string{"a"}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if _, err := store.UpdateOutboundSubscription(context.Background(), sub.ID, db.UpdateOutboundSubscriptionParams{Remark: "sub", URL: "https://example.com/sub", TagPrefix: "sub1-", Enabled: false}); err != nil {
		t.Fatalf("disable subscription: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/outbound-subscriptions/"+strconv.FormatInt(sub.ID, 10), strings.NewReader(`{"remark":"sub","url":"https://example.com/sub","tag_prefix":"sub1-","update_interval_seconds":600,"enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"needs_refresh":true`) {
		t.Fatalf("expected needs_refresh=true, got %s", response.Body.String())
	}
	for _, outbound := range mustListOutbounds(t, store) {
		if outbound.SubscriptionID == sub.ID && outbound.Enabled {
			t.Fatalf("re-enable should not revive old subscription node before refresh: %+v", outbound)
		}
	}
}

type failingSubscriptionFetcher struct{}

func (failingSubscriptionFetcher) Fetch(context.Context, string, bool) ([]byte, error) {
	return nil, errors.New("upstream failed")
}

func TestRefreshAfterReEnableFailureRecordsErrorWithoutReEnablingOldNodes(t *testing.T) {
	store := openWebTestStore(t)
	sub, err := store.CreateOutboundSubscription(context.Background(), db.CreateOutboundSubscriptionParams{Remark: "sub", URL: "https://example.com/sub", Enabled: true})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if _, err := store.MaterializeSubscriptionOutbounds(context.Background(), sub.ID, []db.MaterializedSubscriptionOutbound{
		{Tag: "sub1-a", Remark: "a", Protocol: "trojan", Address: "example.com", Port: 443, Password: "pw", SubscriptionIdentity: "a", Position: 0},
	}, []string{"a"}); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if _, err := store.UpdateOutboundSubscription(context.Background(), sub.ID, db.UpdateOutboundSubscriptionParams{Remark: "sub", URL: "https://example.com/sub", Enabled: false}); err != nil {
		t.Fatalf("disable subscription: %v", err)
	}
	if _, err := store.UpdateOutboundSubscription(context.Background(), sub.ID, db.UpdateOutboundSubscriptionParams{Remark: "sub", URL: "https://example.com/sub", Enabled: true}); err != nil {
		t.Fatalf("re-enable subscription: %v", err)
	}
	_, _, _, err = web.RefreshOutboundSubscription(context.Background(), store, failingSubscriptionFetcher{}, sub.ID)
	if err == nil {
		t.Fatal("expected refresh failure")
	}
	loaded, ok, err := store.GetOutboundSubscription(context.Background(), sub.ID)
	if err != nil || !ok {
		t.Fatalf("get subscription: ok=%v err=%v", ok, err)
	}
	if loaded.LastAttemptAt == "" || loaded.LastError != "upstream failed" {
		t.Fatalf("refresh failure should record attempt and error: %+v", loaded)
	}
	for _, outbound := range mustListOutbounds(t, store) {
		if outbound.SubscriptionID == sub.ID && outbound.Enabled {
			t.Fatalf("failed refresh should not re-enable old subscription node: %+v", outbound)
		}
	}
}

func TestDeleteOutboundAPIDeletesOutbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ob, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag: "temp-proxy", Protocol: "socks", Address: "10.0.0.1", Port: 1080,
	})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/outbounds/"+strconv.FormatInt(ob.ID, 10), nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}

	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, o := range outbounds {
		if o.ID == ob.ID {
			t.Fatalf("outbound %d still present after delete", ob.ID)
		}
	}
}

func TestDeleteOutboundAPIRejectsUnknownID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/outbounds/99999", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", response.Code, response.Body.String())
	}
}

type listOutboundsFailingStore struct {
	*db.Store
	deleteCalled bool
}

func (s *listOutboundsFailingStore) ListOutbounds(ctx context.Context) ([]db.Outbound, error) {
	return nil, errors.New("list outbounds failed")
}

func (s *listOutboundsFailingStore) DeleteOutbound(ctx context.Context, id int64) error {
	s.deleteCalled = true
	return s.Store.DeleteOutbound(ctx, id)
}

func TestDeleteOutboundAPIReportsListFailureBeforeDelete(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ob, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag: "temp-proxy", Protocol: "socks", Address: "10.0.0.1", Port: 1080,
	})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}

	failingStore := &listOutboundsFailingStore{Store: store}
	router := web.NewRouter(web.WithStore(failingStore))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/outbounds/"+strconv.FormatInt(ob.ID, 10), nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", response.Code, response.Body.String())
	}
	assertStandardAPIError(t, response.Body.Bytes(), "list_failed")
	if failingStore.deleteCalled {
		t.Fatal("delete should not run when old outbound lookup fails")
	}
}

type listRoutingRulesFailingStore struct {
	*db.Store
	updateCalled bool
	deleteCalled bool
}

func (s *listRoutingRulesFailingStore) ListRoutingRules(ctx context.Context) ([]db.RoutingRule, error) {
	return nil, errors.New("list routing rules failed")
}

func (s *listRoutingRulesFailingStore) UpdateRoutingRule(ctx context.Context, id int64, params db.UpdateRoutingRuleParams) (db.RoutingRule, error) {
	s.updateCalled = true
	return s.Store.UpdateRoutingRule(ctx, id, params)
}

func (s *listRoutingRulesFailingStore) DeleteRoutingRule(ctx context.Context, id int64) error {
	s.deleteCalled = true
	return s.Store.DeleteRoutingRule(ctx, id)
}

type listInboundsFailingStore struct {
	*db.Store
}

func (s *listInboundsFailingStore) ListInbounds(ctx context.Context) ([]db.Inbound, error) {
	return nil, errors.New("list inbounds failed")
}

type xrayBuildFailingStore struct {
	*db.Store
}

func (s *xrayBuildFailingStore) ListRoutingRules(ctx context.Context) ([]db.RoutingRule, error) {
	return []db.RoutingRule{{ID: 99, OutboundTag: "missing", Enabled: true}}, nil
}

func TestRoutingRulesAPICRUD(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "socks-in", Protocol: "socks", Port: 2080, Network: "tcp", Security: "none"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))

	// GET: empty list
	listResp := httptest.NewRecorder()
	router.ServeHTTP(listResp, httptest.NewRequest(http.MethodGet, "/api/routing-rules", nil))
	if listResp.Code != 200 {
		t.Fatalf("expected 200 listing routing rules, got %d: %s", listResp.Code, listResp.Body.String())
	}
	if listResp.Body.String() != "[]\n" && listResp.Body.String() != "null\n" {
		t.Fatalf("expected empty list, got %s", listResp.Body.String())
	}

	// POST: create rule
	payload := `{"inbound_tag":"","outbound_id":2,"outbound_tag":"blocked","domain":"geosite:malware","ip":"geoip:private","rule_set":"geosite-category-ads-all","protocol":"bittorrent"}`
	createResp := httptest.NewRecorder()
	router.ServeHTTP(createResp, httptest.NewRequest(http.MethodPost, "/api/routing-rules", strings.NewReader(payload)))
	if createResp.Code != 201 {
		t.Fatalf("expected 201 creating routing rule, got %d: %s", createResp.Code, createResp.Body.String())
	}
	var createResult map[string]interface{}
	if err := json.Unmarshal(createResp.Body.Bytes(), &createResult); err != nil {
		t.Fatalf("parse create response: %v", err)
	}
	rule := createResult["rule"].(map[string]interface{})
	if rule["outbound_tag"] != "blocked" || rule["domain"] != "geosite:malware" || rule["ip"] != "geoip:private" || rule["rule_set"] != "geosite-category-ads-all" || rule["protocol"] != "bittorrent" {
		t.Fatalf("unexpected created rule: %+v", rule)
	}
	id := int(rule["id"].(float64))

	// GET: verify rule in list
	listResp2 := httptest.NewRecorder()
	router.ServeHTTP(listResp2, httptest.NewRequest(http.MethodGet, "/api/routing-rules", nil))
	var rules []interface{}
	if err := json.Unmarshal(listResp2.Body.Bytes(), &rules); err != nil {
		t.Fatalf("parse list: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d: %s", len(rules), listResp2.Body.String())
	}

	// PUT: update rule
	updatePayload := `{"inbound_tag":"socks-in","outbound_id":1,"outbound_tag":"direct","domain":"geosite:netflix","ip":"8.8.8.8","rule_set":"geoip-cn","protocol":"dns","enabled":false}`
	updateResp := httptest.NewRecorder()
	router.ServeHTTP(updateResp, httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/routing-rules/%d", id), strings.NewReader(updatePayload)))
	if updateResp.Code != 200 {
		t.Fatalf("expected 200 updating rule, got %d: %s", updateResp.Code, updateResp.Body.String())
	}
	for _, want := range []string{`"ip":"8.8.8.8"`, `"rule_set":"geoip-cn"`, `"protocol":"dns"`, `"enabled":false`} {
		if !strings.Contains(updateResp.Body.String(), want) {
			t.Fatalf("update response missing %q: %s", want, updateResp.Body.String())
		}
	}

	// DELETE
	deleteResp := httptest.NewRecorder()
	router.ServeHTTP(deleteResp, httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/routing-rules/%d", id), nil))
	if deleteResp.Code != 200 {
		t.Fatalf("expected 200 deleting rule, got %d: %s", deleteResp.Code, deleteResp.Body.String())
	}

	// Verify empty
	listResp3 := httptest.NewRecorder()
	router.ServeHTTP(listResp3, httptest.NewRequest(http.MethodGet, "/api/routing-rules", nil))
	if listResp3.Body.String() != "[]\n" && listResp3.Body.String() != "null\n" {
		t.Fatalf("expected empty after delete, got %s", listResp3.Body.String())
	}

	// DELETE unknown
	deleteUnknown := httptest.NewRecorder()
	router.ServeHTTP(deleteUnknown, httptest.NewRequest(http.MethodDelete, "/api/routing-rules/99999", nil))
	if deleteUnknown.Code != 404 {
		t.Fatalf("expected 404 deleting unknown rule, got %d", deleteUnknown.Code)
	}
}

func TestDeleteRoutingRuleAPIReportsListFailureBeforeDelete(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{OutboundID: 1, OutboundTag: "direct", Domain: "example.com", Enabled: true})
	if err != nil {
		t.Fatalf("create routing rule: %v", err)
	}

	failingStore := &listRoutingRulesFailingStore{Store: store}
	router := web.NewRouter(web.WithStore(failingStore))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/routing-rules/"+strconv.FormatInt(rule.ID, 10), nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", response.Code, response.Body.String())
	}
	assertStandardAPIError(t, response.Body.Bytes(), "list_failed")
	if failingStore.deleteCalled {
		t.Fatal("delete should not run when old routing rule lookup fails")
	}
}

func TestUpdateRoutingRuleAPIReportsListFailureBeforeUpdate(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{OutboundID: 1, OutboundTag: "direct", Domain: "example.com", Enabled: true})
	if err != nil {
		t.Fatalf("create routing rule: %v", err)
	}

	failingStore := &listRoutingRulesFailingStore{Store: store}
	router := web.NewRouter(web.WithStore(failingStore))
	response := httptest.NewRecorder()
	body := `{"outbound_id":1,"outbound_tag":"direct","domain":"example.org","enabled":false}`
	req := httptest.NewRequest(http.MethodPut, "/api/routing-rules/"+strconv.FormatInt(rule.ID, 10), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", response.Code, response.Body.String())
	}
	assertStandardAPIError(t, response.Body.Bytes(), "list_failed")
	if failingStore.updateCalled {
		t.Fatal("update should not run when old routing rule lookup fails")
	}
}

func TestCreateRoutingRuleReportsSingboxListFailureInResponse(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(&listInboundsFailingStore{Store: store}))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/routing-rules", strings.NewReader(`{"outbound_id":1,"outbound_tag":"direct","domain":"example.com","enabled":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", response.Code, response.Body.String())
	}
	assertStandardAPIError(t, response.Body.Bytes(), "list_failed")
	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list routing rules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("routing rule should not be created when scope read fails: %+v", rules)
	}
}

func TestRoutingRuleUpdateAppliesSingboxWhenPreviousRuleAffectedSingbox(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21090, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	rule, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{InboundTag: db.GeneratedInboundTag(inbound), OutboundID: 1, OutboundTag: "direct", Domain: "example.com", Enabled: true})
	if err != nil {
		t.Fatalf("create routing rule: %v", err)
	}
	var singboxApplyCalls int
	router := web.NewRouter(
		web.WithStore(store),
		web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
			singboxApplyCalls++
			return web.SingboxApplySummary{Applied: true, Service: "sing-box", ConfigPath: "/etc/migate/cores/sing-box.json", CommandsExecuted: []string{"sing-box check"}}
		}),
	)

	updatePayload := `{"inbound_tag":"` + db.GeneratedInboundTag(inbound) + `","outbound_id":1,"outbound_tag":"direct","domain":"example.com","enabled":false}`
	updateResp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/routing-rules/%d", rule.ID), strings.NewReader(updatePayload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(updateResp, req)

	if updateResp.Code != http.StatusOK {
		t.Fatalf("expected 200 updating rule, got %d: %s", updateResp.Code, updateResp.Body.String())
	}
	if singboxApplyCalls != 1 {
		t.Fatalf("expected sing-box apply for previous affected rule, got %d", singboxApplyCalls)
	}
	if !strings.Contains(updateResp.Body.String(), `"singbox":`) || !strings.Contains(updateResp.Body.String(), `"applied":true`) {
		t.Fatalf("expected sing-box result in response: %s", updateResp.Body.String())
	}
}

func TestInboundsAPIListsStoredInboundsWithClients(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark:   "主入口",
		Protocol: "vless",
		Port:     443,
		Network:  "tcp",
		Security: "reality",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	_, err = store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "sam@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/inbounds", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"remark":"主入口"`, `"protocol":"vless"`, `"port":443`, `"email":"sam@example.com"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "panel_password") || strings.Contains(body, "super-secret-password") {
		t.Fatalf("inbounds api leaked panel secrets: %s", body)
	}
}

func TestCreateInboundPersistsHysteria2MPortForWebUILink(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store))
	payload := map[string]any{
		"remark":            "hy2-link",
		"protocol":          "hysteria2",
		"port":              21001,
		"network":           "udp",
		"security":          "tls",
		"hy2_up_mbps":       100,
		"hy2_down_mbps":     200,
		"hy2_obfs":          "salamander",
		"hy2_obfs_password": "obfs secret",
		"hy2_mport":         "40000-50000",
		"initial_client":    map[string]any{"email": "hy2-user", "uuid": "hy2-password"},
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/inbounds", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("expected list 200, got %d: %s", list.Code, list.Body.String())
	}
	for _, want := range []string{`"hy2_up_mbps":100`, `"hy2_down_mbps":200`, `"hy2_obfs":"salamander"`, `"hy2_obfs_password":"obfs secret"`, `"hy2_mport":"40000-50000"`} {
		if !strings.Contains(list.Body.String(), want) {
			t.Fatalf("inbound list missing %s: %s", want, list.Body.String())
		}
	}
}

func TestCreateSingboxInboundReportsNotInstalledWithoutAppliedTrue(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store), web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
		if !strict {
			t.Fatal("sing-box node creation must use strict apply")
		}
		return web.SingboxApplySummary{Applied: false, Error: "singbox_not_installed", Detail: "singbox_not_installed", Service: "sing-box", ConfigPath: "/etc/migate/cores/sing-box.json", CommandsExecuted: []string{}}
	}))
	payload := []byte(`{"remark":"hy2","protocol":"hysteria2","port":21001,"network":"udp","security":"tls"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected saved-but-not-applied 201, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"created":true`, `"applied":false`, `"error":"singbox_not_installed"`, `"inbound":`, `"singbox":`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("response missing %q: %s", want, response.Body.String())
		}
	}
	if strings.Contains(response.Body.String(), `"applied":true`) {
		t.Fatalf("must not report applied true when sing-box is unavailable: %s", response.Body.String())
	}
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || inbounds[0].Protocol != "hysteria2" {
		t.Fatalf("inbound should be persisted for later apply: %+v", inbounds)
	}
}

func TestCreateSingboxInboundReportsApplyFailureWithCreatedObject(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(store), web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
		if !strict {
			t.Fatal("sing-box node creation must use strict apply")
		}
		return web.SingboxApplySummary{Applied: false, Error: "singbox_apply_failed", Detail: "config check failed", Service: "sing-box", ConfigPath: "/etc/migate/cores/sing-box.json", CommandsExecuted: []string{}}
	}))
	payload := []byte(`{"remark":"tuic","protocol":"tuic","port":21002,"network":"udp","security":"tls"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected saved-but-not-applied 201, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"created":true`, `"applied":false`, `"error":"singbox_apply_failed"`, `"detail":"config check failed"`, `"inbound":`, `"singbox":`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("response missing %q: %s", want, response.Body.String())
		}
	}
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || inbounds[0].Protocol != "tuic" {
		t.Fatalf("inbound should be persisted for later apply: %+v", inbounds)
	}
}

func TestCreateSingboxClientReportsApplyFailureWithCreatedObject(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "tuic", Protocol: "tuic", Port: 21002, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(web.WithStore(store), web.WithSingboxRuntime(fixedWebSingboxRuntime{}), web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
		if !strict {
			t.Fatal("sing-box client creation must use strict apply")
		}
		return web.SingboxApplySummary{Applied: false, Error: "singbox_apply_failed", Detail: "restart failed", Service: "sing-box", ConfigPath: "/etc/migate/cores/sing-box.json", CommandsExecuted: []string{}}
	}))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients", bytes.NewReader([]byte(`{"email":"tuic@example.com","credential_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","password":"secret"}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected saved-but-not-applied 201, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"created":true`, `"applied":false`, `"error":"singbox_apply_failed"`, `"detail":"restart failed"`, `"client":`, `"singbox":`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("response missing %q: %s", want, response.Body.String())
		}
	}
	if strings.Contains(response.Body.String(), `"applied":true`) {
		t.Fatalf("must not report applied true when apply fails: %s", response.Body.String())
	}
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || len(inbounds[0].Clients) != 1 || inbounds[0].Clients[0].Email != "tuic@example.com" {
		t.Fatalf("client should be persisted for later apply: %+v", inbounds)
	}
}

func failedSingboxSummary(detail string) web.SingboxApplySummary {
	return web.SingboxApplySummary{
		Applied:          false,
		Error:            "singbox_apply_failed",
		Detail:           detail,
		Service:          "sing-box",
		ConfigPath:       "/etc/migate/cores/sing-box.json",
		CommandsExecuted: []string{"sing-box check -c <temp>", "systemctl restart migate-sing-box"},
	}
}

func TestUpdateAndDeleteSingboxInboundReportApplyFailure(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21001, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(web.WithStore(store), web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
		if !strict {
			t.Fatal("sing-box inbound writes must use strict apply")
		}
		return failedSingboxSummary("inbound apply failed")
	}))

	updateResp := httptest.NewRecorder()
	updateBody := []byte(`{"remark":"hy2-new","protocol":"hysteria2","port":21002,"network":"udp","security":"tls","enabled":true}`)
	updateReq := httptest.NewRequest(http.MethodPut, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10), bytes.NewReader(updateBody))
	updateReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(updateResp, updateReq)
	if updateResp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateResp.Code, updateResp.Body.String())
	}
	for _, want := range []string{`"inbound":`, `"applied":false`, `"singbox":`, `"detail":"inbound apply failed"`} {
		if !strings.Contains(updateResp.Body.String(), want) {
			t.Fatalf("update response missing %q: %s", want, updateResp.Body.String())
		}
	}

	deleteResp := httptest.NewRecorder()
	router.ServeHTTP(deleteResp, httptest.NewRequest(http.MethodDelete, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10), nil))
	if deleteResp.Code != http.StatusOK {
		t.Fatalf("expected 200 delete, got %d: %s", deleteResp.Code, deleteResp.Body.String())
	}
	for _, want := range []string{`"status":"deleted"`, `"applied":false`, `"detail":"inbound apply failed"`} {
		if !strings.Contains(deleteResp.Body.String(), want) {
			t.Fatalf("delete response missing %q: %s", want, deleteResp.Body.String())
		}
	}
}

func TestUpdateInboundFromSingboxToXrayStillReportsSingboxApplyFailure(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21011, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	var calls int
	router := web.NewRouter(web.WithStore(store), web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
		calls++
		if !strict {
			t.Fatal("sing-box inbound migration must use strict apply")
		}
		return failedSingboxSummary("remove stale sing-box inbound failed")
	}))

	response := httptest.NewRecorder()
	body := []byte(`{"remark":"vless-now","protocol":"vless","port":21011,"network":"tcp","security":"none","enabled":true}`)
	req := httptest.NewRequest(http.MethodPut, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	if calls != 1 {
		t.Fatalf("expected sing-box apply once for migration away from sing-box, got %d", calls)
	}
	for _, want := range []string{`"inbound":`, `"protocol":"vless"`, `"applied":false`, `"detail":"remove stale sing-box inbound failed"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("response missing %q: %s", want, response.Body.String())
		}
	}
}

func TestUpdateToggleAndDeleteSingboxClientReportApplyFailure(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "tuic", Protocol: "tuic", Port: 21003, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "old@example.com", UUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", CredentialID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Password: "secret"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	router := web.NewRouter(web.WithStore(store), web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
		if !strict {
			t.Fatal("sing-box client writes must use strict apply")
		}
		return failedSingboxSummary("client apply failed")
	}))
	base := "/api/inbounds/" + strconv.FormatInt(inbound.ID, 10) + "/clients/" + strconv.FormatInt(client.ID, 10)

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
		want   string
	}{
		{name: "update", method: http.MethodPut, path: base, body: `{"email":"new@example.com","enabled":true}`, want: `"client":`},
		{name: "toggle", method: http.MethodPatch, path: base + "/enabled", body: `{"enabled":false}`, want: `"client":`},
		{name: "delete", method: http.MethodDelete, path: base, body: ``, want: `"status":"deleted"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			resp := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, body)
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			router.ServeHTTP(resp, req)
			if resp.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
			}
			for _, want := range []string{tc.want, `"applied":false`, `"singbox":`, `"detail":"client apply failed"`} {
				if !strings.Contains(resp.Body.String(), want) {
					t.Fatalf("response missing %q: %s", want, resp.Body.String())
				}
			}
		})
	}
}

func TestOutboundAndRoutingWritesReportSingboxApplyFailure(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21004, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(web.WithStore(store), web.WithXrayController(&fakeXrayController{}), web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
		if !strict {
			t.Fatal("sing-box outbound/routing writes must use strict apply")
		}
		return failedSingboxSummary("shared apply failed")
	}))

	outResp := httptest.NewRecorder()
	outReq := httptest.NewRequest(http.MethodPost, "/api/outbounds", bytes.NewReader([]byte(`{"tag":"singbox-hy2-out","protocol":"hysteria2","address":"127.0.0.1","port":443,"password":"secret"}`)))
	outReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(outResp, outReq)
	if outResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", outResp.Code, outResp.Body.String())
	}
	for _, want := range []string{`"outbound":`, `"singbox":`, `"applied":false`, `"detail":"shared apply failed"`} {
		if !strings.Contains(outResp.Body.String(), want) {
			t.Fatalf("outbound response missing %q: %s", want, outResp.Body.String())
		}
	}

	ruleResp := httptest.NewRecorder()
	rulePayload := `{"inbound_tag":"` + db.GeneratedInboundTag(inbound) + `","outbound_id":1,"outbound_tag":"direct","enabled":true}`
	ruleReq := httptest.NewRequest(http.MethodPost, "/api/routing-rules", strings.NewReader(rulePayload))
	ruleReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(ruleResp, ruleReq)
	if ruleResp.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", ruleResp.Code, ruleResp.Body.String())
	}
	for _, want := range []string{`"rule":`, `"singbox":`, `"applied":false`, `"detail":"shared apply failed"`} {
		if !strings.Contains(ruleResp.Body.String(), want) {
			t.Fatalf("routing response missing %q: %s", want, ruleResp.Body.String())
		}
	}
}

func TestCoreWriteApplyScopeDoesNotApplyUnrelatedCore(t *testing.T) {
	t.Run("singbox client only", func(t *testing.T) {
		store, err := db.Open(context.Background(), ":memory:")
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		defer store.Close()
		inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21030, Network: "udp", Security: "tls"})
		if err != nil {
			t.Fatalf("create inbound: %v", err)
		}
		xrayCtrl := &fakeXrayController{}
		var singboxCalls int
		router := web.NewRouter(web.WithStore(store), web.WithXrayController(xrayCtrl), web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
			singboxCalls++
			return web.SingboxApplySummary{Applied: true, Service: "sing-box", ConfigPath: "/etc/migate/cores/sing-box.json", CommandsExecuted: []string{"sing-box check"}}
		}))

		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients", strings.NewReader(`{"email":"hy2@example.com","password":"secret"}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
		}
		if xrayCtrl.applyCalls != 0 {
			t.Fatalf("expected no xray apply for sing-box client write, got %d", xrayCtrl.applyCalls)
		}
		if singboxCalls != 1 {
			t.Fatalf("expected sing-box apply once, got %d", singboxCalls)
		}
		if strings.Contains(resp.Body.String(), `"xray":`) || !strings.Contains(resp.Body.String(), `"singbox":`) {
			t.Fatalf("unexpected core apply response: %s", resp.Body.String())
		}
	})

	t.Run("xray inbound only", func(t *testing.T) {
		store, err := db.Open(context.Background(), ":memory:")
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		defer store.Close()
		xrayCtrl := &fakeXrayController{}
		var singboxCalls int
		router := web.NewRouter(web.WithStore(store), web.WithXrayController(xrayCtrl), web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
			singboxCalls++
			return web.SingboxApplySummary{Applied: true, Service: "sing-box", ConfigPath: "/etc/migate/cores/sing-box.json", CommandsExecuted: []string{"sing-box check"}}
		}))

		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/inbounds", strings.NewReader(`{"remark":"vless","protocol":"vless","port":24430,"network":"tcp","security":"none"}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
		}
		if xrayCtrl.applyCalls != 1 {
			t.Fatalf("expected xray apply once, got %d", xrayCtrl.applyCalls)
		}
		if singboxCalls != 0 {
			t.Fatalf("expected no sing-box apply for xray inbound write, got %d", singboxCalls)
		}
		if !strings.Contains(resp.Body.String(), `"xray":`) || strings.Contains(resp.Body.String(), `"singbox":`) {
			t.Fatalf("unexpected core apply response: %s", resp.Body.String())
		}
	})
}

func TestOutboundAndRoutingApplyScopeFollowsAffectedCores(t *testing.T) {
	t.Run("outbound create with xray inbound only returns xray result", func(t *testing.T) {
		store, err := db.Open(context.Background(), ":memory:")
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		defer store.Close()
		if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "vless", Protocol: "vless", Port: 24431, Network: "tcp", Security: "none"}); err != nil {
			t.Fatalf("create inbound: %v", err)
		}
		xrayCtrl := &fakeXrayController{}
		var singboxCalls int
		router := web.NewRouter(web.WithStore(store), web.WithXrayController(xrayCtrl), web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
			singboxCalls++
			return web.SingboxApplySummary{Applied: true, Service: "sing-box", ConfigPath: "/etc/migate/cores/sing-box.json", CommandsExecuted: []string{"sing-box check"}}
		}))

		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/outbounds", strings.NewReader(`{"tag":"proxy","protocol":"socks","address":"127.0.0.1","port":1080}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
		}
		if xrayCtrl.applyCalls != 1 || singboxCalls != 0 {
			t.Fatalf("unexpected apply calls: xray=%d singbox=%d", xrayCtrl.applyCalls, singboxCalls)
		}
		if !strings.Contains(resp.Body.String(), `"xray":`) || strings.Contains(resp.Body.String(), `"singbox":`) {
			t.Fatalf("unexpected core apply response: %s", resp.Body.String())
		}
	})

	t.Run("routing create for singbox inbound only returns singbox result", func(t *testing.T) {
		store, err := db.Open(context.Background(), ":memory:")
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		defer store.Close()
		inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21031, Network: "udp", Security: "tls"})
		if err != nil {
			t.Fatalf("create inbound: %v", err)
		}
		xrayCtrl := &fakeXrayController{}
		var singboxCalls int
		router := web.NewRouter(web.WithStore(store), web.WithXrayController(xrayCtrl), web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
			singboxCalls++
			return web.SingboxApplySummary{Applied: true, Service: "sing-box", ConfigPath: "/etc/migate/cores/sing-box.json", CommandsExecuted: []string{"sing-box check"}}
		}))

		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/routing-rules", strings.NewReader(`{"inbound_tag":"`+db.GeneratedInboundTag(inbound)+`","outbound_id":1,"outbound_tag":"direct","enabled":true}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", resp.Code, resp.Body.String())
		}
		if xrayCtrl.applyCalls != 0 || singboxCalls != 1 {
			t.Fatalf("unexpected apply calls: xray=%d singbox=%d", xrayCtrl.applyCalls, singboxCalls)
		}
		if strings.Contains(resp.Body.String(), `"xray":`) || !strings.Contains(resp.Body.String(), `"singbox":`) {
			t.Fatalf("unexpected core apply response: %s", resp.Body.String())
		}
	})
}

type fixedWebSingboxRuntime struct{}

func (fixedWebSingboxRuntime) Capability(ctx context.Context) singbox.Capability {
	return singbox.Capability{Checked: true}
}

type apiTestSingboxProbe struct {
	installed    bool
	managed      bool
	service      string
	status       string
	configExists bool
	configValid  bool
}

type fakeWebXrayProbe struct {
	installed    bool
	version      string
	managed      bool
	status       string
	configExists bool
	configValid  bool
	checkErr     error
	logs         []string
}

func (p fakeWebXrayProbe) IsInstalled(ctx context.Context) bool { return p.installed }
func (p fakeWebXrayProbe) Version(ctx context.Context) string {
	if p.version != "" {
		return p.version
	}
	return "Xray 26.3.27"
}
func (p fakeWebXrayProbe) Managed(ctx context.Context) bool { return p.managed }
func (p fakeWebXrayProbe) Status(ctx context.Context) string {
	if p.status != "" {
		return p.status
	}
	return "running"
}
func (p fakeWebXrayProbe) ConfigExists(path string) bool { return p.configExists }
func (p fakeWebXrayProbe) CheckConfig(ctx context.Context, path string) error {
	if p.checkErr != nil {
		return p.checkErr
	}
	if p.configValid {
		return nil
	}
	return errors.New("invalid config")
}
func (p fakeWebXrayProbe) RecentLogs(ctx context.Context, service string, lines int) []string {
	return p.logs
}

func mustListInbounds(t *testing.T, store web.Store) []db.Inbound {
	t.Helper()
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	return inbounds
}

func mustListOutbounds(t *testing.T, store web.Store) []db.Outbound {
	t.Helper()
	outbounds, err := store.ListOutbounds(context.Background())
	if err != nil {
		t.Fatalf("list outbounds: %v", err)
	}
	return outbounds
}

func mustListRules(t *testing.T, store web.Store) []db.RoutingRule {
	t.Helper()
	rules, err := store.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	return rules
}

func (p apiTestSingboxProbe) IsInstalled() bool { return p.installed }
func (p apiTestSingboxProbe) Version() (string, error) {
	return "sing-box 1.13.13", nil
}
func (p apiTestSingboxProbe) Management() singbox.ManagementStatus {
	service := p.service
	if service == "" {
		service = "sing-box"
	}
	return singbox.ManagementStatus{Managed: p.managed, Service: service}
}
func (p apiTestSingboxProbe) Status() string {
	if p.status == "" {
		return "stopped"
	}
	return p.status
}
func (p apiTestSingboxProbe) ConfigExists(path string) bool { return p.configExists }
func (p apiTestSingboxProbe) CheckConfig(path string) error {
	if p.configValid {
		return nil
	}
	return errors.New("invalid")
}
func (p apiTestSingboxProbe) MemoryRSS() int64       { return 0 }
func (p apiTestSingboxProbe) Uptime() string         { return "" }
func (p apiTestSingboxProbe) ActiveConnections() int { return 0 }
func (p apiTestSingboxProbe) RecentLogs(service string, lines int) []string {
	return []string{"sing-box started"}
}

func TestCreateInboundAPIStoresInbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"remark":"新入口","protocol":"trojan","port":9443,"network":"tcp","security":"tls"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"remark":"新入口"`, `"protocol":"trojan"`, `"port":9443`, `"enabled":true`} {
		if !strings.Contains(body, want) {
			t.Fatalf("create response missing %q: %s", want, body)
		}
	}

	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || inbounds[0].Remark != "新入口" || inbounds[0].Protocol != "trojan" {
		t.Fatalf("inbound was not persisted: %+v", inbounds)
	}
}

func TestCreateInboundAPIStoresXHTTPFieldsFromJSON(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"remark":"XHTTP入口","protocol":"vless","port":30040,"network":"xhttp","security":"reality","reality_dest":"www.cloudflare.com:443","reality_server_names":"www.cloudflare.com","xhttp_path":"/migate-xhttp","xhttp_mode":"stream-one"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"network":"xhttp"`, `"xhttp_path":"/migate-xhttp"`, `"xhttp_mode":"stream-one"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("create response missing %q: %s", want, body)
		}
	}

	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || inbounds[0].XHTTPPath != "/migate-xhttp" || inbounds[0].XHTTPMode != "stream-one" {
		t.Fatalf("JSON API did not persist xhttp fields: %+v", inbounds)
	}
}

func TestCreateInboundAPIRejectsUnsupportedProtocol(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"remark":"unsupported","protocol":"` + join("open", "vpn") + `","port":1194,"network":"udp"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "unsupported protocol") {
		t.Fatalf("expected unsupported protocol body, got: %s", response.Body.String())
	}
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 0 {
		t.Fatalf("unsupported inbound should not persist: %+v", inbounds)
	}
}

func TestCreateClientAPIStoresClientUnderInbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "vless", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"email":"client@example.com"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"email":"client@example.com"`, `"enabled":true`} {
		if !strings.Contains(body, want) {
			t.Fatalf("create client response missing %q: %s", want, body)
		}
	}
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(inbounds) != 1 || len(inbounds[0].Clients) != 1 || inbounds[0].Clients[0].Email != "client@example.com" {
		t.Fatalf("client was not persisted under inbound: %+v", inbounds)
	}
}

func TestCreateClientAPIRejectsUnknownInbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	payload := []byte(`{"email":"ghost@example.com"}`)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds/999/clients", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", response.Code, response.Body.String())
	}
}

func TestXrayConfigAPIProducesPreviewFromStoredInbounds(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "vless", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "client@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/xray/config", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"inbounds"`, `"outbounds"`, `"protocol":"vless"`, `"protocol":"freedom"`, `"email":"` + client.StatsKey + `"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("xray config response missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"systemctl", "restart", "write", join("open", "vpn"), "egress"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("xray config preview leaked side-effect/heavy marker %q: %s", forbidden, body)
		}
	}
}

func TestXrayConfigAPIRendersAdvancedRoutingFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "edge", Protocol: "vless", Port: 443, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	if _, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "client@example.com"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundTag: "edge", OutboundID: 2, OutboundTag: "blocked", Domain: "geosite:ads,example.com", IP: "geoip:private\n8.8.8.8", RuleSet: "geosite-category-ads-all", Protocol: "bittorrent,dns", Enabled: true,
	}); err != nil {
		t.Fatalf("create routing rule: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/config", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"domain":["geosite:ads","example.com"]`, `"ip":["geoip:private","8.8.8.8"]`, `"protocol":["bittorrent","dns"]`} {
		if !strings.Contains(body, want) {
			t.Fatalf("xray config response missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, `"ruleSet"`) {
		t.Fatalf("xray config must not emit unsupported ruleSet field: %s", body)
	}
}

func TestSingboxConfigAPISeparatesDiskConfigAndGeneratedPreview(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21001, Network: "udp", Security: "tls"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/singbox/config", nil))

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected missing disk config 404, got %d: %s", response.Code, response.Body.String())
	}

	preview := httptest.NewRecorder()
	router.ServeHTTP(preview, httptest.NewRequest(http.MethodGet, "/api/singbox/config/preview", nil))
	if preview.Code != http.StatusOK {
		t.Fatalf("expected preview 200, got %d: %s", preview.Code, preview.Body.String())
	}
	body := preview.Body.String()
	for _, want := range []string{`"in_sync":false`, `"reason":"disk_missing"`, `"disk":`, `"error":"read_failed"`, `"generated":`, `"type":"hysteria2"`, `"listen_port":21001`} {
		if !strings.Contains(body, want) {
			t.Fatalf("singbox config preview missing %q: %s", want, body)
		}
	}
}

func TestConfigValidateAPIsReturnStructuredResults(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21001, Network: "udp", Security: "tls"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))

	xrayResp := httptest.NewRecorder()
	router.ServeHTTP(xrayResp, httptest.NewRequest(http.MethodGet, "/api/xray/validate", nil))
	if xrayResp.Code != http.StatusOK {
		t.Fatalf("expected xray validate 200, got %d: %s", xrayResp.Code, xrayResp.Body.String())
	}
	for _, want := range []string{`"target":"xray"`, `"valid":true`, `"hysteria2 is handled by sing-box"`} {
		if !strings.Contains(xrayResp.Body.String(), want) {
			t.Fatalf("xray validate response missing %q: %s", want, xrayResp.Body.String())
		}
	}

	singboxResp := httptest.NewRecorder()
	router.ServeHTTP(singboxResp, httptest.NewRequest(http.MethodGet, "/api/singbox/validate", nil))
	if singboxResp.Code != http.StatusOK {
		t.Fatalf("expected singbox validate 200, got %d: %s", singboxResp.Code, singboxResp.Body.String())
	}
	for _, want := range []string{`"target":"singbox"`, `"valid":true`, `"inbounds":1`} {
		if !strings.Contains(singboxResp.Body.String(), want) {
			t.Fatalf("singbox validate response missing %q: %s", want, singboxResp.Body.String())
		}
	}
}

func TestConfigValidateAPIReturnsStructuredInvalidResult(t *testing.T) {
	router := web.NewRouter()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/validate", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected validate API to return structured 200 response, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"target":"xray"`, `"valid":false`, `"error":"store_unavailable"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("validate response missing %q: %s", want, response.Body.String())
		}
	}
}

func TestSubscriptionEndpointReturnsClientShareLink(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "主入口", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "sam@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	if client.SubscriptionToken == "" {
		t.Fatal("created client should have independent subscription token")
	}
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{"vless://" + client.UUID + "@panel.example.com:443", "type=tcp", "security=reality", "sam%40example.com"} {
		if !strings.Contains(body, want) {
			t.Fatalf("subscription missing %q: %s", want, body)
		}
	}
}

func TestSubscriptionEndpointRejectsClientUUIDFallback(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "legacy", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "legacy@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.UUID, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected UUID subscription link to be rejected, got %d: %s", response.Code, response.Body.String())
	}
}

func TestSubscriptionEndpointUsesConfiguredPublicHostOverRequestHost(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "host", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "host@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store), web.WithPublicHost("public.example.com"))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "evil.example.net"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "@public.example.com:443") {
		t.Fatalf("subscription should use configured public host, got %s", body)
	}
	if strings.Contains(body, "evil.example.net") {
		t.Fatalf("malicious Host header leaked into subscription: %s", body)
	}
}

func TestSubscriptionEndpointNormalizesPublicHostURL(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "public-url", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "public-url@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store), web.WithPublicHost("https://public.example.com/panel"))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "evil.example.net"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "@public.example.com:443") || strings.Contains(body, "SERVER_IP") {
		t.Fatalf("public_host URL should normalize to hostname, got %s", body)
	}
}

func TestSubscriptionEndpointStripsPublicHostPort(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "public-port", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "public-port@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store), web.WithPublicHost("public.example.com:8443"))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "evil.example.net"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "@public.example.com:443") || strings.Contains(body, "SERVER_IP") || strings.Contains(body, ":8443:443") {
		t.Fatalf("public_host domain:port should normalize to hostname before appending inbound port, got %s", body)
	}
}

func TestSubscriptionEndpointSanitizesHostFallback(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "host-fallback", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "fallback@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "evil.example.com/path"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if strings.Contains(body, "evil.example.com") || !strings.Contains(body, "@SERVER_IP:443") {
		t.Fatalf("invalid Host fallback should not leak into subscription: %s", body)
	}
}

func TestSubscriptionEndpointStripsPanelPortBeforeAppendingInboundPort(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "主入口", Protocol: "vless", Port: 8443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "sam@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "127.0.0.1:9999"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	want := "vless://" + client.UUID + "@127.0.0.1:8443"
	if !strings.Contains(body, want) {
		t.Fatalf("subscription should strip panel port before appending inbound port, want %q got %s", want, body)
	}
	if strings.Contains(body, "127.0.0.1:9999:8443") {
		t.Fatalf("subscription contains double port: %s", body)
	}
}

func TestSubscriptionEndpointStripsDomainPanelPortBeforeAppendingInboundPort(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "主入口", Protocol: "vless", Port: 8443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "sam@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "panel.example.com:9999"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	want := "vless://" + client.UUID + "@panel.example.com:8443"
	if !strings.Contains(body, want) {
		t.Fatalf("subscription should strip domain panel port before appending inbound port, want %q got %s", want, body)
	}
	if strings.Contains(body, "SERVER_IP") || strings.Contains(body, "panel.example.com:9999:8443") {
		t.Fatalf("subscription contains invalid host fallback or double port: %s", body)
	}
}

func TestSubscriptionEndpointBracketsIPv6Host(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "ipv6", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "ipv6@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "[2001:db8::1]:9999"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	want := "vless://" + client.UUID + "@[2001:db8::1]:443"
	if !strings.Contains(body, want) {
		t.Fatalf("IPv6 subscription host should be bracketed, want %q got %s", want, body)
	}
	if strings.Contains(body, "@2001:db8::1:443") {
		t.Fatalf("IPv6 subscription host is not bracketed: %s", body)
	}
}

func TestSubscriptionHysteria2DefaultGeneratedTLSLink(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark:   "hy2",
		Protocol: "hysteria2",
		Port:     21001,
		Network:  "udp",
		Security: "tls",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "hy2"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{"hysteria2://" + client.UUID + "@panel.example.com:21001", "security=tls", "insecure=1"} {
		if !strings.Contains(body, want) {
			t.Fatalf("hysteria2 default generated TLS link missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"hy2://", "allowInsecure=1"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("hysteria2 subscription must use client-compatible URI params, found %q in %s", forbidden, body)
		}
	}
}

func TestStatsMarksSingBoxClientTrafficAsWaitingBeforeFirstSample(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21001, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "hy2-user"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/stats?detail=1", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"protocol":"hysteria2"`, `"traffic_status":"waiting"`, fmt.Sprintf(`"id":%d`, client.ID)} {
		if !strings.Contains(body, want) {
			t.Fatalf("sing-box stats response missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, `"traffic_stats_note"`) {
		t.Fatalf("waiting sing-box stats should not expose legacy unsupported note: %s", body)
	}
}

type fixedStatsClient struct {
	stats map[string]*xray.ClientStats
	calls *int
}

func (c fixedStatsClient) QueryAllStats(ctx context.Context) (map[string]*xray.ClientStats, error) {
	if c.calls != nil {
		(*c.calls)++
	}
	return c.stats, nil
}

func (c fixedStatsClient) QueryTrafficStats(ctx context.Context) ([]xray.TrafficStat, error) {
	if c.calls != nil {
		(*c.calls)++
	}
	result := make([]xray.TrafficStat, 0, len(c.stats))
	for _, stat := range c.stats {
		result = append(result, xray.TrafficStat{Engine: "xray", ScopeType: "client", ScopeKey: stat.Email, Uplink: stat.Uplink, Downlink: stat.Downlink})
	}
	return result, nil
}

func (c fixedStatsClient) Close() error { return nil }

func seedClientTraffic(t *testing.T, store *db.Store, client db.Client, up, down int64) {
	t.Helper()
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-20 * time.Second)
	raw := func(rawUp, rawDown int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: rawUp, RawDown: rawDown, Status: "ok"}}
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(100, 100), t0); err != nil {
		t.Fatalf("seed baseline traffic: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(100+up, 100+down), t0.Add(10*time.Second)); err != nil {
		t.Fatalf("seed increment traffic: %v", err)
	}
}

func TestStatsAPIUsesRealtimeTrafficAsCurrentWhenAvailable(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "xray", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "sam@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	seedClientTraffic(t, store, client, 1234, 5678)

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/stats?detail=1", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"traffic_up":1234`, `"traffic_down":5678`, `"traffic_total":6912`, `"xray_up":1334`, `"xray_down":5778`, `"traffic_stats_source":"migate"`, `"traffic_status":"ok"`, `"rate_up":123.4`, `"rate_down":567.8`} {
		if !strings.Contains(body, want) {
			t.Fatalf("stats response missing %q: %s", want, body)
		}
	}
}

func TestStatsAPIDefaultIsSummaryOnlyAndCached(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "xray", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "sam@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	seedClientTraffic(t, store, client, 12, 34)

	calls := 0
	router := web.NewRouter(web.WithStore(store), web.WithStatsClient(fixedStatsClient{calls: &calls}))
	for i := 0; i < 2; i++ {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
		}
		body := response.Body.String()
		for _, want := range []string{`"clients":1`, `"traffic_up":12`, `"traffic_down":34`, `"traffic_total":46`} {
			if !strings.Contains(body, want) {
				t.Fatalf("summary stats response missing %q: %s", want, body)
			}
		}
		if strings.Contains(body, `"client_details"`) {
			t.Fatalf("default stats response should omit client_details: %s", body)
		}
	}
	if calls != 0 {
		t.Fatalf("stats response should use stored traffic states without querying live stats, got %d calls", calls)
	}

	detail := httptest.NewRecorder()
	router.ServeHTTP(detail, httptest.NewRequest(http.MethodGet, "/api/stats?detail=1", nil))
	if detail.Code != http.StatusOK {
		t.Fatalf("expected detail 200, got %d: %s", detail.Code, detail.Body.String())
	}
	if !strings.Contains(detail.Body.String(), `"client_details"`) {
		t.Fatalf("detail stats response should include client_details: %s", detail.Body.String())
	}
}

func TestDashboardSummaryAPIReportsHealthAndValidationSnapshot(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "xray", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	now := time.Now().Unix()
	activeClient, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "active@example.com"})
	if err != nil {
		t.Fatalf("create active client: %v", err)
	}
	if _, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "expired@example.com", ExpiryAt: now - 60}); err != nil {
		t.Fatalf("create expired client: %v", err)
	}
	limitedClient, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "limited@example.com", TrafficLimit: 1})
	if err != nil {
		t.Fatalf("create limited client: %v", err)
	}
	seedClientTraffic(t, store, activeClient, 10, 20)
	seedClientTraffic(t, store, limitedClient, 1, 0)
	outbound, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "proxy", Protocol: "socks", Address: "127.0.0.1", Port: 1080})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}
	if _, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{Domain: "example.com", OutboundID: outbound.ID, OutboundTag: "proxy", Enabled: true}); err != nil {
		t.Fatalf("create routing rule: %v", err)
	}
	if err := store.ApplyTrafficRawStats(context.Background(), []db.TrafficRawStat{
		{Engine: "xray", ScopeType: "outbound", ScopeKey: db.GeneratedOutboundTag(db.CoreXray, outbound.ID, outbound.Tag), RawUp: 100, RawDown: 50, Status: "ok"},
	}, time.Unix(100, 0)); err != nil {
		t.Fatalf("seed outbound traffic baseline: %v", err)
	}
	if err := store.ApplyTrafficRawStats(context.Background(), []db.TrafficRawStat{
		{Engine: "xray", ScopeType: "outbound", ScopeKey: db.GeneratedOutboundTag(db.CoreXray, outbound.ID, outbound.Tag), RawUp: 120, RawDown: 70, Status: "ok"},
	}, time.Unix(110, 0)); err != nil {
		t.Fatalf("seed outbound traffic increment: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/dashboard/summary", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`"counts"`,
		`"clients":3`,
		`"clients_active":1`,
		`"clients_expired":1`,
		`"clients_limited":1`,
		`"outbounds":4`,
		`"routing_rules":1`,
		`"protocols":{"vless":1}`,
		`"validation"`,
		`"target":"xray"`,
		`"target":"singbox"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard summary missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{`"traffic"`, `"traffic_rates"`, `"traffic_status"`, `"last_sampled_at"`, `"traffic_series"`, `"outbound_traffic"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("dashboard summary should not include %q: %s", forbidden, body)
		}
	}
}

func TestDashboardSummaryDoesNotRegressBelowStoredTraffic(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "xray", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "limited@example.com", TrafficLimit: 120})
	if err != nil {
		t.Fatalf("create limited client: %v", err)
	}
	seedClientTraffic(t, store, client, 100, 50)

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/dashboard/summary", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`"clients_active":0`,
		`"clients_limited":1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard summary missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{`"traffic"`, `"traffic_series"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("dashboard summary should not include %q: %s", forbidden, body)
		}
	}
}

func TestTrafficAPIsKeepStoredSourceWhenStoredTrafficIsHigherThanRealtime(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "xray-stored", Protocol: "vless", Port: 8443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "stored@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	seedClientTraffic(t, store, client, 100, 50)

	router := web.NewRouter(web.WithStore(store))

	statsResponse := httptest.NewRecorder()
	router.ServeHTTP(statsResponse, httptest.NewRequest(http.MethodGet, "/api/stats?detail=1", nil))
	if statsResponse.Code != http.StatusOK {
		t.Fatalf("expected stats 200, got %d: %s", statsResponse.Code, statsResponse.Body.String())
	}
	statsBody := statsResponse.Body.String()
	for _, want := range []string{
		`"traffic_up":100`,
		`"traffic_down":50`,
		`"traffic_total":150`,
		`"up":100`,
		`"down":50`,
		`"xray_up":200`,
		`"xray_down":150`,
		`"traffic_stats_source":"migate"`,
		`"traffic_status":"ok"`,
	} {
		if !strings.Contains(statsBody, want) {
			t.Fatalf("stats response missing %q: %s", want, statsBody)
		}
	}

	inboundsResponse := httptest.NewRecorder()
	router.ServeHTTP(inboundsResponse, httptest.NewRequest(http.MethodGet, "/api/inbounds", nil))
	if inboundsResponse.Code != http.StatusOK {
		t.Fatalf("expected inbounds 200, got %d: %s", inboundsResponse.Code, inboundsResponse.Body.String())
	}
	inboundsBody := inboundsResponse.Body.String()
	for _, want := range []string{
		`"traffic_up":100`,
		`"traffic_down":50`,
		`"traffic_total":150`,
		`"traffic_stats_source":"migate"`,
		`"traffic_status":"ok"`,
		fmt.Sprintf(`"%d":{"up":100,"down":50`, client.ID),
		`"status":"ok"`,
	} {
		if !strings.Contains(inboundsBody, want) {
			t.Fatalf("inbounds response missing %q: %s", want, inboundsBody)
		}
	}

	trafficRefresh := httptest.NewRecorder()
	router.ServeHTTP(trafficRefresh, httptest.NewRequest(http.MethodGet, "/api/inbounds?refresh=traffic", nil))
	if trafficRefresh.Code != http.StatusOK {
		t.Fatalf("expected traffic refresh 200, got %d: %s", trafficRefresh.Code, trafficRefresh.Body.String())
	}
	refreshBody := trafficRefresh.Body.String()
	for _, want := range []string{
		`"traffic_up":100`,
		`"traffic_down":50`,
		`"traffic_total":150`,
		`"clients":[`,
		fmt.Sprintf(`"%d":{"up":100,"down":50`, client.ID),
	} {
		if !strings.Contains(refreshBody, want) {
			t.Fatalf("traffic refresh response missing %q: %s", want, refreshBody)
		}
	}
	for _, forbidden := range []string{`"reality_private_key"`, `"tls_cert_file"`, `"hy2_obfs_password"`} {
		if strings.Contains(refreshBody, forbidden) {
			t.Fatalf("traffic refresh response should omit full config field %q: %s", forbidden, refreshBody)
		}
	}
}

func TestTrafficSeriesAPIUsesTrafficSamples(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "series", Protocol: "vless", Port: 8444, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "series@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t0 := time.Now().UTC().Add(-time.Hour)
	raw := func(up, down int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: up, RawDown: down, Status: "ok"}}
	}
	if err := store.ApplyTrafficRawStats(context.Background(), raw(10, 20), t0); err != nil {
		t.Fatalf("baseline sample: %v", err)
	}
	if err := store.ApplyTrafficRawStats(context.Background(), raw(30, 60), t0.Add(time.Minute)); err != nil {
		t.Fatalf("increment sample: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/traffic/series?scope_type=client", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"series"`, `"time"`, `"up":20`, `"down":40`, `"rate_up":0.3333333333333333`} {
		if !strings.Contains(body, want) {
			t.Fatalf("traffic series response missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, client.StatsKey) {
		t.Fatalf("traffic series should be aggregated by time, not raw client key: %s", body)
	}
}

func TestTrafficSeriesAPIFiltersExpectedEnginesAndAggregatesByTime(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	xrayInbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "xray", Protocol: "vless", Port: 18445, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create xray inbound: %v", err)
	}
	singboxInbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 18446, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create singbox inbound: %v", err)
	}
	xrayClient, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: xrayInbound.ID, Email: "xray-series"})
	if err != nil {
		t.Fatalf("create xray client: %v", err)
	}
	singboxClient, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: singboxInbound.ID, Email: "hy2-series"})
	if err != nil {
		t.Fatalf("create singbox client: %v", err)
	}
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{
		{Engine: "xray", ScopeType: "client", ScopeKey: xrayClient.StatsKey, RawUp: 100, RawDown: 100, Status: "ok"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: xrayClient.StatsKey, RawUp: 1000, RawDown: 1000, Status: "ok"},
		{Engine: "xray", ScopeType: "client", ScopeKey: singboxClient.StatsKey, RawUp: 2000, RawDown: 2000, Status: "ok"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: singboxClient.StatsKey, RawUp: 200, RawDown: 200, Status: "ok"},
	}, t0); err != nil {
		t.Fatalf("baseline samples: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{
		{Engine: "xray", ScopeType: "client", ScopeKey: xrayClient.StatsKey, RawUp: 110, RawDown: 120, Status: "ok"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: xrayClient.StatsKey, RawUp: 1100, RawDown: 1200, Status: "ok"},
		{Engine: "xray", ScopeType: "client", ScopeKey: singboxClient.StatsKey, RawUp: 2100, RawDown: 2200, Status: "ok"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: singboxClient.StatsKey, RawUp: 230, RawDown: 240, Status: "ok"},
	}, t0.Add(time.Minute)); err != nil {
		t.Fatalf("increment samples: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/traffic/series?scope_type=client&limit=20", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"up":40`) || !strings.Contains(body, `"down":60`) {
		t.Fatalf("expected series to aggregate only xray expected delta 10/20 plus singbox expected delta 30/40, got %s", body)
	}
	for _, forbidden := range []string{xrayClient.StatsKey, singboxClient.StatsKey, `"up":140`, `"down":260`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("series leaked unfiltered or unaggregated sample %q: %s", forbidden, body)
		}
	}
}

func TestTrafficSeriesAPIUsesExpectedEngineFilter(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	xrayInbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "xray", Protocol: "vless", Port: 18448, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create xray inbound: %v", err)
	}
	singboxInbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 18449, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create singbox inbound: %v", err)
	}
	xrayClient, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: xrayInbound.ID, Email: "xray-dashboard-series"})
	if err != nil {
		t.Fatalf("create xray client: %v", err)
	}
	singboxClient, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: singboxInbound.ID, Email: "hy2-dashboard-series"})
	if err != nil {
		t.Fatalf("create singbox client: %v", err)
	}
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{
		{Engine: "xray", ScopeType: "client", ScopeKey: xrayClient.StatsKey, RawUp: 100, RawDown: 100, Status: "ok"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: xrayClient.StatsKey, RawUp: 1000, RawDown: 1000, Status: "ok"},
		{Engine: "xray", ScopeType: "client", ScopeKey: singboxClient.StatsKey, RawUp: 2000, RawDown: 2000, Status: "ok"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: singboxClient.StatsKey, RawUp: 200, RawDown: 200, Status: "ok"},
	}, t0); err != nil {
		t.Fatalf("baseline samples: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{
		{Engine: "xray", ScopeType: "client", ScopeKey: xrayClient.StatsKey, RawUp: 110, RawDown: 120, Status: "ok"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: xrayClient.StatsKey, RawUp: 1100, RawDown: 1200, Status: "ok"},
		{Engine: "xray", ScopeType: "client", ScopeKey: singboxClient.StatsKey, RawUp: 2100, RawDown: 2200, Status: "ok"},
		{Engine: "singbox", ScopeType: "client", ScopeKey: singboxClient.StatsKey, RawUp: 230, RawDown: 240, Status: "ok"},
	}, t0.Add(time.Minute)); err != nil {
		t.Fatalf("increment samples: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	series := httptest.NewRecorder()
	router.ServeHTTP(series, httptest.NewRequest(http.MethodGet, "/api/traffic/series?scope_type=client&limit=240", nil))
	if series.Code != http.StatusOK {
		t.Fatalf("expected series 200, got %d: %s", series.Code, series.Body.String())
	}
	var seriesBody struct {
		Series []struct {
			Up   int64 `json:"up"`
			Down int64 `json:"down"`
		} `json:"series"`
	}
	if err := json.NewDecoder(series.Body).Decode(&seriesBody); err != nil {
		t.Fatalf("decode series: %v", err)
	}
	if len(seriesBody.Series) != 2 {
		t.Fatalf("expected two traffic series points, got %+v", seriesBody.Series)
	}
	last := seriesBody.Series[len(seriesBody.Series)-1]
	if last.Up != 40 || last.Down != 60 {
		t.Fatalf("expected traffic series to avoid cross-engine double count, got %+v", seriesBody.Series)
	}
}

func TestTrafficSeriesLimitUpperBoundIsExplicit(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "limit", Protocol: "vless", Port: 18450, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "limit-series"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 100, RawDown: 100, Status: "ok"}}, t0); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: 101, RawDown: 102, Status: "ok"}}, t0.Add(time.Minute)); err != nil {
		t.Fatalf("increment: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	ok := httptest.NewRecorder()
	router.ServeHTTP(ok, httptest.NewRequest(http.MethodGet, "/api/traffic/series?scope_type=client&limit=2000", nil))
	if ok.Code != http.StatusOK {
		t.Fatalf("expected legal upper limit 2000 to pass, got %d: %s", ok.Code, ok.Body.String())
	}
	if !strings.Contains(ok.Body.String(), `"series"`) || !strings.Contains(ok.Body.String(), `"up":1`) {
		t.Fatalf("expected legal upper limit response to include series point, got %s", ok.Body.String())
	}
	tooHigh := httptest.NewRecorder()
	router.ServeHTTP(tooHigh, httptest.NewRequest(http.MethodGet, "/api/traffic/series?scope_type=client&limit=2001", nil))
	if tooHigh.Code != http.StatusBadRequest || !strings.Contains(tooHigh.Body.String(), "invalid_limit") {
		t.Fatalf("expected over-limit request to fail clearly, got %d: %s", tooHigh.Code, tooHigh.Body.String())
	}
}

func TestInboundsAPIAnnotatesLiveTrafficPerInboundAndClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "xray-live", Protocol: "vless", Port: 8443, Network: "tcp", Security: "reality"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "live@example.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	seedClientTraffic(t, store, client, 222, 333)

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/inbounds", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"traffic_up":222`, `"traffic_down":333`, `"traffic_total":555`, `"traffic_stats_source":"migate"`, `"traffic_status":"ok"`, fmt.Sprintf(`"%d":{"up":222,"down":333`, client.ID), `"status":"ok"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("inbounds response missing %q: %s", want, body)
		}
	}
}

func TestSubscriptionVLESSXHTTPRealityOmitsVisionFlow(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark:             "xhttp",
		Protocol:           "vless",
		Port:               40003,
		Network:            "xhttp",
		Security:           "reality",
		XHTTPPath:          "/samge",
		XHTTPMode:          "stream-one",
		RealityPrivateKey:  "uNisYErm5wwrV9t9EP2P3VB0g3CpS5m70bdG7gwShXg",
		RealityServerNames: "www.cloudflare.com",
		RealityPublicKey:   "IXhEpcgnBhIQ6m4DewngNWqDeLl7-ej53nonOtwM_kM",
		RealityShortID:     "00942aa4",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "xhttp"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "103.193.149.217:9999"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{"type=xhttp", "security=reality", "sni=www.cloudflare.com", "pbk=IXhEpcgnBhIQ6m4DewngNWqDeLl7-ej53nonOtwM_kM", "sid=00942aa4", "path=%2Fsamge", "mode=stream-one"} {
		if !strings.Contains(body, want) {
			t.Fatalf("xhttp subscription missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "flow=xtls-rprx-vision") {
		t.Fatalf("VLESS+XHTTP+REALITY subscription must not include TCP Vision flow: %s", body)
	}
}

func TestSubscriptionEndpointRejectsUnknownClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/missing", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", response.Code, response.Body.String())
	}
}

func TestSubscriptionVlessFormat(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "vless-node", Protocol: "vless", Port: 443, Network: "tcp", Security: "reality",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "user1"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	prefix := "vless://" + client.UUID + "@panel.example.com:443?"
	if !strings.HasPrefix(body, prefix) {
		t.Fatalf("vless format mismatch, want prefix %q, got %s", prefix, body)
	}
	if !strings.Contains(body, "type=tcp") {
		t.Fatalf("vless missing type=tcp: %s", body)
	}
	if !strings.Contains(body, "security=reality") {
		t.Fatalf("vless missing security=reality: %s", body)
	}
	if !strings.HasSuffix(body, "#user1") {
		t.Fatalf("vless missing remark fragment: %s", body)
	}
}

func TestSubscriptionVmessReturnsBase64JSON(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "vmess-node", Protocol: "vmess", Port: 8443, Network: "ws", Security: "tls",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "vmess-user", CredentialID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.HasPrefix(body, "vmess://") {
		t.Fatalf("vmess should start with vmess://, got: %s", body)
	}
	// Decode base64 part
	b64 := body[len("vmess://"):]
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Try URL-safe variant
		decoded, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			t.Fatalf("vmess link is not valid base64: %s, error: %v", b64, err)
		}
	}
	var vmessData map[string]interface{}
	if err := json.Unmarshal(decoded, &vmessData); err != nil {
		t.Fatalf("vmess decoded data is not valid JSON: %s, error: %v", string(decoded), err)
	}
	for _, want := range []struct{ k, v string }{
		{"v", "2"}, {"ps", "vmess-user"}, {"add", "panel.example.com"},
		{"id", client.CredentialIDValue()}, {"aid", "0"}, {"scy", "auto"},
		{"net", "ws"}, {"tls", "tls"},
	} {
		if got, ok := vmessData[want.k]; !ok || fmt.Sprint(got) != want.v {
			t.Fatalf("vmess JSON field %q expected %q, got %q (value: %v)", want.k, want.v, got, got)
		}
	}
}

func TestSubscriptionTrojanReturnsTrojanLink(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "trojan-node", Protocol: "trojan", Port: 443, Network: "tcp", Security: "tls",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "trojan-user"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	prefix := "trojan://" + client.UUID + "@panel.example.com:443?"
	if !strings.HasPrefix(body, prefix) {
		t.Fatalf("trojan format mismatch, want prefix %q, got %s", prefix, body)
	}
	if !strings.Contains(body, "security=tls") {
		t.Fatalf("trojan missing security=tls: %s", body)
	}
	if !strings.HasSuffix(body, "#trojan-user") {
		t.Fatalf("trojan missing remark fragment: %s", body)
	}
}

func TestSubscriptionShadowsocksReturnsSSLink(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		UUID: "manual-ss-password", Remark: "ss-node", Protocol: "shadowsocks", Port: 8388, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "ss-用户"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.HasPrefix(body, "ss://") {
		t.Fatalf("shadowsocks should start with ss://, got: %s", body)
	}
	// Verify base64 encoded method:password@host:port
	after := body[len("ss://"):]
	atIdx := strings.Index(after, "@")
	if atIdx < 0 {
		t.Fatalf("ss:// missing @ sign: %s", body)
	}
	encodedCreds := after[:atIdx]
	decoded, err := base64.StdEncoding.DecodeString(encodedCreds)
	if err != nil {
		decoded, err = base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(encodedCreds)
		if err != nil {
			t.Fatalf("ss:// credentials not valid base64: %s, error: %v", encodedCreds, err)
		}
	}
	creds := string(decoded)
	method := inbound.SSMethod
	if method == "" {
		method = "2022-blake3-aes-128-gcm"
	}
	if !strings.Contains(creds, ":") || !strings.Contains(creds, xray.SSInboundPassword(method, inbound.UUID)) {
		t.Fatalf("ss:// decoded credentials %q should contain method:stable inbound password/key", creds)
	}
	if !strings.HasSuffix(body, "#ss-%E7%94%A8%E6%88%B7") {
		t.Fatalf("ss:// missing URL-encoded remark fragment: %s", body)
	}
}

func TestSubscriptionTUICKeepsUserinfoSeparator(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "tuic-node", Protocol: "tuic", Port: 443, Network: "udp", Security: "tls", TLSSNI: "example.com",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{
		InboundID: inbound.ID, Email: "tuic-user", CredentialID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Password: "pa@ss:word",
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	req.Host = "panel.example.com"
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.HasPrefix(body, "tuic://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:pa%40ss%3Aword@panel.example.com:443?") {
		t.Fatalf("tuic userinfo should preserve uuid/password separator and escape password only, got %s", body)
	}
}

func TestSubscriptionUserinfoEscapesReservedCharacters(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	trojan, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "trojan-node", Protocol: "trojan", Port: 443, Network: "tcp", Security: "tls",
	})
	if err != nil {
		t.Fatalf("create trojan inbound: %v", err)
	}
	trojanClient, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: trojan.ID, Email: "trojan-user", Password: "pa@ss"})
	if err != nil {
		t.Fatalf("create trojan client: %v", err)
	}
	hy2, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "hy2-node", Protocol: "hysteria2", Port: 8443, Network: "udp", Security: "tls",
	})
	if err != nil {
		t.Fatalf("create hy2 inbound: %v", err)
	}
	hy2Client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: hy2.ID, Email: "hy2-user", Password: "hy2@secret"})
	if err != nil {
		t.Fatalf("create hy2 client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	for _, tc := range []struct {
		token string
		want  string
	}{
		{trojanClient.SubscriptionToken, "trojan://pa%40ss@panel.example.com:443?"},
		{hy2Client.SubscriptionToken, "hysteria2://hy2%40secret@panel.example.com:8443?"},
	} {
		response := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/sub/"+tc.token, nil)
		req.Host = "panel.example.com"
		router.ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
		}
		if !strings.HasPrefix(response.Body.String(), tc.want) {
			t.Fatalf("share link should escape userinfo, want prefix %q got %s", tc.want, response.Body.String())
		}
	}
}

func TestUpdateInboundAPIUpdatesFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "old", Protocol: "vless", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	body := `{"remark":"new","port":8443,"network":"ws","security":"tls","enabled":false}`
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10), bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	resp := response.Body.String()
	for _, want := range []string{`"remark":"new"`, `"port":8443`, `"network":"ws"`, `"security":"tls"`, `"enabled":false`} {
		if !strings.Contains(resp, want) {
			t.Fatalf("update response missing %q: %s", want, resp)
		}
	}
}

func TestPatchInboundEnabledAPIPartiallyUpdatesEnabledOnly(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark:    "ws-entry",
		Protocol:  "vless",
		Port:      8443,
		Network:   "ws",
		Security:  "tls",
		WsPath:    "/migate",
		WsHost:    "example.com",
		TLSSNI:    "example.com",
		XHTTPPath: "/xhttp",
		XHTTPMode: "stream-one",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/enabled", bytes.NewReader([]byte(`{"enabled":false}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	resp := response.Body.String()
	for _, want := range []string{`"remark":"ws-entry"`, `"protocol":"vless"`, `"port":8443`, `"network":"ws"`, `"security":"tls"`, `"ws_path":"/migate"`, `"ws_host":"example.com"`, `"tls_sni":"example.com"`, `"xhttp_path":"/xhttp"`, `"xhttp_mode":"stream-one"`, `"enabled":false`} {
		if !strings.Contains(resp, want) {
			t.Fatalf("patch enabled response missing preserved field %q: %s", want, resp)
		}
	}

	loaded, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Enabled || loaded[0].Remark != "ws-entry" || loaded[0].WsPath != "/migate" || loaded[0].XHTTPMode != "stream-one" {
		t.Fatalf("PATCH enabled did not preserve inbound fields: %+v", loaded)
	}
}

func TestPatchClientEnabledAPIPartiallyUpdatesEnabledOnly(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "test", Protocol: "vless", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "old@test.com", TrafficLimit: 12345, ExpiryAt: 1893456000})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients/"+strconv.FormatInt(client.ID, 10)+"/enabled", bytes.NewReader([]byte(`{"enabled":false}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	resp := response.Body.String()
	for _, want := range []string{`"email":"old@test.com"`, `"traffic_limit":12345`, `"expiry_at":1893456000`, `"enabled":false`} {
		if !strings.Contains(resp, want) {
			t.Fatalf("patch client response missing preserved field %q: %s", want, resp)
		}
	}

	loaded, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(loaded) != 1 || len(loaded[0].Clients) != 1 || loaded[0].Clients[0].Enabled || loaded[0].Clients[0].Email != "old@test.com" || loaded[0].Clients[0].TrafficLimit != 12345 {
		t.Fatalf("PATCH enabled did not preserve client fields: %+v", loaded)
	}
}

func TestPatchClientEnabledAPIRejectsClientOutsideInbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inboundA, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "a", Protocol: "vless", Port: 443, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound a: %v", err)
	}
	inboundB, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "b", Protocol: "vless", Port: 8443, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound b: %v", err)
	}
	clientB, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inboundB.ID, Email: "b@test.com"})
	if err != nil {
		t.Fatalf("create client b: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/inbounds/"+strconv.FormatInt(inboundA.ID, 10)+"/clients/"+strconv.FormatInt(clientB.ID, 10)+"/enabled", bytes.NewReader([]byte(`{"enabled":false}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for client outside inbound, got %d: %s", response.Code, response.Body.String())
	}
	loaded, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	if len(loaded) != 2 || len(loaded[1].Clients) != 1 || !loaded[1].Clients[0].Enabled {
		t.Fatalf("cross-inbound PATCH changed the wrong client: %+v", loaded)
	}
}

func TestResetClientTrafficAPIRejectsClientOutsideInbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inboundA, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "a", Protocol: "vless", Port: 443, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound a: %v", err)
	}
	inboundB, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "b", Protocol: "vless", Port: 8443, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound b: %v", err)
	}
	clientB, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inboundB.ID, Email: "b-reset@test.com"})
	if err != nil {
		t.Fatalf("create client b: %v", err)
	}
	raw := []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: clientB.StatsKey, RawUp: 100, RawDown: 100, Status: "ok"}}
	if err := store.ApplyTrafficRawStats(context.Background(), raw, time.Unix(100, 0)); err != nil {
		t.Fatalf("baseline traffic: %v", err)
	}
	raw[0].RawUp = 150
	raw[0].RawDown = 160
	if err := store.ApplyTrafficRawStats(context.Background(), raw, time.Unix(110, 0)); err != nil {
		t.Fatalf("increment traffic: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds/"+strconv.FormatInt(inboundA.ID, 10)+"/clients/"+strconv.FormatInt(clientB.ID, 10)+"/reset-traffic", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for client outside inbound, got %d: %s", response.Code, response.Body.String())
	}
	usage, found, err := store.GetClientTrafficUsageForClient(context.Background(), clientB.ID)
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if !found || usage.TotalUp != 50 || usage.TotalDown != 60 {
		t.Fatalf("cross-inbound reset changed traffic state: found=%v usage=%+v", found, usage)
	}
}

func TestUpdateInboundAPIRejectsUnknownInbound(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	body := `{"remark":"new","port":8443,"network":"tcp","security":"none","enabled":true}`
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/inbounds/99999", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown inbound, got %d: %s", response.Code, response.Body.String())
	}
}

func TestUpdateInboundAPIWithoutStoreReturnsUnavailable(t *testing.T) {
	router := web.NewRouter()
	body := `{"remark":"new","port":8443,"network":"tcp","security":"none","enabled":true}`
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/inbounds/1", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without store, got %d: %s", response.Code, response.Body.String())
	}
	assertStandardAPIError(t, response.Body.Bytes(), "store_unavailable")
}

type updateInboundRecordingStore struct {
	*db.Store
	updateCalled bool
}

func (s *updateInboundRecordingStore) ListInbounds(ctx context.Context) ([]db.Inbound, error) {
	return nil, nil
}

func (s *updateInboundRecordingStore) UpdateInbound(ctx context.Context, id int64, params db.UpdateInboundParams) (db.Inbound, error) {
	s.updateCalled = true
	return s.Store.UpdateInbound(ctx, id, params)
}

func TestUpdateInboundAPIRejectsUnknownInboundBeforeUpdate(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	recordingStore := &updateInboundRecordingStore{Store: store}
	router := web.NewRouter(web.WithStore(recordingStore))
	body := `{"remark":"new","port":8443,"network":"tcp","security":"none","enabled":true}`
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/inbounds/99999", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown inbound, got %d: %s", response.Code, response.Body.String())
	}
	if recordingStore.updateCalled {
		t.Fatal("update should not run when old inbound lookup reports not found")
	}
}

func TestUpdateClientAPIUpdatesFields(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "test", Protocol: "vless", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "old@test.com"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	body := `{"email":"new@test.com","enabled":false}`
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients/"+strconv.FormatInt(client.ID, 10), bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	resp := response.Body.String()
	for _, want := range []string{`"email":"new@test.com"`, `"enabled":false`} {
		if !strings.Contains(resp, want) {
			t.Fatalf("update client response missing %q: %s", want, resp)
		}
	}
}

func TestUpdateClientAPIRejectsUnknownClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	body := `{"email":"x","enabled":true}`
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/inbounds/1/clients/99999", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown client, got %d: %s", response.Code, response.Body.String())
	}
}

type fakeXrayController struct {
	statusCalls  int
	applyCalls   int
	statusResult *web.XrayStatus
	applyResult  *web.XrayApplyResult
}

func (f *fakeXrayController) Status(ctx context.Context) web.XrayStatus {
	f.statusCalls++
	if f.statusResult != nil {
		return *f.statusResult
	}
	return web.XrayStatus{Service: "xray", Status: "running", Managed: true, Installed: true, Version: "Xray 25.6.8", MemoryRSSBytes: 12345678, Uptime: "2h3m", ActiveConnections: 4, ConfigPath: "/etc/migate/cores/xray.json", CommandsExecuted: []string{}}
}

func (f *fakeXrayController) Apply(ctx context.Context) web.XrayApplyResult {
	f.applyCalls++
	if f.applyResult != nil {
		return *f.applyResult
	}
	return web.XrayApplyResult{Applied: true, Status: "applied", Service: "xray", ConfigPath: "/etc/migate/cores/xray.json", CommandsExecuted: []string{"xray -test -config /etc/migate/cores/xray.json", "systemctl restart migate-xray"}}
}

func (f *fakeXrayController) Version(ctx context.Context) string { return "Xray 1.8.0" }

func TestXrayStatusAPIIsReadOnly(t *testing.T) {
	controller := &fakeXrayController{}
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "grpc", Protocol: "vless", Port: 2443, Network: "grpc", Security: "reality", GrpcServiceName: "svc"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(web.WithStore(store), web.WithCertDir(t.TempDir()), web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/xray/status", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"service":"xray"`, `"status":"running"`, `"managed":true`, `"installed":true`, `"version":"Xray 25.6.8"`, `"memory_rss_bytes":12345678`, `"uptime":"2h3m"`, `"active_connections":4`, `"config_path":"/etc/migate/cores/xray.json"`, `"commands_executed":[]`} {
		if !strings.Contains(body, want) {
			t.Fatalf("status response missing %q: %s", want, body)
		}
	}
	for _, want := range []string{`"listening_ports":[`, `"network":"grpc"`, `"grpc_service_name":"svc"`, `"security":"reality"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("status response missing listening detail %q: %s", want, body)
		}
	}
	if controller.statusCalls != 1 || controller.applyCalls != 0 {
		t.Fatalf("status must be read-only, calls: status=%d apply=%d", controller.statusCalls, controller.applyCalls)
	}
}

func TestXrayStatusAPIFillsProductionConfigPathAndListeningPorts(t *testing.T) {
	dir := t.TempDir()
	controller := &fakeXrayController{statusResult: &web.XrayStatus{
		Service: "xray", Status: "running", Managed: true, Installed: true, Version: "Xray 26.3.27",
	}}
	router := web.NewRouter(web.WithConfigDir(dir), web.WithXrayConfigPath(filepath.Join(dir, "xray.json")), web.WithXrayController(controller))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/status", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"installed":true`, `"managed":true`, `"status":"running"`, `"version":"Xray 26.3.27"`, `"config_path":"` + dir + `/xray.json"`, `"listening_ports":[]`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("status response missing %q: %s", want, response.Body.String())
		}
	}
}

func TestXrayStatusAPIReturnsListeningPortsWithTransportDetails(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	for _, params := range []db.CreateInboundParams{
		{Remark: "ws", Protocol: "vless", Port: 2441, Network: "ws", Security: "tls", WsPath: "/ws", TLSCertFile: "/cert.pem", TLSKeyFile: "/key.pem"},
		{Remark: "grpc", Protocol: "vless", Port: 2442, Network: "grpc", Security: "reality", GrpcServiceName: "svc", RealityPrivateKey: "priv", RealityServerNames: "example.com", RealityDest: "example.com:443"},
		{Remark: "xhttp", Protocol: "vless", Port: 2443, Network: "xhttp", Security: "none", XHTTPPath: "/xhttp"},
	} {
		if _, err := store.CreateInbound(context.Background(), params); err != nil {
			t.Fatalf("create %s inbound: %v", params.Remark, err)
		}
	}
	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithStore(store), web.WithCertDir(t.TempDir()), web.WithXrayController(controller))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/status", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var data struct {
		ListeningPorts []struct {
			Protocol        string `json:"protocol"`
			Port            int    `json:"port"`
			Network         string `json:"network"`
			Transport       string `json:"transport"`
			Path            string `json:"path"`
			GrpcServiceName string `json:"grpc_service_name"`
			Security        string `json:"security"`
		} `json:"listening_ports"`
	}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(data.ListeningPorts) != 3 {
		t.Fatalf("expected 3 listening ports, got %+v", data.ListeningPorts)
	}
	byPort := map[int]interface{}{}
	for _, listener := range data.ListeningPorts {
		byPort[listener.Port] = listener
		if listener.Transport != "tcp" {
			t.Fatalf("expected xray listener transport tcp, got %+v", listener)
		}
	}
	if got := data.ListeningPorts[0]; got.Port != 2441 || got.Network != "ws" || got.Path != "/ws" || got.Security != "tls" {
		t.Fatalf("unexpected ws listener: %+v", data.ListeningPorts)
	}
	if got := data.ListeningPorts[1]; got.Port != 2442 || got.Network != "grpc" || got.GrpcServiceName != "svc" || got.Security != "reality" {
		t.Fatalf("unexpected grpc listener: %+v", data.ListeningPorts)
	}
	if got := data.ListeningPorts[2]; got.Port != 2443 || got.Network != "xhttp" || got.Path != "/xhttp" || got.Security != "none" {
		t.Fatalf("unexpected xhttp listener: %+v", data.ListeningPorts)
	}
	if len(byPort) != 3 || controller.applyCalls != 0 {
		t.Fatalf("status should be read-only with all ports represented, ports=%+v applyCalls=%d", byPort, controller.applyCalls)
	}
}

func TestXrayStatusAPIUsesInjectedListenerDiagnostics(t *testing.T) {
	controller := &fakeXrayController{}
	router := web.NewRouter(
		web.WithXrayController(controller),
		web.WithXrayListenerDiagnostics(func(ctx context.Context) []web.CoreListenerDiagnostic {
			return []web.CoreListenerDiagnostic{{InboundID: 99, Protocol: "vless", Port: 29999, Network: "grpc", Transport: "tcp", GrpcServiceName: "injected", Security: "reality", Listening: true}}
		}),
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/status", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"inbound_id":99`, `"port":29999`, `"grpc_service_name":"injected"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("status response should use injected listener diagnostics, missing %q: %s", want, body)
		}
	}
	if controller.applyCalls != 0 {
		t.Fatalf("status must remain read-only, apply calls=%d", controller.applyCalls)
	}
}

func TestXrayApplyAPIRejectsWithoutDoubleConfirmation(t *testing.T) {
	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/apply", bytes.NewReader([]byte(`{"confirm":true}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	assertStandardAPIError(t, response.Body.Bytes(), "confirmation_required")
	if !strings.Contains(body, `"commands_executed":[]`) {
		t.Fatalf("rejection response missing commands_executed: %s", body)
	}
	if controller.applyCalls != 0 {
		t.Fatalf("rejected apply must not call controller, calls=%d", controller.applyCalls)
	}
}

func TestXrayApplyAPICallsControllerAfterDoubleConfirmation(t *testing.T) {
	withTempApplyLock(t)
	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/apply", bytes.NewReader([]byte(`{"confirm":true,"allow_system_changes":true}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"status":"applied"`, `"service":"xray"`, `"systemctl restart migate-xray"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("apply response missing %q: %s", want, body)
		}
	}
	if controller.applyCalls != 1 || controller.statusCalls != 0 {
		t.Fatalf("apply should call only apply once, calls: status=%d apply=%d", controller.statusCalls, controller.applyCalls)
	}
}

func TestXrayApplyAPIOmitsSingboxWhenNotNeeded(t *testing.T) {
	withTempApplyLock(t)
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "vless", Protocol: "vless", Port: 2443, Network: "tcp", Security: "none"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithStore(store), web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/apply", bytes.NewReader([]byte(`{"confirm":true,"allow_system_changes":true}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"xray":`) || !strings.Contains(body, `"applied":true`) {
		t.Fatalf("expected applied xray response: %s", body)
	}
	if strings.Contains(body, `"singbox"`) || strings.Contains(body, `"not_needed"`) {
		t.Fatalf("sing-box not_needed should be omitted when not required: %s", body)
	}
}

func TestXrayApplyAPIReportsSingboxDecisionReadFailure(t *testing.T) {
	withTempApplyLock(t)
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithStore(&listInboundsFailingStore{Store: store}), web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/apply", bytes.NewReader([]byte(`{"confirm":true,"allow_system_changes":true}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"xray":`, `"applied":false`, `"reason":"list_inbounds_failed"`, `"detail":"list inbounds failed"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("response missing %q: %s", want, response.Body.String())
		}
	}
}

func TestXrayApplyAPISkipsSingboxApplyWhenXrayFails(t *testing.T) {
	withTempApplyLock(t)
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21001, Network: "udp", Security: "tls"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	controller := &fakeXrayController{applyResult: &web.XrayApplyResult{
		Applied: false, Status: "failed: validation", Service: "xray", Error: "validation_failed", Detail: "invalid xray config", CommandsExecuted: []string{"xray run -test"},
	}}
	var applierCalls int
	router := web.NewRouter(
		web.WithStore(store),
		web.WithXrayController(controller),
		web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
			applierCalls++
			return web.SingboxApplySummary{Applied: true}
		}),
	)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/apply", bytes.NewReader([]byte(`{"confirm":true,"allow_system_changes":true}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	if applierCalls != 0 {
		t.Fatalf("sing-box applier should not run when xray apply fails, got %d calls", applierCalls)
	}
	body := response.Body.String()
	if !strings.Contains(body, `"error":"validation_failed"`) || strings.Contains(body, `"singbox"`) {
		t.Fatalf("expected only failed xray result, got %s", body)
	}
}

func TestXrayApplyAPIUsesInjectedSingboxApplier(t *testing.T) {
	withTempApplyLock(t)
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21001, Network: "udp", Security: "tls"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	controller := &fakeXrayController{}
	var applierCalls int
	router := web.NewRouter(
		web.WithStore(store),
		web.WithXrayController(controller),
		web.WithSingboxApplier(func(ctx context.Context, store web.Store, runtime web.SingboxRuntime, strict bool) web.SingboxApplySummary {
			applierCalls++
			if strict {
				t.Fatal("xray apply linked sing-box apply should stay best-effort")
			}
			return web.SingboxApplySummary{Applied: false, Error: "singbox_apply_failed", Detail: "injected apply failed", Service: "sing-box", ConfigPath: "/etc/migate/cores/sing-box.json", CommandsExecuted: []string{}}
		}),
	)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/apply", bytes.NewReader([]byte(`{"confirm":true,"allow_system_changes":true}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	if applierCalls != 1 {
		t.Fatalf("expected injected sing-box applier once, got %d", applierCalls)
	}
	for _, want := range []string{`"xray":`, `"singbox":`, `"applied":false`, `"error":"singbox_apply_failed"`, `"detail":"injected apply failed"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("response missing %q: %s", want, response.Body.String())
		}
	}
}

func TestXrayApplyAPIDefaultSingboxApplierReportsNotInstalled(t *testing.T) {
	withTempApplyLock(t)
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21001, Network: "udp", Security: "tls"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	origBinary := singbox.DefaultBinaryPath
	singbox.DefaultBinaryPath = t.TempDir() + "/missing-sing-box"
	defer func() { singbox.DefaultBinaryPath = origBinary }()

	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithStore(store), web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/apply", bytes.NewReader([]byte(`{"confirm":true,"allow_system_changes":true}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"xray":`, `"singbox":`, `"applied":false`, `"reason":"singbox_not_installed"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("response missing %q: %s", want, response.Body.String())
		}
	}
	if strings.Contains(response.Body.String(), `"singbox":{"applied":true`) {
		t.Fatalf("must not report sing-box applied when default applier skipped missing binary: %s", response.Body.String())
	}
}

func TestSingboxStatusAPIReturnsManagedAndConfigPath(t *testing.T) {
	for _, tc := range []struct {
		name        string
		loadState   string
		active      string
		wantManaged bool
		wantStatus  string
		wantRaw     string
		wantService string
	}{
		{name: "standard service", loadState: "loaded", active: "active", wantManaged: true, wantStatus: "running", wantRaw: "running", wantService: "migate-sing-box"},
		{name: "failed service", loadState: "loaded", active: "failed", wantManaged: true, wantStatus: "stopped", wantRaw: "failed", wantService: "migate-sing-box"},
		{name: "activating service", loadState: "loaded", active: "activating", wantManaged: true, wantStatus: "stopped", wantRaw: "activating", wantService: "migate-sing-box"},
		{name: "deactivating service", loadState: "loaded", active: "deactivating", wantManaged: true, wantStatus: "stopped", wantRaw: "deactivating", wantService: "migate-sing-box"},
		{name: "unmanaged", loadState: "not-found", active: "inactive", wantManaged: false, wantStatus: "not_managed", wantRaw: "not_managed", wantService: "migate-sing-box"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := installFakeSingboxStatusCommands(t, tc.loadState, tc.active)
			defer restore()

			router := web.NewRouter()
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/singbox/status", nil))
			if response.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
			}
			var data map[string]interface{}
			if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if data["installed"] != true {
				t.Fatalf("expected installed true, got %v in %s", data["installed"], response.Body.String())
			}
			if data["managed"] != tc.wantManaged {
				t.Fatalf("expected managed %v, got %v in %s", tc.wantManaged, data["managed"], response.Body.String())
			}
			if data["status"] != tc.wantStatus || data["service"] != tc.wantService {
				t.Fatalf("unexpected status/service: %+v", data)
			}
			if data["raw_status"] != tc.wantRaw {
				t.Fatalf("expected raw_status %q, got %+v", tc.wantRaw, data)
			}
			if data["normalized_status"] != tc.wantStatus {
				t.Fatalf("normalized_status should match compatibility status: %+v", data)
			}
			if data["config_path"] != "/etc/migate/cores/sing-box.json" {
				t.Fatalf("expected sing-box config path, got %+v", data)
			}
			if data["version"] != "sing-box version 1.13.13" {
				t.Fatalf("expected normalized version, got %+v", data["version"])
			}
			if _, ok := data["listening_ports"].([]interface{}); !ok {
				t.Fatalf("expected listening_ports array, got %+v", data["listening_ports"])
			}
		})
	}
}

func TestSingboxStatusAPIReturnsListeningPorts(t *testing.T) {
	restore := installFakeSingboxStatusCommands(t, "loaded", "active")
	defer restore()
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21080, Network: "udp", Security: "tls"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/singbox/status", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var data struct {
		ListeningPorts []struct {
			InboundID int64  `json:"inbound_id"`
			Protocol  string `json:"protocol"`
			Port      int    `json:"port"`
			Network   string `json:"network"`
			Listening bool   `json:"listening"`
		} `json:"listening_ports"`
	}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(data.ListeningPorts) != 1 {
		t.Fatalf("expected one listening port diagnostic, got %+v", data.ListeningPorts)
	}
	got := data.ListeningPorts[0]
	if got.Protocol != "hysteria2" || got.Port != 21080 || got.Network != "udp" {
		t.Fatalf("unexpected listening port diagnostic: %+v", got)
	}
}

func TestSingboxDiagnosticsAPIReturnsStructuredResult(t *testing.T) {
	origConfigPath := singbox.DefaultConfigPath
	dir := t.TempDir()
	singbox.DefaultConfigPath = dir + "/config.json"
	defer func() { singbox.DefaultConfigPath = origConfigPath }()
	if err := os.WriteFile(singbox.DefaultConfigPath, []byte(`{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}`), 0644); err != nil {
		t.Fatalf("write disk config: %v", err)
	}
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21082, Network: "udp", Security: "tls"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(
		web.WithStore(store),
		web.WithSingboxRuntime(fixedWebSingboxRuntime{}),
		web.WithSingboxProbe(apiTestSingboxProbe{installed: true, managed: true, service: "sing-box", status: "running", configExists: true, configValid: true}),
		web.WithSingboxListenerDiagnostics(func(ctx context.Context) []web.SingboxListenerDiagnostic {
			return []web.SingboxListenerDiagnostic{{InboundID: 1, Protocol: "hysteria2", Port: 21082, Transport: "udp", Listening: false}}
		}),
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/singbox/diagnostics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"installed":true`, `"service_status":"running"`, `"config_valid":true`, `"missing_listeners":[`, `"warnings":[`, `"suggestions":[`} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics response missing %q: %s", want, body)
		}
	}
}

func TestSingboxApplyAPIReturnsMissingListenerWarning(t *testing.T) {
	withTempApplyLock(t)
	restore := installFakeSingboxApplyCommands(t)
	defer restore()
	origConfigDir := singbox.DefaultConfigDir
	origConfigPath := singbox.DefaultConfigPath
	origCertFile := singbox.CertFile
	origKeyFile := singbox.KeyFile
	dir := t.TempDir()
	singbox.DefaultConfigDir = dir
	singbox.DefaultConfigPath = dir + "/config.json"
	singbox.CertFile = dir + "/server.crt"
	singbox.KeyFile = dir + "/server.key"
	defer func() {
		singbox.DefaultConfigDir = origConfigDir
		singbox.DefaultConfigPath = origConfigPath
		singbox.CertFile = origCertFile
		singbox.KeyFile = origKeyFile
	}()
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21083, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	if _, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "hy2-user", Password: "secret"}); err != nil {
		t.Fatalf("create client: %v", err)
	}
	router := web.NewRouter(
		web.WithStore(store),
		web.WithSingboxRuntime(fixedWebSingboxRuntime{}),
		web.WithSingboxListenerDiagnostics(func(ctx context.Context) []web.SingboxListenerDiagnostic {
			return []web.SingboxListenerDiagnostic{{InboundID: inbound.ID, Protocol: "hysteria2", Port: 21083, Transport: "udp", Listening: false}}
		}),
	)
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/singbox/apply", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "配置已应用，但端口未监听：21083/udp") {
		t.Fatalf("expected missing listener warning in apply response: %s", response.Body.String())
	}
}

func TestSingboxConfigPreviewReportsSyncState(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 21081, Network: "udp", Security: "tls"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	origConfigPath := singbox.DefaultConfigPath
	dir := t.TempDir()
	singbox.DefaultConfigPath = dir + "/config.json"
	defer func() { singbox.DefaultConfigPath = origConfigPath }()
	if err := os.WriteFile(singbox.DefaultConfigPath, []byte(`{"log":{"level":"warn"},"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}`), 0644); err != nil {
		t.Fatalf("write disk config: %v", err)
	}

	router := web.NewRouter(web.WithStore(store), web.WithSingboxRuntime(fixedWebSingboxRuntime{}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/singbox/config/preview", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"in_sync":false`, `"reason":"hash_mismatch"`, `"disk":`, `"generated":`, `"hash":`, `"config_path":"` + singbox.DefaultConfigPath + `"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("preview response missing %q: %s", want, body)
		}
	}
}

func installFakeSingboxStatusCommands(t *testing.T, loadState, active string) func() {
	t.Helper()
	dir := t.TempDir()
	binary := dir + "/sing-box"
	systemctl := dir + "/systemctl"
	ss := dir + "/ss"
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf 'sing-box version 1.13.13\\nTags: with_quic\\n'\n"), 0755); err != nil {
		t.Fatalf("write fake sing-box: %v", err)
	}
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "show" ]; then
  if [ "$2" = "migate-sing-box" ]; then printf '%%s\n' %q; exit 0; fi
fi
if [ "$1" = "is-active" ]; then printf '%%s\n' %q; exit 0; fi
printf '\n'
`, loadState, active)
	if err := os.WriteFile(systemctl, []byte(script), 0755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	if err := os.WriteFile(ss, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake ss: %v", err)
	}
	origBinary := singbox.DefaultBinaryPath
	origPath := os.Getenv("PATH")
	singbox.DefaultBinaryPath = binary
	os.Setenv("PATH", dir+":"+origPath)
	return func() {
		singbox.DefaultBinaryPath = origBinary
		os.Setenv("PATH", origPath)
	}
}

func installFakeSingboxApplyCommands(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	binary := dir + "/sing-box"
	systemctl := dir + "/systemctl"
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nif [ \"$1\" = \"check\" ]; then exit 0; fi\nif [ \"$1\" = \"version\" ]; then printf 'sing-box version 1.13.13\\n'; exit 0; fi\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake sing-box: %v", err)
	}
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\nif [ \"$1\" = \"show\" ]; then printf 'loaded\\n'; exit 0; fi\nif [ \"$1\" = \"restart\" ]; then exit 0; fi\nif [ \"$1\" = \"is-active\" ]; then printf 'active\\n'; exit 0; fi\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	origBinary := singbox.DefaultBinaryPath
	origPath := os.Getenv("PATH")
	singbox.DefaultBinaryPath = binary
	os.Setenv("PATH", dir+":"+origPath)
	return func() {
		singbox.DefaultBinaryPath = origBinary
		os.Setenv("PATH", origPath)
	}
}

func TestXrayVersionAPIReturnsVersionFromController(t *testing.T) {
	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/xray/version", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var data map[string]string
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if data["version"] != "Xray 1.8.0" {
		t.Fatalf("expected version 'Xray 1.8.0', got %q", data["version"])
	}
}

func TestRealControllerStatusIncludesOperationalDetails(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	_, err = store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "xray-vless", Protocol: "vless", Port: 8443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	mockRun := func(name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		switch cmd {
		case "systemctl is-active migate-xray":
			return "active\n", nil
		case "systemctl show migate-xray --property=MemoryCurrent --property=MainPID --property=ActiveEnterTimestamp":
			return "MemoryCurrent=24680\nMainPID=123\nActiveEnterTimestamp=Mon 2026-06-08 08:00:00 UTC\n", nil
		case "/usr/local/bin/xray version":
			return "Xray 26.3.27\nA unified platform for anti-censorship.", nil
		case "ss -tn state established":
			return "ESTAB 0 0 203.0.113.10:8443 198.51.100.2:50000\nESTAB 0 0 203.0.113.10:21000 198.51.100.3:50001\n", nil
		default:
			return "", fmt.Errorf("unexpected command %s", cmd)
		}
	}

	status := web.NewRealController(store, paths.XrayConfig, mockRun).Status(context.Background())
	if status.Status != "running" || !status.Managed || !status.Installed {
		t.Fatalf("expected running managed installed status, got %+v", status)
	}
	if status.Version != "Xray 26.3.27" || status.MemoryRSSBytes != 24680 || status.ConfigPath != "/etc/migate/cores/xray.json" {
		t.Fatalf("unexpected detail fields: %+v", status)
	}
	if status.Uptime == "" || status.Uptime == "未知" {
		t.Fatalf("expected parsed uptime, got %+v", status)
	}
	if status.ActiveConnections != 1 {
		t.Fatalf("expected only Xray inbound port connection counted, got %+v", status)
	}
}

func TestRealControllerStatusReportsNoInboundsWhenXrayIsInstalledButHasNoManagedListeners(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	mockRun := func(name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		switch cmd {
		case "systemctl is-active migate-xray":
			return "inactive\n", fmt.Errorf("inactive")
		case "systemctl show migate-xray --property=MemoryCurrent --property=MainPID --property=ActiveEnterTimestamp":
			return "", nil
		case "/usr/local/bin/xray version":
			return "Xray 26.3.27\nA unified platform for anti-censorship.", nil
		case "ss -tn state established":
			return "", nil
		default:
			return "", fmt.Errorf("unexpected command %s", cmd)
		}
	}

	status := web.NewRealController(store, paths.XrayConfig, mockRun).Status(context.Background())
	if !status.Installed {
		t.Fatalf("expected xray binary to be detected as installed, got %+v", status)
	}
	if status.Status != "inactive" {
		t.Fatalf("empty inbound list should not hide the systemd service state: %+v", status)
	}
}

func TestRealControllerStatusDoesNotReportUnknownWhenXrayBinaryIsInstalledButServiceIsUnmanaged(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	_, err = store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "xray-vless", Protocol: "vless", Port: 8443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	mockRun := func(name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		switch cmd {
		case "systemctl is-active migate-xray":
			return "", fmt.Errorf("Unit migate-xray.service could not be found")
		case "systemctl show migate-xray --property=MemoryCurrent --property=MainPID --property=ActiveEnterTimestamp":
			return "", fmt.Errorf("Unit migate-xray.service could not be found")
		case "/usr/local/bin/xray version":
			return "Xray 26.3.27\nA unified platform for anti-censorship.", nil
		case "ss -tn state established":
			return "", nil
		default:
			return "", fmt.Errorf("unexpected command %s", cmd)
		}
	}

	status := web.NewRealController(store, paths.XrayConfig, mockRun).Status(context.Background())
	if !status.Installed {
		t.Fatalf("expected xray binary to be detected as installed, got %+v", status)
	}
	if status.Status == "unknown" || status.Status == "" {
		t.Fatalf("installed-but-unmanaged xray should not be reported as unknown: %+v", status)
	}
	if status.Managed {
		t.Fatalf("missing migate-xray.service should be reported as unmanaged: %+v", status)
	}
}

func TestRealControllerStatusReportsConfigPathTypeError(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "xray.json")
	if err := os.Mkdir(configPath, 0755); err != nil {
		t.Fatalf("mkdir config placeholder: %v", err)
	}
	mockRun := func(name string, args ...string) (string, error) {
		switch name + " " + strings.Join(args, " ") {
		case "systemctl is-active migate-xray":
			return "active\n", nil
		case "systemctl show migate-xray --property=MemoryCurrent --property=MainPID --property=ActiveEnterTimestamp":
			return "", nil
		case "/usr/local/bin/xray version":
			return "Xray 26.3.27\n", nil
		case "ss -tn state established":
			return "", nil
		default:
			return "", nil
		}
	}
	status := web.NewRealController(store, configPath, mockRun).Status(context.Background())
	if !status.ConfigExists || status.ConfigValid || !strings.Contains(status.ConfigError, "not_file") || !strings.Contains(status.ConfigError, configPath) {
		t.Fatalf("expected config path type error with real path, got %+v", status)
	}
}

func TestRealControllerWritesConfigAndRunsValidationBeforeRestart(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	_, err = store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "Reality", Protocol: "vless", Port: 8443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	outbound, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{
		Tag: "test-socks-egress", Remark: "Test SOCKS", Protocol: "socks", Address: "10.255.239.2", Port: 21080,
	})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}
	_, err = store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{
		InboundTag: "Reality", OutboundID: outbound.ID, OutboundTag: "test-socks-egress", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create routing rule: %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "xray.json")
	var calls []string
	mockRun := func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "ok", nil
	}

	controller := web.NewRealController(store, configPath, mockRun)
	result := controller.Apply(context.Background())

	if !result.Applied || result.Status != "applied" || result.Error != "" {
		t.Fatalf("expected applied result, got %+v", result)
	}
	if result.ConfigPath != configPath || result.Inbounds == 0 || result.Outbounds == 0 || result.Rules == 0 {
		t.Fatalf("expected config path and counts, got %+v", result)
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config file was not written: %v", err)
	}
	if !strings.Contains(string(configBytes), `"protocol": "vless"`) {
		t.Fatalf("config missing inbound: %s", string(configBytes))
	}
	compiledTag := fmt.Sprintf("xray-out-%d", outbound.ID)
	for _, want := range []string{fmt.Sprintf(`"tag": "%s"`, compiledTag), `"protocol": "socks"`, `"address": "10.255.239.2"`, fmt.Sprintf(`"outboundTag": "%s"`, compiledTag), `"inboundTag": [
          "inbound-1-vless"
        ]`} {
		if !strings.Contains(string(configBytes), want) {
			t.Fatalf("config missing %q: %s", want, string(configBytes))
		}
	}
	if len(calls) < 2 {
		t.Fatalf("expected at least 2 runner calls, got %d: %v", len(calls), calls)
	}
	if !strings.Contains(calls[0], "xray") || !strings.Contains(calls[0], "-test") {
		t.Fatalf("first call should be xray -test, got %q", calls[0])
	}
	if !strings.Contains(calls[len(calls)-1], "systemctl restart migate-xray") {
		t.Fatalf("last call should be systemctl restart, got %q", calls[len(calls)-1])
	}
}

func TestRealControllerApplyReportsConfigPathTypeErrorBeforeWrite(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "test", Protocol: "vless", Port: 8443, Network: "tcp", Security: "none"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "xray.json")
	if err := os.Mkdir(configPath, 0755); err != nil {
		t.Fatalf("mkdir config placeholder: %v", err)
	}
	mockRun := func(name string, args ...string) (string, error) {
		if name == "xray" {
			return "ok", nil
		}
		return "", fmt.Errorf("unexpected command %s %s", name, strings.Join(args, " "))
	}
	result := web.NewRealController(store, configPath, mockRun).Apply(context.Background())
	if result.Applied || result.Error != "stat_config_failed" || !strings.Contains(result.Detail, "not_file") || !strings.Contains(result.Detail, configPath) {
		t.Fatalf("expected config path type error before write, got %+v", result)
	}
}

func TestRealControllerApplyStopsOnValidationFailure(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	_, err = store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "test", Protocol: "vmess", Port: 8443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	oldConfigPath := filepath.Join(t.TempDir(), "xray.json")
	oldConfig := []byte(`{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"tag":"old","protocol":"freedom","settings":{}}]}`)
	if err := os.WriteFile(oldConfigPath, oldConfig, 0o644); err != nil {
		t.Fatalf("write old config: %v", err)
	}
	var calls []string
	mockRun := func(name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(calls) == 1 {
			return "FAILED", fmt.Errorf("xray validation failed")
		}
		return "ok", nil
	}

	controller := web.NewRealController(store, oldConfigPath, mockRun)
	result := controller.Apply(context.Background())

	if len(calls) != 1 {
		t.Fatalf("expected only 1 call (validation), got %d: %v", len(calls), calls)
	}
	if !strings.Contains(result.Status, "failed") {
		t.Fatalf("expected status to indicate failure, got %q", result.Status)
	}
	if result.Applied || result.Error != "validation_failed" || !strings.Contains(result.Detail, "FAILED") || result.ConfigPath != oldConfigPath {
		t.Fatalf("expected structured validation failure, got %+v", result)
	}
	gotConfig, err := os.ReadFile(oldConfigPath)
	if err != nil {
		t.Fatalf("read config after failed validation: %v", err)
	}
	if string(gotConfig) != string(oldConfig) {
		t.Fatalf("validation failure must not replace existing config:\n%s", gotConfig)
	}
}

func TestRealControllerApplyReportsRestartFailure(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "test", Protocol: "vless", Port: 8443, Network: "tcp", Security: "none"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "xray.json")
	var calls []string
	mockRun := func(name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		calls = append(calls, cmd)
		if cmd == "systemctl restart migate-xray" {
			return "restart failed", fmt.Errorf("restart failed")
		}
		return "ok", nil
	}
	result := web.NewRealController(store, configPath, mockRun).Apply(context.Background())
	if result.Applied || result.Error != "restart_failed" || result.Detail != "restart failed" || result.Status != "failed: restart" {
		t.Fatalf("expected structured restart failure, got %+v", result)
	}
	if len(calls) != 2 || !strings.Contains(strings.Join(calls, "\n"), "xray run -test") || !strings.Contains(strings.Join(calls, "\n"), "systemctl restart migate-xray") {
		t.Fatalf("expected validation then restart calls, got %+v", calls)
	}
}

func TestRealControllerApplyRestoresExistingConfigWhenRestartFails(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "test", Protocol: "vless", Port: 8443, Network: "tcp", Security: "none"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "xray.json")
	oldConfig := []byte(`{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"tag":"old","protocol":"freedom","settings":{}}]}`)
	if err := os.WriteFile(configPath, oldConfig, 0o644); err != nil {
		t.Fatalf("write old config: %v", err)
	}
	restarts := 0
	var calls []string
	mockRun := func(name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		calls = append(calls, cmd)
		if cmd == "systemctl restart migate-xray" {
			restarts++
			if restarts == 1 {
				return "restart failed", fmt.Errorf("restart failed")
			}
		}
		return "ok", nil
	}
	result := web.NewRealController(store, configPath, mockRun).Apply(context.Background())
	if result.Applied || result.Error != "restart_failed" || result.Detail != "restart failed" {
		t.Fatalf("expected restart failure after restore, got %+v", result)
	}
	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read restored config: %v", err)
	}
	if string(got) != string(oldConfig) {
		t.Fatalf("restart failure should restore previous config:\n%s", got)
	}
	if restarts != 2 {
		t.Fatalf("expected restart attempted again after restore, restarts=%d calls=%v", restarts, calls)
	}
}

func TestRealControllerNormalizesXrayConfigFilePath(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	mockRun := func(name string, args ...string) (string, error) {
		switch name + " " + strings.Join(args, " ") {
		case "systemctl is-active migate-xray":
			return "active\n", nil
		case "systemctl show migate-xray --property=MemoryCurrent --property=MainPID --property=ActiveEnterTimestamp":
			return "", nil
		case "/usr/local/bin/xray version":
			return "Xray 26.3.27\n", nil
		case "ss -tn state established":
			return "", nil
		default:
			return "", nil
		}
	}
	configFile := filepath.Join(t.TempDir(), "xray.json")
	status := web.NewRealController(store, configFile, mockRun).Status(context.Background())
	if status.ConfigPath != configFile {
		t.Fatalf("expected file-form config path to stay exact, got %+v", status)
	}
}

func TestXrayConfigPreviewReportsMissingMismatchAndSync(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "vless", Protocol: "vless", Port: 2443, Network: "tcp", Security: "none"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "xray.json")
	router := web.NewRouter(web.WithStore(store), web.WithConfigDir(dir), web.WithXrayConfigPath(configPath))

	missing := httptest.NewRecorder()
	router.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/api/xray/config/preview", nil))
	if missing.Code != http.StatusOK || !strings.Contains(missing.Body.String(), `"reason":"disk_missing"`) {
		t.Fatalf("expected disk_missing preview, got %d: %s", missing.Code, missing.Body.String())
	}

	if err := os.WriteFile(configPath, []byte(`{"log":{"loglevel":"debug"},"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}`), 0644); err != nil {
		t.Fatalf("write mismatch config: %v", err)
	}
	mismatch := httptest.NewRecorder()
	router.ServeHTTP(mismatch, httptest.NewRequest(http.MethodGet, "/api/xray/config/preview", nil))
	if mismatch.Code != http.StatusOK || !strings.Contains(mismatch.Body.String(), `"reason":"hash_mismatch"`) {
		t.Fatalf("expected hash_mismatch preview, got %d: %s", mismatch.Code, mismatch.Body.String())
	}

	config, err := xray.BuildConfigWithOutbounds(mustListInbounds(t, store), mustListOutbounds(t, store), mustListRules(t, store))
	if err != nil {
		t.Fatalf("build generated config: %v", err)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal generated config: %v", err)
	}
	if err := os.WriteFile(configPath, raw, 0644); err != nil {
		t.Fatalf("write synced config: %v", err)
	}
	synced := httptest.NewRecorder()
	router.ServeHTTP(synced, httptest.NewRequest(http.MethodGet, "/api/xray/config/preview", nil))
	if synced.Code != http.StatusOK || !strings.Contains(synced.Body.String(), `"in_sync":true`) {
		t.Fatalf("expected in_sync preview, got %d: %s", synced.Code, synced.Body.String())
	}
}

func TestXrayApplyUsesApplyLock(t *testing.T) {
	origApplyLock := paths.ApplyLock
	paths.ApplyLock = filepath.Join(t.TempDir(), "apply.lock")
	t.Cleanup(func() { paths.ApplyLock = origApplyLock })
	unlock, err := lockfile.TryAcquire(paths.ApplyLock)
	if err != nil {
		t.Fatalf("acquire apply lock: %v", err)
	}
	defer unlock()

	router := web.NewRouter(web.WithXrayController(&fakeXrayController{}))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/xray/apply", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusConflict {
		t.Fatalf("expected apply lock conflict, got %d: %s", response.Code, response.Body.String())
	}
	assertStandardAPIError(t, response.Body.Bytes(), "apply_locked")
}

func TestXrayConfigPreviewUsesDedicatedXrayConfigPath(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	panelDir := t.TempDir()
	xrayPath := filepath.Join(t.TempDir(), "xray.json")
	router := web.NewRouter(web.WithStore(store), web.WithConfigDir(panelDir), web.WithXrayConfigPath(xrayPath))

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/config/preview", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{
		`"config_path":"` + xrayPath + `"`,
		`"reason":"disk_missing"`,
	} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("preview should use dedicated Xray config path, missing %q: %s", want, response.Body.String())
		}
	}
	if strings.Contains(response.Body.String(), panelDir+`/xray.json`) {
		t.Fatalf("preview must not use panel config dir for Xray disk config: %s", response.Body.String())
	}
}

func TestXrayConfigReturnsStoreReadFailure(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	router := web.NewRouter(web.WithStore(&listInboundsFailingStore{Store: store}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/config", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected list failure, got %d: %s", response.Code, response.Body.String())
	}
	assertStandardAPIError(t, response.Body.Bytes(), "list_inbounds_failed")
}

func TestXrayConfigReturnsBadRequestForGeneratedConfigFailure(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "vless", Protocol: "vless", Port: 2443, Network: "tcp", Security: "none"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(web.WithStore(&xrayBuildFailingStore{Store: store}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/config", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for generated config failure, got %d: %s", response.Code, response.Body.String())
	}
	assertStandardAPIError(t, response.Body.Bytes(), "build_xray_config_failed")
}

func TestXrayDiagnosticsGeneratedConfigBuildFailureHasStructuredAction(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "xray.json")
	if err := os.WriteFile(configPath, []byte(`{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "vless", Protocol: "vless", Port: 2443, Network: "tcp", Security: "none"}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(web.WithStore(&xrayBuildFailingStore{Store: store}), web.WithConfigDir(dir), web.WithXrayConfigPath(configPath), web.WithXrayProbe(fakeWebXrayProbe{installed: true, managed: true, status: "running", configExists: true, configValid: true}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/diagnostics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"xray_generated_config_build_failed"`, `"actions":[`, `"category":"config"`, `"message":"修复数据库中的 Xray 入站、出站或路由配置后重新应用。"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("diagnostics response missing %q: %s", want, response.Body.String())
		}
	}
}

func TestXrayDiagnosticsStructuredWarnings(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	dir := t.TempDir()
	router := web.NewRouter(web.WithStore(store), web.WithConfigDir(dir), web.WithXrayProbe(fakeWebXrayProbe{installed: false}))
	notInstalled := httptest.NewRecorder()
	router.ServeHTTP(notInstalled, httptest.NewRequest(http.MethodGet, "/api/xray/diagnostics", nil))
	if notInstalled.Code != http.StatusOK || !strings.Contains(notInstalled.Body.String(), `"xray_not_installed"`) || !strings.Contains(notInstalled.Body.String(), `"actions":[`) || !strings.Contains(notInstalled.Body.String(), `"category":"service"`) {
		t.Fatalf("expected not installed warning, got %d: %s", notInstalled.Code, notInstalled.Body.String())
	}

	if err := os.WriteFile(dir+"/xray.json", []byte(`{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	router = web.NewRouter(web.WithStore(store), web.WithConfigDir(dir), web.WithXrayProbe(fakeWebXrayProbe{installed: true, managed: false, configExists: true, configValid: true}))
	notManaged := httptest.NewRecorder()
	router.ServeHTTP(notManaged, httptest.NewRequest(http.MethodGet, "/api/xray/diagnostics", nil))
	if !strings.Contains(notManaged.Body.String(), `"service_status":"not_managed"`) || !strings.Contains(notManaged.Body.String(), `"xray_not_systemd_managed"`) || !strings.Contains(notManaged.Body.String(), `"command":"systemctl status migate-xray"`) {
		t.Fatalf("expected not managed diagnostics: %s", notManaged.Body.String())
	}

	router = web.NewRouter(web.WithStore(store), web.WithConfigDir(dir), web.WithXrayProbe(fakeWebXrayProbe{installed: true, managed: true, status: "running", configExists: true, checkErr: errors.New("bad config")}))
	invalid := httptest.NewRecorder()
	router.ServeHTTP(invalid, httptest.NewRequest(http.MethodGet, "/api/xray/diagnostics", nil))
	if !strings.Contains(invalid.Body.String(), `"xray_config_invalid"`) || !strings.Contains(invalid.Body.String(), `"config_error":"bad config"`) || !strings.Contains(invalid.Body.String(), `"category":"config"`) {
		t.Fatalf("expected invalid config diagnostics: %s", invalid.Body.String())
	}

	router = web.NewRouter(web.WithStore(store), web.WithConfigDir(dir), web.WithXrayProbe(fakeWebXrayProbe{installed: true, managed: true, status: "running", configExists: false}))
	configMissing := httptest.NewRecorder()
	router.ServeHTTP(configMissing, httptest.NewRequest(http.MethodGet, "/api/xray/diagnostics", nil))
	if !strings.Contains(configMissing.Body.String(), `"xray_config_missing"`) || !strings.Contains(configMissing.Body.String(), `"actions":[`) || !strings.Contains(configMissing.Body.String(), `"message":"点击应用重新写入 Xray 配置。"`) {
		t.Fatalf("expected structured missing config diagnostics: %s", configMissing.Body.String())
	}

	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "vless", Protocol: "vless", Port: 2444, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router = web.NewRouter(
		web.WithStore(store),
		web.WithConfigDir(dir),
		web.WithXrayProbe(fakeWebXrayProbe{installed: true, managed: true, status: "running", configExists: true, configValid: true}),
		web.WithXrayListenerDiagnostics(func(ctx context.Context) []web.CoreListenerDiagnostic {
			return []web.CoreListenerDiagnostic{{InboundID: inbound.ID, Protocol: "vless", Port: 2444, Transport: "tcp", Listening: false}}
		}),
	)
	missing := httptest.NewRecorder()
	router.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/api/xray/diagnostics", nil))
	if !strings.Contains(missing.Body.String(), `"xray_missing_listeners"`) || !strings.Contains(missing.Body.String(), `"missing_listeners":[`) || !strings.Contains(missing.Body.String(), `"port":2444`) {
		t.Fatalf("expected missing listener diagnostics: %s", missing.Body.String())
	}
}

func TestXrayDiagnosticsReturnsStructuredSemanticAndLogActions(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/xray.json", []byte(`{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "ws", Protocol: "vless", Port: 2444, Network: "ws", Security: "tls", WsPath: "bad"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	router := web.NewRouter(
		web.WithStore(store),
		web.WithConfigDir(dir),
		web.WithXrayProbe(fakeWebXrayProbe{installed: true, managed: true, status: "running", configExists: true, configValid: true, logs: []string{"failed to listen tcp 0.0.0.0:2444: bind: address already in use"}}),
		web.WithXrayListenerDiagnostics(func(ctx context.Context) []web.CoreListenerDiagnostic {
			return []web.CoreListenerDiagnostic{{InboundID: inbound.ID, Protocol: "vless", Port: 2444, Transport: "tcp", Listening: false}}
		}),
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/diagnostics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`"suggestions":[`,
		`"actions":[`,
		`"suggestion_details":[`,
		`"code":"xray_ws_path_invalid"`,
		`"category":"listener"`,
		`"code":"xray_tls_certificate_missing"`,
		`"category":"security"`,
		`"code":"xray_listener_port_in_use"`,
		`"command":"ss -ltnp | grep :2444"`,
		`"inbound_id":`,
		`"port":2444`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics missing %q: %s", want, body)
		}
	}
}

func TestXrayDiagnosticsStructuredActionsCoverExpectedCodes(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/xray.json", []byte(`{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	vless, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "reality", Protocol: "vless", Port: 2446, Network: "tcp", Security: "reality",
	})
	if err != nil {
		t.Fatalf("create reality inbound: %v", err)
	}
	tlsInbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "tls", Protocol: "vless", Port: 2447, Network: "tcp", Security: "tls",
	})
	if err != nil {
		t.Fatalf("create tls inbound: %v", err)
	}
	badOutbound, err := store.CreateOutbound(context.Background(), db.CreateOutboundParams{Tag: "disabled-proxy", Protocol: "socks", Address: "127.0.0.1", Port: 1080})
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}
	if _, err := store.SetOutboundEnabled(context.Background(), badOutbound.ID, false); err != nil {
		t.Fatalf("disable outbound: %v", err)
	}
	if _, err := store.CreateRoutingRule(context.Background(), db.CreateRoutingRuleParams{InboundTag: db.GeneratedInboundTag(vless), OutboundID: badOutbound.ID, OutboundTag: badOutbound.Tag, Enabled: true}); err != nil {
		t.Fatalf("create routing rule: %v", err)
	}
	router := web.NewRouter(
		web.WithStore(store),
		web.WithConfigDir(dir),
		web.WithXrayProbe(fakeWebXrayProbe{
			installed: true, managed: true, status: "stopped", configExists: true, checkErr: errors.New("bad config"),
			logs: []string{"failed to listen tcp 0.0.0.0:2446: bind: address already in use"},
		}),
		web.WithXrayListenerDiagnostics(func(ctx context.Context) []web.CoreListenerDiagnostic {
			return []web.CoreListenerDiagnostic{
				{InboundID: vless.ID, Protocol: "vless", Port: 2446, Transport: "tcp", Security: "reality", Listening: false},
				{InboundID: tlsInbound.ID, Protocol: "vless", Port: 2447, Transport: "tcp", Security: "tls", Listening: false},
			}
		}),
	)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/diagnostics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var diagnostics struct {
		Warnings    []string `json:"warnings"`
		Suggestions []string `json:"suggestions"`
		Actions     []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"actions"`
		SuggestionDetails []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"suggestion_details"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &diagnostics); err != nil {
		t.Fatalf("decode diagnostics: %v", err)
	}
	for _, want := range []string{
		"xray_service_not_running",
		"xray_config_invalid",
		"xray_config_out_of_sync",
		"xray_tls_certificate_missing",
		"xray_route_outbound_unavailable",
		"xray_listener_port_in_use",
	} {
		if !diagnosticActionsContain(diagnostics.Actions, want) {
			t.Fatalf("expected structured action %q, got %+v; body=%s", want, diagnostics.Actions, response.Body.String())
		}
	}
	if len(diagnostics.Suggestions) == 0 || len(diagnostics.Actions) == 0 || len(diagnostics.SuggestionDetails) == 0 {
		t.Fatalf("expected legacy and structured suggestions, got %+v", diagnostics)
	}
	seen := map[string]bool{}
	for _, action := range diagnostics.Actions {
		if strings.TrimSpace(action.Code) == "" || strings.TrimSpace(action.Message) == "" {
			t.Fatalf("diagnostic action must not have empty code/message: %+v", action)
		}
		key := action.Code + "\x00" + action.Message
		if seen[key] {
			t.Fatalf("diagnostic action duplicated: %+v", action)
		}
		seen[key] = true
	}
}

func TestXrayDiagnosticsStructuredActionsCoverInstallAndManagementCodes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe fakeWebXrayProbe
		want  string
	}{
		{name: "not installed", probe: fakeWebXrayProbe{installed: false}, want: "xray_not_installed"},
		{name: "not systemd managed", probe: fakeWebXrayProbe{installed: true, managed: false, configExists: true, configValid: true}, want: "xray_not_systemd_managed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := db.Open(context.Background(), ":memory:")
			if err != nil {
				t.Fatalf("open store: %v", err)
			}
			defer store.Close()
			dir := t.TempDir()
			if err := os.WriteFile(dir+"/xray.json", []byte(`{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}`), 0644); err != nil {
				t.Fatalf("write config: %v", err)
			}
			router := web.NewRouter(web.WithStore(store), web.WithConfigDir(dir), web.WithXrayProbe(tc.probe))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/diagnostics", nil))
			var diagnostics struct {
				Actions []struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"actions"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &diagnostics); err != nil {
				t.Fatalf("decode diagnostics: %v", err)
			}
			if !diagnosticActionsContain(diagnostics.Actions, tc.want) {
				t.Fatalf("expected structured action %q, got %+v; body=%s", tc.want, diagnostics.Actions, response.Body.String())
			}
		})
	}
}

func diagnosticActionsContain(actions []struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}, code string) bool {
	for _, action := range actions {
		if action.Code == code {
			return true
		}
	}
	return false
}

func TestXrayDiagnosticsExpectedListenersIncludeTransportDetails(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/xray.json", []byte(`{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]}`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cases := []db.CreateInboundParams{
		{Remark: "ws", Protocol: "vless", Port: 2441, Network: "ws", Security: "none", WsPath: "/ws"},
		{Remark: "grpc", Protocol: "vless", Port: 2442, Network: "grpc", Security: "none", GrpcServiceName: "svc"},
		{Remark: "xhttp", Protocol: "vless", Port: 2443, Network: "xhttp", Security: "none", XHTTPPath: "/xhttp"},
	}
	for _, params := range cases {
		if _, err := store.CreateInbound(context.Background(), params); err != nil {
			t.Fatalf("create %s inbound: %v", params.Remark, err)
		}
	}
	router := web.NewRouter(web.WithStore(store), web.WithConfigDir(dir), web.WithXrayProbe(fakeWebXrayProbe{installed: true, managed: true, status: "running", configExists: true, configValid: true}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/xray/diagnostics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`"network":"ws"`, `"path":"/ws"`, `"security":"none"`,
		`"network":"grpc"`, `"grpc_service_name":"svc"`,
		`"network":"xhttp"`, `"path":"/xhttp"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics missing %q: %s", want, body)
		}
	}
}

func TestCreateXrayInboundReturnsSynchronousApplyResult(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	controller := &fakeXrayController{applyResult: &web.XrayApplyResult{
		Applied: false, Status: "failed: validation", Service: "xray", ConfigPath: "/tmp/xray.json",
		Error: "validation_failed", Detail: "invalid config", CommandsExecuted: []string{"write /tmp/xray.json", "xray run -test -c /tmp/xray.json"},
	}}
	router := web.NewRouter(web.WithStore(store), web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", strings.NewReader(`{"remark":"vless","protocol":"vless","port":2445,"network":"tcp","security":"none"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	for _, want := range []string{`"created":true`, `"inbound":`, `"xray":`, `"applied":false`, `"error":"validation_failed"`, `"detail":"invalid config"`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("response missing %q: %s", want, response.Body.String())
		}
	}
	if controller.applyCalls != 1 {
		t.Fatalf("expected synchronous xray apply once, got %d", controller.applyCalls)
	}
}

func TestCreateXrayInboundReturnsSemanticWarningsWithoutFailingSave(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithStore(store), web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", strings.NewReader(`{"remark":"bad-ws","protocol":"vless","port":2451,"network":"ws","security":"tls","ws_path":"bad"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"created":true`, `"xray":`, `"applied":true`, `"warnings":[`, `"xray_ws_path_invalid"`, `"xray_tls_certificate_missing"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, `"error":`) {
		t.Fatalf("semantic warnings must not turn save into an error: %s", body)
	}
}

func TestCreateXrayInboundApplyFailureTakesPriorityOverSemanticWarnings(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	controller := &fakeXrayController{applyResult: &web.XrayApplyResult{
		Applied: false, Status: "failed: validation", Service: "xray", ConfigPath: "/tmp/xray.json",
		Error: "validation_failed", Detail: "invalid config", CommandsExecuted: []string{"xray run -test -c /tmp/xray.json"},
	}}
	router := web.NewRouter(web.WithStore(store), web.WithXrayController(controller))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/inbounds", strings.NewReader(`{"remark":"bad-ws","protocol":"vless","port":2452,"network":"ws","security":"tls","ws_path":"bad"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"created":true`, `"xray":`, `"applied":false`, `"error":"validation_failed"`, `"detail":"invalid config"`, `"xray_ws_path_invalid"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q: %s", want, body)
		}
	}
}

func TestDeleteInboundAPIRemovesInboundAndReturns200(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "to-delete", Protocol: "vless", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store), web.WithXrayController(&fakeXrayController{}))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10), nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}

	// Verify inbound is gone
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	for _, ib := range inbounds {
		if ib.ID == inbound.ID {
			t.Fatal("inbound still present after DELETE")
		}
	}
}

func TestDeleteInboundAPIRejectsUnknownID(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/inbounds/99999", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown inbound, got %d: %s", response.Code, response.Body.String())
	}
}

func TestDeleteClientAPIRemovesClientAndReturns200(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "parent", Protocol: "vmess", Port: 8443, Network: "ws", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{
		InboundID: inbound.ID, Email: "del@test.com",
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients/"+strconv.FormatInt(client.ID, 10), nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}

	// Verify client is gone
	inbounds, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatalf("list inbounds: %v", err)
	}
	for _, ib := range inbounds {
		for _, c := range ib.Clients {
			if c.ID == client.ID {
				t.Fatal("client still present after DELETE")
			}
		}
	}
}

func TestDeleteClientAPIRejectsUnknownClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{
		Remark: "parent", Protocol: "trojan", Port: 443, Network: "tcp", Security: "none",
	})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/inbounds/"+strconv.FormatInt(inbound.ID, 10)+"/clients/99999", nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown client, got %d: %s", response.Code, response.Body.String())
	}
}

func TestSubscriptionSkipsExpiredClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "test", Protocol: "vless", Port: 8443})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "expired", ExpiryAt: time.Now().Unix() - 3600})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for expired client, got %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "Subscription unavailable") {
		t.Fatalf("expected generic unavailable message, got: %s", response.Body.String())
	}
}

func TestSubscriptionSkipsDisabledClient(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "test", Protocol: "vless", Port: 8443})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "disabled"})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	// Disable the client
	_, err = store.UpdateClient(context.Background(), client.ID, db.UpdateClientParams{Email: "disabled", Enabled: false, TrafficLimit: 0, ExpiryAt: 0})
	if err != nil {
		t.Fatalf("update client: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for disabled client, got %d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "Subscription unavailable") {
		t.Fatalf("expected generic unavailable message, got: %s", response.Body.String())
	}
}

func TestSubscriptionPassesValidClientWithFutureExpiry(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "test", Protocol: "vless", Port: 8443})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(context.Background(), db.CreateClientParams{InboundID: inbound.ID, Email: "valid", TrafficLimit: 100000, ExpiryAt: time.Now().Unix() + 86400})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil)
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid client with future expiry, got %d", response.Code)
	}
}

func TestSubscriptionLimitUsesUnifiedTrafficStateAndResetReopens(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "limited", Protocol: "vless", Port: 18443, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "limited", TrafficLimit: 100})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	raw := func(up, down int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{{Engine: "xray", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: up, RawDown: down, Status: "ok"}}
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1000, 1000), time.Unix(100, 0)); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1060, 1050), time.Unix(110, 0)); err != nil {
		t.Fatalf("over limit sample: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("expected over-limit subscription to be blocked, got %d: %s", response.Code, response.Body.String())
	}
	if _, err := store.ResetClientTrafficBaseline(ctx, client.ID, raw(1060, 1050)); err != nil {
		t.Fatalf("reset baseline: %v", err)
	}
	reopened := httptest.NewRecorder()
	router.ServeHTTP(reopened, httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil))
	if reopened.Code != http.StatusOK {
		t.Fatalf("expected reset subscription to reopen, got %d: %s", reopened.Code, reopened.Body.String())
	}
}

func TestSubscriptionLimitUsesLegacyClientTotalsWhenNoTrafficState(t *testing.T) {
	path := t.TempDir() + "/legacy-subscription.db"
	store, err := db.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "legacy", Protocol: "vless", Port: 18447, Network: "tcp", Security: "none"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	over, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "legacy-over", TrafficLimit: 100})
	if err != nil {
		t.Fatalf("create over client: %v", err)
	}
	under, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "legacy-under", TrafficLimit: 100})
	if err != nil {
		t.Fatalf("create under client: %v", err)
	}
	seedClientTraffic(t, store, over, 70, 40)
	seedClientTraffic(t, store, under, 30, 40)
	rawDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	defer rawDB.Close()
	if _, err := rawDB.ExecContext(ctx, `DELETE FROM traffic_states WHERE scope_type='client' AND scope_key IN (?, ?)`, over.StatsKey, under.StatsKey); err != nil {
		t.Fatalf("delete traffic states: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	blocked := httptest.NewRecorder()
	router.ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, "/sub/"+over.SubscriptionToken, nil))
	if blocked.Code != http.StatusNotFound {
		t.Fatalf("expected legacy over-limit subscription to be blocked, got %d: %s", blocked.Code, blocked.Body.String())
	}
	allowed := httptest.NewRecorder()
	router.ServeHTTP(allowed, httptest.NewRequest(http.MethodGet, "/sub/"+under.SubscriptionToken, nil))
	if allowed.Code != http.StatusOK {
		t.Fatalf("expected legacy under-limit subscription to pass, got %d: %s", allowed.Code, allowed.Body.String())
	}
}

func TestSubscriptionLimitUsesSingboxTrafficState(t *testing.T) {
	store, err := db.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()
	inbound, err := store.CreateInbound(ctx, db.CreateInboundParams{Remark: "hy2", Protocol: "hysteria2", Port: 18444, Network: "udp", Security: "tls"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	client, err := store.CreateClient(ctx, db.CreateClientParams{InboundID: inbound.ID, Email: "hy2", TrafficLimit: 50})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	raw := func(up, down int64) []db.TrafficRawStat {
		return []db.TrafficRawStat{{Engine: "singbox", ScopeType: "client", ScopeKey: client.StatsKey, RawUp: up, RawDown: down, Status: "ok"}}
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(1, 1), time.Unix(100, 0)); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(20, 20), time.Unix(110, 0)); err != nil {
		t.Fatalf("under limit sample: %v", err)
	}
	router := web.NewRouter(web.WithStore(store))
	allowed := httptest.NewRecorder()
	router.ServeHTTP(allowed, httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil))
	if allowed.Code != http.StatusOK {
		t.Fatalf("expected under-limit singbox subscription to pass, got %d: %s", allowed.Code, allowed.Body.String())
	}
	if err := store.ApplyTrafficRawStats(ctx, raw(40, 30), time.Unix(120, 0)); err != nil {
		t.Fatalf("over limit sample: %v", err)
	}
	blocked := httptest.NewRecorder()
	router.ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, "/sub/"+client.SubscriptionToken, nil))
	if blocked.Code != http.StatusNotFound {
		t.Fatalf("expected over-limit singbox subscription to be blocked, got %d: %s", blocked.Code, blocked.Body.String())
	}
}

func TestCertStatusReturnsEmptyStateWhenNotConfigured(t *testing.T) {
	router := web.NewRouter()
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cert/status", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var data map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if data["domain"] != "" {
		t.Fatalf("expected empty domain, got %v", data["domain"])
	}
	if data["issued"] != false {
		t.Fatalf("expected issued=false, got %v", data["issued"])
	}
}

func TestCertStatusReturnsCertInfoWhenConfigured(t *testing.T) {
	store := openWebTestStore(t)
	cert, key := testCertificatePair(t, "example.com")
	imported, err := store.UpsertCertificate(context.Background(), db.UpsertCertificateParams{
		Name: "example.com", Source: db.CertSourceImport, Status: db.CertStatusIssued, Domains: []string{"example.com"}, CertPath: cert, KeyPath: key,
		NotBefore: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), NotAfter: time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})
	if err != nil || imported.ID == 0 {
		t.Fatalf("seed certificate: %v", err)
	}

	router := web.NewRouter(web.WithStore(store))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cert/status", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var data map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if data["domain"] != "example.com" {
		t.Fatalf("expected domain 'example.com', got %v", data["domain"])
	}
	if data["issued"] != true {
		t.Fatalf("expected issued=true, got %v", data["issued"])
	}
	if data["cert_path"] == nil || data["cert_path"] == "" {
		t.Fatalf("expected non-empty cert_path, got %v", data["cert_path"])
	}
}

func TestCertStatusRejectsInvalidPanelConfigFields(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/panel.json"
	if err := os.WriteFile(configPath, []byte(`{"panel_port":0,"database_path":"relative.db","cert_domain":"example.com","cert_email":"admin@example.com"}`), 0644); err != nil {
		t.Fatalf("write panel.json: %v", err)
	}

	router := web.NewRouter(web.WithConfigDir(dir))
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/cert/status", nil)
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var data map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if data["domain"] != "" || data["email"] != "" {
		t.Fatalf("invalid panel config must not be partially trusted, got %v", data)
	}
}

func TestCertIssueValidatesRequiredFields(t *testing.T) {
	router := web.NewRouter(web.WithStore(openWebTestStore(t)))
	// Missing domain
	response := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/cert/issue", strings.NewReader(`{"domain":"","email":"admin@example.com","confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty domain, got %d: %s", response.Code, response.Body.String())
	}
	// Missing email
	response2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/cert/issue", strings.NewReader(`{"domain":"example.com","email":"","confirm":true,"allow_system_changes":true}`))
	req2.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response2, req2)
	if response2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty email, got %d: %s", response2.Code, response2.Body.String())
	}
	// Not available (no certificate store)
	response3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodPost, "/api/cert/issue", strings.NewReader(`{"domain":"example.com","email":"admin@example.com","confirm":true,"allow_system_changes":true}`))
	req3.Header.Set("Content-Type", "application/json")
	web.NewRouter().ServeHTTP(response3, req3)
	if response3.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when no store, got %d: %s", response3.Code, response3.Body.String())
	}
}

func TestCertIssuePreflightFailuresReturnStructuredClientErrors(t *testing.T) {
	tests := []struct {
		name       string
		certDir    string
		lookupIP   func(context.Context, string) ([]net.IP, error)
		listenTCP  func(string, string) (net.Listener, error)
		wantStatus int
		wantCode   string
	}{
		{
			name:    "dns not resolved",
			certDir: t.TempDir(),
			lookupIP: func(context.Context, string) ([]net.IP, error) {
				return nil, fmt.Errorf("no such host")
			},
			listenTCP: func(string, string) (net.Listener, error) {
				return net.Listen("tcp", "127.0.0.1:0")
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "domain_not_resolved",
		},
		{
			name:    "http 01 port unavailable",
			certDir: t.TempDir(),
			lookupIP: func(context.Context, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("203.0.113.10")}, nil
			},
			listenTCP: func(string, string) (net.Listener, error) {
				return nil, fmt.Errorf("bind: address already in use")
			},
			wantStatus: http.StatusConflict,
			wantCode:   "http_01_port_unavailable",
		},
		{
			name:    "cert dir not writable",
			certDir: filepath.Join(t.TempDir(), "missing", "certs"),
			lookupIP: func(context.Context, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("203.0.113.10")}, nil
			},
			listenTCP: func(string, string) (net.Listener, error) {
				return net.Listen("tcp", "127.0.0.1:0")
			},
			wantStatus: http.StatusBadRequest,
			wantCode:   "cert_dir_not_writable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantCode == "cert_dir_not_writable" {
				if err := os.WriteFile(filepath.Dir(tt.certDir), []byte("file"), 0644); err != nil {
					t.Fatalf("prepare unwritable parent: %v", err)
				}
			}
			router := web.NewRouter(web.WithStore(openWebTestStore(t)), web.WithCertDir(tt.certDir), web.WithCertPreflightHooks(tt.lookupIP, tt.listenTCP))
			resp := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/certificates", strings.NewReader(`{"domains":["example.com"],"email":"admin@example.com","confirm":true,"allow_system_changes":true}`))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(resp, req)
			if resp.Code != tt.wantStatus || resp.Code == http.StatusInternalServerError {
				t.Fatalf("expected %d, got %d: %s", tt.wantStatus, resp.Code, resp.Body.String())
			}
			body := resp.Body.String()
			var payload struct {
				Error struct {
					Code   string                 `json:"code"`
					Fields map[string]interface{} `json:"fields"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(body), &payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if payload.Error.Code != "preflight_failed" {
				t.Fatalf("expected preflight_failed, got %#v", payload.Error.Code)
			}
			preflight, ok := payload.Error.Fields["preflight"].(map[string]interface{})
			if !ok || preflight["ok"] != false || !strings.Contains(body, tt.wantCode) {
				t.Fatalf("missing structured preflight %s: %#v body=%s", tt.wantCode, payload.Error.Fields, body)
			}
		})
	}
}

func TestCertificatePreflightValidationErrorUsesStandardErrorObject(t *testing.T) {
	router := web.NewRouter(web.WithStore(openWebTestStore(t)), web.WithCertDir(t.TempDir()))
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/certificates/preflight", strings.NewReader(`{"domains":[],"email":"admin@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", resp.Code, resp.Body.String())
	}
	body := resp.Body.Bytes()
	assertStandardAPIError(t, body, "domain_required")
	if !bytes.Contains(body, []byte(`"preflight"`)) || !bytes.Contains(body, []byte(`"domain_required"`)) {
		t.Fatalf("expected structured preflight in error fields: %s", string(body))
	}
}

func TestCertificateFixedChildRoutesReturnMethodNotAllowed(t *testing.T) {
	router := web.NewRouter(web.WithStore(openWebTestStore(t)))
	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/certificates/preflight"},
		{http.MethodGet, "/api/certificates/import"},
		{http.MethodGet, "/api/certificates/renew-due"},
		{http.MethodPost, "/api/certificates/inbounds"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, httptest.NewRequest(tt.method, tt.path, nil))
			if resp.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405, got %d: %s", resp.Code, resp.Body.String())
			}
			assertStandardAPIError(t, resp.Body.Bytes(), "method_not_allowed")
		})
	}
}

func TestRenewedCertificateCoreApplyReloadsUsageFromStore(t *testing.T) {
	store := openWebTestStore(t)
	cert, err := store.UpsertCertificate(context.Background(), db.UpsertCertificateParams{
		Name: "example.com", Source: db.CertSourceACME, Status: db.CertStatusIssued, Domains: []string{"example.com"}, CertPath: "/etc/migate/certs/example/fullchain.pem", KeyPath: "/etc/migate/certs/example/privkey.pem",
		NotBefore: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), NotAfter: time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("seed certificate: %v", err)
	}
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "tls", Protocol: "vless", Port: 24444, Network: "tcp", Security: "tls", TLSCertFile: cert.CertPath, TLSKeyFile: cert.KeyPath})
	if err != nil || inbound.ID == 0 {
		t.Fatalf("create inbound: %v", err)
	}
	controller := &fakeXrayController{}
	apply := web.CertificateCoreApplyFunc(web.WithStore(store), web.WithXrayController(controller))
	payload := apply(context.Background(), []db.Certificate{{ID: cert.ID}})
	if controller.applyCalls != 1 {
		t.Fatalf("expected xray apply after reloading certificate usage, calls=%d payload=%#v", controller.applyCalls, payload)
	}
	if _, ok := payload["xray"]; !ok {
		t.Fatalf("expected xray apply payload, got %#v", payload)
	}
}

func TestCertificateImportListAndOperationsAPI(t *testing.T) {
	store := openWebTestStore(t)
	certPath, keyPath := testCertificatePair(t, "example.com")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	router := web.NewRouter(web.WithStore(store), web.WithCertDir(t.TempDir()))

	missingConfirm := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/certificates/import", strings.NewReader(`{"name":"example","fullchain":"x","private_key":"y","confirm":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(missingConfirm, req)
	if missingConfirm.Code != http.StatusForbidden {
		t.Fatalf("expected confirmation_required status, got %d: %s", missingConfirm.Code, missingConfirm.Body.String())
	}
	assertStandardAPIError(t, missingConfirm.Body.Bytes(), "confirmation_required")

	body, _ := json.Marshal(map[string]interface{}{
		"name":                 "example",
		"fullchain":            string(certPEM),
		"private_key":          string(keyPEM),
		"confirm":              true,
		"allow_system_changes": true,
	})
	resp := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/certificates/import", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected import 201, got %d: %s", resp.Code, resp.Body.String())
	}
	var imported struct {
		Certificate db.Certificate `json:"certificate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&imported); err != nil {
		t.Fatalf("decode import: %v", err)
	}
	if imported.Certificate.ID == 0 || imported.Certificate.Domains[0] != "example.com" || imported.Certificate.Fingerprint == "" {
		t.Fatalf("unexpected imported certificate: %#v", imported.Certificate)
	}

	listResp := httptest.NewRecorder()
	router.ServeHTTP(listResp, httptest.NewRequest(http.MethodGet, "/api/certificates", nil))
	if listResp.Code != http.StatusOK || !strings.Contains(listResp.Body.String(), `"certificates"`) {
		t.Fatalf("unexpected list response: %d %s", listResp.Code, listResp.Body.String())
	}
	opsResp := httptest.NewRecorder()
	router.ServeHTTP(opsResp, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/certificates/%d/operations", imported.Certificate.ID), nil))
	if opsResp.Code != http.StatusOK || !strings.Contains(opsResp.Body.String(), `"operations"`) {
		t.Fatalf("unexpected operations response: %d %s", opsResp.Code, opsResp.Body.String())
	}
}

func TestCertificateImportValidationErrorsReturnBadRequest(t *testing.T) {
	router := web.NewRouter(web.WithStore(openWebTestStore(t)), web.WithCertDir(t.TempDir()))
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/certificates/import", strings.NewReader(`{"name":"bad","fullchain":"not a cert","private_key":"not a key","confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected import validation 400, got %d: %s", resp.Code, resp.Body.String())
	}
	assertStandardAPIError(t, resp.Body.Bytes(), "invalid_certificate")
}

func TestCertificateApplyAPIWritesTLSInboundAndReturnsCoreSummary(t *testing.T) {
	store := openWebTestStore(t)
	certPath, keyPath := testCertificatePair(t, "example.com")
	certificate, err := store.UpsertCertificate(context.Background(), db.UpsertCertificateParams{
		Name: "example.com", Source: db.CertSourceImport, Status: db.CertStatusIssued, Domains: []string{"example.com"}, CertPath: certPath, KeyPath: keyPath,
		NotBefore: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), NotAfter: time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("seed certificate: %v", err)
	}
	inbound, err := store.CreateInbound(context.Background(), db.CreateInboundParams{Remark: "tls", Protocol: "vless", Port: 24443, Network: "tcp", Security: "tls", TLSSNI: "old.example.com"})
	if err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	controller := &fakeXrayController{}
	router := web.NewRouter(web.WithStore(store), web.WithXrayController(controller))
	body := fmt.Sprintf(`{"inbound_ids":[%d],"confirm":true,"allow_system_changes":true}`, inbound.ID)
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/certificates/%d/apply", certificate.ID), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected apply 200, got %d: %s", resp.Code, resp.Body.String())
	}
	if controller.applyCalls != 1 || !strings.Contains(resp.Body.String(), `"xray"`) {
		t.Fatalf("expected xray apply summary, calls=%d body=%s", controller.applyCalls, resp.Body.String())
	}
	loaded, err := store.ListInbounds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if loaded[0].TLSCertFile != certPath || loaded[0].TLSKeyFile != keyPath || loaded[0].TLSSNI != "example.com" {
		t.Fatalf("certificate not applied to inbound: %#v", loaded[0])
	}
}

func TestSettingsGetReturnsNotFoundWithoutConfigDir(t *testing.T) {
	router := web.NewRouter()
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404 without configDir, got %d: %s", resp.Code, resp.Body.String())
	}
}

func TestSettingsGetReturnsPanelConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/panel.json"
	if err := os.WriteFile(configPath, []byte(`{"panel_port":8888,"panel_username":"admin","panel_password":"secret","database_path":"/var/lib/migate/migate.db","web_base_path":"/migate"}`), 0644); err != nil {
		t.Fatalf("write panel.json: %v", err)
	}
	router := web.NewRouter(web.WithConfigDir(dir))
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if data["panel_port"] != float64(8888) {
		t.Fatalf("expected panel_port=8888, got %v", data["panel_port"])
	}
	if _, exists := data["panel_password"]; exists {
		t.Fatalf("panel_password should be masked in GET response")
	}
	if data["has_password"] != true {
		t.Fatalf("expected has_password=true, got %v", data["has_password"])
	}
}

func TestSettingsPutUpdatesPanelConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/panel.json"
	if err := os.WriteFile(configPath, []byte(`{"panel_port":9999,"panel_username":"admin","panel_password":"secret","web_base_path":"/"}`), 0644); err != nil {
		t.Fatalf("write panel.json: %v", err)
	}
	router := web.NewRouter(web.WithConfigDir(dir))
	body := `{"panel_port":7777,"panel_username":"newadmin","panel_password":"newpass","unknown_config_path":"/opt/xray","web_base_path":"/panel"}`
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	// Verify file was written
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var saved map[string]interface{}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if saved["panel_port"] != float64(7777) {
		t.Fatalf("expected panel_port=7777, got %v", saved["panel_port"])
	}
	if saved["panel_username"] != "newadmin" {
		t.Fatalf("expected panel_username=newadmin, got %v", saved["panel_username"])
	}
	if password, ok := saved["panel_password"].(string); !ok || !web.IsPanelPasswordHash(password) || !web.VerifyPanelPassword(password, "newpass") {
		t.Fatalf("expected panel_password to be an Argon2id hash for newpass, got %v", saved["panel_password"])
	}
	if _, exists := saved["unknown_config_path"]; exists {
		t.Fatalf("unknown config fields should not be saved, got %v", saved["unknown_config_path"])
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("expected panel.json mode 0640, got %03o", got)
	}
}

func TestSettingsPutPreservesPasswordWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	configPath := dir + "/panel.json"
	if err := os.WriteFile(configPath, []byte(`{"panel_port":9999,"panel_username":"admin","panel_password":"secret","database_path":"/db/migate.db","web_base_path":"/"}`), 0644); err != nil {
		t.Fatalf("write panel.json: %v", err)
	}
	router := web.NewRouter(web.WithConfigDir(dir))
	body := `{"panel_port":7777,"panel_username":"admin","panel_password":"","web_base_path":"/"}`
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var saved map[string]interface{}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if password, ok := saved["panel_password"].(string); !ok || !web.IsPanelPasswordHash(password) || !web.VerifyPanelPassword(password, "secret") {
		t.Fatalf("expected panel_password preserved by migrating secret to hash, got %v", saved["panel_password"])
	}
	if saved["database_path"] != "/db/migate.db" {
		t.Fatalf("expected database_path preserved, got %v", saved["database_path"])
	}
}

func TestRestartReturnsRestarting(t *testing.T) {
	router := web.NewRouter()
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/restart", strings.NewReader(`{"confirm":true,"allow_system_changes":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if data["status"] != "restarting" {
		t.Fatalf("expected status=restarting, got %v", data["status"])
	}
}

func TestRestartRejectsNonPost(t *testing.T) {
	router := web.NewRouter()
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/api/restart", nil)
		router.ServeHTTP(resp, req)
		if resp.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405 for %s, got %d", method, resp.Code)
		}
	}
}
